#include "logger.h"
#include "selector.h"
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <pthread.h>


#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif


#include <arpa/inet.h>
#include <unistd.h>

#include "netutils.h"

#define N(x) (sizeof(x) / sizeof((x)[0]))

uint16_t get_socket_port(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }

    return 0;
}

extern const char *sockaddr_to_human(char *buff, const size_t buffsize,
                                     const struct sockaddr *addr) {
    if (addr == 0) {
        strncpy(buff, "null", buffsize);
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch (addr->sa_family) {
    case AF_INET:
        p = &((struct sockaddr_in *)addr)->sin_addr;
        port = ((struct sockaddr_in *)addr)->sin_port;
        handled = true;
        break;
    case AF_INET6:
        p = &((struct sockaddr_in6 *)addr)->sin6_addr;
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
        handled = true;
        break;
    }
    if (handled) {
        if (inet_ntop(addr->sa_family, p, buff, buffsize) == 0) {
            strncpy(buff, "unknown ip", buffsize);
            buff[buffsize - 1] = 0;
        }
    } else {
        strncpy(buff, "unknown", buffsize);
    }

    if (handled) strncat(buff, ":", buffsize);

    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if (handled) {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }
    buff[buffsize - 1] = 0;

    return buff;
}

int sock_blocking_write(const int fd, buffer *b) {
    int ret = 0;
    ssize_t nwritten;
    size_t n;
    uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char *out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
error:

    return ret;
}

static struct in6_addr ipv6_test;

static int get_ip_addr_family(const char* ip_str, uint16_t port, struct sockaddr_storage* addr, socklen_t* addr_len) {
    int family = AF_INET;

    if (ip_str == NULL) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        addr4->sin_addr.s_addr = htonl(INADDR_ANY);
        *addr_len = sizeof(struct sockaddr_in);
    } else {
        int ip_str_len = strlen(ip_str);
        char ip_str_copy[ip_str_len + 1];
        strncpy(ip_str_copy, ip_str, ip_str_len + 1);

        char* percentage = strchr(ip_str_copy, '%');
        
        if (percentage != NULL) {
            *percentage = '\0';
        }

        if (inet_pton(AF_INET6, ip_str_copy, &ipv6_test) == 1) {
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = htons(port);
            addr6->sin6_addr = ipv6_test;

            if (percentage != NULL) {
                unsigned int ifindex = if_nametoindex(percentage + 1);
                if (ifindex == 0) return -1;
                addr6->sin6_scope_id = ifindex;
            }

            family = AF_INET6;
            *addr_len = sizeof(struct sockaddr_in6);
        } else {
            struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
            if (inet_pton(AF_INET, ip_str, &addr4->sin_addr) <= 0)
                return -1;
            addr4->sin_family = AF_INET;
            addr4->sin_port = htons(port);
            *addr_len = sizeof(struct sockaddr_in);
        }
    }

    return family;
}

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_passive_tcp_socket(const char* ip_str, uint16_t port, uint32_t max_connections) {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int addr_family;
    if ((addr_family = get_ip_addr_family(ip_str, port, &addr, &addr_len)) < 0)  {
        LOG(LOG_DEBUG, "Could not get the address for the IP address string");
        return -1;
    }

    int passive_tcp_socket = socket(addr_family, SOCK_STREAM, 0);
    if (passive_tcp_socket < 0) {
        LOG(LOG_DEBUG, "Could not create passive TCP socket");
        return -1;
    }

    if (set_non_blocking(passive_tcp_socket) < 0) {
        LOG(LOG_DEBUG, "Could not set TCP socket as passive");
        close(passive_tcp_socket);
        return -1;
    }
    
    // Don't allow dual mode if IPv6
    int opt = 1;
    setsockopt(passive_tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(passive_tcp_socket, (struct sockaddr*)&addr, addr_len) < 0) {
        LOG(LOG_DEBUG, "Could not bind TCP socket to address");
        close(passive_tcp_socket);
        return -1;
    }

    if (listen(passive_tcp_socket, max_connections) < 0) {
        LOG(LOG_DEBUG, "Could not listen on TCP socket");
        close(passive_tcp_socket);
        return -1;
    }

    return passive_tcp_socket;
}

struct connect_args {
    char* host;
    char* port;
    int notify_fd;
};

struct connection_finished {
    void (*callback)(int, fd_selector, void*);
    void* data;
};

static char* copy_str(const char* str) {
    int len = strlen(str);
    char* out = malloc(len + 1);
    if (out == NULL) return NULL;
    strcpy(out, str);
    return out;
}

void* connect_in_other_thread(void* arg_ptr) {
    LOG(LOG_DEBUG, "Attempting connection");
    struct connect_args* args = (struct connect_args*) arg_ptr;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *res;

    if (getaddrinfo(args->host, args->port, &hints, &res) != 0) {
        LOG(LOG_DEBUG, "Could not get address info");
        int invalid_sock = -1;
        if (write(args->notify_fd, &invalid_sock, sizeof(invalid_sock)) < 0) {
            LOG(LOG_DEBUG, "Could not write to pipe");
        }
        free(args->host);
        free(args->port);
        close(args->notify_fd);
        free(args);
        return NULL;
    }

    for (struct addrinfo* rp = res; rp != NULL; rp = rp->ai_next) {
        int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            set_non_blocking(sock);
            freeaddrinfo(res);
            if (write(args->notify_fd, &sock, sizeof(sock)) < 0) {
                LOG(LOG_DEBUG, "Could not write to pipe");
            }
            LOG(LOG_DEBUG, "Connected to address");
            free(args->host);
            free(args->port);
            close(args->notify_fd);
            free(args);
            return NULL;
        }

        close(sock);
    }

    freeaddrinfo(res);
    int invalid_sock = -1;

    if (write(args->notify_fd, &invalid_sock, sizeof(invalid_sock)) < 0) {
        LOG(LOG_DEBUG, "Could not write to pipe");
    }

    free(args->host);
    free(args->port);
    close(args->notify_fd);
    free(args);

    return NULL;
}

static void connect_finished(struct selector_key *key) {
    LOG(LOG_DEBUG, "Connection finished callback");
    struct connection_finished* data = (struct connection_finished*)key->data;

    int socket;
    if (read(key->fd, &socket, sizeof(socket)) < 0) {
        return;
    }

    selector_unregister_fd(key->s, key->fd);
    close(key->fd);

    data->callback(socket, key->s, data->data);
}

static fd_handler get_addr_info_finished_handler = {
    .handle_read = connect_finished
};

int connect_to_host_non_blocking(const char* host, const char *port, fd_selector selector, void(*callback)(int, fd_selector, void*), void* data) {
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        LOG(LOG_DEBUG, "Could not create pipes for get_addr_info");
        return -1;
    }

    struct connection_finished* callback_data = malloc(sizeof(struct connection_finished));
    callback_data->callback = callback;
    callback_data->data = data;
    if (selector_register(selector, pipe_fds[0], &get_addr_info_finished_handler, OP_READ, (void*)callback_data) != SELECTOR_SUCCESS) {
        free(callback_data);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        LOG(LOG_DEBUG, "Could no register selector for get_addr_info");
        return -1;
    }

    struct connect_args* args = malloc(sizeof(struct connect_args));
    args->host = copy_str(host);
    args->port = copy_str(port);
    args->notify_fd = pipe_fds[1];

    pthread_t tid;
    if (pthread_create(&tid, NULL, connect_in_other_thread, (void*)args) != 0) {
        free(callback_data);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        free(args->host);
        free(args->port);
        free(args);
        LOG(LOG_DEBUG, "Could not create connect thread");
        return -1;
    }

    return 0;
}

int connect_to_host(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *res;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return -1; 
    }

    for (struct addrinfo* rp = res; rp != NULL; rp = rp->ai_next) {
        int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;

        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            set_non_blocking(sock);
            freeaddrinfo(res);
            return sock;
        }

        close(sock);
    }

    freeaddrinfo(res);
    return -1;
}

int get_socket_peer_address(int fd, struct sockaddr_storage *out_addr) {
    socklen_t len = sizeof(*out_addr);
    return getpeername(fd, (struct sockaddr*)out_addr, &len);
}
