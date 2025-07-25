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

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int create_passive_tcp_socket(const char* ip_str, uint16_t port, uint32_t max_connections) {
    struct addrinfo *res;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE 
    };

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    // sure, this is blocking. But it only runs when the server starts. So apparently this is OK :).
    if (getaddrinfo(ip_str, port_str, &hints, &res) < 0)  {
        LOG(LOG_DEBUG, "Could not get the address for the IP address string");
        return -1;
    }

    for (struct addrinfo* rp = res; rp != NULL; rp = rp->ai_next) {
        int passive_tcp_socket = socket(rp->ai_family, SOCK_STREAM, 0);
        if (passive_tcp_socket < 0) {
            LOG(LOG_DEBUG, "Could not create passive TCP socket");
            continue;
        }

        if (set_non_blocking(passive_tcp_socket) < 0) {
            LOG(LOG_DEBUG, "Could not set TCP socket as passive");
            close(passive_tcp_socket);
            continue;
        }
        
        // Don't allow dual mode if IPv6
        int opt = 1;
        setsockopt(passive_tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        if (bind(passive_tcp_socket, rp->ai_addr, rp->ai_addrlen) < 0) {
            LOG(LOG_DEBUG, "Could not bind TCP socket to address");
            close(passive_tcp_socket);
            continue;
        }

        if (listen(passive_tcp_socket, max_connections) < 0) {
            LOG(LOG_DEBUG, "Could not listen on TCP socket");
            close(passive_tcp_socket);
            continue;
        }

        freeaddrinfo(res);

        return passive_tcp_socket;
    }

    freeaddrinfo(res);

    return -1;
}

struct addr_info_args {
    char* host;
    char* port;
    struct addrinfo** out;
    fd_selector selector;
    int notify_fd;
};

static char* copy_str(const char* str) {
    int len = strlen(str);
    char* out = malloc(len + 1);
    if (out == NULL) return NULL;
    strcpy(out, str);
    return out;
}

void* getaddrinfo_in_other_thread(void* data) {
    struct addr_info_args* addr_info_args = (struct addr_info_args*) data;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };

    if (getaddrinfo(addr_info_args->host, addr_info_args->port, &hints, addr_info_args->out) != 0) {
        LOG(LOG_DEBUG, "Could not get address info");
    } else {
        LOG(LOG_DEBUG, "Got address info in another thread, merging to main");
    }

    fd_selector selector = addr_info_args->selector;
    int notify_fd = addr_info_args->notify_fd;

    free(addr_info_args->host);
    free(addr_info_args->port);
    free(addr_info_args);

    selector_notify_block(selector, notify_fd);

    return NULL;
}

int get_addr_info_non_blocking(const char* host, const char *port, fd_selector selector, int notify_fd, struct addrinfo** out) {
    LOG(LOG_DEBUG, "Getting address info non blocking");

    struct addr_info_args* args = malloc(sizeof(struct addr_info_args));
    args->host = copy_str(host);
    args->port = copy_str(port);
    args->selector = selector;
    args->notify_fd = notify_fd;
    args->out = out;

    pthread_t tid;
    if (pthread_create(&tid, NULL, getaddrinfo_in_other_thread, (void*)args) != 0) {
        free(args->host);
        free(args->port);
        free(args);
        LOG(LOG_DEBUG, "Could not create connect thread");
        return -1;
    } 
    pthread_detach(tid);
    
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
