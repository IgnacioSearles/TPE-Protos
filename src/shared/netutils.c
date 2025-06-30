#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <unistd.h>

#include "netutils.h"

#define N(x) (sizeof(x) / sizeof((x)[0]))

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

    strncat(buff, ":", buffsize);
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
    int passive_tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (passive_tcp_socket < 0) {
        return -1;
    }

    if (set_non_blocking(passive_tcp_socket) < 0) {
        close(passive_tcp_socket);
        return -1;
    }
    
    int opt = 1;
    setsockopt(passive_tcp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    if (ip_str == NULL) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, ip_str, &addr.sin_addr) <= 0) {
        close(passive_tcp_socket);
        return -1;
    }

    if (bind(passive_tcp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(passive_tcp_socket);
        return -1;
    }

    if (listen(passive_tcp_socket, max_connections) < 0) {
        close(passive_tcp_socket);
        return -1;
    }

    return passive_tcp_socket;
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
