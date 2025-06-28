#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include "buffer.h"
#include "selector.h"
#include "netutils.h"

#define BUFFER_SIZE 4096

static fd_selector selector;
static int client_fd = -1;

static uint8_t r_data[BUFFER_SIZE], w_data[BUFFER_SIZE];
static buffer read_buffer, write_buffer;

struct client_data {
    buffer *read_buffer;
    buffer *write_buffer;
};

static void client_read(struct selector_key *key) {
    struct client_data *data = key->data;
    buffer *b = data->read_buffer;
    size_t bytes;
    uint8_t *ptr = buffer_write_ptr(b, &bytes);
    ssize_t n = recv(key->fd, ptr, bytes, 0);

    if (n <= 0) {
        selector_unregister_fd(key->s, key->fd);
        close(key->fd);
        return;
    }

    buffer_write_adv(b, n);
    size_t to_read;
    uint8_t *msg = buffer_read_ptr(b, &to_read);
    fwrite(msg, 1, to_read, stdout);
    buffer_read_adv(b, to_read);
}

static void client_write(struct selector_key *key) {
    struct client_data *data = key->data;
    buffer *b = data->write_buffer;
    if (!buffer_can_read(b)) return;
    sock_blocking_write(key->fd, b);
    if (!buffer_can_read(b)) {
        selector_set_interest(key->s, key->fd, OP_READ);
    }
}

static void stdin_read(struct selector_key *key) {
    struct client_data *data = key->data;
    buffer *b = data->write_buffer;
    size_t bytes;
    uint8_t *ptr = buffer_write_ptr(b, &bytes);
    ssize_t n = read(STDIN_FILENO, ptr, bytes);

    if (n <= 0) {
        selector_unregister_fd(key->s, STDIN_FILENO);
        return;
    }

    buffer_write_adv(b, n);
    selector_set_interest(key->s, client_fd, OP_WRITE);
}

int connect_to_server(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
    int sfd;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }

    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sfd);
        sfd = -1;
    }

    freeaddrinfo(res);
    return sfd;
}

int main(int argc, char *argv[]) {
    char *host = NULL, *port = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "h:p:")) != -1) {
        switch (opt) {
            case 'h': host = optarg; break;
            case 'p': port = optarg; break;
            default:
                fprintf(stderr, "Uso: %s -h <host> -p <puerto>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!host || !port) {
        fprintf(stderr, "Faltan argumentos obligatorios.\n");
        exit(EXIT_FAILURE);
    }

    client_fd = connect_to_server(host, port);
    if (client_fd == -1) {
        perror("connect");
        exit(EXIT_FAILURE);
    }
    set_non_blocking(client_fd);
    set_non_blocking(STDIN_FILENO);

    buffer_init(&read_buffer, BUFFER_SIZE, r_data);
    buffer_init(&write_buffer, BUFFER_SIZE, w_data);
    struct client_data data = { &read_buffer, &write_buffer };

    selector_init(&(struct selector_init){
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    });

    selector = selector_new(1024);
    if (selector == NULL) {
        perror("selector_new");
        exit(EXIT_FAILURE);
    }

    const fd_handler client_handler = {
        .handle_read = client_read,
        .handle_write = client_write,
    };
    selector_register(selector, client_fd, &client_handler, OP_READ, &data);

    const fd_handler stdin_handler = {
        .handle_read = stdin_read,
    };
    selector_register(selector, STDIN_FILENO, &stdin_handler, OP_READ, &data);

    while (1) {
        selector_select(selector);
    }

    selector_destroy(selector);
    close(client_fd);
    return 0;
}