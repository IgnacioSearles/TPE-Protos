#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "../shared/netutils.h"
#include "client_params.h"
#include <logger.h>

#define BUFFER_SIZE 4096
#define MAX_SELECTOR_FDS 2

static volatile bool done = false;
void handle_shutdown(int sig) {
    done = true;
}

struct client_data {
    int server_fd;
    volatile bool* done;
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
        *data->done = true;
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
    selector_set_interest(key->s, data->server_fd, OP_WRITE);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_shutdown);  // Ctrl+C
    signal(SIGTERM, handle_shutdown); // kill pid
    
    client_config config = {
        .host = NULL, 
        .port = NULL,
        .log_level = NULL
    };

    if (client_params_parse(argc, argv, &config) < 0) {
        client_config_destroy(&config);
        return EXIT_FAILURE;
    }

    logger_set_level(config.log_level);

    int server_fd = connect_to_host(config.host, config.port);
    if (server_fd < 0) {
        LOG(LOG_ERROR, "client error: could not connect");
        client_config_destroy(&config);
        return EXIT_FAILURE;
    }

    set_non_blocking(STDIN_FILENO);

    uint8_t r_data[BUFFER_SIZE], w_data[BUFFER_SIZE];
    buffer read_buffer, write_buffer;

    buffer_init(&read_buffer, BUFFER_SIZE, r_data);
    buffer_init(&write_buffer, BUFFER_SIZE, w_data);
    struct client_data data = { 
        .server_fd = server_fd,
        .done = &done,
        .read_buffer = &read_buffer, 
        .write_buffer = &write_buffer 
    };

    struct selector_init selector_config = {
        .signal = SIGALRM,
        .select_timeout = { .tv_sec = 10, .tv_nsec = 0 },
    };

    if (selector_init(&selector_config) != SELECTOR_SUCCESS) {
        LOG(LOG_ERROR, "client error: could not init selector library");
        client_config_destroy(&config);
        close(server_fd);
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_SELECTOR_FDS);
    if (selector == NULL) {
        LOG(LOG_ERROR, "client error: could not create selector");
        close(server_fd);
        client_config_destroy(&config);
        return EXIT_FAILURE;
    }

    const fd_handler client_handler = {
        .handle_read = client_read,
        .handle_write = client_write,
    };
    if (selector_register(selector, server_fd, &client_handler, OP_READ, &data) != SELECTOR_SUCCESS) {
        LOG(LOG_ERROR, "client error: could not register server fd");
        close(server_fd);
        client_config_destroy(&config);
        selector_destroy(selector);
        return EXIT_FAILURE;
    }

    const fd_handler stdin_handler = {
        .handle_read = stdin_read,
    };
    if (selector_register(selector, STDIN_FILENO, &stdin_handler, OP_READ, &data) != SELECTOR_SUCCESS) {
        LOG(LOG_ERROR, "client error: could not register stdin fd");
        close(server_fd);
        client_config_destroy(&config);
        selector_destroy(selector);
        return EXIT_FAILURE;
    }

    while (!done) {
        selector_status status = selector_select(selector);
        if (status != SELECTOR_SUCCESS) {
            break;
        }
    }

    client_config_destroy(&config);
    selector_destroy(selector);
    close(server_fd);
    return 0;
}
