#include "socks5.h"
#include "buffer.h"
#include "selector.h"
#include "stm.h"
#include "parser.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_close(struct selector_key *key);

// @Neich llamar cuando se acepta una conexión SOCKS5
void socks5_init(const int client_fd, fd_selector s) {
    socks5* socks = malloc(sizeof(*socks));
    if (socks == NULL) abort();

    socks->client_fd = client_fd;
    socks->origin_fd = -1;

    socks->stm.initial = HELLO_READ;
    socks->stm.max_state = ERROR;

    buffer_init(&(socks->read_buffer), INITIAL_BUFFER_SIZE, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), INITIAL_BUFFER_SIZE, socks->write_raw_buff);
    buffer_init(&(socks->origin_buffer), INITIAL_BUFFER_SIZE, socks->origin_raw_buff);

    // TODO: debes definir estos parser_definition reales
    // socks->hello_parser = parser_init(); 
    // socks->auth_parser = parser_init();
    // socks->request_parser = parser_init();

    stm_init(&socks->stm);

    const struct fd_handler handler = {
        .handle_read  = socks5_read,
        .handle_write = socks5_write,
        .handle_close = socks5_close,
    };

    selector_register(s, client_fd, &handler, OP_READ, socks);
}

static void socks5_read(struct selector_key *key) {
    struct socks5 *socks = key->data;
    stm_handler_read(&socks->stm, key);
}

static void socks5_write(struct selector_key *key) {
    struct socks5 *socks = key->data;
    stm_handler_write(&socks->stm, key);
}

static void socks5_close(struct selector_key *key) {
    struct socks5 *socks = key->data;
    stm_handler_close(&socks->stm, key);
}