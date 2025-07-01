#include "socks5.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define VERSION_5 0x05
#define METHOD_USER_PASS 0x02

#define HELLO_FINISHED 42

static unsigned hello_read(struct selector_key *key);
static unsigned hello_write(struct selector_key *key);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static unsigned connect_done(struct selector_key *key);
static unsigned forward(struct selector_key *key);
static void on_close(const unsigned state, struct selector_key *key);

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_close(struct selector_key *key);


static const struct state_definition states[] = {
    { .state = HELLO_READ,   .on_read_ready = hello_read },
    { .state = HELLO_WRITE,  .on_write_ready = hello_write },
    { .state = AUTH_READ,    .on_read_ready = auth_read },
    { .state = AUTH_WRITE,   .on_write_ready = auth_write },
    { .state = REQUEST_READ, .on_read_ready = request_read },
    { .state = REQUEST_WRITE,.on_write_ready = request_write },
    { .state = CONNECTING,   .on_write_ready = connect_done },
    { .state = FORWARDING,   .on_read_ready = forward, .on_write_ready = forward },
    { .state = DONE,         .on_departure = on_close },
    { .state = ERROR,        .on_departure = on_close },
};

// @Neich llamar cuando se acepta una conexión SOCKS5
int socks5_init(const int client_fd, fd_selector s) {
    socks5* socks = malloc(sizeof(*socks));
    if (socks == NULL) {
        close(client_fd);
        return -1;
    }

    socks->client_fd = client_fd;
    socks->origin_fd = -1;

    socks->stm.initial = HELLO_READ;
    socks->stm.max_state = ERROR;
    socks->stm.states = states;

    buffer_init(&(socks->read_buffer), INITIAL_BUFFER_SIZE, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), INITIAL_BUFFER_SIZE, socks->write_raw_buff);
    buffer_init(&(socks->origin_buffer), INITIAL_BUFFER_SIZE, socks->origin_raw_buff);

    // TODO: definir estos parsers inits
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

    return 0;
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

static unsigned hello_read(struct selector_key *key) {
    struct socks5 *socks = key->data;
    buffer* b = &socks->read_buffer;

    uint8_t* ptr;
    size_t count = 0;

    ptr = buffer_write_ptr(b, &count);
    ssize_t n = recv(socks->client_fd, ptr, count, MSG_NOSIGNAL);
    if (n <= 0) {
        return ERROR;
    }

    buffer_write_adv(b, n);

    printf("Received %ld bytes in HELLO_READ\n", n);

    while (buffer_can_read(b)) {
        uint8_t c = buffer_read(b);
        const struct parser_event* e = parser_feed(socks->hello_parser, c);
        if (e->type == HELLO_FINISHED) {
            printf("Hello parser done!\n");
            return HELLO_WRITE;
        }
    }

    return HELLO_READ;
}

static unsigned hello_write(struct selector_key *key) {
    struct socks5* socks = key->data;

    uint8_t response[2] = { VERSION_5, METHOD_USER_PASS };

    ssize_t n = send(socks->client_fd, response, sizeof(response), MSG_NOSIGNAL);
    if (n <= 0) {
        return ERROR;
    }

    printf("Sent HELLO_REPLY\n");

    return AUTH_READ;
}


static void on_close(const unsigned state, struct selector_key *key) {
    struct socks5* socks = key->data;
    if (socks->client_fd >= 0) close(socks->client_fd);
    if (socks->origin_fd >= 0) close(socks->origin_fd);
    free(socks);
    printf("Closed SOCKS5 session.\n");
}

// Para que compile
static unsigned auth_read(struct selector_key *key)   { return ERROR; }
static unsigned auth_write(struct selector_key *key)  { return ERROR; }
static unsigned request_read(struct selector_key *key){ return ERROR; }
static unsigned request_write(struct selector_key *key){ return ERROR; }
static unsigned connect_done(struct selector_key *key){ return ERROR; }
static unsigned forward(struct selector_key *key)     { return ERROR; }
