#include <selector.h>
#include "buffer.h"
#include "stm.h"
#include <logger.h>
#include <socks5.h>
#include <server_stats.h>
#include <socks5_protocol.h>
#include <socks5_hello.h>
#include <socks5_auth.h>  
#include <socks5_request.h>
#include <socks5_copy.h>
#include <netutils.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_DATA_SIZE 256

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_close(struct selector_key *key);
static void socks5_unblock(struct selector_key *key);

static const struct state_definition client_statbl[] = {
    { .state = HELLO_READ,    .on_read_ready  = hello_read    },
    { .state = HELLO_WRITE,   .on_write_ready = hello_write   },
    { .state = AUTH_READ,     .on_read_ready  = auth_read     },
    { .state = AUTH_WRITE,    .on_write_ready = auth_write    },  
    { .state = REQUEST_READ,  .on_read_ready  = request_read  },
    { .state = REQUEST_WRITE, .on_write_ready = request_write },
    { .state = CONNECTING,    .on_block_ready = on_got_address_info   },
    { .state = AWAITING_CONNECTION, .on_write_ready = connecting_response },
    { .state = CONNECTING_RESPONSE, .on_write_ready = connected  }, 
    { .state = COPY,          .on_arrival     = copy_on_arrival,
                              .on_read_ready  = copy_read,         // Cliente → Servidor remoto
                              .on_write_ready = copy_write          }, // Buffer → Cliente
    { .state = DONE   },
    { .state = ERROR  }
};

const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_close = socks5_close,
    .handle_block = socks5_unblock
};

static const struct state_machine socks5_stm = {
    .initial   = HELLO_READ,
    .max_state = ERROR,
    .states    = client_statbl,
};

int socks5_init(const int client_fd, fd_selector s, server_config* config, server_stats stats) {
    LOG_A(LOG_DEBUG, "SOCKS5: Initializing connection (fd=%d)", client_fd);
    
    if (set_non_blocking(client_fd) < 0) {
        LOG(LOG_WARN, "SOCKS5: Failed to set non-blocking");
        return -1;
    }
    
    socks5* socks = calloc(1, sizeof(*socks));
    if (socks == NULL) {
        LOG(LOG_WARN, "SOCKS5: Failed to allocate memory");
        return -1;
    }

    socks->read_raw_buff = malloc(config->io_buffer_size * sizeof(socks->read_raw_buff[0]));
    socks->write_raw_buff = malloc(config->io_buffer_size * sizeof(socks->write_raw_buff[0]));

    if (socks->read_raw_buff == NULL || socks->write_raw_buff == NULL) {
        free(socks->read_raw_buff);
        free(socks->write_raw_buff);
        free(socks);
        LOG(LOG_WARN, "SOCKS5: Failed to allocate memory");
        return -1;
    }

    socks->client_fd = client_fd;
    socks->origin_fd = -1;
    socks->config = config;
    socks->stats = stats;
    socks->auth_ok = false;
    socks->auth_method = 0;
    socks->reply_code = SOCKS5_REP_GENERAL_FAILURE;

    buffer_init(&(socks->read_buffer), config->io_buffer_size, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), config->io_buffer_size, socks->write_raw_buff);

    socks->stm.initial   = socks5_stm.initial;
    socks->stm.max_state = socks5_stm.max_state;
    socks->stm.states    = socks5_stm.states;
    
    stm_init(&socks->stm);
    
    selector_status status;
    if ((status = selector_register(s, client_fd, &socks5_handler, OP_READ, socks)) != SELECTOR_SUCCESS) {
        LOG_A(LOG_WARN, "SOCKS5: Failed to register with selector. STATUS = %d", status);
        free(socks->read_raw_buff);
        free(socks->write_raw_buff);
        free(socks);
        return -1;
    }

    log_connection_open(stats, client_fd);
    LOG_A(LOG_DEBUG, "SOCKS5: Connection initialized successfully (fd=%d)", client_fd);

    return 0;
}

static bool is_write_state(const socks5_state state, socks5* socks) {
    return (state == HELLO_WRITE || state == AUTH_WRITE || 
            state == REQUEST_WRITE || state == CONNECTING_RESPONSE
            || (state == COPY && buffer_can_read(&socks->write_buffer)));
}

static bool is_read_state(const socks5_state state) {
    return (state == HELLO_READ || state == AUTH_READ || 
            state == REQUEST_READ || state == COPY);
}

static void set_interest_for_state(socks5_state next_state, fd_selector selector, int fd, socks5* socks) {
    fd_interest interest = OP_NOOP; 

    interest |= is_write_state(next_state, socks) ? OP_WRITE : OP_NOOP; 
    interest |= is_read_state(next_state) ? OP_READ : OP_NOOP;

    if (interest != OP_NOOP) {
        LOG_A(LOG_DEBUG, "SOCKS5: Changing selector interest to %d for fd = %d", interest, fd);
        selector_set_interest(selector, fd, interest);
    }
}

static void socks5_read(struct selector_key *key) {
    struct socks5* socks = ATTACHMENT(key);
    socks5_state next = stm_handler_read(&socks->stm, key);
    
    LOG_A(LOG_DEBUG, "SOCKS5: Read event → state %d", next);
    
    if (ERROR == next || DONE == next) {
        LOG_A(LOG_DEBUG, "SOCKS5: Terminating connection (state=%d)", next);
        selector_unregister_fd(key->s, socks->client_fd);
    } else {
        set_interest_for_state(next, key->s, socks->client_fd, socks); 
    }
}

static void socks5_write(struct selector_key *key) {
    struct socks5* socks = ATTACHMENT(key);
    socks5_state next = stm_handler_write(&socks->stm, key);
    
    LOG_A(LOG_DEBUG, "SOCKS5: Write event → state %d", next);
    
    if (ERROR == next || DONE == next) {
        LOG_A(LOG_DEBUG, "SOCKS5: Terminating connection (state=%d)", next);
        selector_unregister_fd(key->s, key->fd);
    } else {
        set_interest_for_state(next, key->s, socks->client_fd, socks); 
    }
}

static void socks5_unblock(struct selector_key *key) {
    struct socks5* socks = ATTACHMENT(key);
    socks5_state next = stm_handler_block(&socks->stm, key);

    LOG_A(LOG_DEBUG, "SOCKS5: Un-Block event → state %d", next);

    if (ERROR == next || DONE == next) {
        LOG_A(LOG_DEBUG, "SOCKS5: Terminating connection (state=%d)", next);
        selector_unregister_fd(key->s, key->fd);
    } else {
        set_interest_for_state(next, key->s, socks->client_fd, socks); 
    }
}

static void socks5_close(struct selector_key *key) {
    struct socks5* socks = ATTACHMENT(key);
    if (socks == NULL || key->fd == socks->origin_fd) {
        return;
    }
    
    LOG_A(LOG_DEBUG, "SOCKS5: Cleaning up connection (client_fd=%d, origin_fd=%d)", socks->client_fd, socks->origin_fd);
    LOG_A(LOG_DEBUG, "SOCKS5: Exit status %d", socks->reply_code);
    log_connection_close(socks->stats, socks->client_fd, socks->reply_code);

    if (socks->origin_fd >= 0) {
        LOG_A(LOG_DEBUG, "SOCKS5: Unregistering origin_fd=%d from selector", socks->origin_fd);
        selector_unregister_fd(key->s, socks->origin_fd);
        close(socks->origin_fd);
        socks->origin_fd = -1;
    }
    
    if (socks->client_fd >= 0) {
        close(socks->client_fd);
        socks->client_fd = -1;
    }
    free(socks->read_raw_buff);
    free(socks->write_raw_buff);
    free(socks);
}

