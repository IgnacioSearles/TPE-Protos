#ifndef SOCKS5_H
#define SOCKS5_H

#include "../shared/stm.h"
#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "server_config.h"
#include "server_stats.h"
#include <netinet/in.h>

#define INITIAL_BUFFER_SIZE 4096
#define MAX_DATA_SIZE 256

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

typedef enum socks5_state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    CONNECTING,
    AWAITING_CONNECTION,
    CONNECTING_RESPONSE,
    COPY,
    DONE,
    ERROR,
} socks5_state;

typedef struct {
    uint8_t version;
    uint8_t cmd;
    uint8_t atyp;
    char target_host[MAX_DATA_SIZE];
    uint16_t target_port;
} parsed_request;

typedef struct socks5 {
    int client_fd;
    int origin_fd;
    
    socks5_state state;
    struct state_machine stm;
    
    buffer read_buffer;
    buffer write_buffer;
    
    uint8_t read_raw_buff[INITIAL_BUFFER_SIZE];
    uint8_t write_raw_buff[INITIAL_BUFFER_SIZE];
    
    server_config* config;
    server_stats stats;
    
    uint8_t auth_method;
    bool auth_ok;
    
    char target_host[MAX_DATA_SIZE];
    uint16_t target_port;
    uint8_t target_atyp;
    uint8_t reply_code;

    struct addrinfo *res;
} socks5;

int socks5_init(const int client_fd, fd_selector s, server_config* config, server_stats stats);

#endif
