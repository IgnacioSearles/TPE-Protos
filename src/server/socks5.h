#ifndef SOCKS5_H
#define SOCKS5_H

#include "../shared/stm.h"
#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "server_config.h"

#define INITIAL_BUFFER_SIZE 4096

typedef enum socks5_state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    COPY,
    DONE,
    ERROR,
} socks5_state;

typedef struct socks5 {
    int client_fd;
    int origin_fd;
    
    socks5_state state;  // Estado simple en lugar de STM
    
    buffer read_buffer;
    buffer write_buffer;
    
    uint8_t read_raw_buff[INITIAL_BUFFER_SIZE];
    uint8_t write_raw_buff[INITIAL_BUFFER_SIZE];
    
    server_config* config;
    
    uint8_t auth_method;
    bool auth_ok;
    
} socks5;

int socks5_init(const int client_fd, fd_selector s, server_config* config);

#endif
