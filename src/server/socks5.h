#ifndef SOCKS5_H
#define SOCKS5_H

#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "../shared/stm.h"
#include "../shared/parser.h"

#define MAX_DATA_SIZE 256
#define INITIAL_BUFFER_SIZE 4096

enum socks5_states {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_WRITE,
    CONNECTING,
    FORWARDING,
    DONE,
    ERROR,
};

typedef struct socks5 {
    int client_fd;
    int origin_fd;

    uint8_t read_raw_buff[INITIAL_BUFFER_SIZE];
    buffer read_buffer;

    uint8_t write_raw_buff[INITIAL_BUFFER_SIZE];
    buffer write_buffer;

    uint8_t origin_raw_buff[INITIAL_BUFFER_SIZE];
    buffer origin_buffer;

    struct state_machine stm;

    struct parser *hello_parser;
    struct parser *auth_parser;
    struct parser *request_parser;

    // Datos parseados
    char username[MAX_DATA_SIZE];
    char password[MAX_DATA_SIZE];
    char dest_addr[MAX_DATA_SIZE];
    uint16_t dest_port;

} socks5;

int socks5_init(const int client_fd, fd_selector s);

#endif
