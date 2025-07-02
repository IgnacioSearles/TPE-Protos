// Proxy Configuration and Tracking Protocol
// (Patent pending)

#ifndef PCTP_H
#define PCTP_H

#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "../shared/stm.h"
#include "../shared/parser.h"
#include "server_config.h"
#include "server_stats.h"

#define MAX_DATA_SIZE 256
#define INITIAL_BUFFER_SIZE 4096

#define DEFAULT_ADMIN_USER "postgres"
#define DEFAULT_ADMIN_PASS "postgres"

typedef struct pctp {
    server_config* config;
    server_stats stats;

    int client_fd;

    uint8_t read_raw_buff[INITIAL_BUFFER_SIZE];
    buffer read_buffer;

    uint8_t write_raw_buff[INITIAL_BUFFER_SIZE];
    buffer write_buffer;

    struct state_machine stm;
    
    struct fd_handler handlers;
    
    struct parser *user_parser;
    struct parser *pass_parser;
    // struct parser *stats_parser;
    struct parser *add_parser;
    // struct parser *config_parser;
    struct parser *exit_parser;

    int id;

    // Datos parseados
    char username[MAX_DATA_SIZE];
    int username_len;
    char password[MAX_DATA_SIZE];
    int password_len;

    char new_username[MAX_DATA_SIZE];
    int new_username_len;
    char new_password[MAX_DATA_SIZE];
    int new_password_len;
    int level;

} pctp;

int pctp_init(const int client_fd, fd_selector s, server_config* config, server_stats stats);

#endif
