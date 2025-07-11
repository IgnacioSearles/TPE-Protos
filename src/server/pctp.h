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

#define INITIAL_BUFFER_SIZE 4096
#define MAX_CREDENTIAL_SIZE 24
#define MAX_MSG_SIZE 1024
#define MAX_LOGS_DIGITS 24
#define MAX_LOGS_TO_SEND 100
#define DEFAULT_LOGS_TO_SEND 10

#define DEFAULT_ADMIN_USER "username"
#define DEFAULT_ADMIN_PASS "password"

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
    struct parser *stats_parser;
    struct parser *logs_parser;
    struct parser *add_parser;
    struct parser *del_parser;
    struct parser *list_parser;
    // struct parser *config_parser;
    struct parser *exit_parser;

    int id;

    // Datos parseados
    char username[MAX_CREDENTIAL_SIZE];
    int username_len;
    char password[MAX_CREDENTIAL_SIZE];
    int password_len;

    char new_username[MAX_CREDENTIAL_SIZE];
    int new_username_len;
    char new_password[MAX_CREDENTIAL_SIZE];
    int new_password_len;
    int level;

    char del_username[MAX_CREDENTIAL_SIZE];
    int del_username_len;

    char logs_n[MAX_LOGS_DIGITS+1];
    int logs_n_len;
} pctp;

int pctp_init(const int client_fd, fd_selector s, server_config* config, server_stats stats);

#endif
