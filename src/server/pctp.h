// Proxy Configuration and Tracking Protocol
// (Patent pending)

#ifndef PCTP_H
#define PCTP_H

#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "../shared/stm.h"
#include "../shared/parser.h"

#define MAX_DATA_SIZE 256
#define INITIAL_BUFFER_SIZE 4096

typedef struct pctp {
    char pctp_username[MAX_DATA_SIZE];
    int pctp_username_len;
    char pctp_password[MAX_DATA_SIZE];
    int pctp_password_len;
    int client_fd;

    uint8_t read_raw_buff[INITIAL_BUFFER_SIZE];
    buffer read_buffer;

    uint8_t write_raw_buff[INITIAL_BUFFER_SIZE];
    buffer write_buffer;

    struct state_machine stm;
    
    struct fd_handler handlers;
    
    struct parser *user_parser;
    struct parser *pass_parser;
    struct parser *main_parser;
    struct parser *stats_parser;
    struct parser *add_user_parser;
    struct parser *config_parser;
    struct parser *exit_parser;

    // Datos parseados
    char username[MAX_DATA_SIZE];
    int username_len;
    char password[MAX_DATA_SIZE];
    int password_len;
    char new_username[MAX_DATA_SIZE];
    int new_username_len;
    char new_password[MAX_DATA_SIZE];
    int new_password_len;

} pctp;

int pctp_init(const int client_fd, fd_selector s, char* pctp_username, char* pctp_password);

#endif
