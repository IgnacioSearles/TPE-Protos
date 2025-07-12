#ifndef PCTP_PROTOCOL_H
#define PCTP_PROTOCOL_H

#include "buffer.h"

#define OK_USER_MSG "+OK Please send password\n"
#define OK_PASS_MSG "+OK Succesfully logged in\n"
#define OK_STATS_MSG "+OK Sending stats...\n"
#define OK_LOGS_MSG "+OK Sending logs...\n"
#define OK_IO_CONFIG_MSG "+OK Setting IO buffers size\n"
#define OK_ADD_MSG "+OK Please provide new user credentials\n"
#define OK_ADD_PASS_MSG "+OK Succesfully added user\n"
#define OK_DEL_MSG "+OK Succesfully deleted user\n"
#define OK_LIST_MSG "+OK Sending user list...\n"
#define OK_DONE_MSG "+OK Done\n"

#define CURRENT_CONNECTIONS_MSG "current_connections: %ld\n"
#define TOTAL_CONNECTIONS_MSG "total_connections: %ld\n"
#define CURRENT_BYTES_PROXIED_MSG "current_bytes_proxied: %ld\n"
#define TOTAL_BYTES_PROXIED_MSG "total_bytes_proxied: %ld\n"
#define LOG_ENTRY_MSG "%d-%02d-%02dT%02d:%02d:%02dZ\t%s\tA\t%s\t%d\t%s\t%d\t%d\t%ld\t%s\n"
#define USER_ENTRY_MSG "%s\t%s\n"
#define EMPTY_MSG "\n"

#define ERR_INVALID_USER_MSG "-ERR Invalid username\n"
#define ERR_INVALID_PASS_MSG "-ERR Invalid password\n"
#define ERR_DEL_MSG "-ERR Could not delete user\n"
#define ERR_INVALID_COMMAND_MSG "-ERR Invalid command for current state\n"
#define ERR_OOM_MSG "-ERR Out of memory\n"

enum pctp_states {
    LOGIN_USER_READ,
    LOGIN_USER_SUCCESS_WRITE,
    LOGIN_USER_INVALID_WRITE,
    LOGIN_USER_ERROR_WRITE,
    LOGIN_PASS_READ,
    LOGIN_PASS_INVALID_WRITE,
    LOGIN_PASS_ERROR_WRITE,
    MAIN_READ,
    MAIN_WRITE,
    ADD_WRITE,
    ADD_USER_READ,
    ADD_USER_SUCCESS_WRITE,
    ADD_USER_INVALID_WRITE,
    ADD_USER_ERROR_WRITE,
    ADD_PASS_READ,
    ADD_PASS_ERROR_WRITE,
    // CONFIG,
    EXIT_WRITE,
    DONE,
    ERROR,
};

enum msg_send {
    MSG_SENT,
    MSG_SEND_BLOCKED,
    MSG_SEND_ERROR
};

void write_msg_to_buffer(buffer* write_buffer, const char* msg);
int send_buffer_msg(int fd, buffer* write_buffer);

#endif