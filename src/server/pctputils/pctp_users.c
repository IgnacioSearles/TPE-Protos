#include "pctp_users.h"
#include "pctp_protocol.h"
#include "pctp_parser_tables.h"
#include "../../shared/logger.h"
#include "../../shared/parser.h"
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

// Includes para macOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

unsigned add_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return ADD_USER_READ;
        case MSG_SEND_BLOCKED: return ADD_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned add_user_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->user_parser, c);
        if (e->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "User parser succeded");
            LOG_A(LOG_DEBUG, "Username: %.*s", pctp_data->new_username_len, pctp_data->new_username);

            pctp_data->id = check_new_username(pctp_data);
            if (pctp_data->new_username_len > 0 && pctp_data->id == -1) {
                LOG(LOG_DEBUG, "New username is valid");
                write_msg_to_buffer(&pctp_data->write_buffer, OK_USER_MSG);
                return ADD_USER_SUCCESS_WRITE;
            }
            LOG(LOG_DEBUG, "Username already exists");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_USER_MSG);
            return ADD_USER_INVALID_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "User parser failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return ADD_USER_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->new_username_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->new_username[pctp_data->new_username_len++] = c;
        }
    }

    selector_set_interest_key(key, OP_READ);
    return ADD_USER_READ;
}

unsigned add_user_success_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return ADD_PASS_READ;
        case MSG_SEND_BLOCKED: return ADD_USER_SUCCESS_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned add_user_invalid_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return ADD_USER_READ;
        case MSG_SEND_BLOCKED: return ADD_USER_INVALID_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned add_user_error_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return ADD_USER_READ;
        case MSG_SEND_BLOCKED: return ADD_USER_ERROR_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned add_pass_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->pass_parser, c);
        if (e->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Pass parser succeded");
            LOG_A(LOG_DEBUG, "Password: %.*s", pctp_data->new_password_len, pctp_data->new_password);
            LOG(LOG_DEBUG, "Password set");
            
            char* new_user = malloc(sizeof(char) * (pctp_data->new_username_len+1));
            char* new_pass = malloc(sizeof(char) * (pctp_data->new_password_len+1));
            if (new_user == NULL || new_pass == NULL) {
                free(new_user);
                free(new_pass);
                LOG(LOG_DEBUG, "Could not add credentials");
                write_msg_to_buffer(&pctp_data->write_buffer, ERR_OOM_MSG);
                return ADD_PASS_ERROR_WRITE;
            }
            strncpy(new_user, pctp_data->new_username, pctp_data->new_username_len);
            new_user[pctp_data->new_username_len] = 0;

            strncpy(new_pass, pctp_data->new_password, pctp_data->new_password_len);
            new_pass[pctp_data->new_password_len] = 0;

            add_user(pctp_data->config, new_user, new_pass, pctp_data->level);
            LOG(LOG_DEBUG, "Added new user credentials");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_ADD_PASS_MSG);
            return MAIN_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "Pass parser failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return ADD_PASS_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->new_password_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->new_password[pctp_data->new_password_len++] = c;
        }
    }

    selector_set_interest_key(key, OP_READ);
    return ADD_PASS_READ;
}

unsigned add_pass_error_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return ADD_PASS_READ;
        case MSG_SEND_BLOCKED: return ADD_PASS_ERROR_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

void reset_add_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->add_parser);
    reset_new_user_state(state, key);
    reset_new_pass_state(state, key);
}

void reset_new_user_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->user_parser);
    pctp_data->new_username_len = 0;
}

void reset_new_pass_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->pass_parser);
    pctp_data->new_password_len = 0;
}

int check_new_username(pctp* pctp_data) {
    for(int i=0; i<pctp_data->config->user_count; i++) {
        server_user user = pctp_data->config->users[i];
        int name_len = strlen(user.user);
        if (pctp_data->new_username_len == name_len && strncmp(pctp_data->new_username, user.user, name_len) == 0) 
            return i;
    }
    return -1;
}
