#include "pctp_auth.h"
#include "pctp_protocol.h"
#include "pctp_parser_tables.h"
#include "../../shared/logger.h"
#include "../../shared/parser.h"
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

// Includes para macOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

unsigned login_user_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    size_t available = 0;
    uint8_t* ptr = buffer_write_ptr(read_buffer, &available);
    ssize_t n = recv(pctp_data->client_fd, ptr, available, MSG_NOSIGNAL);
    if (n <= 0) {
        return LOGIN_USER_READ;
    }

    buffer_write_adv(read_buffer, n);

    LOG_A(LOG_DEBUG, "Received %ld bytes in LOGIN_USER_READ", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->user_parser, c);
        if (e->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "User parser succeded");
            LOG_A(LOG_DEBUG, "Username: %.*s", pctp_data->username_len, pctp_data->username);

            pctp_data->id = check_admin_username(pctp_data);
            if (pctp_data->id != -1) {
                LOG(LOG_DEBUG, "Username is correct");
                write_msg_to_buffer(&pctp_data->write_buffer, OK_USER_MSG);
                return LOGIN_USER_SUCCESS_WRITE;
            }
            LOG(LOG_DEBUG, "Username is incorrect");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_USER_MSG);
            return LOGIN_USER_INVALID_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "User parser failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return LOGIN_USER_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->username_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->username[pctp_data->username_len++] = c;
        }
    }

    return LOGIN_USER_READ;
}

unsigned login_user_success_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return LOGIN_PASS_READ;
        case MSG_SEND_BLOCKED: return LOGIN_USER_SUCCESS_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned login_user_invalid_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return LOGIN_USER_READ;
        case MSG_SEND_BLOCKED: return LOGIN_USER_INVALID_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned login_user_error_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return LOGIN_USER_READ;
        case MSG_SEND_BLOCKED: return LOGIN_USER_ERROR_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned login_pass_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    size_t available = 0;
    uint8_t* ptr = buffer_write_ptr(read_buffer, &available);
    ssize_t n = recv(pctp_data->client_fd, ptr, available, MSG_NOSIGNAL);
    if (n <= 0) {
        return LOGIN_PASS_READ;
    }

    buffer_write_adv(read_buffer, n);

    LOG_A(LOG_DEBUG, "Received %ld bytes in LOGIN_PASS_READ", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->pass_parser, c);
        if (e->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Pass parser succeded");
            LOG_A(LOG_DEBUG, "Password: %.*s", pctp_data->password_len, pctp_data->password);

            int id = check_admin_password(pctp_data);
            if (id != -1) {
                LOG(LOG_DEBUG, "Password is correct");
                write_msg_to_buffer(&pctp_data->write_buffer, OK_PASS_MSG);
                return MAIN_WRITE;
            }
            LOG(LOG_DEBUG, "Password is incorrect");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_PASS_MSG);
            return LOGIN_PASS_INVALID_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "Pass parser failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return LOGIN_PASS_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->password_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->password[pctp_data->password_len++] = c;
        }
    }

    return LOGIN_PASS_READ;
}

unsigned login_pass_invalid_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return LOGIN_PASS_READ;
        case MSG_SEND_BLOCKED: return LOGIN_PASS_INVALID_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

unsigned login_pass_error_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return LOGIN_PASS_READ;
        case MSG_SEND_BLOCKED: return LOGIN_PASS_ERROR_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

void reset_user_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->user_parser);
    pctp_data->username_len = 0;
}

void reset_pass_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->pass_parser);
    pctp_data->password_len = 0;
}

int check_admin_username(pctp* pctp_data) {
    for(int i=0; i<pctp_data->config->user_count; i++) {
        server_user user = pctp_data->config->users[i];
        if (user.role != ADMIN) continue;
        int name_len = strlen(user.user);
        if (pctp_data->username_len == name_len && strncmp(pctp_data->username, user.user, name_len) == 0) 
            return i;
    }
    return -1;
}

int check_admin_password(pctp* pctp_data) {
    if (pctp_data->id == -1 || pctp_data->id >= pctp_data->config->user_count) return -1;
    server_user user = pctp_data->config->users[pctp_data->id];
    if (user.role != ADMIN) return -1;
    int pass_len = strlen(user.pass);
    if (pctp_data->password_len != pass_len) return -1;
    if (strncmp(pctp_data->password, user.pass, pass_len) != 0) return -1;
    return pctp_data->id;
}
