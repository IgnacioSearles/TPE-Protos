#include "pctp.h"
#include "./pctputils/pctp_parser_tables.h"
#include "logger.h"
#include "server_stats.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Includes para macOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define OK_USER_MSG "+OK Please send password\n"
#define OK_PASS_MSG "+OK Succesfully logged in\n"
#define OK_STATS_MSG "+OK Sending stats...\n"
#define OK_LOGS_MSG "+OK Sending logs...\n"
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

static unsigned login_user_read(struct selector_key *key);
static void reset_user_state(const unsigned state, struct selector_key *key);

static unsigned login_user_success_write(struct selector_key *key);
static unsigned login_user_invalid_write(struct selector_key *key);
static unsigned login_user_error_write(struct selector_key *key);

static unsigned login_pass_read(struct selector_key *key);
static void reset_pass_state(const unsigned state, struct selector_key *key);

static unsigned login_pass_invalid_write(struct selector_key *key);
static unsigned login_pass_error_write(struct selector_key *key);

static unsigned main_read(struct selector_key *key);
static void reset_main_state(const unsigned state, struct selector_key *key);
static void reset_logs_state(const unsigned state, struct selector_key *key);
static void reset_add_state(const unsigned state, struct selector_key *key);
static void reset_del_state(const unsigned state, struct selector_key *key);

static unsigned main_write(struct selector_key *key);

static unsigned add_write(struct selector_key *key);

static unsigned add_user_read(struct selector_key *key);
static void reset_new_user_state(const unsigned state, struct selector_key *key);

static unsigned add_user_success_write(struct selector_key *key);
static unsigned add_user_invalid_write(struct selector_key *key);
static unsigned add_user_error_write(struct selector_key *key);

static unsigned add_pass_read(struct selector_key *key);
static void reset_new_pass_state(const unsigned state, struct selector_key *key);

static unsigned add_pass_error_write(struct selector_key *key);

static unsigned exit_write(struct selector_key *key);

static void selector_set_interest_read(const unsigned state, struct selector_key *key);
static void selector_set_interest_write(const unsigned state, struct selector_key *key);

static void on_close(const unsigned state, struct selector_key *key);

static void pctp_read(struct selector_key *key);
static void pctp_write(struct selector_key *key);
static void pctp_close(struct selector_key *key);

static int check_new_username(pctp* pctp_data);
static int check_admin_username(pctp* pctp_data);
static int check_admin_password(pctp* pctp_data);

enum msg_send {
    MSG_SENT,
    MSG_SEND_BLOCKED,
    MSG_SEND_ERROR
};

static void write_msg_to_buffer(buffer* write_buffer, const char* msg);
static int send_buffer_msg(int fd, buffer* write_buffer);

static const struct state_definition states[] = {
    { .state = LOGIN_USER_READ,             .on_arrival = selector_set_interest_read, .on_read_ready = login_user_read },
    { .state = LOGIN_USER_SUCCESS_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_user_success_write },
    { .state = LOGIN_USER_INVALID_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_user_invalid_write, .on_departure = reset_user_state },
    { .state = LOGIN_USER_ERROR_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = login_user_error_write, .on_departure = reset_user_state },
    { .state = LOGIN_PASS_READ,             .on_arrival = selector_set_interest_read, .on_read_ready = login_pass_read },
    { .state = LOGIN_PASS_INVALID_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_invalid_write, .on_departure = reset_pass_state },
    { .state = LOGIN_PASS_ERROR_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_error_write, .on_departure = reset_pass_state },
    { .state = MAIN_READ,                   .on_arrival = selector_set_interest_read, .on_read_ready = main_read },
    { .state = MAIN_WRITE,            .on_arrival = selector_set_interest_write, .on_write_ready = main_write, .on_departure = reset_main_state },
    { .state = ADD_WRITE,                   .on_arrival = selector_set_interest_write, .on_write_ready = add_write, .on_departure = reset_main_state },
    { .state = ADD_USER_READ,               .on_arrival = selector_set_interest_read, .on_read_ready = add_user_read },
    { .state = ADD_USER_SUCCESS_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = add_user_success_write },
    { .state = ADD_USER_INVALID_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = add_user_invalid_write, .on_departure = reset_new_user_state },
    { .state = ADD_USER_ERROR_WRITE,        .on_arrival = selector_set_interest_write, .on_write_ready = add_user_error_write, .on_departure = reset_new_user_state },
    { .state = ADD_PASS_READ,               .on_arrival = selector_set_interest_read, .on_read_ready = add_pass_read },
    { .state = ADD_PASS_ERROR_WRITE,        .on_arrival = selector_set_interest_write, .on_write_ready = add_pass_error_write, .on_departure = reset_new_pass_state },
    // { .state = CONFIG, },
    { .state = EXIT_WRITE,                  .on_arrival = selector_set_interest_write, .on_write_ready = exit_write, .on_departure = reset_main_state },
    { .state = DONE,                        .on_arrival = on_close },
    { .state = ERROR,                       .on_arrival = on_close },
};

static unsigned int parser_classes[0xFF] = {0};

int pctp_init(const int client_fd, fd_selector selector, server_config* config, server_stats stats) {
    pctp* pctp_data = malloc(sizeof(*pctp_data));
    if (pctp_data == NULL) return -1;

    pctp_data->config = config;
    pctp_data->stats = stats;
    if (admin_count(config) == 0) {
        add_user(config, DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, ADMIN);
    }

    pctp_data->client_fd = client_fd;

    pctp_data->stm.initial = LOGIN_USER_READ;
    pctp_data->stm.max_state = ERROR;
    pctp_data->stm.states = states;

    buffer_init(&(pctp_data->read_buffer), INITIAL_BUFFER_SIZE, pctp_data->read_raw_buff);
    buffer_init(&(pctp_data->write_buffer), INITIAL_BUFFER_SIZE, pctp_data->write_raw_buff);

    for (int c = 'a'; c <= 'z'; c++){
        parser_classes[c] |= CLASS_ALNUM;
    }
    for (int c = 'A'; c <= 'Z'; c++){
        parser_classes[c] |= CLASS_ALNUM;
    }
    for (int c = '0'; c <= '9'; c++){
        parser_classes[c] |= CLASS_ALNUM;
        parser_classes[c] |= CLASS_NUM;
    }

    // TODO: init parsers
    pctp_data->user_parser = parser_init(parser_classes, &user_parser_def);
    pctp_data->pass_parser = parser_init(parser_classes, &pass_parser_def);
    pctp_data->stats_parser = parser_init(parser_no_classes(), &stats_parser_def);
    pctp_data->logs_parser = parser_init(parser_classes, &logs_parser_def);
    pctp_data->add_parser = parser_init(parser_no_classes(), &add_parser_def);
    pctp_data->del_parser = parser_init(parser_classes, &del_parser_def);
    pctp_data->list_parser = parser_init(parser_no_classes(), &list_parser_def);
    // pctp_data->config_parser = parser_init();
    pctp_data->exit_parser = parser_init(parser_no_classes(), &exit_parser_def);

    stm_init(&pctp_data->stm);

    pctp_data->handlers.handle_read  = pctp_read;
    pctp_data->handlers.handle_write = pctp_write;
    pctp_data->handlers.handle_close = pctp_close;

    selector_register(selector, client_fd, &pctp_data->handlers, OP_READ, pctp_data);

    pctp_data->username_len = 0;
    pctp_data->password_len = 0;
    pctp_data->new_username_len = 0;
    pctp_data->new_password_len = 0;
    pctp_data->logs_n_len = 0;
    
    return 0;
}

static void pctp_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_read(&pctp_data->stm, key);
}

static void pctp_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_write(&pctp_data->stm, key);
}

static void pctp_close(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_close(&pctp_data->stm, key);
}

static void selector_set_interest_read(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}

static void selector_set_interest_write(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_WRITE);
}

static unsigned login_user_read(struct selector_key *key) {
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

static void reset_user_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->user_parser);
    pctp_data->username_len = 0;
}

static unsigned login_pass_read(struct selector_key *key) {
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

static void reset_pass_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->pass_parser);
    pctp_data->password_len = 0;
}

static void write_stats_to_buffer(buffer* write_buffer, server_stats stats) {
    char current_connections[MAX_MSG_SIZE];
    char total_connections[MAX_MSG_SIZE];
    char current_bytes_proxied[MAX_MSG_SIZE];
    char total_bytes_proxied[MAX_MSG_SIZE];
    sprintf(current_connections, CURRENT_CONNECTIONS_MSG, get_active_connection_count(stats));
    sprintf(total_connections, TOTAL_CONNECTIONS_MSG, get_total_connection_count(stats));
    sprintf(current_bytes_proxied, CURRENT_BYTES_PROXIED_MSG, get_current_connections_bytes_proxied(stats));
    sprintf(total_bytes_proxied, TOTAL_BYTES_PROXIED_MSG, get_total_bytes_proxied(stats));
    write_msg_to_buffer(write_buffer, current_connections);
    write_msg_to_buffer(write_buffer, total_connections);
    write_msg_to_buffer(write_buffer, current_bytes_proxied);
    write_msg_to_buffer(write_buffer, total_bytes_proxied);
    write_msg_to_buffer(write_buffer, EMPTY_MSG);
}

static int get_logs_to_send(pctp *pctp_data) {
    pctp_data->logs_n[pctp_data->logs_n_len] = 0;
    int logs_to_send = 0;
    sscanf(pctp_data->logs_n, "%d", &logs_to_send);
    if (logs_to_send == 0) return DEFAULT_LOGS_TO_SEND;
    if (logs_to_send > MAX_LOGS_TO_SEND) return MAX_LOGS_TO_SEND;
    return logs_to_send;
}

static void write_n_logs_to_buffer(buffer* write_buffer, server_stats stats, int logs_to_send) {
    reset_server_connection_entry_iterator(stats);
    while(has_next_server_connection_entry(stats) && logs_to_send-- > 0) {
        server_connection_entry* entry = get_next_server_connection_entry(stats);
        char log_entry[MAX_MSG_SIZE];
        struct tm *t = localtime(&entry->timestamp);
        sprintf(log_entry, LOG_ENTRY_MSG, t->tm_year + TM_YEAR_RELATIVE, t->tm_mon + TM_MONTH_RELATIVE, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
                entry->user, entry->source_host, entry->source_port, entry->target_host, entry->target_port,
                entry->reply_code, entry->bytes_proxied, entry->auth_success == AUTHENTICATED ? "Auth" : "No auth");
        write_msg_to_buffer(write_buffer, log_entry);
    }
    write_msg_to_buffer(write_buffer, EMPTY_MSG);
}

static void write_users_to_buffer(buffer* write_buffer, server_config* config) {
    for (int i=0; i<config->user_count; i++) {
        server_user user = config->users[i];
        char user_entry[MAX_MSG_SIZE]; 
        sprintf(user_entry, USER_ENTRY_MSG, user.user, user.role == ADMIN? "Admin" : "Basic");
        write_msg_to_buffer(write_buffer, user_entry);
    }
    write_msg_to_buffer(write_buffer, EMPTY_MSG);
}

static unsigned main_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    size_t available = 0;
    uint8_t* ptr = buffer_write_ptr(read_buffer, &available);
    ssize_t n = recv(pctp_data->client_fd, ptr, available, MSG_NOSIGNAL);
    if (n <= 0) {
        return MAIN_READ;
    }

    buffer_write_adv(read_buffer, n);

    LOG_A(LOG_DEBUG, "Received %ld bytes in MAIN", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* stats_event = parser_feed(pctp_data->stats_parser, c);
        const struct parser_event* logs_event = parser_feed(pctp_data->logs_parser, c);
        const struct parser_event* add_event = parser_feed(pctp_data->add_parser, c);
        const struct parser_event* del_event = parser_feed(pctp_data->del_parser, c);
        const struct parser_event* list_event = parser_feed(pctp_data->list_parser, c);
        const struct parser_event* exit_event = parser_feed(pctp_data->exit_parser, c);
        if (stats_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded\n");
            LOG(LOG_DEBUG, "Command: stats\n");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_STATS_MSG);
            write_stats_to_buffer(&pctp_data->write_buffer, pctp_data->stats);
            return MAIN_WRITE;
        }
        if (logs_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded\n");
            LOG(LOG_DEBUG, "Command: logs\n");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_LOGS_MSG);
            write_n_logs_to_buffer(&pctp_data->write_buffer, pctp_data->stats, get_logs_to_send(pctp_data));
            return MAIN_WRITE;
        }
        if (add_event->type == TYPE_BASIC) {
            LOG(LOG_DEBUG, "Main parser succeded");
            LOG(LOG_DEBUG, "Command: add basic");
            pctp_data->level = BASIC;
            write_msg_to_buffer(&pctp_data->write_buffer, OK_ADD_MSG);
            return ADD_WRITE;
        }
        if (add_event->type == TYPE_ADMIN) {
            LOG(LOG_DEBUG, "Main parser succeded");
            LOG(LOG_DEBUG, "Command: add admin");
            pctp_data->level = ADMIN;
            write_msg_to_buffer(&pctp_data->write_buffer, OK_ADD_MSG);
            return ADD_WRITE;
        }
        if (del_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded");
            LOG(LOG_DEBUG, "Command: del");
            if (del_user(pctp_data->config, pctp_data->del_username, pctp_data->del_username_len) == 0)
                write_msg_to_buffer(&pctp_data->write_buffer, OK_DEL_MSG);
            else write_msg_to_buffer(&pctp_data->write_buffer, ERR_DEL_MSG);
            return MAIN_WRITE;
        }
        if (list_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded");
            LOG(LOG_DEBUG, "Command: list");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_LIST_MSG);
            write_users_to_buffer(&pctp_data->write_buffer, pctp_data->config);
            return MAIN_WRITE;
        }
        if (exit_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded");
            LOG(LOG_DEBUG, "Command: exit");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_DONE_MSG);
            return EXIT_WRITE;
        }
        if (stats_event->type == TYPE_ERROR && logs_event->type == TYPE_ERROR && add_event->type == TYPE_ERROR
            && del_event->type == TYPE_ERROR && list_event->type == TYPE_ERROR && exit_event->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "Main parsers failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return MAIN_WRITE;
        }
        if (del_event->type == TYPE_INPUT && pctp_data->del_username_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->del_username[pctp_data->del_username_len++] = c;
        }
        if (logs_event->type == TYPE_INPUT && pctp_data->logs_n_len < MAX_LOGS_DIGITS) {
            pctp_data->logs_n[pctp_data->logs_n_len++] = c;
        }
    }

    return MAIN_READ;
}

static void reset_main_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->stats_parser);
    reset_logs_state(state, key);
    reset_add_state(state, key);
    reset_del_state(state, key);
    parser_reset(pctp_data->list_parser);
    parser_reset(pctp_data->exit_parser);
}

static void reset_logs_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->logs_parser);
    pctp_data->logs_n_len = 0;
}

static void reset_add_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->add_parser);
    reset_new_user_state(state, key);
    reset_new_pass_state(state, key);
}

static void reset_del_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->del_parser);
    pctp_data->del_username_len = 0;
}

static int check_admin_username(pctp* pctp_data) {
    for(int i=0; i<pctp_data->config->user_count; i++) {
        server_user user = pctp_data->config->users[i];
        if (user.role != ADMIN) continue;
        int name_len = strlen(user.user);
        if (pctp_data->username_len == name_len && strncmp(pctp_data->username, user.user, name_len) == 0) 
            return i;
    }
    return -1;
}

static int check_new_username(pctp* pctp_data) {
    for(int i=0; i<pctp_data->config->user_count; i++) {
        server_user user = pctp_data->config->users[i];
        int name_len = strlen(user.user);
        if (pctp_data->new_username_len == name_len && strncmp(pctp_data->new_username, user.user, name_len) == 0) 
            return i;
    }
    return -1;
}

static int check_admin_password(pctp* pctp_data) {
    if (pctp_data->id == -1 || pctp_data->id >= pctp_data->config->user_count) return -1;
    server_user user = pctp_data->config->users[pctp_data->id];
    if (user.role != ADMIN) return -1;
    int pass_len = strlen(user.pass);
    if (pctp_data->password_len != pass_len) return -1;
    if (strncmp(pctp_data->password, user.pass, pass_len) != 0) return -1;
    return pctp_data->id;
}

static void write_msg_to_buffer(buffer* write_buffer, const char* msg) {
    size_t len = strlen(msg);
    size_t available;
    uint8_t *ptr = buffer_write_ptr(write_buffer, &available);
    size_t to_copy = len < available ? len : available;
    memcpy(ptr, msg, to_copy);
    buffer_write_adv(write_buffer, to_copy);
}

static int send_buffer_msg(int fd, buffer* write_buffer) {
    uint8_t *ptr;
    size_t count;

    while (buffer_can_read(write_buffer)) {
        ptr = buffer_read_ptr(write_buffer, &count);
        ssize_t sent = send(fd, ptr, count, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MSG_SEND_BLOCKED;
            } else {
                LOG(LOG_DEBUG, "Send failed");
                return MSG_SEND_ERROR;
            }
        }
        buffer_read_adv(write_buffer, sent);
    }
    return MSG_SENT;
}

static unsigned login_user_success_write(struct selector_key *key) {
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

static unsigned login_user_invalid_write(struct selector_key *key) {
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

static unsigned login_user_error_write(struct selector_key *key) {
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

static unsigned login_pass_invalid_write(struct selector_key *key) {
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

static unsigned login_pass_error_write(struct selector_key *key) {
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

static unsigned main_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return MAIN_READ;
        case MSG_SEND_BLOCKED: return MAIN_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

static unsigned add_write(struct selector_key *key) {
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

static unsigned add_user_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    size_t available = 0;
    uint8_t* ptr = buffer_write_ptr(read_buffer, &available);
    ssize_t n = recv(pctp_data->client_fd, ptr, available, MSG_NOSIGNAL);
    if (n <= 0) {
        return ADD_USER_READ;
    }

    buffer_write_adv(read_buffer, n);

    LOG_A(LOG_DEBUG, "Received %ld bytes in ADD_USER_READ", n);

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

    return ADD_USER_READ;
}

static void reset_new_user_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->user_parser);
    pctp_data->new_username_len = 0;
}

static unsigned add_user_success_write(struct selector_key *key) {
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

static unsigned add_user_invalid_write(struct selector_key *key) {
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

static unsigned add_user_error_write(struct selector_key *key) {
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

static unsigned add_pass_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer* read_buffer = &pctp_data->read_buffer;

    size_t available = 0;
    uint8_t* ptr = buffer_write_ptr(read_buffer, &available);
    ssize_t n = recv(pctp_data->client_fd, ptr, available, MSG_NOSIGNAL);
    if (n <= 0) {
        return ADD_PASS_READ;
    }

    buffer_write_adv(read_buffer, n);

    LOG_A(LOG_DEBUG, "Received %ld bytes in ADD_PASS_READ", n);

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

    return ADD_PASS_READ;
}

static void reset_new_pass_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->pass_parser);
    pctp_data->new_password_len = 0;
}

static unsigned add_pass_error_write(struct selector_key *key) {
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

static unsigned exit_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return DONE;
        case MSG_SEND_BLOCKED: return EXIT_WRITE;
        case MSG_SEND_ERROR: return ERROR;
    }
    return ERROR;
}

static void on_close(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    if (pctp_data->client_fd >= 0) {
        close(pctp_data->client_fd);
        selector_unregister_fd(key->s, pctp_data->client_fd);
    }
    free(pctp_data);
    LOG(LOG_DEBUG, "Closed PCTP session.");
}
