#include "pctp.h"
#include "ptctp_parser_tables.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

#define OK_USER_MSG "+OK Please send password\n"
#define OK_PASS_MSG "+OK Succesfully logged in\n"
#define OK_DONE_MSG "+OK Done\n"
#define ERR_INVALID_USER_MSG "-ERR Invalid username\n"
#define ERR_INVALID_PASS_MSG "-ERR Invalid password\n"
#define ERR_INVALID_COMMAND_MSG "-ERR Invalid command for current state\n"

enum pctp_states {
    LOGIN_USER_READ,
    LOGIN_USER_SUCCESS_WRITE,
    LOGIN_USER_INVALID_WRITE,
    LOGIN_USER_ERROR_WRITE,
    LOGIN_PASS_READ,
    LOGIN_PASS_SUCCESS_WRITE,
    LOGIN_PASS_INVALID_WRITE,
    LOGIN_PASS_ERROR_WRITE,
    MAIN_READ,
    MAIN_ERROR_WRITE,
    // STATS,
    // ADD_USER,
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

static unsigned login_pass_success_write(struct selector_key *key);
static unsigned login_pass_invalid_write(struct selector_key *key);
static unsigned login_pass_error_write(struct selector_key *key);

static unsigned main_read(struct selector_key *key);
static void reset_main_state(const unsigned state, struct selector_key *key);

static unsigned main_error_write(struct selector_key *key);

static unsigned exit_write(struct selector_key *key);

static void selector_set_interest_read(const unsigned state, struct selector_key *key);
static void selector_set_interest_write(const unsigned state, struct selector_key *key);

static void on_close(const unsigned state, struct selector_key *key);

static void pctp_read(struct selector_key *key);
static void pctp_write(struct selector_key *key);
static void pctp_close(struct selector_key *key);

static int check_username(pctp* pctp_data);
static int check_password(pctp* pctp_data);

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
    { .state = LOGIN_PASS_SUCCESS_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_success_write },
    { .state = LOGIN_PASS_INVALID_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_invalid_write, .on_departure = reset_pass_state },
    { .state = LOGIN_PASS_ERROR_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_error_write, .on_departure = reset_pass_state },
    { .state = MAIN_READ,                   .on_arrival = selector_set_interest_read, .on_read_ready = main_read },
    { .state = MAIN_ERROR_WRITE,            .on_arrival = selector_set_interest_write, .on_write_ready = main_error_write, .on_departure = reset_main_state },
    // { .state = STATS, },
    // { .state = ADD_USER, },
    // { .state = CONFIG, },
    { .state = EXIT_WRITE,                  .on_arrival = selector_set_interest_write, .on_write_ready = exit_write },
    { .state = DONE,                        .on_arrival = on_close },
    { .state = ERROR,                       .on_arrival = on_close },
};

static unsigned int parser_classes[0xFF] = {0};

int pctp_init(const int client_fd, fd_selector selector, server_config* config) {
    pctp* pctp_data = malloc(sizeof(*pctp_data));
    if (pctp_data == NULL) return -1;

    pctp_data->config = config;
    if (config->user_count == 0) {
        add_user(config, "postgres", "postgres", ADMIN);
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
    }

    // TODO: init parsers
    pctp_data->user_parser = parser_init(parser_classes, &user_parser_def);
    pctp_data->pass_parser = parser_init(parser_classes, &pass_parser_def);
    // pctp_data->stats_parser = parser_init();
    // pctp_data->add_user_parser = parser_init();
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

    printf("Received %ld bytes in LOGIN_USER_READ\n", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->user_parser, c);
        if (e->type == TYPE_SUCCESS) {
            printf("User parser succeded\n");
            printf("Username: %.*s\n", pctp_data->username_len, pctp_data->username);

            pctp_data->id = check_username(pctp_data);
            if (pctp_data->id != -1) {
                printf("Username is correct\n");
                write_msg_to_buffer(&pctp_data->write_buffer, OK_USER_MSG);
                return LOGIN_USER_SUCCESS_WRITE;
            }
            printf("Username is incorrect\n");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_USER_MSG);
            return LOGIN_USER_INVALID_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            printf("User parser failed\n");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return LOGIN_USER_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->username_len < MAX_DATA_SIZE) {
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

    printf("Received %ld bytes in LOGIN_PASS_READ\n", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* e = parser_feed(pctp_data->pass_parser, c);
        if (e->type == TYPE_SUCCESS) {
            printf("Pass parser succeded\n");
            printf("Password: %.*s\n", pctp_data->password_len, pctp_data->password);

            int id = check_password(pctp_data);
            if (id != -1) {
                printf("Password is correct\n");
                write_msg_to_buffer(&pctp_data->write_buffer, OK_PASS_MSG);
                return LOGIN_PASS_SUCCESS_WRITE;
            }
            printf("Password is incorrect\n");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_PASS_MSG);
            return LOGIN_PASS_INVALID_WRITE;
        }
        if (e->type == TYPE_ERROR) {
            printf("Pass parser failed\n");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return LOGIN_PASS_ERROR_WRITE;
        }
        if (e->type == TYPE_INPUT && pctp_data->password_len < MAX_DATA_SIZE) {
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

    printf("Received %ld bytes in MAIN\n", n);

    while (buffer_can_read(read_buffer)) {
        uint8_t c = buffer_read(read_buffer);
        const struct parser_event* exit_event = parser_feed(pctp_data->exit_parser, c);
        if (exit_event->type == TYPE_SUCCESS) {
            printf("Main parser succeded\n");
            printf("Command: exit\n");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_DONE_MSG);
            return EXIT_WRITE;
        }
        if (exit_event->type == TYPE_ERROR) {
            printf("Main parsers failed\n");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return MAIN_ERROR_WRITE;
        }
    }

    return MAIN_READ;
}

static void reset_main_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->exit_parser);
}

static int check_username(pctp* pctp_data) {
    for(int i=0; i<pctp_data->config->user_count; i++) {
        server_user user = pctp_data->config->users[i];
        if (user.role != ADMIN) continue;
        int name_len = strlen(user.user);
        if (pctp_data->username_len == name_len && strncmp(pctp_data->username, user.user, name_len) == 0) 
            return i;
    }
    return -1;
}

static int check_password(pctp* pctp_data) {
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
                printf("Send failed\n");
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
static unsigned login_pass_success_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return MAIN_READ;
        case MSG_SEND_BLOCKED: return LOGIN_PASS_SUCCESS_WRITE;
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

static unsigned main_error_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    buffer *write_buffer = &pctp_data->write_buffer;
    int fd = pctp_data->client_fd;
    int res = send_buffer_msg(fd, write_buffer);
    switch (res) {
        case MSG_SENT: return MAIN_READ;
        case MSG_SEND_BLOCKED: return MAIN_ERROR_WRITE;
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
    printf("Closed PCTP session.\n");
}