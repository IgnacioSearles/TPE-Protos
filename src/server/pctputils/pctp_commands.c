#include "pctp_commands.h"
#include "pctp_protocol.h"
#include "pctp_users.h"
#include "pctp_parser_tables.h"
#include "../../shared/logger.h"
#include "../../shared/parser.h"
#include "../server_stats.h"
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

// Includes para macOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

unsigned main_read(struct selector_key *key) {
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
        const struct parser_event* config_event = parser_feed(pctp_data->config_parser, c);
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
        if (config_event->type == TYPE_SUCCESS) {
            LOG(LOG_DEBUG, "Main parser succeded\n");
            LOG(LOG_DEBUG, "Command: config\n");
            write_msg_to_buffer(&pctp_data->write_buffer, OK_IO_CONFIG_MSG);
            pctp_data->config->io_buffer_size = get_io_config(pctp_data);
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
        if (stats_event->type == TYPE_ERROR && logs_event->type == TYPE_ERROR && logs_event->type == TYPE_ERROR
            && add_event->type == TYPE_ERROR && del_event->type == TYPE_ERROR && list_event->type == TYPE_ERROR
            && exit_event->type == TYPE_ERROR) {
            LOG(LOG_DEBUG, "Main parsers failed");
            write_msg_to_buffer(&pctp_data->write_buffer, ERR_INVALID_COMMAND_MSG);
            return MAIN_WRITE;
        }
        if (logs_event->type == TYPE_INPUT && pctp_data->logs_n_len < MAX_LOGS_DIGITS) {
            pctp_data->logs_n[pctp_data->logs_n_len++] = c;
        }
        if (config_event->type == TYPE_INPUT && pctp_data->io_config_len < MAX_IO_DIGITS) {
            pctp_data->io_config[pctp_data->io_config_len++] = c;
        }
        if (del_event->type == TYPE_INPUT && pctp_data->del_username_len < MAX_CREDENTIAL_SIZE) {
            pctp_data->del_username[pctp_data->del_username_len++] = c;
        }
    }

    return MAIN_READ;
}

unsigned main_write(struct selector_key *key) {
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

unsigned exit_write(struct selector_key *key) {
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

void reset_main_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->stats_parser);
    reset_logs_state(state, key);
    reset_config_state(state, key);
    reset_add_state(state, key);
    reset_del_state(state, key);
    parser_reset(pctp_data->list_parser);
    parser_reset(pctp_data->exit_parser);
}

void reset_logs_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->logs_parser);
    pctp_data->logs_n_len = 0;
}

void reset_config_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->config_parser);
    pctp_data->io_config_len = 0;
}

void reset_del_state(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    parser_reset(pctp_data->del_parser);
    pctp_data->del_username_len = 0;
}

void write_stats_to_buffer(buffer* write_buffer, server_stats stats) {
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

int get_logs_to_send(pctp *pctp_data) {
    pctp_data->logs_n[pctp_data->logs_n_len] = 0;
    int logs_to_send = 0;
    sscanf(pctp_data->logs_n, "%d", &logs_to_send);
    if (logs_to_send == 0) return DEFAULT_LOGS_TO_SEND;
    if (logs_to_send > LOG_SIZE) return LOG_SIZE;
    return logs_to_send;
}

int get_io_config(pctp *pctp_data) {
    pctp_data->io_config[pctp_data->io_config_len] = 0;
    int io_config = 0;
    sscanf(pctp_data->io_config, "%d", &io_config);
    if (io_config == 0) return INITIAL_BUFFER_SIZE;
    return io_config;
}

void write_n_logs_to_buffer(buffer* write_buffer, server_stats stats, int logs_to_send) {
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

void write_users_to_buffer(buffer* write_buffer, server_config* config) {
    for (int i=0; i<config->user_count; i++) {
        server_user user = config->users[i];
        char user_entry[MAX_MSG_SIZE]; 
        sprintf(user_entry, USER_ENTRY_MSG, user.user, user.role == ADMIN? "Admin" : "Basic");
        write_msg_to_buffer(write_buffer, user_entry);
    }
    write_msg_to_buffer(write_buffer, EMPTY_MSG);
}
