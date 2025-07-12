#include "server_stats.h"
#include "../shared/netutils.h"
#include <logger.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define CLOSED_FD_STATE -1

typedef struct {
    int fd;
    server_connection_entry entry;
} server_connection_log_entry;

struct server_stats_cdt {
    uint64_t active_connection_count;
    uint64_t total_connection_count;
    uint64_t total_bytes_proxied;
    uint64_t current_connections_bytes_proxied;

    uint64_t log_iter_remaining;
    uint64_t log_iter_index;

    int64_t log_index;
    uint64_t log_size;
    server_connection_log_entry log[LOG_SIZE];
};

server_stats create_server_stats() {
    server_stats stats = calloc(1, sizeof(struct server_stats_cdt));
    return stats;
}

static server_connection_log_entry* find_log_entry_by_fd(server_stats stats, int client_fd) {
    for (int64_t i = stats->log_index - 1; i >= 0; i--) {
        if (stats->log[i].fd == client_fd)
            return &(stats->log[i]);
    }

    if (stats->log_size == LOG_SIZE) {
        for (int64_t i = LOG_SIZE - 1; i >= stats->log_index; i--) {
            if (stats->log[i].fd == client_fd)
                return &(stats->log[i]);
        }
    }

    return NULL;
}

static void print_log_entry(server_connection_entry* entry) {
    struct tm *t = localtime(&entry->timestamp);

    // Not using the logger here because a human is not a computer.
    printf("%d-%02d-%02dT%02d:%02d:%02dZ\t%s\tA\t%s\t%d\t%s\t%d\t%d\n", 
            t->tm_year + TM_YEAR_RELATIVE, t->tm_mon + TM_MONTH_RELATIVE, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
            entry->user, 
            entry->source_host, 
            entry->source_port, 
            entry->target_host, 
            entry->target_port, 
            entry->reply_code); 
}

void log_connection_open(server_stats stats, int client_fd) {
    stats->total_connection_count++;
    stats->active_connection_count++;

    server_connection_log_entry* log = &(stats->log[stats->log_index]);

    struct sockaddr_storage client_addr;
    get_socket_peer_address(client_fd, &(client_addr));
    sockaddr_to_human(log->entry.source_host, MAX_HOST_LEN, (struct sockaddr*)&client_addr);
    char* colon = strchr(log->entry.source_host, ':');
    if (colon != NULL) *colon = '\0';
    log->entry.source_port = get_socket_port((struct sockaddr*)&client_addr);

    log->entry.auth_success = AWAITING_AUTHENTICATION;
    log->entry.timestamp = time(NULL);
    log->entry.is_connection_active = 1;
    log->entry.target_port = 0;
    log->entry.target_host[0] = '\0';
    log->entry.reply_code = 0;
    log->entry.user = NULL;
    log->entry.bytes_proxied = 0;
    log->fd = client_fd;

    stats->log_index = (stats->log_index + 1) % LOG_SIZE;
    stats->log_size = min(stats->log_size + 1, LOG_SIZE);
}

void log_user_authenticated(server_stats stats, int client_fd, const char *user) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    log->entry.auth_success = AUTHENTICATED;
    log->entry.user = user;
}

void log_client_connected_to_destination_server(server_stats stats, int client_fd, const char* target_host, uint16_t target_port) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    log->entry.target_port = target_port;
    strncpy(log->entry.target_host, target_host, MAX_HOST_LEN - 1); // the struct is allocated with calloc so no need to null terminate just in case
}

void log_bytes_proxied(server_stats stats, int client_fd, uint64_t bytes) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    stats->total_bytes_proxied += bytes;
    stats->current_connections_bytes_proxied += bytes;
    log->entry.bytes_proxied += bytes;
}

void log_connection_close(server_stats stats, int client_fd, uint8_t reply_code) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    stats->active_connection_count -= (stats->active_connection_count > 0);
    stats->current_connections_bytes_proxied -= log->entry.bytes_proxied;

    log->fd = CLOSED_FD_STATE;
    log->entry.auth_success = (log->entry.auth_success != AUTHENTICATED) ? NEVER_AUTHENTICATED : AUTHENTICATED;
    log->entry.is_connection_active = 0;
    log->entry.reply_code = reply_code;

    print_log_entry(&(log->entry));
}

uint64_t get_active_connection_count(server_stats stats) {
    return stats->active_connection_count;
}

uint64_t get_total_connection_count(server_stats stats) {
    return stats->total_connection_count;
}

uint64_t get_total_bytes_proxied(server_stats stats) {
    return stats->total_bytes_proxied;
}

uint64_t get_current_connections_bytes_proxied(server_stats stats) {
    return stats->current_connections_bytes_proxied;
}

void reset_server_connection_entry_iterator(server_stats stats) {
    stats->log_iter_index = (stats->log_index == 0 && stats->log_size == LOG_SIZE) ? LOG_SIZE - 1 : stats->log_index - 1;
    stats->log_iter_remaining = stats->log_size;
}

int has_next_server_connection_entry(server_stats stats) {
    return stats->log_iter_remaining > 0;
}

server_connection_entry* get_next_server_connection_entry(server_stats stats) {
    if (!has_next_server_connection_entry(stats)) {
        return NULL;
    }

    server_connection_entry* entry = &(stats->log[stats->log_iter_index].entry);

    stats->log_iter_index = (stats->log_iter_index == 0 && stats->log_size == LOG_SIZE) ? LOG_SIZE - 1 : stats->log_iter_index - 1;
    stats->log_iter_remaining--;

    return entry;
}

void destroy_server_stats(server_stats stats) {
    free(stats);
}
