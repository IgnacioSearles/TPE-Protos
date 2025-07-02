#include "server_stats.h"
#include "../shared/netutils.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define LOG_SIZE 4096
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

server_connection_log_entry* find_log_entry_by_fd(server_stats stats, int client_fd) {
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

void log_connection_open(server_stats stats, int client_fd) {
    stats->total_connection_count++;
    stats->active_connection_count++;

    server_connection_log_entry* log = &(stats->log[stats->log_index]);

    get_socket_peer_address(client_fd, &(log->entry.client_addr));
    log->entry.auth_success = AWAITING_AUTHENTICATION;
    log->entry.timestamp = time(NULL);
    log->entry.is_connection_active = 1;
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

void log_client_connected_to_destination_server(server_stats stats, int client_fd, int destination_fd) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    get_socket_peer_address(destination_fd, &(log->entry.dest_addr));
}

void log_bytes_proxied(server_stats stats, int client_fd, uint64_t bytes) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    stats->total_bytes_proxied += bytes;
    stats->current_connections_bytes_proxied += bytes;
    log->entry.bytes_proxied += bytes;
}

void log_connection_close(server_stats stats, int client_fd) {
    server_connection_log_entry* log = find_log_entry_by_fd(stats, client_fd);
    if (log == NULL)
        return;

    stats->active_connection_count -= (stats->active_connection_count > 0);
    stats->current_connections_bytes_proxied -= log->entry.bytes_proxied;

    log->fd = CLOSED_FD_STATE;
    log->entry.auth_success = (log->entry.auth_success != AUTHENTICATED) ? NEVER_AUTHENTICATED : AUTHENTICATED;
    log->entry.is_connection_active = 0;
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
