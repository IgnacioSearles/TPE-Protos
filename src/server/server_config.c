#include "server_config.h"
#include <stdlib.h>

int count_admins(server_config* config) {
    int count = 0;
    for (int i=0; i<config->user_count; i++) {
        if (config->users[i].role == ADMIN) count++;
    }
    return count;
}

int add_user(server_config* config, char* user, char* pass, user_role role) {
    if (config->user_count >= MAX_USERS)
        return -1;

    config->users[config->user_count].user = user;
    config->users[config->user_count].pass = pass;
    config->users[config->user_count].role = role;
    config->user_count++;

    return 0;
}

int del_user(server_config* config, char* user_to_del, int name_len) {
    if (config->user_count == 0)
        return -1;
    int i;
    for (i=0; i<config->user_count; i++) {
        server_user user = config->users[i];
        int username_len = strlen(user.user);
        if (name_len == username_len && strncmp(user_to_del, user.user, name_len) == 0) 
            break;
    }
    if (i == config->user_count) return -1;
    config->user_count--;
    for (; i<config->user_count; i++) config->users[i] = config->users[i+1];
    return 0;
}

int admin_count(server_config* config) {
    int count = 0;
    for (int i = 0; i < config->user_count; i++) {
        if (config->users[i].role == ADMIN) {
            count++;
        }
    }
    return count;
}

server_config create_config(uint64_t initial_io_buffer_size) {
    server_config config = {
        .socks_addr = NULL,
        .pctp_addr = NULL,
        .log_level = NULL,
        .socks_port = SOCKS5_STD_PORT,
        .pctp_port = PCTP_STD_PORT,
        .user_count = 0,
        .io_buffer_size = initial_io_buffer_size
    };

    return config;
}

void destroy_config(server_config* config) {
    if (config->socks_addr != NULL) {
        free(config->socks_addr);
    }

    if (config->pctp_addr != NULL) {
        free(config->pctp_addr);
    }

    if (config->log_level != NULL) {
        free(config->log_level);
    }
}
