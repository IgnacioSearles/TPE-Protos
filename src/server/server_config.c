#include "server_config.h"
#include <stdlib.h>

int add_user(server_config* config, char* user, char* pass, user_role role) {
    if (config->user_count >= MAX_USERS)
        return -1;

    config->users[config->user_count].user = user;
    config->users[config->user_count].pass = pass;
    config->users[config->user_count].role = role;
    config->user_count++;

    return 0;
}

server_config create_config() {
    server_config config = {
        .socks_addr = NULL,
        .pctp_addr = NULL,
        .log_level = NULL,
        .socks_port = SOCKS5_STD_PORT,
        .pctp_port = PCTP_STD_PORT,
        .disectors_enabled = 1,
        .user_count = 0
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
