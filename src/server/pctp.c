#include "pctp.h"
#include "./pctputils/pctp_parser_tables.h"
#include "./pctputils/pctp_protocol.h"
#include "./pctputils/pctp_auth.h"
#include "./pctputils/pctp_commands.h"
#include "./pctputils/pctp_users.h"
#include "./pctputils/pctp_stm.h"
#include "logger.h"
#include "selector.h"
#include "server_stats.h"
#include <stdlib.h>
#include <stdio.h>

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
    pctp_data->stm.states = pctp_states;

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

    if (selector_register(selector, client_fd, &pctp_data->handlers, OP_READ, pctp_data) != SELECTOR_SUCCESS) {
        LOG(LOG_DEBUG, "Could not register fd for pctp connection");
        free(pctp_data);
        return -1;
    }

    pctp_data->username_len = 0;
    pctp_data->password_len = 0;
    pctp_data->new_username_len = 0;
    pctp_data->new_password_len = 0;
    pctp_data->logs_n_len = 0;
    
    return 0;
}
