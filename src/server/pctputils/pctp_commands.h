#ifndef PCTP_COMMANDS_H
#define PCTP_COMMANDS_H

#include "../pctp.h"

#define CMD_MAIN_READ                   7
#define CMD_MAIN_WRITE                  8
#define CMD_EXIT_WRITE                  15

unsigned main_read(struct selector_key *key);
unsigned main_write(struct selector_key *key);
unsigned exit_write(struct selector_key *key);

void reset_main_state(const unsigned state, struct selector_key *key);
void reset_logs_state(const unsigned state, struct selector_key *key);
void reset_del_state(const unsigned state, struct selector_key *key);

void write_stats_to_buffer(buffer* write_buffer, server_stats stats);
void write_n_logs_to_buffer(buffer* write_buffer, server_stats stats, int logs_to_send);
void write_users_to_buffer(buffer* write_buffer, server_config* config);
int get_logs_to_send(pctp *pctp_data);

#endif
