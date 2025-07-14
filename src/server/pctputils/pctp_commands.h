#ifndef PCTP_COMMANDS_H
#define PCTP_COMMANDS_H

/**
 * pctp_commands.h - Procesamiento de comandos principales PCTP
 *
 * Implementa el manejo de comandos una vez autenticado el administrador.
 * Procesa comandos como STATS, LOGS, LIST, CONFIG y EXIT, generando
 * las respuestas apropiadas y actualizando la configuración del servidor.
 */

#include "../pctp.h"

/** Estados de comandos principales */
#define CMD_MAIN_READ                   7
#define CMD_MAIN_WRITE                  8
#define CMD_EXIT_WRITE                  15

/** Funciones principales de comandos */
unsigned main_read(struct selector_key *key);
unsigned main_write(struct selector_key *key);
unsigned exit_write(struct selector_key *key);

/** Funciones de reset de estado */
void reset_main_state(const unsigned state, struct selector_key *key);
void reset_logs_state(const unsigned state, struct selector_key *key);
void reset_config_state(const unsigned state, struct selector_key *key);
void reset_del_state(const unsigned state, struct selector_key *key);

/** Generadores de respuestas estructuradas */
void write_stats_to_buffer(buffer* write_buffer, server_stats stats);
void write_n_logs_to_buffer(buffer* write_buffer, server_stats stats, int logs_to_send);
void write_users_to_buffer(buffer* write_buffer, server_config* config);

/** Parsers de parámetros */
int get_logs_to_send(pctp *pctp_data);
int get_io_config(pctp *pctp_data);

#endif
