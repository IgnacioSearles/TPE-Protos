#ifndef SERVER_STATS_H
#define SERVER_STATS_H

#include <stdint.h>
#include <sys/socket.h>

typedef struct server_stats_cdt* server_stats;

typedef enum {
    AUTHENTICATED,
    AWAITING_AUTHENTICATION,
    NEVER_AUTHENTICATED
} auth_state;

typedef struct {
    int is_connection_active;

    struct sockaddr_storage client_addr;
    auth_state auth_success;
    
    struct sockaddr_storage dest_addr;
    const char* user;

    uint64_t bytes_proxied;
    uint64_t timestamp;
} server_connection_entry;

/*
 *  Crea una instancia de los stats
 *
 *  retorna NULL si hubo error
 * */
server_stats create_server_stats();

/*
 *  Loggea que se creo una conexion
 * */
void log_connection_open(server_stats stats, int client_fd);

/*
 *  Loggea que se autentico un usuario
 *
 *  No realiza una copia del username
 * */
void log_user_authenticated(server_stats stats, int client_fd, const char* user);

/*
 *  Loggea que un usuario se conecto a un servidor de destino (se hizo el proxy)
 * */
void log_client_connected_to_destination_server(server_stats stats, int client_fd, int destination_fd);

/*
 *  Loggea que se hizo proxy de cierta cantidad de bytes para un usuario particular
 * */
void log_bytes_proxied(server_stats stats, int client_fd, uint64_t bytes);

/*
 *  Loggea que se cerro una conexion
 * */
void log_connection_close(server_stats stats, int client_fd);

/*
 *  Restea el iterador de los logs
 * */
void reset_server_connection_entry_iterator(server_stats stats);

/*
 * Checkea si el iterador de logs tiene un proximo elemento
 * */
int has_next_server_connection_entry(server_stats stats);

/*
 * Retorna la proxima entrada del iterador de logs
 * */
server_connection_entry* get_next_server_connection_entry(server_stats stats);

uint64_t get_active_connection_count(server_stats stats);
uint64_t get_total_connection_count(server_stats stats);
uint64_t get_total_bytes_proxied(server_stats stats);
uint64_t get_current_connections_bytes_proxied(server_stats stats);

/*
 *  Destruye una instancia de los stats
 * */
void destroy_server_stats(server_stats stats);

#endif
