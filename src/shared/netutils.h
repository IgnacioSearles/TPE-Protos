#ifndef NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U
#define NETUTILS_H_CTCyWGhkVt1pazNytqIRptmAi5U

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include "buffer.h"
#include <selector.h>
#include <netdb.h>

/*
 * Setea un socket como no bloqueante 
 *
 * retorna menor a 0 si ocurrio un error
 * */
int set_non_blocking(int fd);

/*
 * Crea un socket TCP pasivo no bloqueante que escucha
 *
 * si el parametro ip_str es null el socket escucha en todas las direcciones
 *
 * retorna menor a 0 si ocurrio un error
 * retorna el fd del socket si se realizo sin problema
 */
int create_passive_tcp_socket(const char* ip_str, uint16_t port, uint32_t max_connections);

/*
 * Crea un socket TCP conectado a un host determinado en un puerto determinado
 *
 * Se bloquea
 *
 * retorna menor a 0 si ocurrio un error
 * retorna el fd del socket si se realizo sin problema
 * */
int connect_to_host(const char *host, const char *port);

int get_addr_info_non_blocking(const char* host, const char *port, fd_selector selector, int notify_fd, struct addrinfo** out);

/*
 * Obtiene la dirección remota del socket
 * */
int get_socket_peer_address(int fd, struct sockaddr_storage *out_addr);

#define SOCKADDR_TO_HUMAN_MIN (INET6_ADDRSTRLEN + 5 + 1)
/**
 * Describe de forma humana un sockaddr:
 *
 * @param buff     el buffer de escritura
 * @param buffsize el tamaño del buffer  de escritura
 *
 * @param af    address family
 * @param addr  la dirección en si
 * @param nport puerto en network byte order
 *
 */
const char *sockaddr_to_human(char *buff, const size_t buffsize,
                              const struct sockaddr *addr);


/*
 *  Gets the port of the socket
 * */
uint16_t get_socket_port(const struct sockaddr* addr);

/**
 * Escribe n bytes de buff en fd de forma bloqueante
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_write(const int fd, buffer *b);

/**
 * copia todo el contenido de source a dest de forma bloqueante.
 *
 * Retorna 0 si se realizó sin problema y errno si hubo problemas
 */
int sock_blocking_copy(const int source, const int dest);

#endif
