#ifndef SOCKS5_REQUEST_H
#define SOCKS5_REQUEST_H

/**
 * socks5_request.h - Manejo de solicitudes de conexión SOCKS5
 *
 * Implementa el procesamiento de solicitudes de conexión según RFC 1928.
 * Maneja la resolución de nombres, establecimiento de conexiones TCP
 * y generación de respuestas apropiadas al cliente.
 *
 * Soporta:
 *  - Direcciones IPv4, IPv6 y nombres de dominio (FQDN)
 *  - Resolución asíncrona de nombres
 *  - Conexiones no bloqueantes
 */

#include <selector.h>
#include <socks5.h>

/** Procesamiento de solicitud de conexión */
socks5_state request_read(struct selector_key *key);

/** Envío de respuesta inicial a solicitud */
socks5_state request_write(struct selector_key *key);

/** Establecimiento de conexión con destino */
socks5_state connecting(struct selector_key *key);

/** Manejo de conexión establecida */
socks5_state connected(struct selector_key *key);

/** Envío de respuesta final de conexión */
socks5_state connecting_response(struct selector_key *key);

/** Manejador principal de eventos SOCKS5 */
extern const struct fd_handler socks5_handler;

/** Tamaño mínimo de solicitud */
#define SOCKS5_REQUEST_MIN_SIZE 6       // VER + CMD + RSV + ATYP + mínimo addr + port
/** Tamaño de respuesta con IPv4 */
#define REQUEST_RESPONSE_SIZE   10      // Respuesta fija con IPv4

#endif
