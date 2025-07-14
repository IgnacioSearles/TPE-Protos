#ifndef SOCKS5_COPY_H
#define SOCKS5_COPY_H

/**
 * socks5_copy.h - Manejo de transferencia bidireccional de datos
 *
 * Implementa la fase COPY del protocolo SOCKS5, donde se realiza
 * la transferencia de datos entre el cliente y el servidor destino.
 *
 * Características:
 *  - Transferencia bidireccional asíncrona
 *  - Optimización para evitar cambios constantes de interés en el selector
 *  - Manejo eficiente de buffers para maximizar throughput
 *  - Estadísticas de bytes transferidos en tiempo real
 *
 */

#include <selector.h>
#include <socks5.h>

/** Callback de llegada al estado COPY */
void copy_on_arrival(const unsigned state, struct selector_key *key);

/** Manejo de lectura en estado COPY */
socks5_state copy_read(struct selector_key *key);

/** Manejo de escritura en estado COPY */
socks5_state copy_write(struct selector_key *key);

/** Lectura desde servidor remoto hacia cliente */
void origin_read(struct selector_key *key);

/** Escritura desde cliente hacia servidor remoto */
void origin_write(struct selector_key *key);

/** Manejador de eventos para el descriptor del origen */
extern const struct fd_handler origin_handler;

#endif
