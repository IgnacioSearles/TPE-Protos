#ifndef SOCKS5_HELLO_H
#define SOCKS5_HELLO_H

/**
 * socks5_hello.h - Manejo del saludo inicial SOCKS5
 *
 * Implementa la negociación inicial del protocolo SOCKS5 según RFC 1928.
 * Procesa la lista de métodos de autenticación soportados por el cliente
 * y selecciona el método apropiado según la configuración del servidor.
 */

#include <selector.h>
#include <socks5.h>

/** Procesamiento del saludo inicial del cliente */
socks5_state hello_read(struct selector_key *key);

/** Envío de respuesta con método seleccionado */
socks5_state hello_write(struct selector_key *key);

/** Tamaño mínimo del mensaje de saludo */
#define SOCKS5_HELLO_MIN_SIZE 3         // VER + NMETHODS + al menos 1 método
/** Tamaño de respuesta de saludo */
#define HELLO_RESPONSE_SIZE   2         // VER + SELECTED_METHOD

#endif
