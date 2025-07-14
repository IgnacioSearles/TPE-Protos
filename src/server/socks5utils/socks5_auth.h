#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

/**
 * socks5_auth.h - Manejo de autenticación usuario/contraseña SOCKS5
 *
 * Implementa la subnegociación de autenticación según RFC 1929.
 * Procesa credenciales de usuario y contraseña enviadas por el cliente
 * y valida contra la configuración del servidor.
 */

#include <selector.h>
#include <socks5.h>

/** Procesamiento de lectura de credenciales */
socks5_state auth_read(struct selector_key *key);

/** Envío de respuesta de autenticación */
socks5_state auth_write(struct selector_key *key);

/** Tamaño mínimo de mensaje de autenticación */
#define SOCKS5_AUTH_MIN_SIZE 5          // VER + ULEN + 1char + PLEN + 1char (mínimo)
/** Tamaño de respuesta de autenticación */
#define AUTH_RESPONSE_SIZE   2          // VER + STATUS

#endif