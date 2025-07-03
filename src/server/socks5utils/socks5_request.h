#ifndef SOCKS5_REQUEST_H
#define SOCKS5_REQUEST_H

#include <selector.h>
#include <socks5.h>

socks5_state request_read(struct selector_key *key);
socks5_state request_write(struct selector_key *key);
socks5_state connecting(struct selector_key *key);

#define SOCKS5_REQUEST_MIN_SIZE 6       // VER + CMD + RSV + ATYP + mínimo addr + port
#define REQUEST_RESPONSE_SIZE   10      // Respuesta fija con IPv4

#endif
