#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

#include <selector.h>
#include <socks5.h>

socks5_state auth_read(struct selector_key *key);
socks5_state auth_write(struct selector_key *key);

#define SOCKS5_AUTH_MIN_SIZE 5          // VER + ULEN + 1char + PLEN + 1char (mínimo)
#define AUTH_RESPONSE_SIZE   2          // VER + STATUS

#endif