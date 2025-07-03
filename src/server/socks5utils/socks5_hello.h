#ifndef SOCKS5_HELLO_H
#define SOCKS5_HELLO_H

#include <selector.h>
#include <socks5.h>

socks5_state hello_read(struct selector_key *key);
socks5_state hello_write(struct selector_key *key);

#define SOCKS5_HELLO_MIN_SIZE 3         // VER + NMETHODS + al menos 1 método
#define HELLO_RESPONSE_SIZE   2         // VER + SELECTED_METHOD

#endif
