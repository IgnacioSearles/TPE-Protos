#ifndef SOCKS5_COPY_H
#define SOCKS5_COPY_H

#include <selector.h>
#include <socks5.h>

void copy_on_arrival(const unsigned state, struct selector_key *key);
socks5_state copy_bidirectional(struct selector_key *key);
void origin_read(struct selector_key *key); // Servidor remoto - Cliente
void origin_write(struct selector_key *key); // Servidor remoto - Cliente
extern const struct fd_handler origin_handler;

#endif
