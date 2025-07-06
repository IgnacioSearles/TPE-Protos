#ifndef PCTP_STM_H
#define PCTP_STM_H

#include "../pctp.h"

void selector_set_interest_read(const unsigned state, struct selector_key *key);
void selector_set_interest_write(const unsigned state, struct selector_key *key);
void on_close(const unsigned state, struct selector_key *key);

void pctp_read(struct selector_key *key);
void pctp_write(struct selector_key *key);
void pctp_close(struct selector_key *key);

extern const struct state_definition pctp_states[];

#endif
