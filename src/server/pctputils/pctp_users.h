#ifndef PCTP_USERS_H
#define PCTP_USERS_H

#include "../pctp.h"

#define USER_ADD_WRITE                  9
#define USER_ADD_USER_READ              10
#define USER_ADD_USER_SUCCESS_WRITE     11
#define USER_ADD_USER_INVALID_WRITE     12
#define USER_ADD_USER_ERROR_WRITE       13
#define USER_ADD_PASS_READ              14
#define USER_ADD_PASS_ERROR_WRITE       16

unsigned add_write(struct selector_key *key);
unsigned add_user_read(struct selector_key *key);
unsigned add_user_success_write(struct selector_key *key);
unsigned add_user_invalid_write(struct selector_key *key);
unsigned add_user_error_write(struct selector_key *key);

unsigned add_pass_read(struct selector_key *key);
unsigned add_pass_error_write(struct selector_key *key);

void reset_add_state(const unsigned state, struct selector_key *key);
void reset_new_user_state(const unsigned state, struct selector_key *key);
void reset_new_pass_state(const unsigned state, struct selector_key *key);

int check_new_username(pctp* pctp_data);

#endif
