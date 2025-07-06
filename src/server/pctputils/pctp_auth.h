#ifndef PCTP_AUTH_H
#define PCTP_AUTH_H

#include "../pctp.h"

#define AUTH_LOGIN_USER_READ            0
#define AUTH_LOGIN_USER_SUCCESS_WRITE   1  
#define AUTH_LOGIN_USER_INVALID_WRITE   2
#define AUTH_LOGIN_USER_ERROR_WRITE     3
#define AUTH_LOGIN_PASS_READ            4
#define AUTH_LOGIN_PASS_INVALID_WRITE   5
#define AUTH_LOGIN_PASS_ERROR_WRITE     6

unsigned login_user_read(struct selector_key *key);
unsigned login_user_success_write(struct selector_key *key);
unsigned login_user_invalid_write(struct selector_key *key);
unsigned login_user_error_write(struct selector_key *key);

unsigned login_pass_read(struct selector_key *key);
unsigned login_pass_invalid_write(struct selector_key *key);
unsigned login_pass_error_write(struct selector_key *key);

void reset_user_state(const unsigned state, struct selector_key *key);
void reset_pass_state(const unsigned state, struct selector_key *key);

int check_admin_username(pctp* pctp_data);
int check_admin_password(pctp* pctp_data);

#endif
