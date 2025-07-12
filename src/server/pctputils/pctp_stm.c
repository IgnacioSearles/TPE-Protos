#include "pctp_stm.h"
#include "pctp_auth.h"
#include "pctp_commands.h"
#include "pctp_users.h"
#include "pctp_protocol.h"
#include "../../shared/logger.h"
#include "../../shared/stm.h"
#include <stdlib.h>
#include <unistd.h>

void selector_set_interest_read(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_READ);
}

void selector_set_interest_write(const unsigned state, struct selector_key *key) {
    selector_set_interest_key(key, OP_WRITE);
}

void pctp_read(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_read(&pctp_data->stm, key);
}

void pctp_write(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_write(&pctp_data->stm, key);
}

void pctp_close(struct selector_key *key) {
    pctp *pctp_data = key->data;
    stm_handler_close(&pctp_data->stm, key);
}

void on_close(const unsigned state, struct selector_key *key) {
    pctp* pctp_data = key->data;
    if (pctp_data->client_fd >= 0) {
        close(pctp_data->client_fd);
        selector_unregister_fd(key->s, pctp_data->client_fd);
    }
    free(pctp_data);
    LOG(LOG_DEBUG, "Closed PCTP session.");
}

const struct state_definition pctp_states[] = {
    { .state = LOGIN_USER_READ,             .on_arrival = selector_set_interest_read, .on_read_ready = login_user_read },
    { .state = LOGIN_USER_SUCCESS_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_user_success_write },
    { .state = LOGIN_USER_INVALID_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_user_invalid_write, .on_departure = reset_user_state },
    { .state = LOGIN_USER_ERROR_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = login_user_error_write, .on_departure = reset_user_state },
    { .state = LOGIN_PASS_READ,             .on_arrival = selector_set_interest_read, .on_read_ready = login_pass_read },
    { .state = LOGIN_PASS_INVALID_WRITE,    .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_invalid_write, .on_departure = reset_pass_state },
    { .state = LOGIN_PASS_ERROR_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = login_pass_error_write, .on_departure = reset_pass_state },
    { .state = MAIN_READ,                   .on_arrival = selector_set_interest_read, .on_read_ready = main_read },
    { .state = MAIN_WRITE,                  .on_arrival = selector_set_interest_write, .on_write_ready = main_write, .on_departure = reset_main_state },
    { .state = ADD_WRITE,                   .on_arrival = selector_set_interest_write, .on_write_ready = add_write, .on_departure = reset_main_state },
    { .state = ADD_USER_READ,               .on_arrival = selector_set_interest_read, .on_read_ready = add_user_read },
    { .state = ADD_USER_SUCCESS_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = add_user_success_write },
    { .state = ADD_USER_INVALID_WRITE,      .on_arrival = selector_set_interest_write, .on_write_ready = add_user_invalid_write, .on_departure = reset_new_user_state },
    { .state = ADD_USER_ERROR_WRITE,        .on_arrival = selector_set_interest_write, .on_write_ready = add_user_error_write, .on_departure = reset_new_user_state },
    { .state = ADD_PASS_READ,               .on_arrival = selector_set_interest_read, .on_read_ready = add_pass_read },
    { .state = ADD_PASS_ERROR_WRITE,        .on_arrival = selector_set_interest_write, .on_write_ready = add_pass_error_write, .on_departure = reset_new_pass_state },
    { .state = EXIT_WRITE,                  .on_arrival = selector_set_interest_write, .on_write_ready = exit_write, .on_departure = reset_main_state },
    { .state = DONE,                        .on_arrival = on_close },
    { .state = ERROR,                       .on_arrival = on_close },
};
