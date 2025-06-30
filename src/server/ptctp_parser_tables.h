#ifndef PCTP_PARSER_TABLES_H
#define PCTP_PARSER_TABLES_H
#include "../shared/parser.h"

#define CLASS_ALNUM (1 << 8)

enum type { TYPE_UNDEFINED, TYPE_SUCCESS, TYPE_ERROR, TYPE_INPUT };

static void set_type_success(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_SUCCESS;
}

static void set_type_error(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_ERROR;
}

static void set_type_input(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_INPUT;
}

static void ignore(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_UNDEFINED;
}

enum user_parser_states { ST_USER_U, ST_USER_S, ST_USER_E, ST_USER_R, ST_USER_SPACE, ST_USER_INPUT, ST_USER_NL, ST_USER_DONE, ST_USER_ERROR};

static const struct parser_state_transition user_parser_state_U_transitions[] = {
    { .when = 'U', .dest = ST_USER_S, .act1 = ignore }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_S_transitions[] = {
    { .when = 'S', .dest = ST_USER_E, .act1 = ignore }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_E_transitions[] = {
    { .when = 'E', .dest = ST_USER_R, .act1 = ignore }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_R_transitions[] = {
    { .when = 'R', .dest = ST_USER_SPACE, .act1 = ignore }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_USER_INPUT, .act1 = ignore }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_USER_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_DONE, .act1 = set_type_success }, 
    { .when = CLASS_ALNUM, .dest = ST_USER_INPUT, .act1 = set_type_input },
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_USER_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition user_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const size_t user_parser_states_n[] = {2, 2, 2, 2, 2, 4, 2, 0, 2};

static const struct parser_state_transition* user_parser_state_transitions[] = {
    user_parser_state_U_transitions,
    user_parser_state_S_transitions,
    user_parser_state_E_transitions,
    user_parser_state_R_transitions,
    user_parser_state_SPACE_transitions,
    user_parser_state_INPUT_transitions,
    user_parser_state_NL_transitions,
    user_parser_state_DONE_transitions,
    user_parser_state_ERROR_transitions,
};

static const struct parser_definition user_parser_def = {
    .states_count = ST_USER_ERROR,
    .states = (const struct parser_state_transition **) user_parser_state_transitions,
    .states_n = user_parser_states_n,
    .start_state = ST_USER_U
};

enum pass_parser_states { ST_PASS_P, ST_PASS_A, ST_PASS_S1, ST_PASS_S2, ST_PASS_SPACE, ST_PASS_INPUT, ST_PASS_NL, ST_PASS_DONE, ST_PASS_ERROR};

static const struct parser_state_transition pass_parser_state_P_transitions[] = {
    { .when = 'P', .dest = ST_PASS_A, .act1 = ignore }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_A_transitions[] = {
    { .when = 'A', .dest = ST_PASS_S1, .act1 = ignore }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_S1_transitions[] = {
    { .when = 'S', .dest = ST_PASS_S2, .act1 = ignore }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_S2_transitions[] = {
    { .when = 'S', .dest = ST_PASS_SPACE, .act1 = ignore }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_PASS_INPUT, .act1 = ignore }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_PASS_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_DONE, .act1 = set_type_success }, 
    { .when = CLASS_ALNUM, .dest = ST_PASS_INPUT, .act1 = set_type_input },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_PASS_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition pass_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const size_t pass_parser_states_n[] = {2, 2, 2, 2, 2, 4, 2, 0, 2};

static const struct parser_state_transition* pass_parser_state_transitions[] = {
    pass_parser_state_P_transitions,
    pass_parser_state_A_transitions,
    pass_parser_state_S1_transitions,
    pass_parser_state_S2_transitions,
    pass_parser_state_SPACE_transitions,
    pass_parser_state_INPUT_transitions,
    pass_parser_state_NL_transitions,
    pass_parser_state_DONE_transitions,
    pass_parser_state_ERROR_transitions,
};

static const struct parser_definition pass_parser_def = {
    .states_count = ST_PASS_ERROR,
    .states = (const struct parser_state_transition **) pass_parser_state_transitions,
    .states_n = pass_parser_states_n,
    .start_state = ST_PASS_P
};

enum exit_parser_states { ST_EXIT_E, ST_EXIT_X, ST_EXIT_I, ST_EXIT_T, ST_EXIT_CR, ST_EXIT_NL, ST_EXIT_DONE, ST_EXIT_ERROR};

static const struct parser_state_transition exit_parser_state_E_transitions[] = {
    { .when = 'E', .dest = ST_EXIT_X, .act1 = ignore }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_X_transitions[] = {
    { .when = 'X', .dest = ST_EXIT_I, .act1 = ignore }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_I_transitions[] = {
    { .when = 'I', .dest = ST_EXIT_T, .act1 = ignore }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_T_transitions[] = {
    { .when = 'T', .dest = ST_EXIT_CR, .act1 = ignore }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_CR_transitions[] = {
    { .when = '\r', .dest = ST_EXIT_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_EXIT_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_EXIT_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition exit_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_EXIT_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const size_t exit_parser_states_n[] = {2, 2, 2, 2, 3, 2, 0, 2};

static const struct parser_state_transition* exit_parser_state_transitions[] = {
    exit_parser_state_E_transitions,
    exit_parser_state_X_transitions,
    exit_parser_state_I_transitions,
    exit_parser_state_T_transitions,
    exit_parser_state_CR_transitions,
    exit_parser_state_NL_transitions,
    exit_parser_state_DONE_transitions,
    exit_parser_state_ERROR_transitions,
};

static const struct parser_definition exit_parser_def = {
    .states_count = ST_EXIT_ERROR,
    .states = (const struct parser_state_transition **) exit_parser_state_transitions,
    .states_n = exit_parser_states_n,
    .start_state = ST_EXIT_E
};

#endif