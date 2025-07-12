#ifndef PCTP_PARSER_TABLES_H
#define PCTP_PARSER_TABLES_H
#include "../shared/parser.h"

#define CLASS_ALNUM (1 << 8)
#define CLASS_NUM (1 << 10)

enum type { TYPE_UNDEFINED, TYPE_SUCCESS, TYPE_ERROR, TYPE_INPUT, TYPE_BASIC, TYPE_ADMIN };

static void set_type_success(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_SUCCESS;
}

static void set_type_error(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_ERROR;
}

static void set_type_input(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_INPUT;
}

static void set_type_basic(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_BASIC;
}

static void set_type_admin(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_ADMIN;
}

static void ignore(struct parser_event* ret, const uint8_t c) {
    ret->type = TYPE_UNDEFINED;
}

enum user_parser_states { ST_USER_U, ST_USER_S, ST_USER_E, ST_USER_R, ST_USER_SPACE, ST_USER_INPUT, ST_USER_NL, ST_USER_DONE, ST_USER_ERROR};

static const struct parser_state_transition user_parser_state_U_transitions[] = {
    { .when = 'U', .dest = ST_USER_S, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_S_transitions[] = {
    { .when = 'S', .dest = ST_USER_E, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_E_transitions[] = {
    { .when = 'E', .dest = ST_USER_R, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_R_transitions[] = {
    { .when = 'R', .dest = ST_USER_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_USER_ERROR, .act1 = ignore }
};

static const struct parser_state_transition user_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_USER_INPUT, .act1 = ignore }, 
    { .when = '\n', .dest = ST_USER_ERROR, .act1 = set_type_error },
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

static const size_t user_parser_states_n[] = {3, 3, 3, 3, 3, 4, 2, 0, 2};

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
    .states = user_parser_state_transitions,
    .states_n = user_parser_states_n,
    .start_state = ST_USER_U
};

enum pass_parser_states { ST_PASS_P, ST_PASS_A, ST_PASS_S1, ST_PASS_S2, ST_PASS_SPACE, ST_PASS_INPUT, ST_PASS_NL, ST_PASS_DONE, ST_PASS_ERROR};

static const struct parser_state_transition pass_parser_state_P_transitions[] = {
    { .when = 'P', .dest = ST_PASS_A, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_A_transitions[] = {
    { .when = 'A', .dest = ST_PASS_S1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_S1_transitions[] = {
    { .when = 'S', .dest = ST_PASS_S2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_S2_transitions[] = {
    { .when = 'S', .dest = ST_PASS_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_PASS_INPUT, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_PASS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition pass_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_PASS_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_PASS_DONE, .act1 = set_type_success }, 
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

static const size_t pass_parser_states_n[] = {3, 3, 3, 3, 3, 4, 2, 0, 2};

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
    .states = pass_parser_state_transitions,
    .states_n = pass_parser_states_n,
    .start_state = ST_PASS_P
};

enum stats_parser_states { ST_STATS_S1, ST_STATS_T1, ST_STATS_A, ST_STATS_T2, ST_STATS_S2, ST_STATS_CR, ST_STATS_NL, ST_STATS_DONE, ST_STATS_ERROR};

static const struct parser_state_transition stats_parser_state_S1_transitions[] = {
    { .when = 'S', .dest = ST_STATS_T1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_T1_transitions[] = {
    { .when = 'T', .dest = ST_STATS_A, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_A_transitions[] = {
    { .when = 'A', .dest = ST_STATS_T2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_T2_transitions[] = {
    { .when = 'T', .dest = ST_STATS_S2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_S2_transitions[] = {
    { .when = 'S', .dest = ST_STATS_CR, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_CR_transitions[] = {
    { .when = '\r', .dest = ST_STATS_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_STATS_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_STATS_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition stats_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition stats_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_STATS_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_STATS_ERROR, .act1 = ignore }
};

static const size_t stats_parser_states_n[] = {3, 3, 3, 3, 3, 3, 2, 0, 2};

static const struct parser_state_transition* stats_parser_state_transitions[] = {
    stats_parser_state_S1_transitions,
    stats_parser_state_T1_transitions,
    stats_parser_state_A_transitions,
    stats_parser_state_T2_transitions,
    stats_parser_state_S2_transitions,
    stats_parser_state_CR_transitions,
    stats_parser_state_NL_transitions,
    stats_parser_state_DONE_transitions,
    stats_parser_state_ERROR_transitions,
};

static const struct parser_definition stats_parser_def = {
    .states_count = ST_STATS_ERROR,
    .states = stats_parser_state_transitions,
    .states_n = stats_parser_states_n,
    .start_state = ST_STATS_S1
};

enum logs_parser_states { ST_LOGS_L, ST_LOGS_O, ST_LOGS_G, ST_LOGS_S, ST_LOGS_SPACE, ST_LOGS_INPUT, ST_LOGS_NL, ST_LOGS_DONE, ST_LOGS_ERROR};

static const struct parser_state_transition logs_parser_state_L_transitions[] = {
    { .when = 'L', .dest = ST_LOGS_O, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_O_transitions[] = {
    { .when = 'O', .dest = ST_LOGS_G, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_G_transitions[] = {
    { .when = 'G', .dest = ST_LOGS_S, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_S_transitions[] = {
    { .when = 'S', .dest = ST_LOGS_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_LOGS_INPUT, .act1 = ignore }, 
    { .when = '\r', .dest = ST_LOGS_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_LOGS_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LOGS_DONE, .act1 = set_type_success }, 
    { .when = CLASS_NUM, .dest = ST_LOGS_INPUT, .act1 = set_type_input },
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_LOGS_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const struct parser_state_transition logs_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition logs_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_LOGS_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_LOGS_ERROR, .act1 = ignore }
};

static const size_t logs_parser_states_n[] = {3, 3, 3, 3, 4, 4, 2, 0, 2};

static const struct parser_state_transition* logs_parser_state_transitions[] = {
    logs_parser_state_L_transitions,
    logs_parser_state_O_transitions,
    logs_parser_state_G_transitions,
    logs_parser_state_S_transitions,
    logs_parser_state_SPACE_transitions,
    logs_parser_state_INPUT_transitions,
    logs_parser_state_NL_transitions,
    logs_parser_state_DONE_transitions,
    logs_parser_state_ERROR_transitions,
};

static const struct parser_definition logs_parser_def = {
    .states_count = ST_LOGS_ERROR,
    .states = logs_parser_state_transitions,
    .states_n = logs_parser_states_n,
    .start_state = ST_LOGS_L
};

enum config_parser_states { ST_CONFIG_C, ST_CONFIG_O1, ST_CONFIG_N, ST_CONFIG_F, ST_CONFIG_I1, ST_CONFIG_G, ST_CONFIG_SPACE, ST_CONFIG_I2, ST_CONFIG_O2, ST_CONFIG_EQUALS, ST_CONFIG_INPUT, ST_CONFIG_NL, ST_CONFIG_DONE, ST_CONFIG_ERROR};

static const struct parser_state_transition config_parser_state_C_transitions[] = {
    { .when = 'C', .dest = ST_CONFIG_O1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_O1_transitions[] = {
    { .when = 'O', .dest = ST_CONFIG_N, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_N_transitions[] = {
    { .when = 'N', .dest = ST_CONFIG_F, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_F_transitions[] = {
    { .when = 'F', .dest = ST_CONFIG_I1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_I1_transitions[] = {
    { .when = 'I', .dest = ST_CONFIG_G, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_G_transitions[] = {
    { .when = 'G', .dest = ST_CONFIG_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_CONFIG_I2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_DONE, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_I2_transitions[] = {
    { .when = 'I', .dest = ST_CONFIG_O2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_DONE, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_O2_transitions[] = {
    { .when = 'O', .dest = ST_CONFIG_EQUALS, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_DONE, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_EQUALS_transitions[] = {
    { .when = '=', .dest = ST_CONFIG_INPUT, .act1 = ignore },
    { .when = '\r', .dest = ST_LOGS_NL, .act1 = ignore }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_CONFIG_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_CONFIG_DONE, .act1 = set_type_success }, 
    { .when = CLASS_NUM, .dest = ST_CONFIG_INPUT, .act1 = set_type_input },
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_CONFIG_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const struct parser_state_transition config_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition config_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_CONFIG_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_CONFIG_ERROR, .act1 = ignore }
};

static const size_t config_parser_states_n[] = {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 2, 0, 2};

static const struct parser_state_transition* config_parser_state_transitions[] = {
    config_parser_state_C_transitions,
    config_parser_state_O1_transitions,
    config_parser_state_N_transitions,
    config_parser_state_F_transitions,
    config_parser_state_I1_transitions,
    config_parser_state_G_transitions,
    config_parser_state_SPACE_transitions,
    config_parser_state_I2_transitions,
    config_parser_state_O2_transitions,
    config_parser_state_EQUALS_transitions,
    config_parser_state_INPUT_transitions,
    config_parser_state_NL_transitions,
    config_parser_state_DONE_transitions,
    config_parser_state_ERROR_transitions,
};

static const struct parser_definition config_parser_def = {
    .states_count = ST_CONFIG_ERROR,
    .states = config_parser_state_transitions,
    .states_n = config_parser_states_n,
    .start_state = ST_CONFIG_C
};

enum add_parser_states { ST_ADD_A1, ST_ADD_D1, ST_ADD_D2, ST_ADD_SPACE, 
                         ST_ADD_B_A3, ST_ADD_A2, ST_ADD_S, ST_ADD_I1, ST_ADD_C,
                                      ST_ADD_D3, ST_ADD_M, ST_ADD_I2, ST_ADD_N,
                         ST_ADD_CR_BASIC, ST_ADD_NL_BASIC, ST_ADD_DONE_BASIC,
                         ST_ADD_CR_ADMIN, ST_ADD_NL_ADMIN, ST_ADD_DONE_ADMIN, ST_ADD_ERROR, };

static const struct parser_state_transition add_parser_state_A1_transitions[] = {
    { .when = 'A', .dest = ST_ADD_D1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_D1_transitions[] = {
    { .when = 'D', .dest = ST_ADD_D2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_D2_transitions[] = {
    { .when = 'D', .dest = ST_ADD_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_ADD_B_A3, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_B_A3_transitions[] = {
    { .when = 'B', .dest = ST_ADD_A2, .act1 = ignore }, 
    { .when = 'A', .dest = ST_ADD_D3, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_A2_transitions[] = {
    { .when = 'A', .dest = ST_ADD_S, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_S_transitions[] = {
    { .when = 'S', .dest = ST_ADD_I1, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_I1_transitions[] = {
    { .when = 'I', .dest = ST_ADD_C, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_C_transitions[] = {
    { .when = 'C', .dest = ST_ADD_CR_BASIC, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_D3_transitions[] = {
    { .when = 'D', .dest = ST_ADD_M, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_M_transitions[] = {
    { .when = 'M', .dest = ST_ADD_I2, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_I2_transitions[] = {
    { .when = 'I', .dest = ST_ADD_N, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_N_transitions[] = {
    { .when = 'N', .dest = ST_ADD_CR_ADMIN, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_CR_BASIC_transitions[] = {
    { .when = '\r', .dest = ST_ADD_NL_BASIC, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_DONE_BASIC, .act1 = set_type_basic }, 
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_NL_BASIC_transitions[] = {
    { .when = '\n', .dest = ST_ADD_DONE_BASIC, .act1 = set_type_basic }, 
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_DONE_BASIC_transitions[] = {0};

static const struct parser_state_transition add_parser_state_CR_ADMIN_transitions[] = {
    { .when = '\r', .dest = ST_ADD_NL_ADMIN, .act1 = ignore }, 
    { .when = '\n', .dest = ST_ADD_DONE_ADMIN, .act1 = set_type_admin }, 
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_NL_ADMIN_transitions[] = {
    { .when = '\n', .dest = ST_ADD_DONE_ADMIN, .act1 = set_type_admin }, 
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const struct parser_state_transition add_parser_state_DONE_ADMIN_transitions[] = {0};

static const struct parser_state_transition add_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_ADD_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_ADD_ERROR, .act1 = ignore }
};

static const size_t add_parser_states_n[] = {3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 0, 3, 2, 0, 2};

static const struct parser_state_transition* add_parser_state_transitions[] = {
    add_parser_state_A1_transitions,
    add_parser_state_D1_transitions,
    add_parser_state_D2_transitions,
    add_parser_state_SPACE_transitions,
    add_parser_state_B_A3_transitions,
    add_parser_state_A2_transitions,
    add_parser_state_S_transitions,
    add_parser_state_I1_transitions,
    add_parser_state_C_transitions,
    add_parser_state_D3_transitions,
    add_parser_state_M_transitions,
    add_parser_state_I2_transitions,
    add_parser_state_N_transitions,
    add_parser_state_CR_BASIC_transitions,
    add_parser_state_NL_BASIC_transitions,
    add_parser_state_DONE_BASIC_transitions,
    add_parser_state_CR_ADMIN_transitions,
    add_parser_state_NL_ADMIN_transitions,
    add_parser_state_DONE_ADMIN_transitions,
    add_parser_state_ERROR_transitions,
};

static const struct parser_definition add_parser_def = {
    .states_count = ST_ADD_ERROR,
    .states = add_parser_state_transitions,
    .states_n = add_parser_states_n,
    .start_state = ST_ADD_A1
};

enum del_parser_states { ST_DEL_D, ST_DEL_E, ST_DEL_L, ST_DEL_SPACE, ST_DEL_INPUT, ST_DEL_NL, ST_DEL_DONE, ST_DEL_ERROR};

static const struct parser_state_transition del_parser_state_D_transitions[] = {
    { .when = 'D', .dest = ST_DEL_E, .act1 = ignore }, 
    { .when = '\n', .dest = ST_DEL_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_E_transitions[] = {
    { .when = 'E', .dest = ST_DEL_L, .act1 = ignore }, 
    { .when = '\n', .dest = ST_DEL_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_L_transitions[] = {
    { .when = 'L', .dest = ST_DEL_SPACE, .act1 = ignore }, 
    { .when = '\n', .dest = ST_DEL_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_SPACE_transitions[] = {
    { .when = ' ', .dest = ST_DEL_INPUT, .act1 = ignore }, 
    { .when = '\n', .dest = ST_DEL_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_INPUT_transitions[] = {
    { .when = '\r', .dest = ST_DEL_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_DEL_DONE, .act1 = set_type_success }, 
    { .when = CLASS_ALNUM, .dest = ST_DEL_INPUT, .act1 = set_type_input },
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_DEL_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const struct parser_state_transition del_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition del_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_DEL_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_DEL_ERROR, .act1 = ignore }
};

static const size_t del_parser_states_n[] = {3, 3, 3, 3, 4, 2, 0, 2};

static const struct parser_state_transition* del_parser_state_transitions[] = {
    del_parser_state_D_transitions,
    del_parser_state_E_transitions,
    del_parser_state_L_transitions,
    del_parser_state_SPACE_transitions,
    del_parser_state_INPUT_transitions,
    del_parser_state_NL_transitions,
    del_parser_state_DONE_transitions,
    del_parser_state_ERROR_transitions,
};

static const struct parser_definition del_parser_def = {
    .states_count = ST_DEL_ERROR,
    .states = del_parser_state_transitions,
    .states_n = del_parser_states_n,
    .start_state = ST_DEL_D
};

enum list_parser_states { ST_LIST_L, ST_LIST_I, ST_LIST_S, ST_LIST_T, ST_LIST_CR, ST_LIST_NL, ST_LIST_DONE, ST_LIST_ERROR};

static const struct parser_state_transition list_parser_state_L_transitions[] = {
    { .when = 'L', .dest = ST_LIST_I, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LIST_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_I_transitions[] = {
    { .when = 'I', .dest = ST_LIST_S, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LIST_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_S_transitions[] = {
    { .when = 'S', .dest = ST_LIST_T, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LIST_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_T_transitions[] = {
    { .when = 'T', .dest = ST_LIST_CR, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LIST_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_CR_transitions[] = {
    { .when = '\r', .dest = ST_LIST_NL, .act1 = ignore }, 
    { .when = '\n', .dest = ST_LIST_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_NL_transitions[] = {
    { .when = '\n', .dest = ST_LIST_DONE, .act1 = set_type_success }, 
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const struct parser_state_transition list_parser_state_DONE_transitions[] = {0};

static const struct parser_state_transition list_parser_state_ERROR_transitions[] = {
    { .when = '\n', .dest = ST_LIST_ERROR, .act1 = set_type_error }, 
    { .when = ANY, .dest = ST_LIST_ERROR, .act1 = ignore }
};

static const size_t list_parser_states_n[] = {3, 3, 3, 3, 3, 2, 0, 2};

static const struct parser_state_transition* list_parser_state_transitions[] = {
    list_parser_state_L_transitions,
    list_parser_state_I_transitions,
    list_parser_state_S_transitions,
    list_parser_state_T_transitions,
    list_parser_state_CR_transitions,
    list_parser_state_NL_transitions,
    list_parser_state_DONE_transitions,
    list_parser_state_ERROR_transitions,
};

static const struct parser_definition list_parser_def = {
    .states_count = ST_LIST_ERROR,
    .states = list_parser_state_transitions,
    .states_n = list_parser_states_n,
    .start_state = ST_LIST_L
};

enum exit_parser_states { ST_EXIT_E, ST_EXIT_X, ST_EXIT_I, ST_EXIT_T, ST_EXIT_CR, ST_EXIT_NL, ST_EXIT_DONE, ST_EXIT_ERROR};

static const struct parser_state_transition exit_parser_state_E_transitions[] = {
    { .when = 'E', .dest = ST_EXIT_X, .act1 = ignore }, 
    { .when = '\n', .dest = ST_EXIT_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_X_transitions[] = {
    { .when = 'X', .dest = ST_EXIT_I, .act1 = ignore }, 
    { .when = '\n', .dest = ST_EXIT_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_I_transitions[] = {
    { .when = 'I', .dest = ST_EXIT_T, .act1 = ignore }, 
    { .when = '\n', .dest = ST_EXIT_ERROR, .act1 = set_type_error },
    { .when = ANY, .dest = ST_EXIT_ERROR, .act1 = ignore }
};

static const struct parser_state_transition exit_parser_state_T_transitions[] = {
    { .when = 'T', .dest = ST_EXIT_CR, .act1 = ignore }, 
    { .when = '\n', .dest = ST_EXIT_ERROR, .act1 = set_type_error },
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

static const size_t exit_parser_states_n[] = {3, 3, 3, 3, 3, 2, 0, 2};

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
    .states = exit_parser_state_transitions,
    .states_n = exit_parser_states_n,
    .start_state = ST_EXIT_E
};

#endif