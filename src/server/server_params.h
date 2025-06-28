#ifndef SERVER_PARAMS_H
#define SERVER_PARAMS_H

#include "server_config.h"

typedef enum {
    PARAMS_SUCCESS,
    PARAMS_SHOULD_EXIT,
    PARAMS_ERROR
} parse_server_params_status;

/*
 * Parsea los argumentos del programa
 *
 * */
parse_server_params_status parse_server_params(int argc, char** argv, server_config* config);

#endif
