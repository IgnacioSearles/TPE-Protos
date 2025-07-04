#ifndef CLIENT_PARAMS_H
#define CLIENT_PARAMS_H

typedef struct {
    char* host;
    char* port;
    char* log_level;
} client_config;

/*
 *  Parsea los argumentos del programa seteando la configuracion
 *
 *  retorna menor a 0 si hay error
 * */
int client_params_parse(int argc, char** argv, client_config* config);

/*
 * Limpia recursos utilizados por la configuracion 
 * */
void client_config_destroy(client_config* config);

#endif
