#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdint.h>

#define SOCKS5_STD_PORT 1080
#define PCTP_STD_PORT 8080
#define VERSION "0.1"

#define MAX_INITIAL_USERS 10
#define MAX_USERS 50

typedef enum {
    BASIC,
    ADMIN
} user_role;

typedef struct {
    char* user;
    char* pass;
    user_role role;
} server_user;

typedef struct {
    char *socks_addr;
    char *pctp_addr;
    char *log_level;
    uint16_t socks_port;
    uint16_t pctp_port;
    server_user users[MAX_USERS];
    int user_count;
} server_config;

/*
 *  Agregar un usuario al servidor
 *
 *  Retorna < 0 si no pudo agregar el usuario
 *
 * */
int add_user(server_config* config, char* user, char* pass, user_role role);

/*
 *  Crea la configuracion inicial se guarda en el stack, no hace malloc
 * */
server_config create_config();

/*
 *  Limpia los datos internos de la configuracion
 * */
void destroy_config(server_config* config);

#endif
