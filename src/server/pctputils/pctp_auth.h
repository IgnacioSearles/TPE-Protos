#ifndef PCTP_AUTH_H
#define PCTP_AUTH_H

/**
 * pctp_auth.h - Manejo de autenticación en protocolo PCTP
 *
 * Implementa los estados y funciones para el proceso de autenticación
 * de administradores en el protocolo PCTP. Maneja el flujo secuencial
 * de USER -> PASS y validación contra credenciales configuradas.
 */

#include "../pctp.h"

/** Estados de autenticación de usuario */
#define AUTH_LOGIN_USER_READ            0
#define AUTH_LOGIN_USER_SUCCESS_WRITE   1  
#define AUTH_LOGIN_USER_INVALID_WRITE   2
#define AUTH_LOGIN_USER_ERROR_WRITE     3
#define AUTH_LOGIN_PASS_READ            4
#define AUTH_LOGIN_PASS_INVALID_WRITE   5
#define AUTH_LOGIN_PASS_ERROR_WRITE     6

/** Funciones de procesamiento de usuario */
unsigned login_user_read(struct selector_key *key);
unsigned login_user_success_write(struct selector_key *key);
unsigned login_user_invalid_write(struct selector_key *key);
unsigned login_user_error_write(struct selector_key *key);

/** Funciones de procesamiento de contraseña */
unsigned login_pass_read(struct selector_key *key);
unsigned login_pass_invalid_write(struct selector_key *key);
unsigned login_pass_error_write(struct selector_key *key);

/** Funciones de reset de estado */
void reset_user_state(const unsigned state, struct selector_key *key);
void reset_pass_state(const unsigned state, struct selector_key *key);

/** Funciones de validación */
int check_admin_username(pctp* pctp_data);
int check_admin_password(pctp* pctp_data);

#endif
