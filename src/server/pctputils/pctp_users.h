#ifndef PCTP_USERS_H
#define PCTP_USERS_H

/**
 * pctp_users.h - Gestión dinámica de usuarios PCTP
 *
 * Implementa los comandos ADD y DEL para gestión dinámica de usuarios
 * del servidor SOCKS5. Permite a administradores agregar y eliminar
 * usuarios en tiempo real sin reiniciar el servidor.
 *
 * Funcionalidades:
 *  - Agregar usuarios BASIC y ADMIN
 *  - Validación de nombres de usuario únicos
 *  - Eliminación segura de usuarios
 *  - Persistencia de cambios en configuración
 */

#include "../pctp.h"

/** Estados de gestión de usuarios */
#define USER_ADD_WRITE                  9
#define USER_ADD_USER_READ              10
#define USER_ADD_USER_SUCCESS_WRITE     11
#define USER_ADD_USER_INVALID_WRITE     12
#define USER_ADD_USER_ERROR_WRITE       13
#define USER_ADD_PASS_READ              14
#define USER_ADD_PASS_ERROR_WRITE       16

/** Funciones de agregado de usuarios */
unsigned add_write(struct selector_key *key);
unsigned add_user_read(struct selector_key *key);
unsigned add_user_success_write(struct selector_key *key);
unsigned add_user_invalid_write(struct selector_key *key);
unsigned add_user_error_write(struct selector_key *key);

unsigned add_pass_read(struct selector_key *key);
unsigned add_pass_error_write(struct selector_key *key);

/** Funciones de reset de estado */
void reset_add_state(const unsigned state, struct selector_key *key);
void reset_new_user_state(const unsigned state, struct selector_key *key);
void reset_new_pass_state(const unsigned state, struct selector_key *key);

/** Validación de usuarios */
int check_new_username(pctp* pctp_data);

#endif
