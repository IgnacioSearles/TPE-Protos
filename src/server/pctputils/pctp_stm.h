#ifndef PCTP_STM_H
#define PCTP_STM_H

/**
 * pctp_stm.h - Máquina de estados del protocolo PCTP
 *
 * Define la máquina de estados principal para el protocolo PCTP,
 * integrando todos los módulos de autenticación, comandos y gestión de usarios
 */

#include "../pctp.h"

/** Funciones de configuración de intereses del selector */
void selector_set_interest_read(const unsigned state, struct selector_key *key);
void selector_set_interest_write(const unsigned state, struct selector_key *key);

/** Callback de cierre de conexión */
void on_close(const unsigned state, struct selector_key *key);

/** Manejadores principales de eventos */
void pctp_read(struct selector_key *key);
void pctp_write(struct selector_key *key);
void pctp_close(struct selector_key *key);

/** Definición completa de la máquina de estados PCTP */
extern const struct state_definition pctp_states[];

#endif
