#ifndef PCTP_PROTOCOL_H
#define PCTP_PROTOCOL_H

/**
 * pctp_protocol.h - Definiciones del protocolo PCTP
 *
 * Contiene todas las constantes, mensajes y estados del protocolo
 * de administración PCTP (Proxy Configuration and Tracking Protocol).
 *
 * Mensajes del protocolo:
 *  - Respuestas exitosas (+OK)
 *  - Mensajes de error (-ERR)
 *  - Formatos de datos estructurados
 *
 * Estados de la máquina de estados:
 *  - Estados de autenticación (LOGIN_*)
 *  - Estados de comandos principales (MAIN_*)
 *  - Estados de gestión de usuarios (ADD_*)
 */

#include "buffer.h"

/** Mensajes de respuesta exitosa del protocolo */
#define OK_USER_MSG "+OK Please send password\n"
#define OK_PASS_MSG "+OK Successfully logged in\n"
#define OK_STATS_MSG "+OK Sending stats...\n"
#define OK_LOGS_MSG "+OK Sending logs...\n"
#define OK_IO_CONFIG_MSG "+OK Setting IO buffers size\n"
#define OK_ADD_MSG "+OK Please provide new user credentials\n"
#define OK_ADD_PASS_MSG "+OK Successfully added user\n"
#define OK_DEL_MSG "+OK Successfully deleted user\n"
#define OK_LIST_MSG "+OK Sending user list...\n"
#define OK_DONE_MSG "+OK Done\n"

/** Formatos para datos estructurados */
#define CURRENT_CONNECTIONS_MSG "current_connections: %ld\n"
#define TOTAL_CONNECTIONS_MSG "total_connections: %ld\n"
#define CURRENT_BYTES_PROXIED_MSG "current_bytes_proxied: %ld\n"
#define TOTAL_BYTES_PROXIED_MSG "total_bytes_proxied: %ld\n"
#define LOG_ENTRY_MSG "%d-%02d-%02dT%02d:%02d:%02dZ\t%s\tA\t%s\t%d\t%s\t%d\t%d\t%ld\t%s\n"
#define USER_ENTRY_MSG "%s\t%s\n"
#define EMPTY_MSG "\n"

/** Mensajes de error del protocolo */
#define ERR_INVALID_USER_MSG "-ERR Invalid username\n"
#define ERR_INVALID_PASS_MSG "-ERR Invalid password\n"
#define ERR_DEL_MSG "-ERR Could not delete user\n"
#define ERR_INVALID_COMMAND_MSG "-ERR Invalid command for current state\n"
#define ERR_OOM_MSG "-ERR Out of memory\n"

/** Estados de la máquina de estados PCTP */
enum pctp_states {
    /** Leyendo nombre de usuario */
    LOGIN_USER_READ,
    /** Confirmando usuario válido */
    LOGIN_USER_SUCCESS_WRITE,
    /** Usuario inválido */
    LOGIN_USER_INVALID_WRITE,
    /** Error en usuario */
    LOGIN_USER_ERROR_WRITE,
    /** Leyendo contraseña */
    LOGIN_PASS_READ,
    /** Contraseña inválida */
    LOGIN_PASS_INVALID_WRITE,
    /** Error en contraseña */
    LOGIN_PASS_ERROR_WRITE,
    /** Estado principal - leyendo comandos */
    MAIN_READ,
    /** Estado principal - enviando respuestas */
    MAIN_WRITE,
    /** Procesando comando ADD */
    ADD_WRITE,
    /** Leyendo usuario nuevo */
    ADD_USER_READ,
    /** Usuario nuevo aceptado */
    ADD_USER_SUCCESS_WRITE,
    /** Usuario nuevo inválido */
    ADD_USER_INVALID_WRITE,
    /** Error en usuario nuevo */
    ADD_USER_ERROR_WRITE,
    /** Leyendo contraseña nueva */
    ADD_PASS_READ,
    /** Error en contraseña nueva */
    ADD_PASS_ERROR_WRITE,
    /** Procesando comando EXIT */
    EXIT_WRITE,
    /** Sesión terminada */
    DONE,
    /** Error en el protocolo */
    ERROR,
};

/** Estados de envío de mensajes */
enum msg_send {
    /** Mensaje enviado exitosamente */
    MSG_SENT,
    /** Envío bloqueado por buffer lleno */
    MSG_SEND_BLOCKED,
    /** Error en el envío */
    MSG_SEND_ERROR
};

/**
 * Escribe un mensaje en el buffer de escritura
 * @param write_buffer buffer donde escribir
 * @param msg mensaje a escribir
 */
void write_msg_to_buffer(buffer* write_buffer, const char* msg);

/**
 * Envía el contenido del buffer al descriptor
 * @param fd descriptor de archivo
 * @param write_buffer buffer con datos a enviar
 * @return estado del envío según enum msg_send
 */
int send_buffer_msg(int fd, buffer* write_buffer);

#endif