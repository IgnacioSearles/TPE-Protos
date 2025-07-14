/**
 * pctp.c - Proxy Configuration and Tracking Protocol
 *
 * Implementa un protocolo de administración personalizado para el servidor
 * SOCKS5 que permite:
 *  - Autenticación de administradores
 *  - Gestión dinámica de usuarios (agregar, eliminar, listar)
 *  - Consulta de estadísticas en tiempo real
 *  - Configuración dinámica de parámetros del servidor
 *  - Acceso a logs de conexiones
 *
 * El protocolo funciona sobre TCP con comandos de texto plano y respuestas
 * estructuradas. Utiliza una máquina de estados para manejar el flujo de
 * autenticación y procesamiento de comandos.
 *
 * Flujo típico de una sesión PCTP:
 *  1. Conexión del cliente administrativo
 *  2. Autenticación: USER <username> -> PASS <password>
 *  3. Comandos disponibles: STATS, LIST, ADD, DEL, CONFIG, LOGS
 *  4. Cierre de sesión: EXIT
 *
 * Todas las operaciones son logged y pueden ser auditadas.
 */

#ifndef PCTP_H
#define PCTP_H

#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "../shared/stm.h"
#include "../shared/parser.h"
#include "server_config.h"
#include "server_stats.h"

/** Tamaño máximo para credenciales de usuario */
#define MAX_CREDENTIAL_SIZE 24
/** Longitud máxima de un mensaje individual */
#define MAX_MSG_LEN 1024
/** Número máximo de mensajes que se pueden enviar */
#define MAX_MSG_TO_SEND 5000
/** Tamaño del buffer de I/O basado en límites de mensajes */
#define IO_BUFFER_SIZE MAX_MSG_LEN * MAX_MSG_TO_SEND
/** Dígitos máximos para especificar cantidad de logs */
#define MAX_LOGS_DIGITS 24
/** Dígitos máximos para configuración de I/O */
#define MAX_IO_DIGITS 24
/** Cantidad por defecto de logs a enviar */
#define DEFAULT_LOGS_TO_SEND 100

/**
 * Estructura principal para sesiones PCTP
 * 
 * Mantiene el estado completo de una sesión administrativa,
 * incluyendo buffers, parsers y datos de autenticación.
 */
typedef struct pctp {
    /** Configuración global del servidor */
    server_config* config;
    /** Estadísticas globales del servidor */
    server_stats stats;

    /** Descriptor del cliente administrativo */
    int client_fd;

    /** Buffer raw para lectura */
    uint8_t read_raw_buff[IO_BUFFER_SIZE];
    /** Buffer estructurado para lectura */
    buffer read_buffer;

    /** Buffer raw para escritura */
    uint8_t write_raw_buff[IO_BUFFER_SIZE];
    /** Buffer estructurado para escritura */
    buffer write_buffer;

    /** Máquina de estados para procesamiento asíncrono */
    struct state_machine stm;
    
    /** Manejadores de eventos del selector */
    struct fd_handler handlers;
    
    /** Parsers para diferentes comandos PCTP */
    struct parser *user_parser;
    struct parser *pass_parser;
    struct parser *stats_parser;
    struct parser *logs_parser;
    struct parser *add_parser;
    struct parser *del_parser;
    struct parser *list_parser;
    struct parser *config_parser;
    struct parser *exit_parser;

    /** Identificador único de sesión */
    int id;

    /** Datos de autenticación parseados */
    /** Nombre de usuario para login */
    char username[MAX_CREDENTIAL_SIZE];
    int username_len;
    /** Contraseña para login */
    char password[MAX_CREDENTIAL_SIZE];
    int password_len;

    /** Datos para creación de nuevos usuarios */
    /** Nuevo nombre de usuario */
    char new_username[MAX_CREDENTIAL_SIZE];
    int new_username_len;
    /** Nueva contraseña */
    char new_password[MAX_CREDENTIAL_SIZE];
    int new_password_len;
    /** Nivel de privilegios del nuevo usuario */
    int level;

    /** Usuario a eliminar */
    char del_username[MAX_CREDENTIAL_SIZE];
    int del_username_len;

    /** Parámetro para comando LOGS */
    char logs_n[MAX_LOGS_DIGITS+1];
    int logs_n_len;
    
    /** Parámetro para configuración de I/O */
    char io_config[MAX_IO_DIGITS+1];
    int io_config_len;
} pctp;

/**
 * Inicializa una nueva sesión PCTP
 * 
 * @param client_fd descriptor del cliente administrativo
 * @param s selector para registro de eventos
 * @param config configuración global del servidor
 * @param stats estructura de estadísticas del servidor
 * @return 0 en caso de éxito, -1 en caso de error
 */
int pctp_init(const int client_fd, fd_selector s, server_config* config, server_stats stats);

#endif
