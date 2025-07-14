#ifndef SOCKS5_H
#define SOCKS5_H

/**
 * socks5.c - Implementación del protocolo SOCKS5 según RFC 1928
 *
 * Implementa un servidor proxy SOCKS5 completo que maneja:
 *  - Negociación inicial y métodos de autenticación
 *  - Autenticación usuario/contraseña (RFC 1929)
 *  - Resolución de nombres y conexiones TCP
 *  - Transferencia bidireccional de datos
 *  - Logging y estadísticas de conexiones
 *
 * La implementación utiliza una máquina de estados asíncrona para manejar
 * múltiples conexiones concurrentes sin bloqueo. Cada conexión pasa por
 * los siguientes estados principales:
 *  - HELLO: negociación inicial y selección de método de autenticación
 *  - AUTH: autenticación usuario/contraseña si es requerida
 *  - REQUEST: procesamiento de la solicitud de conexión
 *  - RESOLV: resolución asíncrona de nombres (si es necesaria)
 *  - CONNECTING: establecimiento de conexión con el destino
 *  - COPY: transferencia bidireccional de datos
 *
 * El servidor mantiene estadísticas globales de conexiones y bytes
 * transferidos que pueden ser consultadas vía el protocolo PCTP.
 */

#include "../shared/stm.h"
#include "../shared/buffer.h"
#include "../shared/selector.h"
#include "server_config.h"
#include "server_stats.h"
#include <netinet/in.h>

#define MAX_DATA_SIZE 256

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

/** Estados de la máquina de estados SOCKS5 */
typedef enum socks5_state {
    /** Lectura del saludo inicial del cliente */
    HELLO_READ,
    /** Envío de respuesta al saludo inicial */
    HELLO_WRITE,
    /** Lectura de credenciales de autenticación */
    AUTH_READ,
    /** Envío de respuesta de autenticación */
    AUTH_WRITE,
    /** Lectura de solicitud de conexión */
    REQUEST_READ,
    /** Envío de respuesta a la solicitud */
    REQUEST_WRITE,
    /** Estableciendo conexión con el destino */
    CONNECTING,
    /** Esperando conexión asíncrona */
    AWAITING_CONNECTION,
    /** Enviando respuesta de conexión */
    CONNECTING_RESPONSE,
    /** Transferencia bidireccional de datos */
    COPY,
    /** Conexión terminada exitosamente */
    DONE,
    /** Error en el procesamiento */
    ERROR,
} socks5_state;

/** Estructura para parsear solicitudes SOCKS5 */
typedef struct {
    /** Versión del protocolo SOCKS */
    uint8_t version;
    /** Comando solicitado (CONNECT, BIND, UDP) */
    uint8_t cmd;
    /** Tipo de dirección (IPv4, IPv6, FQDN) */
    uint8_t atyp;
    /** Host de destino */
    char target_host[MAX_DATA_SIZE];
    /** Puerto de destino */
    uint16_t target_port;
} parsed_request;

/** 
 * Estructura principal que mantiene el estado de una conexión SOCKS5
 * 
 * Cada conexión de cliente genera una instancia de esta estructura
 * que persiste durante toda la sesión SOCKS5.
 */
typedef struct socks5 {
    /** Descriptor del socket del cliente */
    int client_fd;
    /** Descriptor del socket hacia el destino */
    int origin_fd;
    
    /** Estado actual de la máquina de estados */
    socks5_state state;
    /** Máquina de estados para manejo asíncrono */
    struct state_machine stm;
    
    /** Buffer para lectura de datos */
    buffer read_buffer;
    /** Buffer para escritura de datos */
    buffer write_buffer;
    
    /** Buffer raw para lectura */
    uint8_t* read_raw_buff;
    /** Buffer raw para escritura */
    uint8_t* write_raw_buff;
    
    /** Configuración global del servidor */
    server_config* config;
    /** Estadísticas globales del servidor */
    server_stats stats;
    
    /** Método de autenticación negociado */
    uint8_t auth_method;
    /** Estado de la autenticación */
    bool auth_ok;
    
    /** Host de destino parseado */
    char target_host[MAX_DATA_SIZE];
    /** Puerto de destino parseado */
    uint16_t target_port;
    /** Tipo de dirección de destino */
    uint8_t target_atyp;
    /** Código de respuesta SOCKS5 */
    uint8_t reply_code;

    /** Resultado de resolución de nombres */
    struct addrinfo *res;

    /** Inicio al resultado de resolución de nombres */
    struct addrinfo *start_res;
} socks5;

/**
 * Inicializa una nueva sesión SOCKS5
 * 
 * @param client_fd descriptor del cliente conectado
 * @param s selector para registro de eventos
 * @param config configuración global del servidor
 * @param stats estructura de estadísticas para actualizar
 * @return 0 en caso de éxito, -1 en caso de error
 */
int socks5_init(const int client_fd, fd_selector s, server_config* config, server_stats stats);

#endif
