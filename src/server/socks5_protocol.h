#ifndef SOCKS5_PROTOCOL_H
#define SOCKS5_PROTOCOL_H

#include <stdint.h>

#define SOCKS5_VERSION 0x05
#define AUTH_VERSION 0x01

// Métodos de autenticación (RFC 1928)
#define AUTH_METHOD_NO_AUTH     0x00
#define AUTH_METHOD_GSSAPI      0x01
#define AUTH_METHOD_USER_PASS   0x02
#define AUTH_METHOD_NO_METHODS  0xFF

// Comandos SOCKS5 (RFC 1928)
#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOC    0x03

// Tipos de dirección (RFC 1928)
#define SOCKS5_ATYP_IPV4        0x01
#define SOCKS5_ATYP_DOMAIN      0x03
#define SOCKS5_ATYP_IPV6        0x04

// Códigos de respuesta (RFC 1928)
#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_FAILURE      0x01
#define SOCKS5_REP_NOT_ALLOWED  0x02
#define SOCKS5_REP_NET_UNREACH  0x03
#define SOCKS5_REP_HOST_UNREACH 0x04
#define SOCKS5_REP_REFUSED      0x05
#define SOCKS5_REP_TTL_EXPIRED  0x06
#define SOCKS5_REP_CMD_NOT_SUP  0x07
#define SOCKS5_REP_ATYP_NOT_SUP 0x08

#define AUTH_SUCCESS            0x00
#define AUTH_FAILURE            0x01

#define MAX_REQUEST_SIZE 262 // Tamaño máximo de un request según RFC 1928

typedef struct {
    uint8_t version;
    uint8_t nmethods;
    uint8_t methods[255];
} socks5_hello_request;

typedef struct {
    uint8_t version;
    uint8_t method;
} socks5_hello_response;

typedef struct {
    uint8_t version;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
} socks5_request_header;

typedef struct {
    uint8_t version;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
    uint8_t addr[4];  // Para IPv4
    uint16_t port;
} socks5_response;

typedef struct {
    uint8_t version;
    uint8_t ulen;
    char username[255];
    uint8_t plen;
    char password[255];
} auth_request;

typedef struct {
    uint8_t version;
    uint8_t status;
} auth_response;

// Declaraciones de funciones (implementadas en socks5_protocol.c)
socks5_hello_response create_hello_response(uint8_t method);
auth_response create_auth_response(uint8_t status);
socks5_response create_socks5_response(uint8_t rep);

#endif
