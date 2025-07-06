#ifndef SOCKS5_PROTOCOL_H
#define SOCKS5_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "server_config.h"

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
#define SOCKS5_REP_GENERAL_FAILURE    0x01
#define SOCKS5_REP_CONNECTION_NOT_ALLOWED    0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE    0x03
#define SOCKS5_REP_HOST_UNREACH     0x04
#define SOCKS5_REP_CONNECTION_REFUSED    0x05
#define SOCKS5_REP_TTL_EXPIRED     0x06
#define SOCKS5_REP_COMMAND_NOT_SUPPORTED    0x07
#define SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED    0x08

#define SOCKS5_RSV_EXPECTED 0x00

// Códigos de autenticación subnegociación (RFC 1929)
#define AUTH_SUCCESS    0x00
#define AUTH_FAILURE    0x01

// Tamaños de protocolo SOCKS5
#define SOCKS5_HELLO_MIN_SIZE    3    // VER + NMETHODS + al menos 1 método
#define SOCKS5_AUTH_MIN_SIZE     5    // VER + ULEN + usuario(min 1) + PLEN + password(min 1)  
#define SOCKS5_REQUEST_MIN_SIZE  6    // VER + CMD + RSV + ATYP + mínimo addr + puerto

// Tamaños específicos para IPv6
#define SOCKS5_IPV4_ADDR_SIZE    4 
#define SOCKS5_IPV6_ADDR_SIZE    16
#define SOCKS5_PORT_SIZE         2
#define SOCKS5_RESPONSE_HEADER_SIZE  4    // VER + REP + RSV + ATYP

// Tamaños de respuesta según tipo de dirección
#define SOCKS5_RESPONSE_IPV4_SIZE    (SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV4_ADDR_SIZE + SOCKS5_PORT_SIZE)
#define SOCKS5_RESPONSE_IPV6_SIZE    (SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV6_ADDR_SIZE + SOCKS5_PORT_SIZE)

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
    union {
        uint8_t ipv4[4];
        uint8_t ipv6[16];
    } addr;
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

socks5_hello_response create_hello_response(uint8_t method);
auth_response create_auth_response(uint8_t status);
socks5_response create_socks5_response(uint8_t rep);
socks5_response create_socks5_response_with_addr(uint8_t rep, uint8_t atyp, const void* addr, uint16_t port);
size_t get_socks5_response_size(uint8_t atyp);
int get_socket_local_address(int sockfd, uint8_t* atyp, void* addr, uint16_t* port);

typedef struct {
    bool valid;
    uint8_t version;
    uint8_t nmethods;
    bool supports_userpass;
    uint8_t selected_method;
} socks5_hello_parser_result;

typedef struct {
    bool valid;
    bool auth_ok;
    char username[256];
    char password[256];
} socks5_auth_parser_result;

typedef struct {
    bool valid;
    uint8_t cmd;
    uint8_t atyp;
    char target_host[256];
    uint16_t target_port;
    size_t total_size;
} socks5_request_parser_result;

socks5_hello_parser_result parse_socks5_hello(uint8_t* data, size_t data_len);
socks5_auth_parser_result parse_socks5_auth(uint8_t* data, size_t data_len, server_config* config);
socks5_request_parser_result parse_socks5_request(uint8_t* data, size_t data_len);

#endif