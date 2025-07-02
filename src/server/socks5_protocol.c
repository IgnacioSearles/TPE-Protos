#include "socks5_protocol.h"

socks5_hello_response create_hello_response(uint8_t method) {
    socks5_hello_response response;
    response.version = SOCKS5_VERSION;
    response.method = method;
    return response;
}

auth_response create_auth_response(uint8_t status) {
    auth_response response;
    response.version = AUTH_VERSION;
    response.status = status;
    return response;
}

socks5_response create_socks5_response(uint8_t rep) {
    socks5_response response;
    response.version = SOCKS5_VERSION;
    response.rep = rep;
    response.rsv = 0x00;
    response.atyp = SOCKS5_ATYP_IPV4;
    response.addr[0] = 0;
    response.addr[1] = 0;
    response.addr[2] = 0;
    response.addr[3] = 0;
    response.port = 0;
    return response;
}