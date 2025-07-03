#include <socks5_protocol.h>
#include <server_config.h>
#include <string.h>
#include <stdio.h>

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

socks5_hello_parser_result parse_socks5_hello(uint8_t* data, size_t data_len) {
    socks5_hello_parser_result result = {0};
    
    if (data_len < SOCKS5_HELLO_MIN_SIZE) {
        return result;
    }
    
    result.version = data[0];
    result.nmethods = data[1];
    
    if (data_len < 2 + (size_t)result.nmethods) {
        return result;
    }
    
    if (result.version != SOCKS5_VERSION) {
        return result;
    }
    
    result.supports_userpass = false;
    for (int i = 0; i < result.nmethods; i++) {
        if (data[2 + i] == AUTH_METHOD_USER_PASS) {
            result.supports_userpass = true;
            break;
        }
    }
    
    result.selected_method = result.supports_userpass ? AUTH_METHOD_USER_PASS : AUTH_METHOD_NO_METHODS;
    result.valid = true;
    
    return result;
}

socks5_auth_parser_result parse_socks5_auth(uint8_t* data, size_t data_len, server_config* config) {
    socks5_auth_parser_result result = {0};
    
    if (data_len < SOCKS5_AUTH_MIN_SIZE) {
        return result;
    }
    
    uint8_t version = data[0];
    uint8_t ulen = data[1];
    
    if (version != AUTH_VERSION || ulen == 0) {
        return result;
    }
    
    // Verificar que tenemos username completo + plen
    if (data_len < 2 + (size_t)ulen + 1) {
        return result;
    }
    
    uint8_t plen = data[2 + ulen];
    if (plen == 0) {
        return result;
    }
    
    if (data_len < 2 + (size_t)ulen + 1 + (size_t)plen) {
        return result;
    }
    
    memcpy(result.username, &data[2], ulen);
    result.username[ulen] = '\0';
    
    memcpy(result.password, &data[2 + ulen + 1], plen);
    result.password[plen] = '\0';
    
    result.auth_ok = false;
    result.valid = true;
    return result;
}

socks5_request_parser_result parse_socks5_request(uint8_t* data, size_t data_len) {
    socks5_request_parser_result result = {0};
    
    if (data_len < SOCKS5_REQUEST_MIN_SIZE) {
        return result;
    }
    
    uint8_t version = data[0];
    result.cmd = data[1];
    uint8_t rsv = data[2];
    result.atyp = data[3];
    
    if (version != SOCKS5_VERSION || rsv != 0x00 || result.cmd != SOCKS5_CMD_CONNECT) {
        return result;
    }
    
    size_t addr_start = 4;
    size_t addr_len = 0;
    
    if (result.atyp == SOCKS5_ATYP_IPV4) {
        addr_len = 4;
        result.total_size = 4 + 4 + 2; // header + IPv4 + puerto
        
        if (data_len < result.total_size) {
            return result;
        }
        
        snprintf(result.target_host, sizeof(result.target_host), 
                "%d.%d.%d.%d", data[4], data[5], data[6], data[7]);
        
    } else if (result.atyp == SOCKS5_ATYP_DOMAIN) {
        if (data_len < 5) {
            return result;
        }
        
        uint8_t domain_len = data[4];
        addr_len = 1 + domain_len;
        result.total_size = 4 + 1 + domain_len + 2; // header + len + domain + puerto
        
        if (data_len < result.total_size || domain_len == 0) {
            return result;
        }
        
        memcpy(result.target_host, &data[5], domain_len);
        result.target_host[domain_len] = '\0';
        
    } else {
        return result; // ? ATYP no soportado
    }
    
    size_t port_offset = addr_start + addr_len;
    result.target_port = (data[port_offset] << 8) | data[port_offset + 1];
    
    result.valid = true;
    return result;
}