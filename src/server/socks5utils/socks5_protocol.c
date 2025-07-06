#include <socks5_protocol.h>
#include <server_config.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

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
    memset(&response.addr, 0, sizeof(response.addr));
    response.port = 0;
    return response;
}

socks5_response create_socks5_response_with_addr(uint8_t rep, uint8_t atyp, const void* addr, uint16_t port) {
    socks5_response response;
    response.version = SOCKS5_VERSION;
    response.rep = rep;
    response.rsv = 0x00;
    response.atyp = atyp;
    response.port = htons(port);
    
    if (atyp == SOCKS5_ATYP_IPV4 && addr) {
        memcpy(response.addr.ipv4, addr, SOCKS5_IPV4_ADDR_SIZE);
    } else if (atyp == SOCKS5_ATYP_IPV6 && addr) {
        memcpy(response.addr.ipv6, addr, SOCKS5_IPV6_ADDR_SIZE);
    } else {
        memset(&response.addr, 0, sizeof(response.addr));
    }
    
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
    
    if (version != SOCKS5_VERSION) {
        return result;
    }
    
    if (rsv != SOCKS5_RSV_EXPECTED) {
        return result;
    }
    
    if (result.cmd != SOCKS5_CMD_CONNECT) {
        result.valid = true;
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
        
    } else if (result.atyp == SOCKS5_ATYP_IPV6) {
        addr_len = SOCKS5_IPV6_ADDR_SIZE;
        result.total_size = SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV6_ADDR_SIZE + SOCKS5_PORT_SIZE;
        
        if (data_len < result.total_size) {
            return result;
        }
        
        char ipv6_str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &data[SOCKS5_RESPONSE_HEADER_SIZE], ipv6_str, INET6_ADDRSTRLEN) != NULL) {
            snprintf(result.target_host, sizeof(result.target_host), "%s", ipv6_str);
        } else {
            return result;
        }
        
    } else {
        return result;
    }
    
    size_t port_offset = addr_start + addr_len;
    result.target_port = (data[port_offset] << 8) | data[port_offset + 1];
    
    result.valid = true;
    return result;
}

size_t get_socks5_response_size(uint8_t atyp) {
    switch (atyp) {
        case SOCKS5_ATYP_IPV4:
            return SOCKS5_RESPONSE_IPV4_SIZE;
        case SOCKS5_ATYP_IPV6:
            return SOCKS5_RESPONSE_IPV6_SIZE;
        default:
            return SOCKS5_RESPONSE_IPV4_SIZE;
    }
}

int get_socket_local_address(int sockfd, uint8_t* atyp, void* addr, uint16_t* port) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    
    if (getsockname(sockfd, (struct sockaddr*)&ss, &len) != 0) {
        return -1;
    }
    
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)&ss;
        *atyp = SOCKS5_ATYP_IPV4;
        memcpy(addr, &sin->sin_addr, SOCKS5_IPV4_ADDR_SIZE);
        *port = ntohs(sin->sin_port);
        return 0;
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&ss;
        *atyp = SOCKS5_ATYP_IPV6;
        memcpy(addr, &sin6->sin6_addr, SOCKS5_IPV6_ADDR_SIZE);
        *port = ntohs(sin6->sin6_port);
        return 0;
    }
    
    return -1;
}