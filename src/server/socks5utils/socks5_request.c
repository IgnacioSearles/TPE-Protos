#include "selector.h"
#include "server_stats.h"
#include "socks5.h"
#include <logger.h>
#include <socks5_request.h>
#include <socks5_protocol.h>
#include <netutils.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

socks5_state connecting(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);

    if (data->origin_fd >= 0) {
        log_client_connected_to_destination_server(data->stats, data->client_fd, data->target_host, data->target_port);
        LOG_A(LOG_DEBUG, "CONNECTING: Connection initiated to %s:%d (fd=%d)", data->target_host, data->target_port, data->origin_fd);
        data->reply_code = SOCKS5_REP_SUCCESS;
        return CONNECTING_RESPONSE;
    } else {
        LOG_A(LOG_DEBUG, "CONNECTING: Failed to connect to %s:%d (errno=%d)", data->target_host, data->target_port, errno);
        switch (errno) {
            case ECONNREFUSED:
                data->reply_code = SOCKS5_REP_CONNECTION_REFUSED;
                break;
            case ENETUNREACH:
                data->reply_code = SOCKS5_REP_NETWORK_UNREACHABLE;
                break;
            case EHOSTUNREACH:
                data->reply_code = SOCKS5_REP_HOST_UNREACH;
                break;
            case ETIMEDOUT:
                data->reply_code = SOCKS5_REP_TTL_EXPIRED;
                break;
            default:
                data->reply_code = SOCKS5_REP_HOST_UNREACH;
                break;
        }
    }
    return REQUEST_WRITE;
}

void connect_to_host_callback(int socket, fd_selector selector, void* data) {
    struct socks5* socks5 = (struct socks5*) data;

    socks5->origin_fd = socket;

    struct selector_key key = {
        .data = socks5,
        .s = selector,
        .fd = socks5->client_fd
    };

    LOG_A(LOG_DEBUG, "State at callback start: %d", stm_state(&socks5->stm));
    socks5_state next = stm_handler_read(&socks5->stm, &key);

    if (next != CONNECTING_RESPONSE && next != REQUEST_WRITE) {
        LOG_A(LOG_ERROR, "Illegal next state. STATE: %d", next);
    }

    selector_set_interest(selector, socks5->client_fd, OP_WRITE);
}

socks5_state request_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t count;
    uint8_t *ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    LOG_A(LOG_DEBUG, "REQUEST_READ: recv returned %ld (errno=%d)", n, errno);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        LOG_A(LOG_DEBUG, "REQUEST_READ: Buffer has %zu bytes available", count);
        
        if (count >= SOCKS5_REQUEST_MIN_SIZE) {
            socks5_request_parser_result result = parse_socks5_request(read_ptr, count);
            if (result.valid && count >= result.total_size) {
                LOG_A(LOG_DEBUG, "REQUEST_READ: SUCCESS - target='%s:%d', cmd=%d, atyp=%d", 
                       result.target_host, result.target_port, result.cmd, result.atyp);
        
                buffer_read_adv(&data->read_buffer, result.total_size);
                strcpy(data->target_host, result.target_host);
                data->target_port = result.target_port;
                data->target_atyp = result.atyp;
                
                if (result.cmd != SOCKS5_CMD_CONNECT) {
                    LOG_A(LOG_DEBUG, "REQUEST_READ: Unsupported command %d", result.cmd);
                    data->reply_code = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
                    return REQUEST_WRITE;
                }
                
                if (result.atyp != SOCKS5_ATYP_IPV4 && result.atyp != SOCKS5_ATYP_IPV6 && result.atyp != SOCKS5_ATYP_DOMAIN) {
                    LOG_A(LOG_DEBUG, "REQUEST_READ: Unsupported address type %d", result.atyp);
                    data->reply_code = SOCKS5_REP_ADDRESS_TYPE_NOT_SUPPORTED;
                    return REQUEST_WRITE;
                }
            
                LOG_A(LOG_DEBUG, "REQUEST_READ: Attempting connection to %s:%d (ATYP=%d)", data->target_host, data->target_port, data->target_atyp);
            
                char port_str[6];
                snprintf(port_str, sizeof(port_str), "%d", data->target_port);

                selector_set_interest(key->s, data->client_fd, OP_NOOP);
                connect_to_host_non_blocking(data->target_host, port_str, key->s, (void (*)(int, fd_selector, void*))connect_to_host_callback, (void*)data);
                return CONNECTING;
            } else if (!result.valid) {
                LOG(LOG_DEBUG, "REQUEST_READ: INVALID request - terminating");
                data->reply_code = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
                return REQUEST_WRITE;
            } else {
                LOG_A(LOG_DEBUG, "REQUEST_READ: Need more data (have %zu, need %zu)", count, result.total_size);
            }
        } else {
            LOG_A(LOG_DEBUG, "REQUEST_READ: Need more data (have %zu, min %d)", count, SOCKS5_REQUEST_MIN_SIZE);
        }
    } else if (n == 0) {
        LOG(LOG_DEBUG, "REQUEST_READ: Client closed connection");
        return DONE;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "REQUEST_READ: Error reading: %s", strerror(errno));
        return ERROR;
    } else {
        LOG(LOG_DEBUG, "REQUEST_READ: Would block, waiting for more data");
    }
    
    return REQUEST_READ;
}

socks5_state connected(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "CONNECTED: Checking connection status");
    
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error == 0) {
            LOG_A(LOG_DEBUG, "CONNECTED: Connection successful to %s:%d", 
                   data->target_host, data->target_port);
            data->reply_code = SOCKS5_REP_SUCCESS;
        } else {
            LOG_A(LOG_DEBUG, "CONNECTED: Connection failed: %s", strerror(error));
            data->reply_code = SOCKS5_REP_HOST_UNREACH;
        }
        
        return REQUEST_WRITE;
    } else {
        LOG_A(LOG_DEBUG, "CONNECTED: Error checking socket status: %s", strerror(errno));
        return ERROR;
    }
}

socks5_state request_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);

    LOG_A(LOG_DEBUG, "REQUEST_WRITE: Sending response (code=%d)", data->reply_code);

    socks5_response response;
    
    if (data->reply_code == SOCKS5_REP_SUCCESS && data->origin_fd >= 0) {
        struct sockaddr_storage local_addr;
        socklen_t addr_len = sizeof(local_addr);
        
        if (getsockname(data->origin_fd, (struct sockaddr*)&local_addr, &addr_len) == 0) {
            if (local_addr.ss_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)&local_addr;
                response = create_socks5_response_with_addr(data->reply_code, SOCKS5_ATYP_IPV4, &ipv4->sin_addr, ntohs(ipv4->sin_port));
            } else if (local_addr.ss_family == AF_INET6) {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&local_addr;
                response = create_socks5_response_with_addr(data->reply_code, SOCKS5_ATYP_IPV6, &ipv6->sin6_addr, ntohs(ipv6->sin6_port));
            } else {
                response = create_socks5_response(data->reply_code);
            }
        } else {
            response = create_socks5_response(data->reply_code);
        }
    } else {
        response = create_socks5_response(data->reply_code);
    }
    
    size_t response_size = SOCKS5_RESPONSE_HEADER_SIZE;
    if (response.atyp == SOCKS5_ATYP_IPV4) {
        response_size += SOCKS5_IPV4_ADDR_SIZE + SOCKS5_PORT_SIZE;
    } else if (response.atyp == SOCKS5_ATYP_IPV6) {
        response_size += SOCKS5_IPV6_ADDR_SIZE + SOCKS5_PORT_SIZE;
    } else {
        response_size += SOCKS5_IPV4_ADDR_SIZE + SOCKS5_PORT_SIZE;
    }
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);

    if (count >= response_size) {
        uint8_t* buf = ptr;
        
        buf[0] = response.version;  // VER
        buf[1] = response.rep;      // REP  
        buf[2] = response.rsv;      // RSV
        buf[3] = response.atyp;     // ATYP
        
        if (response.atyp == SOCKS5_ATYP_IPV4) {
            memcpy(&buf[SOCKS5_RESPONSE_HEADER_SIZE], response.addr.ipv4, SOCKS5_IPV4_ADDR_SIZE);
            memcpy(&buf[SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV4_ADDR_SIZE], &response.port, SOCKS5_PORT_SIZE);
        } else if (response.atyp == SOCKS5_ATYP_IPV6) {
            memcpy(&buf[SOCKS5_RESPONSE_HEADER_SIZE], response.addr.ipv6, SOCKS5_IPV6_ADDR_SIZE);
            memcpy(&buf[SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV6_ADDR_SIZE], &response.port, SOCKS5_PORT_SIZE);
        } else {
            memset(&buf[SOCKS5_RESPONSE_HEADER_SIZE], 0, SOCKS5_IPV4_ADDR_SIZE);
            memcpy(&buf[SOCKS5_RESPONSE_HEADER_SIZE + SOCKS5_IPV4_ADDR_SIZE], &response.port, SOCKS5_PORT_SIZE);
        }
        
        buffer_write_adv(&data->write_buffer, response_size);
        
        ptr = buffer_read_ptr(&data->write_buffer, &count);
        ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            
            if (!buffer_can_read(&data->write_buffer)) {
                if (data->reply_code == SOCKS5_REP_SUCCESS) {
                    LOG(LOG_DEBUG, "REQUEST_WRITE: → Transitioning to COPY mode");
                    return COPY;
                } else {
                    LOG(LOG_DEBUG, "REQUEST_WRITE: Connection failed - terminating");
                    return DONE;
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_A(LOG_DEBUG, "REQUEST_WRITE: Error sending: %s", strerror(errno));
            return ERROR;
        }
    } else {
        LOG(LOG_DEBUG, "REQUEST_WRITE: Buffer full - cannot fit response");
        return ERROR;
    }

    return REQUEST_WRITE;
}
