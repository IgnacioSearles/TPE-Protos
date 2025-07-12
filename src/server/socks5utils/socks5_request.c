#include "selector.h"
#include "server_stats.h"
#include "socks5.h"
#include "stm.h"
#include <asm-generic/errno.h>
#include <logger.h>
#include <socks5_request.h>
#include <socks5_protocol.h>
#include <netutils.h>
#include <buffer.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


uint8_t get_reply_code() {
    switch (errno) {
        case ECONNREFUSED:
            return SOCKS5_REP_CONNECTION_REFUSED;
        case ENETUNREACH:
            return SOCKS5_REP_NETWORK_UNREACHABLE;
        case EHOSTUNREACH:
            return SOCKS5_REP_HOST_UNREACH;
        case ETIMEDOUT:
            return SOCKS5_REP_TTL_EXPIRED;
        default:
            return SOCKS5_REP_HOST_UNREACH;
    }

    return SOCKS5_REP_GENERAL_FAILURE;
}

socks5_state connecting_response(struct selector_key *key) {
    LOG(LOG_DEBUG, "CONNECTING: One of the connection in progress sockets finished");
    struct socks5* data = ATTACHMENT(key);

    selector_unregister_fd(key->s, data->origin_fd);

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error == 0) {
            LOG_A(LOG_DEBUG, "CONNECTED: Connection successful to %s:%d", data->target_host, data->target_port);
            data->reply_code = SOCKS5_REP_SUCCESS;
            return CONNECTING_RESPONSE;
        } else {
            LOG(LOG_DEBUG, "CONNECTED: connection not successful, should try again");
            return connecting(key);
        }
    }

    return ERROR;
}

socks5_state connecting(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);

    LOG(LOG_DEBUG, "CONNECTING: Got address info, now trying to connect");

    data->reply_code = SOCKS5_REP_HOST_UNREACH;

    for (struct addrinfo* rp = data->res; rp != NULL; rp = rp->ai_next) {
        int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        set_non_blocking(sock);

        if (sock < 0) continue;
        
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != 0) {
            if (errno == EINPROGRESS) {
                LOG(LOG_DEBUG, "CONNECTING: Registering socket to wait for connection EINPROGRESS");
                data->origin_fd = sock;
                data->res = rp->ai_next;

                if (selector_register(key->s, sock, &socks5_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                    LOG(LOG_DEBUG, "CONNECTING: Could not register fd");
                    close(sock);
                    data->reply_code = SOCKS5_REP_GENERAL_FAILURE;
                    continue;
                }

                return AWAITING_CONNECTION;
            } else {
                LOG(LOG_DEBUG, "CONNECTING: Could not connect with address info");
                data->reply_code = get_reply_code();
                close(sock);
            }
        } else {
            LOG(LOG_DEBUG, "CONNECTING: Didn't have to wait to connect");
            data->origin_fd = sock;
            freeaddrinfo(data->res);
            return CONNECTING_RESPONSE;
        }
    }

    LOG(LOG_DEBUG, "CONNECTING: could not connect to host");
    freeaddrinfo(data->res);
    data->res = NULL;

    return REQUEST_WRITE;
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
                get_addr_info_non_blocking(data->target_host, port_str, key->s, data->client_fd, &data->res);
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

    LOG(LOG_DEBUG, "CONNECTED: Connected to server");
    log_client_connected_to_destination_server(data->stats, data->client_fd, data->target_host, data->target_port);
    data->reply_code = SOCKS5_REP_SUCCESS;

    return REQUEST_WRITE;
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
