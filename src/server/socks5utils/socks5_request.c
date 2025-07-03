#include <socks5_request.h>
#include <socks5_protocol.h>
#include <netutils.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

socks5_state request_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t count;
    uint8_t *ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    printf("REQUEST_READ: recv returned %ld (errno=%d)\n", n, errno);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        printf("REQUEST_READ: Buffer has %zu bytes available\n", count);
        
        if (count >= SOCKS5_REQUEST_MIN_SIZE) {
            socks5_request_parser_result result = parse_socks5_request(read_ptr, count);
            if (result.valid && count >= result.total_size) {
                printf("REQUEST_READ: SUCCESS - target='%s:%d', cmd=%d, atyp=%d\n", 
                       result.target_host, result.target_port, result.cmd, result.atyp);
        
                buffer_read_adv(&data->read_buffer, result.total_size);
                strcpy(data->target_host, result.target_host);
                data->target_port = result.target_port;
            
                char port_str[6];
                snprintf(port_str, sizeof(port_str), "%d", data->target_port);
                data->origin_fd = connect_to_host(data->target_host, port_str);
                
                if (data->origin_fd >= 0) {
                    printf("REQUEST_READ: Connection initiated to %s:%d (fd=%d)\n", data->target_host, data->target_port, data->origin_fd);
                    data->reply_code = SOCKS5_REP_SUCCESS;
                    return CONNECTING;
                } else {
                    printf("REQUEST_READ: Failed to connect to %s:%d\n", data->target_host, data->target_port);
                    data->reply_code = SOCKS5_REP_HOST_UNREACH;
                    return REQUEST_WRITE;
                }
            } else if (!result.valid) {
                printf("REQUEST_READ: INVALID request - terminating\n");
                data->reply_code = SOCKS5_REP_COMMAND_NOT_SUPPORTED;
                return REQUEST_WRITE;
            } else {
                printf("REQUEST_READ: Need more data (have %zu, need %zu)\n", count, result.total_size);
            }
        } else {
            printf("REQUEST_READ: Need more data (have %zu, min %d)\n", count, SOCKS5_REQUEST_MIN_SIZE);
        }
    } else if (n == 0) {
        printf("REQUEST_READ: Client closed connection\n");
        return DONE;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        printf("REQUEST_READ: Error reading: %s\n", strerror(errno));
        return ERROR;
    } else {
        printf("REQUEST_READ: Would block, waiting for more data\n");
    }
    
    return REQUEST_READ;
}

socks5_state connecting(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("CONNECTING: Checking connection status\n");
    
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error == 0) {
            printf("CONNECTING: Connection successful to %s:%d\n", 
                   data->target_host, data->target_port);
            data->reply_code = SOCKS5_REP_SUCCESS;
        } else {
            printf("CONNECTING: Connection failed: %s\n", strerror(error));
            data->reply_code = SOCKS5_REP_HOST_UNREACH;
        }
        
        return REQUEST_WRITE;
    } else {
        printf("CONNECTING: Error checking socket status: %s\n", strerror(errno));
        return ERROR;
    }
}

socks5_state request_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);

    printf("REQUEST_WRITE: Sending response (code=%d)\n", data->reply_code);

    socks5_response response = create_socks5_response(data->reply_code);
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);

    if (count >= sizeof(response)) {
        memcpy(ptr, &response, sizeof(response));
        buffer_write_adv(&data->write_buffer, sizeof(response));
        
        ptr = buffer_read_ptr(&data->write_buffer, &count);
        ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            
            if (!buffer_can_read(&data->write_buffer)) {
                if (data->reply_code == SOCKS5_REP_SUCCESS) {
                    printf("REQUEST_WRITE: → Transitioning to COPY mode\n");
                    return COPY;
                } else {
                    printf("REQUEST_WRITE: Connection failed - terminating\n");
                    return DONE;
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("REQUEST_WRITE: Error sending: %s\n", strerror(errno));
            return ERROR;
        }
    } else {
        printf("REQUEST_WRITE: Buffer full - cannot fit response\n");
        return ERROR;
    }

    return REQUEST_WRITE;
}