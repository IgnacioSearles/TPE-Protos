#include <logger.h>
#include <socks5_hello.h>
#include <socks5_protocol.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

socks5_state hello_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG_A(LOG_DEBUG, "HELLO_READ: Starting handshake (state=%d)", stm_state(&data->stm));
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    LOG_A(LOG_DEBUG, "HELLO_READ: Received %ld bytes", n);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        uint8_t *read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        LOG_A(LOG_DEBUG, "HELLO_READ: Processing (available: %zu)", count);
        
        if (count >= SOCKS5_HELLO_MIN_SIZE) {
            socks5_hello_parser_result result = parse_socks5_hello(read_ptr, count);
            
            if (result.valid) {
                LOG_A(LOG_DEBUG, "HELLO_READ: version=%d, nmethods=%d", result.version, result.nmethods);
                LOG_A(LOG_DEBUG, "HELLO_READ: Supports user/pass: %s", result.supports_userpass ? "YES" : "NO");
                
                buffer_read_adv(&data->read_buffer, 2 + result.nmethods);
                data->auth_method = result.selected_method;
                
                LOG_A(LOG_DEBUG, "HELLO_READ: Success! Selected method: %d", data->auth_method);
                return HELLO_WRITE;
            }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "HELLO_READ: Error reading: %s", strerror(errno));
        return ERROR;
    }
    
    return HELLO_READ;
}

socks5_state hello_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "HELLO_WRITE: Sending response");
    
    socks5_hello_response response = create_hello_response(data->auth_method);
    
    ssize_t n = send(key->fd, &response, sizeof(response), MSG_NOSIGNAL | MSG_DONTWAIT);
    
    if (n > 0) {
        LOG_A(LOG_DEBUG, "HELLO_WRITE: Success! Sent method=%d (%ld bytes)", data->auth_method, n);
        
        if (data->auth_method == AUTH_METHOD_NO_METHODS) {
            LOG(LOG_DEBUG, "HELLO_WRITE: No supported methods - terminating");
            return ERROR;
        } else {
            LOG(LOG_DEBUG, "HELLO_WRITE: → Transitioning to AUTH_READ");
            return AUTH_READ;
        }
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG(LOG_DEBUG, "HELLO_WRITE: Would block, retrying later");
        } else {
            LOG_A(LOG_DEBUG, "HELLO_WRITE: Error sending: %s", strerror(errno));
            return ERROR;
        }
    }

    return HELLO_WRITE;
}
