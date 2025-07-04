#include "server_stats.h"
#include <socks5_auth.h>
#include <logger.h>
#include <socks5_protocol.h>
#include <server_config.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

socks5_state auth_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "AUTH_READ: Reading credentials");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        
        uint8_t* read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        
        if (count >= SOCKS5_AUTH_MIN_SIZE) {
            socks5_auth_parser_result result = parse_socks5_auth(read_ptr, count, data->config);
            
            if (result.valid) {
                LOG_A(LOG_DEBUG, "AUTH_READ: Parsed - user='%s'", result.username);
        
                bool auth_ok = false;
                if (data->config) {
                    bool found = false;
                    for (int i = 0; i < data->config->user_count && !found; i++) {
                        server_user user = data->config->users[i];
                        if (strcmp(user.user, result.username) == 0 && 
                            strcmp(user.pass, result.password) == 0) {
                            log_user_authenticated(data->stats, data->client_fd, user.user);
                            auth_ok = true;
                            LOG_A(LOG_DEBUG, "AUTH_READ: Credentials match user[%d]", i);
                            found = true;
                        }
                    }
                }
                
                LOG_A(LOG_DEBUG, "AUTH_READ: Authentication %s", auth_ok ? "SUCCESS" : "FAILED");
                
                size_t consumed = 2 + strlen(result.username) + 1 + strlen(result.password);
                buffer_read_adv(&data->read_buffer, consumed);
                
                data->auth_ok = auth_ok;
                return AUTH_WRITE;
            }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "AUTH_READ: Error reading: %s", strerror(errno));
        return ERROR;
    }
    
    return AUTH_READ;
}

socks5_state auth_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG_A(LOG_DEBUG, "AUTH_WRITE: Sending result (%s)", data->auth_ok ? "SUCCESS" : "FAILURE");
    
    auth_response response = create_auth_response(data->auth_ok ? AUTH_SUCCESS : AUTH_FAILURE);
    
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
                if (!data->auth_ok) {
                    LOG(LOG_DEBUG, "AUTH_WRITE: Authentication failed - terminating");
                    return ERROR;
                } else {
                    LOG(LOG_DEBUG, "AUTH_WRITE: → Transitioning to REQUEST_READ");
                    return REQUEST_READ;
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_A(LOG_DEBUG, "AUTH_WRITE: Error sending: %s", strerror(errno));
            return ERROR;
        }
    } else {
        LOG(LOG_DEBUG, "AUTH_WRITE: Buffer full - cannot fit response");
        return ERROR;
    }

    return AUTH_WRITE;
}
