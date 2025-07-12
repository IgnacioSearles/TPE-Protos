#include "server_stats.h"
#include "socks5_protocol.h"
#include <logger.h>
#include <socks5_copy.h>
#include <selector.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

const struct fd_handler origin_handler = {
    .handle_read  = origin_read,
};

void copy_on_arrival(const unsigned state, struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG_A(LOG_DEBUG, "COPY: Entering tunnel mode - registering origin_fd=%d", data->origin_fd);
    
    if (selector_register(key->s, data->origin_fd, &origin_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        LOG(LOG_WARN, "COPY: Failed to register origin_fd in selector - TERMINATING CLIENT");
        data->reply_code = SOCKS5_REP_GENERAL_FAILURE;
        close(data->client_fd);
    } else {
        LOG(LOG_DEBUG, "COPY: Origin registered - bidirectional tunnel active");
        LOG_A(LOG_DEBUG, "COPY: Cliente[%d] ←→ Proxy ←→ Origin[%d]", data->client_fd, data->origin_fd);
    }
}

socks5_state copy_r(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "COPY_R: Reading from client");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        LOG_A(LOG_DEBUG, "COPY_R: Received %ld bytes from client → forwarding to origin[%d]", n, data->origin_fd);
        
        uint8_t* read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->origin_fd, read_ptr, count, MSG_NOSIGNAL);
            if (sent > 0) {
                log_bytes_proxied(data->stats, data->client_fd, sent);
                buffer_read_adv(&data->read_buffer, sent);
                LOG_A(LOG_DEBUG, "COPY_R: Forwarded %ld bytes to origin", sent);
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_A(LOG_DEBUG, "COPY_R: Error forwarding to origin: %s", strerror(errno));
                return ERROR;
            }
        }
    } else if (n == 0) {
        LOG(LOG_DEBUG, "COPY_R: Client closed connection");
        return DONE;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "COPY_R: Error reading from client: %s", strerror(errno));
        return ERROR;
    }
    
    return COPY;
}

socks5_state copy_w(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
   
    LOG(LOG_DEBUG, "COPY_W: Writing to client (buffered data)");
    
    size_t count;
    uint8_t* ptr = buffer_read_ptr(&data->write_buffer, &count);
    
    if (count > 0) {
        ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            log_bytes_proxied(data->stats, data->client_fd, n);

            buffer_read_adv(&data->write_buffer, n);
            LOG_A(LOG_DEBUG, "COPY_W: Sent %ld bytes to client from buffer", n);
            
            size_t remaining;
            buffer_read_ptr(&data->write_buffer, &remaining);
            if (remaining == 0) {
                LOG(LOG_DEBUG, "COPY_W: All buffered data sent - back to read mode");
                selector_set_interest_key(key, OP_READ);
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_A(LOG_DEBUG, "COPY_W: Error writing to client: %s", strerror(errno));
            return ERROR;
        }
    } else {
        LOG(LOG_DEBUG, "COPY_W: No pending data to send");
        selector_set_interest_key(key, OP_READ);
    }
    
    return COPY;
}

void origin_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "ORIGIN_READ: Reading from remote server");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->write_buffer, n);
        LOG_A(LOG_DEBUG, "ORIGIN_READ: Received %ld bytes from origin → forwarding to client", n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->write_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->client_fd, read_ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                log_bytes_proxied(data->stats, data->client_fd, sent);

                buffer_read_adv(&data->write_buffer, sent);
                LOG_A(LOG_DEBUG, "ORIGIN_READ: Forwarded %ld bytes to client immediately", sent);
            } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                LOG(LOG_DEBUG, "ORIGIN_READ: Client not ready - data buffered for later");
                selector_set_interest(key->s, data->client_fd, OP_WRITE);
            } else if (sent < 0) {
                LOG_A(LOG_DEBUG, "ORIGIN_READ: Error sending to client: %s", strerror(errno));
                selector_unregister_fd(key->s, key->fd);
                return;
            }
        }
    } else if (n == 0) {
        LOG(LOG_DEBUG, "ORIGIN_READ: Remote server closed connection");
        
        size_t pending_count;
        buffer_read_ptr(&data->write_buffer, &pending_count);
        
        if (pending_count > 0) {
            LOG_A(LOG_DEBUG, "ORIGIN_READ: %zu bytes pending for client - keeping connection", pending_count);
            selector_set_interest(key->s, data->client_fd, OP_WRITE);
        } else {
            LOG(LOG_DEBUG, "ORIGIN_READ: No pending data - closing client connection");
            selector_unregister_fd(key->s, data->client_fd);
        }
        
        selector_unregister_fd(key->s, key->fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "ORIGIN_READ: Error reading from origin: %s", strerror(errno));
        selector_unregister_fd(key->s, key->fd);
    }
}
