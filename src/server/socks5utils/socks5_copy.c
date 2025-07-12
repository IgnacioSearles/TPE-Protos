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
        selector_set_interest(key->s, data->client_fd, OP_READ | OP_WRITE);
    }
}

socks5_state copy_bidirectional(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t read_count;
    uint8_t* read_ptr = buffer_write_ptr(&data->read_buffer, &read_count);
    if (read_count > 0) {
        ssize_t n = recv(key->fd, read_ptr, read_count, MSG_DONTWAIT);
        if (n > 0) {
            buffer_write_adv(&data->read_buffer, n);
            LOG_A(LOG_DEBUG, "COPY: Read %ld bytes from client", n);
            
            size_t forward_count;
            uint8_t* forward_ptr = buffer_read_ptr(&data->read_buffer, &forward_count);
            if (forward_count > 0) {
                ssize_t sent = send(data->origin_fd, forward_ptr, forward_count, MSG_NOSIGNAL | MSG_DONTWAIT);
                if (sent > 0) {
                    log_bytes_proxied(data->stats, data->client_fd, sent);
                    buffer_read_adv(&data->read_buffer, sent);
                    LOG_A(LOG_DEBUG, "COPY: Forwarded %ld bytes to origin", sent);
                }
            }
        } else if (n == 0) {
            LOG(LOG_DEBUG, "COPY: Client closed connection");
            return DONE;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_A(LOG_DEBUG, "COPY: Error reading from client: %s", strerror(errno));
            return ERROR;
        }
    }
    
    size_t write_count;
    uint8_t* write_ptr = buffer_read_ptr(&data->write_buffer, &write_count);
    if (write_count > 0) {
        ssize_t n = send(key->fd, write_ptr, write_count, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            log_bytes_proxied(data->stats, data->client_fd, n);
            buffer_read_adv(&data->write_buffer, n);
            LOG_A(LOG_DEBUG, "COPY: Sent %ld bytes to client", n);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_A(LOG_DEBUG, "COPY: Error writing to client: %s", strerror(errno));
            return ERROR;
        }
    }
    
    return COPY;
}

void origin_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    LOG(LOG_DEBUG, "ORIGIN: Reading from remote server");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->write_buffer, n);
        LOG_A(LOG_DEBUG, "ORIGIN: Received %ld bytes from origin", n);
        uint8_t *read_ptr = buffer_read_ptr(&data->write_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->client_fd, read_ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                log_bytes_proxied(data->stats, data->client_fd, sent);
                buffer_read_adv(&data->write_buffer, sent);
                LOG_A(LOG_DEBUG, "ORIGIN: Forwarded %ld bytes to client", sent);
                size_t write_space;
                buffer_write_ptr(&data->write_buffer, &write_space);
                if (sent == count && write_space > 0) {
                    uint8_t* next_ptr = buffer_write_ptr(&data->write_buffer, &write_space);
                    ssize_t next_n = recv(key->fd, next_ptr, write_space, MSG_DONTWAIT);
                    if (next_n > 0) {
                        buffer_write_adv(&data->write_buffer, next_n);
                        LOG_A(LOG_DEBUG, "ORIGIN: Optimized read - additional %ld bytes", next_n);
                        uint8_t* next_read_ptr = buffer_read_ptr(&data->write_buffer, &count);
                        if (count > 0) {
                            ssize_t next_sent = send(data->client_fd, next_read_ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
                            if (next_sent > 0) {
                                log_bytes_proxied(data->stats, data->client_fd, next_sent);
                                buffer_read_adv(&data->write_buffer, next_sent);
                                LOG_A(LOG_DEBUG, "ORIGIN: Optimized forward - additional %ld bytes", next_sent);
                            }
                        }
                    }
                }
            } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                LOG(LOG_DEBUG, "ORIGIN: Client not ready - data buffered");
            } else if (sent < 0) {
                LOG_A(LOG_DEBUG, "ORIGIN: Error sending to client: %s", strerror(errno));
                selector_unregister_fd(key->s, key->fd);
                return;
            }
        }
    } else if (n == 0) {
        LOG(LOG_DEBUG, "ORIGIN: Remote server closed connection");
        size_t pending_count;
        buffer_read_ptr(&data->write_buffer, &pending_count);
        
        if (pending_count > 0) {
            LOG_A(LOG_DEBUG, "ORIGIN: %zu bytes pending for client - keeping connection", pending_count);
        } else {
            LOG(LOG_DEBUG, "ORIGIN: No pending data - closing client connection");
            selector_unregister_fd(key->s, data->client_fd);
        }
        
        selector_unregister_fd(key->s, key->fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_A(LOG_DEBUG, "ORIGIN: Error reading from origin: %s", strerror(errno));
        selector_unregister_fd(key->s, key->fd);
    }
}
