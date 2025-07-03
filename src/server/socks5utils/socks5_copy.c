#include <socks5_copy.h>
#include <buffer.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

const struct fd_handler origin_handler = {
    .handle_read  = origin_read,
};

void copy_on_arrival(const unsigned state, struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("COPY: Entering tunnel mode - registering origin_fd=%d\n", data->origin_fd);
    
    if (selector_register(key->s, data->origin_fd, &origin_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        printf("COPY: Failed to register origin_fd in selector\n");
    } else {
        printf("COPY: Origin registered - bidirectional tunnel active\n");
        printf("COPY: Cliente[%d] ←→ Proxy ←→ Origin[%d]\n", data->client_fd, data->origin_fd);
    }
}

socks5_state copy_r(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("COPY_R: Reading from client\n");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        printf("COPY_R: Received %ld bytes from client → forwarding to origin[%d]\n", n, data->origin_fd);
        
        uint8_t* read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->origin_fd, read_ptr, count, MSG_NOSIGNAL);
            if (sent > 0) {
                buffer_read_adv(&data->read_buffer, sent);
                printf("COPY_R: Forwarded %ld bytes to origin\n", sent);
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                printf("COPY_R: Error forwarding to origin: %s\n", strerror(errno));
                return ERROR;
            }
        }
    } else if (n == 0) {
        printf("COPY_R: Client closed connection\n");
        return DONE;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        printf("COPY_R: Error reading from client: %s\n", strerror(errno));
        return ERROR;
    }
    
    return COPY;
}

socks5_state copy_w(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
   
    printf("COPY_W: Writing to client (buffered data)\n");
    
    size_t count;
    uint8_t* ptr = buffer_read_ptr(&data->write_buffer, &count);
    
    if (count > 0) {
        ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            printf("COPY_W: Sent %ld bytes to client from buffer\n", n);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("COPY_W: Error writing to client: %s\n", strerror(errno));
            return ERROR;
        }
    }
    
    return COPY;
}

void origin_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("ORIGIN_READ: Reading from remote server\n");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->write_buffer, n);
        printf("ORIGIN_READ: Received %ld bytes from origin → forwarding to client\n", n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->write_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->client_fd, read_ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                buffer_read_adv(&data->write_buffer, sent);
                printf("ORIGIN_READ: Forwarded %ld bytes to client immediately\n", sent);
            } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                printf("ORIGIN_READ: Client not ready - data buffered for later\n");
                selector_set_interest(key->s, data->client_fd, OP_WRITE);
            } else if (sent < 0) {
                printf("ORIGIN_READ: Error sending to client: %s\n", strerror(errno));
                selector_unregister_fd(key->s, key->fd);
                selector_unregister_fd(key->s, data->client_fd);
                return;
            }
        }
    } else if (n == 0) {
        printf("ORIGIN_READ: Remote server closed connection - cleaning up\n");
        selector_unregister_fd(key->s, key->fd);
        selector_unregister_fd(key->s, data->client_fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        printf("ORIGIN_READ: Error reading from origin: %s\n", strerror(errno));
        selector_unregister_fd(key->s, key->fd);
        selector_unregister_fd(key->s, data->client_fd);
    }
}