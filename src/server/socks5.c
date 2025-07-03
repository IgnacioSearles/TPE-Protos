#include "socks5.h"
#include "server_stats.h"
#include "socks5_protocol.h"
#include "../shared/netutils.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_DATA_SIZE 256

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static void copy_on_arrival(const unsigned state, struct selector_key *key);

static socks5_state hello_read(struct selector_key *key);
static socks5_state hello_write(struct selector_key *key);
static socks5_state auth_read(struct selector_key *key);
static socks5_state auth_write(struct selector_key *key);
static socks5_state request_read(struct selector_key *key);
static socks5_state request_write(struct selector_key *key);
static socks5_state connecting(struct selector_key *key);
static socks5_state copy_r(struct selector_key *key);
static socks5_state copy_w(struct selector_key *key);

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_close(struct selector_key *key);

static void origin_read(struct selector_key *key);

static const struct state_definition client_statbl[] = {
    { .state = HELLO_READ,    .on_read_ready  = hello_read    },
    { .state = HELLO_WRITE,   .on_write_ready = hello_write   },
    { .state = AUTH_READ,     .on_read_ready  = auth_read     },
    { .state = AUTH_WRITE,    .on_write_ready = auth_write    },
    { .state = REQUEST_READ,  .on_read_ready  = request_read  },
    { .state = REQUEST_WRITE, .on_write_ready = request_write },
    { .state = CONNECTING,    .on_write_ready = connecting    },
    { .state = COPY,          .on_arrival     = copy_on_arrival,
                              .on_read_ready  = copy_r,         // Cliente → Servidor remoto
                              .on_write_ready = copy_w          }, // Buffer → Cliente
    { .state = DONE   },
    { .state = ERROR  }
};

static const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_close = socks5_close,
};

static const struct fd_handler origin_handler = {
    .handle_read  = origin_read,
};

static const struct state_machine socks5_stm = {
    .initial   = HELLO_READ,
    .max_state = ERROR,
    .states    = client_statbl,
};

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

static void copy_on_arrival(const unsigned state, struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("SOCKS5: Entering COPY state, registering origin_fd=%d\n", data->origin_fd);
    
    if (selector_register(key->s, data->origin_fd, &origin_handler, OP_READ, data) != SELECTOR_SUCCESS) {
        printf("SOCKS5: Failed to register origin_fd in selector\n");
    } else {
        printf("SOCKS5: Successfully registered origin_fd in selector\n");
    }
}

static socks5_state hello_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("SOCKS5: hello_read called (current_state=%d)\n", stm_state(&data->stm));
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    printf("SOCKS5: Received %ld bytes\n", n);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        uint8_t *read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        printf("SOCKS5: Processing HELLO_READ (available: %zu)\n", count);
        
        if (count >= SOCKS5_HELLO_MIN_SIZE) {
            socks5_hello_parser_result result = parse_socks5_hello(read_ptr, count);
            
            if (result.valid) {
                printf("SOCKS5: HELLO version=%d, nmethods=%d\n", result.version, result.nmethods);
                printf("SOCKS5: Supports user/pass: %s\n", result.supports_userpass ? "YES" : "NO");
                
                buffer_read_adv(&data->read_buffer, 2 + result.nmethods);
                data->auth_method = result.selected_method;
                
                printf("SOCKS5: HELLO parsed successfully, selected method: %d\n", data->auth_method);
                
                return HELLO_WRITE;
            }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        printf("SOCKS5: Error reading: %s\n", strerror(errno));
        return ERROR;
    }
    
    return HELLO_READ;
}

static socks5_state hello_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("SOCKS5: Processing HELLO_WRITE\n");
    
    // 🏗️ Crear respuesta usando protocolo en lugar de array manual
    socks5_hello_response response = create_hello_response(data->auth_method);
    
    ssize_t n = send(key->fd, &response, sizeof(response), MSG_NOSIGNAL | MSG_DONTWAIT);
    
    if (n > 0) {
        printf("SOCKS5: Sent HELLO_REPLY successfully (method=%d, bytes=%ld)\n", data->auth_method, n);
        
        if (data->auth_method == AUTH_METHOD_NO_METHODS) {
            return ERROR;
        } else {
            printf("SOCKS5: Transitioning to AUTH_READ\n");
            return AUTH_READ;
        }
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("SOCKS5: HELLO_WRITE would block, staying in HELLO_WRITE\n");
        } else {
            printf("SOCKS5: Error sending HELLO_REPLY: %s\n", strerror(errno));
            return ERROR;
        }
    }

    return HELLO_WRITE;
}

static socks5_state auth_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        
        uint8_t* read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        
        if (count >= SOCKS5_AUTH_MIN_SIZE) {
            socks5_auth_parser_result result = parse_socks5_auth(read_ptr, count, data->config);
            
            if (result.valid) {
                printf("SOCKS5: AUTH parsed - user='%s'\n", result.username);
        
                bool auth_ok = false;
                if (data->config && data->config->users) {
                    bool found = false;
                    for (int i = 0; i < data->config->user_count && !found; i++) {
                        server_user user = data->config->users[i];
                        if (strcmp(user.user, result.username) == 0 && 
                            strcmp(user.pass, result.password) == 0) {
                            auth_ok = true;
                            found = true;
                        }
                    }
                }
                
                printf("SOCKS5: Authentication result: %s\n", auth_ok ? "SUCCESS" : "FAILED");
                
                size_t consumed = 2 + strlen(result.username) + 1 + strlen(result.password);
                buffer_read_adv(&data->read_buffer, consumed);
                
                data->auth_ok = auth_ok;
                
                return AUTH_WRITE;
            }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return ERROR;
    }
    
    return AUTH_READ;
}

static socks5_state auth_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    auth_response response = create_auth_response(data->auth_ok ? AUTH_SUCCESS : AUTH_FAILURE);
    
    size_t count;

    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n;
     
    if (count >= sizeof(response)) {
        memcpy(ptr, &response, sizeof(response));
        buffer_write_adv(&data->write_buffer, sizeof(response));
        
        ptr = buffer_read_ptr(&data->write_buffer, &count);
        n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            
            if (!buffer_can_read(&data->write_buffer)) {
                if (!data->auth_ok) {
                    return ERROR;
                } else {
                    return REQUEST_READ;
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            return ERROR;
        }
    }
     
    return ERROR;
}

static socks5_state request_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t count;
    uint8_t *ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        
        if (count >= SOCKS5_REQUEST_MIN_SIZE) {
            socks5_request_parser_result result = parse_socks5_request(read_ptr, count);
            
            if (result.valid && count >= result.total_size) {
                printf("SOCKS5: REQUEST parsed - target='%s:%d', cmd=%d, atyp=%d\n", result.target_host, result.target_port, result.cmd, result.atyp);
        
                buffer_read_adv(&data->read_buffer, result.total_size);
                
                strcpy(data->target_host, result.target_host);
                data->target_port = result.target_port;
                
                char port_str[6];
                snprintf(port_str, sizeof(port_str), "%d", data->target_port);
                data->origin_fd = connect_to_host(data->target_host, port_str);
                
                if (data->origin_fd >= 0) {
                    data->reply_code = SOCKS5_REP_SUCCESS;
                    return CONNECTING;
                } else {
                    data->reply_code = SOCKS5_REP_HOST_UNREACH;
                    return REQUEST_WRITE;
                }
            } else if (!result.valid) {
                printf("SOCKS5: Invalid request received\n");
                return ERROR;
            }
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        return ERROR;
    }
    
    return REQUEST_READ;
}

static socks5_state connecting(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(data->origin_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
        if (error == 0) {
            data->reply_code = SOCKS5_REP_SUCCESS;
        } else {
            data->reply_code = SOCKS5_REP_HOST_UNREACH;
        }
        
        return REQUEST_WRITE;
    } else {
        return ERROR;
    }
    
    return CONNECTING;
}

static socks5_state request_write(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);

    socks5_response response = create_socks5_response(data->reply_code);
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n;

    if (count >= sizeof(response)) {
        memcpy(ptr, &response, sizeof(response));
        buffer_write_adv(&data->write_buffer, sizeof(response));
        
        ptr = buffer_read_ptr(&data->write_buffer, &count);
        n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            
            if (!buffer_can_read(&data->write_buffer)) {
                if (data->reply_code == SOCKS5_REP_SUCCESS) {
                    return COPY;
                } else {
                    return DONE; // ? o ver is otro estado, porque en realidad falló la conexión
                }
            }
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            return ERROR;
        }
    } else {
        return ERROR;
    }

    return REQUEST_READ;
}

static socks5_state copy_r(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->read_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->read_buffer, n);
        printf("SOCKS5: Received %ld bytes from origin_fd=%d\n ! ! ! !  ! 1 ! ! ! !      !", n, data->origin_fd);
        uint8_t* read_ptr = buffer_read_ptr(&data->read_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->origin_fd, read_ptr, count, MSG_NOSIGNAL);
            if (sent > 0) {
                buffer_read_adv(&data->read_buffer, sent);
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                return ERROR;
            }
        }
    } else if (n == 0) {
        return DONE;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        return ERROR;
    }
    
    return COPY;
}

static socks5_state copy_w(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
   
    size_t count;
    uint8_t* ptr = buffer_read_ptr(&data->write_buffer, &count);
    
    if (count > 0) {
        ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n > 0) {
            buffer_read_adv(&data->write_buffer, n);
            printf("SOCKS5: Sent %ld bytes to client from write buffer\n", n);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            printf("SOCKS5: Error writing to client: %s\n", strerror(errno));
            return ERROR;
        }
    }
    
    return COPY;
}

int socks5_init(const int client_fd, fd_selector s, server_config* config, server_stats stats) {
    printf("SOCKS5: Initializing connection (fd=%d)\n", client_fd);
    
    // Configurar socket como no-bloqueante
    if (set_non_blocking(client_fd) < 0) {
        printf("SOCKS5: Failed to set non-blocking\n");
        return -1;
    }
    
    socks5* socks = calloc(1, sizeof(*socks));
    if (socks == NULL) {
        printf("SOCKS5: Failed to allocate memory\n");
        return -1;
    }

    socks->client_fd = client_fd;
    socks->origin_fd = -1;
    socks->config = config;
    socks->stats = stats;
    socks->auth_ok = false;
    socks->auth_method = 0;

    buffer_init(&(socks->read_buffer), INITIAL_BUFFER_SIZE, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), INITIAL_BUFFER_SIZE, socks->write_raw_buff);

    socks->stm.initial   = socks5_stm.initial;
    socks->stm.max_state = socks5_stm.max_state;
    socks->stm.states    = socks5_stm.states;
    
    stm_init(&socks->stm);
    
    if (selector_register(s, client_fd, &socks5_handler, OP_READ, socks) != SELECTOR_SUCCESS) {
        printf("SOCKS5: Failed to register with selector\n");
        free(socks);
        return -1;
    }

    log_connection_open(stats, client_fd);
    printf("SOCKS5: Connection initialized successfully (fd=%d, initial_state=%d)\n", client_fd, socks5_stm.initial);

    return 0;
}


static bool is_op_write(const enum socks5_state state) {
    return (state == HELLO_WRITE || state == AUTH_WRITE || state == REQUEST_WRITE || state == CONNECTING || state == COPY);
}

static bool is_op_read(const enum socks5_state state) {
    return (state == HELLO_READ || state == AUTH_READ || state == REQUEST_READ || state == CONNECTING || state == COPY);
}

static void socks5_read(struct selector_key *key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    socks5_state next = stm_handler_read(stm, key);
    
    printf("SOCKS5: Read event, state transition to %d\n", next);
    
    if (ERROR == next || DONE == next) {
        printf("SOCKS5: Terminating connection (state=%d)\n", next);
        selector_unregister_fd(key->s, key->fd);
    } else {
        fd_interest interest = OP_NOOP;
        if (is_op_write(next)) {
            interest = OP_WRITE;
        } else if (is_op_read(next)) {
            interest = OP_READ;
        }
        
        if (interest != OP_NOOP) {
            printf("SOCKS5: Changing selector interest to %d\n", interest);
            selector_set_interest_key(key, interest);
        }
    }
}


static void socks5_write(struct selector_key *key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    socks5_state next = stm_handler_write(stm, key);
    
    printf("SOCKS5: Write event, state transition to %d\n", next);
    
    if (ERROR == next || DONE == next) {
        printf("SOCKS5: Terminating connection (state=%d)\n", next);
        selector_unregister_fd(key->s, key->fd);
    } else {
        fd_interest interest = OP_NOOP;
        if (is_op_read(next)) {
            interest = OP_READ;
        } else if (is_op_write(next)) {
            interest = OP_WRITE;
        }

        if (interest != OP_NOOP) {
            printf("SOCKS5: Changing selector interest to %d\n", interest);
            selector_set_interest_key(key, interest);
        }
    }
}

static void socks5_close(struct selector_key *key) {
    struct socks5* socks = ATTACHMENT(key);
    if (socks == NULL) {
        return;
    }
    
    log_connection_close(socks->stats, socks->client_fd);

    if (socks->client_fd >= 0) {
        close(socks->client_fd);
    }
    if (socks->origin_fd >= 0) {
        close(socks->origin_fd);
    }
    free(socks);
}

static void origin_read(struct selector_key *key) {
    struct socks5* data = ATTACHMENT(key);
    
    printf("SOCKS5: Origin read event\n");
    
    size_t count;
    uint8_t* ptr = buffer_write_ptr(&data->write_buffer, &count);
    ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);
    
    if (n > 0) {
        buffer_write_adv(&data->write_buffer, n);
        printf("SOCKS5: Received %ld bytes from origin, forwarding to client!\n", n);
        
        uint8_t *read_ptr = buffer_read_ptr(&data->write_buffer, &count);
        if (count > 0) {
            ssize_t sent = send(data->client_fd, read_ptr, count, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (sent > 0) {
                buffer_read_adv(&data->write_buffer, sent);
                printf("SOCKS5: Forwarded %ld bytes to client immediately\n", sent);
            } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                printf("SOCKS5: Client not ready, data buffered for later\n");
                selector_set_interest(key->s, data->client_fd, OP_WRITE); // mas tarde
            } else if (sent < 0) {
                printf("SOCKS5: Error sending to client: %s\n", strerror(errno));
                selector_unregister_fd(key->s, key->fd);
                selector_unregister_fd(key->s, data->client_fd);
                return;
            }
        }
    } else if (n == 0) {
        printf("SOCKS5: Origin closed connection - cleaning up properly\n");
        selector_unregister_fd(key->s, key->fd);
        selector_unregister_fd(key->s, data->client_fd);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        printf("SOCKS5: Error reading from origin: %s\n", strerror(errno));
        selector_unregister_fd(key->s, key->fd);
        selector_unregister_fd(key->s, data->client_fd);
    }
}