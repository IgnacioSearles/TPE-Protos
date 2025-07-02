#include "socks5.h"
#include "socks5_protocol.h"
#include "../shared/netutils.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static void socks5_read(struct selector_key *key);
static void socks5_write(struct selector_key *key);
static void socks5_close(struct selector_key *key);

static const struct fd_handler socks5_handler = {
    .handle_read  = socks5_read,
    .handle_write = socks5_write,
    .handle_close = socks5_close,
};

int socks5_init(const int client_fd, fd_selector s, server_config* config) {
    socks5* socks = calloc(1, sizeof(*socks));
    if (socks == NULL) {
        close(client_fd);
        return -1;
    }

    socks->client_fd = client_fd;
    socks->origin_fd = -1;
    socks->config = config;
    socks->state = HELLO_READ;
    socks->auth_ok = false;
    socks->auth_method = 0;

    buffer_init(&(socks->read_buffer), INITIAL_BUFFER_SIZE, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), INITIAL_BUFFER_SIZE, socks->write_raw_buff);

    if (selector_register(s, client_fd, &socks5_handler, OP_READ, socks) != SELECTOR_SUCCESS) {
        free(socks);
        return -1;
    }

    return 0;
}

static void socks5_read(struct selector_key *key) {
    struct socks5 *socks = (struct socks5 *)key->data;
    bool should_cleanup = false;
    
    switch (socks->state) {
        case HELLO_READ: {
            uint8_t buffer[257];
            ssize_t n = recv(socks->client_fd, buffer, sizeof(buffer) - 1, MSG_NOSIGNAL);
            
            if (n <= 0 || n < 2) {
                should_cleanup = true;
                break;
            }

            uint8_t version = buffer[0];
            uint8_t nmethods = buffer[1];
            
            if (version != SOCKS5_VERSION || n < 2 + nmethods) {
                should_cleanup = true;
                break;
            }

            bool supports_userpass = false;
            for (int i = 0; i < nmethods && i < (n - 2); i++) {
                if (buffer[2 + i] == AUTH_METHOD_USER_PASS) {
                    supports_userpass = true;
                    break;
                }
            }

            socks->auth_method = supports_userpass ? AUTH_METHOD_USER_PASS : AUTH_METHOD_NO_METHODS;
            socks->state = HELLO_WRITE;
            
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        case AUTH_READ: {
            uint8_t buffer[513];
            ssize_t n = recv(socks->client_fd, buffer, sizeof(buffer) - 1, MSG_NOSIGNAL);
            
            if (n <= 0 || n < 2) {
                should_cleanup = true;
                break;
            }

            uint8_t version = buffer[0];
            uint8_t ulen = buffer[1];
            
            if (version != AUTH_VERSION || n < 2 + ulen + 1 || ulen > 255) {
                should_cleanup = true;
                break;
            }

            char username[256] = {0};
            memcpy(username, buffer + 2, ulen);
            
            uint8_t plen = buffer[2 + ulen];
            if (n < 2 + ulen + 1 + plen || plen > 255) {
                should_cleanup = true;
                break;
            }
            
            char password[256] = {0};
            memcpy(password, buffer + 2 + ulen + 1, plen);
            
            // Verificar credenciales
            socks->auth_ok = false;
            if (socks->config && socks->config->users) {
                for (int i = 0; i < socks->config->user_count; i++) {
                    server_user user = socks->config->users[i];
                    if (strcmp(user.user, username) == 0 && strcmp(user.pass, password) == 0) {
                        socks->auth_ok = true;
                        break;
                    }
                }
            }

            socks->state = AUTH_WRITE;
            printf("✅ SOCKS5: AUTH processed (user='%s', success=%s)\n", 
                   username, socks->auth_ok ? "YES" : "NO");
            
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        // TODO seguir con esto
        case REQUEST_READ: {
            printf("🚧 SOCKS5: REQUEST received but not implemented yet\n");
            should_cleanup = true;
            break;
        }
        
        default:
            should_cleanup = true;
            break;
    }
    
    if (should_cleanup) {
        printf("SOCKS5: Cleaning up connection fd=%d\n", socks->client_fd);
        selector_unregister_fd(key->s, key->fd);
    }
}

static void socks5_write(struct selector_key *key) {
    struct socks5 *socks = (struct socks5 *)key->data;
    bool should_cleanup = false;
    
    switch (socks->state) {
        case HELLO_WRITE: {
            socks5_hello_response response = create_hello_response(socks->auth_method);
            ssize_t n = send(socks->client_fd, &response, sizeof(response), MSG_NOSIGNAL);
            
            if (n <= 0) {
                should_cleanup = true;
                break;
            }

            if (socks->auth_method == AUTH_METHOD_NO_METHODS) {
                should_cleanup = true;
                break;
            }

            socks->state = AUTH_READ;
            
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        case AUTH_WRITE: {
            auth_response response = create_auth_response(socks->auth_ok ? AUTH_SUCCESS : AUTH_FAILURE);
            ssize_t n = send(socks->client_fd, &response, sizeof(response), MSG_NOSIGNAL);
            
            if (n <= 0) {
                should_cleanup = true;
                break;
            }
            
            if (!socks->auth_ok) {
                printf("❌ SOCKS5: Authentication failed, closing connection\n");
                should_cleanup = true;
                break;
            }

            printf("✅ SOCKS5: AUTH_REPLY sent successfully - Authentication OK!\n");
            
            socks->state = REQUEST_READ;
            
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        default:
            should_cleanup = true;
            break;
    }
    
    if (should_cleanup) {
        printf("SOCKS5: Cleaning up connection fd=%d\n", socks->client_fd);
        selector_unregister_fd(key->s, key->fd);
    }
}

static void socks5_close(struct selector_key *key) {
    struct socks5* socks = (struct socks5 *)key->data;
    if (socks == NULL) {
        return;
    }
    
    if (socks->client_fd >= 0) {
        close(socks->client_fd);
    }
    if (socks->origin_fd >= 0) {
        close(socks->origin_fd);
    }
    free(socks);
}