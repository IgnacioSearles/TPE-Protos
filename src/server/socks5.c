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

// Función para conectar al servidor destino
static int connect_to_target(const char* host, uint16_t port) {
    printf("SOCKS5: Connecting to %s:%d\n", host, port);
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("SOCKS5: Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Intentar convertir como IP primero
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        // Si no es IP, resolver hostname
        printf("SOCKS5: Resolving hostname %s...\n", host);
        struct hostent *he = gethostbyname(host);
        if (he == NULL) {
            printf("❌ SOCKS5: Failed to resolve %s: ", host);
            switch (h_errno) {
                case HOST_NOT_FOUND:
                    printf("Host not found\n");
                    break;
                case NO_DATA:
                    printf("No address associated with hostname\n");
                    break;
                case NO_RECOVERY:
                    printf("Non-recoverable name server error\n");
                    break;
                case TRY_AGAIN:
                    printf("Temporary failure in name resolution\n");
                    break;
                default:
                    printf("Unknown error (%d)\n", h_errno);
                    break;
            }
            close(sockfd);
            return -1;
        }
        
        if (he->h_addr_list == NULL || he->h_addr_list[0] == NULL) {
            printf("SOCKS5: No addresses found for %s\n", host);
            close(sockfd);
            return -1;
        }
        
        printf("SOCKS5: Resolved %s to %s\n", host, inet_ntoa(*((struct in_addr*)he->h_addr_list[0])));
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    } else {
        printf("SOCKS5: Using IP address %s\n", host);
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("SOCKS5: Failed to connect to %s:%d: %s\n", host, port, strerror(errno));
        close(sockfd);
        return -1;
    }

    printf("SOCKS5: Connected to %s:%d (fd=%d)\n", host, port, sockfd);
    return sockfd;
}

static int parse_socks5_request(uint8_t* buffer, ssize_t buffer_len, parsed_request* req) {
    printf("SOCKS5: Parsing request (%ld bytes)\n", buffer_len);
    if (buffer_len < 4) {
        printf("SOCKS5: Request too short (need at least 4 bytes)\n");
        return -1;
    }

    req->version = buffer[0];
    req->cmd = buffer[1];
    req->atyp = buffer[3];

    printf("SOCKS5: version=0x%02x, cmd=0x%02x, atyp=0x%02x\n", req->version, req->cmd, req->atyp);

    if (req->version != SOCKS5_VERSION) {
        printf("SOCKS5: Invalid version 0x%02x\n", req->version);
        return -1;
    }

    if (req->cmd != SOCKS5_CMD_CONNECT) {
        printf("SOCKS5: Unsupported command 0x%02x\n", req->cmd);
        return -1;
    }

    int addr_start = 4;
    int addr_len = 0;

    switch (req->atyp) {
        case SOCKS5_ATYP_IPV4: {
            printf("SOCKS5: IPv4 address\n");
            if (buffer_len < 4 + 4 + 2) {
                printf("SOCKS5: Incomplete IPv4 request\n");
                return -1;
            }
            
            // Convertir IP a string
            struct in_addr ip_addr;
            memcpy(&ip_addr, buffer + addr_start, 4);
            if (inet_ntop(AF_INET, &ip_addr, req->target_host, sizeof(req->target_host)) == NULL) {
                printf("SOCKS5: Failed to convert IPv4 address\n");
                return -1;
            }
            addr_len = 4;
            break;
        }
        
        case SOCKS5_ATYP_DOMAIN: {
            printf("SOCKS5: Domain name\n");
            if (buffer_len < 4 + 1) {
                printf("SOCKS5: Incomplete domain request\n");
                return -1;
            }
            
            uint8_t domain_len = buffer[addr_start];
            if (buffer_len < 4 + 1 + domain_len + 2) {
                printf("SOCKS5: Incomplete domain request\n");
                return -1;
            }
            
            if (domain_len >= sizeof(req->target_host)) {
                printf("SOCKS5: Domain name too long\n");
                return -1;
            }
            
            memcpy(req->target_host, buffer + addr_start + 1, domain_len);
            req->target_host[domain_len] = '\0';
            addr_len = 1 + domain_len;
            break;
        }
        
        case SOCKS5_ATYP_IPV6:
            // TODO falta ipv6 support, agregarlo en el struct tmb!
            printf("SOCKS5: IPv6 not supported yet\n");
            return -1;
            
        default:
            printf("SOCKS5: Unsupported address type 0x%02x\n", req->atyp);
            return -1;
    }

    uint16_t* port_ptr = (uint16_t*)(buffer + addr_start + addr_len);
    req->target_port = ntohs(*port_ptr);

    printf("SOCKS5: Parsed request - target=%s:%d\n", req->target_host, req->target_port);

    return 0;
}

int socks5_init(const int client_fd, fd_selector s, server_config* config, server_stats stats) {
    socks5* socks = calloc(1, sizeof(*socks));
    if (socks == NULL) {
        return -1;
    }

    socks->client_fd = client_fd;
    socks->origin_fd = -1;
    socks->config = config;
    socks->state = HELLO_READ;
    socks->auth_ok = false;
    socks->auth_method = 0;
    socks->stats = stats;

    buffer_init(&(socks->read_buffer), INITIAL_BUFFER_SIZE, socks->read_raw_buff);
    buffer_init(&(socks->write_buffer), INITIAL_BUFFER_SIZE, socks->write_raw_buff);

    if (selector_register(s, client_fd, &socks5_handler, OP_READ, socks) != SELECTOR_SUCCESS) {
        free(socks);
        return -1;
    }

    log_connection_open(stats, client_fd);

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
            printf("SOCKS5: AUTH processed (user='%s', success=%s)\n", 
                   username, socks->auth_ok ? "YES" : "NO");
            
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        case REQUEST_READ: {
            printf("SOCKS5: Processing REQUEST_READ\n");
            
            uint8_t buffer[MAX_REQUEST_SIZE];
            ssize_t n = recv(socks->client_fd, buffer, sizeof(buffer), MSG_NOSIGNAL);
            
            if (n <= 0) {
                printf("SOCKS5: Error reading request: %s\n", strerror(errno));
                should_cleanup = true;
                break;
            }

            parsed_request req;
            if (parse_socks5_request(buffer, n, &req) != 0) {
                printf("SOCKS5: Invalid REQUEST format\n");
                socks5_response error_resp = create_socks5_response(SOCKS5_REP_FAILURE);
                send(socks->client_fd, &error_resp, sizeof(error_resp), MSG_NOSIGNAL);
                should_cleanup = true;
                break;
            }

            strncpy(socks->target_host, req.target_host, sizeof(socks->target_host) - 1);
            socks->target_port = req.target_port;

            socks->origin_fd = connect_to_target(req.target_host, req.target_port);
            
            if (socks->origin_fd >= 0) {
                socks->reply_code = SOCKS5_REP_SUCCESS;
                printf("SOCKS5: Connection to %s:%d successful\n", req.target_host, req.target_port);
            } else {
                socks->reply_code = SOCKS5_REP_HOST_UNREACH;
                printf("SOCKS5: Connection to %s:%d failed\n", req.target_host, req.target_port);
            }

            socks->state = REQUEST_WRITE;
            
            if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS) {
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
                printf("SOCKS5: Authentication failed, closing connection\n");
                should_cleanup = true;
                break;
            }

            printf("SOCKS5: AUTH_REPLY sent successfully - Authentication OK!\n");
            
            socks->state = REQUEST_READ;
            
            if (selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS) {
                should_cleanup = true;
            }
            break;
        }
        
        case REQUEST_WRITE: {
            printf("SOCKS5: Processing REQUEST_WRITE\n");
            
            socks5_response response = create_socks5_response(socks->reply_code);
            ssize_t n = send(socks->client_fd, &response, sizeof(response), MSG_NOSIGNAL);
            
            if (n <= 0) {
                printf("SOCKS5: Error sending REQUEST response: %s\n", strerror(errno));
                should_cleanup = true;
                break;
            }

            printf("SOCKS5: REQUEST_REPLY sent (reply=0x%02x)\n", socks->reply_code);
            
            if (socks->reply_code == SOCKS5_REP_SUCCESS) {
                printf("SOCKS5: Handshake complete! Connection established to %s:%d\n", socks->target_host, socks->target_port);
                printf("🚧 SOCKS5: Data forwarding not implemented yet - closing connection\n");
                // TODO: Aquí iría el estado COPY para forwarding de datos
            }
            
            should_cleanup = true; // Por ahora cerrar después de REQUEST
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
    
    log_connection_close(socks->stats, socks->client_fd);

    if (socks->client_fd >= 0) {
        close(socks->client_fd);
    }
    if (socks->origin_fd >= 0) {
        close(socks->origin_fd);
    }
    free(socks);
}
