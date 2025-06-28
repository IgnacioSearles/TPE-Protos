#include <stdio.h>
#include <signal.h>
#include "../shared/selector.h"
#include "../shared/netutils.h"
#include "server_params.h"
#include "socks5.h"
#include "server_config.h"
#include <stdlib.h>
#include <sys/socket.h>

#define MAX_SOCKS5_CONNECTIONS 1000
#define MAX_PCTP_CONNECTIONS 24
#define MAX_CONNECTIONS (MAX_SOCKS5_CONNECTIONS + MAX_PCTP_CONNECTIONS)

// TODO: checkear si esto esta bien para manejar la señal
static volatile bool done = false;
void handle_shutdown(int sig) {
    done = true;
}

static void accept_socks5(struct selector_key *key) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd < 0) {
        perror("server error: could not accept socks5 client");
        return;
    }

    if (set_non_blocking(client_fd) < 0) {
        close(client_fd);
        perror("server error: could not set socks5 client fd as non blocking");
        return;
    }

    //socks5_init(client_fd, key->s);
    printf("server ok: client connected to socks5 port\n");
    close(client_fd);
}

static void accept_pctp(struct selector_key *key) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(key->fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_fd < 0) {
        perror("server error: could not accept PCTP client");
        return;
    }

    if (set_non_blocking(client_fd) < 0) {
        close(client_fd);
        perror("server error: could not set PCTP client fd as non blocking");
        return;
    }

    //pctp_init(client_fd, key->s);
    printf("server ok: client connected to PCTP port\n");
    close(client_fd);
}

int main(int argc, char** argv) {
    server_config config = create_config(); 

    parse_server_params_status status = parse_server_params(argc, argv, &config);
    if (status == PARAMS_SHOULD_EXIT || status == PARAMS_ERROR) {
        destroy_config(&config);
        return 0;
    }

    signal(SIGINT, handle_shutdown);  // Ctrl+C
    signal(SIGTERM, handle_shutdown); // kill pid

    int socks5_socket = create_passive_tcp_socket(config.socks_addr, config.socks_port, MAX_SOCKS5_CONNECTIONS); 
    if (socks5_socket < 0) {
        perror("server error: failed to create SOCKS5 socket");
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    int pctp_socket = create_passive_tcp_socket(config.pctp_addr, config.pctp_port, MAX_PCTP_CONNECTIONS);
    if (pctp_socket < 0) {
        perror("server error: failed to create PCTP socket");
        close(socks5_socket);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    const struct selector_init selector_config = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec = 10,
            .tv_nsec = 0
        }
    };

    if (selector_init(&selector_config) != SELECTOR_SUCCESS) {
        perror("server error: could no init selector library");
        close(socks5_socket);
        close(pctp_socket);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_CONNECTIONS);
    if (selector == NULL) {
        perror("server errror: could no initialize selector");
        close(socks5_socket);
        close(pctp_socket);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_handler socks5_accept_handler = {
        .handle_read = accept_socks5
    };
    if (selector_register(selector, socks5_socket, &socks5_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("server error: could not register socks5 socket in selector");
        close(socks5_socket);
        close(pctp_socket);
        selector_destroy(selector);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_handler pctp_accept_handler = {
        .handle_read = accept_pctp
    };
    if (selector_register(selector, pctp_socket, &pctp_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        perror("server error: could not register pctp socket in selector");
        close(socks5_socket);
        close(pctp_socket);
        selector_destroy(selector);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    while (!done) {
        selector_status status = selector_select(selector);
        if (status != SELECTOR_SUCCESS && status != SELECTOR_MAXFD) {
            perror("server error: fatal error in selection");
            break;
        }
    }

    close(socks5_socket);
    close(pctp_socket);
    selector_destroy(selector);
    destroy_config(&config);
    return 0;
}
