#include <stdio.h>
#include <signal.h>
#include "../shared/selector.h"
#include "../shared/netutils.h"
#include <logger.h>
#include "server_params.h"
#include "server_stats.h"
#include "socks5.h"
#include "pctp.h"
#include "server_config.h"
#include <stdlib.h>
#include <sys/socket.h>

#define MAX_SOCKS5_CONNECTIONS 1000
#define MAX_PCTP_CONNECTIONS 24
#define MAX_CONNECTIONS (MAX_SOCKS5_CONNECTIONS + MAX_PCTP_CONNECTIONS)

static server_config config;
static server_stats socks5_server_stats;

static volatile bool done = false;
void handle_shutdown(int sig) {
    done = true;
}

static void accept_socks5(struct selector_key *key) {
    int client_fd = accept(key->fd, NULL, NULL);

    if (client_fd < 0) {
        LOG(LOG_WARN, "server error: could not accept socks5 client");
        return;
    }

    if (set_non_blocking(client_fd) < 0) {
        close(client_fd);
        LOG(LOG_WARN, "server error: could not set socks5 client fd as non blocking");
        return;
    }

    if (socks5_init(client_fd, key->s, &config, socks5_server_stats) < 0) {
        close(client_fd);
        LOG(LOG_WARN, "server error: could not initialize SOCKS5");
        return;
    }
}

static void accept_pctp(struct selector_key *key) {
    int client_fd = accept(key->fd, NULL, NULL);

    if (client_fd < 0) {
        LOG(LOG_WARN, "server error: could not accept PCTP client");
        return;
    }

    if (set_non_blocking(client_fd) < 0) {
        close(client_fd);
        LOG(LOG_WARN, "server error: could not set PCTP client fd as non blocking");
        return;
    }

    if (pctp_init(client_fd, key->s, &config, socks5_server_stats) < 0){
        close(client_fd);
        LOG(LOG_WARN, "server error: could not initialize PCTP");
        return;
    }
}

int main(int argc, char** argv) {
    config = create_config(); 

    parse_server_params_status status = parse_server_params(argc, argv, &config);
    if (status == PARAMS_SHOULD_EXIT || status == PARAMS_ERROR) {
        destroy_config(&config);
        return 0;
    }

    if (admin_count(&config) == 0) {
        add_user(&config, DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, ADMIN);
    }

    logger_set_level(config.log_level);

    signal(SIGINT, handle_shutdown);  // Ctrl+C
    signal(SIGTERM, handle_shutdown); // kill pid

    socks5_server_stats = create_server_stats(); 
    if (socks5_server_stats == NULL) {
        LOG(LOG_ERROR, "server error: failed to create stats collector for SOCKS5 server");
        return EXIT_FAILURE;
    }

    int socks5_socket = create_passive_tcp_socket(config.socks_addr, config.socks_port, MAX_SOCKS5_CONNECTIONS); 
    if (socks5_socket < 0) {
        LOG(LOG_ERROR, "server error: failed to create SOCKS5 socket");
        destroy_server_stats(socks5_server_stats);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    int pctp_socket = create_passive_tcp_socket(config.pctp_addr, config.pctp_port, MAX_PCTP_CONNECTIONS);
    if (pctp_socket < 0) {
        LOG(LOG_ERROR, "server error: failed to create PCTP socket");
        close(socks5_socket);
        destroy_server_stats(socks5_server_stats);
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
        LOG(LOG_ERROR, "server error: could no init selector library");
        close(socks5_socket);
        close(pctp_socket);
        destroy_server_stats(socks5_server_stats);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(MAX_CONNECTIONS);
    if (selector == NULL) {
        LOG(LOG_ERROR, "server errror: could no initialize selector");
        close(socks5_socket);
        close(pctp_socket);
        destroy_server_stats(socks5_server_stats);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_handler socks5_accept_handler = {
        .handle_read = accept_socks5
    };
    if (selector_register(selector, socks5_socket, &socks5_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        LOG(LOG_ERROR, "server error: could not register socks5 socket in selector");
        close(socks5_socket);
        close(pctp_socket);
        selector_destroy(selector);
        destroy_server_stats(socks5_server_stats);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    fd_handler pctp_accept_handler = {
        .handle_read = accept_pctp
    };
    if (selector_register(selector, pctp_socket, &pctp_accept_handler, OP_READ, NULL) != SELECTOR_SUCCESS) {
        LOG(LOG_ERROR, "server error: could not register pctp socket in selector");
        close(socks5_socket);
        close(pctp_socket);
        selector_destroy(selector);
        destroy_server_stats(socks5_server_stats);
        destroy_config(&config);
        return EXIT_FAILURE;
    }

    while (!done) {
        selector_status status = selector_select(selector);
        if (status != SELECTOR_SUCCESS && status != SELECTOR_MAXFD) {
            LOG_A(LOG_ERROR, "server error: fatal error in selection. STATUS: %d", status);
            break;
        }
    }

    close(socks5_socket);
    close(pctp_socket);
    selector_destroy(selector);
    destroy_server_stats(socks5_server_stats);
    destroy_config(&config);
    return 0;
}
