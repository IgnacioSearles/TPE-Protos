#include "server_params.h"
#include "logger.h"
#include "server_config.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void print_help(const char *program_name) {
    printf("%s [options]\n", program_name);
    printf("  -h                 shows help and terminates\n");
    printf("  -l <addr>          address where the SOCKS proxy will be served\n");
    printf("  -L <addr>          address where the Proxy Configuration and Tracking Protocol (PCTP) will be served\n");
    printf("  -p <port>          SOCKS port (default %d)\n", SOCKS5_STD_PORT);
    printf("  -P <port>          PCTP port (default %d)\n", PCTP_STD_PORT);
    printf("  -u <user:pass>     adds an initial ADMIN user (max %d)\n", MAX_INITIAL_USERS);
    printf("  -v                 shows version and terminates\n");
    printf("  -d                 <log_level> can be one of: DEBUG, INFO, WARN, ERROR, NONE\n");
}

void print_version(const char* program_name) {
    printf("%s version %s\n", program_name, VERSION);
}

char* copy_str(const char* str) {
    int len = strlen(str);
    char* out = malloc(len + 1);
    if (out == NULL) return NULL;
    strcpy(out, str);
    return out;
}

parse_server_params_status parse_server_params(int argc, char **argv,
                                               server_config *config) {
    int opt;
    while ((opt = getopt(argc, argv, "hl:L:p:P:d:u:v")) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return PARAMS_SHOULD_EXIT;
        case 'v':
            print_version(argv[0]);
            return PARAMS_SHOULD_EXIT;
        case 'l':
            config->socks_addr = copy_str(optarg);
            break;
        case 'L':
            config->pctp_addr = copy_str(optarg);
            break;
        case 'p':
            config->socks_port = atoi(optarg);
            break;
        case 'P':
            config->pctp_port = atoi(optarg);
            break;
        case 'u':
            if (config->user_count >= MAX_INITIAL_USERS) {
                fprintf(stderr, "server error: max amount of initial users is %d\n", MAX_INITIAL_USERS);
                return PARAMS_ERROR;
            }

            char *sep = strchr(optarg, ':');
            if (sep == NULL) {
                fprintf(stderr, "server error: invalid format to add user\n");
                return PARAMS_ERROR;
            }

            sep[0] = '\0';
            add_user(config, optarg, &sep[1], ADMIN);

            break;
        case 'd':
            config->log_level = copy_str(optarg);
            break;
        default:
            break;
        }
    }

    return PARAMS_SUCCESS;
}
