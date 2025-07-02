#include "server_params.h"
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
    printf("  -N                 allows password disserters\n");
    printf("  -v                 shows version and terminates\n");
}

void print_version(const char* program_name) {
    printf("%s version %s\n", program_name, VERSION);
}

char* copy_ip_addr(const char* addr) {
    int len = strlen(addr);
    char* out = malloc(len + 1);
    if (out == NULL) return NULL;
    strcpy(out, addr);
    return out;
}

parse_server_params_status parse_server_params(int argc, char **argv,
                                               server_config *config) {
    printf("DEBUG: parse_server_params called with argc=%d\n", argc);
    
    int opt;
    while ((opt = getopt(argc, argv, "hl:L:p:P:u:Nv")) != -1) {
        printf("DEBUG: Processing option '%c'\n", opt);
        switch (opt) {
        case 'h':
            print_help(argv[0]);
            return PARAMS_SHOULD_EXIT;
        case 'v':
            print_version(argv[0]);
            return PARAMS_SHOULD_EXIT;
        case 'l':
            config->socks_addr = copy_ip_addr(optarg);
            printf("DEBUG: Set socks_addr to %s\n", optarg);
            break;
        case 'L':
            config->pctp_addr = copy_ip_addr(optarg);
            printf("DEBUG: Set pctp_addr to %s\n", optarg);
            break;
        case 'p':
            config->socks_port = atoi(optarg);
            printf("DEBUG: Set socks_port to %d\n", config->socks_port);
            break;
        case 'P':
            config->pctp_port = atoi(optarg);
            printf("DEBUG: Set pctp_port to %d\n", config->pctp_port);
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
            printf("DEBUG: Added user %s\n", optarg);

            break;
        case 'N':
            config->disectors_enabled = 0;
            printf("DEBUG: Disabled disectors\n");
            break;
        default:
            printf("DEBUG: Unknown option '%c'\n", opt);
            break;
        }
    }

    printf("DEBUG: parse_server_params returning PARAMS_SUCCESS\n");
    return PARAMS_SUCCESS;
}
