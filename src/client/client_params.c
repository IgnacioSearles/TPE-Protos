#include "client_params.h"
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char* create_str_copy(const char* src) {
    if (src == NULL) return NULL;
    int len = strlen(src);
    char* copy = malloc(len + 1);
    if (copy == NULL) return NULL;
    strcpy(copy, src);
    return copy;
}

int client_params_parse(int argc, char **argv, client_config *config) {
    int opt;
    while ((opt = getopt(argc, argv, "h:p:")) != -1) {
        switch (opt) {
            case 'h': config->host = create_str_copy(optarg); break;
            case 'p': config->port = create_str_copy(optarg); break;
            default:
                printf("client: %s -h <host> -p <port>\n", argv[0]);
                return -1;
        }
    }

    if (config->host == NULL || config->port == NULL) {
        fprintf(stderr, "client error: missing parameters\n");
        return -1;
    }

    return 0;
}

void client_config_destroy(client_config *config) {
    if (config->port != NULL) {
        free(config->port);
    }

    if (config->host != NULL) {
        free(config->host);
    }
}
