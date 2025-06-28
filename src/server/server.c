#include <stdio.h>
#include "../shared/selector.h"
#include "socks5.h"

#define MAX_CONNECTIONS_ALLOWED 1024

int main(void) {
    fd_selector selector = selector_new(MAX_CONNECTIONS_ALLOWED);
    if (selector == NULL) {
        return 1;
    }

    int fake_client_fd = 42;
    socks5_init(fake_client_fd, selector);

    printf("Sock5 init OK\n");

    selector_destroy(selector);
    return 0;
}
