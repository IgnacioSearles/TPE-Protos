#include <stdio.h>
#include "selector.h"
#include "socks5.h"

int main(void) {
    fd_selector selector = selector_new(1024);
    if (selector == NULL) {
        return 1;
    }

    int fake_client_fd = 42;
    socks5_init(fake_client_fd, selector);

    printf("Sock5 init OK\n");

    // selector_destroy(selector);
    return 0;
}
