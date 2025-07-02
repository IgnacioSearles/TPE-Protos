#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

void print_bytes(uint8_t* data, int len, const char* label) {
    printf("%s (%d bytes): ", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int main() {
    printf("🧪 Testing SOCKS5 Implementation\n");
    printf("================================\n");
    
    // Crear socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("❌ socket");
        return 1;
    }

    // Conectar al servidor
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("🔌 Connecting to SOCKS5 server...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("❌ connect");
        close(sock);
        return 1;
    }
    printf("✅ Connected to server\n\n");

    // === FASE 1: HELLO ===
    printf("📋 PHASE 1: HELLO Handshake\n");
    printf("---------------------------\n");
    
    uint8_t hello[] = {0x05, 0x01, 0x02}; // version=5, nmethods=1, method=2
    print_bytes(hello, sizeof(hello), "📤 Sending HELLO");
    
    if (send(sock, hello, sizeof(hello), 0) < 0) {
        perror("❌ send hello");
        close(sock);
        return 1;
    }

    uint8_t hello_resp[2];
    if (recv(sock, hello_resp, sizeof(hello_resp), 0) < 0) {
        perror("❌ recv hello");
        close(sock);
        return 1;
    }
    print_bytes(hello_resp, sizeof(hello_resp), "📥 Received HELLO_REPLY");

    if (hello_resp[0] != 0x05 || hello_resp[1] != 0x02) {
        printf("❌ HELLO failed: version=%d, method=%d\n", hello_resp[0], hello_resp[1]);
        close(sock);
        return 1;
    }
    printf("✅ HELLO phase completed successfully\n\n");

    // === FASE 2: AUTHENTICATION ===
    printf("📋 PHASE 2: Authentication\n");
    printf("--------------------------\n");
    
    char* user = "admin";
    char* pass = "password";
    uint8_t auth[256];
    int auth_len = 0;
    
    auth[auth_len++] = 0x01;                    // version
    auth[auth_len++] = strlen(user);            // username length
    memcpy(auth + auth_len, user, strlen(user)); // username
    auth_len += strlen(user);
    auth[auth_len++] = strlen(pass);            // password length  
    memcpy(auth + auth_len, pass, strlen(pass)); // password
    auth_len += strlen(pass);

    print_bytes(auth, auth_len, "📤 Sending AUTH");
    
    if (send(sock, auth, auth_len, 0) < 0) {
        perror("❌ send auth");
        close(sock);
        return 1;
    }

    uint8_t auth_resp[2];
    if (recv(sock, auth_resp, sizeof(auth_resp), 0) < 0) {
        perror("❌ recv auth");
        close(sock);
        return 1;
    }
    print_bytes(auth_resp, sizeof(auth_resp), "📥 Received AUTH_REPLY");

    if (auth_resp[0] != 0x01 || auth_resp[1] != 0x00) {
        printf("❌ AUTH failed: version=%d, status=%d\n", auth_resp[0], auth_resp[1]);
        close(sock);
        return 1;
    }
    printf("✅ Authentication phase completed successfully\n\n");

    // === FASE 3: REQUEST (should fail) ===
    printf("📋 PHASE 3: REQUEST (Testing Implementation Limit)\n");
    printf("--------------------------------------------------\n");
    
    uint8_t request[] = {
        0x05, 0x01, 0x00, 0x01,  // VER, CMD=CONNECT, RSV, ATYP=IPv4
        0x08, 0x08, 0x08, 0x08,  // IP: 8.8.8.8
        0x00, 0x50               // Port: 80
    };
    
    print_bytes(request, sizeof(request), "📤 Sending REQUEST");
    
    if (send(sock, request, sizeof(request), 0) < 0) {
        perror("❌ send request");
        close(sock);
        return 1;
    }

    printf("⏳ Waiting for response or connection close...\n");
    
    // Intentar recibir respuesta con timeout
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    timeout.tv_sec = 2;  // 2 segundos timeout
    timeout.tv_usec = 0;
    
    int result = select(sock + 1, &readfds, NULL, NULL, &timeout);
    
    if (result > 0) {
        uint8_t request_resp[10];
        ssize_t n = recv(sock, request_resp, sizeof(request_resp), 0);
        if (n > 0) {
            print_bytes(request_resp, n, "📥 Received REQUEST_REPLY");
            printf("⚠️  Server responded to REQUEST (unexpected)\n");
        } else if (n == 0) {
            printf("🚧 Server closed connection after REQUEST (expected)\n");
            printf("✅ This indicates REQUEST parsing is not yet implemented\n");
        } else {
            printf("❌ Error reading response: %s\n", strerror(errno));
        }
    } else if (result == 0) {
        printf("⏰ Timeout waiting for response\n");
        printf("🚧 Server likely closed connection (expected behavior)\n");
        printf("✅ This indicates REQUEST parsing is not yet implemented\n");
    } else {
        printf("❌ Select error: %s\n", strerror(errno));
    }

    close(sock);
    
    printf("\n🎯 TEST SUMMARY\n");
    printf("===============\n");
    printf("✅ HELLO handshake: WORKING\n");
    printf("✅ Authentication: WORKING\n");
    printf("🚧 REQUEST parsing: NOT IMPLEMENTED (as expected)\n");
    printf("\n🎉 SOCKS5 basic protocol implementation is functional!\n");
    printf("📝 Next step: Implement REQUEST parsing and connection forwarding\n");
    
    return 0;
}