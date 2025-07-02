#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

void print_bytes(uint8_t* data, int len, const char* label) {
    printf("%s (%d bytes): ", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

int test_single_target(const char* host, int port) {
    printf("🎯 Testing SOCKS5 connection to %s:%d\n", host, port);
    printf("=====================================\n");
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("❌ socket");
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("🔌 Connecting to SOCKS5 server...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("❌ connect to SOCKS5");
        close(sock);
        return -1;
    }
    printf("✅ Connected to SOCKS5 server\n");

    // HELLO
    printf("\n📋 HELLO Phase\n");
    uint8_t hello[] = {0x05, 0x01, 0x02};
    print_bytes(hello, sizeof(hello), "📤 Sending HELLO");
    
    if (send(sock, hello, sizeof(hello), 0) < 0) {
        perror("❌ send hello");
        close(sock);
        return -1;
    }
    
    uint8_t hello_resp[2];
    if (recv(sock, hello_resp, sizeof(hello_resp), 0) < 0) {
        perror("❌ recv hello");
        close(sock);
        return -1;
    }
    print_bytes(hello_resp, sizeof(hello_resp), "📥 Received HELLO_REPLY");
    
    if (hello_resp[0] != 0x05 || hello_resp[1] != 0x02) {
        printf("❌ HELLO failed: version=%d, method=%d\n", hello_resp[0], hello_resp[1]);
        close(sock);
        return -1;
    }
    printf("✅ HELLO phase successful\n");

    // AUTH
    printf("\n📋 AUTH Phase\n");
    char* user = "admin";
    char* pass = "password";
    uint8_t auth[256];
    int auth_len = 0;
    
    auth[auth_len++] = 0x01;
    auth[auth_len++] = strlen(user);
    memcpy(auth + auth_len, user, strlen(user));
    auth_len += strlen(user);
    auth[auth_len++] = strlen(pass);
    memcpy(auth + auth_len, pass, strlen(pass));
    auth_len += strlen(pass);

    print_bytes(auth, auth_len, "📤 Sending AUTH");
    
    if (send(sock, auth, auth_len, 0) < 0) {
        perror("❌ send auth");
        close(sock);
        return -1;
    }
    
    uint8_t auth_resp[2];
    if (recv(sock, auth_resp, sizeof(auth_resp), 0) < 0) {
        perror("❌ recv auth");
        close(sock);
        return -1;
    }
    print_bytes(auth_resp, sizeof(auth_resp), "📥 Received AUTH_REPLY");
    
    if (auth_resp[0] != 0x01 || auth_resp[1] != 0x00) {
        printf("❌ AUTH failed: version=%d, status=%d\n", auth_resp[0], auth_resp[1]);
        close(sock);
        return -1;
    }
    printf("✅ AUTH phase successful\n");

    // REQUEST
    printf("\n📋 REQUEST Phase\n");
    uint8_t request[262];
    int req_len = 0;
    
    request[req_len++] = 0x05; // VER
    request[req_len++] = 0x01; // CMD=CONNECT
    request[req_len++] = 0x00; // RSV
    
    // Usar dominio
    printf("📍 Building domain request for: %s\n", host);
    request[req_len++] = 0x03; // ATYP=DOMAIN
    int host_len = strlen(host);
    request[req_len++] = host_len;
    memcpy(request + req_len, host, host_len);
    req_len += host_len;
    
    // Puerto
    uint16_t port_net = htons(port);
    memcpy(request + req_len, &port_net, 2);
    req_len += 2;
    
    print_bytes(request, req_len, "📤 Sending REQUEST");
    
    printf("⏳ Sending request...\n");
    if (send(sock, request, req_len, 0) < 0) {
        perror("❌ send request");
        close(sock);
        return -1;
    }
    printf("✅ Request sent successfully\n");

    printf("⏰ Waiting for response (10s timeout)...\n");
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    
    int result = select(sock + 1, &readfds, NULL, NULL, &timeout);
    
    if (result > 0) {
        uint8_t response[10];
        ssize_t n = recv(sock, response, sizeof(response), 0);
        if (n > 0) {
            print_bytes(response, n, "📥 Received RESPONSE");
            
            if (n >= 2) {
                uint8_t version = response[0];
                uint8_t reply = response[1];
                
                printf("📊 Response: version=0x%02x, reply=0x%02x\n", version, reply);
                
                if (reply == 0x00) {
                    printf("🎉 SUCCESS: Connection established to %s:%d!\n", host, port);
                    close(sock);
                    return 0;
                } else {
                    printf("❌ Connection failed with reply code 0x%02x\n", reply);
                }
            }
        } else if (n == 0) {
            printf("🔌 Server closed connection\n");
        } else {
            printf("❌ Error reading response: %s\n", strerror(errno));
        }
    } else if (result == 0) {
        printf("⏰ TIMEOUT: No response received\n");
    } else {
        printf("❌ Select error: %s\n", strerror(errno));
    }

    close(sock);
    return -1;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <host> <port>\n", argv[0]);
        printf("Example: %s google.com 80\n", argv[0]);
        return 1;
    }
    
    const char* host = argv[1];
    int port = atoi(argv[2]);
    
    printf("🧪 Single Target SOCKS5 Test\n");
    printf("============================\n\n");
    
    int result = test_single_target(host, port);
    
    if (result == 0) {
        printf("\n🎉 Overall result: SUCCESS\n");
    } else {
        printf("\n💥 Overall result: FAILED\n");
    }
    
    return result;
}