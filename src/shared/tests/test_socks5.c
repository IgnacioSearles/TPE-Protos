#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>

// Set socket to non-blocking mode
int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Non-blocking send with timeout
int nb_send(int sock, const uint8_t* data, size_t len, int timeout_sec) {
    size_t sent = 0;
    time_t start = time(NULL);
    
    while (sent < len) {
        if (time(NULL) - start > timeout_sec) {
            printf("⏰ Send timeout\n");
            return -1;
        }
        
        fd_set writefds;
        struct timeval tv;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int result = select(sock + 1, NULL, &writefds, NULL, &tv);
        if (result > 0 && FD_ISSET(sock, &writefds)) {
            ssize_t n = send(sock, data + sent, len - sent, MSG_DONTWAIT);
            if (n > 0) {
                sent += n;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("❌ send error");
                return -1;
            }
        } else if (result < 0) {
            perror("❌ select error");
            return -1;
        }
    }
    return 0;
}

// Non-blocking recv with timeout
int nb_recv(int sock, uint8_t* buffer, size_t len, int timeout_sec) {
    size_t received = 0;
    time_t start = time(NULL);
    
    while (received < len) {
        if (time(NULL) - start > timeout_sec) {
            printf("⏰ Recv timeout (received %zu/%zu bytes)\n", received, len);
            return received; // Return partial data
        }
        
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int result = select(sock + 1, &readfds, NULL, NULL, &tv);
        if (result > 0 && FD_ISSET(sock, &readfds)) {
            ssize_t n = recv(sock, buffer + received, len - received, MSG_DONTWAIT);
            if (n > 0) {
                received += n;
            } else if (n == 0) {
                printf("🔌 Connection closed by server\n");
                return received;
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("❌ recv error");
                return -1;
            }
        } else if (result < 0) {
            perror("❌ select error");
            return -1;
        }
    }
    return received;
}

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

    // Set socket to non-blocking
    if (set_non_blocking(sock) < 0) {
        perror("❌ set_non_blocking");
        close(sock);
        return -1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1080);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("🔌 Connecting to SOCKS5 server...\n");
    int connect_result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (connect_result < 0 && errno != EINPROGRESS) {
        perror("❌ connect to SOCKS5");
        close(sock);
        return -1;
    }

    // Wait for connection to complete
    if (errno == EINPROGRESS) {
        printf("⏳ Connection in progress...\n");
        fd_set writefds;
        struct timeval tv;
        FD_ZERO(&writefds);
        FD_SET(sock, &writefds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int result = select(sock + 1, NULL, &writefds, NULL, &tv);
        if (result <= 0) {
            printf("❌ Connection timeout or error\n");
            close(sock);
            return -1;
        }
        
        // Check if connection succeeded
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
            printf("❌ Connection failed: %s\n", strerror(error));
            close(sock);
            return -1;
        }
    }
    
    printf("✅ Connected to SOCKS5 server\n");

    // HELLO
    printf("\n📋 HELLO Phase\n");
    uint8_t hello[] = {0x05, 0x01, 0x02};
    print_bytes(hello, sizeof(hello), "📤 Sending HELLO");
    
    if (nb_send(sock, hello, sizeof(hello), 5) < 0) {
        printf("❌ Failed to send HELLO\n");
        close(sock);
        return -1;
    }
    
    uint8_t hello_resp[2];
    int received = nb_recv(sock, hello_resp, sizeof(hello_resp), 5);
    if (received != sizeof(hello_resp)) {
        printf("❌ Failed to receive HELLO response\n");
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
    
    if (nb_send(sock, auth, auth_len, 5) < 0) {
        printf("❌ Failed to send AUTH\n");
        close(sock);
        return -1;
    }
    
    uint8_t auth_resp[2];
    received = nb_recv(sock, auth_resp, sizeof(auth_resp), 5);
    if (received != sizeof(auth_resp)) {
        printf("❌ Failed to receive AUTH response\n");
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
    
    if (nb_send(sock, request, req_len, 5) < 0) {
        printf("❌ Failed to send REQUEST\n");
        close(sock);
        return -1;
    }
    printf("✅ Request sent successfully\n");

    printf("⏰ Waiting for response...\n");
    uint8_t response[10];
    received = nb_recv(sock, response, sizeof(response), 10);
    
    if (received >= 2) {
        print_bytes(response, received, "📥 Received RESPONSE");
        
        uint8_t version = response[0];
        uint8_t reply = response[1];
        
        printf("📊 Response: version=0x%02x, reply=0x%02x\n", version, reply);
        
        if (reply == 0x00) {
            printf("🎉 SUCCESS: Connection established to %s:%d!\n", host, port);
            
            // Test HTTP request
            printf("\n📋 Testing HTTP request...\n");
            char http_request[512];
            snprintf(http_request, sizeof(http_request), 
                    "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host);
            
            if (nb_send(sock, (uint8_t*)http_request, strlen(http_request), 5) == 0) {
                printf("📤 HTTP request sent\n");
                
                uint8_t http_resp[1024];
                int http_received = nb_recv(sock, http_resp, sizeof(http_resp), 10);
                if (http_received > 0) {
                    printf("� HTTP response received (%d bytes)\n", http_received);
                    printf("🎉 SOCKS5 proxy working correctly!\n");
                    close(sock);
                    return 0;
                } else {
                    printf("❌ Failed to receive HTTP response\n");
                }
            } else {
                printf("❌ Failed to send HTTP request\n");
            }
        } else {
            printf("❌ Connection failed with reply code 0x%02x\n", reply);
        }
    } else {
        printf("❌ Failed to receive REQUEST response (received %d bytes)\n", received);
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