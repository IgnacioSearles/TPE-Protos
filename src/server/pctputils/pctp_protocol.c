#include "pctp_protocol.h"
#include "../../shared/logger.h"
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

// Includes para macOS
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

void write_msg_to_buffer(buffer* write_buffer, const char* msg) {
    size_t len = strlen(msg);
    size_t available;
    uint8_t *ptr = buffer_write_ptr(write_buffer, &available);
    size_t to_copy = len < available ? len : available;
    memcpy(ptr, msg, to_copy);
    buffer_write_adv(write_buffer, to_copy);
}

int send_buffer_msg(int fd, buffer* write_buffer) {
    uint8_t *ptr;
    size_t count;

    while (buffer_can_read(write_buffer)) {
        ptr = buffer_read_ptr(write_buffer, &count);
        ssize_t sent = send(fd, ptr, count, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return MSG_SEND_BLOCKED;
            } else {
                LOG(LOG_DEBUG, "Send failed");
                return MSG_SEND_ERROR;
            }
        }
        buffer_read_adv(write_buffer, sent);
    }
    return MSG_SENT;
}