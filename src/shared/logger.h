#ifndef LOGGER_H
#define LOGGER_H

#define LOG(level, fmt) logger_log(level, __FILE__, fmt)
#define LOG_A(level, fmt, ...) logger_log(level, __FILE__, fmt, __VA_ARGS__)

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
    LOG_NONE  = 4
} logging_level;

void logger_set_level(const char* level);
void logger_log(logging_level level, const char* file, const char* fmt, ...);

#endif
