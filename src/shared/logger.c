#include <logger.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static logging_level min_level = LOG_INFO;

#define TM_YEAR_RELATIVE 1900
#define TM_MONTH_RELATIVE 1

typedef struct {
    const char *name;
    int level;
} logging_level_representation;

static logging_level_representation logging_levels[] = {
    {"DEBUG", LOG_DEBUG},
    {"INFO",  LOG_INFO},
    {"WARNG", LOG_WARN},
    {"ERROR", LOG_ERROR},
    {"NONE",  LOG_NONE},
    {NULL, -1}
};

static const char* get_logging_level_name(logging_level level) {
    if (level > LOG_NONE) return "INVALID";

    return logging_levels[level].name;
}

static int get_logging_level(const char* level) {
    if (level == NULL) return -1;

    for (int i = 0; logging_levels[i].level != -1; i++) {
        if (strcmp(level, logging_levels[i].name) == 0)
            return logging_levels[i].level;
    }

    return -1;
}

void logger_set_level(const char *level) {
    int val = get_logging_level(level);
    if (val >= 0) min_level = val;
}

static FILE* get_output_stream(logging_level level) {
    if (level >= LOG_WARN)
        return stderr;

    return stdout;
}

static const char* get_filename(const char* path) {
    const char* file = strrchr(path, '/');
    if (file) file++;
    else file = path;
    return file;
}

void logger_log(logging_level level, const char* file, const char *fmt, ...) {
    if (level < min_level) return;

    FILE* out = get_output_stream(level);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    fprintf(out, "[%d-%02d-%02dT%02d:%02d:%02dZ] [%s] [%s] ", t->tm_year + TM_YEAR_RELATIVE, t->tm_mon + TM_MONTH_RELATIVE, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, get_filename(file), get_logging_level_name(level));

    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
    fflush(out);
}
