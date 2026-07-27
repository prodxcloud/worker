#include "vx_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static vx_log_level_t g_level = VX_LOG_WARN;

static const char *level_tag(vx_log_level_t level) {
    switch (level) {
    case VX_LOG_ERROR:
        return "ERROR";
    case VX_LOG_WARN:
        return "WARN ";
    case VX_LOG_INFO:
        return "INFO ";
    case VX_LOG_DEBUG:
        return "DEBUG";
    case VX_LOG_TRACE:
        return "TRACE";
    default:
        return "?????";
    }
}

void vx_log_set_level(vx_log_level_t level) {
    g_level = level;
}
vx_log_level_t vx_log_get_level(void) {
    return g_level;
}

void vx_log_init_from_env(void) {
    const char *env = getenv("VX_LOG");
    if (env == NULL || *env == '\0') return;
    if (strcmp(env, "silent") == 0)
        g_level = VX_LOG_SILENT;
    else if (strcmp(env, "error") == 0)
        g_level = VX_LOG_ERROR;
    else if (strcmp(env, "warn") == 0)
        g_level = VX_LOG_WARN;
    else if (strcmp(env, "info") == 0)
        g_level = VX_LOG_INFO;
    else if (strcmp(env, "debug") == 0)
        g_level = VX_LOG_DEBUG;
    else if (strcmp(env, "trace") == 0)
        g_level = VX_LOG_TRACE;
}

unsigned long long vx_now_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (unsigned long long)ts.tv_sec * 1000000ull + (unsigned long long)ts.tv_nsec / 1000ull;
}

/* Trim a __FILE__ down to its basename so log lines stay narrow. */
static const char *basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

void vx_logf(vx_log_level_t level, const char *file, int line, const char *fmt, ...) {
    if (level > g_level) return;

    /* One buffer, one write(2): concurrent sandboxes share stderr and we do not
     * want interleaved half-lines. */
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "[vxworker %s %llu %s:%d] ", level_tag(level), vx_now_us(),
                     basename_of(file), line);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0) return;

    size_t total = (size_t)n + (size_t)m;
    if (total > sizeof(buf) - 2) total = sizeof(buf) - 2;
    buf[total++] = '\n';

    ssize_t written = write(STDERR_FILENO, buf, total);
    (void)written; /* logging must never fail the caller */
}
