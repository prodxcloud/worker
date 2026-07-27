/* vx_log.h — minimal, allocation-free structured logger.
 *
 * Writes a single write(2) per record to stderr so output stays intact when
 * multiple sandboxed processes share a terminal.  Safe to call after fork()
 * and before exec(): it never allocates and never touches locks. */
#ifndef VX_LOG_H
#define VX_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VX_LOG_SILENT = 0,
    VX_LOG_ERROR = 1,
    VX_LOG_WARN = 2,
    VX_LOG_INFO = 3,
    VX_LOG_DEBUG = 4,
    VX_LOG_TRACE = 5
} vx_log_level_t;

/* Reads VX_LOG=silent|error|warn|info|debug|trace (default: warn). */
void vx_log_init_from_env(void);
void vx_log_set_level(vx_log_level_t level);
vx_log_level_t vx_log_get_level(void);

/* Emit a record.  Truncates at 1 KiB rather than allocating. */
void vx_logf(vx_log_level_t level, const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define VX_ERROR(...) vx_logf(VX_LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define VX_WARN(...) vx_logf(VX_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define VX_INFO(...) vx_logf(VX_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define VX_DEBUG(...) vx_logf(VX_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define VX_TRACE(...) vx_logf(VX_LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

/* Monotonic microseconds since boot — the engine's only clock. */
unsigned long long vx_now_us(void);

#ifdef __cplusplus
}
#endif

#endif /* VX_LOG_H */
