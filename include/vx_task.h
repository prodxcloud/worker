/* vx_task.h — encode and decode the wire format defined in worker_abi.h.
 *
 * The header is packed and little-endian, so on every supported target (x86-64,
 * aarch64) a validated buffer can be read in place with zero copies.  Decoding
 * is therefore a bounds-and-magic check, not a parse. */
#ifndef VX_TASK_H
#define VX_TASK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Validate buf as a task header and return a pointer into it.
 *
 * Checks, in order: buffer at least VX_TASK_HEADER_SIZE, magic matches,
 * engine is known, payload_len <= VX_MAX_PAYLOAD_LEN, and
 * VX_TASK_HEADER_SIZE + payload_len <= len (no truncated payload).
 * Returns VX_ERR_BAD_MAGIC / VX_ERR_PAYLOAD_TOO_LARGE / VX_ERR_INVALID_ARG. */
vx_status_t vx_task_decode(const void *buf, size_t len, const vx_task_header_t **out);

/* Total wire size of a header plus its payload. */
size_t vx_task_wire_len(const vx_task_header_t *hdr);

/* Serialise a task into buf.  Returns the number of bytes written, or a
 * negative vx_status_t if buf is too small. */
long vx_task_encode(void *buf, size_t cap, uint64_t task_id, const char *tenant_id,
                    vx_engine_type_t engine, uint32_t memory_limit_mb,
                    uint32_t cpu_quota_us, const void *payload, size_t payload_len);

/* tenant_id is NUL-padded rather than NUL-terminated when it fills all 64
 * bytes, so it needs a bounded copy to be printed safely.  out must hold at
 * least VX_TENANT_ID_LEN + 1 bytes. */
void vx_task_tenant(const vx_task_header_t *hdr, char *out, size_t out_len);

/* Serialise a result record.  Returns bytes written or negative vx_status_t. */
long vx_result_encode(void *buf, size_t cap, uint64_t task_id, vx_task_state_t state,
                      int32_t exit_code, uint64_t duration_us, const void *payload,
                      size_t payload_len);

vx_status_t vx_result_decode(const void *buf, size_t len, const vx_result_header_t **out);

/* Human-readable one-liner for logs and the CLI. */
int vx_task_describe(const vx_task_header_t *hdr, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* VX_TASK_H */
