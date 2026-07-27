#include "vx_task.h"

#include <stdio.h>
#include <string.h>

#include "vx_error.h"

vx_status_t vx_task_decode(const void *buf, size_t len, const vx_task_header_t **out) {
    if (buf == NULL || out == NULL) return VX_ERR_INVALID_ARG;
    if (len < VX_TASK_HEADER_SIZE) return VX_ERR_INVALID_ARG;

    /* The struct is packed, so every field is byte-addressed and no member can
     * be misaligned relative to the buffer start.  Copy the scalars we need to
     * validate rather than dereferencing through a possibly-unaligned pointer,
     * which keeps UBSan quiet on strict-alignment targets. */
    uint32_t magic;
    memcpy(&magic, buf, sizeof(magic));
    if (magic != VX_MAGIC_HEADER) return VX_ERR_BAD_MAGIC;

    uint8_t engine;
    memcpy(&engine, (const unsigned char *)buf + 76, sizeof(engine));
    if (engine != ENGINE_ION && engine != ENGINE_IRON) return VX_ERR_INVALID_ARG;

    uint64_t payload_len;
    memcpy(&payload_len, (const unsigned char *)buf + 85, sizeof(payload_len));
    if (payload_len > VX_MAX_PAYLOAD_LEN) return VX_ERR_PAYLOAD_TOO_LARGE;
    if (payload_len > len - VX_TASK_HEADER_SIZE) return VX_ERR_INVALID_ARG;

    *out = (const vx_task_header_t *)buf;
    return VX_OK;
}

size_t vx_task_wire_len(const vx_task_header_t *hdr) {
    if (hdr == NULL) return 0;
    return VX_TASK_HEADER_SIZE + (size_t)hdr->payload_len;
}

long vx_task_encode(void *buf, size_t cap, uint64_t task_id, const char *tenant_id,
                    vx_engine_type_t engine, uint32_t memory_limit_mb, uint32_t cpu_quota_us,
                    const void *payload, size_t payload_len) {
    if (buf == NULL) return VX_ERR_INVALID_ARG;
    if (payload_len > VX_MAX_PAYLOAD_LEN) return VX_ERR_PAYLOAD_TOO_LARGE;
    if (payload_len > 0 && payload == NULL) return VX_ERR_INVALID_ARG;
    if (cap < VX_TASK_HEADER_SIZE + payload_len) return VX_ERR_INVALID_ARG;

    vx_task_header_t *hdr = (vx_task_header_t *)buf;
    memset(hdr, 0, VX_TASK_HEADER_SIZE);
    hdr->magic = VX_MAGIC_HEADER;
    hdr->task_id = task_id;
    if (tenant_id != NULL) {
        /* NUL-pad, and truncate a 64+ byte tenant slug instead of overflowing. */
        size_t n = strnlen(tenant_id, VX_TENANT_ID_LEN);
        memcpy(hdr->tenant_id, tenant_id, n);
    }
    hdr->engine = (uint8_t)engine;
    hdr->memory_limit_mb = memory_limit_mb;
    hdr->cpu_quota_us = cpu_quota_us;
    hdr->payload_len = payload_len;
    if (payload_len > 0) memcpy(hdr->payload, payload, payload_len);

    return (long)(VX_TASK_HEADER_SIZE + payload_len);
}

void vx_task_tenant(const vx_task_header_t *hdr, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) return;
    if (hdr == NULL) {
        out[0] = '\0';
        return;
    }
    size_t n = strnlen(hdr->tenant_id, VX_TENANT_ID_LEN);
    if (n > out_len - 1) n = out_len - 1;
    memcpy(out, hdr->tenant_id, n);
    out[n] = '\0';
}

long vx_result_encode(void *buf, size_t cap, uint64_t task_id, vx_task_state_t state,
                      int32_t exit_code, uint64_t duration_us, const void *payload,
                      size_t payload_len) {
    if (buf == NULL) return VX_ERR_INVALID_ARG;
    if (payload_len > VX_MAX_PAYLOAD_LEN) return VX_ERR_PAYLOAD_TOO_LARGE;
    if (payload_len > 0 && payload == NULL) return VX_ERR_INVALID_ARG;
    if (cap < VX_RESULT_HEADER_SIZE + payload_len) return VX_ERR_INVALID_ARG;

    vx_result_header_t *res = (vx_result_header_t *)buf;
    memset(res, 0, VX_RESULT_HEADER_SIZE);
    res->magic = VX_MAGIC_HEADER;
    res->task_id = task_id;
    res->state = (uint8_t)state;
    res->exit_code = exit_code;
    res->duration_us = duration_us;
    res->payload_len = (uint32_t)payload_len;
    if (payload_len > 0) memcpy(res->payload, payload, payload_len);

    return (long)(VX_RESULT_HEADER_SIZE + payload_len);
}

vx_status_t vx_result_decode(const void *buf, size_t len, const vx_result_header_t **out) {
    if (buf == NULL || out == NULL) return VX_ERR_INVALID_ARG;
    if (len < VX_RESULT_HEADER_SIZE) return VX_ERR_INVALID_ARG;

    uint32_t magic;
    memcpy(&magic, buf, sizeof(magic));
    if (magic != VX_MAGIC_HEADER) return VX_ERR_BAD_MAGIC;

    uint32_t payload_len;
    memcpy(&payload_len, (const unsigned char *)buf + 25, sizeof(payload_len));
    if (payload_len > VX_MAX_PAYLOAD_LEN) return VX_ERR_PAYLOAD_TOO_LARGE;
    if (payload_len > len - VX_RESULT_HEADER_SIZE) return VX_ERR_INVALID_ARG;

    *out = (const vx_result_header_t *)buf;
    return VX_OK;
}

int vx_task_describe(const vx_task_header_t *hdr, char *out, size_t out_len) {
    if (hdr == NULL || out == NULL) return VX_ERR_INVALID_ARG;
    char tenant[VX_TENANT_ID_LEN + 1];
    vx_task_tenant(hdr, tenant, sizeof(tenant));
    return snprintf(out, out_len, "task=%llu tenant=%s engine=%s mem=%uMiB cpu=%uus payload=%llub",
                    (unsigned long long)hdr->task_id, tenant, vx_engine_str(hdr->engine),
                    hdr->memory_limit_mb, hdr->cpu_quota_us, (unsigned long long)hdr->payload_len);
}
