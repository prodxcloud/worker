/* test_task.c — encode/decode of the ABI frame, including every rejection path.
 *
 * Decoding is the trust boundary: a frame arrives from shared memory that a
 * guest engine can also write to, so every field has to be validated before it
 * is believed. */
#include "vx_error.h"
#include "vx_task.h"
#include "vxtest.h"

int main(void) {
    VXT_BEGIN("task frame codec");

    unsigned char buf[VX_TASK_HEADER_SIZE + 64];
    const vx_task_header_t *hdr = NULL;

    VXT_CASE("roundtrip preserves every field");
    long n = vx_task_encode(buf, sizeof(buf), 0xDEADBEEFull, "acme-prod", ENGINE_IRON, 256, 75000,
                            "hello world", 11);
    VXT_EQ_INT(n, VX_TASK_HEADER_SIZE + 11, "encoded length");
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_OK, "decode status");
    if (hdr != NULL) {
        VXT_EQ_INT(hdr->magic, VX_MAGIC_HEADER, "magic");
        VXT_EQ_INT(hdr->task_id, 0xDEADBEEFull, "task_id");
        VXT_EQ_INT(hdr->engine, ENGINE_IRON, "engine");
        VXT_EQ_INT(hdr->memory_limit_mb, 256, "memory_limit_mb");
        VXT_EQ_INT(hdr->cpu_quota_us, 75000, "cpu_quota_us");
        VXT_EQ_INT(hdr->payload_len, 11, "payload_len");
        VXT_CHECK(memcmp(hdr->payload, "hello world", 11) == 0, "payload bytes");
        char tenant[VX_TENANT_ID_LEN + 1];
        vx_task_tenant(hdr, tenant, sizeof(tenant));
        VXT_CHECK(strcmp(tenant, "acme-prod") == 0, "tenant is \"%s\"", tenant);
        VXT_EQ_INT(vx_task_wire_len(hdr), VX_TASK_HEADER_SIZE + 11, "wire length");
    }

    VXT_CASE("empty payload is valid");
    n = vx_task_encode(buf, sizeof(buf), 1, "t", ENGINE_ION, 8, 10000, NULL, 0);
    VXT_EQ_INT(n, VX_TASK_HEADER_SIZE, "header-only length");
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_OK, "header-only decode");

    VXT_CASE("corrupt magic is rejected");
    n = vx_task_encode(buf, sizeof(buf), 1, "t", ENGINE_ION, 8, 10000, "x", 1);
    buf[0] ^= 0xFF;
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_ERR_BAD_MAGIC, "flipped magic");
    buf[0] ^= 0xFF;

    VXT_CASE("unknown engine is rejected");
    buf[76] = 0x7F;
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_ERR_INVALID_ARG, "engine 0x7F");
    buf[76] = ENGINE_ION;

    VXT_CASE("a truncated header is rejected");
    VXT_EQ_INT(vx_task_decode(buf, VX_TASK_HEADER_SIZE - 1, &hdr), VX_ERR_INVALID_ARG,
               "92-byte buffer");
    VXT_EQ_INT(vx_task_decode(buf, 0, &hdr), VX_ERR_INVALID_ARG, "empty buffer");

    VXT_CASE("a payload_len that overruns the buffer is rejected");
    /* This is the important one: a hostile guest sets a huge payload_len so the
     * host reads past the end of the shared-memory slot. */
    uint64_t lie = 4096;
    memcpy(buf + 85, &lie, sizeof(lie));
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_ERR_INVALID_ARG,
               "payload_len beyond buffer end");

    VXT_CASE("payload_len above the 16 MiB ABI cap is rejected");
    lie = (uint64_t)VX_MAX_PAYLOAD_LEN + 1;
    memcpy(buf + 85, &lie, sizeof(lie));
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_ERR_PAYLOAD_TOO_LARGE, "16 MiB + 1");

    VXT_CASE("encode refuses to overflow a short buffer");
    VXT_CHECK(vx_task_encode(buf, 10, 1, "t", ENGINE_ION, 8, 1, "xxxxx", 5) < 0,
              "10-byte destination");
    VXT_CHECK(vx_task_encode(buf, sizeof(buf), 1, "t", ENGINE_ION, 8, 1, "x",
                             (size_t)VX_MAX_PAYLOAD_LEN + 1) == VX_ERR_PAYLOAD_TOO_LARGE,
              "oversize payload");
    VXT_CHECK(vx_task_encode(NULL, 100, 1, "t", ENGINE_ION, 8, 1, NULL, 0) < 0, "NULL dest");

    VXT_CASE("an over-long tenant slug is truncated, not overflowed");
    static const char long_tenant[] =
        "0123456789012345678901234567890123456789012345678901234567890123456789";
    n = vx_task_encode(buf, sizeof(buf), 7, long_tenant, ENGINE_ION, 8, 1, NULL, 0);
    VXT_EQ_INT(n, VX_TASK_HEADER_SIZE, "encoded length with long tenant");
    VXT_EQ_INT(vx_task_decode(buf, (size_t)n, &hdr), VX_OK, "decodes after truncation");
    if (hdr != NULL) {
        VXT_EQ_INT(hdr->engine, ENGINE_ION, "engine survived the long tenant");
        char tenant[VX_TENANT_ID_LEN + 1];
        vx_task_tenant(hdr, tenant, sizeof(tenant));
        VXT_EQ_INT(strlen(tenant), VX_TENANT_ID_LEN, "tenant truncated to 64 bytes");
    }

    VXT_CASE("result frames roundtrip");
    unsigned char rbuf[VX_RESULT_HEADER_SIZE + 32];
    const vx_result_header_t *res = NULL;
    long rn = vx_result_encode(rbuf, sizeof(rbuf), 99, VX_STATE_KILLED_OOM, 137, 1234567, "oom", 3);
    VXT_EQ_INT(rn, VX_RESULT_HEADER_SIZE + 3, "encoded result length");
    VXT_EQ_INT(vx_result_decode(rbuf, (size_t)rn, &res), VX_OK, "decode result");
    if (res != NULL) {
        VXT_EQ_INT(res->task_id, 99, "result task_id");
        VXT_EQ_INT(res->state, VX_STATE_KILLED_OOM, "result state");
        VXT_EQ_INT(res->exit_code, 137, "result exit_code");
        VXT_EQ_INT(res->duration_us, 1234567, "result duration_us");
        VXT_EQ_INT(res->payload_len, 3, "result payload_len");
    }

    VXT_CASE("negative exit codes survive the wire");
    rn = vx_result_encode(rbuf, sizeof(rbuf), 1, VX_STATE_FAILED, -1, 0, NULL, 0);
    VXT_EQ_INT(vx_result_decode(rbuf, (size_t)rn, &res), VX_OK, "decode negative exit");
    if (res != NULL) VXT_EQ_INT(res->exit_code, -1, "exit_code is signed");

    VXT_CASE("result frame validation");
    rbuf[0] ^= 0xFF;
    VXT_EQ_INT(vx_result_decode(rbuf, (size_t)rn, &res), VX_ERR_BAD_MAGIC, "bad result magic");
    rbuf[0] ^= 0xFF;
    VXT_EQ_INT(vx_result_decode(rbuf, VX_RESULT_HEADER_SIZE - 1, &res), VX_ERR_INVALID_ARG,
               "truncated result");

    VXT_CASE("status and state names are stable");
    VXT_CHECK(strcmp(vx_status_name(VX_ERR_CGROUP), "VX_ERR_CGROUP") == 0, "status name");
    VXT_CHECK(strcmp(vx_state_str(VX_STATE_COMPLETED), "COMPLETED") == 0, "state name");
    VXT_CHECK(strcmp(vx_engine_str(ENGINE_ION), "ion") == 0, "engine name");
    VXT_CHECK(strcmp(vx_engine_str(0x55), "unknown") == 0, "unknown engine name");

    VXT_END();
}
