/* test_abi_layout.c — freezes the v1 wire layout.
 *
 * If this suite fails, ion and iron are already broken: both hard-code these
 * offsets to decode a frame without a parser. */
#include <stddef.h>

#include "vxtest.h"
#include "worker_abi.h"

int main(void) {
    VXT_BEGIN("abi v1 wire layout");

    VXT_CASE("constants are frozen");
    VXT_EQ_INT(VX_MAGIC_HEADER, 0x58575601u, "magic");
    VXT_EQ_INT(VX_ABI_VERSION, 1, "abi version");
    VXT_EQ_INT(VX_TENANT_ID_LEN, 64, "tenant id length");
    VXT_EQ_INT(VX_TASK_HEADER_SIZE, 93, "task header size");
    VXT_EQ_INT(VX_RESULT_HEADER_SIZE, 29, "result header size");
    VXT_EQ_INT(VX_MAX_PAYLOAD_LEN, 16 * 1024 * 1024, "max payload");
    VXT_EQ_INT(ENGINE_ION, 0x01, "ENGINE_ION");
    VXT_EQ_INT(ENGINE_IRON, 0x02, "ENGINE_IRON");

    VXT_CASE("struct sizes match the declared wire sizes");
    VXT_EQ_INT(sizeof(vx_task_header_t), VX_TASK_HEADER_SIZE, "sizeof task header");
    VXT_EQ_INT(sizeof(vx_result_header_t), VX_RESULT_HEADER_SIZE, "sizeof result header");

    VXT_CASE("task header field offsets");
    VXT_EQ_INT(offsetof(vx_task_header_t, magic), 0, "magic");
    VXT_EQ_INT(offsetof(vx_task_header_t, task_id), 4, "task_id");
    VXT_EQ_INT(offsetof(vx_task_header_t, tenant_id), 12, "tenant_id");
    VXT_EQ_INT(offsetof(vx_task_header_t, engine), 76, "engine");
    VXT_EQ_INT(offsetof(vx_task_header_t, memory_limit_mb), 77, "memory_limit_mb");
    VXT_EQ_INT(offsetof(vx_task_header_t, cpu_quota_us), 81, "cpu_quota_us");
    VXT_EQ_INT(offsetof(vx_task_header_t, payload_len), 85, "payload_len");
    VXT_EQ_INT(offsetof(vx_task_header_t, payload), 93, "payload");

    VXT_CASE("result header field offsets");
    VXT_EQ_INT(offsetof(vx_result_header_t, magic), 0, "magic");
    VXT_EQ_INT(offsetof(vx_result_header_t, task_id), 4, "task_id");
    VXT_EQ_INT(offsetof(vx_result_header_t, state), 12, "state");
    VXT_EQ_INT(offsetof(vx_result_header_t, exit_code), 13, "exit_code");
    VXT_EQ_INT(offsetof(vx_result_header_t, duration_us), 17, "duration_us");
    VXT_EQ_INT(offsetof(vx_result_header_t, payload_len), 25, "payload_len");
    VXT_EQ_INT(offsetof(vx_result_header_t, payload), 29, "payload");

    VXT_CASE("bytes on the wire are little-endian and unpadded");
    unsigned char buf[VX_TASK_HEADER_SIZE + 4] = {0};
    vx_task_header_t *h = (vx_task_header_t *)buf;
    h->magic = VX_MAGIC_HEADER;
    h->task_id = 0x0102030405060708ull;
    memcpy(h->tenant_id, "acme", 4);
    h->engine = ENGINE_ION;
    h->memory_limit_mb = 8;
    h->cpu_quota_us = 50000;
    h->payload_len = 4;
    memcpy(h->payload, "ping", 4);

    VXT_CHECK(buf[0] == 0x01 && buf[1] == 0x56 && buf[2] == 0x57 && buf[3] == 0x58,
              "magic bytes are %02x %02x %02x %02x", buf[0], buf[1], buf[2], buf[3]);
    VXT_CHECK(buf[4] == 0x08, "task_id low byte is 0x%02x", buf[4]);
    VXT_CHECK(buf[11] == 0x01, "task_id high byte is 0x%02x", buf[11]);
    VXT_CHECK(memcmp(buf + 12, "acme", 4) == 0, "tenant bytes at offset 12");
    VXT_CHECK(buf[16] == 0, "tenant is NUL-padded, not garbage");
    VXT_CHECK(buf[76] == 0x01, "engine byte is 0x%02x", buf[76]);
    VXT_CHECK(memcmp(buf + 93, "ping", 4) == 0, "payload starts at offset 93");

    VXT_CASE("a 64-byte tenant slug fills the field with no terminator");
    vx_task_header_t *h2 = (vx_task_header_t *)buf;
    memset(h2->tenant_id, 'x', VX_TENANT_ID_LEN);
    VXT_CHECK(buf[12 + 63] == 'x', "last tenant byte is used");
    VXT_CHECK(buf[76] == 0x01, "engine field is not clobbered by a full tenant slug");

    VXT_END();
}
