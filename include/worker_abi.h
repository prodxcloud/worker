/*
 * worker_abi.h — VxCloud immutable System ABI (v1)
 *
 * This header is THE execution contract between the host `vxnode` runtime and
 * every guest engine (`ion` in Rust, `iron` in C++23).  It is deliberately
 * dependency-free C11: no libc calls, no allocation, no platform headers beyond
 * <stdint.h>/<stdbool.h>, so it can be consumed verbatim by C, C++, Rust
 * (bindgen / hand-mirrored), and any language with a C FFI.
 *
 * STABILITY: v1 field order and offsets are frozen.  Additive changes require
 * bumping VX_ABI_VERSION and the low byte of VX_MAGIC_HEADER.  Never reorder,
 * resize, or repurpose an existing field — engines pin these offsets.
 *
 * On-wire layout of vx_task_header_t (packed, little-endian):
 *
 *   offset  size  field
 *   ------  ----  ------------------------------------------------------------
 *        0     4  magic              VX_MAGIC_HEADER
 *        4     8  task_id            monotonic per-node task identifier
 *       12    64  tenant_id[64]      NUL-padded tenant slug (multi-tenant key)
 *       76     1  engine             vx_engine_type_t
 *       77     4  memory_limit_mb    cgroup memory.max, mebibytes
 *       81     4  cpu_quota_us       cgroup cpu.max quota, microseconds
 *       85     8  payload_len        length of payload[] in bytes
 *       93     -  payload[]          flexible array (JSON / Protobuf / raw)
 *
 *   VX_TASK_HEADER_SIZE == 93
 *
 * Copyright (c) 2026 VxCloud / ProdXCloud.  Licensed under Apache-2.0.
 */
#ifndef WORKER_ABI_H
#define WORKER_ABI_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Versioning                                                                */
/* ------------------------------------------------------------------------- */

/* 'V','X','W' + version nibble.  A guest MUST reject any header whose magic
 * does not match exactly; a mismatch means an incompatible host runtime. */
#define VX_MAGIC_HEADER 0x58575601u /* 'V','X','W', v1 */

#define VX_ABI_VERSION 1u

/* Fixed sizes engines may rely on. */
#define VX_TENANT_ID_LEN 64
#define VX_TASK_HEADER_SIZE 93u
#define VX_RESULT_HEADER_SIZE 29u

/* Largest payload a single ring-buffer record may carry (16 MiB).  Larger
 * payloads must be passed by shared-memory handle, not inline. */
#define VX_MAX_PAYLOAD_LEN (16u * 1024u * 1024u)

/* ------------------------------------------------------------------------- */
/* Engine selection                                                          */
/* ------------------------------------------------------------------------- */

typedef enum {
    ENGINE_ION = 0x01,  /* Micro-worker  (Rust 2024 / Tokio) — <1ms, <8MB RSS */
    ENGINE_IRON = 0x02  /* Heavy worker  (C++23 / io_uring)  — durable tasks   */
} vx_engine_type_t;

/* ------------------------------------------------------------------------- */
/* Task header — host -> guest                                               */
/* ------------------------------------------------------------------------- */

typedef struct __attribute__((packed)) {
    uint32_t magic;                     /* VX_MAGIC_HEADER                   */
    uint64_t task_id;                   /* monotonic task identifier         */
    char tenant_id[VX_TENANT_ID_LEN];   /* NUL-padded tenant slug            */
    uint8_t engine;                     /* vx_engine_type_t                  */
    uint32_t memory_limit_mb;           /* cgroup memory.max (MiB)           */
    uint32_t cpu_quota_us;              /* cgroup cpu.max quota (us/100ms)   */
    uint64_t payload_len;               /* bytes in payload[]                */
    uint8_t payload[];                  /* flexible array (JSON / Protobuf)  */
} vx_task_header_t;

/* ------------------------------------------------------------------------- */
/* Result header — guest -> host                                             */
/* ------------------------------------------------------------------------- */

typedef enum {
    VX_STATE_PENDING = 0x00,
    VX_STATE_RUNNING = 0x01,
    VX_STATE_COMPLETED = 0x02,
    VX_STATE_FAILED = 0x03,
    VX_STATE_KILLED_OOM = 0x04,   /* cgroup memory.max breach               */
    VX_STATE_KILLED_TIMEOUT = 0x05,
    VX_STATE_KILLED_SIGNAL = 0x06 /* SIGTERM / SIGKILL from supervisor      */
} vx_task_state_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;         /* VX_MAGIC_HEADER                              */
    uint64_t task_id;       /* echoes vx_task_header_t.task_id              */
    uint8_t state;          /* vx_task_state_t                              */
    int32_t exit_code;      /* engine/process exit status                   */
    uint64_t duration_us;   /* wall-clock execution time, microseconds      */
    uint32_t payload_len;   /* bytes in payload[] (result body / error text)*/
    uint8_t payload[];
} vx_result_header_t;

/* ------------------------------------------------------------------------- */
/* Error codes — negative returns from every vx_* entry point                */
/* ------------------------------------------------------------------------- */

typedef enum {
    VX_OK = 0,
    VX_ERR_INVALID_ARG = -1,
    VX_ERR_BAD_MAGIC = -2,
    VX_ERR_PAYLOAD_TOO_LARGE = -3,
    VX_ERR_NO_MEMORY = -4,
    VX_ERR_SHM = -5,          /* shm_open / mmap / ftruncate failed         */
    VX_ERR_RING_FULL = -6,    /* producer found no space                    */
    VX_ERR_RING_EMPTY = -7,   /* consumer found no record                   */
    VX_ERR_NAMESPACE = -8,    /* unshare()/clone() denied                   */
    VX_ERR_CGROUP = -9,       /* cgroup v2 node create / write failed       */
    VX_ERR_UIDMAP = -10,      /* uid_map / gid_map write denied             */
    VX_ERR_SPAWN = -11,       /* fork / exec failed                         */
    VX_ERR_TIMEOUT = -12,
    VX_ERR_UNSUPPORTED = -13  /* kernel lacks a required facility           */
} vx_status_t;

/* ------------------------------------------------------------------------- */
/* Compile-time layout assertions — these are the contract                   */
/* ------------------------------------------------------------------------- */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__cplusplus)
_Static_assert(sizeof(vx_task_header_t) == VX_TASK_HEADER_SIZE,
               "vx_task_header_t must be 93 packed bytes");
_Static_assert(sizeof(vx_result_header_t) == VX_RESULT_HEADER_SIZE,
               "vx_result_header_t must be 29 packed bytes");
_Static_assert(__builtin_offsetof(vx_task_header_t, task_id) == 4, "task_id @4");
_Static_assert(__builtin_offsetof(vx_task_header_t, tenant_id) == 12, "tenant_id @12");
_Static_assert(__builtin_offsetof(vx_task_header_t, engine) == 76, "engine @76");
_Static_assert(__builtin_offsetof(vx_task_header_t, memory_limit_mb) == 77, "memory_limit_mb @77");
_Static_assert(__builtin_offsetof(vx_task_header_t, cpu_quota_us) == 81, "cpu_quota_us @81");
_Static_assert(__builtin_offsetof(vx_task_header_t, payload_len) == 85, "payload_len @85");
#elif defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(vx_task_header_t) == VX_TASK_HEADER_SIZE,
              "vx_task_header_t must be 93 packed bytes");
static_assert(sizeof(vx_result_header_t) == VX_RESULT_HEADER_SIZE,
              "vx_result_header_t must be 29 packed bytes");
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WORKER_ABI_H */
