/* vx_ipc.h — lock-free shared-memory ring buffer (SPMC).
 *
 * Transport between the host vxnode runtime (single producer) and one or more
 * guest engines (multiple consumers).  Backed by POSIX shm_open + mmap, so a
 * payload crosses the process boundary with exactly one memcpy in and one out —
 * no sockets, no serialisation hop, no kernel copy.
 *
 * Algorithm: bounded slot ring with a per-slot sequence number (Vyukov).  A
 * slot's sequence encodes its generation, which makes claim/publish a single
 * release-store and lets many consumers race on one CAS without a lock and
 * without ABA.  Correctness rests on three invariants:
 *
 *   seq == pos      -> slot is free for the producer at cursor pos
 *   seq == pos + 1   -> slot holds a published record for the consumer at pos
 *   seq == pos + N   -> slot has been drained and recycled one generation on
 *
 * A consumer that wins the CAS owns the slot exclusively until it republishes
 * the sequence, so the producer can never overwrite a record being read.
 *
 * All cursors are monotonic 64-bit counters; they are never reduced modulo the
 * slot count, so wrap-around needs no special case. */
#ifndef VX_IPC_H
#define VX_IPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VX_RING_MAGIC 0x58525831u /* 'V','R','X', v1 */
#define VX_RING_NAME_MAX 96
#define VX_RING_SLOTS_DEFAULT 1024u
#define VX_RING_SLOT_BYTES_DEFAULT 4096u
#define VX_CACHELINE 64u

typedef struct vx_ring vx_ring_t; /* opaque per-process handle */

typedef struct {
    uint32_t slot_count;   /* rounded up to a power of two                 */
    uint32_t slot_bytes;   /* usable payload bytes per slot                */
    uint64_t produced;     /* records pushed since creation                */
    uint64_t consumed;     /* records popped since creation                */
    uint64_t depth;        /* produced - consumed                          */
    uint64_t push_full;    /* pushes rejected because the ring was full    */
    uint64_t map_bytes;    /* size of the shared mapping                   */
    bool lock_free;        /* atomics on this platform are truly lock-free */
} vx_ring_stats_t;

/* Create (or truncate) a ring.  slot_count is rounded up to a power of two;
 * pass 0 for the defaults.  The shm object is named "/vxring.<name>". */
vx_status_t vx_ring_create(vx_ring_t **out, const char *name, uint32_t slot_count,
                           uint32_t slot_bytes);

/* Attach to a ring another process created. */
vx_status_t vx_ring_open(vx_ring_t **out, const char *name, bool read_only);

/* Producer side.  Returns VX_ERR_RING_FULL without blocking. */
vx_status_t vx_ring_push(vx_ring_t *r, const void *buf, uint32_t len);

/* Consumer side.  Returns VX_ERR_RING_EMPTY without blocking.  Safe to call
 * concurrently from any number of threads or processes. */
vx_status_t vx_ring_pop(vx_ring_t *r, void *buf, uint32_t cap, uint32_t *out_len);

/* Convenience: push a complete task header + its flexible payload. */
vx_status_t vx_ring_push_task(vx_ring_t *r, const vx_task_header_t *hdr);

/* Convenience: pop into a caller buffer and validate it as a task header.
 * On success *out points into buf. */
vx_status_t vx_ring_pop_task(vx_ring_t *r, void *buf, uint32_t cap,
                             const vx_task_header_t **out);

void vx_ring_stats(const vx_ring_t *r, vx_ring_stats_t *out);
uint64_t vx_ring_depth(const vx_ring_t *r);

/* Unmap and close this process's handle.  Does not remove the shm object. */
void vx_ring_close(vx_ring_t *r);

/* Remove the shm object so the name can be reused. */
vx_status_t vx_ring_unlink(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* VX_IPC_H */
