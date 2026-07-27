/* vx_ipc.c — lock-free SPMC shared-memory ring buffer.
 *
 * See vx_ipc.h for the sequence-number invariants.  The short version: each
 * slot carries a monotonically increasing generation counter, and the only
 * synchronising operations are one release-store by the producer, one
 * acquire-load plus one CAS by each consumer, and one release-store to recycle.
 * There is no mutex, no futex, and no syscall on either hot path. */
#include "vx_ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"
#include "vx_task.h"

/* ------------------------------------------------------------------------- */
/* Shared-memory layout                                                      */
/* ------------------------------------------------------------------------- */

/* Exactly one cache line, so a slot's control word never shares a line with
 * its neighbour's — false sharing between a producer and N consumers is the
 * single biggest throughput killer in a ring like this.
 *
 * `len` is atomic even though it is only ever meaningful to the one consumer
 * that owns the slot.  A consumer reads it speculatively *before* winning the
 * claim CAS, in order to reject an undersized destination buffer without
 * consuming the record; by then another consumer may already have taken the slot
 * and the producer may be refilling it.  As a plain uint32_t that concurrent
 * read/write pair is a data race — undefined behaviour, and a genuinely torn
 * read on a weakly-ordered target.  Relaxed atomics make the speculative read
 * well-defined; it is still allowed to be stale, which is why the value is
 * re-read and re-checked after the CAS succeeds. */
typedef struct {
    _Alignas(VX_CACHELINE) atomic_uint_least64_t seq;
    atomic_uint_least32_t len;
    uint32_t reserved;
    unsigned char pad[VX_CACHELINE - 16];
} vx_slot_hdr_t;

_Static_assert(sizeof(vx_slot_hdr_t) == VX_CACHELINE, "slot header must be one cache line");

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t slot_count; /* power of two                                    */
    uint32_t slot_bytes;
    uint64_t slot_stride;
    uint64_t map_bytes;
    uint64_t data_off;

    /* Producer cursor — its own line. */
    _Alignas(VX_CACHELINE) atomic_uint_least64_t write_pos;

    /* Consumer cursor — its own line; this is the one that gets CAS-hammered. */
    _Alignas(VX_CACHELINE) atomic_uint_least64_t read_pos;

    /* Cold statistics — off the hot lines entirely. */
    _Alignas(VX_CACHELINE) atomic_uint_least64_t produced;
    atomic_uint_least64_t consumed;
    atomic_uint_least64_t push_full;
} vx_ring_shared_t;

struct vx_ring {
    vx_ring_shared_t *sh;
    unsigned char *base;
    size_t map_bytes;
    int fd;
    bool owner;
    bool read_only;
    char name[VX_RING_NAME_MAX];
};

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static uint64_t align_up(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static uint32_t next_pow2(uint32_t v) {
    if (v == 0) return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

/* shm names live in a flat global namespace, so reject anything that could
 * escape it or collide with another tenant's object. */
static vx_status_t shm_path(const char *name, char *out, size_t out_len) {
    if (name == NULL || *name == '\0') return VX_ERR_INVALID_ARG;
    size_t n = strlen(name);
    if (n + 8 >= out_len || n >= VX_RING_NAME_MAX) return VX_ERR_INVALID_ARG;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        if (!ok) return VX_ERR_INVALID_ARG;
    }
    snprintf(out, out_len, "/vxring.%s", name);
    return VX_OK;
}

static vx_slot_hdr_t *slot_at(const struct vx_ring *r, uint64_t pos) {
    uint32_t idx = (uint32_t)(pos & (r->sh->slot_count - 1)); /* power-of-two mask */
    return (vx_slot_hdr_t *)(r->base + r->sh->data_off + (uint64_t)idx * r->sh->slot_stride);
}

static unsigned char *slot_data(const struct vx_ring *r, vx_slot_hdr_t *hdr) {
    (void)r;
    return (unsigned char *)hdr + sizeof(vx_slot_hdr_t);
}

/* ------------------------------------------------------------------------- */
/* Create / open / close                                                     */
/* ------------------------------------------------------------------------- */

vx_status_t vx_ring_create(vx_ring_t **out, const char *name, uint32_t slot_count,
                           uint32_t slot_bytes) {
    if (out == NULL) return VX_ERR_INVALID_ARG;
    *out = NULL;

    if (slot_count == 0) slot_count = VX_RING_SLOTS_DEFAULT;
    if (slot_bytes == 0) slot_bytes = VX_RING_SLOT_BYTES_DEFAULT;
    slot_count = next_pow2(slot_count);
    if (slot_bytes > VX_MAX_PAYLOAD_LEN) return VX_ERR_PAYLOAD_TOO_LARGE;

    char path[VX_RING_NAME_MAX + 16];
    vx_status_t st = shm_path(name, path, sizeof(path));
    if (st != VX_OK) return st;

    uint64_t stride = align_up(sizeof(vx_slot_hdr_t) + slot_bytes, VX_CACHELINE);
    uint64_t data_off = align_up(sizeof(vx_ring_shared_t), (uint64_t)sysconf(_SC_PAGESIZE));
    uint64_t map_bytes = align_up(data_off + stride * slot_count, (uint64_t)sysconf(_SC_PAGESIZE));

    struct vx_ring *r = calloc(1, sizeof(*r));
    if (r == NULL) return VX_ERR_NO_MEMORY;

    /* O_EXCL then unlink-and-retry: a stale object from a crashed run must not
     * be silently reused, because its slot geometry may differ. */
    int fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 && errno == EEXIST) {
        shm_unlink(path);
        fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    }
    if (fd < 0) {
        VX_ERROR("shm_open(%s) failed: %s", path, strerror(errno));
        free(r);
        return VX_ERR_SHM;
    }
    if (ftruncate(fd, (off_t)map_bytes) != 0) {
        VX_ERROR("ftruncate(%llu) failed: %s", (unsigned long long)map_bytes, strerror(errno));
        close(fd);
        shm_unlink(path);
        free(r);
        return VX_ERR_SHM;
    }

    void *mem = mmap(NULL, map_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        VX_ERROR("mmap(%llu) failed: %s", (unsigned long long)map_bytes, strerror(errno));
        close(fd);
        shm_unlink(path);
        free(r);
        return VX_ERR_SHM;
    }

    vx_ring_shared_t *sh = (vx_ring_shared_t *)mem;
    memset(sh, 0, sizeof(*sh));
    sh->magic = VX_RING_MAGIC;
    sh->version = VX_ABI_VERSION;
    sh->slot_count = slot_count;
    sh->slot_bytes = slot_bytes;
    sh->slot_stride = stride;
    sh->map_bytes = map_bytes;
    sh->data_off = data_off;
    atomic_init(&sh->write_pos, 0);
    atomic_init(&sh->read_pos, 0);
    atomic_init(&sh->produced, 0);
    atomic_init(&sh->consumed, 0);
    atomic_init(&sh->push_full, 0);

    r->sh = sh;
    r->base = (unsigned char *)mem;
    r->map_bytes = map_bytes;
    r->fd = fd;
    r->owner = true;
    r->read_only = false;
    snprintf(r->name, sizeof(r->name), "%s", name);

    /* Seed the generation counters: slot i starts at generation i, which is
     * exactly the "free for the producer at cursor i" state. */
    for (uint32_t i = 0; i < slot_count; i++) {
        vx_slot_hdr_t *slot = slot_at(r, i);
        atomic_init(&slot->seq, i);
        atomic_init(&slot->len, 0);
        slot->reserved = 0;
    }

    VX_DEBUG("ring %s created: %u slots x %u bytes, %llu bytes mapped", path, slot_count,
             slot_bytes, (unsigned long long)map_bytes);
    *out = r;
    return VX_OK;
}

vx_status_t vx_ring_open(vx_ring_t **out, const char *name, bool read_only) {
    if (out == NULL) return VX_ERR_INVALID_ARG;
    *out = NULL;

    char path[VX_RING_NAME_MAX + 16];
    vx_status_t st = shm_path(name, path, sizeof(path));
    if (st != VX_OK) return st;

    int fd = shm_open(path, read_only ? O_RDONLY : O_RDWR, 0600);
    if (fd < 0) {
        VX_DEBUG("shm_open(%s) for attach failed: %s", path, strerror(errno));
        return VX_ERR_SHM;
    }

    /* Two-step map: read the header to learn the real geometry, then remap the
     * full object.  Trusting a caller-supplied size here would be a way to map
     * past the end of the object. */
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    void *probe = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
    if (probe == MAP_FAILED) {
        close(fd);
        return VX_ERR_SHM;
    }
    vx_ring_shared_t hdr;
    memcpy(&hdr, probe, sizeof(hdr));
    munmap(probe, page);

    if (hdr.magic != VX_RING_MAGIC || hdr.version != VX_ABI_VERSION) {
        VX_ERROR("ring %s has magic 0x%08x version %u (want 0x%08x/%u)", path, hdr.magic,
                 hdr.version, VX_RING_MAGIC, VX_ABI_VERSION);
        close(fd);
        return VX_ERR_BAD_MAGIC;
    }
    if (hdr.slot_count == 0 || (hdr.slot_count & (hdr.slot_count - 1)) != 0 || hdr.map_bytes == 0) {
        close(fd);
        return VX_ERR_SHM;
    }

    int prot = read_only ? PROT_READ : (PROT_READ | PROT_WRITE);
    void *mem = mmap(NULL, hdr.map_bytes, prot, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        close(fd);
        return VX_ERR_SHM;
    }

    struct vx_ring *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        munmap(mem, hdr.map_bytes);
        close(fd);
        return VX_ERR_NO_MEMORY;
    }
    r->sh = (vx_ring_shared_t *)mem;
    r->base = (unsigned char *)mem;
    r->map_bytes = hdr.map_bytes;
    r->fd = fd;
    r->owner = false;
    r->read_only = read_only;
    snprintf(r->name, sizeof(r->name), "%s", name);

    *out = r;
    return VX_OK;
}

void vx_ring_close(vx_ring_t *r) {
    if (r == NULL) return;
    if (r->base != NULL) munmap(r->base, r->map_bytes);
    if (r->fd >= 0) close(r->fd);
    free(r);
}

vx_status_t vx_ring_unlink(const char *name) {
    char path[VX_RING_NAME_MAX + 16];
    vx_status_t st = shm_path(name, path, sizeof(path));
    if (st != VX_OK) return st;
    if (shm_unlink(path) != 0 && errno != ENOENT) return VX_ERR_SHM;
    return VX_OK;
}

/* ------------------------------------------------------------------------- */
/* Producer                                                                  */
/* ------------------------------------------------------------------------- */

vx_status_t vx_ring_push(vx_ring_t *r, const void *buf, uint32_t len) {
    if (r == NULL || buf == NULL) return VX_ERR_INVALID_ARG;
    if (r->read_only) return VX_ERR_INVALID_ARG;
    if (len == 0) return VX_ERR_INVALID_ARG;
    if (len > r->sh->slot_bytes) return VX_ERR_PAYLOAD_TOO_LARGE;

    vx_ring_shared_t *sh = r->sh;

    /* Single producer, so the cursor needs no CAS — a relaxed load is correct
     * because nobody else ever writes write_pos. */
    uint64_t pos = atomic_load_explicit(&sh->write_pos, memory_order_relaxed);
    vx_slot_hdr_t *slot = slot_at(r, pos);

    /* Acquire pairs with the consumer's release-store when it recycled this
     * slot, so everything the consumer did is visible before we overwrite. */
    uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);
    if (seq != pos) {
        atomic_fetch_add_explicit(&sh->push_full, 1, memory_order_relaxed);
        return VX_ERR_RING_FULL;
    }

    memcpy(slot_data(r, slot), buf, len);
    atomic_store_explicit(&slot->len, len, memory_order_relaxed);

    /* Release-store publishes the payload: any consumer that observes
     * seq == pos+1 with an acquire-load is guaranteed to see both the memcpy and
     * the length, even though the length store itself is relaxed. */
    atomic_store_explicit(&slot->seq, pos + 1, memory_order_release);
    atomic_store_explicit(&sh->write_pos, pos + 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&sh->produced, 1, memory_order_relaxed);
    return VX_OK;
}

vx_status_t vx_ring_push_task(vx_ring_t *r, const vx_task_header_t *hdr) {
    if (r == NULL || hdr == NULL) return VX_ERR_INVALID_ARG;
    if (hdr->magic != VX_MAGIC_HEADER) return VX_ERR_BAD_MAGIC;
    size_t wire = vx_task_wire_len(hdr);
    if (wire > UINT32_MAX) return VX_ERR_PAYLOAD_TOO_LARGE;
    return vx_ring_push(r, hdr, (uint32_t)wire);
}

/* ------------------------------------------------------------------------- */
/* Consumer                                                                  */
/* ------------------------------------------------------------------------- */

vx_status_t vx_ring_pop(vx_ring_t *r, void *buf, uint32_t cap, uint32_t *out_len) {
    if (r == NULL || buf == NULL || out_len == NULL) return VX_ERR_INVALID_ARG;
    *out_len = 0;

    vx_ring_shared_t *sh = r->sh;

    for (;;) {
        uint64_t pos = atomic_load_explicit(&sh->read_pos, memory_order_relaxed);
        vx_slot_hdr_t *slot = slot_at(r, pos);
        uint64_t seq = atomic_load_explicit(&slot->seq, memory_order_acquire);

        if (seq == pos + 1) {
            /* A record is published here.  This speculative read may be stale —
             * a peer can claim the slot and the producer refill it between here
             * and the CAS below — but it lets the common case reject an
             * undersized destination without consuming the record. */
            uint32_t len = (uint32_t)atomic_load_explicit(&slot->len, memory_order_relaxed);
            if (len > cap) return VX_ERR_INVALID_ARG;

            if (!atomic_compare_exchange_weak_explicit(
                    &sh->read_pos, &pos, pos + 1, memory_order_acq_rel, memory_order_relaxed)) {
                continue; /* another consumer claimed it; re-read the cursor */
            }

            /* We now own the slot exclusively until we republish its sequence:
             * the producer cannot advance into it, and no other consumer can
             * have claimed this generation.  So this re-read is authoritative. */
            len = (uint32_t)atomic_load_explicit(&slot->len, memory_order_relaxed);
            if (len > cap) {
                /* Only reachable if the pre-check raced; recycle so the ring
                 * cannot wedge, and report the undersized buffer. */
                atomic_store_explicit(&slot->seq, pos + sh->slot_count, memory_order_release);
                return VX_ERR_INVALID_ARG;
            }
            memcpy(buf, slot_data(r, slot), len);

            /* Recycle one generation forward: the slot becomes free for the
             * producer once its cursor reaches pos + slot_count. */
            atomic_store_explicit(&slot->seq, pos + sh->slot_count, memory_order_release);
            atomic_fetch_add_explicit(&sh->consumed, 1, memory_order_relaxed);
            *out_len = len;
            return VX_OK;
        }

        if (seq < pos + 1) return VX_ERR_RING_EMPTY; /* producer has not published */

        /* seq > pos + 1 means our read_pos load was stale: another consumer has
         * already advanced past this generation.  Retry with a fresh cursor. */
    }
}

vx_status_t vx_ring_pop_task(vx_ring_t *r, void *buf, uint32_t cap, const vx_task_header_t **out) {
    if (out == NULL) return VX_ERR_INVALID_ARG;
    *out = NULL;
    uint32_t len = 0;
    vx_status_t st = vx_ring_pop(r, buf, cap, &len);
    if (st != VX_OK) return st;
    return vx_task_decode(buf, len, out);
}

/* ------------------------------------------------------------------------- */
/* Introspection                                                             */
/* ------------------------------------------------------------------------- */

void vx_ring_stats(const vx_ring_t *r, vx_ring_stats_t *out) {
    if (r == NULL || out == NULL) return;
    memset(out, 0, sizeof(*out));
    const vx_ring_shared_t *sh = r->sh;
    uint64_t produced = atomic_load_explicit(&sh->produced, memory_order_relaxed);
    uint64_t consumed = atomic_load_explicit(&sh->consumed, memory_order_relaxed);
    out->slot_count = sh->slot_count;
    out->slot_bytes = sh->slot_bytes;
    out->produced = produced;
    out->consumed = consumed;
    out->depth = produced > consumed ? produced - consumed : 0;
    out->push_full = atomic_load_explicit(&sh->push_full, memory_order_relaxed);
    out->map_bytes = sh->map_bytes;
    out->lock_free = atomic_is_lock_free(&sh->write_pos);
}

uint64_t vx_ring_depth(const vx_ring_t *r) {
    if (r == NULL) return 0;
    uint64_t w = atomic_load_explicit(&r->sh->write_pos, memory_order_relaxed);
    uint64_t rd = atomic_load_explicit(&r->sh->read_pos, memory_order_relaxed);
    return w > rd ? w - rd : 0;
}
