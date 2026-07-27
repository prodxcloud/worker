/* test_ipc.c — the shared-memory ring, including real concurrency.
 *
 * A ring like this passes single-threaded tests trivially; the bugs live under
 * contention and across process boundaries.  So this suite runs a genuine
 * 1-producer/4-consumer race over 200k records and asserts the two properties
 * that actually matter — no record is lost and none is delivered twice — using a
 * seen-bitmap rather than just comparing counters. */
#include <pthread.h>
#include <stdatomic.h>
#include <sys/wait.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_ipc.h"
#include "vx_task.h"
#include "vxtest.h"

#define RING_NAME "vxtest_ipc"
#define CONC_RING "vxtest_conc"
#define PROC_RING "vxtest_proc"

#define CONC_ITEMS 200000u
#define CONC_CONSUMERS 4

/* ------------------------------------------------------------------------- */
/* Concurrency fixture                                                       */
/* ------------------------------------------------------------------------- */

typedef struct {
    vx_ring_t *ring;
    atomic_uint *seen;      /* one counter per record id — detects duplicates */
    atomic_uint_least64_t *consumed;
    atomic_int *producer_done;
} consumer_ctx_t;

static void *consumer_thread(void *arg) {
    consumer_ctx_t *ctx = (consumer_ctx_t *)arg;
    unsigned char buf[64];

    for (;;) {
        uint32_t len = 0;
        vx_status_t st = vx_ring_pop(ctx->ring, buf, sizeof(buf), &len);
        if (st == VX_OK) {
            if (len == sizeof(uint32_t)) {
                uint32_t id;
                memcpy(&id, buf, sizeof(id));
                if (id < CONC_ITEMS) atomic_fetch_add(&ctx->seen[id], 1u);
            }
            atomic_fetch_add(ctx->consumed, 1);
            continue;
        }
        if (st == VX_ERR_RING_EMPTY) {
            /* Only stop once the producer has finished *and* the ring has
             * drained; stopping on the first empty read would race. */
            if (atomic_load(ctx->producer_done) &&
                vx_ring_depth(ctx->ring) == 0) {
                uint32_t l2 = 0;
                if (vx_ring_pop(ctx->ring, buf, sizeof(buf), &l2) == VX_ERR_RING_EMPTY) break;
            }
            continue;
        }
        break; /* unexpected error */
    }
    return NULL;
}

static int run_concurrency_case(void) {
    vx_ring_unlink(CONC_RING);
    vx_ring_t *ring = NULL;
    /* A small ring (256 slots) against 200k records forces the full/empty paths
     * and the generation wrap to be hit thousands of times. */
    if (vx_ring_create(&ring, CONC_RING, 256, 64) != VX_OK) {
        printf("    FAIL: could not create concurrency ring\n");
        return 1;
    }

    atomic_uint *seen = calloc(CONC_ITEMS, sizeof(*seen));
    if (seen == NULL) {
        vx_ring_close(ring);
        return 1;
    }
    for (uint32_t i = 0; i < CONC_ITEMS; i++) atomic_init(&seen[i], 0u);

    atomic_uint_least64_t consumed;
    atomic_int producer_done;
    atomic_init(&consumed, 0);
    atomic_init(&producer_done, 0);

    consumer_ctx_t ctx = {
        .ring = ring, .seen = seen, .consumed = &consumed, .producer_done = &producer_done};

    pthread_t tids[CONC_CONSUMERS];
    for (int i = 0; i < CONC_CONSUMERS; i++) pthread_create(&tids[i], NULL, consumer_thread, &ctx);

    uint64_t retries = 0;
    for (uint32_t i = 0; i < CONC_ITEMS; i++) {
        for (;;) {
            vx_status_t st = vx_ring_push(ring, &i, sizeof(i));
            if (st == VX_OK) break;
            if (st != VX_ERR_RING_FULL) {
                printf("    FAIL: push returned %s\n", vx_status_name(st));
                free(seen);
                vx_ring_close(ring);
                return 1;
            }
            retries++; /* ring full: spin until a consumer frees a slot */
        }
    }
    atomic_store(&producer_done, 1);
    for (int i = 0; i < CONC_CONSUMERS; i++) pthread_join(tids[i], NULL);

    int failures = 0;
    uint64_t total = atomic_load(&consumed);
    if (total != CONC_ITEMS) {
        printf("    FAIL: consumed %llu records, produced %u\n", (unsigned long long)total,
               CONC_ITEMS);
        failures++;
    }

    uint32_t missing = 0, duplicated = 0;
    for (uint32_t i = 0; i < CONC_ITEMS; i++) {
        unsigned c = atomic_load(&seen[i]);
        if (c == 0) missing++;
        else if (c > 1) duplicated++;
    }
    if (missing != 0) {
        printf("    FAIL: %u records were never delivered\n", missing);
        failures++;
    }
    if (duplicated != 0) {
        printf("    FAIL: %u records were delivered more than once\n", duplicated);
        failures++;
    }

    vx_ring_stats_t stats;
    vx_ring_stats(ring, &stats);
    printf("    %u records via %d consumers: produced=%llu consumed=%llu full_retries=%llu\n",
           CONC_ITEMS, CONC_CONSUMERS, (unsigned long long)stats.produced,
           (unsigned long long)stats.consumed, (unsigned long long)retries);
    if (stats.produced != CONC_ITEMS || stats.consumed != CONC_ITEMS) {
        printf("    FAIL: stats disagree with the observed totals\n");
        failures++;
    }
    if (retries == 0) {
        printf("    NOTE: the ring never filled, so the full path went untested\n");
    }

    free(seen);
    vx_ring_close(ring);
    vx_ring_unlink(CONC_RING);
    return failures;
}

/* ------------------------------------------------------------------------- */
/* Cross-process fixture                                                     */
/* ------------------------------------------------------------------------- */

#ifndef __SANITIZE_THREAD__
static int run_cross_process_case(void) {
    const uint32_t items = 5000;

    vx_ring_unlink(PROC_RING);
    vx_ring_t *ring = NULL;
    if (vx_ring_create(&ring, PROC_RING, 64, 64) != VX_OK) {
        printf("    FAIL: could not create cross-process ring\n");
        return 1;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        vx_ring_close(ring);
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        vx_ring_close(ring);
        return 1;
    }

    if (pid == 0) {
        /* Child: a completely separate address space attaching by name.  This is
         * the real host-runtime-to-guest-engine path. */
        close(pipefd[0]);
        vx_ring_close(ring);

        vx_ring_t *child = NULL;
        if (vx_ring_open(&child, PROC_RING, false) != VX_OK) _exit(2);

        uint64_t sum = 0;
        uint32_t got = 0;
        unsigned char buf[64];
        while (got < items) {
            uint32_t len = 0;
            vx_status_t st = vx_ring_pop(child, buf, sizeof(buf), &len);
            if (st == VX_OK && len == sizeof(uint32_t)) {
                uint32_t v;
                memcpy(&v, buf, sizeof(v));
                sum += v;
                got++;
            }
        }
        ssize_t w = write(pipefd[1], &sum, sizeof(sum));
        (void)w;
        close(pipefd[1]);
        vx_ring_close(child);
        _exit(0);
    }

    close(pipefd[1]);
    uint64_t expect = 0;
    for (uint32_t i = 0; i < items; i++) {
        expect += i;
        while (vx_ring_push(ring, &i, sizeof(i)) == VX_ERR_RING_FULL) {}
    }

    uint64_t got_sum = 0;
    ssize_t rn = read(pipefd[0], &got_sum, sizeof(got_sum));
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    int failures = 0;
    if (rn != (ssize_t)sizeof(got_sum)) {
        printf("    FAIL: child reported nothing (exit status %d)\n", status);
        failures++;
    } else if (got_sum != expect) {
        printf("    FAIL: child summed %llu, expected %llu\n", (unsigned long long)got_sum,
               (unsigned long long)expect);
        failures++;
    } else {
        printf("    %u records crossed the process boundary, checksum %llu matched\n", items,
               (unsigned long long)got_sum);
    }

    vx_ring_close(ring);
    vx_ring_unlink(PROC_RING);
    return failures;
}
#endif /* !__SANITIZE_THREAD__ */

/* ------------------------------------------------------------------------- */

int main(void) {
    VXT_BEGIN("shared-memory ring buffer");

    vx_ring_unlink(RING_NAME);

    VXT_CASE("create reports its geometry");
    vx_ring_t *r = NULL;
    VXT_EQ_INT(vx_ring_create(&r, RING_NAME, 8, 128), VX_OK, "create");
    if (r == NULL) {
        printf("  cannot continue without a ring\n");
        return 1;
    }
    vx_ring_stats_t s;
    vx_ring_stats(r, &s);
    VXT_EQ_INT(s.slot_count, 8, "slot_count");
    VXT_EQ_INT(s.slot_bytes, 128, "slot_bytes");
    VXT_CHECK(s.lock_free, "64-bit atomics must be lock-free for cross-process use");
    VXT_CHECK(s.map_bytes >= 8 * 128, "mapping covers the slots (%llu bytes)",
              (unsigned long long)s.map_bytes);

    VXT_CASE("a non-power-of-two slot count is rounded up");
    vx_ring_t *r2 = NULL;
    vx_ring_unlink("vxtest_pow2");
    VXT_EQ_INT(vx_ring_create(&r2, "vxtest_pow2", 100, 64), VX_OK, "create with 100 slots");
    if (r2 != NULL) {
        vx_ring_stats_t s2;
        vx_ring_stats(r2, &s2);
        VXT_EQ_INT(s2.slot_count, 128, "rounded slot_count");
        vx_ring_close(r2);
        vx_ring_unlink("vxtest_pow2");
    }

    VXT_CASE("push then pop returns the same bytes");
    unsigned char out[256];
    uint32_t len = 0;
    VXT_EQ_INT(vx_ring_push(r, "hello", 5), VX_OK, "push");
    VXT_EQ_INT(vx_ring_pop(r, out, sizeof(out), &len), VX_OK, "pop");
    VXT_EQ_INT(len, 5, "popped length");
    VXT_CHECK(memcmp(out, "hello", 5) == 0, "popped bytes");

    VXT_CASE("an empty ring reports empty rather than blocking");
    VXT_EQ_INT(vx_ring_pop(r, out, sizeof(out), &len), VX_ERR_RING_EMPTY, "pop on empty");
    VXT_EQ_INT(vx_ring_depth(r), 0, "depth");

    VXT_CASE("records come back in FIFO order");
    for (int i = 0; i < 5; i++) {
        char msg[16];
        int wn = snprintf(msg, sizeof(msg), "m%d", i);
        VXT_EQ_INT(vx_ring_push(r, msg, (uint32_t)wn), VX_OK, "push in order");
    }
    VXT_EQ_INT(vx_ring_depth(r), 5, "depth after 5 pushes");
    for (int i = 0; i < 5; i++) {
        char want[16];
        snprintf(want, sizeof(want), "m%d", i);
        VXT_EQ_INT(vx_ring_pop(r, out, sizeof(out), &len), VX_OK, "pop in order");
        VXT_CHECK(len == strlen(want) && memcmp(out, want, len) == 0, "FIFO position %d", i);
    }

    VXT_CASE("the ring reports full instead of overwriting");
    for (int i = 0; i < 8; i++) VXT_EQ_INT(vx_ring_push(r, "x", 1), VX_OK, "fill slot");
    VXT_EQ_INT(vx_ring_push(r, "x", 1), VX_ERR_RING_FULL, "push into a full ring");
    vx_ring_stats(r, &s);
    VXT_EQ_INT(s.push_full, 1, "push_full counter");
    /* Draining one slot must make exactly one more push succeed. */
    VXT_EQ_INT(vx_ring_pop(r, out, sizeof(out), &len), VX_OK, "drain one");
    VXT_EQ_INT(vx_ring_push(r, "y", 1), VX_OK, "push after draining one");
    VXT_EQ_INT(vx_ring_push(r, "z", 1), VX_ERR_RING_FULL, "full again");
    while (vx_ring_pop(r, out, sizeof(out), &len) == VX_OK) {}

    VXT_CASE("generation counters survive wrapping many times over");
    /* 8 slots, 400 records: the sequence numbers wrap 50 times. */
    for (int round = 0; round < 400; round++) {
        uint32_t v = (uint32_t)round;
        VXT_CHECK(vx_ring_push(r, &v, sizeof(v)) == VX_OK, "push round %d", round);
        uint32_t got = 0;
        VXT_CHECK(vx_ring_pop(r, out, sizeof(out), &len) == VX_OK, "pop round %d", round);
        memcpy(&got, out, sizeof(got));
        VXT_CHECK(got == v && len == sizeof(v), "round %d value", round);
    }

    VXT_CASE("oversized and empty pushes are rejected");
    VXT_EQ_INT(vx_ring_push(r, out, 129), VX_ERR_PAYLOAD_TOO_LARGE, "129 bytes into 128");
    VXT_EQ_INT(vx_ring_push(r, out, 0), VX_ERR_INVALID_ARG, "zero-length push");
    VXT_EQ_INT(vx_ring_push(r, NULL, 4), VX_ERR_INVALID_ARG, "NULL push");

    VXT_CASE("a too-small pop buffer fails without losing the record");
    VXT_EQ_INT(vx_ring_push(r, "0123456789", 10), VX_OK, "push 10 bytes");
    VXT_EQ_INT(vx_ring_pop(r, out, 4, &len), VX_ERR_INVALID_ARG, "pop into 4 bytes");
    VXT_EQ_INT(vx_ring_depth(r), 1, "record is still queued");
    VXT_EQ_INT(vx_ring_pop(r, out, sizeof(out), &len), VX_OK, "pop with room");
    VXT_EQ_INT(len, 10, "recovered length");
    VXT_CHECK(memcmp(out, "0123456789", 10) == 0, "recovered bytes");

    VXT_CASE("task frames travel through the ring intact");
    vx_ring_t *rt = NULL;
    vx_ring_unlink("vxtest_task");
    VXT_EQ_INT(vx_ring_create(&rt, "vxtest_task", 4, 512), VX_OK, "create task ring");
    if (rt != NULL) {
        unsigned char frame[VX_TASK_HEADER_SIZE + 32];
        long fn = vx_task_encode(frame, sizeof(frame), 4242, "tenant-x", ENGINE_IRON, 64, 25000,
                                 "payload!", 8);
        VXT_CHECK(fn > 0, "encode frame");
        VXT_EQ_INT(vx_ring_push_task(rt, (const vx_task_header_t *)frame), VX_OK, "push task");

        unsigned char rx[512];
        const vx_task_header_t *hdr = NULL;
        VXT_EQ_INT(vx_ring_pop_task(rt, rx, sizeof(rx), &hdr), VX_OK, "pop task");
        if (hdr != NULL) {
            VXT_EQ_INT(hdr->task_id, 4242, "task_id across the ring");
            VXT_EQ_INT(hdr->engine, ENGINE_IRON, "engine across the ring");
            VXT_CHECK(memcmp(hdr->payload, "payload!", 8) == 0, "payload across the ring");
        }
        vx_ring_close(rt);
        vx_ring_unlink("vxtest_task");
    }

    VXT_CASE("a second handle attaches to the same ring by name");
    vx_ring_t *attached = NULL;
    VXT_EQ_INT(vx_ring_open(&attached, RING_NAME, false), VX_OK, "open existing");
    if (attached != NULL) {
        VXT_EQ_INT(vx_ring_push(r, "shared", 6), VX_OK, "push on handle A");
        VXT_EQ_INT(vx_ring_pop(attached, out, sizeof(out), &len), VX_OK, "pop on handle B");
        VXT_CHECK(len == 6 && memcmp(out, "shared", 6) == 0, "bytes crossed handles");
        vx_ring_close(attached);
    }

    VXT_CASE("opening a nonexistent ring fails cleanly");
    vx_ring_t *missing = NULL;
    VXT_EQ_INT(vx_ring_open(&missing, "vxtest_does_not_exist", false), VX_ERR_SHM, "open missing");
    VXT_CHECK(missing == NULL, "handle stays NULL on failure");

    VXT_CASE("invalid ring names are rejected");
    vx_ring_t *bad = NULL;
    VXT_EQ_INT(vx_ring_create(&bad, "../escape", 4, 64), VX_ERR_INVALID_ARG, "path traversal");
    VXT_EQ_INT(vx_ring_create(&bad, "has/slash", 4, 64), VX_ERR_INVALID_ARG, "embedded slash");
    VXT_EQ_INT(vx_ring_create(&bad, "", 4, 64), VX_ERR_INVALID_ARG, "empty name");

    vx_ring_close(r);
    vx_ring_unlink(RING_NAME);

    VXT_CASE("1 producer / 4 consumers over 200k records loses and duplicates nothing");
    vxt_checks++;
    int conc_failures = run_concurrency_case();
    if (conc_failures != 0) vxt_failures++;

#ifdef __SANITIZE_THREAD__
    /* Skipped under TSan by design.  TSan instruments one process, so it cannot
     * observe the peer's loads and stores through the shared mapping — the case
     * would contribute no race coverage, and TSan aborts trying to place its
     * shadow in the forked child.  The threaded case above is what actually
     * exercises the ring's memory ordering, and it runs under TSan. */
    VXT_CASE("records cross a real process boundary via shm [skipped under TSan]");
#else
    VXT_CASE("records cross a real process boundary via shm");
    vxt_checks++;
    int proc_failures = run_cross_process_case();
    if (proc_failures != 0) vxt_failures++;
#endif

    VXT_END();
}
