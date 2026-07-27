/* bench_ipc.c — throughput and latency of the shared-memory ring.
 *
 * Reports three numbers that matter for a task transport:
 *   1. single-threaded push+pop throughput (the uncontended ceiling)
 *   2. cross-thread producer/consumer throughput (the realistic case)
 *   3. per-operation latency percentiles (the tail is what shows up in an SLA)
 */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vx_error.h"
#include "vx_ipc.h"
#include "vx_log.h"

#define BENCH_RING "vxbench"
#define ITERS 2000000u
#define LAT_SAMPLES 200000u
#define PAYLOAD 64u

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

typedef struct {
    vx_ring_t *ring;
    uint32_t count;
    atomic_int *go;
} thread_arg_t;

static void *consumer_main(void *arg) {
    thread_arg_t *ta = (thread_arg_t *)arg;
    unsigned char buf[PAYLOAD];
    uint32_t got = 0;
    while (!atomic_load(ta->go)) {}
    while (got < ta->count) {
        uint32_t len = 0;
        if (vx_ring_pop(ta->ring, buf, sizeof(buf), &len) == VX_OK) got++;
    }
    return NULL;
}

int main(void) {
    unsigned char payload[PAYLOAD];
    memset(payload, 0xAB, sizeof(payload));

    printf("ring benchmark: %u iterations, %u-byte payloads\n", ITERS, PAYLOAD);

    /* ---------------------------------------------------------------- */
    /* 1. Uncontended push+pop in one thread                            */
    /* ---------------------------------------------------------------- */
    vx_ring_unlink(BENCH_RING);
    vx_ring_t *r = NULL;
    if (vx_ring_create(&r, BENCH_RING, 1024, PAYLOAD) != VX_OK) {
        fprintf(stderr, "ring create failed\n");
        return 1;
    }

    unsigned char out[PAYLOAD];
    uint32_t len = 0;
    uint64_t t0 = vx_now_us();
    for (uint32_t i = 0; i < ITERS; i++) {
        if (vx_ring_push(r, payload, PAYLOAD) != VX_OK) {
            fprintf(stderr, "unexpected full ring at %u\n", i);
            return 1;
        }
        if (vx_ring_pop(r, out, sizeof(out), &len) != VX_OK) {
            fprintf(stderr, "unexpected empty ring at %u\n", i);
            return 1;
        }
    }
    uint64_t elapsed = vx_now_us() - t0;
    double ops = (double)ITERS / ((double)elapsed / 1e6);
    printf("\n  same-thread push+pop : %.2f M round-trips/s  (%.0f ns per round-trip)\n",
           ops / 1e6, (double)elapsed * 1000.0 / (double)ITERS);
    printf("  throughput           : %.2f GiB/s payload\n",
           ((double)ITERS * PAYLOAD * 2.0) / ((double)elapsed / 1e6) / (1024.0 * 1024.0 * 1024.0));

    /* ---------------------------------------------------------------- */
    /* 2. Latency distribution of a single push+pop                     */
    /* ---------------------------------------------------------------- */
    uint64_t *samples = malloc((size_t)LAT_SAMPLES * sizeof(*samples));
    if (samples == NULL) return 1;
    for (uint32_t i = 0; i < LAT_SAMPLES; i++) {
        uint64_t s = vx_now_us();
        vx_ring_push(r, payload, PAYLOAD);
        vx_ring_pop(r, out, sizeof(out), &len);
        samples[i] = vx_now_us() - s;
    }
    qsort(samples, LAT_SAMPLES, sizeof(*samples), cmp_u64);
    printf("\n  latency (us, %u samples): p50=%llu p90=%llu p99=%llu p99.9=%llu max=%llu\n",
           LAT_SAMPLES, (unsigned long long)samples[LAT_SAMPLES / 2],
           (unsigned long long)samples[LAT_SAMPLES * 90 / 100],
           (unsigned long long)samples[LAT_SAMPLES * 99 / 100],
           (unsigned long long)samples[LAT_SAMPLES * 999 / 1000],
           (unsigned long long)samples[LAT_SAMPLES - 1]);
    printf("  (clock granularity is 1us, so a p50 of 0 means sub-microsecond)\n");
    free(samples);
    vx_ring_close(r);
    vx_ring_unlink(BENCH_RING);

    /* ---------------------------------------------------------------- */
    /* 3. Producer thread -> consumer thread                            */
    /* ---------------------------------------------------------------- */
    vx_ring_t *r2 = NULL;
    if (vx_ring_create(&r2, BENCH_RING, 4096, PAYLOAD) != VX_OK) return 1;

    atomic_int go;
    atomic_init(&go, 0);
    thread_arg_t ta = {.ring = r2, .count = ITERS, .go = &go};
    pthread_t consumer;
    pthread_create(&consumer, NULL, consumer_main, &ta);

    atomic_store(&go, 1);
    t0 = vx_now_us();
    for (uint32_t i = 0; i < ITERS; i++) {
        while (vx_ring_push(r2, payload, PAYLOAD) == VX_ERR_RING_FULL) {}
    }
    pthread_join(consumer, NULL);
    elapsed = vx_now_us() - t0;
    ops = (double)ITERS / ((double)elapsed / 1e6);

    vx_ring_stats_t stats;
    vx_ring_stats(r2, &stats);
    printf("\n  1 producer -> 1 consumer thread: %.2f M records/s (%.0f ns per record)\n",
           ops / 1e6, (double)elapsed * 1000.0 / (double)ITERS);
    printf("  full-ring stalls: %llu of %u pushes (%.2f%%)\n",
           (unsigned long long)stats.push_full, ITERS,
           100.0 * (double)stats.push_full / (double)ITERS);

    vx_ring_close(r2);
    vx_ring_unlink(BENCH_RING);
    printf("\n  no syscalls on either hot path: shm_open/mmap happen once at setup.\n");
    return 0;
}
