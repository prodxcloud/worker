/* hog.c — deterministic memory hog used by the sandbox smoke test.
 *
 * Two hazards make a naive hog useless as an OOM fixture:
 *   1. an untouched malloc is never charged to a memory cgroup, so lazy
 *      allocation never trips the limit; and
 *   2. write-only stores are dead code — at -O2 the compiler deletes them and
 *      the backing malloc with them, so the test allocates nothing at all.
 *
 * Holding every block live and summing the pages into a volatile sink defeats
 * both, at any optimisation level. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile unsigned long sink;

int main(int argc, char **argv) {
    long mib = argc > 1 ? strtol(argv[1], NULL, 10) : 256;
    long page = sysconf(_SC_PAGESIZE);
    if (mib <= 0) {
        fprintf(stderr, "usage: hog <MiB>\n");
        return 2;
    }

    unsigned char **blocks = malloc((size_t)mib * sizeof(*blocks));
    if (blocks == NULL) return 3;

    for (long i = 0; i < mib; i++) {
        blocks[i] = malloc(1024 * 1024);
        if (blocks[i] == NULL) {
            printf("malloc failed after %ld MiB\n", i);
            return 3;
        }
        for (long off = 0; off < 1024 * 1024; off += page)
            blocks[i][off] = (unsigned char)(i + off);
        if (i % 32 == 0) {
            printf("touched %ld MiB\n", i);
            fflush(stdout);
        }
    }

    unsigned long sum = 0;
    for (long i = 0; i < mib; i++)
        for (long off = 0; off < 1024 * 1024; off += page) sum += blocks[i][off];
    sink = sum;

    printf("allocated and read back %ld MiB without being killed (checksum %lu)\n", mib, sink);
    return 0;
}
