/* vxtest.h — a 60-line test harness.
 *
 * Deliberately not a framework: this project has zero dependencies, and the
 * tests should not be the thing that introduces one.  Exit code 0 = pass,
 * 1 = fail, 77 = skipped (the automake convention, which run_tests.sh honours). */
#ifndef VXTEST_H
#define VXTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VX_SKIP_EXIT 77

static int vxt_checks = 0;
static int vxt_failures = 0;
static const char *vxt_current = "";

#define VXT_CASE(name)                                                                 \
    do {                                                                               \
        vxt_current = (name);                                                          \
        printf("  - %s\n", (name));                                                    \
    } while (0)

#define VXT_CHECK(cond, ...)                                                           \
    do {                                                                               \
        vxt_checks++;                                                                  \
        if (!(cond)) {                                                                 \
            vxt_failures++;                                                            \
            printf("    FAIL [%s:%d] in %s: ", __FILE__, __LINE__, vxt_current);        \
            printf(__VA_ARGS__);                                                       \
            printf("\n      expression: %s\n", #cond);                                 \
        }                                                                              \
    } while (0)

#define VXT_EQ_INT(got, want, label)                                                   \
    do {                                                                               \
        long long g_ = (long long)(got), w_ = (long long)(want);                        \
        VXT_CHECK(g_ == w_, "%s: got %lld, want %lld", (label), g_, w_);                \
    } while (0)

#define VXT_SKIP(...)                                                                  \
    do {                                                                               \
        printf("  SKIP: ");                                                            \
        printf(__VA_ARGS__);                                                           \
        printf("\n");                                                                  \
        return VX_SKIP_EXIT;                                                           \
    } while (0)

#define VXT_BEGIN(suite) printf("== %s\n", (suite))

#define VXT_END()                                                                      \
    do {                                                                               \
        if (vxt_failures == 0) {                                                       \
            printf("  PASS (%d checks)\n", vxt_checks);                                \
            return 0;                                                                  \
        }                                                                              \
        printf("  FAILED (%d/%d checks failed)\n", vxt_failures, vxt_checks);           \
        return 1;                                                                      \
    } while (0)

/* Several suites need real kernel privilege; say so rather than pretending. */
static inline int vxt_is_root(void) { return geteuid() == 0; }

#endif /* VXTEST_H */
