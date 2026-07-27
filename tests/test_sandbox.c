/* test_sandbox.c — the isolation guarantees, asserted from C.
 *
 * The suite re-execs itself with "--hog <MiB>" as the guest payload for the OOM
 * case, so it needs no helper binary on disk and cannot silently pass because a
 * fixture was missing.
 *
 * argv entries are mutable char arrays rather than cast string literals:
 * execvp() takes char *const *, and casting away const from a literal is
 * exactly the sort of thing -Wcast-qual exists to catch. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"
#include "vx_sandbox.h"
#include "vxtest.h"

/* Mutable argv strings. */
static char p_sh[] = "/bin/sh";
static char p_true[] = "/bin/true";
static char p_sleep[] = "/bin/sleep";
static char a_c[] = "-c";
static char a_30[] = "30";
static char a_2[] = "2";
static char a_hog[] = "--hog";
static char sc_exit42[] = "exit 42";
static char sc_pid1[] = "test $$ -eq 1";
static char sc_uid0[] = "test \"$(id -u)\" -eq 0";
static char sc_net[] = "n=$(grep -c ':' /proc/net/dev); test \"$n\" -eq 1 && "
                       "grep -q lo /proc/net/dev";
static char sc_proc[] = "test \"$(ls -d /proc/[0-9]* | wc -l)\" -lt 10";
static char sc_uts[] = "test \"$(hostname)\" = vxsandbox-test";
static char sc_forkbomb[] = "i=0; while [ $i -lt 200 ]; do (sleep 5) & i=$((i+1)); done; "
                            "echo spawned-all";
static char p_missing[] = "/nonexistent/vxworker/binary";

static char self_path[4096];
static char hog_mib[16];

/* Volatile sink: the sum below must be observably used, or the optimiser is
 * entitled to delete every store that feeds it — and then the malloc that backs
 * those stores.  At -O2 GCC does exactly that, which makes the OOM test pass
 * without allocating a single page. */
static volatile unsigned long g_hog_sink;

/* Fault in every page and read it back.
 *
 * Two separate hazards make a naive hog useless here:
 *   1. an untouched malloc is never charged to the memory cgroup, so lazy
 *      allocation never trips the limit; and
 *   2. write-only stores are dead code, so the allocation is optimised away.
 * Holding every block live and summing the pages afterwards defeats both. */
static int run_as_hog(long mib) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char **blocks = malloc((size_t)mib * sizeof(*blocks));
    if (blocks == NULL) return 3;

    for (long i = 0; i < mib; i++) {
        blocks[i] = malloc(1024 * 1024);
        if (blocks[i] == NULL) {
            free(blocks);
            return 3;
        }
        for (long off = 0; off < 1024 * 1024; off += page)
            blocks[i][off] = (unsigned char)(i + off);
    }

    unsigned long sum = 0;
    for (long i = 0; i < mib; i++)
        for (long off = 0; off < 1024 * 1024; off += page) sum += blocks[i][off];
    g_hog_sink = sum;

    for (long i = 0; i < mib; i++) free(blocks[i]);
    free(blocks);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--hog") == 0) return run_as_hog(strtol(argv[2], NULL, 10));

    VXT_BEGIN("namespace + cgroup sandbox");

    ssize_t sl = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (sl > 0)
        self_path[sl] = '\0';
    else
        snprintf(self_path, sizeof(self_path), "%s", argv[0]);

    vx_sandbox_caps_t caps;
    VXT_EQ_INT(vx_sandbox_probe(&caps), VX_OK, "probe");
    if (!caps.userns || !caps.pidns)
        VXT_SKIP("kernel denies CLONE_NEWUSER/CLONE_NEWPID (userns=%d pidns=%d)", (int)caps.userns,
                 (int)caps.pidns);
    if (!vxt_is_root()) VXT_SKIP("needs root to write uid_map and create cgroups");

    printf("    caps: userns=%d pidns=%d netns=%d cgroup2=%d cgroup.kill=%d pidfd=%d\n",
           (int)caps.userns, (int)caps.pidns, (int)caps.netns, (int)caps.cgroup_v2,
           (int)caps.cgroup_kill, (int)caps.pidfd);

    vx_sandbox_spec_t spec;
    vx_sandbox_t sb;
    vx_sandbox_result_t res;

    /* --------------------------------------------------------------------- */
    VXT_CASE("spec defaults enable every namespace");
    vx_sandbox_spec_init(&spec);
    VXT_CHECK(spec.new_user && spec.new_pid && spec.new_net && spec.new_ipc && spec.new_mount &&
                  spec.new_uts,
              "all namespaces default on");
    VXT_EQ_INT(spec.host_uid, 65534, "default host uid is unprivileged");
    VXT_CHECK(spec.memory_limit_mb > 0 && spec.cpu_quota_us > 0, "default limits are set");

    /* --------------------------------------------------------------------- */
    VXT_CASE("a successful guest reports COMPLETED with exit 0");
    char *argv_true[] = {p_true, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800001;
    spec.tenant_id = "test";
    spec.argv = argv_true;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn /bin/true");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.state, VX_STATE_COMPLETED, "state");
    VXT_EQ_INT(res.exit_code, 0, "exit code");
    VXT_CHECK(res.duration_us > 0, "duration was measured (%lluus)",
              (unsigned long long)res.duration_us);
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("a nonzero exit is FAILED and the code is preserved");
    char *argv_exit42[] = {p_sh, a_c, sc_exit42, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800002;
    spec.argv = argv_exit42;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.state, VX_STATE_FAILED, "state");
    VXT_EQ_INT(res.exit_code, 42, "exit code");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("the guest is PID 1 inside its pid namespace");
    char *argv_pid1[] = {p_sh, a_c, sc_pid1, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800003;
    spec.argv = argv_pid1;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.exit_code, 0, "$$ == 1 inside the sandbox");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("the guest is uid 0 inside its user namespace");
    char *argv_uid0[] = {p_sh, a_c, sc_uid0, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800004;
    spec.argv = argv_uid0;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.exit_code, 0, "id -u == 0 inside the sandbox");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("that same guest is unprivileged on the host");
    /* The whole security model in one assertion: read the kernel's own uid_map
     * for the live guest and confirm inside-0 maps to a non-root host uid. */
    char *argv_sleep2[] = {p_sleep, a_2, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800005;
    spec.host_uid = 65534;
    spec.host_gid = 65534;
    spec.argv = argv_sleep2;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn sleeper");
    if (sb.pid > 0) {
        char path[64];
        char line[128] = "";
        snprintf(path, sizeof(path), "/proc/%lld/uid_map", (long long)sb.pid);
        FILE *f = fopen(path, "re");
        if (f != NULL) {
            if (fgets(line, sizeof(line), f) == NULL) line[0] = '\0';
            fclose(f);
        }
        unsigned inner = 9999, outer = 9999, count = 0;
        VXT_CHECK(sscanf(line, "%u %u %u", &inner, &outer, &count) == 3, "parsed uid_map \"%s\"",
                  line);
        VXT_EQ_INT(inner, 0, "namespace uid 0 is mapped");
        VXT_EQ_INT(outer, 65534, "maps to host uid 65534");
        VXT_EQ_INT(count, 1, "exactly one uid is mapped");
        VXT_CHECK(outer != 0, "the host uid is NOT root — this is the isolation guarantee");

        snprintf(path, sizeof(path), "/proc/%lld/status", (long long)sb.pid);
        f = fopen(path, "re");
        long host_uid = -1;
        if (f != NULL) {
            char buf[256];
            while (fgets(buf, sizeof(buf), f) != NULL) {
                if (strncmp(buf, "Uid:", 4) == 0) {
                    host_uid = strtol(buf + 4, NULL, 10);
                    break;
                }
            }
            fclose(f);
        }
        VXT_EQ_INT(host_uid, 65534, "host-visible Uid of the guest");
    }
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait for sleeper");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    if (caps.netns) {
        VXT_CASE("the network namespace has no host interfaces but a working loopback");
        char *argv_net[] = {p_sh, a_c, sc_net, NULL};
        vx_sandbox_spec_init(&spec);
        spec.task_id = 800006;
        spec.argv = argv_net;
        VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
        VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
        VXT_EQ_INT(res.exit_code, 0, "only loopback is visible");
        vx_sandbox_destroy(&sb);
    }

    /* --------------------------------------------------------------------- */
    VXT_CASE("a fresh /proc reflects the new pid namespace");
    char *argv_proc[] = {p_sh, a_c, sc_proc, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800007;
    spec.argv = argv_proc;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.exit_code, 0, "fewer than 10 processes visible in /proc");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("a hostname set inside the UTS namespace does not leak out");
    char host_before[256] = "", host_after[256] = "";
    gethostname(host_before, sizeof(host_before) - 1);
    char *argv_uts[] = {p_sh, a_c, sc_uts, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800008;
    spec.hostname = "vxsandbox-test";
    spec.argv = argv_uts;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.exit_code, 0, "hostname applied inside");
    vx_sandbox_destroy(&sb);
    gethostname(host_after, sizeof(host_after) - 1);
    VXT_CHECK(strcmp(host_before, host_after) == 0, "host hostname unchanged (%s -> %s)",
              host_before, host_after);

    /* --------------------------------------------------------------------- */
    VXT_CASE("a wall-clock overrun is KILLED_TIMEOUT, not a hang");
    char *argv_sleep30[] = {p_sleep, a_30, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800009;
    spec.argv = argv_sleep30;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn sleep 30");
    unsigned long long t0 = vx_now_us();
    VXT_EQ_INT(vx_sandbox_wait(&sb, 400, &res), VX_OK, "wait with a 400ms deadline");
    unsigned long long elapsed = vx_now_us() - t0;
    VXT_EQ_INT(res.state, VX_STATE_KILLED_TIMEOUT, "state");
    VXT_CHECK(elapsed < 3000000ull, "returned in %lluus, well before the sleep ended", elapsed);
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("an explicit kill is reported as KILLED_SIGNAL");
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800010;
    spec.argv = argv_sleep30;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_kill(&sb, SIGKILL), VX_OK, "kill");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 5000, &res), VX_OK, "wait");
    VXT_EQ_INT(res.state, VX_STATE_KILLED_SIGNAL, "state");
    VXT_EQ_INT(res.term_signal, SIGKILL, "term signal");
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    if (caps.cgroup_v2 && caps.cgroup_memory) {
        char *argv_hog[] = {self_path, a_hog, hog_mib, NULL};

        VXT_CASE("breaching the memory limit is KILLED_OOM, and promptly");
        snprintf(hog_mib, sizeof(hog_mib), "256");
        vx_sandbox_spec_init(&spec);
        spec.task_id = 800011;
        spec.memory_limit_mb = 16;
        spec.argv = argv_hog;
        VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn a 256 MiB hog under a 16 MiB cap");
        VXT_EQ_INT(vx_sandbox_wait(&sb, 30000, &res), VX_OK, "wait");
        VXT_EQ_INT(res.state, VX_STATE_KILLED_OOM, "state");
        VXT_CHECK(res.usage.oom_kill > 0, "memory.events oom_kill is %llu",
                  (unsigned long long)res.usage.oom_kill);
        VXT_CHECK(res.usage.memory_peak <= 20ull * 1024 * 1024,
                  "peak was %lluB, within the 16 MiB cap plus slack",
                  (unsigned long long)res.usage.memory_peak);
        /* Prompt: with memory.high disabled this is tens of milliseconds, not
         * the multi-second thrash that throttling produces. */
        VXT_CHECK(res.duration_us < 5000000ull, "killed in %lluus (not a thrash)",
                  (unsigned long long)res.duration_us);
        vx_sandbox_destroy(&sb);

        VXT_CASE("a task within its limit is untouched");
        snprintf(hog_mib, sizeof(hog_mib), "8");
        vx_sandbox_spec_init(&spec);
        spec.task_id = 800012;
        spec.memory_limit_mb = 128;
        spec.argv = argv_hog;
        VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn an 8 MiB hog under a 128 MiB cap");
        VXT_EQ_INT(vx_sandbox_wait(&sb, 30000, &res), VX_OK, "wait");
        VXT_EQ_INT(res.state, VX_STATE_COMPLETED, "state");
        VXT_EQ_INT(res.usage.oom_kill, 0, "nothing was OOM-killed");
        vx_sandbox_destroy(&sb);
    }

    /* --------------------------------------------------------------------- */
    VXT_CASE("a pids cap stops a fork bomb");
    char *argv_fork[] = {p_sh, a_c, sc_forkbomb, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800013;
    spec.pids_max = 8;
    spec.timeout_ms = 5000;
    spec.argv = argv_fork;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn");
    VXT_EQ_INT(vx_sandbox_wait(&sb, 8000, &res), VX_OK, "wait");
    VXT_CHECK(res.state != VX_STATE_COMPLETED || res.usage.pids_current <= 16,
              "the fork bomb was contained (state=%s pids=%llu)", vx_state_str(res.state),
              (unsigned long long)res.usage.pids_current);
    vx_sandbox_destroy(&sb);

    /* --------------------------------------------------------------------- */
    VXT_CASE("a missing binary fails fast instead of hanging");
    char *argv_missing[] = {p_missing, NULL};
    vx_sandbox_spec_init(&spec);
    spec.task_id = 800014;
    spec.argv = argv_missing;
    unsigned long long t1 = vx_now_us();
    vx_status_t st = vx_sandbox_spawn(&sb, &spec);
    unsigned long long spawn_us = vx_now_us() - t1;
    VXT_EQ_INT(st, VX_ERR_SPAWN, "spawn reports VX_ERR_SPAWN");
    VXT_CHECK(spawn_us < 2000000ull, "reported in %lluus", spawn_us);

    VXT_CASE("bad arguments are rejected");
    VXT_EQ_INT(vx_sandbox_spawn(NULL, &spec), VX_ERR_INVALID_ARG, "NULL sandbox");
    VXT_EQ_INT(vx_sandbox_spawn(&sb, NULL), VX_ERR_INVALID_ARG, "NULL spec");
    vx_sandbox_spec_init(&spec);
    spec.argv = NULL;
    VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_ERR_INVALID_ARG, "NULL argv");

    VXT_CASE("no cgroup nodes are left behind");
    /* Every case above ran destroy(); if any leaked, its directory survives. */
    int leaked = 0;
    for (unsigned long long id = 800001; id <= 800014; id++) {
        char path[256];
        snprintf(path, sizeof(path), "/sys/fs/cgroup/vxworker_%llu", id);
        if (access(path, F_OK) == 0) {
            printf("    leaked: %s\n", path);
            leaked++;
        }
    }
    VXT_EQ_INT(leaked, 0, "leaked cgroup nodes");

    VXT_END();
}
