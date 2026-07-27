/* test_cgroup.c — cgroup v2 control files are written and read back correctly.
 *
 * Asserts against the actual kernel control files rather than trusting the
 * setter's return value: a write that succeeds can still land the wrong value
 * (unit confusion between bytes and MiB is the classic one). */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "vx_cgroup.h"
#include "vx_error.h"
#include "vxtest.h"

/* Read a control file's first line, newline stripped. */
static int read_ctl(const vx_cgroup_t *cg, const char *file, char *out, size_t out_len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", cg->path, file);
    FILE *f = fopen(path, "re");
    if (f == NULL) return -1;
    if (fgets(out, (int)out_len, f) == NULL) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = '\0';
    return 0;
}

int main(void) {
    VXT_BEGIN("cgroup v2 resource control");

    if (!vxt_is_root()) VXT_SKIP("needs root to create a cgroup node (euid=%d)", (int)geteuid());
    if (!vx_cgroup_v2_available(NULL))
        VXT_SKIP("/sys/fs/cgroup is not a cgroup2 mount on this kernel");

    VXT_CASE("the controllers we depend on are delegable");
    char ctrls[256];
    VXT_EQ_INT(vx_cgroup_controllers(NULL, ctrls, sizeof(ctrls)), VX_OK, "read controllers");
    printf("    controllers: %s\n", ctrls);
    VXT_CHECK(strstr(ctrls, "memory") != NULL, "memory controller present");
    VXT_CHECK(strstr(ctrls, "pids") != NULL, "pids controller present");

    VXT_CASE("create makes a real directory");
    vx_cgroup_t cg;
    VXT_EQ_INT(vx_cgroup_create(&cg, 777001, NULL), VX_OK, "create");
    VXT_CHECK(cg.created, "created flag");
    struct stat st;
    VXT_CHECK(stat(cg.path, &st) == 0 && S_ISDIR(st.st_mode), "%s is a directory", cg.path);

    VXT_CASE("memory.max is written in bytes, not MiB");
    VXT_EQ_INT(vx_cgroup_set_memory(&cg, 64), VX_OK, "set_memory(64)");
    char value[128];
    if (read_ctl(&cg, "memory.max", value, sizeof(value)) == 0) {
        VXT_CHECK(strcmp(value, "67108864") == 0, "memory.max is \"%s\", want 67108864", value);
    } else {
        VXT_CHECK(0, "could not read memory.max");
    }

    VXT_CASE("swap is denied so the limit cannot be escaped");
    if (read_ctl(&cg, "memory.swap.max", value, sizeof(value)) == 0) {
        VXT_CHECK(strcmp(value, "0") == 0, "memory.swap.max is \"%s\", want 0", value);
    } else {
        printf("    NOTE: memory.swap.max absent (swap accounting off); skipping\n");
    }

    VXT_CASE("memory.high stays disabled by default");
    /* Enabled, it converts an OOM into an indefinite stall — see vx_cgroup.c. */
    if (read_ctl(&cg, "memory.high", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "max") == 0, "memory.high is \"%s\", want max", value);

    VXT_CASE("memory.high can be opted into explicitly");
    VXT_EQ_INT(vx_cgroup_set_memory_high(&cg, 32), VX_OK, "set_memory_high(32)");
    if (read_ctl(&cg, "memory.high", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "33554432") == 0, "memory.high is \"%s\"", value);
    VXT_EQ_INT(vx_cgroup_set_memory_high(&cg, 0), VX_OK, "disable again");

    VXT_CASE("cpu.max is written as \"quota period\"");
    VXT_EQ_INT(vx_cgroup_set_cpu(&cg, 25000, 100000), VX_OK, "set_cpu");
    if (read_ctl(&cg, "cpu.max", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "25000 100000") == 0, "cpu.max is \"%s\"", value);

    VXT_CASE("a zero quota means unlimited, not zero CPU");
    VXT_EQ_INT(vx_cgroup_set_cpu(&cg, 0, 100000), VX_OK, "set_cpu(0)");
    if (read_ctl(&cg, "cpu.max", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "max 100000") == 0, "cpu.max is \"%s\"", value);

    VXT_CASE("pids.max is written");
    VXT_EQ_INT(vx_cgroup_set_pids_max(&cg, 32), VX_OK, "set_pids_max");
    if (read_ctl(&cg, "pids.max", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "32") == 0, "pids.max is \"%s\"", value);

    VXT_CASE("vx_cgroup_apply drives both limits off a task header");
    unsigned char frame[VX_TASK_HEADER_SIZE];
    vx_task_header_t *hdr = (vx_task_header_t *)frame;
    memset(frame, 0, sizeof(frame));
    hdr->magic = VX_MAGIC_HEADER;
    hdr->engine = ENGINE_ION;
    hdr->memory_limit_mb = 128;
    hdr->cpu_quota_us = 40000;
    VXT_EQ_INT(vx_cgroup_apply(&cg, hdr), VX_OK, "apply");
    if (read_ctl(&cg, "memory.max", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "134217728") == 0, "applied memory.max is \"%s\"", value);
    if (read_ctl(&cg, "cpu.max", value, sizeof(value)) == 0)
        VXT_CHECK(strcmp(value, "40000 100000") == 0, "applied cpu.max is \"%s\"", value);

    VXT_CASE("attach moves a live process into the cgroup");
    VXT_EQ_INT(vx_cgroup_set_pids_max(&cg, 0), VX_OK, "lift the pids cap for the fixture");
    VXT_EQ_INT(vx_cgroup_set_memory(&cg, 256), VX_OK, "room for the fixture to allocate");

    /* The child allocates only after it has been told it is in the cgroup.
     *
     * This ordering is the whole point: cgroup v2 does not migrate existing page
     * charges when a process is moved, so memory a process allocated before the
     * move stays billed to its old cgroup and memory.current here reads 0.  That
     * is precisely why vx_sandbox_spawn() attaches the guest *before* exec —
     * otherwise the guest's startup allocations escape the limit entirely. */
    int to_child[2], to_parent[2];
    VXT_CHECK(pipe(to_child) == 0 && pipe(to_parent) == 0, "fixture pipes");
    pid_t pid = fork();
    if (pid == 0) {
        close(to_child[1]);
        close(to_parent[0]);
        char go = 0;
        if (read(to_child[0], &go, 1) != 1) _exit(1);

        /* 8 MiB, touched and read back.  The checksum is folded into the
         * acknowledgement byte so the stores are observably used and cannot be
         * optimised away along with the malloc that backs them. */
        enum { BLOCKS = 8 };
        unsigned char *b[BLOCKS];
        long page = sysconf(_SC_PAGESIZE);
        for (int i = 0; i < BLOCKS; i++) {
            b[i] = malloc(1024 * 1024);
            if (b[i] == NULL) _exit(2);
            for (long off = 0; off < 1024 * 1024; off += page) b[i][off] = (unsigned char)(i + 1);
        }
        unsigned long sum = 0;
        for (int i = 0; i < BLOCKS; i++)
            for (long off = 0; off < 1024 * 1024; off += page) sum += b[i][off];

        char ack = (char)('a' + (sum % 26u));
        ssize_t w = write(to_parent[1], &ack, 1);
        (void)w;
        pause();
        _exit(0);
    }
    VXT_CHECK(pid > 0, "fork");
    if (pid > 0) {
        close(to_child[0]);
        close(to_parent[1]);

        VXT_EQ_INT(vx_cgroup_attach(&cg, pid), VX_OK, "attach");

        char procs[256] = "";
        read_ctl(&cg, "cgroup.procs", procs, sizeof(procs));
        char want[32];
        snprintf(want, sizeof(want), "%lld", (long long)pid);
        VXT_CHECK(strstr(procs, want) != NULL, "cgroup.procs contains %s (got \"%s\")", want,
                  procs);

        /* Release the child, then wait for its acknowledgement. */
        ssize_t w = write(to_child[1], "g", 1);
        VXT_CHECK(w == 1, "released the fixture");
        char ack = 0;
        VXT_CHECK(read(to_parent[0], &ack, 1) == 1, "fixture finished allocating");

        vx_cgroup_stats_t stats;
        VXT_EQ_INT(vx_cgroup_read_stats(&cg, &stats), VX_OK, "read stats");
        VXT_CHECK(stats.pids_current >= 1, "pids.current is %llu",
                  (unsigned long long)stats.pids_current);
        VXT_CHECK(stats.memory_current >= 4ull * 1024 * 1024,
                  "post-attach allocations are charged here: memory.current is %llu",
                  (unsigned long long)stats.memory_current);
        VXT_CHECK(!vx_cgroup_was_oom_killed(&cg), "nothing was OOM-killed");
        close(to_child[1]);
        close(to_parent[0]);

        VXT_CASE("cgroup.kill removes every member at once");
        VXT_EQ_INT(vx_cgroup_kill_all(&cg), VX_OK, "cgroup.kill");
        int status = 0;
        VXT_CHECK(waitpid(pid, &status, 0) == pid, "reap the killed child");
        VXT_CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "child died by SIGKILL");
    }

    VXT_CASE("destroy removes the node");
    VXT_EQ_INT(vx_cgroup_destroy(&cg), VX_OK, "destroy");
    VXT_CHECK(!cg.created, "created flag cleared");
    VXT_CHECK(stat(cg.path, &st) != 0 && errno == ENOENT, "%s is gone", cg.path);

    VXT_CASE("destroy is idempotent");
    VXT_EQ_INT(vx_cgroup_destroy(&cg), VX_OK, "second destroy");

    VXT_CASE("setters reject a cgroup that was never created");
    vx_cgroup_t empty;
    memset(&empty, 0, sizeof(empty));
    VXT_EQ_INT(vx_cgroup_set_memory(&empty, 64), VX_ERR_INVALID_ARG, "set_memory");
    VXT_EQ_INT(vx_cgroup_attach(&empty, 1), VX_ERR_INVALID_ARG, "attach");
    VXT_EQ_INT(vx_cgroup_set_memory(NULL, 64), VX_ERR_INVALID_ARG, "NULL cgroup");

    VXT_END();
}
