/* vx_cgroup.c — cgroups v2 (unified hierarchy) resource enforcement. */
#include "vx_cgroup.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

/* ------------------------------------------------------------------------- */
/* Control-file primitives                                                   */
/* ------------------------------------------------------------------------- */

static vx_status_t cg_write(const char *dir, const char *file, const char *value) {
    char path[VX_CGROUP_PATH_MAX + 64];
    if (snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path))
        return VX_ERR_INVALID_ARG;

    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        VX_DEBUG("open(%s) for write failed: %s", path, strerror(errno));
        return VX_ERR_CGROUP;
    }
    size_t len = strlen(value);
    ssize_t n = write(fd, value, len);
    int saved = errno;
    close(fd);
    if (n < 0 || (size_t)n != len) {
        VX_WARN("write(%s, \"%s\") failed: %s", path, value, strerror(saved));
        return VX_ERR_CGROUP;
    }
    VX_TRACE("cgroup write %s <- %s", path, value);
    return VX_OK;
}

static vx_status_t cg_read(const char *dir, const char *file, char *out, size_t out_len) {
    char path[VX_CGROUP_PATH_MAX + 64];
    if (snprintf(path, sizeof(path), "%s/%s", dir, file) >= (int)sizeof(path))
        return VX_ERR_INVALID_ARG;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return VX_ERR_CGROUP;
    ssize_t n = read(fd, out, out_len - 1);
    close(fd);
    if (n < 0) return VX_ERR_CGROUP;
    out[n] = '\0';
    return VX_OK;
}

/* Read a single scalar control file such as memory.current. */
static vx_status_t cg_read_u64(const char *dir, const char *file, uint64_t *out) {
    char buf[64];
    vx_status_t st = cg_read(dir, file, buf, sizeof(buf));
    if (st != VX_OK) return st;
    if (strncmp(buf, "max", 3) == 0) {
        *out = UINT64_MAX;
        return VX_OK;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(buf, &end, 10);
    if (end == buf || errno != 0) return VX_ERR_CGROUP;
    *out = (uint64_t)v;
    return VX_OK;
}

/* Read one key from a "key value\n"-per-line file (cpu.stat, memory.events).
 * Matches the whole first token, so looking up "oom" never picks up
 * "oom_kill". */
static vx_status_t cg_read_keyed(const char *dir, const char *file, const char *key,
                                 uint64_t *out) {
    char buf[2048];
    vx_status_t st = cg_read(dir, file, buf, sizeof(buf));
    if (st != VX_OK) return st;

    size_t key_len = strlen(key);
    char *line = buf;
    while (line != NULL && *line != '\0') {
        char *eol = strchr(line, '\n');
        if (eol != NULL) *eol = '\0';
        if (strncmp(line, key, key_len) == 0 && line[key_len] == ' ') {
            *out = strtoull(line + key_len + 1, NULL, 10);
            return VX_OK;
        }
        line = (eol != NULL) ? eol + 1 : NULL;
    }
    return VX_ERR_CGROUP;
}

/* ------------------------------------------------------------------------- */
/* Capability probing                                                        */
/* ------------------------------------------------------------------------- */

bool vx_cgroup_v2_available(const char *root) {
    if (root == NULL) root = VX_CGROUP_ROOT_DEFAULT;
    struct statfs sfs;
    if (statfs(root, &sfs) != 0) return false;
    return (unsigned long)sfs.f_type == (unsigned long)CGROUP2_SUPER_MAGIC;
}

vx_status_t vx_cgroup_controllers(const char *root, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) return VX_ERR_INVALID_ARG;
    if (root == NULL) root = VX_CGROUP_ROOT_DEFAULT;
    vx_status_t st = cg_read(root, "cgroup.controllers", out, out_len);
    if (st != VX_OK) {
        out[0] = '\0';
        return st;
    }
    /* Strip the trailing newline so callers can print it inline. */
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' ')) out[--n] = '\0';
    return VX_OK;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

vx_status_t vx_cgroup_create(vx_cgroup_t *cg, uint64_t task_id, const char *root) {
    if (cg == NULL) return VX_ERR_INVALID_ARG;
    if (root == NULL) root = VX_CGROUP_ROOT_DEFAULT;

    memset(cg, 0, sizeof(*cg));
    cg->task_id = task_id;
    if (snprintf(cg->path, sizeof(cg->path), "%s/vxworker_%llu", root,
                 (unsigned long long)task_id) >= (int)sizeof(cg->path))
        return VX_ERR_INVALID_ARG;

    if (!vx_cgroup_v2_available(root)) {
        VX_WARN("%s is not a cgroup2 mount; resource limits unavailable", root);
        return VX_ERR_UNSUPPORTED;
    }

    /* A controller is only visible inside a child if the parent delegates it
     * via cgroup.subtree_control.  This is idempotent and frequently already
     * done by systemd, so a failure here is only fatal if the controller then
     * turns out to be missing. */
    char have[256];
    if (vx_cgroup_controllers(root, have, sizeof(have)) == VX_OK) {
        char want[128] = "";
        size_t used = 0;
        static const char *ctrls[] = {"memory", "cpu", "pids"};
        for (size_t i = 0; i < sizeof(ctrls) / sizeof(ctrls[0]); i++) {
            if (strstr(have, ctrls[i]) == NULL) continue;
            int n = snprintf(want + used, sizeof(want) - used, "%s+%s", used ? " " : "", ctrls[i]);
            if (n > 0) used += (size_t)n;
        }
        if (used > 0) (void)cg_write(root, "cgroup.subtree_control", want);
    }

    if (mkdir(cg->path, 0755) != 0) {
        if (errno == EEXIST) {
            cg->created = true; /* reuse a leftover node from a previous run */
            VX_DEBUG("cgroup %s already existed; reusing", cg->path);
            return VX_OK;
        }
        VX_ERROR("mkdir(%s) failed: %s", cg->path, strerror(errno));
        return errno == EACCES || errno == EPERM ? VX_ERR_CGROUP : VX_ERR_CGROUP;
    }
    cg->created = true;
    VX_DEBUG("cgroup %s created", cg->path);
    return VX_OK;
}

vx_status_t vx_cgroup_set_memory(vx_cgroup_t *cg, uint32_t mb) {
    if (cg == NULL || !cg->created) return VX_ERR_INVALID_ARG;

    if (mb == 0) {
        vx_status_t st = cg_write(cg->path, "memory.max", "max");
        if (st != VX_OK) return st;
        (void)cg_write(cg->path, "memory.swap.max", "max");
        return cg_write(cg->path, "memory.high", "max");
    }

    uint64_t bytes = (uint64_t)mb * 1024ull * 1024ull;
    char value[32];
    snprintf(value, sizeof(value), "%" PRIu64, bytes);
    vx_status_t st = cg_write(cg->path, "memory.max", value);
    if (st != VX_OK) return st;

    /* Deny swap outright.  Without this, memory.max caps only *resident* memory:
     * the kernel happily reclaims a task's cold anonymous pages to swap, so a
     * 16 MiB task can still consume hundreds of MiB of backing store and is
     * never OOM-killed.  A limit that swap can escape is not a limit, and on a
     * multi-tenant node the swap device is shared. */
    if (cg_write(cg->path, "memory.swap.max", "0") != VX_OK)
        VX_WARN("memory.swap.max unavailable on %s; limit is resident-only", cg->path);

    /* Leave memory.high disabled by default, and this is deliberate.
     *
     * memory.high does not kill: it throttles the cgroup with escalating
     * allocator stalls and reclaims instead.  Combined with memory.swap.max=0 a
     * task that blows its limit then makes near-zero forward progress until the
     * supervisor's wall-clock deadline fires — so a memory bug burns the entire
     * timeout budget and is misreported as KILLED_TIMEOUT rather than
     * KILLED_OOM.  Measured here: a 256 MiB allocation under a 16 MiB limit
     * thrashed for the full 20s with memory.high=90%, versus an OOM kill in
     * ~40ms without it.
     *
     * Only memory.max gives a prompt, correctly-attributed failure, which is why
     * Docker and Kubernetes also set the hard limit alone.  Callers that would
     * rather trade latency for survival can opt in via
     * vx_cgroup_set_memory_high(). */
    if (cg_write(cg->path, "memory.high", "max") != VX_OK)
        VX_DEBUG("memory.high not present on %s", cg->path);
    return VX_OK;
}

vx_status_t vx_cgroup_set_memory_high(vx_cgroup_t *cg, uint32_t mb) {
    if (cg == NULL || !cg->created) return VX_ERR_INVALID_ARG;
    char value[32];
    if (mb == 0)
        snprintf(value, sizeof(value), "max");
    else
        snprintf(value, sizeof(value), "%" PRIu64, (uint64_t)((uint64_t)mb * 1024ull * 1024ull));
    return cg_write(cg->path, "memory.high", value);
}

vx_status_t vx_cgroup_set_cpu(vx_cgroup_t *cg, uint32_t quota_us, uint32_t period_us) {
    if (cg == NULL || !cg->created) return VX_ERR_INVALID_ARG;
    if (period_us == 0) period_us = VX_CPU_PERIOD_DEFAULT_US;

    char value[64];
    if (quota_us == 0)
        snprintf(value, sizeof(value), "max %u", period_us);
    else
        snprintf(value, sizeof(value), "%u %u", quota_us, period_us);
    return cg_write(cg->path, "cpu.max", value);
}

vx_status_t vx_cgroup_set_pids_max(vx_cgroup_t *cg, uint32_t max) {
    if (cg == NULL || !cg->created) return VX_ERR_INVALID_ARG;
    char value[32];
    if (max == 0)
        snprintf(value, sizeof(value), "max");
    else
        snprintf(value, sizeof(value), "%u", max);
    return cg_write(cg->path, "pids.max", value);
}

vx_status_t vx_cgroup_apply(vx_cgroup_t *cg, const vx_task_header_t *hdr) {
    if (cg == NULL || hdr == NULL) return VX_ERR_INVALID_ARG;
    vx_status_t st = vx_cgroup_set_memory(cg, hdr->memory_limit_mb);
    if (st != VX_OK) return st;
    return vx_cgroup_set_cpu(cg, hdr->cpu_quota_us, VX_CPU_PERIOD_DEFAULT_US);
}

vx_status_t vx_cgroup_attach(vx_cgroup_t *cg, pid_t pid) {
    if (cg == NULL || !cg->created || pid <= 0) return VX_ERR_INVALID_ARG;
    char value[32];
    snprintf(value, sizeof(value), "%lld", (long long)pid);
    return cg_write(cg->path, "cgroup.procs", value);
}

vx_status_t vx_cgroup_read_stats(const vx_cgroup_t *cg, vx_cgroup_stats_t *out) {
    if (cg == NULL || out == NULL || !cg->created) return VX_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    /* Every field is best-effort: a controller may be absent, and a node whose
     * members have all exited still has readable counters.  Missing values stay
     * zero rather than failing the whole read. */
    (void)cg_read_u64(cg->path, "memory.current", &out->memory_current);
    (void)cg_read_u64(cg->path, "memory.peak", &out->memory_peak);
    (void)cg_read_u64(cg->path, "pids.current", &out->pids_current);
    (void)cg_read_keyed(cg->path, "cpu.stat", "usage_usec", &out->cpu_usage_us);
    (void)cg_read_keyed(cg->path, "memory.events", "oom_kill", &out->oom_kill);
    return VX_OK;
}

bool vx_cgroup_was_oom_killed(const vx_cgroup_t *cg) {
    if (cg == NULL || !cg->created) return false;
    uint64_t n = 0;
    if (cg_read_keyed(cg->path, "memory.events", "oom_kill", &n) != VX_OK) return false;
    return n > 0;
}

vx_status_t vx_cgroup_kill_all(const vx_cgroup_t *cg) {
    if (cg == NULL || !cg->created) return VX_ERR_INVALID_ARG;
    /* cgroup.kill (5.14+) kills the whole subtree atomically, which beats
     * walking cgroup.procs and racing a task that is still forking. */
    return cg_write(cg->path, "cgroup.kill", "1");
}

vx_status_t vx_cgroup_destroy(vx_cgroup_t *cg) {
    if (cg == NULL) return VX_ERR_INVALID_ARG;
    if (!cg->created) return VX_OK;

    /* rmdir fails with EBUSY while any member remains, so give the kernel a
     * few short grace periods after the kill before giving up. */
    for (int attempt = 0; attempt < 50; attempt++) {
        if (rmdir(cg->path) == 0) {
            cg->created = false;
            VX_DEBUG("cgroup %s removed", cg->path);
            return VX_OK;
        }
        if (errno == ENOENT) {
            cg->created = false;
            return VX_OK;
        }
        if (errno != EBUSY) {
            VX_WARN("rmdir(%s) failed: %s", cg->path, strerror(errno));
            return VX_ERR_CGROUP;
        }
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 2 * 1000 * 1000}; /* 2ms */
        nanosleep(&ts, NULL);
    }
    VX_WARN("cgroup %s still busy after kill; leaking node", cg->path);
    return VX_ERR_CGROUP;
}
