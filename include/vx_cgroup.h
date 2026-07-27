/* vx_cgroup.h — cgroups v2 resource isolation.
 *
 * Every task gets its own cgroup node at <root>/vxworker_<task_id>.  Limits are
 * written as unified-hierarchy control files; there is no cgroup v1 fallback by
 * design — v1's per-controller hierarchies cannot express the atomic
 * memory+cpu+pids envelope VxCloud guarantees.
 *
 * Delegation note: the parent cgroup must list the controllers we want in its
 * cgroup.subtree_control, otherwise memory.max/cpu.max will not exist in the
 * child.  vx_cgroup_create() enables them for you when it has permission. */
#ifndef VX_CGROUP_H
#define VX_CGROUP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VX_CGROUP_ROOT_DEFAULT "/sys/fs/cgroup"
#define VX_CGROUP_PATH_MAX 256

/* Linux default CFS period.  cpu.max is written as "<quota> <period>". */
#define VX_CPU_PERIOD_DEFAULT_US 100000u

typedef struct {
    char path[VX_CGROUP_PATH_MAX]; /* absolute path to the cgroup directory */
    uint64_t task_id;
    bool created; /* true once the directory exists and is ours to remove */
} vx_cgroup_t;

typedef struct {
    uint64_t memory_current; /* memory.current, bytes                       */
    uint64_t memory_peak;    /* memory.peak, bytes (0 if kernel lacks it)   */
    uint64_t cpu_usage_us;   /* cpu.stat usage_usec                         */
    uint64_t oom_kill;       /* memory.events oom_kill counter              */
    uint64_t pids_current;   /* pids.current                                */
} vx_cgroup_stats_t;

/* True when /sys/fs/cgroup is a cgroup2 superblock. */
bool vx_cgroup_v2_available(const char *root);

/* Which controllers the given cgroup root can delegate to children. */
vx_status_t vx_cgroup_controllers(const char *root, char *out, size_t out_len);

/* Create <root>/vxworker_<task_id>.  Pass root=NULL for the default. */
vx_status_t vx_cgroup_create(vx_cgroup_t *cg, uint64_t task_id, const char *root);

/* Hard memory envelope: memory.max = mb MiB and memory.swap.max = 0, so the
 * limit cannot be escaped by swapping cold pages out.  mb == 0 means unlimited.
 *
 * memory.high is explicitly left disabled — see the comment in the
 * implementation for the measurement behind that choice. */
vx_status_t vx_cgroup_set_memory(vx_cgroup_t *cg, uint32_t mb);

/* Opt-in soft watermark.  Above this the kernel throttles and reclaims instead
 * of killing, which suits an elastic workload that would rather run slowly than
 * die — but it converts a limit breach into a stall, so it is off by default.
 * mb == 0 disables it. */
vx_status_t vx_cgroup_set_memory_high(vx_cgroup_t *cg, uint32_t mb);

/* cpu.max = "<quota_us> <period_us>".  quota_us == 0 means "max". */
vx_status_t vx_cgroup_set_cpu(vx_cgroup_t *cg, uint32_t quota_us, uint32_t period_us);

/* pids.max — the cheapest defence against a fork bomb. */
vx_status_t vx_cgroup_set_pids_max(vx_cgroup_t *cg, uint32_t max);

/* Apply an entire task header's resource envelope in one call. */
vx_status_t vx_cgroup_apply(vx_cgroup_t *cg, const vx_task_header_t *hdr);

/* Move a pid into the cgroup by writing cgroup.procs. */
vx_status_t vx_cgroup_attach(vx_cgroup_t *cg, pid_t pid);

vx_status_t vx_cgroup_read_stats(const vx_cgroup_t *cg, vx_cgroup_stats_t *out);

/* True if the kernel OOM-killed anything in this cgroup. */
bool vx_cgroup_was_oom_killed(const vx_cgroup_t *cg);

/* SIGKILL every member via cgroup.kill (kernel >= 5.14), atomically. */
vx_status_t vx_cgroup_kill_all(const vx_cgroup_t *cg);

/* rmdir the node.  Fails with VX_ERR_CGROUP while members remain. */
vx_status_t vx_cgroup_destroy(vx_cgroup_t *cg);

#ifdef __cplusplus
}
#endif

#endif /* VX_CGROUP_H */
