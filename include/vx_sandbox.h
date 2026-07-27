/* vx_sandbox.h — unprivileged Linux namespace + cgroup sandbox.
 *
 * The sandbox is created with a direct clone(2) system call rather than
 * fork()+unshare(), because CLONE_NEWPID applied via unshare() only takes
 * effect for the caller's *children* — cloning directly makes the guest process
 * PID 1 of its own namespace, which is what a task supervisor needs in order to
 * reap orphans and receive the namespace's signals.
 *
 * Startup handshake (both barriers are load-bearing):
 *
 *   parent                                   child (clone'd)
 *   ------                                   ---------------
 *   clone(CLONE_NEW*)  ------------------->  blocks reading sync_in
 *   write setgroups=deny
 *   write uid_map "0 <host_uid> 1"
 *   write gid_map "0 <host_gid> 1"
 *   cgroup.procs <- child pid
 *   write sync_in  ------------------------> wakes; setresuid(0); mounts; exec
 *
 * The child must not run before the uid mapping lands, or it would execute as
 * the overflow uid (65534) with no way to become root inside its own namespace.
 * The parent must not exec the child before the cgroup attach, or the first
 * allocations would escape the memory limit. */
#ifndef VX_SANDBOX_H
#define VX_SANDBOX_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "vx_cgroup.h"
#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What the running kernel will actually let us do.  Probed, never assumed:
 * a hardened host, an unprivileged container, or a WSL kernel can each be
 * missing any one of these. */
typedef struct {
    bool userns;        /* CLONE_NEWUSER permitted                       */
    bool pidns;         /* CLONE_NEWPID permitted                        */
    bool netns;         /* CLONE_NEWNET permitted                        */
    bool ipcns;         /* CLONE_NEWIPC permitted                        */
    bool mountns;       /* CLONE_NEWNS permitted                         */
    bool utsns;         /* CLONE_NEWUTS permitted                        */
    bool cgroupns;      /* CLONE_NEWCGROUP permitted                     */
    bool cgroup_v2;     /* /sys/fs/cgroup is cgroup2                     */
    bool cgroup_memory; /* memory controller delegable                   */
    bool cgroup_cpu;    /* cpu controller delegable                      */
    bool cgroup_pids;   /* pids controller delegable                     */
    bool cgroup_kill;   /* cgroup.kill available (kernel >= 5.14)        */
    bool pidfd;         /* pidfd_open(2) available (kernel >= 5.3)       */
    bool signalfd;      /* signalfd(2) available                         */
    long max_user_ns;   /* /proc/sys/user/max_user_namespaces            */
} vx_sandbox_caps_t;

typedef struct {
    /* Identity / accounting */
    uint64_t task_id;
    const char *tenant_id;

    /* Namespaces to unshare */
    bool new_user;
    bool new_pid;
    bool new_net;
    bool new_ipc;
    bool new_mount;
    bool new_uts;
    bool new_cgroup;

    /* uid 0 inside the namespace maps to this host id.  Must be non-root on a
     * multi-tenant node: that is the whole point of the user namespace. */
    uid_t host_uid;
    gid_t host_gid;

    /* Resource envelope (0 == unlimited) */
    uint32_t memory_limit_mb;
    uint32_t cpu_quota_us;
    uint32_t cpu_period_us;
    uint32_t pids_max;

    /* Wall-clock kill deadline; 0 disables. */
    uint32_t timeout_ms;

    /* With new_mount: remount / as MS_PRIVATE and mount a fresh procfs, so
     * /proc reflects the new PID namespace instead of the host's. */
    bool mount_proc;

    /* With new_net: bring the namespace's loopback up via SIOCSIFFLAGS, so
     * localhost-bound servers inside the sandbox work. */
    bool loopback_up;

    /* Optional hostname inside a new UTS namespace. */
    const char *hostname;

    /* Optional working directory for the guest. */
    const char *cwd;

    /* Program to run.  argv[0] is resolved through PATH by execvp. */
    char *const *argv;
    char *const *envp; /* NULL inherits the parent environment */

    /* Where to create the cgroup node; NULL means /sys/fs/cgroup. */
    const char *cgroup_root;
} vx_sandbox_spec_t;

typedef struct {
    pid_t pid;      /* host-side pid of the guest (PID 1 inside)        */
    int pidfd;      /* pidfd for race-free wait/kill; -1 if unavailable */
    vx_cgroup_t cg; /* the task's cgroup node                          */
    uint64_t started_us;
    bool reaped;
} vx_sandbox_t;

typedef struct {
    vx_task_state_t state;
    int exit_code;   /* exit status, or 128+signo when signalled        */
    int term_signal; /* 0 if the guest exited normally                  */
    uint64_t duration_us;
    vx_cgroup_stats_t usage;
} vx_sandbox_result_t;

/* Fill a spec with safe defaults: every namespace on, 64 MiB, 50% of one core,
 * 64 pids, procfs mounted, loopback up, uid 0 -> uid 65534. */
void vx_sandbox_spec_init(vx_sandbox_spec_t *spec);

/* Probe kernel support.  Cheap enough to call at startup, and the CLI does. */
vx_status_t vx_sandbox_probe(vx_sandbox_caps_t *out);

/* Clone the guest, apply the isolation envelope, and exec spec->argv. */
vx_status_t vx_sandbox_spawn(vx_sandbox_t *sb, const vx_sandbox_spec_t *spec);

/* Wait for the guest.  timeout_ms == 0 blocks indefinitely; on expiry the guest
 * is SIGKILLed via the cgroup and the result reports KILLED_TIMEOUT. */
vx_status_t vx_sandbox_wait(vx_sandbox_t *sb, uint32_t timeout_ms, vx_sandbox_result_t *out);

vx_status_t vx_sandbox_kill(vx_sandbox_t *sb, int signo);

/* Release the pidfd and remove the cgroup.  Idempotent. */
vx_status_t vx_sandbox_destroy(vx_sandbox_t *sb);

#ifdef __cplusplus
}
#endif

#endif /* VX_SANDBOX_H */
