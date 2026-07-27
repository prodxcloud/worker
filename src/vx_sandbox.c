/* vx_sandbox.c — unprivileged namespace + cgroup v2 sandbox.
 *
 * See vx_sandbox.h for the startup handshake, which is the part that is easy to
 * get subtly wrong. */
#include "vx_sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"
#include "vx_signal.h"

/* The overflow uid: the standard "nobody" target for a mapped root. */
#define VX_DEFAULT_HOST_UID 65534
#define VX_DEFAULT_HOST_GID 65534

/* ------------------------------------------------------------------------- */
/* Raw syscall wrappers                                                      */
/* ------------------------------------------------------------------------- */

/* Direct clone(2).  With a NULL stack the kernel gives fork-like semantics
 * (returns 0 in the child, on the child's own copy of the stack), which is what
 * every container runtime relies on.  Going through the glibc clone() wrapper
 * would force us to supply a stack and a function pointer for no benefit. */
static pid_t vx_raw_clone(unsigned long flags) {
#if defined(__x86_64__) || defined(__aarch64__)
    return (pid_t)syscall(SYS_clone, flags, (void *)NULL, (int *)NULL, (int *)NULL,
                          (unsigned long)0);
#else
#error "vx_raw_clone: unsupported architecture"
#endif
}

static int vx_pidfd_open(pid_t pid) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int vx_pidfd_send_signal(int pidfd, int sig) {
#ifdef SYS_pidfd_send_signal
    return (int)syscall(SYS_pidfd_send_signal, pidfd, sig, (void *)NULL, (unsigned int)0);
#else
    (void)pidfd;
    (void)sig;
    errno = ENOSYS;
    return -1;
#endif
}

/* ------------------------------------------------------------------------- */
/* Small file helpers                                                        */
/* ------------------------------------------------------------------------- */

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t len = strlen(data);
    ssize_t n = write(fd, data, len);
    int saved = errno;
    close(fd);
    if (n < 0 || (size_t)n != len) {
        errno = saved;
        return -1;
    }
    return 0;
}

static long read_long_file(const char *path, long fallback) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fallback;
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return fallback;
    buf[n] = '\0';
    return strtol(buf, NULL, 10);
}

/* ------------------------------------------------------------------------- */
/* Capability probing                                                        */
/* ------------------------------------------------------------------------- */

/* Fork a throwaway child and have it actually attempt the unshare.  Inspecting
 * /proc or the kernel version only tells you what should work; this tells you
 * what does, under whatever seccomp/AppArmor/LSM policy is really in force. */
static bool probe_unshare(int flags) {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) _exit(unshare(flags) == 0 ? 0 : 1);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

vx_status_t vx_sandbox_probe(vx_sandbox_caps_t *out) {
    if (out == NULL) return VX_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    out->userns = probe_unshare(CLONE_NEWUSER);
    out->pidns = probe_unshare(CLONE_NEWPID);
    out->netns = probe_unshare(CLONE_NEWNET);
    out->ipcns = probe_unshare(CLONE_NEWIPC);
    out->mountns = probe_unshare(CLONE_NEWNS);
    out->utsns = probe_unshare(CLONE_NEWUTS);
    out->cgroupns = probe_unshare(CLONE_NEWCGROUP);

    out->max_user_ns = read_long_file("/proc/sys/user/max_user_namespaces", -1);

    out->cgroup_v2 = vx_cgroup_v2_available(NULL);
    if (out->cgroup_v2) {
        char ctrls[256];
        if (vx_cgroup_controllers(NULL, ctrls, sizeof(ctrls)) == VX_OK) {
            out->cgroup_memory = strstr(ctrls, "memory") != NULL;
            out->cgroup_cpu = strstr(ctrls, "cpu") != NULL;
            out->cgroup_pids = strstr(ctrls, "pids") != NULL;
        }

        /* cgroup.kill only exists on non-root nodes, so the only honest test is
         * to make one.  Uses a reserved probe id so it cannot collide. */
        vx_cgroup_t probe;
        if (vx_cgroup_create(&probe, 0, NULL) == VX_OK) {
            char path[VX_CGROUP_PATH_MAX + 32];
            snprintf(path, sizeof(path), "%s/cgroup.kill", probe.path);
            out->cgroup_kill = access(path, F_OK) == 0;
            vx_cgroup_destroy(&probe);
        }
    }

    int pfd = vx_pidfd_open(getpid());
    if (pfd >= 0) {
        out->pidfd = true;
        close(pfd);
    }

    /* signalfd with an empty mask is a valid no-op subscription. */
    sigset_t empty;
    sigemptyset(&empty);
    int sfd = signalfd(-1, &empty, SFD_CLOEXEC);
    if (sfd >= 0) {
        out->signalfd = true;
        close(sfd);
    }

    out->seccomp = vx_seccomp_available();
    out->seccomp_kill = vx_seccomp_kill_process_supported();

    return VX_OK;
}

/* ------------------------------------------------------------------------- */
/* Spec defaults                                                             */
/* ------------------------------------------------------------------------- */

void vx_sandbox_spec_init(vx_sandbox_spec_t *spec) {
    if (spec == NULL) return;
    memset(spec, 0, sizeof(*spec));
    spec->new_user = true;
    spec->new_pid = true;
    spec->new_net = true;
    spec->new_ipc = true;
    spec->new_mount = true;
    spec->new_uts = true;
    spec->new_cgroup = true;
    spec->host_uid = VX_DEFAULT_HOST_UID;
    spec->host_gid = VX_DEFAULT_HOST_GID;
    spec->memory_limit_mb = 64;
    spec->cpu_quota_us = 50000; /* half a core against the 100ms default period */
    spec->cpu_period_us = VX_CPU_PERIOD_DEFAULT_US;
    spec->pids_max = 64;
    spec->timeout_ms = 30000;
    spec->mount_proc = true;
    spec->loopback_up = true;
    spec->hostname = "vxworker";
    vx_seccomp_policy_init(&spec->seccomp);
}

/* ------------------------------------------------------------------------- */
/* Child-side setup (post-clone, pre-exec)                                   */
/* ------------------------------------------------------------------------- */

/* Report a failure reason to the parent and die.  Deliberately avoids stdio and
 * anything that could take a lock: between clone() and exec() the child shares
 * the parent's address space image, so a lock held elsewhere at clone time
 * would deadlock here. */
__attribute__((noreturn)) static void child_fail(int errfd, int stage, int err) {
    int payload[2] = {stage, err};
    ssize_t rc = write(errfd, payload, sizeof(payload));
    (void)rc;
    _exit(127);
}

#define STAGE_SYNC 1
#define STAGE_SETGID 2
#define STAGE_SETUID 3
#define STAGE_HOSTNAME 4
#define STAGE_MOUNT_PRIVATE 5
#define STAGE_MOUNT_PROC 6
#define STAGE_LOOPBACK 7
#define STAGE_CHDIR 8
#define STAGE_EXEC 9
#define STAGE_SECCOMP 10

/* Bring "lo" up inside the new network namespace with SIOCSIFFLAGS.  A netns
 * starts with loopback administratively down, which breaks anything that binds
 * 127.0.0.1 — and doing this with an ioctl keeps us free of a netlink
 * dependency and of spawning `ip`. */
static int loopback_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, "lo", 3);

    if (ioctl(s, SIOCGIFFLAGS, &ifr) != 0) {
        int saved = errno;
        close(s);
        errno = saved;
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) {
        int saved = errno;
        close(s);
        errno = saved;
        return -1;
    }
    close(s);
    return 0;
}

__attribute__((noreturn)) static void child_main(const vx_sandbox_spec_t *spec, int syncfd,
                                                 int errfd) {
    /* Barrier: the parent writes one byte once the uid map and cgroup attach are
     * done.  A short read means the parent died first. */
    char token = 0;
    ssize_t n;
    do {
        n = read(syncfd, &token, 1);
    } while (n < 0 && errno == EINTR);
    if (n != 1) child_fail(errfd, STAGE_SYNC, n == 0 ? EPIPE : errno);
    close(syncfd);

    if (spec->new_user) {
        /* Become root *inside* the namespace.  On the host this is still
         * spec->host_uid — an unprivileged account. */
        if (setresgid(0, 0, 0) != 0) child_fail(errfd, STAGE_SETGID, errno);
        if (setresuid(0, 0, 0) != 0) child_fail(errfd, STAGE_SETUID, errno);
    }

    /* Set after the credential change: a uid transition clears PDEATHSIG. */
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    if (spec->new_uts && spec->hostname != NULL) {
        if (sethostname(spec->hostname, strlen(spec->hostname)) != 0)
            child_fail(errfd, STAGE_HOSTNAME, errno);
    }

    if (spec->new_mount) {
        /* Without MS_PRIVATE the new mount namespace still shares propagation
         * with the host, so our /proc mount would leak back out. */
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
            child_fail(errfd, STAGE_MOUNT_PRIVATE, errno);

        if (spec->mount_proc) {
            /* A fresh procfs so /proc reflects the new PID namespace: without
             * this, `ps` inside the sandbox still enumerates host processes. */
            if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
                child_fail(errfd, STAGE_MOUNT_PROC, errno);
        }
    }

    if (spec->new_net && spec->loopback_up) {
        if (loopback_up() != 0) child_fail(errfd, STAGE_LOOPBACK, errno);
    }

    if (spec->cwd != NULL) {
        if (chdir(spec->cwd) != 0) child_fail(errfd, STAGE_CHDIR, errno);
    }

    vx_signal_reset_for_child();

    /* Install the syscall filter last, and deliberately so: everything above
     * calls mount(2) and sethostname(2), which the filter denies. Applying it
     * here means the supervisor's setup runs unhindered while the guest — which
     * begins at the execvp below, and inherits the filter through it — cannot
     * make those calls at all. */
    if (spec->seccomp.mode != VX_SECCOMP_OFF) {
        if (vx_seccomp_apply(&spec->seccomp) != VX_OK) child_fail(errfd, STAGE_SECCOMP, ENOSYS);
    }

    if (spec->envp != NULL)
        execvpe(spec->argv[0], spec->argv, (char *const *)spec->envp);
    else
        execvp(spec->argv[0], spec->argv);

    child_fail(errfd, STAGE_EXEC, errno);
}

static const char *stage_name(int stage) {
    switch (stage) {
    case STAGE_SYNC:
        return "sync barrier";
    case STAGE_SETGID:
        return "setresgid";
    case STAGE_SETUID:
        return "setresuid";
    case STAGE_HOSTNAME:
        return "sethostname";
    case STAGE_MOUNT_PRIVATE:
        return "mount / private";
    case STAGE_MOUNT_PROC:
        return "mount /proc";
    case STAGE_LOOPBACK:
        return "loopback up";
    case STAGE_CHDIR:
        return "chdir";
    case STAGE_EXEC:
        return "execvp";
    case STAGE_SECCOMP:
        return "seccomp filter install";
    default:
        return "unknown stage";
    }
}

/* ------------------------------------------------------------------------- */
/* Spawn                                                                     */
/* ------------------------------------------------------------------------- */

static vx_status_t write_id_maps(pid_t pid, uid_t host_uid, gid_t host_gid) {
    char path[64];
    char value[64];

    /* setgroups must be denied before gid_map is written, otherwise the kernel
     * refuses the map for an unprivileged writer (it would let a process drop
     * supplementary groups to bypass a negative-permission ACL). */
    snprintf(path, sizeof(path), "/proc/%lld/setgroups", (long long)pid);
    if (write_file(path, "deny") != 0 && errno != ENOENT) {
        VX_WARN("write %s failed: %s", path, strerror(errno));
    }

    snprintf(path, sizeof(path), "/proc/%lld/uid_map", (long long)pid);
    snprintf(value, sizeof(value), "0 %lld 1", (long long)host_uid);
    if (write_file(path, value) != 0) {
        VX_ERROR("write %s <- \"%s\" failed: %s", path, value, strerror(errno));
        return VX_ERR_UIDMAP;
    }

    snprintf(path, sizeof(path), "/proc/%lld/gid_map", (long long)pid);
    snprintf(value, sizeof(value), "0 %lld 1", (long long)host_gid);
    if (write_file(path, value) != 0) {
        VX_ERROR("write %s <- \"%s\" failed: %s", path, value, strerror(errno));
        return VX_ERR_UIDMAP;
    }
    return VX_OK;
}

vx_status_t vx_sandbox_spawn(vx_sandbox_t *sb, const vx_sandbox_spec_t *spec) {
    if (sb == NULL || spec == NULL) return VX_ERR_INVALID_ARG;
    if (spec->argv == NULL || spec->argv[0] == NULL) return VX_ERR_INVALID_ARG;

    memset(sb, 0, sizeof(*sb));
    sb->pid = -1;
    sb->pidfd = -1;

    unsigned long flags = 0;
    if (spec->new_user) flags |= CLONE_NEWUSER;
    if (spec->new_pid) flags |= CLONE_NEWPID;
    if (spec->new_net) flags |= CLONE_NEWNET;
    if (spec->new_ipc) flags |= CLONE_NEWIPC;
    if (spec->new_mount) flags |= CLONE_NEWNS;
    if (spec->new_uts) flags |= CLONE_NEWUTS;
    if (spec->new_cgroup) flags |= CLONE_NEWCGROUP;

    /* Create and populate the cgroup before the guest can run.  Attaching after
     * exec would let the first (often largest) allocations escape the limit. */
    bool want_cgroup = spec->memory_limit_mb > 0 || spec->cpu_quota_us > 0 || spec->pids_max > 0;
    if (want_cgroup) {
        vx_status_t st = vx_cgroup_create(&sb->cg, spec->task_id, spec->cgroup_root);
        if (st != VX_OK) {
            VX_WARN("cgroup unavailable (%s); continuing without resource limits",
                    vx_status_str(st));
        } else {
            if (spec->memory_limit_mb > 0) vx_cgroup_set_memory(&sb->cg, spec->memory_limit_mb);
            if (spec->cpu_quota_us > 0)
                vx_cgroup_set_cpu(&sb->cg, spec->cpu_quota_us, spec->cpu_period_us);
            if (spec->pids_max > 0) vx_cgroup_set_pids_max(&sb->cg, spec->pids_max);
        }
    }

    int syncpipe[2] = {-1, -1};
    int errpipe[2] = {-1, -1};
    if (pipe2(syncpipe, O_CLOEXEC) != 0) {
        vx_cgroup_destroy(&sb->cg);
        return VX_ERR_SPAWN;
    }
    /* O_CLOEXEC on the error pipe turns a successful exec into a clean EOF for
     * the parent — that is how we distinguish "exec worked" from "exec failed"
     * without a timeout. */
    if (pipe2(errpipe, O_CLOEXEC) != 0) {
        close(syncpipe[0]);
        close(syncpipe[1]);
        vx_cgroup_destroy(&sb->cg);
        return VX_ERR_SPAWN;
    }

    sb->started_us = vx_now_us();

    pid_t pid = vx_raw_clone(flags | SIGCHLD);
    if (pid < 0) {
        int saved = errno;
        VX_ERROR("clone(0x%lx) failed: %s", flags, strerror(saved));
        close(syncpipe[0]);
        close(syncpipe[1]);
        close(errpipe[0]);
        close(errpipe[1]);
        vx_cgroup_destroy(&sb->cg);
        return (saved == EPERM || saved == EINVAL) ? VX_ERR_NAMESPACE : VX_ERR_SPAWN;
    }

    if (pid == 0) {
        close(syncpipe[1]);
        close(errpipe[0]);
        child_main(spec, syncpipe[0], errpipe[1]);
        /* unreachable */
    }

    close(syncpipe[0]);
    close(errpipe[1]);
    sb->pid = pid;

    vx_status_t st = VX_OK;
    if (spec->new_user) st = write_id_maps(pid, spec->host_uid, spec->host_gid);

    if (st == VX_OK && sb->cg.created) {
        vx_status_t cst = vx_cgroup_attach(&sb->cg, pid);
        if (cst != VX_OK) VX_WARN("cgroup attach of pid %lld failed", (long long)pid);
    }

    sb->pidfd = vx_pidfd_open(pid);

    if (st != VX_OK) {
        /* Never release the barrier on a failed setup: the guest would run
         * unmapped and unlimited. */
        close(syncpipe[1]);
        close(errpipe[0]);
        kill(pid, SIGKILL);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        sb->reaped = true;
        vx_sandbox_destroy(sb);
        return st;
    }

    /* Release the barrier. */
    ssize_t wn;
    do {
        wn = write(syncpipe[1], "1", 1);
    } while (wn < 0 && errno == EINTR);
    close(syncpipe[1]);

    /* Wait for either an exec-failure report or EOF meaning exec succeeded. */
    int payload[2] = {0, 0};
    ssize_t rn;
    do {
        rn = read(errpipe[0], payload, sizeof(payload));
    } while (rn < 0 && errno == EINTR);
    close(errpipe[0]);

    if (rn == (ssize_t)sizeof(payload)) {
        VX_ERROR("sandbox setup failed at %s: %s", stage_name(payload[0]), strerror(payload[1]));
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        sb->reaped = true;
        vx_status_t rc = (payload[0] == STAGE_EXEC) ? VX_ERR_SPAWN : VX_ERR_NAMESPACE;
        vx_sandbox_destroy(sb);
        return rc;
    }

    VX_INFO("sandbox task=%llu pid=%lld flags=0x%lx running", (unsigned long long)spec->task_id,
            (long long)pid, flags);
    return VX_OK;
}

/* ------------------------------------------------------------------------- */
/* Wait / kill / destroy                                                     */
/* ------------------------------------------------------------------------- */

/* Block until the guest exits or the deadline passes.  Returns 1 on exit,
 * 0 on timeout, negative on error.
 *
 * The fallback path reaps with WNOHANG, so it is the only one that can observe
 * the wait status; it hands it back through the status_out and have_status
 * out-params rather than dropping it, because once a child has been reaped its
 * status is gone for good. */
static int wait_for_exit(vx_sandbox_t *sb, uint32_t timeout_ms, int *status_out,
                         bool *have_status) {
    *have_status = false;
    *status_out = 0;

    if (sb->pidfd >= 0) {
        /* A pidfd is immune to pid reuse, so this cannot accidentally wait on a
         * recycled pid the way kill()/waitpid() polling can. */
        struct pollfd pfd = {.fd = sb->pidfd, .events = POLLIN, .revents = 0};
        int remaining = timeout_ms == 0 ? -1 : (int)timeout_ms;
        for (;;) {
            uint64_t before = vx_now_us();
            int rc = poll(&pfd, 1, remaining);
            if (rc < 0) {
                if (errno != EINTR) return VX_ERR_SPAWN;
                if (remaining > 0) {
                    uint64_t spent = (vx_now_us() - before) / 1000ull;
                    remaining = spent >= (uint64_t)remaining ? 0 : remaining - (int)spent;
                }
                continue;
            }
            return rc > 0 ? 1 : 0;
        }
    }

    /* Fallback for kernels without pidfd_open: poll waitpid with a bounded
     * sleep.  1ms keeps the latency cost small relative to task runtimes. */
    uint64_t deadline = timeout_ms == 0 ? 0 : vx_now_us() + (uint64_t)timeout_ms * 1000ull;
    for (;;) {
        int status = 0;
        pid_t rc = waitpid(sb->pid, &status, WNOHANG);
        if (rc == sb->pid) {
            sb->reaped = true;
            *status_out = status;
            *have_status = true;
            return 1;
        }
        if (rc < 0 && errno != EINTR) return VX_ERR_SPAWN;
        if (deadline != 0 && vx_now_us() >= deadline) return 0;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
        nanosleep(&ts, NULL);
    }
}

vx_status_t vx_sandbox_wait(vx_sandbox_t *sb, uint32_t timeout_ms, vx_sandbox_result_t *out) {
    if (sb == NULL || out == NULL) return VX_ERR_INVALID_ARG;
    if (sb->pid <= 0) return VX_ERR_INVALID_ARG;

    memset(out, 0, sizeof(*out));
    out->state = VX_STATE_RUNNING;

    int status = 0;
    bool have_status = false;
    bool timed_out = false;
    if (!sb->reaped) {
        int rc = wait_for_exit(sb, timeout_ms, &status, &have_status);
        if (rc < 0) return (vx_status_t)rc;
        if (rc == 0) {
            timed_out = true;
            VX_WARN("task %llu exceeded %ums; killing", (unsigned long long)sb->cg.task_id,
                    timeout_ms);
            /* cgroup.kill takes out the whole subtree at once; a bare
             * kill(pid) would miss grandchildren that re-parented. */
            if (vx_cgroup_kill_all(&sb->cg) != VX_OK) kill(sb->pid, SIGKILL);
        }
    }

    if (!have_status) {
        while (waitpid(sb->pid, &status, 0) < 0) {
            if (errno == ECHILD) break;
            if (errno != EINTR) return VX_ERR_SPAWN;
        }
        sb->reaped = true;
    }

    out->duration_us = vx_now_us() - sb->started_us;

    /* Read usage while the cgroup still exists — destroy() will remove it. */
    if (sb->cg.created) vx_cgroup_read_stats(&sb->cg, &out->usage);

    if (timed_out) {
        out->state = VX_STATE_KILLED_TIMEOUT;
        out->term_signal = SIGKILL;
        out->exit_code = 128 + SIGKILL;
    } else if (WIFEXITED(status)) {
        out->exit_code = WEXITSTATUS(status);
        out->state = out->exit_code == 0 ? VX_STATE_COMPLETED : VX_STATE_FAILED;
    } else if (WIFSIGNALED(status)) {
        out->term_signal = WTERMSIG(status);
        out->exit_code = 128 + out->term_signal;
        /* A SIGKILL plus a non-zero oom_kill counter is the kernel's OOM
         * killer, not the supervisor's — report it as such so the caller can
         * distinguish "needs more memory" from "crashed". */
        out->state = (out->usage.oom_kill > 0) ? VX_STATE_KILLED_OOM : VX_STATE_KILLED_SIGNAL;
    } else {
        out->state = VX_STATE_FAILED;
        out->exit_code = -1;
    }

    VX_INFO("task %llu -> %s exit=%d %lluus mem_peak=%lluB cpu=%lluus",
            (unsigned long long)sb->cg.task_id, vx_state_str(out->state), out->exit_code,
            (unsigned long long)out->duration_us, (unsigned long long)out->usage.memory_peak,
            (unsigned long long)out->usage.cpu_usage_us);
    return VX_OK;
}

vx_status_t vx_sandbox_kill(vx_sandbox_t *sb, int signo) {
    if (sb == NULL || sb->pid <= 0) return VX_ERR_INVALID_ARG;
    if (sb->reaped) return VX_OK;

    if (sb->pidfd >= 0 && vx_pidfd_send_signal(sb->pidfd, signo) == 0) return VX_OK;
    if (kill(sb->pid, signo) != 0) return vx_status_from_errno(errno);
    return VX_OK;
}

vx_status_t vx_sandbox_destroy(vx_sandbox_t *sb) {
    if (sb == NULL) return VX_ERR_INVALID_ARG;

    if (sb->pid > 0 && !sb->reaped) {
        vx_sandbox_kill(sb, SIGKILL);
        int status = 0;
        while (waitpid(sb->pid, &status, 0) < 0) {
            if (errno == ECHILD) break;
            if (errno != EINTR) break;
        }
        sb->reaped = true;
    }
    if (sb->pidfd >= 0) {
        close(sb->pidfd);
        sb->pidfd = -1;
    }
    vx_status_t st = VX_OK;
    if (sb->cg.created) st = vx_cgroup_destroy(&sb->cg);
    sb->pid = -1;
    return st;
}
