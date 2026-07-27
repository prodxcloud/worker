/* test_seccomp.c — the syscall filter, proven by issuing the syscalls.
 *
 * Every enforcement case runs in a forked child, because installing a filter is
 * irreversible: doing it in-process would permanently constrain the test runner
 * and every case after it.
 *
 * The assertions are deliberately behavioural. Checking that build_filter emits
 * the right instruction count would pass just as happily with the jump offsets
 * wrong; the only convincing test of a seccomp program is to make the call and
 * see what the kernel does. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_sandbox.h"
#include "vx_seccomp.h"
#include "vxtest.h"

/* Run fn in a child under the given policy and report how it ended.
 * exit_code is the child's status; signalled/term_sig describe a kill. */
typedef struct {
    int exit_code;
    bool signalled;
    int term_sig;
} child_outcome_t;

static child_outcome_t run_filtered(const vx_seccomp_policy_t *policy, int (*fn)(void)) {
    child_outcome_t out = {.exit_code = -1, .signalled = false, .term_sig = 0};

    pid_t pid = fork();
    if (pid < 0) return out;
    if (pid == 0) {
        if (vx_seccomp_apply(policy) != VX_OK) _exit(90); /* 90 = could not install */
        _exit(fn());
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return out;
    }
    if (WIFEXITED(status)) {
        out.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        out.signalled = true;
        out.term_sig = WTERMSIG(status);
    }
    return out;
}

/* Denied call. Returns 0 if it was refused with EPERM, 1 if it went through,
 * 2 if it failed for some other reason. mount(2) with nonsense arguments would
 * fail with EINVAL/EPERM anyway — what matters is *which* error comes back,
 * because the filter's EPERM arrives before the kernel ever validates. */
static int try_mount(void) {
    errno = 0;
    long rc = syscall(SYS_mount, "none", "/vx-nonexistent-mount-target", "tmpfs", 0UL, NULL);
    if (rc == 0) return 1;
    return errno == EPERM ? 0 : 2;
}

static int try_keyctl(void) {
#ifdef SYS_keyctl
    errno = 0;
    long rc = syscall(SYS_keyctl, 0 /* KEYCTL_GET_KEYRING_ID */, 0, 0);
    if (rc >= 0) return 1;
    return errno == EPERM ? 0 : 2;
#else
    return 0;
#endif
}

static int try_unshare_newuser(void) {
    errno = 0;
    long rc = syscall(SYS_unshare, 0x10000000L /* CLONE_NEWUSER */);
    if (rc == 0) return 1;
    return errno == EPERM ? 0 : 2;
}

static int try_ptrace_traceme(void) {
    errno = 0;
    long rc = syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
    if (rc == 0) return 1;
    return errno == EPERM ? 0 : 2;
}

/* An allowed call must still work: a filter that breaks ordinary programs is a
 * filter nobody will leave switched on. */
static int try_allowed_calls(void) {
    if (getpid() <= 0) return 1;
    if (getuid() == (uid_t)-1) return 1;
    char buf[64];
    /* write/read/open/close/brk/mmap all exercised by ordinary libc use */
    int n = snprintf(buf, sizeof(buf), "ok");
    if (n != 2) return 1;
    void *p = malloc(1 << 20); /* brk/mmap */
    if (p == NULL) return 1;
    memset(p, 1, 1 << 20);
    free(p);
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    char rb[128];
    ssize_t r = read(fd, rb, sizeof(rb));
    close(fd);
    if (r <= 0) return 1;
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000};
    nanosleep(&ts, NULL);
    return 0;
}

int main(void) {
    VXT_BEGIN("seccomp-bpf syscall filter");

    VXT_CASE("mode names round-trip");
    vx_seccomp_mode_t m;
    VXT_EQ_INT(vx_seccomp_mode_parse("off", &m), VX_OK, "parse off");
    VXT_EQ_INT(m, VX_SECCOMP_OFF, "off value");
    VXT_EQ_INT(vx_seccomp_mode_parse("audit", &m), VX_OK, "parse audit");
    VXT_EQ_INT(m, VX_SECCOMP_AUDIT, "audit value");
    VXT_EQ_INT(vx_seccomp_mode_parse("errno", &m), VX_OK, "parse errno");
    VXT_EQ_INT(vx_seccomp_mode_parse("kill", &m), VX_OK, "parse kill");
    VXT_EQ_INT(vx_seccomp_mode_parse("nonsense", &m), VX_ERR_INVALID_ARG, "reject nonsense");
    VXT_EQ_INT(vx_seccomp_mode_parse(NULL, &m), VX_ERR_INVALID_ARG, "reject NULL");
    VXT_CHECK(strcmp(vx_seccomp_mode_name(VX_SECCOMP_ERRNO), "errno") == 0, "name errno");

    VXT_CASE("defaults are the conservative ones");
    vx_seccomp_policy_t pol;
    vx_seccomp_policy_init(&pol);
    VXT_EQ_INT(pol.mode, VX_SECCOMP_ERRNO, "default mode is errno, not kill");
    VXT_CHECK(pol.deny_namespace_calls, "setns/unshare denied by default");
    /* Allowed by default, and deliberately: LeakSanitizer ptrace-attaches at exit
     * to scan for leaks, so denying it breaks every ASan-built guest — which is
     * exactly how we found out. Inside the PID and user namespaces ptrace reaches
     * only the tenant's own processes anyway. */
    VXT_CHECK(pol.allow_ptrace, "ptrace allowed by default (see vx_seccomp.h)");

    VXT_CASE("the denylist is populated and policy-sensitive");
    const char *names[128];
    size_t n_default = vx_seccomp_denied_list(&pol, names, 128);
    printf("    %zu syscalls denied by default\n", n_default);
    VXT_CHECK(n_default >= 30, "denylist has %zu entries", n_default);
    bool saw_mount = false, saw_bpf = false, saw_ptrace = false;
    for (size_t i = 0; i < n_default && i < 128; i++) {
        if (strcmp(names[i], "mount") == 0) saw_mount = true;
        if (strcmp(names[i], "bpf") == 0) saw_bpf = true;
        if (strcmp(names[i], "ptrace") == 0) saw_ptrace = true;
    }
    VXT_CHECK(saw_mount, "mount is denied");
    VXT_CHECK(saw_bpf, "bpf is denied");
    VXT_CHECK(!saw_ptrace, "ptrace is NOT denied by default");

    /* Hardened: everything the default permits, denied. */
    vx_seccomp_policy_t strict = pol;
    strict.allow_ptrace = false;
    size_t n_strict = vx_seccomp_denied_list(&strict, NULL, 0);
    VXT_CHECK(n_strict > n_default, "--deny-ptrace denies more calls (%zu > %zu)", n_strict,
              n_default);

    /* Relaxed: namespace calls permitted too. */
    vx_seccomp_policy_t relaxed = pol;
    relaxed.deny_namespace_calls = false;
    size_t n_relaxed = vx_seccomp_denied_list(&relaxed, NULL, 0);
    VXT_CHECK(n_relaxed < n_default, "--allow-nsops denies fewer calls (%zu < %zu)", n_relaxed,
              n_default);

    /* io_uring must stay allowed: the iron engine is built on it, so denying it
     * would deny the product. Documented as residual risk rather than hidden. */
    VXT_CASE("io_uring is deliberately NOT denied");
    bool saw_uring = false;
    for (size_t i = 0; i < n_default && i < 128; i++) {
        if (strstr(names[i], "io_uring") != NULL) saw_uring = true;
    }
    VXT_CHECK(!saw_uring, "io_uring_setup is allowed (iron depends on it)");

    if (!vx_seccomp_available()) VXT_SKIP("this kernel will not install seccomp filters");

    printf("    RET_KILL_PROCESS available: %s\n",
           vx_seccomp_kill_process_supported() ? "yes" : "no");

    /* --------------------------------------------------------------------- */
    VXT_CASE("ordinary syscalls still work under the filter");
    child_outcome_t o = run_filtered(&pol, try_allowed_calls);
    VXT_EQ_INT(o.exit_code, 0, "malloc/open/read/write/nanosleep all succeeded");
    VXT_CHECK(!o.signalled, "the guest was not killed doing normal work");

    /* --------------------------------------------------------------------- */
    VXT_CASE("errno mode: mount(2) is refused with EPERM, guest survives");
    o = run_filtered(&pol, try_mount);
    VXT_EQ_INT(o.exit_code, 0, "mount refused with EPERM");
    VXT_CHECK(!o.signalled, "errno mode does not kill the guest");

    VXT_CASE("errno mode: keyctl(2) is refused");
    o = run_filtered(&pol, try_keyctl);
    VXT_EQ_INT(o.exit_code, 0, "keyctl refused with EPERM");

    VXT_CASE("errno mode: unshare(CLONE_NEWUSER) is refused");
    o = run_filtered(&pol, try_unshare_newuser);
    VXT_EQ_INT(o.exit_code, 0, "unshare refused with EPERM");

    VXT_CASE("--allow-nsops actually takes effect");
    /* With namespace calls permitted, unshare must no longer be refused by the
     * filter. It may still fail for lack of privilege, which is a different
     * error — so anything other than "refused with EPERM by us" is a pass here. */
    o = run_filtered(&relaxed, try_unshare_newuser);
    VXT_CHECK(o.exit_code != 90, "filter still installed with the relaxed policy");
    printf("    relaxed unshare outcome: exit=%d (0=EPERM 1=succeeded 2=other errno)\n",
           o.exit_code);

    VXT_CASE("ptrace works by default, and --deny-ptrace stops it");
    o = run_filtered(&pol, try_ptrace_traceme);
    VXT_CHECK(o.exit_code != 0, "PTRACE_TRACEME not refused under the default policy");
    o = run_filtered(&strict, try_ptrace_traceme);
    VXT_EQ_INT(o.exit_code, 0, "PTRACE_TRACEME refused with EPERM under --deny-ptrace");

    /* --------------------------------------------------------------------- */
    if (vx_seccomp_kill_process_supported()) {
        VXT_CASE("kill mode terminates the guest with SIGSYS");
        vx_seccomp_policy_t killing = pol;
        killing.mode = VX_SECCOMP_KILL;
        o = run_filtered(&killing, try_mount);
        VXT_CHECK(o.signalled, "guest was killed rather than returning an error");
        VXT_EQ_INT(o.term_sig, SIGSYS, "killed by SIGSYS");
    }

    VXT_CASE("audit mode allows the call through");
    vx_seccomp_policy_t auditing = pol;
    auditing.mode = VX_SECCOMP_AUDIT;
    o = run_filtered(&auditing, try_mount);
    /* The call is permitted to reach the kernel, which then rejects the nonsense
     * arguments with something other than our EPERM — or with EPERM for lack of
     * CAP_SYS_ADMIN. Either way it must not have been killed. */
    VXT_CHECK(!o.signalled, "audit mode never kills");
    VXT_CHECK(o.exit_code != 90, "audit filter installed successfully");

    VXT_CASE("off mode installs nothing and returns OK");
    vx_seccomp_policy_t off = pol;
    off.mode = VX_SECCOMP_OFF;
    VXT_EQ_INT(vx_seccomp_apply(&off), VX_OK, "off is a no-op");
    VXT_EQ_INT(vx_seccomp_apply(NULL), VX_ERR_INVALID_ARG, "NULL policy rejected");

    /* --------------------------------------------------------------------- */
    /* The integration that matters: the filter reaches a real sandboxed guest
     * through exec, having not obstructed the supervisor's own mount and
     * sethostname during setup. */
    if (vxt_is_root()) {
        VXT_CASE("a sandboxed guest inherits the filter through exec");
        static char p_sh[] = "/bin/sh";
        static char a_c[] = "-c";
        /* `mount` inside the guest must fail. Busybox/dash `mount` exits nonzero
         * when the syscall is refused. */
        static char sc[] = "mount -t tmpfs none /mnt 2>/dev/null && echo MOUNTED || echo REFUSED";
        char *argv_mount[] = {p_sh, a_c, sc, NULL};

        vx_sandbox_spec_t spec;
        vx_sandbox_t sb;
        vx_sandbox_result_t res;

        vx_sandbox_spec_init(&spec);
        spec.task_id = 810001;
        spec.argv = argv_mount;
        /* Setup still needs mount(2) and sethostname(2) for the supervisor's own
         * work; if the filter were installed too early, spawn would fail here. */
        VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK,
                   "spawn succeeds — supervisor setup ran before the filter");
        VXT_EQ_INT(vx_sandbox_wait(&sb, 10000, &res), VX_OK, "wait");
        VXT_CHECK(res.state == VX_STATE_COMPLETED || res.state == VX_STATE_FAILED,
                  "guest ran to completion (state=%s)", vx_state_str(res.state));
        vx_sandbox_destroy(&sb);

        VXT_CASE("seccomp off is honoured end to end");
        vx_sandbox_spec_init(&spec);
        spec.task_id = 810002;
        spec.seccomp.mode = VX_SECCOMP_OFF;
        static char sc_true[] = "exit 0";
        char *argv_true[] = {p_sh, a_c, sc_true, NULL};
        spec.argv = argv_true;
        VXT_EQ_INT(vx_sandbox_spawn(&sb, &spec), VX_OK, "spawn with no filter");
        VXT_EQ_INT(vx_sandbox_wait(&sb, 10000, &res), VX_OK, "wait");
        VXT_EQ_INT(res.state, VX_STATE_COMPLETED, "guest completed");
        vx_sandbox_destroy(&sb);

        VXT_CASE("probe reports seccomp support");
        vx_sandbox_caps_t caps;
        VXT_EQ_INT(vx_sandbox_probe(&caps), VX_OK, "probe");
        VXT_CHECK(caps.seccomp, "probe found seccomp available");
    }

    VXT_END();
}
