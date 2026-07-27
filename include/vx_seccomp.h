/* vx_seccomp.h — seccomp-bpf syscall filtering.
 *
 * Namespaces and cgroups bound what a task can *reach* and *consume*. They say
 * nothing about which system calls it may issue, and the kernel's syscall
 * surface is itself attack surface: every year brings another privilege
 * escalation reachable from an unprivileged context. This is the layer that
 * closes that gap.
 *
 * DENYLIST, NOT ALLOWLIST — and that is a deliberate choice.
 *
 * A minimal allowlist is the stronger construction, and it is the right one when
 * you know what the guest is: you enumerate the forty syscalls your own binary
 * makes and refuse the rest. VxCloud does not know what the guest is. It runs
 * arbitrary tenant code — a Rust micro-worker, a C++ engine, headless Chromium,
 * somebody's Python script — and an allowlist tight enough to be worth having
 * would break most of them, at which point operators disable it and the security
 * value is zero.
 *
 * So this filter denies the syscalls that are unambiguously dangerous and that
 * no ordinary program needs: loading kernel modules, reconfiguring mounts,
 * rebooting, setting the clock, joining namespaces, touching IO ports, and the
 * kernel-introspection interfaces (bpf, perf_event_open, userfaultfd) that keep
 * appearing in escape chains. This is the same shape as Docker's default
 * profile, for the same reason.
 *
 * Several denied calls would already fail with EPERM inside the user namespace
 * for want of a capability. Denying them anyway is defence in depth: it holds if
 * a capability is ever granted, and it turns a kernel-side check into a
 * userspace-side one that cannot be reached at all.
 *
 * The filter is applied in the child between the mount/hostname setup and
 * execvp(), because that setup legitimately calls mount(2) and sethostname(2) —
 * the very calls the guest must not have. It survives exec by design, and cannot
 * be lifted afterwards. */
#ifndef VX_SECCOMP_H
#define VX_SECCOMP_H

#include <stdbool.h>
#include <stddef.h>

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What happens when the guest issues a denied syscall.
 *
 * AUDIT exists because turning a filter on blind is how you discover in
 * production that some dependency calls keyctl(2) on startup. Run AUDIT, read
 * the kernel log, then enforce. */
typedef enum {
    VX_SECCOMP_OFF = 0,   /* no filter installed                             */
    VX_SECCOMP_AUDIT = 1, /* allow, but log to the audit subsystem            */
    VX_SECCOMP_ERRNO = 2, /* fail the call with EPERM; the guest keeps running */
    VX_SECCOMP_KILL = 3   /* kill the whole guest process                     */
} vx_seccomp_mode_t;

typedef struct {
    vx_seccomp_mode_t mode;

    /* ptrace(2) and process_vm_readv/writev: how a debugger works, and also how
     * one process reads another's memory.
     *
     * ALLOWED by default, which is not the obvious choice, so here is the
     * reasoning. Inside the sandbox's PID and user namespaces, ptrace can only
     * reach the tenant's own processes — processes it already controls
     * completely. Another tenant is unreachable: different PID namespace,
     * different host uid. The classic ptrace escalation route, attaching to a
     * setuid binary, is closed separately by PR_SET_NO_NEW_PRIVS, which
     * vx_seccomp_apply() always sets.
     *
     * Against that small gain, denying it breaks real tooling. LeakSanitizer
     * calls ptrace(PTRACE_ATTACH) at exit to stop threads and scan for leaks, so
     * *every* ASan-instrumented guest fails under a ptrace-denying filter — we
     * found this by running our own test suite under ASan inside the sandbox.
     * gdb, perf and any profiler are affected the same way. Docker's default
     * profile permits ptrace for the same reason.
     *
     * Set false for a hardened deployment that runs no debuggers. */
    bool allow_ptrace;

    /* Deny setns/unshare so the guest cannot construct further namespaces.
     * Nesting is not itself an escape, but it is a common step in one, and a
     * task runner has no reason to need it. Set false only for a guest that
     * legitimately sandboxes its own children. */
    bool deny_namespace_calls;
} vx_seccomp_policy_t;

/* Fill with the recommended defaults: ERRNO mode, ptrace allowed (see above),
 * namespace calls denied.
 *
 * ERRNO rather than KILL is deliberate. A killed process gives an operator a
 * bare SIGSYS and no idea which call was responsible; EPERM is a failure the
 * guest can report, and it is what Docker returns. Use KILL when a denied call
 * should be treated as a compromise rather than a bug. */
void vx_seccomp_policy_init(vx_seccomp_policy_t *policy);

/* Parse "off", "audit", "errno" or "kill". Returns VX_ERR_INVALID_ARG on
 * anything else. */
vx_status_t vx_seccomp_mode_parse(const char *name, vx_seccomp_mode_t *out);

const char *vx_seccomp_mode_name(vx_seccomp_mode_t mode);

/* True when this kernel supports seccomp filtering at all.  Probed by actually
 * attempting an installation in a throwaway child, because the syscall can be
 * compiled in but disabled by policy. */
bool vx_seccomp_available(void);

/* True when the kernel supports SECCOMP_RET_KILL_PROCESS (5.x+) and the audit
 * log action.  Older kernels silently degrade to killing only the calling
 * thread, which leaves the rest of the guest running — worth knowing about. */
bool vx_seccomp_kill_process_supported(void);

/* Install the filter on the calling thread.
 *
 * Must be called after any privileged setup the *supervisor* needs to do in the
 * child, and before execvp(). Sets PR_SET_NO_NEW_PRIVS first, which is required
 * for an unprivileged filter and independently stops a setuid binary from
 * gaining privilege through exec.
 *
 * Async-signal-safe: builds the program on the stack and issues two prctl/seccomp
 * syscalls. No allocation, so it is safe between clone() and exec(). */
vx_status_t vx_seccomp_apply(const vx_seccomp_policy_t *policy);

/* Number of syscalls the policy denies, and their names — for `vxworker probe`
 * and for documentation that cannot drift from the code. Returns the count;
 * pass out=NULL to query the count alone. */
size_t vx_seccomp_denied_list(const vx_seccomp_policy_t *policy, const char **out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* VX_SECCOMP_H */
