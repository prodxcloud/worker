/* vx_seccomp.c — hand-assembled seccomp-bpf filter, no libseccomp.
 *
 * libseccomp would be one apt package and forty fewer lines, but this project's
 * whole premise is libc plus the kernel, and the program below is small enough
 * to read in one sitting. Hand-assembling it also means the exact instruction
 * sequence — including the architecture check that closes the x32 bypass — is
 * visible rather than trusted. */
#include "vx_seccomp.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"

/* ------------------------------------------------------------------------- */
/* Architecture                                                              */
/* ------------------------------------------------------------------------- */

#if defined(__x86_64__)
#define VX_AUDIT_ARCH AUDIT_ARCH_X86_64
/* On x86-64 the same kernel serves three ABIs. A filter that checks only the
 * syscall number can be sidestepped by issuing the call through the x32 or
 * i386 entry point, where the numbers mean something else entirely — the
 * classic seccomp bypass. Pinning the arch and rejecting the x32 bit closes it. */
#define VX_HAS_X32_BIT 1
#elif defined(__aarch64__)
#define VX_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define VX_HAS_X32_BIT 0
#else
#error "vx_seccomp: unsupported architecture"
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG (1UL << 1)
#endif
#ifndef X32_SYSCALL_BIT
#define X32_SYSCALL_BIT 0x40000000
#endif

/* ------------------------------------------------------------------------- */
/* The denylist                                                              */
/* ------------------------------------------------------------------------- */

/* Grouped by why, because "which syscalls" is the easy half of the question.
 * Every entry is guarded so the file still builds against older kernel headers
 * that predate the call. */
typedef struct {
    const char *name;
    int nr;
    unsigned char group;
} vx_denied_call_t;

#define VXG_MODULE 1    /* load or unload kernel code                        */
#define VXG_MACHINE 2   /* reboot, power, clock — host-wide state            */
#define VXG_MOUNT 3     /* reconfigure the filesystem view                   */
#define VXG_NAMESPACE 4 /* join or create namespaces                         */
#define VXG_IDENTITY 5  /* host name and domain                              */
#define VXG_HARDWARE 6  /* direct IO port access                             */
#define VXG_KERNEL 7    /* kernel introspection: bpf, perf, userfaultfd      */
#define VXG_KEYRING 8   /* kernel keyring                                    */
#define VXG_TRACE 9     /* read or write another process (opt-in)            */
#define VXG_MISC 10     /* accounting, quotas, obsolete interfaces           */

/* clang-format off */
static const vx_denied_call_t vx_denied[] = {
    /* Loading kernel code into the host is game over for any sandbox. */
#ifdef __NR_init_module
    {"init_module", __NR_init_module, VXG_MODULE},
#endif
#ifdef __NR_finit_module
    {"finit_module", __NR_finit_module, VXG_MODULE},
#endif
#ifdef __NR_delete_module
    {"delete_module", __NR_delete_module, VXG_MODULE},
#endif
#ifdef __NR_create_module
    {"create_module", __NR_create_module, VXG_MODULE},
#endif
#ifdef __NR_get_kernel_syms
    {"get_kernel_syms", __NR_get_kernel_syms, VXG_MODULE},
#endif
#ifdef __NR_query_module
    {"query_module", __NR_query_module, VXG_MODULE},
#endif

    /* Host-wide state. A task must not be able to reboot the node, load a new
     * kernel, or move the clock — the last of which quietly breaks TLS
     * validation and every certificate expiry check on the box. */
#ifdef __NR_reboot
    {"reboot", __NR_reboot, VXG_MACHINE},
#endif
#ifdef __NR_kexec_load
    {"kexec_load", __NR_kexec_load, VXG_MACHINE},
#endif
#ifdef __NR_kexec_file_load
    {"kexec_file_load", __NR_kexec_file_load, VXG_MACHINE},
#endif
#ifdef __NR_settimeofday
    {"settimeofday", __NR_settimeofday, VXG_MACHINE},
#endif
#ifdef __NR_clock_settime
    {"clock_settime", __NR_clock_settime, VXG_MACHINE},
#endif
#ifdef __NR_clock_adjtime
    {"clock_adjtime", __NR_clock_adjtime, VXG_MACHINE},
#endif
#ifdef __NR_adjtimex
    {"adjtimex", __NR_adjtimex, VXG_MACHINE},
#endif
#ifdef __NR_swapon
    {"swapon", __NR_swapon, VXG_MACHINE},
#endif
#ifdef __NR_swapoff
    {"swapoff", __NR_swapoff, VXG_MACHINE},
#endif

    /* The supervisor sets up the mount namespace before installing this filter;
     * the guest has no business changing it afterwards. The newer mount API
     * (fsopen/fsconfig/move_mount) is included because denying only mount(2)
     * leaves the modern path wide open. */
#ifdef __NR_mount
    {"mount", __NR_mount, VXG_MOUNT},
#endif
#ifdef __NR_umount2
    {"umount2", __NR_umount2, VXG_MOUNT},
#endif
#ifdef __NR_pivot_root
    {"pivot_root", __NR_pivot_root, VXG_MOUNT},
#endif
#ifdef __NR_chroot
    {"chroot", __NR_chroot, VXG_MOUNT},
#endif
#ifdef __NR_mount_setattr
    {"mount_setattr", __NR_mount_setattr, VXG_MOUNT},
#endif
#ifdef __NR_open_tree
    {"open_tree", __NR_open_tree, VXG_MOUNT},
#endif
#ifdef __NR_move_mount
    {"move_mount", __NR_move_mount, VXG_MOUNT},
#endif
#ifdef __NR_fsopen
    {"fsopen", __NR_fsopen, VXG_MOUNT},
#endif
#ifdef __NR_fsconfig
    {"fsconfig", __NR_fsconfig, VXG_MOUNT},
#endif
#ifdef __NR_fsmount
    {"fsmount", __NR_fsmount, VXG_MOUNT},
#endif
#ifdef __NR_fspick
    {"fspick", __NR_fspick, VXG_MOUNT},
#endif
    /* Turns an open directory fd into a path-independent handle, historically a
     * route out of a chroot. */
#ifdef __NR_open_by_handle_at
    {"open_by_handle_at", __NR_open_by_handle_at, VXG_MOUNT},
#endif
#ifdef __NR_name_to_handle_at
    {"name_to_handle_at", __NR_name_to_handle_at, VXG_MOUNT},
#endif

    /* Namespace joining and creation. */
#ifdef __NR_setns
    {"setns", __NR_setns, VXG_NAMESPACE},
#endif
#ifdef __NR_unshare
    {"unshare", __NR_unshare, VXG_NAMESPACE},
#endif

#ifdef __NR_sethostname
    {"sethostname", __NR_sethostname, VXG_IDENTITY},
#endif
#ifdef __NR_setdomainname
    {"setdomainname", __NR_setdomainname, VXG_IDENTITY},
#endif

    /* Raw IO port access is a direct path to the hardware. */
#ifdef __NR_iopl
    {"iopl", __NR_iopl, VXG_HARDWARE},
#endif
#ifdef __NR_ioperm
    {"ioperm", __NR_ioperm, VXG_HARDWARE},
#endif
#ifdef __NR_modify_ldt
    {"modify_ldt", __NR_modify_ldt, VXG_HARDWARE},
#endif

    /* Kernel introspection. These are the interfaces that keep turning up in
     * escape chains: bpf(2) and perf_event_open(2) have both produced local
     * privilege escalations, and userfaultfd is the standard tool for winning
     * kernel race conditions by stalling a page fault at will.
     *
     * Note what is deliberately NOT here: io_uring_setup. The iron engine is
     * built on io_uring, so denying it would deny the product. That is a real
     * residual risk and it is documented rather than hidden. */
#ifdef __NR_bpf
    {"bpf", __NR_bpf, VXG_KERNEL},
#endif
#ifdef __NR_perf_event_open
    {"perf_event_open", __NR_perf_event_open, VXG_KERNEL},
#endif
#ifdef __NR_userfaultfd
    {"userfaultfd", __NR_userfaultfd, VXG_KERNEL},
#endif
#ifdef __NR_fanotify_init
    {"fanotify_init", __NR_fanotify_init, VXG_KERNEL},
#endif
#ifdef __NR_lookup_dcookie
    {"lookup_dcookie", __NR_lookup_dcookie, VXG_KERNEL},
#endif
#ifdef __NR_kcmp
    {"kcmp", __NR_kcmp, VXG_KERNEL},
#endif

    /* The kernel keyring is shared state with the host. */
#ifdef __NR_add_key
    {"add_key", __NR_add_key, VXG_KEYRING},
#endif
#ifdef __NR_request_key
    {"request_key", __NR_request_key, VXG_KEYRING},
#endif
#ifdef __NR_keyctl
    {"keyctl", __NR_keyctl, VXG_KEYRING},
#endif

    /* Reading or writing another process's memory. Denied unless allow_ptrace. */
#ifdef __NR_ptrace
    {"ptrace", __NR_ptrace, VXG_TRACE},
#endif
#ifdef __NR_process_vm_readv
    {"process_vm_readv", __NR_process_vm_readv, VXG_TRACE},
#endif
#ifdef __NR_process_vm_writev
    {"process_vm_writev", __NR_process_vm_writev, VXG_TRACE},
#endif

#ifdef __NR_acct
    {"acct", __NR_acct, VXG_MISC},
#endif
#ifdef __NR_quotactl
    {"quotactl", __NR_quotactl, VXG_MISC},
#endif
#ifdef __NR_vhangup
    {"vhangup", __NR_vhangup, VXG_MISC},
#endif
#ifdef __NR_syslog
    {"syslog", __NR_syslog, VXG_MISC},
#endif
#ifdef __NR_uselib
    {"uselib", __NR_uselib, VXG_MISC},
#endif
#ifdef __NR_nfsservctl
    {"nfsservctl", __NR_nfsservctl, VXG_MISC},
#endif
#ifdef __NR_personality
    /* Can request a legacy ABI personality, which changes how the kernel
     * interprets later calls — including relaxing address-space randomisation. */
    {"personality", __NR_personality, VXG_MISC},
#endif
};
/* clang-format on */

#define VX_DENIED_COUNT (sizeof(vx_denied) / sizeof(vx_denied[0]))

/* Is this entry active under the given policy? */
static bool denied_under(const vx_seccomp_policy_t *p, const vx_denied_call_t *c) {
    if (c->group == VXG_TRACE && p->allow_ptrace) return false;
    if (c->group == VXG_NAMESPACE && !p->deny_namespace_calls) return false;
    return true;
}

/* ------------------------------------------------------------------------- */
/* Policy plumbing                                                           */
/* ------------------------------------------------------------------------- */

void vx_seccomp_policy_init(vx_seccomp_policy_t *policy) {
    if (policy == NULL) return;
    memset(policy, 0, sizeof(*policy));
    policy->mode = VX_SECCOMP_ERRNO;
    /* Allowed by default — see the field comment in vx_seccomp.h. Denying it
     * breaks LeakSanitizer, gdb and perf while buying almost nothing, because
     * ptrace inside the namespaces reaches only the tenant's own processes. */
    policy->allow_ptrace = true;
    policy->deny_namespace_calls = true;
}

const char *vx_seccomp_mode_name(vx_seccomp_mode_t mode) {
    switch (mode) {
    case VX_SECCOMP_OFF:
        return "off";
    case VX_SECCOMP_AUDIT:
        return "audit";
    case VX_SECCOMP_ERRNO:
        return "errno";
    case VX_SECCOMP_KILL:
        return "kill";
    default:
        return "unknown";
    }
}

vx_status_t vx_seccomp_mode_parse(const char *name, vx_seccomp_mode_t *out) {
    if (name == NULL || out == NULL) return VX_ERR_INVALID_ARG;
    if (strcmp(name, "off") == 0)
        *out = VX_SECCOMP_OFF;
    else if (strcmp(name, "audit") == 0)
        *out = VX_SECCOMP_AUDIT;
    else if (strcmp(name, "errno") == 0)
        *out = VX_SECCOMP_ERRNO;
    else if (strcmp(name, "kill") == 0)
        *out = VX_SECCOMP_KILL;
    else
        return VX_ERR_INVALID_ARG;
    return VX_OK;
}

size_t vx_seccomp_denied_list(const vx_seccomp_policy_t *policy, const char **out, size_t out_len) {
    vx_seccomp_policy_t fallback;
    if (policy == NULL) {
        vx_seccomp_policy_init(&fallback);
        policy = &fallback;
    }
    size_t n = 0;
    for (size_t i = 0; i < VX_DENIED_COUNT; i++) {
        if (!denied_under(policy, &vx_denied[i])) continue;
        if (out != NULL && n < out_len) out[n] = vx_denied[i].name;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* Filter construction                                                       */
/* ------------------------------------------------------------------------- */

static uint32_t deny_action(vx_seccomp_mode_t mode) {
    switch (mode) {
    case VX_SECCOMP_AUDIT:
        return SECCOMP_RET_LOG;
    case VX_SECCOMP_KILL:
        return vx_seccomp_kill_process_supported() ? SECCOMP_RET_KILL_PROCESS
                                                   : SECCOMP_RET_KILL_THREAD;
    case VX_SECCOMP_ERRNO:
    default:
        return SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA);
    }
}

/* Room for the prologue, every denied call, and the two terminal returns. */
#define VX_FILTER_MAX (VX_DENIED_COUNT + 8)

/* Assemble the program.
 *
 *   0: A = seccomp_data.arch
 *   1: if A == our arch, continue, else kill        <- closes the x32/i386 bypass
 *   3: A = seccomp_data.nr
 *   4: if A >= X32_SYSCALL_BIT, kill                (x86-64 only)
 *   n: for each denied nr: if A == nr, jump to DENY
 *   -: return ALLOW
 * DENY: return <deny action>
 *
 * Jump offsets are relative to the instruction *after* the jump, and are 8-bit,
 * so the denylist must stay under 255 entries. It is around fifty.
 */
static size_t build_filter(const vx_seccomp_policy_t *policy, struct sock_filter *out) {
    size_t i = 0;

    /* Architecture gate. */
    out[i++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    out[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, VX_AUDIT_ARCH, 1, 0);
    out[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Syscall number. */
    out[i++] =
        (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

#if VX_HAS_X32_BIT
    out[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1);
    out[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

    /* Count the active entries first: each comparison's jump distance to DENY
     * depends on how many comparisons follow it. */
    size_t active = vx_seccomp_denied_list(policy, NULL, 0);
    size_t first_cmp = i;
    size_t deny_idx = first_cmp + active + 1; /* +1 for the ALLOW return */

    for (size_t k = 0; k < VX_DENIED_COUNT; k++) {
        if (!denied_under(policy, &vx_denied[k])) continue;
        size_t here = i;
        unsigned char jt = (unsigned char)(deny_idx - here - 1);
        out[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                (unsigned)vx_denied[k].nr, jt, 0);
    }

    out[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    out[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, deny_action(policy->mode));

    return i;
}

/* ------------------------------------------------------------------------- */
/* Capability probing                                                        */
/* ------------------------------------------------------------------------- */

/* Ask the kernel whether an action is recognised. SECCOMP_GET_ACTION_AVAIL is
 * the supported way to feature-test an action without installing anything. */
static bool action_available(uint32_t action) {
#ifdef SECCOMP_GET_ACTION_AVAIL
    return syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0;
#else
    (void)action;
    return false;
#endif
}

bool vx_seccomp_kill_process_supported(void) {
    return action_available(SECCOMP_RET_KILL_PROCESS);
}

bool vx_seccomp_available(void) {
    /* Probe in a throwaway child: a successful installation is irreversible, so
     * this cannot be tested in-process without permanently constraining the
     * supervisor itself. */
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        vx_seccomp_policy_t p;
        vx_seccomp_policy_init(&p);
        p.mode = VX_SECCOMP_ERRNO;
        _exit(vx_seccomp_apply(&p) == VX_OK ? 0 : 1);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ------------------------------------------------------------------------- */
/* Apply                                                                     */
/* ------------------------------------------------------------------------- */

vx_status_t vx_seccomp_apply(const vx_seccomp_policy_t *policy) {
    if (policy == NULL) return VX_ERR_INVALID_ARG;
    if (policy->mode == VX_SECCOMP_OFF) return VX_OK;

    /* Required before an unprivileged process may install a filter, and
     * independently valuable: it stops a setuid binary reached through exec from
     * gaining privilege, which is the other half of confining a guest. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return VX_ERR_UNSUPPORTED;
    }

    struct sock_filter filter[VX_FILTER_MAX];
    size_t len = build_filter(policy, filter);
    if (len > (size_t)UINT16_MAX) return VX_ERR_INVALID_ARG;

    struct sock_fprog prog = {
        .len = (unsigned short)len,
        .filter = filter,
    };

    unsigned int flags = 0;
#ifdef SECCOMP_FILTER_FLAG_LOG
    if (policy->mode == VX_SECCOMP_AUDIT) flags |= SECCOMP_FILTER_FLAG_LOG;
#endif

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &prog) == 0) return VX_OK;

    /* Older kernels lack the seccomp(2) syscall but have the prctl interface,
     * which cannot carry flags — so audit mode is genuinely unavailable there
     * rather than silently downgraded to something weaker. */
    if (errno == ENOSYS || errno == EINVAL) {
        if (policy->mode == VX_SECCOMP_AUDIT) return VX_ERR_UNSUPPORTED;
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0) return VX_OK;
    }
    return VX_ERR_UNSUPPORTED;
}
