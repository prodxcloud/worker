/* vx_signal.c — signalfd-based signal handling with a sigaction fallback. */
#include "vx_signal.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_log.h"

static int g_sigfd = -1;
static sigset_t g_old_mask;
static bool g_installed = false;
static volatile sig_atomic_t g_shutdown = 0;
static volatile sig_atomic_t g_child = 0;

/* The set the supervisor cares about.  SIGCHLD is included so a task exiting
 * wakes the poll loop instead of relying on a timeout. */
static void build_set(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGQUIT);
    sigaddset(set, SIGHUP);
    sigaddset(set, SIGCHLD);
}

/* Fallback path only.  Touches nothing but two sig_atomic_t flags. */
static void fallback_handler(int signo) {
    if (signo == SIGCHLD) g_child = 1;
    else g_shutdown = 1;
}

vx_status_t vx_signal_install(void) {
    if (g_installed) return VX_OK;

    sigset_t set;
    build_set(&set);

    /* Block first, then attach the fd.  Doing it the other way round leaves a
     * window where the default disposition would kill the supervisor. */
    if (sigprocmask(SIG_BLOCK, &set, &g_old_mask) != 0) {
        VX_ERROR("sigprocmask(SIG_BLOCK) failed: %s", strerror(errno));
        return VX_ERR_UNSUPPORTED;
    }

    g_sigfd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    if (g_sigfd < 0) {
        VX_WARN("signalfd unavailable (%s); using sigaction fallback", strerror(errno));
        sigprocmask(SIG_SETMASK, &g_old_mask, NULL);

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = fallback_handler;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&sa.sa_mask);
        int sigs[] = {SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGCHLD};
        for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
            if (sigaction(sigs[i], &sa, NULL) != 0) {
                VX_ERROR("sigaction(%d) failed: %s", sigs[i], strerror(errno));
                return VX_ERR_UNSUPPORTED;
            }
        }
    }

    g_installed = true;
    g_shutdown = 0;
    g_child = 0;
    VX_DEBUG("signal handling installed (signalfd=%d)", g_sigfd);
    return VX_OK;
}

int vx_signal_fd(void) { return g_sigfd; }

int vx_signal_drain(bool *shutdown, bool *child_exited) {
    bool sd = false, ce = false;
    int count = 0;

    if (g_sigfd >= 0) {
        struct signalfd_siginfo si;
        for (;;) {
            ssize_t n = read(g_sigfd, &si, sizeof(si));
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                return VX_ERR_UNSUPPORTED;
            }
            if (n != (ssize_t)sizeof(si)) break;
            count++;
            if (si.ssi_signo == SIGCHLD) ce = true;
            else sd = true;
            VX_TRACE("signal %u from pid %u", si.ssi_signo, si.ssi_pid);
        }
    } else {
        if (g_shutdown) {
            sd = true;
            g_shutdown = 0;
            count++;
        }
        if (g_child) {
            ce = true;
            g_child = 0;
            count++;
        }
    }

    if (sd) g_shutdown = 1; /* latch: shutdown is not a transient event */
    if (shutdown != NULL) *shutdown = sd;
    if (child_exited != NULL) *child_exited = ce;
    return count;
}

bool vx_signal_shutdown_requested(void) { return g_shutdown != 0; }

int vx_signal_wait(int timeout_ms) {
    if (g_sigfd < 0) {
        /* Fallback: no descriptor to poll, so report what the handler latched. */
        return (g_shutdown || g_child) ? 1 : 0;
    }
    struct pollfd pfd = {.fd = g_sigfd, .events = POLLIN, .revents = 0};
    for (;;) {
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return VX_ERR_UNSUPPORTED;
        }
        return rc > 0 ? 1 : 0;
    }
}

vx_status_t vx_signal_reset_for_child(void) {
    /* Runs between clone() and execvp().  A blocked or ignored signal survives
     * exec, so the guest would otherwise start life unable to receive SIGTERM. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    int sigs[] = {SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGCHLD, SIGPIPE};
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) sigaction(sigs[i], &sa, NULL);

    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) != 0) return VX_ERR_UNSUPPORTED;
    return VX_OK;
}

void vx_signal_uninstall(void) {
    if (!g_installed) return;
    if (g_sigfd >= 0) {
        close(g_sigfd);
        g_sigfd = -1;
    }
    sigprocmask(SIG_SETMASK, &g_old_mask, NULL);
    g_installed = false;
    g_shutdown = 0;
    g_child = 0;
}
