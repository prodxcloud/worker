/* vx_signal.h — POSIX signal handling for a task supervisor.
 *
 * Signals are converted into readable file-descriptor events with signalfd(2)
 * rather than handled in an async-signal context.  That removes the entire
 * class of "what may I call from a handler" bugs: the supervisor just polls a
 * descriptor alongside its other fds.  A sigaction-based fallback with a
 * volatile sig_atomic_t flag is provided for kernels without signalfd. */
#ifndef VX_SIGNAL_H
#define VX_SIGNAL_H

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "worker_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Block SIGTERM/SIGINT/SIGQUIT/SIGHUP/SIGCHLD and route them to a signalfd.
 * Must be called before spawning children so the mask is inherited-then-reset
 * correctly by vx_sandbox_spawn(). */
vx_status_t vx_signal_install(void);

/* The descriptor to poll.  -1 when signalfd is unavailable and the fallback
 * handler path is active. */
int vx_signal_fd(void);

/* Drain pending signals.  Returns the number consumed, or a negative
 * vx_status_t.  *shutdown is set when a termination signal was seen and
 * *child_exited when SIGCHLD arrived. */
int vx_signal_drain(bool *shutdown, bool *child_exited);

/* True once SIGTERM/SIGINT/SIGQUIT has been observed.  Safe from anywhere. */
bool vx_signal_shutdown_requested(void);

/* Wait up to timeout_ms for a signal to become readable.  Returns 1 if one is
 * pending, 0 on timeout, negative vx_status_t on error. */
int vx_signal_wait(int timeout_ms);

/* Restore the inherited signal mask and default dispositions.  Called in the
 * child between clone() and execvp() so the guest starts with a clean slate —
 * a blocked SIGTERM would otherwise be inherited straight through exec. */
vx_status_t vx_signal_reset_for_child(void);

void vx_signal_uninstall(void);

#ifdef __cplusplus
}
#endif

#endif /* VX_SIGNAL_H */
