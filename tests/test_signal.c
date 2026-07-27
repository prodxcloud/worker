/* test_signal.c — signalfd delivery and the child-side mask reset.
 *
 * The reset matters more than it looks: a blocked signal survives execve, so a
 * guest launched without it would start life unable to receive SIGTERM and the
 * supervisor's graceful-shutdown path would silently do nothing. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "vx_error.h"
#include "vx_signal.h"
#include "vxtest.h"

int main(void) {
    VXT_BEGIN("signal handling");

    VXT_CASE("install succeeds and is idempotent");
    VXT_EQ_INT(vx_signal_install(), VX_OK, "install");
    VXT_EQ_INT(vx_signal_install(), VX_OK, "install again");
    int fd = vx_signal_fd();
    printf("    signalfd = %d\n", fd);

    VXT_CASE("no signal is pending on a quiet supervisor");
    VXT_CHECK(!vx_signal_shutdown_requested(), "shutdown not requested yet");
    VXT_EQ_INT(vx_signal_wait(0), 0, "wait(0) finds nothing pending");

    VXT_CASE("SIGTERM is delivered through the descriptor, not the default action");
    /* If the mask were not installed, this raise would terminate the test
     * process outright — reaching the next line is itself the assertion. */
    raise(SIGTERM);
    VXT_EQ_INT(vx_signal_wait(500), 1, "wait sees the pending signal");
    bool shutdown = false, child = false;
    int drained = vx_signal_drain(&shutdown, &child);
    VXT_CHECK(drained >= 1, "drained %d signal(s)", drained);
    VXT_CHECK(shutdown, "reported as a shutdown request");
    VXT_CHECK(vx_signal_shutdown_requested(), "shutdown latches");

    VXT_CASE("SIGCHLD is distinguished from a shutdown request");
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    VXT_CHECK(pid > 0, "fork");
    VXT_EQ_INT(vx_signal_wait(1000), 1, "wait sees SIGCHLD");
    shutdown = false;
    child = false;
    vx_signal_drain(&shutdown, &child);
    VXT_CHECK(child, "reported as a child exit");
    int status = 0;
    waitpid(pid, &status, 0);

    VXT_CASE("drain on an idle fd returns zero rather than blocking");
    shutdown = false;
    child = false;
    VXT_EQ_INT(vx_signal_drain(&shutdown, &child), 0, "nothing to drain");

    VXT_CASE("the child mask reset lets a guest receive SIGTERM after exec");
    /* Fork with SIGTERM still blocked, reset in the child, then confirm the
     * child dies from SIGTERM.  Without vx_signal_reset_for_child() the signal
     * would stay blocked and the child would run to completion. */
    pid_t victim = fork();
    if (victim == 0) {
        vx_signal_reset_for_child();
        for (;;) pause();
        _exit(0);
    }
    VXT_CHECK(victim > 0, "fork victim");
    if (victim > 0) {
        usleep(150000);
        kill(victim, SIGTERM);
        int vstatus = 0;
        VXT_CHECK(waitpid(victim, &vstatus, 0) == victim, "reap victim");
        VXT_CHECK(WIFSIGNALED(vstatus) && WTERMSIG(vstatus) == SIGTERM,
                  "victim died from SIGTERM (signalled=%d sig=%d)", (int)WIFSIGNALED(vstatus),
                  WIFSIGNALED(vstatus) ? WTERMSIG(vstatus) : 0);
    }

    VXT_CASE("without the reset, a blocked SIGTERM is inherited and ignored");
    /* The negative control for the case above. */
    pid_t survivor = fork();
    if (survivor == 0) {
        /* Inherits the blocked mask; SIGTERM should just go pending. */
        usleep(300000);
        _exit(7);
    }
    if (survivor > 0) {
        usleep(100000);
        kill(survivor, SIGTERM);
        int sstatus = 0;
        waitpid(survivor, &sstatus, 0);
        VXT_CHECK(WIFEXITED(sstatus) && WEXITSTATUS(sstatus) == 7,
                  "child with the inherited mask survived SIGTERM and exited 7");
    }
    /* That child's exit queued another SIGCHLD; clear it. */
    vx_signal_drain(&shutdown, &child);

    VXT_CASE("uninstall restores the previous disposition");
    vx_signal_uninstall();
    VXT_CHECK(!vx_signal_shutdown_requested(), "latch cleared on uninstall");
    sigset_t now;
    sigemptyset(&now);
    sigprocmask(SIG_BLOCK, NULL, &now);
    VXT_CHECK(!sigismember(&now, SIGTERM), "SIGTERM is no longer blocked");

    VXT_CASE("uninstall is idempotent");
    vx_signal_uninstall();

    VXT_END();
}
