#!/usr/bin/env bash
# smoke_sandbox.sh — exercise the real isolation guarantees end to end.
# Not part of `make test` (that suite is self-checking C); this is the
# human-readable demonstration used to capture README output.
set -u
VX=${VX:-./build/vxworker}

hr() { printf '\n=== %s\n' "$1"; }

hr "identity inside the sandbox (uid 0 inside == uid 65534 on the host)"
$VX run --task-id 101 --tenant acme -- \
  /bin/sh -c 'echo "inside: uid=$(id -u) gid=$(id -g) hostname=$(hostname) pid=$$"'

hr "pid namespace: the guest is PID 1 and sees only itself"
$VX run --task-id 102 -- /bin/sh -c 'echo "visible processes: $(ls -d /proc/[0-9]* | wc -l)"; ps -eo pid,comm 2>/dev/null | head -5'

hr "network namespace: no host interfaces, loopback up"
$VX run --task-id 103 -- /bin/sh -c 'ip -o link show 2>/dev/null || cat /proc/net/dev'

hr "host view of the same task's uid (should be 65534, not 0)"
# Delegated to verify_uidmap.sh, which reads /proc/<pid>/uid_map and
# /proc/<pid>/status for the specific guest.  A `ps | grep` here is not
# trustworthy: it matches unrelated processes with the same comm.
bash "$(dirname "$0")/verify_uidmap.sh" | grep -E 'uid_map|Uid:|PASS|FAIL'

hr "memory limit enforced: 16 MiB cap against a 256 MiB allocation"
# build/hog touches every page it allocates — an untouched malloc is never
# charged to the cgroup, so a streaming pipe here would pass vacuously.
$VX run --task-id 105 --mem 16 --timeout 20000 -- ./build/hog 256
echo "exit=$?  (137 == SIGKILL, state should be KILLED_OOM)"

hr "cpu quota enforced: 10% of one core (cpu.max = 10000 100000)"
$VX run --task-id 106 --cpu 10000 --timeout 3000 -- \
  /bin/sh -c 'i=0; while [ $i -lt 4000000 ]; do i=$((i+1)); done'
echo "exit=$? (expect KILLED_TIMEOUT: throttled to 10% it cannot finish in 3s)"

hr "pids limit enforced: pids.max = 5"
$VX run --task-id 107 --pids 5 --timeout 5000 -- \
  /bin/sh -c 'for i in 1 2 3 4 5 6 7 8 9 10; do (sleep 0.2) & done; wait; echo survived'

hr "timeout kill"
$VX run --task-id 108 --timeout 500 -- /bin/sleep 30
echo "exit=$? (expect 137 / KILLED_TIMEOUT)"

hr "exit code propagation"
$VX run --task-id 109 -- /bin/sh -c 'exit 42'
echo "exit=$? (expect 42)"

hr "exec of a nonexistent binary is reported, not hung"
$VX run --task-id 110 -- /nonexistent/binary
echo "exit=$? (expect nonzero with an execvp diagnostic)"

hr "cgroup nodes are cleaned up (expect no output)"
ls -d /sys/fs/cgroup/vxworker_* 2>/dev/null || echo "none left behind"
