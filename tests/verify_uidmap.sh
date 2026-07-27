#!/usr/bin/env bash
# verify_uidmap.sh — prove the central security claim: a process that is uid 0
# *inside* its namespace is an unprivileged uid *on the host*.
#
# Reads /proc/<pid>/status and /proc/<pid>/uid_map directly rather than trusting
# `ps` output, which resolves names through the host passwd database and is easy
# to misread.
set -u
VX=${VX:-./build/vxworker}
MAPPED_UID=${MAPPED_UID:-65534}

echo "=== host uid of a sandboxed 'root' process"

# Park a long-running guest so we can inspect it from the host.
$VX run --task-id 900 --host-uid "$MAPPED_UID" --timeout 8000 -- \
  /bin/sh -c 'echo "inside: uid=$(id -u)"; sleep 4' &
VX_PID=$!
sleep 1

# The guest is the only descendant of the vxworker process running `sleep 4`.
GUEST=""
for pid in $(ls -d /proc/[0-9]* | sed 's|/proc/||'); do
  [ -r "/proc/$pid/uid_map" ] || continue
  # A mapped namespace has a non-identity uid_map; the host's is "0 0 4294967295".
  map=$(tr -s ' ' < "/proc/$pid/uid_map" 2>/dev/null | sed 's/^ //')
  case "$map" in
    "0 $MAPPED_UID 1") GUEST=$pid; break ;;
  esac
done

if [ -z "$GUEST" ]; then
  echo "FAIL: found no process with uid_map '0 $MAPPED_UID 1'"
  wait $VX_PID 2>/dev/null
  exit 1
fi

echo "guest host-pid : $GUEST"
echo "uid_map        : $(cat /proc/$GUEST/uid_map | tr -s ' ')"
echo "gid_map        : $(cat /proc/$GUEST/gid_map | tr -s ' ')"
echo "setgroups      : $(cat /proc/$GUEST/setgroups)"
grep -E '^(Uid|Gid):' "/proc/$GUEST/status"
echo "comm           : $(cat /proc/$GUEST/comm)"

HOST_UID=$(awk '/^Uid:/ {print $2}' "/proc/$GUEST/status")
echo
if [ "$HOST_UID" = "$MAPPED_UID" ]; then
  echo "PASS: guest is uid 0 inside its namespace but uid $HOST_UID on the host"
  RC=0
else
  echo "FAIL: guest host uid is $HOST_UID, expected $MAPPED_UID"
  RC=1
fi

echo
echo "=== namespace identity differs from the host's"
for ns in user pid net ipc mnt uts; do
  host_ns=$(readlink "/proc/self/ns/$ns")
  guest_ns=$(readlink "/proc/$GUEST/ns/$ns" 2>/dev/null || echo "unreadable")
  if [ "$host_ns" = "$guest_ns" ]; then
    echo "  $ns: SHARED with host ($host_ns)  <-- not isolated"
    RC=1
  else
    echo "  $ns: isolated (host=$host_ns guest=$guest_ns)"
  fi
done

wait $VX_PID 2>/dev/null
exit $RC
