#!/usr/bin/env bash
# tsan_probe.sh — determine whether this kernel lets TSan place its shadow.
# Used to document the environment honestly rather than to work around a bug.
set -u
cd "$(dirname "$0")/.."

echo "mmap_rnd_bits = $(cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo n/a) (TSan wants <= 28)"

gcc-14 -std=c11 -D_GNU_SOURCE -Iinclude -O1 -g -fsanitize=thread \
  -fno-omit-frame-pointer -o /tmp/tsan_ipc tests/test_ipc.c src/vx_*.c -pthread || exit 1

echo
echo "=== (a) plain run"
/tmp/tsan_ipc >/tmp/a.out 2>/tmp/a.err
echo "exit=$?"
grep -E 'PASS|FAILED' /tmp/a.out || true
echo "stderr: $(tr -d '\n' < /tmp/a.err | head -c 200)"

echo
echo "=== (b) ASLR disabled via setarch -R"
setarch "$(uname -m)" -R /tmp/tsan_ipc >/tmp/b.out 2>/tmp/b.err
echo "exit=$?"
grep -E 'PASS|FAILED' /tmp/b.out || true
echo "stderr: $(tr -d '\n' < /tmp/b.err | head -c 200)"

echo
echo "=== (c) ASLR disabled and mmap_rnd_bits lowered to 28"
orig=$(cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo "")
if [ -n "$orig" ]; then
  sysctl -q -w vm.mmap_rnd_bits=28 2>/dev/null || echo "  (could not lower mmap_rnd_bits)"
  setarch "$(uname -m)" -R /tmp/tsan_ipc >/tmp/c.out 2>/tmp/c.err
  echo "exit=$?"
  grep -E 'PASS|FAILED' /tmp/c.out || true
  echo "stderr: $(tr -d '\n' < /tmp/c.err | head -c 200)"
  # Always put the host setting back.
  sysctl -q -w "vm.mmap_rnd_bits=$orig" 2>/dev/null
  echo "  restored vm.mmap_rnd_bits=$(cat /proc/sys/vm/mmap_rnd_bits)"
fi

echo
echo "grep for races in every run (empty == none found):"
grep -h "data race" /tmp/a.err /tmp/b.err /tmp/c.err 2>/dev/null || echo "  no data races reported"
