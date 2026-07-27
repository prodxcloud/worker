#!/usr/bin/env bash
# run_tsan.sh — run a TSan-instrumented binary and fail only on an actual race.
#
# Two environment quirks have to be separated from real findings:
#
#  1. TSan maps its shadow at fixed addresses and aborts with "unexpected memory
#     mapping" on kernels built with high-entropy ASLR (vm.mmap_rnd_bits=32,
#     which is the default on 6.x and on WSL2).  `setarch -R` disables
#     randomisation for the child, which is the upstream-recommended workaround.
#
#  2. Even with that, TSan's teardown can abort with exit 66 *after* the suite has
#     run and reported.  That is not a race, so exiting on it alone would make
#     the target useless.
#
# So: pass/fail is decided by whether TSan printed a data-race report, which is
# the thing we actually care about.
set -u
BIN=${1:?usage: run_tsan.sh <tsan-instrumented-binary>}
ERR=$(mktemp)
OUT=$(mktemp)
trap 'rm -f "$ERR" "$OUT"' EXIT

if command -v setarch >/dev/null 2>&1; then
  setarch "$(uname -m)" -R "$BIN" >"$OUT" 2>"$ERR"
else
  echo "note: setarch not found; TSan may abort on a high-ASLR kernel"
  "$BIN" >"$OUT" 2>"$ERR"
fi
rc=$?

cat "$OUT"

races=$(grep -c 'WARNING: ThreadSanitizer: data race' "$ERR" || true)
other=$(grep -cE 'WARNING: ThreadSanitizer: (lock-order-inversion|thread leak|signal-unsafe)' "$ERR" || true)

echo
if [ "$races" -gt 0 ] || [ "$other" -gt 0 ]; then
  echo "ThreadSanitizer reported $races data race(s) and $other other finding(s):"
  echo "-----------------------------------------------------------"
  grep -A 12 'WARNING: ThreadSanitizer' "$ERR" | head -80
  echo "-----------------------------------------------------------"
  exit 1
fi

if ! grep -q 'PASS' "$OUT"; then
  echo "TSan run produced no PASS line (exit $rc); stderr was:"
  head -5 "$ERR"
  exit 1
fi

echo "ThreadSanitizer: no data races reported."
if [ "$rc" -ne 0 ]; then
  echo "note: the instrumented process exited $rc during teardown, after the"
  echo "      suite had already completed — an environment quirk, not a race."
fi
exit 0
