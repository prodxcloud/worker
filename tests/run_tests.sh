#!/usr/bin/env bash
# run_tests.sh — run every test binary passed on the command line.
# Exit 77 from a test means "skipped" (missing privilege / kernel facility) and
# is not a failure; anything else nonzero is.
set -u

pass=0
fail=0
skip=0
failed_names=()

for bin in "$@"; do
  [ -x "$bin" ] || continue
  name=$(basename "$bin")
  out=$("$bin" 2>&1)
  rc=$?
  case $rc in
    0)  pass=$((pass + 1)); printf '%s\n' "$out" ;;
    77) skip=$((skip + 1)); printf '%s\n' "$out" ;;
    *)  fail=$((fail + 1)); failed_names+=("$name"); printf '%s\n' "$out" ;;
  esac
done

echo
echo "-----------------------------------------------------------"
printf 'test summary: %d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
if [ "$fail" -gt 0 ]; then
  printf 'failed: %s\n' "${failed_names[*]}"
  exit 1
fi
echo "-----------------------------------------------------------"
exit 0
