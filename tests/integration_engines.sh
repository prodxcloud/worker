#!/usr/bin/env bash
# integration_engines.sh — prove the ABI is a real contract, not just a header.
#
# `worker` emits a task frame; `ion` (Rust) and `iron` (C++23) consume the exact
# same bytes.  A layout drift in any of the three repos shows up here as a decode
# failure, which is the only way to catch it: each engine hard-codes the offsets
# rather than parsing.
#
# Skips (exit 77) any engine whose binary is not present, so it is usable from a
# single-repo checkout.
set -u
cd "$(dirname "$0")/.."

VX=${VX:-./build/vxworker}

# Both engines are commonly built out of tree (a Rust CARGO_TARGET_DIR, a CMake
# build dir), so search the usual places instead of assuming one layout.
find_bin() {
  for candidate in "$@"; do
    [ -x "$candidate" ] && { echo "$candidate"; return 0; }
  done
  echo "$1"
}
ION=${ION:-$(find_bin ../ion/target/release/ion /tmp/ion-target/release/ion \
                      ../ion/target/debug/ion /tmp/ion-target/debug/ion \
                      "$(command -v ion 2>/dev/null || echo /nonexistent)")}
IRON=${IRON:-$(find_bin /tmp/iron-build/iron ../iron/build/iron \
                        /tmp/iron-build/src/iron \
                        "$(command -v iron 2>/dev/null || echo /nonexistent)")}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fails=0
skips=0

banner() { printf '\n=== %s\n' "$1"; }

banner "worker: the frozen ABI v1 layout"
$VX abi || fails=$((fails + 1))

# --------------------------------------------------------------------------
banner "worker -> frame on disk"
# Each engine defines its own payload schema on top of the shared header; the
# header is the contract, the body is the engine's business.  ion takes JSON
# tagged by "op", iron takes op=/arg= lines.  Both ops chosen here are offline so
# the check never depends on the network.
PAYLOAD='{"op":"noop"}'
$VX encode-task --task-id 4242 --tenant acme-prod --engine ion \
    --mem 8 --cpu 50000 --payload "$PAYLOAD" > "$TMP/ion_task.bin" || fails=$((fails + 1))
IRON_PAYLOAD=$(printf 'op=exec\narg=/bin/echo\narg=from-iron\n')
$VX encode-task --task-id 9001 --tenant acme-prod --engine iron \
    --mem 512 --cpu 200000 --payload "$IRON_PAYLOAD" \
    > "$TMP/iron_task.bin" || fails=$((fails + 1))

ion_size=$(wc -c < "$TMP/ion_task.bin")
echo "ion frame  : $ion_size bytes (93 header + ${#PAYLOAD} payload)"
if [ "$ion_size" -ne $((93 + ${#PAYLOAD})) ]; then
  echo "FAIL: frame size is not 93 + payload"
  fails=$((fails + 1))
fi

echo "first 32 bytes:"
od -A d -t x1 -N 32 "$TMP/ion_task.bin"
echo "magic must be 01 56 57 58 (0x58575601 little-endian)"
if [ "$(od -A n -t x1 -N 4 "$TMP/ion_task.bin" | tr -d ' ')" != "01565758" ]; then
  echo "FAIL: wrong magic on the wire"
  fails=$((fails + 1))
fi

# --------------------------------------------------------------------------
banner "worker reads its own frame back"
$VX decode-task "$TMP/ion_task.bin" || fails=$((fails + 1))

# --------------------------------------------------------------------------
banner "ion (Rust) decodes the same bytes"
if [ -x "$ION" ]; then
  # ion reads a *stream* of frames, so the source is --input (or stdin), not a
  # positional path.  --output matters as much: result frames go to stdout by
  # default, and letting raw binary into this script's stdout makes the whole
  # transcript a binary file.
  if "$ION" run --input "$TMP/ion_task.bin" --output "$TMP/ion_result.bin"; then
    if [ "$(od -A n -t x1 -N 4 "$TMP/ion_result.bin" | tr -d ' ')" = "01565758" ]; then
      echo "ok  : ion emitted a well-formed result frame ($(wc -c < "$TMP/ion_result.bin") bytes)"
    else
      echo "FAIL: ion's result frame has the wrong magic"
      fails=$((fails + 1))
    fi
  else
    echo "FAIL: ion could not run the frame"
    fails=$((fails + 1))
  fi
else
  echo "SKIP: no ion binary at $ION (build it with: cd ../ion && cargo build --release)"
  skips=$((skips + 1))
fi

# --------------------------------------------------------------------------
banner "iron (C++23) decodes the same bytes"
if [ -x "$IRON" ]; then
  "$IRON" run "$TMP/iron_task.bin" || { echo "FAIL: iron could not run the frame"; fails=$((fails + 1)); }
else
  echo "SKIP: no iron binary at $IRON (build it with: cmake -S ../iron -B /tmp/iron-build && cmake --build /tmp/iron-build)"
  skips=$((skips + 1))
fi

# --------------------------------------------------------------------------
banner "every engine must reject a corrupted frame"
# Flip the magic and confirm all three refuse it rather than reading garbage.
cp "$TMP/ion_task.bin" "$TMP/corrupt.bin"
printf '\xFF' | dd of="$TMP/corrupt.bin" bs=1 seek=0 count=1 conv=notrunc status=none

if $VX decode-task "$TMP/corrupt.bin" >/dev/null 2>&1; then
  echo "FAIL: worker accepted a bad magic"
  fails=$((fails + 1))
else
  echo "ok  : worker rejected it"
fi

if [ -x "$ION" ]; then
  if "$ION" run --input "$TMP/corrupt.bin" --output /dev/null >/dev/null 2>&1; then
    echo "FAIL: ion accepted a bad magic"
    fails=$((fails + 1))
  else
    echo "ok  : ion rejected it"
  fi
fi

if [ -x "$IRON" ]; then
  if "$IRON" run "$TMP/corrupt.bin" >/dev/null 2>&1; then
    echo "FAIL: iron accepted a bad magic"
    fails=$((fails + 1))
  else
    echo "ok  : iron rejected it"
  fi
fi

# --------------------------------------------------------------------------
banner "the natural invocation must not silently no-op"
# `ion run <file>` used to drop the positional and read an empty stdin: zero
# tasks, exit 0.  That made a typo look like success and a corrupt frame look
# accepted, so it is worth asserting from outside ion as well as inside it.
if [ -x "$ION" ]; then
  if "$ION" run "$TMP/ion_task.bin" --output /dev/null >/dev/null 2>&1; then
    echo "ok  : ion accepts a positional input path"
  else
    echo "FAIL: ion rejected a positional input path"
    fails=$((fails + 1))
  fi
  if "$ION" run "$TMP/corrupt.bin" --output /dev/null >/dev/null 2>&1; then
    echo "FAIL: ion silently accepted a corrupt frame via the positional form"
    fails=$((fails + 1))
  else
    echo "ok  : the positional form still rejects a corrupt frame"
  fi
fi

banner "a truncated payload must not be read past the end"
head -c 100 "$TMP/ion_task.bin" > "$TMP/short.bin"   # header claims 45 payload bytes, only 7 present
if $VX decode-task "$TMP/short.bin" >/dev/null 2>&1; then
  echo "FAIL: worker accepted a truncated frame"
  fails=$((fails + 1))
else
  echo "ok  : worker rejected the truncated frame"
fi
if [ -x "$ION" ]; then
  if "$ION" run --input "$TMP/short.bin" --output /dev/null >/dev/null 2>&1; then
    echo "FAIL: ion accepted a truncated frame"
    fails=$((fails + 1))
  else
    echo "ok  : ion rejected the truncated frame"
  fi
fi
if [ -x "$IRON" ] && "$IRON" run "$TMP/short.bin" >/dev/null 2>&1; then
  echo "FAIL: iron accepted a truncated frame"
  fails=$((fails + 1))
fi

# --------------------------------------------------------------------------
banner "ion runs inside a worker sandbox (the real production path)"
if [ -x "$ION" ]; then
  $VX run --task-id 4242 --tenant acme-prod --mem 64 --no-net --timeout 15000 \
      -- "$ION" selftest \
    || { echo "FAIL: ion selftest inside the sandbox"; fails=$((fails + 1)); }
else
  echo "SKIP: no ion binary"
fi

# --------------------------------------------------------------------------
printf '\n-----------------------------------------------------------\n'
if [ "$fails" -eq 0 ]; then
  echo "integration: PASS ($skips engine(s) skipped)"
  [ "$skips" -gt 0 ] && exit 77
  exit 0
fi
echo "integration: FAILED ($fails failure(s), $skips skipped)"
exit 1
