# prodxcloud/worker — Phase 1 requirements

Phase 1 of the VxCloud worker specification: **Core System ABI & C11 Engine**.

Boxes are ticked only where the behaviour is implemented *and* covered by a test
that would fail if it regressed. Anything unimplemented is listed as such in
[Not implemented](#not-implemented) rather than quietly ticked.

Verified on Linux 6.6.87 (WSL2), cgroup v2 unified hierarchy, GCC 14.2,
`-std=c11 -Wall -Wextra -Wpedantic -Werror`.

---

## 1.1 Low-level kernel sandbox (`vx_sandbox.c`)

### Unprivileged namespace creation

- [x] Issues **direct system calls** — `syscall(SYS_clone, ...)` for the sandbox
      and `unshare()` for capability probing. No `libcontainer`, no runtime.
- [x] `CLONE_NEWUSER` — user namespace
- [x] `CLONE_NEWPID` — pid namespace (guest is PID 1)
- [x] `CLONE_NEWNET` — network namespace
- [x] `CLONE_NEWIPC` — IPC namespace
- [x] `CLONE_NEWNS` — mount namespace
- [x] `CLONE_NEWUTS` — UTS namespace *(beyond spec)*
- [x] `CLONE_NEWCGROUP` — cgroup namespace *(beyond spec)*
- [x] **Maps uid 0 inside the namespace to a non-root uid on the host**
      (`0 65534 1` by default, configurable via `spec.host_uid`)
- [x] `setgroups` denied before `gid_map` is written
- [x] Each namespace is verified to have a different inode from the host's

Tests: `test_sandbox.c` (uid 0 inside / 65534 outside, PID 1, single-interface
netns, isolated `/proc`, non-leaking hostname), `verify_uidmap.sh` (asserts against
`/proc/<pid>/uid_map`, `gid_map`, `setgroups`, `status` and all six `ns/*` links).

Measured:

```
inside:  uid=0 gid=0 hostname=vxworker pid=1
host:    Uid: 65534 65534 65534 65534   uid_map: "0 65534 1"   setgroups: deny
```

### Resource isolation (cgroups v2)

- [x] Dynamic cgroup node at `/sys/fs/cgroup/vxworker_<task_id>`
- [x] Hard memory limit via `memory.max`
- [x] `memory.high` supported — **deliberately disabled by default**, see
      [Deviations](#deviations-from-the-original-spec)
- [x] CPU bandwidth throttling via `cpu.max` as `"<quota_us> <period_us>"`
- [x] `pids.max` fork-bomb containment *(beyond spec)*
- [x] `memory.swap.max = 0` so the memory limit cannot be escaped *(beyond spec)*
- [x] Atomic subtree teardown via `cgroup.kill` *(beyond spec)*
- [x] Controller delegation through the parent's `cgroup.subtree_control`
- [x] Usage readback: `memory.current`, `memory.peak`, `cpu.stat usage_usec`,
      `memory.events oom_kill`, `pids.current`
- [x] Nodes are removed on teardown; leaks are asserted against

Tests: `test_cgroup.c` reads every control file back and checks the exact value
(catching MiB/byte unit confusion), and pins the fact that cgroup v2 does not
migrate page charges on attach. `test_sandbox.c` proves each limit actually binds.

Measured:

```
memory  16 MiB cap vs 256 MiB alloc → KILLED_OOM, peak 16777216 B, 52 ms
cpu     10% of one core, 3s budget  → KILLED_TIMEOUT, cpu_us=309723
pids    pids.max=5 vs 10 forks      → "Cannot fork", FAILED
```

## 1.2 Zero-copy shared-memory IPC (`vx_ipc.c`)

- [x] POSIX shared memory (`shm_open`) + `mmap`
- [x] Ring buffer built on C11 atomics (`<stdatomic.h>`)
- [x] **Lock-free SPMC** — single producer, many consumers, no mutex or futex
- [x] Sub-microsecond exchange (**24 ns** same-thread, **65 ns** cross-thread;
      p50 below the 1 µs clock granularity)
- [x] Zero syscalls on either hot path after setup
- [x] Cache-line isolation of the producer cursor, consumer cursor and statistics
- [x] Bounded, non-blocking: `VX_ERR_RING_FULL` / `VX_ERR_RING_EMPTY`
- [x] Undersized destination buffer fails **without** consuming the record
- [x] Monotonic 64-bit cursors — generation wrap needs no special case
- [x] `atomic_is_lock_free` asserted, since a lock-based fallback would deadlock
      across processes
- [x] Ring names validated against path traversal
- [x] Geometry validated on attach rather than trusted

Tests: `test_ipc.c` — 1,269 assertions including FIFO order, full/empty edges,
50 generation wraps, a 200,000-record 1-producer/4-consumer race (checked with a
per-record seen-counter, 197,122 full-ring retries) and a real cross-process
`fork()` exchange verified by checksum. Clean under TSan.

Measured:

```
41.91 M round-trips/s same-thread · 5.00 GiB/s · p99 1 µs
15.44 M records/s producer thread → consumer thread
200000 produced / 200000 consumed → 0 lost, 0 duplicated
```

### Standard C ABI header (`worker_abi.h`)

- [x] `VX_MAGIC_HEADER 0x58575601`
- [x] `vx_engine_type_t` — `ENGINE_ION 0x01`, `ENGINE_IRON 0x02`
- [x] `vx_task_header_t` packed, with the flexible `payload[]` member
- [x] All spec'd fields at the spec'd order: `magic`, `task_id`, `tenant_id[64]`,
      `engine`, `memory_limit_mb`, `cpu_quota_us`, `payload_len`, `payload[]`
- [x] `_Static_assert` on size and every offset — layout drift fails to compile
- [x] Compiles unmodified as C11 **and** C++23
- [x] `vx_result_header_t` for the return path *(beyond spec)*
- [x] `vx_task_state_t`, `vx_status_t` *(beyond spec)*
- [x] Byte-exact little-endian layout asserted, not assumed

Tests: `test_abi_layout.c` (34 assertions on offsets and raw bytes),
`test_task.c` (41 assertions covering every rejection path).

## POSIX signal handling

- [x] `signalfd(2)` delivery, so no work happens in an async-signal context
- [x] `sigaction` + `volatile sig_atomic_t` fallback for kernels without it
- [x] `SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP` latch a shutdown request
- [x] `SIGCHLD` distinguished from a shutdown request
- [x] Mask and dispositions reset between `clone()` and `execvp()`
- [x] Negative control: a child *without* the reset survives `SIGTERM`

Tests: `test_signal.c` (18 assertions).

---

## Deviations from the original spec

**`memory.high` is disabled by default.** The spec asked for "hard limit via
`memory.max` and enforcement on `memory.high`". Both are implemented, but
`memory.high` is off unless the caller opts in via
`vx_cgroup_set_memory_high()`.

`memory.high` throttles; it does not kill. Combined with `memory.swap.max = 0` and
a supervisor wall-clock deadline, a task that breaches its limit stops making
forward progress and is eventually killed by the *timeout*:

| configuration | outcome | latency | reported state |
|---|---|---|---|
| `memory.max` only | OOM-killed | 52 ms | `KILLED_OOM` ✅ |
| `+ memory.high` at 90% | thrashed to deadline | 20,050 ms | `KILLED_TIMEOUT` ❌ |

A 400× slower failure, misattributed to the wrong cause. Docker and Kubernetes set
the hard limit alone for the same reason. Keeping the knob available preserves the
spec's intent for elastic workloads that would rather run slowly than die.

---

## Not implemented

- **`seccomp-bpf` syscall filtering.** Namespaces and cgroups bound what a task can
  reach and consume, not which syscalls it may issue. Not in the Phase 1 spec;
  it is the natural next layer.
- **rootfs pivot / `pivot_root`.** The guest shares the host filesystem view apart
  from a private `/proc`. `spec.rootfs` is reserved but unimplemented.
- **cgroup v1.** Will not be added; split hierarchies cannot express an atomic
  memory+cpu+pids envelope.
- **Architectures beyond x86-64 and aarch64.** `vx_raw_clone()` fails the build
  elsewhere rather than guessing at the argument order.

---

## Verification summary

| gate | result |
|---|---|
| `make` (`-Werror`, 12 extra warning classes) | clean |
| `make test` | **6 suites, 1,471 assertions, 0 failed, 0 skipped** |
| `make asan` (ASan + UBSan) | clean — no leaks, no UB |
| `make tsan` (ThreadSanitizer) | **no data races** |
| `make bench` | 41.9 M ops/s, p99 1 µs |
| `tests/verify_uidmap.sh` | PASS — uid 0 inside, 65534 on host, 6/6 namespaces isolated |
| `tests/smoke_sandbox.sh` | all limits enforced, no cgroup nodes leaked |

One bug found by TSan that the functional suite passed straight through — a
speculative non-atomic read of `slot->len` in `vx_ring_pop()` — is described in
the README. It is fixed.
