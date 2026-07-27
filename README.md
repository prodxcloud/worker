# prodxcloud/worker

**The VxCloud system ABI and kernel isolation layer — pure C11, zero dependencies.**

`worker` is the immutable execution contract every VxCloud task passes through, and
the sandbox it runs inside. It is deliberately the least interesting layer in the
stack: no runtime, no garbage collector, no event loop, no allocator tricks — just
libc and Linux system calls. Everything above it (`ion` in Rust, `iron` in C++23)
is free to be clever, because this layer is not.

```
             host: vxnode runtime
                     │
                     │  vx_task_header_t  (93 bytes, packed, LE)
                     ▼
        ┌────────────────────────────┐
        │   libvxworker (C11)        │
        │                            │
        │  vx_sandbox  clone(2) →    │   CLONE_NEWUSER | NEWPID | NEWNET
        │              namespaces    │   NEWIPC | NEWNS | NEWUTS | NEWCGROUP
        │  vx_cgroup   cgroups v2    │   memory.max · cpu.max · pids.max
        │  vx_ipc      shm ring      │   lock-free SPMC, zero syscalls
        │  vx_signal   signalfd      │   no async-signal-safety hazards
        └────────────┬───────────────┘
                     ▼
         guest: ion (Rust) │ iron (C++23)
```

| | |
|---|---|
| Language | C11 (`-std=c11`, `-Wall -Wextra -Wpedantic -Werror`) |
| Dependencies | none — libc + Linux kernel only |
| Platform | Linux ≥ 5.14 (cgroup v2 unified hierarchy, `cgroup.kill`) |
| Binary | `vxworker` (~60 KiB) + `libvxworker.a` |
| Tests | 1,471 assertions across 6 suites; clean under ASan, UBSan and TSan |

---

## Quick start

```sh
make                 # build libvxworker.a + vxworker
make test            # 6 suites, 1,471 assertions
make bench           # ring-buffer throughput and latency
make asan            # AddressSanitizer + UndefinedBehaviorSanitizer
make tsan            # ThreadSanitizer over the concurrent ring
sudo make install    # /usr/local/{bin,lib,include/vx}
```

Namespace and cgroup work needs `CAP_SYS_ADMIN`; the affected suites report
`SKIP` rather than failing when run unprivileged.

---

## What it actually enforces

Verified on Linux 6.6 (WSL2), cgroup v2, GCC 14.2 — this is captured output, not
aspiration.

### Identity: root inside, nobody outside

The central guarantee. A task believes it is `uid 0` and can do root-ish things
to its own namespace; the host sees an unprivileged account.

```
$ vxworker run --task-id 101 --tenant acme -- \
    sh -c 'echo "inside: uid=$(id -u) hostname=$(hostname) pid=$$"'
inside: uid=0 hostname=vxworker pid=1
state=COMPLETED exit=0 duration_us=44060 mem_peak=1302528 cpu_us=7332 oom=0

$ cat /proc/<guest>/uid_map        # read from the host
    0      65534          1
$ grep Uid: /proc/<guest>/status
Uid:    65534   65534   65534   65534
```

`tests/verify_uidmap.sh` asserts this from `/proc` directly, and confirms all six
namespace inodes differ from the host's:

```
user: isolated (host=user:[4026531837] guest=user:[4026534237])
pid:  isolated (host=pid:[4026532227]  guest=pid:[4026534241])
net:  isolated (host=net:[4026531840]  guest=net:[4026534243])
ipc:  isolated (host=ipc:[4026532212]  guest=ipc:[4026534240])
mnt:  isolated (host=mnt:[4026532224]  guest=mnt:[4026534238])
uts:  isolated (host=uts:[4026532226]  guest=uts:[4026534239])
```

### Resource limits that actually bind

```
memory: 16 MiB cap vs a 256 MiB allocation
  state=KILLED_OOM exit=137 duration_us=52379 mem_peak=16777216 oom=1

cpu:    10% of one core, 3s deadline, busy loop
  state=KILLED_TIMEOUT exit=137 cpu_us=309723   (throttled, never finished)

pids:   pids.max=5 vs 10 forks
  /bin/sh: 0: Cannot fork
  state=FAILED exit=2

timeout: sleep 30 with a 500ms deadline
  state=KILLED_TIMEOUT exit=137 duration_us=504885
```

Peak memory landed on exactly 16777216 bytes — the limit, to the byte — and the
kill took 52 ms.

### Network

A new netns starts with loopback administratively **down**, which silently breaks
anything that binds `127.0.0.1`. `worker` brings it up with `SIOCSIFFLAGS` on an
`AF_INET` socket — no netlink dependency, no spawning `ip`:

```
$ vxworker run -- ip -o link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
```

One interface. No host devices, no route to the host network.

---

## Two findings worth reading before you copy this code

Both were caught by tooling, not review, and both are the kind of bug that
happily passes a green test suite.

### 1. `memory.max` alone is not a memory limit

First attempt capped a task at 16 MiB and watched it allocate 256 MiB anyway. The
cgroup limit was being honoured exactly — `memory.current` never exceeded
15 MiB — because the kernel reclaimed the task's cold anonymous pages to **swap**.
A limit that swap can escape is not a limit, and on a multi-tenant node the swap
device is shared. So `vx_cgroup_set_memory()` writes `memory.swap.max = 0`
alongside `memory.max`.

Then it got worse in a more interesting way. With swap denied and
`memory.high` set to 90% of the cap — the "be graceful, reclaim before you kill"
setting — the task did not die. It *thrashed*, making essentially no forward
progress, until the supervisor's 20-second wall-clock deadline fired:

| configuration | outcome | latency | reported state |
|---|---|---|---|
| `memory.max` only | OOM-killed | **52 ms** | `KILLED_OOM` ✅ |
| `+ memory.high` at 90% | thrashed to deadline | 20,050 ms | `KILLED_TIMEOUT` ❌ |

`memory.high` throttles; it does not kill. Combined with a wall-clock deadline it
converts a memory bug into a 400×-slower failure *and* misattributes the cause.
So `memory.high` is left disabled by default — the same choice Docker and
Kubernetes make — and offered as opt-in via `vx_cgroup_set_memory_high()` for
elastic workloads that would rather run slowly than die.

### 2. ThreadSanitizer found a data race that 1,268 passing assertions did not

The ring's `slot->len` was a plain `uint32_t`. A consumer reads it
*speculatively*, before winning the claim CAS, so it can reject an undersized
destination buffer without consuming the record. By then a peer may have claimed
the slot and the producer may already be refilling it — an unsynchronised
concurrent read and write.

Behaviourally it was fine: the length is re-read and re-validated after the CAS
succeeds. But a data race is undefined behaviour, and on a weakly-ordered target
the read can genuinely tear. `len` is now `atomic_uint_least32_t` accessed with
relaxed ordering: the speculative read becomes well-defined while staying free,
and correctness still rests on the post-CAS re-read.

A green suite is not evidence of a correct lock-free protocol. Run the sanitizer.

---

## The ABI

`include/worker_abi.h` is the contract. v1 offsets are **frozen** — `ion` and
`iron` decode frames by hard-coded offset, with no parser:

```
offset  size  field
     0     4  magic            0x58575601  ('V','X','W', v1)
     4     8  task_id
    12    64  tenant_id[64]    NUL-padded
    76     1  engine           0x01 ion │ 0x02 iron
    77     4  memory_limit_mb  → cgroup memory.max
    81     4  cpu_quota_us     → cgroup cpu.max
    85     8  payload_len
    93     -  payload[]        JSON / Protobuf / raw
```

93 bytes, packed, little-endian. `tests/test_abi_layout.c` asserts every offset
and the exact byte pattern, and the header carries `_Static_assert`s so a layout
drift fails at compile time in C **and** C++. Frames round-trip through
`worker` → `ion` and `worker` → `iron`:

```sh
vxworker encode-task --task-id 42 --tenant acme --engine ion \
         --payload '{"url":"https://example.com"}' > task.bin
ion run task.bin          # or: iron run task.bin
```

Decoding is a validation, not a parse — bad magic, an unknown engine, a
`payload_len` past the end of the buffer, and anything over the 16 MiB cap are all
rejected before a single field is believed. That matters because the frame arrives
through shared memory a guest can also write to.

---

## The IPC ring

Single producer, many consumers, over `shm_open` + `mmap`. A payload crosses the
process boundary with one `memcpy` in and one out: no socket, no serialisation
hop, no kernel copy, and **no syscall on either hot path** after setup.

The algorithm is a bounded slot ring with a per-slot generation counter (Vyukov).
Three invariants carry it:

```
seq == pos          slot is free for the producer at cursor pos
seq == pos + 1      slot holds a published record for the consumer at pos
seq == pos + N      slot has been drained and recycled one generation on
```

A consumer that wins the CAS owns its slot exclusively until it republishes the
sequence, so the producer can never overwrite a record mid-read. Cursors are
monotonic 64-bit counters, never reduced modulo the slot count, so wrap-around
needs no special case. Producer cursor, consumer cursor and statistics each get
their own cache line.

Measured (`make bench`, 2M iterations, 64-byte payloads):

| | |
|---|---|
| same-thread push+pop | **41.9 M round-trips/s** (24 ns) |
| payload throughput | 5.00 GiB/s |
| latency | p50 <1 µs · p99 1 µs · p99.9 1 µs |
| producer thread → consumer thread | **15.4 M records/s** (65 ns) |

Correctness under contention — 200,000 records, 1 producer, 4 consumers, a
256-slot ring forced full 197,122 times:

```
produced=200000 consumed=200000  →  0 lost, 0 duplicated
ThreadSanitizer: no data races reported.
```

Loss and duplication are checked with a per-record seen-counter, not by comparing
totals: equal counts can hide one record delivered twice and another dropped.

---

## API

```c
/* Sandbox */
void        vx_sandbox_spec_init (vx_sandbox_spec_t *);          /* safe defaults */
vx_status_t vx_sandbox_probe     (vx_sandbox_caps_t *);          /* what the kernel allows */
vx_status_t vx_sandbox_spawn     (vx_sandbox_t *, const vx_sandbox_spec_t *);
vx_status_t vx_sandbox_wait      (vx_sandbox_t *, uint32_t ms, vx_sandbox_result_t *);
vx_status_t vx_sandbox_kill      (vx_sandbox_t *, int signo);
vx_status_t vx_sandbox_destroy   (vx_sandbox_t *);

/* cgroups v2 */
vx_status_t vx_cgroup_create     (vx_cgroup_t *, uint64_t task_id, const char *root);
vx_status_t vx_cgroup_set_memory (vx_cgroup_t *, uint32_t mb);   /* + swap.max = 0 */
vx_status_t vx_cgroup_set_cpu    (vx_cgroup_t *, uint32_t quota_us, uint32_t period_us);
vx_status_t vx_cgroup_kill_all   (const vx_cgroup_t *);          /* cgroup.kill */
vx_status_t vx_cgroup_read_stats (const vx_cgroup_t *, vx_cgroup_stats_t *);

/* Ring */
vx_status_t vx_ring_create       (vx_ring_t **, const char *name, uint32_t slots, uint32_t bytes);
vx_status_t vx_ring_open         (vx_ring_t **, const char *name, bool read_only);
vx_status_t vx_ring_push         (vx_ring_t *, const void *, uint32_t);
vx_status_t vx_ring_pop          (vx_ring_t *, void *, uint32_t cap, uint32_t *out_len);

/* Frames */
vx_status_t vx_task_decode       (const void *, size_t, const vx_task_header_t **);
long        vx_task_encode       (void *, size_t, uint64_t, const char *, vx_engine_type_t,
                                  uint32_t, uint32_t, const void *, size_t);
```

Every entry point returns a `vx_status_t`; negative values are errors with stable
names (`vx_status_name()`) and operator-readable text (`vx_status_str()`). Nothing
returns `errno` and nothing aborts.

---

## Design notes

**Why `clone(2)` and not `fork()` + `unshare()`.** `CLONE_NEWPID` applied via
`unshare()` only affects the caller's *children*. Cloning directly makes the guest
PID 1 of its own namespace, which is what a supervisor needs in order to reap
orphans and receive the namespace's signals.

**The startup handshake.** Both barriers are load-bearing:

```
parent                                child (clone'd)
──────                                ───────────────
clone(CLONE_NEW*)  ───────────────→   blocks reading sync_in
write setgroups = deny
write uid_map "0 <host_uid> 1"
write gid_map "0 <host_gid> 1"
cgroup.procs ← child pid
write sync_in      ───────────────→   wakes; setresuid(0); mounts; exec
```

The child must not run before the uid map lands, or it executes as the overflow
uid with no way to become root in its own namespace. The parent must not release
it before the cgroup attach, or the guest's startup allocations escape the memory
limit — cgroup v2 does **not** migrate existing page charges when a process is
moved, so attaching late means those pages stay billed to the old cgroup forever.
`tests/test_cgroup.c` pins that behaviour deliberately.

**Exec failure without a timeout.** The error pipe is `O_CLOEXEC`, so a successful
`execvp` closes it and the parent reads EOF. A failure writes `{stage, errno}`
instead. No polling, no guessing:

```
$ vxworker run -- /nonexistent/binary
[vxworker ERROR] sandbox setup failed at execvp: No such file or directory
spawn failed: VX_ERR_SPAWN
```

**`signalfd` over handlers.** Signals become readable fd events, which deletes the
entire "what may I call from a handler" class of bug. `vx_signal_reset_for_child()`
restores default dispositions before `exec` — a blocked signal survives `execve`,
so without it the guest would start life unable to receive `SIGTERM` and graceful
shutdown would silently do nothing. `tests/test_signal.c` asserts both the
positive and the negative control.

**`pidfd` over pid polling.** A pidfd cannot be confused by pid reuse. `poll()` on
it gives a race-free wait with a deadline; there is a `waitpid(WNOHANG)` fallback
for kernels below 5.3.

**Probe, never assume.** `vx_sandbox_probe()` forks a throwaway child and *tries*
each `unshare()` flag, because a hardened host, an unprivileged container or an LSM
policy can deny any one of them. Inspecting `/proc` tells you what should work.

```
$ vxworker probe
namespaces:  CLONE_NEWUSER yes  CLONE_NEWPID yes  CLONE_NEWNET yes ...
cgroups:     cgroup v2 yes  memory yes  cpu yes  pids yes  cgroup.kill yes
facilities:  pidfd_open yes  signalfd yes  euid 0
verdict: full isolation available
```

---

## Layout

```
include/worker_abi.h     the frozen v1 contract (also consumed by ion and iron)
include/vx_sandbox.h     namespaces + cgroups + lifecycle
include/vx_cgroup.h      cgroup v2 control files
include/vx_ipc.h         lock-free SPMC shared-memory ring
include/vx_signal.h      signalfd supervision
include/vx_task.h        frame codec
src/                     implementations (~2,000 lines)
tests/                   6 self-checking suites + shell verifiers
bench/bench_ipc.c        throughput and latency
```

## Known limits

- **Linux only, by construction.** The build refuses any other kernel rather than
  pretending to be portable.
- **No seccomp filter yet.** Namespaces and cgroups bound what a task can *reach*
  and *consume*, not which syscalls it may issue. A `seccomp-bpf` allowlist is the
  next layer.
- **No rootfs pivot.** `spec.rootfs` is not implemented; the guest shares the
  host filesystem view apart from `/proc`. Pair with an overlay or an existing
  image runtime if you need a private root.
- **cgroup v1 is not supported** and will not be — its split hierarchies cannot
  express an atomic memory+cpu+pids envelope.
- TSan's teardown aborts on kernels with `vm.mmap_rnd_bits=32` (the 6.x/WSL2
  default) *after* the suite completes. `tests/run_tsan.sh` separates that from a
  real finding instead of hiding it.

## License

Apache-2.0. See [LICENSE](LICENSE).
