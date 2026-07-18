# Architecture

Neutron is a five-crate Rust workspace that runs an Aya-loaded eBPF
program against a kernel 6.1+ Android device. There is no C BPF source, no
custom ELF parser, no hand-rolled relocation engine, and no per-CPU perf
ring buffer — Aya owns all of that.

This document describes the runtime data flow and the shape of each
component. For the device baseline see
[docs/devices/pixel8pro.md](devices/pixel8pro.md). For commands and CLI
flags see [docs/REFERENCE.md](REFERENCE.md).

## Component Overview

```
┌────────────────────────────────────────────────────────────────────────┐
│                       Android kernel (6.1.x GKI)                       │
│                                                                        │
│  tracepoint/raw_syscalls/sys_enter ─────┐                              │
│  tracepoint/raw_syscalls/sys_exit  ─────┤                              │
│  tracepoint/sched/sched_process_exit ───┼─▶ trace_*  (aya-ebpf, Rust) │
│  tracepoint/binder/binder_transaction  ─┤                              │
│  tracepoint/binder/binder_transaction_received ─┘                      │
│                                            │                           │
│              ┌─────────────────────────────▼─────┐                     │
│              │ Maps (declared in neutron-ebpf):  │                     │
│              │   FILTER_MAP            Array<u32, 16>  (1.2: 16 slots) │
│              │   EVENTS                RingBuf 1 MiB                   │
│              │   INFLIGHT              HashMap                         │
│              │   SYSCALL_FILTER        HashMap                         │
│              │   PID_WHITELIST         HashMap                         │
│              │   TRACED_PROCESSES      HashMap                         │
│              │   BINDER_FOLLOW_DENY_PIDS HashMap                       │
│              │   ADMITTED_THREAD_ENTERS HashMap                        │
│              │   ROOT_UID_CONTEXT      Array                           │
│              │   BINDER_*_CONTEXT      HashMap                         │
│              │   WATCH_FDS             HashMap                         │
│              │   STACK_TRACES          StackTrace                      │
│              │   COUNTERS              PerCpuArray<u64>                │
│              │   MATCH_UID_SET         HashMap   (1.2)                 │
│              │   MATCH_IOCTL_CMD_SET   HashMap   (1.2)                 │
│              │   MATCH_IOCTL_TYPE_SET  HashMap   (1.2)                 │
│              │   MATCH_IOCTL_NR_SET    HashMap   (1.2)                 │
│              │   MATCH_ARG_U32_VALS    HashMap   (1.2)                 │
│              └────────────────┬───────────────────┘                     │
│                               │  RingBuf reservation                    │
└───────────────────────────────│────────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────────┐
│                      neutron (Aya userspace loader)                    │
│                                                                        │
│  Ebpf::load(bytes) → program_mut(name) → load() → attach()             │
│  bpf.take_map("EVENTS") → RingBuf::try_from(...)                       │
│                                                                        │
│  Userspace sources (sprint-2 + 1.2):                                   │
│    FdGraphPoller   thread → /proc/<pid>/fd  → fd_snapshot lines       │
│    BinderTracker   in-flight LRU keyed by debug_id → binder_call lines │
│    LogcatReader    `logcat -v threadtime *:F` → process_exit lines    │
│    TombstoneWatcher poll /data/tombstones/   → process_exit lines     │
│    RingBufferStore per-PID lookback ring → crash_context dump         │
│    CapturePredicate (1.2)  matcher::MatchSpec | predicate::Expr        │
│    ContextRing      (1.2)  --capture matched+context=<DUR>             │
│    SamplerChain     (1.2)  --sample p + --rate-limit N                 │
│    BinderServiceMap (1.2)  --binder-services <FILE>                    │
│    KernelResolver   (1.2)  kallsyms ⊕ /proc/modules fallback           │
│                                                                        │
│  Event loop:                                                           │
│    1. ring.next() → &[u8] → read_unaligned::<SyscallEvent>             │
│    2. comm / RWX filtering (userspace)                                 │
│    3. dispatch by syscall_nr:                                          │
│         -1  binder caller    → BinderTracker.record_caller             │
│         -2  fd_snapshot      → (drained from poller channel, not ring) │
│         -3  process_exit     → BinderTracker.on_callee_crash + emit    │
│         -4  binder received  → BinderTracker.record_received           │
│         else syscall         → format + engine + lookback              │
│    4. resolve stack via STACK_TRACES + ProcSymbolizer + KernelResolver │
│    5. format JSON (always) + optional text                             │
│    6. CapturePredicate.evaluate(...)                                   │
│       → SamplerChain.keep(ts, nr) (admitted state-tracking exempt)     │
│       → ContextRing.observe(...) when --capture matched+context        │
│    7. RuleEngine::feed → drain_ready (matched events only)             │
│       (--fd-snapshot-on-finding splices fdinfo_at_event on emit)       │
│    8. follow_children / capture_reads side effects                     │
│    9. emit (or park in ContextRing for backward dump)                  │
│  poll(2) on the ring fd when empty.                                    │
└────────────────────────────────────────────────────────────────────────┘

Host-side post-processors:
  neutron window     anchor → time/event window cut (sprint-2)
  neutron summarize  --by <fields> → group counts + exemplars (1.2)
  neutron diff       baseline vs test on a shared key (1.2)
  neutron mark       append a type:"marker" NDJSON line (1.2)
  neutron graph      causal NDJSON → Mermaid or causal-graph/v1 JSON
  neutron surface    inventory/query/reachability/semantic snapshot diff
  neutron report     capture → Markdown boundary report
  neutron ioctl/aidl deterministic source indexes and schema catalogs
  neutron harness    extract/build/minimize/replay regression artifacts
  neutron research   validated data-only scenarios and reports
  neutron native-map / ghidra-export offline ELF address products
  neutron selinux    captured AVC/delegation explanation
```

## BPF Programs (`neutron-ebpf`)

Five programs in `neutron-ebpf/src/main.rs`. All target
`bpfel-unknown-none`, are linked with `bpf-linker`, and ship as a single ELF
object (`neutron.bpf.elf`).

### `trace_sys_enter` (tracepoint/raw_syscalls/sys_enter)

1. Read `pid_tgid` via `bpf_get_current_pid_tgid()`.
2. Filter on `FILTER_MAP[FILTER_KEY_PID]` and `PID_WHITELIST` (children).
3. If `FILTER_MAP[FILTER_KEY_ACTIVE] == 1`, drop syscalls absent from
   `SYSCALL_FILTER` (security profile whitelist).
4. Reserve a slot in the `EVENTS` `RingBuf`.
5. Fill the `SyscallEvent`: timestamp, pid/tgid/uid, syscall_nr, args[0..5],
   `comm`, and `data[128]` decoded by `syscall_nr` (path string,
   `sockaddr`, ioctl cmd+payload, RWX marker).
6. Path strings come from `bpf_probe_read_user_str_bytes` (helper 114).
   Buffer reads come from `bpf_probe_read_user_buf` (helper 112) or
   `bpf_probe_read_kernel_buf` (helper 113).
7. Collect stack IDs via `bpf_get_stackid()` into `STACK_TRACES`
   (`BPF_F_USER_STACK` for user, none for kernel).
8. `INFLIGHT[pid_tgid] = event` for the exit handler.
9. Submit the ring slot.

### `trace_sys_exit` (tracepoint/raw_syscalls/sys_exit)

1. Same PID filter as enter.
2. Look up `INFLIGHT[pid_tgid]` to recover args, data, stack IDs from the
   matching enter event.
3. Stash the enter `timestamp_ns` into the exit event's `args[5]` so
   userspace can compute latency.
4. Set `ret` from the exit tracepoint context.
5. Reserve + fill + submit a new ring slot.
6. Delete the `INFLIGHT` entry.

### `trace_binder_transaction` (tracepoint/binder/binder_transaction)

Loaded only with `--binder`. Synthetic `syscall_nr = -1`. Captures
`to_proc`, AIDL `code`, transaction `flags`, `to_thread`, `reply` flag, and
`target_node` into `args[0..5]`. The kernel-assigned `debug_id` is stashed
in `ptr_hint` so the userspace correlator can pair this with the callee
side. `data[128]` is unused for binder events.

### `trace_binder_transaction_received` (tracepoint/binder/binder_transaction_received)

Loaded only with `--binder`; best-effort attach (a missing tracepoint is
logged but does not abort the run). Synthetic `syscall_nr = -4`. Reads
the kernel-assigned `debug_id` from the tracepoint payload into
`ptr_hint`. Carries no other useful fields — callee `pid` / `tid` come
from `bpf_get_current_pid_tgid()`. Userspace pairs caller and callee by
`debug_id` to emit synthesised `type:"binder_call"` events.

### `trace_sched_process_exit` (tracepoint/sched/sched_process_exit)

Always attached. Synthetic `syscall_nr = -3`. Fires once per task
termination (normal exit, fatal signal, SIGKILL, OOM kill). Captures the
dying task's `comm` from the tracepoint payload (more reliable than
`bpf_get_current_comm()` on the do_exit teardown path) and stamps
`ExitSource::Tracepoint` in `args[2]`. Does NOT carry `exit_code` or
`exit_signal` — the tracepoint payload doesn't expose them, and reading
`task_struct->exit_code` via BTF is deferred. Userspace logcat /
tombstone watchers fill in the signal info when available; otherwise
the event is a "this PID died at this time" marker.

## Aya Loader (`src/main.rs`)

The userspace path is intentionally short. `Ebpf::load` does ELF parsing,
BTF + CO-RE relocation, map creation, license/version checks, and verifier
log capture. Programs are loaded and attached individually:

```rust
let mut bpf = Ebpf::load(&fs::read(object_path)?)?;
let prog: &mut TracePoint = bpf.program_mut("trace_sys_enter")?
    .try_into()?;
prog.load()?;
prog.attach("raw_syscalls", "sys_enter")?;
```

Maps are taken (mutably) once and re-borrowed inside the loop where needed:

```rust
let events_map = bpf.take_map("EVENTS")?;
let mut ring: RingBuf<_> = RingBuf::try_from(events_map)?;
```

`bpf.map_mut("PID_WHITELIST")` and `bpf.map_mut("WATCH_FDS")` are taken
on-demand inside the event-loop iteration when `--follow-children` /
`--capture-reads` is active. Map borrow scopes are short — the rest of the
loop only borrows `bpf` immutably (via `bpf.map("STACK_TRACES")` for the
stack-resolve step).

### Runtime ioctl schemas

`neutron ioctl generate` is a host-only clang subprocess pipeline. It scans
only the requested header roots, preprocesses `_IO*` macros, asks clang for
constant values and record layouts, normalizes/sorts the result, hashes it and
atomically writes a data-only `neutron.ioctl-schema/v1` pack. Optional Rust
constants come from that same normalized model.

Before loading BPF, trace mode validates and merges selected packs into one
descriptor registry. Lookup keys on the full cmd and optional FD path/family,
so reused magic bytes do not collapse unrelated drivers. Existing specialized
Binder, DMA-heap and LWIS decoders run as before; a matching generated
descriptor additionally emits `ioctl_fields`. R/RW commands populate the
existing `IOCTL_REFRESH_CMD_SET` before tracepoint attach. Conflicts and map
capacity errors stop startup.

The generic decoder reads at most the captured 124 bytes. Scalar values,
enums, fixed arrays and pointer numeric values may be rendered; pointer targets
are never read. Unions, bitfields, nested records, flexible arrays and fields
crossing the capture boundary remain opaque.

### Event loop

```
loop {
    while let Some(item) = ring.next() {
        let bytes = &*item;                     // RingBufItem auto-acks on Drop
        let ev: SyscallEvent = read_unaligned(bytes.as_ptr() as _);
        ...
    }
    poll(ring_fd, POLLIN, POLL_TIMEOUT_MS);     // block until readable
}
```

`RingBufItem` releases its slot when dropped (Aya semantics). There is no
separate `data_head` / `data_tail` bookkeeping — that responsibility is
inside Aya. The ring buffer is bounded: a failed BPF `reserve()` drops the
event and increments `COUNTER_RINGBUF_RESERVE_FAILED`; any non-zero value
degrades capture health.

### Symbolization layer (`src/symbolize/`)

Two top-level types:

- `ProcSymbolizer::new(pid)` — parses `/proc/<pid>/maps` once, lazily loads
  ELF symbol tables (`goblin`) per shared library on first hit, detects
  `[anon:dalvik-jit-code-cache]` regions for ART JIT tagging.
  `symbolize(ip)` returns `<file>:<symbol>+0xN`, or `<JIT>+0xN` for JIT
  regions, or `<file>+0xN` when no symbol matched, or `0x...` when the IP
  doesn't fall in any known mapping.
- `KernelSymbolizer::from_kallsyms()` — reads `/proc/kallsyms` once at
  startup. `symbolize(ip)` returns `kernel_symbol+0xN` or raw hex when
  `kptr_restrict` masks the table.

`format_stack()` in `src/main.rs` walks a `StackTraceMap` entry, picks the
right symbolizer per frame (kernel addresses ≥ `0xffff_0000_0000_0000`
on aarch64), and joins frames with ` <- `.

A per-PID cache (`HashMap<u32, Option<ProcSymbolizer>>`) avoids re-reading
`/proc/<pid>/maps` for every event. `None` cached entries mean the process
exited or maps was unreadable.

### Rule-engine pipeline

```
SyscallEvent → JSON line → neutron_rules::Event::parse_line → view → engine.feed(view)
                                                                       │
                                                                       ▼
                                            MatchCondition AND-evaluation
                                                                       │
                                                              frequency window
                                                                       │
                                                              aggregation mode
                                                                       │
                                                                       ▼
                                                             Finding queue
                                                                       │
                                                       drain_ready every N events
                                                                       │
                                                                       ▼
                                                                    output
```

The JSON line is always built (cheap) — it is the canonical input to the
rule engine. The `--stacks`-resolved frames are injected into the JSON as a
top-level `"stack"` field **before** `engine.feed`, so `stack_contains` /
`stack_not_contains` rules see them.

`engine.flush_all()` runs at shutdown to emit any frequency / aggregate
findings still pending in their windows.

## Userspace event sources (sprint-2)

Three crash-correlation sources and the FD-graph poller live in
`src/sources/` and `src/fdgraph/poller.rs`. They run alongside the BPF
event loop; main.rs drains their output channels every iteration.

### `FdGraphPoller`

Spawned thread that periodically reads `/proc/<pid>/fd` and
`/proc/<pid>/limits` for in-scope PIDs and forwards `FdSampleEvent`
values back via an `mpsc::sync_channel`. Main loop converts each into a
`type:"fd_snapshot"` JSON line and feeds it to the rule engine. Scope
policies (`Traced`, `Active`, `UidClass`, `All`) and interval are
controlled by `--fdgraph-pids` / `--fdgraph-interval`. PID set updates
are pushed to the poller via a separate channel; sends are non-blocking
so the BPF event loop never stalls.

### `BinderTracker`

Bounded LRU map keyed by `debug_id`. The BPF caller-side
`binder_transaction` (nr=-1) inserts an `Inflight` record; the
callee-side `binder_transaction_received` (nr=-4) removes it and emits a
synthesised `type:"binder_call"` JSON line with `status:"completed"`.
On a `process_exit` with `classification=crash`, the tracker drains
every in-flight entry whose `callee_pid` matches the dying PID and
emits each as `status:"callee_crashed"`. Default cap is 1024 in-flight
transactions; LRU eviction silently drops the oldest entry on overflow.

### `LogcatReader` and `TombstoneWatcher`

Two userspace crash sources, both behind small traits so unit tests can
inject synthetic streams. `LogcatReader` spawns
`logcat -v threadtime *:F` and parses three line patterns: Java
`FATAL EXCEPTION:` blocks, native `DEBUG : pid: N, tid: N, name: ...`
debuggerd headers, and `ANR in <pkg>` lines. `TombstoneWatcher` polls a
configurable directory (default `/data/tombstones/`) at 1 Hz; on first
observation it primes the seen-set without emission so pre-existing
files don't show up as "new" crashes. Both sources emit
`ProcessExitEvent` values that are formatted into `type:"process_exit"`
JSON via the shared `emit_process_exit` helper.

### `RingBufferStore`

Per-PID bounded ring buffer of recent NDJSON event lines. The main
loop pushes every emitted line into it; on `process_exit` (from any
source) the buffer is drained for the dying PID and dumped into the
emitted JSON's `crash_context` array. Default cap is 200 PIDs × 100
lines; LRU eviction handles overflow. Disabled with
`--lookback-events 0`.

## SyscallEvent Wire Format

Defined once in `neutron-common/src/lib.rs`. `#[repr(C, packed)]`,
**257 bytes total**, asserted at compile time in both `neutron-common`
and `neutron-ebpf`. The legacy 0.1 layout was 241 bytes; the current layout
adds a dedicated `enter_timestamp_ns` slot (8 B), `maps_generation` (2 B),
and 6 reserved bytes. Later event semantics did not bump the struct.

| Field                | Type   | Offset | Size | Notes                                                    |
|----------------------|--------|--------|------|----------------------------------------------------------|
| `timestamp_ns`       | u64    | 0      | 8    | `bpf_ktime_get_ns()`                                     |
| `pid`                | u32    | 8      | 4    | Userspace PID (kernel `tgid`); what `--pid` matches      |
| `tgid`               | u32    | 12     | 4    | Userspace TID (kernel `pid`); per-thread                 |
| `uid`                | u32    | 16     | 4    | from `bpf_get_current_uid_gid()`                         |
| `syscall_nr`         | i32    | 20     | 4    | -1 binder caller / -2 fd_snapshot / -3 process_exit / -4 binder_received |
| `args[6]`            | u64[6] | 24     | 48   | syscall args; on exit/synth events: see per-nr table     |
| `ret`                | i64    | 72     | 8    | return value (exit events)                               |
| `is_enter`           | u8     | 80     | 1    | 1 = enter, 0 = exit                                      |
| `comm[16]`           | u8[16] | 81     | 16   | from `bpf_get_current_comm()`                            |
| `data[128]`          | u8[128]| 97     | 128  | union, see below                                         |
| `kernel_stackid`     | i32    | 225    | 4    | key into `STACK_TRACES`, -1 if unset                     |
| `user_stackid`       | i32    | 229    | 4    | key into `STACK_TRACES`, -1 if unset                     |
| `ptr_hint`           | u64    | 233    | 8    | raw user pointer; binder `debug_id` on nr=-1 / nr=-4     |
| `enter_timestamp_ns` | u64    | 241    | 8    | enter ts copied through INFLIGHT for latency calc        |
| `maps_generation`    | u16    | 249    | 2    | active causal scenario generation; zero outside a scenario |
| `_reserved`          | u8[6]  | 251    | 6    | padding for next single-field bump                       |

### Synthetic event semantics

| `syscall_nr` | Event kind          | Notes                                                           |
|--------------|---------------------|-----------------------------------------------------------------|
| `-1`         | `binder` (caller)   | `args[0..5]` = to_proc/code/flags/to_thread/reply/target_node; `ptr_hint` = debug_id |
| `-2`         | `fd_snapshot`       | Not emitted via the BPF wire; constructed userspace-side from poller channel |
| `-3`         | `process_exit`      | `args[0]` = exit_code, `args[1]` = exit_signal, `args[2]` = ExitSource enum |
| `-4`         | `binder_received`   | `ptr_hint` = debug_id (matched against nr=-1 entries)           |

### `data[128]` union semantics

| `syscall_nr`                           | Encoding                                     |
|----------------------------------------|----------------------------------------------|
| 56, 48, 79, 78, 43, 36, 35             | NUL-terminated path string from `args[1]`    |
| 221 (execve)                           | NUL-terminated filename from `args[0]`       |
| 281 (execveat)                         | NUL-terminated filename from `args[1]`       |
| 29 (ioctl)                             | `[0..4]` cmd LE u32; `[4..128]` payload      |
| 200, 203, 206 (bind/connect/sendto)    | `sockaddr` from the address pointer          |
| 211, 212 (sendmsg/recvmsg)             | `[0..28]` sockaddr; `[64..72]` controllen    |
| 222, 226 (mmap/mprotect)               | `[0]` = 1 (RWX), 2 (WX), or 0                |
| -1 (binder)                            | unused; binder fields live in `args[0..5]`   |

### Latency computation

`trace_sys_exit` copies the enter event's `timestamp_ns` into the exit
event's `enter_timestamp_ns` slot before submitting (no longer hijacks
`args[5]` — that was the 1.0.0 baseline workaround). Userspace
`compute_latency_us()` subtracts it from the exit `ts_ns` and divides
by 1000 to get `latency_us`. If `INFLIGHT` was full and the entry got
evicted, `latency_us` is `null` in JSON output.

## BPF Maps

| Map | Type | Key | Value | Max entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `FILTER_MAP` | `Array<u32>` | u32 slot | u32 | 16 | Trace, predicate, and causal mode controls defined by `FILTER_KEY_*`. |
| `EVENTS` | `RingBuf` | — | bytes | 1 MiB | Single multi-producer event ring. |
| `EVENT_SCRATCH` | `PerCpuArray` | u32 | aligned event | 1 | Exit-path scratch outside the 512-byte BPF stack. |
| `INFLIGHT` | `HashMap` | u64 pid_tgid | `SyscallEvent` | 4096 | Syscall enter/exit correlation. |
| `SYSCALL_FILTER` | `HashMap` | u32 syscall | u8 | 64 | Active syscall whitelist. |
| `PID_WHITELIST` | `HashMap` | u32 PID | u8 | 256 | `--follow-children` PIDs. |
| `TRACED_PROCESSES` | `HashMap` | u32 PID | `ProcessTraceContext` | 64 default, loader override | Bounded dynamic causal set (`--max-processes`). |
| `BINDER_FOLLOW_DENY_PIDS` | `HashMap` | u32 PID | u8 | 64 | Reserved for pre-admission Binder deny policy. The related CLI flags are rejected in 1.5 because complete enforcement is not yet safe. |
| `ADMITTED_THREAD_ENTERS` | `HashMap` | u64 pid_tgid | u8 | 4096 | Post-admission syscall-enter marker. It classifies a first exit from an already-active sibling Binder thread as a causal admission boundary rather than an `INFLIGHT` loss. |
| `ROOT_UID_CONTEXT` | `Array` | u32 | `ProcessTraceContext` | 1 | Current explicit UID-root context. |
| `BINDER_TRANSACTION_CONTEXT` | `HashMap` | u32 debug ID | Binder transaction context | 4096 | Caller-to-callee causal propagation, including a one-use admission-boundary marker for syscall-exit accounting. |
| `THREAD_BINDER_CONTEXT` | `HashMap` | u64 pid_tgid | Binder thread context | 4096 | Exact receiving-thread attribution. |
| `WATCH_FDS` | `HashMap` | u64 pid<<32\|fd | u8 | 256 | Selective read/write FD tracking; buffer content is not captured in ABI v1. |
| `STACK_TRACES` | `StackTrace` | u32 stack ID | u64[127] | 16384 | Kernel and user IP arrays; present with `stacks`. |
| `MATCH_UID_SET` | `HashMap` | u32 UID | u8 | 64 | UID predicate values. |
| `MATCH_IOCTL_CMD_SET` | `HashMap` | u32 cmd | u8 | 64 | Full ioctl command predicates. |
| `MATCH_IOCTL_TYPE_SET` | `HashMap` | u32 type | u8 | 16 | `_IOC_TYPE` predicates. |
| `MATCH_IOCTL_NR_SET` | `HashMap` | u32 number | u8 | 64 | `_IOC_NR` predicates. |
| `MATCH_ARG_U32_VALS` | `HashMap` | u32 value | u8 | 32 | Bounded captured-argument predicates. |
| `IOCTL_REFRESH_CMD_SET` | `HashMap` | u32 cmd | u8 | 64 | Schema-selected post-exit refresh commands. |
| `IOCTL_REFRESH_TYPE_SET` | `HashMap` | u32 type | u8 | 32 | Schema-selected post-exit refresh families. |
| `COUNTERS` | `PerCpuArray<u64>` | u32 slot | per-CPU u64 | 21 | Capture-health counters aggregated by userspace without racy read/add/write updates. |

Map names are the **exact** Rust static identifiers in
`neutron-ebpf/src/main.rs`. Aya does not lowercase them. The userspace
loader looks them up case-sensitively.

## Kernel 6.1+ assumptions

These are **not** workarounds — they are direct uses of capabilities the
target kernel guarantees. See `docs/devices/pixel8pro.md` for the verified
config.

- **BTF available**: `/sys/kernel/btf/vmlinux` is exposed. Aya runs runtime
  BTF relocation when the BPF object contains debuginfo (it does — `debug
  = true` in the release profile of `neutron-ebpf`).
- **JIT mandatory** (`BPF_JIT_ALWAYS_ON=y`).
- **No PAN restriction**: `bpf_probe_read_user_*` reads userspace memory
  directly from the BPF programs. The userspace `--resolve-paths`
  fallback (`/proc/<pid>/fd/<fd>` readlink, `/proc/net/tcp*`) remains as
  a belt-and-braces option for cases where the in-kernel read returned a
  truncated buffer or a closed fd.
- **RingBuf available** (kernel 5.8+). `BPF_MAP_TYPE_RINGBUF` is the
  output channel. The CLI `--pages` flag is accepted for backward
  compatibility but ignored.
- **No BPF LSM, no `fentry`/`fexit`**: see device profile. We use
  tracepoints + kprobes only.
- **BPF stack limit still 512 bytes**: `SyscallEvent` (257) goes via
  `MaybeUninit` and a `RingBuf::reserve()` slot, never as a stack-local
  copy.

## What is intentionally not yet implemented

- `bpf_d_path` for fd-to-path resolution. Requires BPF LSM hooks, which
  are not enabled on the husky GKI kernel.
- ART method-resolved JIT symbolization. The current implementation tags
  JIT regions but does not walk ART runtime structures — that is V1.x
  backlog (see [docs/ROADMAP.md](ROADMAP.md)).
- `bpf_loop` for variable-length scans. The verifier on 6.1.x supports it,
  but the existing unrolled paths are short enough that the rewrite has
  not been justified.
- Pinned maps (`/sys/fs/bpf/...`) for cross-process coordination. The
  filesystem is mounted on the device — see V2 considerations in
  ROADMAP.md.
- `task_struct->exit_code` BTF read on the BPF `sched_process_exit` path.
  The tracepoint payload doesn't carry exit_code/exit_signal; today
  userspace logcat / tombstone sources fill them in. A BTF read would
  let the BPF path emit `exit_signal` directly, useful on hosts where
  logcat is unavailable.
- Generic Binder Parcel decoding beyond the AIDL `code` field. The correlator
  pairs caller↔callee and surfaces interface/method attribution where exact
  catalog evidence exists. A bounded offline KeyMint plugin can decode one
  complete harness shape; version-independent arbitrary Parcel unmarshalling
  remains out of scope.
