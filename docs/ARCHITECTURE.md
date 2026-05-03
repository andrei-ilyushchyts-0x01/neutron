# Architecture

neutron 1.0 is a four-crate Rust workspace that runs an Aya-loaded eBPF
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
│  tracepoint/raw_syscalls/sys_enter ──┐                                 │
│  tracepoint/raw_syscalls/sys_exit  ──┼──▶ trace_*  (aya-ebpf, Rust)   │
│  tracepoint/binder/binder_transaction┘     │                           │
│                                            │                           │
│              ┌─────────────────────────────▼─────┐                     │
│              │ Maps (declared in neutron-ebpf):  │                     │
│              │   FILTER_MAP    Array<u32>         │                     │
│              │   EVENTS        RingBuf 1 MiB      │                     │
│              │   INFLIGHT      HashMap            │                     │
│              │   SYSCALL_FILTER HashMap           │                     │
│              │   PID_WHITELIST  HashMap           │                     │
│              │   WATCH_FDS      HashMap           │                     │
│              │   STACK_TRACES   StackTrace        │                     │
│              └────────────────┬───────────────────┘                     │
│                               │  RingBuf reservation                    │
└───────────────────────────────│────────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────────┐
│                      neutron (Aya userspace loader)                    │
│                                                                        │
│  Ebpf::load(bytes) → program_mut(name) → load() → attach()            │
│  bpf.take_map("EVENTS") → RingBuf::try_from(...)                       │
│                                                                        │
│  Event loop:                                                           │
│    1. ring.next() → &[u8] → read_unaligned::<SyscallEvent>             │
│    2. comm/RWX filtering (userspace)                                    │
│    3. resolve stack via STACK_TRACES + ProcSymbolizer + KernelSymbolizer│
│    4. format JSON (always) + optional text                             │
│    5. RuleEngine::feed → drain_ready                                    │
│    6. follow_children / capture_reads side effects                     │
│    7. emit                                                             │
│  poll(2) on the ring fd when empty.                                    │
└────────────────────────────────────────────────────────────────────────┘
```

## BPF Programs (`neutron-ebpf`)

Three programs in `neutron-ebpf/src/main.rs`. All target
`bpfel-unknown-none`, are linked with `bpf-linker`, and ship as a single ELF
object (`neutron.bpf.elf`, ~20 KiB).

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
`target_node` into `args[0..5]`. `data[128]` is unused for binder events.

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
inside Aya. Lossless from the producer's perspective: drops only happen if
`reserve()` returns `None` inside the BPF program (ring full), which the
BPF code handles silently.

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
`stack_not_contains` rules see them. (Pre-1.0 this was a bug: stack
resolution happened later, so stack-aware rules would never match.)

`engine.flush_all()` runs at shutdown to emit any frequency / aggregate
findings still pending in their windows.

## SyscallEvent Wire Format

Defined once in `neutron-common/src/lib.rs`. `#[repr(C, packed)]`,
**241 bytes total**, asserted at compile time. Both `neutron-ebpf` and the
userspace loader read this type directly via `addr_of!` /
`read_unaligned`.

| Field            | Type   | Offset | Size | Notes                                         |
|------------------|--------|--------|------|-----------------------------------------------|
| `timestamp_ns`   | u64    | 0      | 8    | `bpf_ktime_get_ns()`                          |
| `pid`            | u32    | 8      | 4    | Linux TID                                     |
| `tgid`           | u32    | 12     | 4    | Linux PID                                     |
| `uid`            | u32    | 16     | 4    | from `bpf_get_current_uid_gid()`              |
| `syscall_nr`     | i32    | 20     | 4    | `-1` = binder synthetic event                 |
| `args[6]`        | u64[6] | 24     | 48   | syscall args; `args[5]` repurposed on exit    |
| `ret`            | i64    | 72     | 8    | return value (exit events)                    |
| `is_enter`       | u8     | 80     | 1    | 1 = enter, 0 = exit                           |
| `comm[16]`       | u8[16] | 81     | 16   | from `bpf_get_current_comm()`                 |
| `data[128]`      | u8[128]| 97     | 128  | union, see below                              |
| `kernel_stackid` | i32    | 225    | 4    | key into `STACK_TRACES`, -1 if unset          |
| `user_stackid`   | i32    | 229    | 4    | key into `STACK_TRACES`, -1 if unset          |
| `ptr_hint`       | u64    | 233    | 8    | raw user pointer; reserved for Frida bridge   |

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

### `args[5]` repurposing on exit

`trace_sys_exit` writes `INFLIGHT[pid_tgid].timestamp_ns` into the exit
event's `args[5]` before submitting. Userspace `compute_latency_us()`
subtracts it from the exit `ts_ns` and divides by 1000 to get
`latency_us`. If `INFLIGHT` was full and the entry got evicted,
`latency_us` is `null` in JSON output.

## BPF Maps

| Map               | Type             | Key             | Value          | Max entries | Purpose                                            |
|-------------------|------------------|-----------------|----------------|-------------|----------------------------------------------------|
| `FILTER_MAP`      | `Array<u32>`     | u32 idx         | u32            | 2           | `[0]` = target PID, `[1]` = syscall filter active  |
| `EVENTS`          | `RingBuf`        | —               | bytes          | 1 MiB       | event output ring (single multi-producer ring)     |
| `INFLIGHT`        | `HashMap`        | u64 (pid_tgid)  | `SyscallEvent` | 4096        | enter/exit correlation                             |
| `SYSCALL_FILTER`  | `HashMap`        | u32 (nr)        | u8             | 64          | `--profile security` whitelist                     |
| `PID_WHITELIST`   | `HashMap`        | u32 (pid)       | u8             | 256         | `--follow-children` child PIDs                     |
| `WATCH_FDS`       | `HashMap`        | u64 (pid<<32\|fd)| u8            | 256         | `--capture-reads` watched fds                      |
| `STACK_TRACES`    | `StackTrace`     | u32 (stackid)   | u64[127]       | 16384       | kernel + user IP arrays for `bpf_get_stackid`      |

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
  directly. The 0.1.0 PAN-fallback path (`process_vm_readv` from
  userspace) is gone from the BPF programs. The userspace `--resolve-paths`
  fallback (`/proc/<pid>/fd/<fd>` readlink, `/proc/net/tcp*`) remains as a
  belt-and-braces option for cases where the in-kernel read returned a
  truncated buffer or a closed fd.
- **RingBuf available** (kernel 5.8+). `BPF_MAP_TYPE_RINGBUF` is the
  output channel. The CLI `--pages` flag is accepted for backward
  compatibility but ignored.
- **No BPF LSM, no `fentry`/`fexit`**: see device profile. We use
  tracepoints + kprobes only.
- **BPF stack limit still 512 bytes**: `SyscallEvent` (241) goes via
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
