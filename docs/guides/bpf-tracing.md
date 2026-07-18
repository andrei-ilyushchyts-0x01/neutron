# BPF Tracing Guide

This guide covers how neutron uses BPF to capture syscall events, what each
tracing mode does, and how to get the most out of the tool.

## How Syscall Tracing Works

neutron attaches BPF programs (in `neutron-ebpf`) to up to five
tracepoints:

| Tracepoint | When attached | Synthetic `nr` | Purpose |
|------------|---------------|----------------|---------|
| `raw_syscalls/sys_enter` | always | n/a (real `nr`) | syscall enter capture |
| `raw_syscalls/sys_exit` | always | n/a (real `nr`) | syscall exit capture |
| `sched/sched_process_exit` | always | `-3` | process termination marker (crash correlation) |
| `binder/binder_transaction` | `--binder` | `-1` | caller-side binder transaction |
| `binder/binder_transaction_received` | `--binder` (best-effort) | `-4` | callee-side binder dequeue |

At each tracepoint, the BPF program runs in kernel context with access to
BPF helpers. It fills a `SyscallEvent` (257 bytes, packed) and submits it
to the `EVENTS` `RingBuf`.

The two events are correlated in the `INFLIGHT` map (keyed by
`pid_tgid`): the enter handler stores the event, the exit handler looks
it up, copies the data, adds the return value, and submits the exit
event.

```
sys_enter  ─────────────────────────────────────►  INFLIGHT[pid_tgid] = event
                                                          │
sys_exit   ◄─────────────────────────────────────  lookup INFLIGHT
           submit exit event (with ret + enter_ts)  delete INFLIGHT[pid_tgid]
```

The `EVENTS` map is a bounded single multi-producer
`BPF_MAP_TYPE_RINGBUF` (kernel 5.8+) of 1 MiB. When
`ring.reserve()` returns `None` because the ring is full, the event is
dropped and the reserve-failure health counter is incremented. There is no
per-CPU buffer juggling and no `--pages` to tune (the flag is accepted for
backward compatibility but ignored).

## PID Filtering

Set `--pid N` to trace a single process. All threads of that process are
traced (filter is on `tgid`, the POSIX PID). `--pid 0` traces all
processes.

**Child process tracking**: With `--follow-children`, neutron monitors
`clone()` exit events and inserts child PIDs into `PID_WHITELIST`.
Children of children are also tracked.

## Syscall Profiles

### Default (no profile)

All syscalls from the target PID are captured. Produces high-volume
output. Useful for general investigation, but the rule engine remains
the right way to consume that volume — leave findings on, add `--raw`
only when you need the per-event stream.

### `--profile security`

Activates BPF-side whitelisting via `SYSCALL_FILTER`. Only security-
relevant syscalls pass the filter:

- File access: `openat`, `faccessat`, `fstatat`, `readlinkat`, `execve`, `execveat`
- Network: `connect`, `bind`, `sendto`, `recvfrom`, `socket`
- Memory: `mmap`, `mprotect`
- Process: `prctl`, `kill`, `clone`
- IPC: `ioctl`

Events for other syscalls never reach userspace — they are discarded in
the kernel before `RingBuf::reserve()`. The `--profile security` shorthand
applies this list only when neither `--match-syscall` nor `--match EXPR` was
supplied, and also auto-populates `--exclude-comm` with common high-volume
Android thread names.

In security profile mode, the BPF program calls
`bpf_probe_read_user_str_bytes` (helper 114) to capture the first argument
of file syscalls into `data[128]`.

## Data Capture (`data[128]`)

The `data[128]` field is a union interpreted by `syscall_nr` in
userspace:

| Syscall                                | `data[128]` content                                |
|----------------------------------------|----------------------------------------------------|
| File ops (openat, faccessat, etc.)     | NUL-terminated path string                         |
| execve / execveat                      | NUL-terminated executable path                     |
| connect / bind                         | raw `sockaddr` struct (decoded to `AF_INET 1.2.3.4:443`) |
| sendto                                 | destination `sockaddr`                             |
| ioctl                                  | `[0..4]` = cmd LE u32, `[4..128]` = payload bytes  |
| mmap / mprotect                        | `[0]` = RWX marker byte                            |

On kernel 6.1+, `bpf_probe_read_user_*` reads userspace memory directly —
there is no PAN restriction to work around.

The userspace `--resolve-paths` flag is still useful as a safety net:

- For `openat()` exit events with a successful return, it resolves the fd
  via `/proc/<pid>/fd/<fd>` readlink if `data[128]` is empty.
- For `connect()` / `connect()`-alike exits, it reads the socket inode
  from `/proc/<pid>/fd/<fd>` and looks up peer details in
  `/proc/<pid>/net/tcp*` and `/proc/<pid>/net/udp*`.

This is independent of the BPF read path — it kicks in when the in-kernel
read returned a truncated buffer or a closed/reused fd.

`STATE_EMIT_REQUIRED` is enabled by fd-path predicates. It exempts admitted
lifecycle events from later predicate gates; it does not expand an active
syscall whitelist.
`--resolve-paths`, `--follow-children`, and `--capture-reads` do not enable it automatically.
Without that fd-path exemption, active BPF predicates can suppress lifecycle events.
The fdgraph does not model `fcntl` duplication or `close_range`, so a cached
path is enrichment rather than proof of a current live FD binding.

## Network Event Decoding

Connect/bind/sendto events decode the `sockaddr` argument:

```
AF_INET  1.2.3.4:443
AF_INET6 [2001:db8::1]:8080
AF_UNIX  /run/something.sock
```

For `sendmsg`/`recvmsg`, the destination address is extracted from
`msg_name` in the `msghdr` struct.

## ioctl Decoding

ioctl events in `data[128]` include:

- `[0..4]`: the ioctl command as a u32 LE integer.
- `[4..128]`: the first 124 bytes of the data argument.

The ioctl direction, type, number, and size are decoded from the command
using the `_IOC` macro structure. Known device types:

- `type=0x62` (`b`): binder device (`/dev/binder`).
- `type=0x77` (`w`): ashmem device (`/dev/ashmem`).

For binder, the most important command is
`BINDER_WRITE_READ = 0xc0306201`.

## Process Exit Correlation

The `sched/sched_process_exit` tracepoint is always attached and emits
synthetic events with `syscall_nr == -3`. The handler captures the
dying task's `comm` (more reliable than `bpf_get_current_comm` on the
do_exit teardown path) and submits a marker event. Userspace converts
the marker into a `type:"process_exit"` JSON line and (optionally) dumps
the per-PID lookback ring buffer into the line's `crash_context` field.

The BPF tracepoint payload does **not** carry `exit_code` /
`exit_signal` — those live on `task_struct` and require BTF reads
(deferred to V1.x backlog). Userspace logcat / tombstone watchers
fill in the signal info when they observe the same crash.

```bash
# Watch every process exit live (no rules, just raw events):
$NEUTRON --pid 0 --raw --no-findings --json \
  | jq -c 'select(.type == "process_exit")'
```

See [docs/REFERENCE.md](../REFERENCE.md#process-exit-event-type--process_exit)
for the JSON schema.

## Binder Transaction Tracing

Enable with `--binder`. Attaches two binder tracepoints (the second is
best-effort — a missing tracepoint is logged but does not abort attach):

- `binder/binder_transaction` — caller side, `syscall_nr == -1`.
- `binder/binder_transaction_received` — callee side, `syscall_nr == -4`.

Each caller-side event captures the AIDL routing metadata into
`args[0..5]`, and the kernel-assigned transaction `debug_id` into the
`ptr_hint` field:

```
args[0] = to_proc    (destination process PID)
args[1] = code       (AIDL method code)
args[2] = flags      (transaction flags)
args[3] = to_thread  (0 = any thread)
args[4] = reply      (0 = call, 1 = reply)
args[5] = target_node
ptr_hint = debug_id  (kernel transaction id; matching key for callee side)
```

Each callee-side event carries only `debug_id` in `ptr_hint`; the
callee `pid` / `comm` come from `bpf_get_current_*`. The userspace
correlator pairs caller↔callee by `debug_id` to emit synthesised
`type:"binder_call"` events with `caller_pid`, `callee_pid`,
`latency_us`, and a lifecycle `status` (`completed` / `callee_crashed`
/ `unmatched`). See
[docs/REFERENCE.md](../REFERENCE.md#binder-call-event-type--binder_call)
for the JSON schema.

Text output:

```
[   1234.567] 21093/21093  e.bankapp        -> BINDER_TXN to_proc=1234 code=2 flags=0x10 reply=false node=7
```

## Stack Traces

Enable with `--stacks`. Uses `bpf_get_stackid` (helper 27) +
`STACK_TRACES` map (`BPF_MAP_TYPE_STACK_TRACE`).

Stack frames are resolved by the userspace symbolizer (`src/symbolize/`):

- **Native ELF**: `<file>:<symbol>+0xN`. `goblin` parses the symbol
  table of each shared library on first hit; results are cached per
  library.
- **ART JIT**: `<JIT>+0xN`. Frames whose IP falls inside an
  `[anon:dalvik-jit-code-cache]` mapping are tagged but not
  method-resolved (V1.x backlog).
- **Kernel frames**: `kernel_symbol+0xN` via a one-shot read of
  `/proc/kallsyms`. On Android, `kptr_restrict` typically masks the
  table when read by an unprivileged process; running as root usually
  works, but the device may still hide some symbols. When kallsyms is
  unavailable, kernel frames render as raw hex (`0xffff…`).
- **Unresolved**: raw hex `0x...`.

User stacks on aarch64 are still subject to the frame-pointer
limitation — NDK binaries built without `-fno-omit-frame-pointer` show
shallow or wrong stacks. Kernel stacks remain reliable.

Output format:

```
[   1234.567] 21093/21093  e.bankapp        -> openat(AT_FDCWD, O_RDONLY) "/proc/self/maps"
    stack=<libc.so:__openat+0x4 <- libnative-foo.so:check_root+0x40 ;; vfs_open+0x12 <- do_sys_openat2+0x80>
```

In `--json` mode the resolved stack is emitted as a top-level
`"stack":"…"` field (kernel and user frames separated by ` ;; `, frames
within each section by ` <- `). The rule engine uses this string for
`stack_contains` / `stack_not_contains` matches.

## RWX Memory Alerts

Enable with `--alert-rwx`. Filters output to only show `mmap`/`mprotect`
calls where the protection includes `PROT_EXEC` alongside `PROT_WRITE`.
This pattern indicates:

- JIT compilation (normal for ART/Dalvik).
- Dynamic code loading (suspicious in apps that claim not to do this).
- Potential shellcode injection.

Text output:

```
[   1234.567] 21093/21093  e.bankapp        [!RWX] -> mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, ...)
```

JSON output adds `"rwx_alert": "RWX"` or `"rwx_alert": "WX"`.

## Selective Read Capture

Enable with `--capture-reads`. When the target process calls `openat` on
a path under `/proc/` or `/sys/`, neutron records the returned fd in the
`WATCH_FDS` BPF map (key = `pid << 32 | fd`).

Note: `--capture-reads` is fd-tracking only — buffer-content readback
is not implemented. Follow-up work could repurpose
`bpf_probe_read_user_buf` to capture buffer bytes directly into
`data[..]`.

## Excluding Noise

Use `--exclude-comm` to filter out high-volume system threads:

```bash
--exclude-comm kworker,jbd2,irq/
```

This applies in userspace (after reading from the ring buffer), so it
does not reduce BPF overhead.

`--profile security` already includes a sensible default exclude list.

## Verbose Mode

`-v` / `--verbose` prints diagnostic information to stderr:

- Aya verifier log on a failed `prog.load()`.
- Map-fd table at startup.
- Attached programs.
- `kallsyms` symbol count (or "unavailable").
- `--follow-children` and `--capture-reads` decisions.

Useful when debugging a failed `Ebpf::load` or attach.
