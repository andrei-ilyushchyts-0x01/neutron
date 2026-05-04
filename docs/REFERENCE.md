# Reference

## CLI Flags

<!-- AUTO-GENERATED from src/cli.rs Args struct -->

| Flag                              | Type             | Default                                  | Description |
|-----------------------------------|------------------|------------------------------------------|-------------|
| `--pid N`                         | u32              | `0`                                      | Target process ID. `0` traces all processes. |
| `--object PATH`                   | String           | `/data/local/tmp/neutron.bpf.elf`        | Path to the compiled Aya BPF ELF object on the device. |
| `--pages N`                       | usize            | `64`                                     | **Deprecated.** Accepted for backward compatibility; ignored. The kernel `RingBuf` size is fixed in the BPF object. |
| `-v, --verbose`                   | flag             | off                                      | Print diagnostic information to stderr: attached programs, kallsyms status, follow-children / capture-reads decisions, Aya verifier log on a failed `prog.load()`. |
| `--exclude-comm LIST`             | comma-separated  | empty                                    | Exclude events whose `comm` field contains any of the listed substrings. Applied in userspace after reading from the ring buffer. |
| `--output PATH`                   | String           | stdout                                   | Write event output to a file instead of stdout. |
| `--json`                          | flag             | off                                      | Emit events and findings as NDJSON (one JSON object per line). |
| `--profile security`              | String           | off                                      | Enable BPF-side syscall whitelisting: only security-relevant syscalls are captured. Also captures file paths via `bpf_probe_read_user_str_bytes` and auto-populates `--exclude-comm` with kernel-worker noise. |
| `--binder`                        | flag             | off                                      | Enable binder transaction tracing via the `binder/binder_transaction` tracepoint. Emits events with `syscall_nr = -1`. |
| `--stacks`                        | flag             | off                                      | Collect kernel and userspace stack traces via `bpf_get_stackid`. Resolve native ELF symbols, ART JIT regions, and (when not masked) kernel symbols via `/proc/kallsyms`. |
| `--alert-rwx`                     | flag             | off                                      | Only show `mmap`/`mprotect` events with `PROT_READ\|PROT_WRITE\|PROT_EXEC`. Adds `"rwx_alert"` field in JSON mode. |
| `--resolve-paths`                 | flag             | off                                      | When `data[128]` is empty (truncated read or closed fd), fall back to `/proc/<pid>/fd/<fd>` readlink for paths and `/proc/<pid>/net/tcp*` for socket addresses. |
| `--follow-children`               | flag             | off                                      | On `clone()` exit, write the child PID into the `PID_WHITELIST` BPF map so child events are also captured. |
| `--capture-reads`                 | flag             | off                                      | On `openat()` exit for `/proc/*` or `/sys/*` paths, register the fd in `WATCH_FDS`. (Buffer-content peek removed in V1; fd-tracking only.) |
| `--rules PATH`                    | String           | bundled                                  | Path to a custom YAML rule file. Defaults to the bundled detector pack (19 rules — see below). |
| `--raw`                           | flag             | off                                      | Output raw syscall events in addition to (or instead of, with `--no-findings`) findings. Without this flag, neutron emits only rule-engine findings. |
| `--no-findings`                   | flag             | off                                      | Suppress findings output. Useful with `--raw` for the legacy per-event-only behavior of pre-rule-engine versions. |
| `--findings-drain-interval N`     | u64              | `256`                                    | Drain pending findings every N events. |

<!-- END AUTO-GENERATED -->

## Text Output Format

```
[timestamp_ms] pid/tid  comm             -> syscall(args) "data"
[timestamp_ms] pid/tid  comm             <- syscall = ret [+latency_us µs] "data"
[timestamp_ms] pid/tid  comm             [!RWX] -> mmap(args)
[timestamp_ms] pid/tid  comm             -> BINDER_TXN to_proc=N code=N flags=0xN
```

With `--stacks`, ` stack=<…>` is appended to the same line. See
[guides/output-formats.md](guides/output-formats.md).

## JSON Event Schema

Emitted with `--json` (and `--raw`). One object per line (NDJSON).

### Syscall Event

```json
{
  "type":           "syscall",
  "ts_ns":          1712345678901234,
  "pid":            21093,
  "tid":            21093,
  "uid":            10147,
  "nr":             56,
  "name":           "openat",
  "comm":           "e.bankapp",
  "enter":          false,
  "phase":          "exit",
  "ret":            42,
  "ok":             true,
  "args":           [4294967196, 140234567890, 524288, 438, 0, 0],
  "data":           "/proc/self/maps",
  "data_phase":     "enter",
  "kernel_stackid": 17,
  "user_stackid":   42,
  "latency_us":     123,
  "stack":          "libc.so:__openat+0x4 <- libnative.so:check_root+0x40 ;; vfs_open+0x12",
  "event_id":       18437
}
```

| Field             | Type                | Description                                                  |
|-------------------|---------------------|--------------------------------------------------------------|
| `type`            | String              | Always `"syscall"` for syscall events. Stable event-class identifier. |
| `ts_ns`           | u64                 | Kernel monotonic timestamp (ns since boot)                   |
| `pid`             | u32                 | Linux PID (= POSIX `tgid`)                                   |
| `tid`             | u32                 | Linux TID (= kernel `pid`)                                   |
| `uid`             | u32                 | UID of the calling thread                                    |
| `nr`              | i32                 | Syscall number; `-1` for binder synthetic events             |
| `name`            | String              | Human-readable syscall name (from internal table)            |
| `comm`            | String              | Task comm (up to 15 chars, kernel-set)                       |
| `enter`           | bool                | **Deprecated.** Use `phase` instead. Both fields are still emitted for one release. |
| `phase`           | String              | `"enter"` or `"exit"`.                                       |
| `ret`             | i64                 | Return value (exit only; 0 on enter)                         |
| `ok`              | bool (optional)     | `true` if `ret >= 0` on an exit event; omitted on enter events. |
| `errno`           | u32 (optional)      | `-ret` for failed exit events (when `ok:false`); omitted otherwise. |
| `args`            | u64[6]              | Syscall arguments. All six positions reflect the actual ABI args. |
| `data`            | String (optional)   | Decoded `data[128]`: path, sockaddr, hex; omitted if empty   |
| `data_phase`      | String              | `"enter"` when `data[]` is the pre-call buffer; `"exit"` when the BPF program refreshed it post-call (for `ioctl(2)` cmds with `_IOC_DIR ∈ {R,RW}` and `_IOC_TYPE ∈ {'H','b','w'}`). |
| `ioctl_family`    | String (optional)   | `"dma_heap"`, `"binder"`, `"dma_buf"`, `"ashmem"`, or `"unknown"`. Emitted for `ioctl(2)` events. |
| `ioctl_name`      | String (optional)   | Human cmd name (e.g. `"DMA_HEAP_IOCTL_ALLOC"`) when the decoder registry recognises it. |
| `dma_heap`        | Object (optional)   | Decoded `struct dma_heap_allocation_data`. Fields: `len`, `returned_fd`, `fd_flags`, `fd_flags_str`, `heap_flags`. |
| `rwx_alert`       | `"RWX" \| "WX" \| null` | Set on mmap/mprotect with PROT_EXEC                      |
| `kernel_stackid`  | i32 (optional)      | Key into `STACK_TRACES` map; omitted if both ids are negative |
| `user_stackid`    | i32 (optional)      | Key into `STACK_TRACES` map; omitted if both ids are negative |
| `latency_us`      | u64 (optional)      | Syscall latency (exit only; omitted if `INFLIGHT` evicted)   |
| `stack`           | String (optional)   | Resolved stack trace; only present with `--stacks`           |
| `event_id`        | u64 (optional)      | Session-scoped monotonic correlation token. Resets on neutron restart. |

### Binder Event (`syscall_nr == -1`)

```json
{
  "type":        "binder",
  "ts_ns":       1712345678901234,
  "pid":         21093,
  "tgid":        21093,
  "uid":         10147,
  "phase":       "enter",
  "comm":        "e.bankapp",
  "reply":       false,
  "to_proc":     1234,
  "to_thread":   0,
  "target_node": 7,
  "code":        2,
  "flags":       16,
  "stack":       "...",
  "event_id":    18438
}
```

Binder transactions are point-in-time so `phase` is always `"enter"`. Binder
events have no `ret`/`ok`/`errno` (the binder tracepoint does not expose a
return code) and no `data`/`data_phase` (the routing fields are first-class
columns on the event itself).

### Finding Event

```json
{
  "type":          "finding",
  "rule_id":       "T001_proc_self_maps_polling",
  "rule_name":     "Periodic /proc/self/maps inspection",
  "category":      "root_detection",
  "severity":      "medium",
  "process":       {"comm": "example.app", "pid": 21093},
  "event_count":   130,
  "first_seen_ms": 1037686.946,
  "last_seen_ms":  1037946.946,
  "period_ms":     2033.0,
  "evidence":      [...]
}
```

## Default Detector Pack (19 rules)

| ID    | Category        | What it catches                                           |
|-------|-----------------|-----------------------------------------------------------|
| T001  | root_detection  | Periodic `/proc/self/maps` polling                        |
| T002  | root_detection  | Mount table inspection (Magisk overlay detection)         |
| T003  | antitamper      | `/proc/self/status` (TracerPid scrape)                    |
| T004  | root_detection  | `su` binary probe                                         |
| T005  | root_detection  | Magisk artifact probe                                     |
| T006  | antitamper      | Frida artifact probe                                      |
| T007  | antitamper      | Xposed / EdXposed artifact probe                          |
| T008  | root_detection  | `Runtime.exec` of root-related binaries                   |
| T009  | antitamper      | `ptrace` syscall observed                                 |
| T010  | antitamper      | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`                |
| T011  | memory          | RWX or W^X-violating memory mapping                       |
| T012  | network_recon   | `/proc/net/tcp*` enumeration                              |
| T013  | antitamper      | SELinux enforcement state probe                           |
| T014  | antitamper      | Android property service access                           |
| T015  | recon           | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads      |
| T016  | root_detection  | `fstatat` on `su` binary with `libc` on the stack         |
| T017  | antitamper      | Syscalls from inside the ART JIT code cache               |
| T018  | antitamper      | `ptrace` resolved to `sys_ptrace` from native code        |
| T019  | recon           | `/system/lib64/*` probing excluding RenderScript / Skia   |

Source: [`neutron-rules/rules/default.yaml`](../neutron-rules/rules/default.yaml).
T016..T019 require `--stacks`.

## Syscall Table (aarch64)

The following syscall numbers are recognized and named. Events with
unlisted numbers display as `syscall_<NR>`.

### File Operations

| Nr  | Name        | `data[128]` content                  |
|-----|-------------|--------------------------------------|
| 35  | mkdirat     | path string                          |
| 36  | unlinkat    | path string                          |
| 43  | statfs      | path string                          |
| 48  | faccessat   | path string                          |
| 56  | openat      | path string                          |
| 63  | read        | (currently unused — see `--capture-reads` notes) |
| 64  | write       | (currently unused)                   |
| 78  | readlinkat  | path string                          |
| 79  | fstatat     | path string                          |
| 221 | execve      | filename string                      |
| 281 | execveat    | filename string                      |

### Network

| Nr  | Name         | `data[128]` content                                |
|-----|--------------|----------------------------------------------------|
| 198 | socket       | —                                                  |
| 200 | bind         | sockaddr struct                                    |
| 203 | connect      | sockaddr struct                                    |
| 206 | sendto       | destination sockaddr                               |
| 207 | recvfrom     | —                                                  |
| 208 | shutdown     | —                                                  |
| 209 | setsockopt   | —                                                  |
| 210 | getsockopt   | —                                                  |
| 211 | sendmsg      | msg_name sockaddr + msg_controllen                 |
| 212 | recvmsg      | msg_name sockaddr + msg_controllen                 |
| 240 | accept4      | —                                                  |
| 241 | recvmmsg     | —                                                  |
| 269 | sendmmsg     | —                                                  |
| 288 | accept       | —                                                  |
| 293 | socket (alt) | device-specific number observed on some kernels    |
| 294 | connect (alt)| device-specific number observed on some kernels    |

### Memory

| Nr  | Name      | `data[128]` content    |
|-----|-----------|------------------------|
| 222 | mmap      | `[0]` = RWX marker     |
| 226 | mprotect  | `[0]` = RWX marker     |
| 233 | madvise   | —                      |

### Process / Thread

| Nr  | Name       |
|-----|------------|
| 93  | exit       |
| 94  | exit_group |
| 117 | ptrace     |
| 129 | kill       |
| 167 | prctl      |
| 172 | getpid     |
| 173 | getppid    |
| 220 | clone      |

### IPC

| Nr  | Name         | `data[128]` content                                |
|-----|--------------|----------------------------------------------------|
| 29  | ioctl        | `[0..4]` = cmd u32, `[4..128]` = payload           |
| -1  | BINDER_TXN   | (binder fields in `args[0..5]`)                    |

## Security Profile Syscall Whitelist

When `--profile security` is active, the BPF filter passes only these
syscall numbers:

```
56 (openat)   48 (faccessat)   221 (execve)   281 (execveat)
79 (fstatat)  78 (readlinkat)  203 (connect)  200 (bind)
206 (sendto)  207 (recvfrom)   29 (ioctl)     222 (mmap)
226 (mprotect) 167 (prctl)     129 (kill)     220 (clone)
```

All other syscall numbers are silently discarded in BPF before any
RingBuf reservation.

## Binder Transaction Fields (`args[0..5]`)

When `syscall_nr == -1`:

| `args` index | Field          | Description                  |
|--------------|----------------|------------------------------|
| 0            | `to_proc`      | Destination process PID      |
| 1            | `code`         | AIDL method code             |
| 2            | `flags`        | Transaction flags            |
| 3            | `to_thread`    | Target thread (0 = any)      |
| 4            | `reply`        | 0 = call, 1 = reply          |
| 5            | `target_node`  | Binder node handle           |
