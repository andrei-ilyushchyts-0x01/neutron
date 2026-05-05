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
| `--fdgraph-pids POLICY`           | String           | `active`                                 | Periodic FD-poller scope: `traced` (target + followed children), `active` (PIDs with at least one traced event), `uid` (sprint-2 stub → falls back to `active`), `all` (every `/proc/<NUM>` — heavy). |
| `--fdgraph-interval DURATION`     | String           | `1s`                                     | Poller interval. Accepts `1s`, `500ms`, or `off` to disable polling. |
| `--fdgraph-thresholds TIERS`      | String           | `1024,8192,90%`                          | Comma-separated FD-count alert tiers. Parsed for forward-compat; rules carry their own thresholds today. |
| `--fdgraph-top-paths-n N`         | usize            | `0`                                      | Top-N `/proc/<pid>/fd/<fd>` readlink aggregation per snapshot. `0` disables. |

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

### FD Snapshot Event (`type == "fd_snapshot"`)

```json
{
  "type":              "fd_snapshot",
  "ts_ns":             1234567890,
  "pid":               540,
  "uid":               1000,
  "comm":              "vendor.qti.cam",
  "fd_count":          16380,
  "fd_rlimit":         32768,
  "fd_pct_of_rlimit":  49,
  "high_water_mark":   16380,
  "growth_rate_per_sec": 124.5,
  "top_paths":         [{"path":"/dev/dma_heap/system","count":8190}],
  "event_id":          18234
}
```

| Field                  | Type   | Description                                                                 |
|------------------------|--------|-----------------------------------------------------------------------------|
| `fd_count`             | u32    | Authoritative count from `/proc/<pid>/fd` at sample time.                   |
| `fd_rlimit`            | u32    | Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. `0` = unknown.              |
| `fd_pct_of_rlimit`     | u8     | `0..=100`, omitted when `fd_rlimit == 0`.                                   |
| `high_water_mark`      | u32    | Maximum `fd_count` ever observed for this PID this session.                 |
| `growth_rate_per_sec`  | f32    | (fds gained since last sample) / interval. `0.0` for the first sample.      |
| `top_paths`            | array  | `[{"path","count"}]` from readlinks. Empty unless `--fdgraph-top-paths-n > 0`. |

### Binder Call Event (`type == "binder_call"`)

Synthesised by the userspace correlator (sprint-2 PR 2). Pairs caller-side
`binder_transaction` (BPF nr=-1, raw `type:"binder"`) with callee-side
`binder_transaction_received` (BPF nr=-4, raw `type:"binder_received"`) by
`debug_id` carried in `ptr_hint`. On callee crash, in-flight transactions
are flushed with `status:"callee_crashed"`.

```json
{
  "type":           "binder_call",
  "ts_ns":          1234567890,
  "debug_id":       8421,
  "caller_pid":     12345,
  "caller_uid":     10001,
  "caller_comm":    "com.example.app",
  "callee_pid":     1000,
  "code":           7,
  "flags":          16,
  "reply":          false,
  "sent_ts_ns":     1234567890,
  "received_ts_ns": 1234568390,
  "latency_us":     500,
  "status":         "completed",
  "event_id":       18234
}
```

| Field            | Type    | Description                                                                |
|------------------|---------|----------------------------------------------------------------------------|
| `debug_id`       | i32     | Kernel-assigned binder transaction id; matching key.                        |
| `caller_pid`     | u32     | Sending process (TGID).                                                    |
| `callee_pid`     | u32     | Receiving process — taken from caller-side `to_proc` field.                |
| `code`           | u32     | AIDL transaction code on the binder interface.                              |
| `flags`          | u32     | TF_* flags (e.g. `0x01` = TF_ONE_WAY async).                               |
| `reply`          | bool    | `true` when this is a reply transaction; `false` for a request.             |
| `received_ts_ns` | u64     | When the callee dequeued. **Omitted** for `callee_crashed` pairs.           |
| `latency_us`     | u64     | `(received - sent) / 1000`. **Omitted** when `received_ts_ns` is absent.    |
| `status`         | string  | `"completed"`, `"callee_crashed"`, or `"unmatched"`.                       |

The rule engine maps `caller_pid` → the standard `pid` field for
`per_process` aggregation. `R004_binder_callee_crash` matches
`status: "callee_crashed"` and surfaces one finding per caller.

### Process Exit Event (`type == "process_exit"`)

```json
{
  "type":           "process_exit",
  "ts_ns":          1234567890,
  "pid":            12345,
  "uid":            10123,
  "comm":           "vendor.qti.cam",
  "source":         "tombstone",
  "classification": "crash",
  "exit_signal":    11,
  "signal_name":    "SIGSEGV",
  "crash_context":  ["{\"type\":\"syscall\",...}", "..."],
  "event_id":       18234
}
```

| Field            | Type   | Description                                                                  |
|------------------|--------|------------------------------------------------------------------------------|
| `source`         | string | `"tracepoint"` (BPF), `"logcat"`, or `"tombstone"`.                          |
| `classification` | string | `"crash"`, `"signal_exit"`, `"abnormal_exit"`, or `"normal_exit"`.           |
| `exit_signal`    | u32    | POSIX signal number (omitted when 0). `11` = SIGSEGV, `6` = SIGABRT, etc.    |
| `signal_name`    | string | Symbolic name when known (omitted otherwise).                                |
| `exit_code`      | u8     | exit(2) status (omitted when 0).                                             |
| `crash_context`  | array  | Last N raw NDJSON lines for this PID (lookback ring buffer). Empty when off. |

Sources are independent: a single SIGSEGV typically produces all three
events within milliseconds. `R003_process_crash` uses `aggregate: per_process`
so the rule fires once per PID. The `exit_source_in` predicate lets rules
require a specific source (e.g. only act on tombstone-backed evidence).

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

## Default Detector Pack (26 rules)

| ID    | Category             | What it catches                                           |
|-------|----------------------|-----------------------------------------------------------|
| T001  | root_detection       | Periodic `/proc/self/maps` polling                        |
| T002  | root_detection       | Mount table inspection (Magisk overlay detection)         |
| T003  | antitamper           | `/proc/self/status` (TracerPid scrape)                    |
| T004  | root_detection       | `su` binary probe                                         |
| T005  | root_detection       | Magisk artifact probe                                     |
| T006  | antitamper           | Frida artifact probe                                      |
| T007  | antitamper           | Xposed / EdXposed artifact probe                          |
| T008  | root_detection       | `Runtime.exec` of root-related binaries                   |
| T009  | antitamper           | `ptrace` syscall observed                                 |
| T010  | antitamper           | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`                |
| T011  | memory               | RWX or W^X-violating memory mapping                       |
| T012  | network_recon        | `/proc/net/tcp*` enumeration                              |
| T013  | antitamper           | SELinux enforcement state probe                           |
| T014  | antitamper           | Android property service access                           |
| T015  | recon                | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads      |
| T016  | root_detection       | `fstatat` on `su` binary with `libc` on the stack         |
| T017  | antitamper           | Syscalls from inside the ART JIT code cache               |
| T018  | antitamper           | `ptrace` resolved to `sys_ptrace` from native code        |
| T019  | recon                | `/system/lib64/*` probing excluding RenderScript / Skia   |
| T020  | antitamper           | `/proc/self/*` introspection from anonymous r-x mapping   |
| T021  | antitamper           | Thread-comm enumeration (`/proc/self/task/<TID>/comm`)    |
| T022  | antitamper           | `bpf(2)` from a non-system process                        |
| R001  | resource_exhaustion  | FD table > 90% of `RLIMIT_NOFILE` (FD-graph poller)       |
| R002  | resource_exhaustion  | DMA-heap allocation burst (50+ in 5 s)                    |
| R003  | crash                | Process killed by fatal signal (SEGV/ABRT/BUS/ILL/FPE/SYS)|
| R004  | crash                | Binder callee crashed mid-transaction                     |

Source: [`neutron-rules/rules/default.yaml`](../neutron-rules/rules/default.yaml).
T016..T021 require `--stacks`. R001 requires the FD-graph poller
(`--fdgraph-pids active --fdgraph-interval 1s`, on by default). R002
requires post-exit ioctl decoding (always on for whitelisted commands).
R003 requires the `sched_process_exit` BPF tracepoint (always attached);
the lookback ring buffer (`--lookback-events 100` default) and at least
one of the three crash sources (`--lookback-events`, `--tombstone-dir`,
`logcat` available in PATH) populate `crash_context` and the signal field.
R004 requires `--binder` plus `--binder-inflight > 0` (default 1024) for
the userspace correlator to track in-flight transactions.

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
