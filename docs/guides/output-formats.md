# Output Formats

neutron supports two output formats: human-readable text (default) and
NDJSON. Both can be written to stdout or a file (`--output PATH`).

By default, output consists of rule-engine **findings** (one block per
triggered detector). Add `--raw` to also emit per-event lines. Add
`--no-findings --raw` to reproduce the legacy per-event-only behaviour
of pre-rule-engine versions.

## Text Format (Raw Events)

### Enter Events

```
[timestamp_ms] pid/tid  comm             -> syscall(decoded_args) "data_field"
```

### Exit Events

```
[timestamp_ms] pid/tid  comm             <- syscall = return_value [+latency µs] "data_field"
```

### RWX Alert

```
[timestamp_ms] pid/tid  comm             [!RWX] -> mmap(decoded_args)
```

### Binder Event

```
[timestamp_ms] pid/tid  comm             -> BINDER_TXN to_proc=N code=N flags=0xN reply=false node=N
```

### Stack Trace (with `--stacks`)

When `--stacks` is active, raw text events are followed by
` stack=<…>` on the same line. Kernel and user frames are separated by
` ;; `; frames within a section are separated by ` <- ` (caller on the
right):

```
[   1234.567] 21093/21093  e.bankapp        -> openat(AT_FDCWD, O_RDONLY) "/proc/self/maps" stack=<libc.so:__openat+0x4 <- libnative.so:check_root+0x40 ;; vfs_open+0x12 <- do_sys_openat2+0x80>
```

### Examples

```
[   1234.567] 21093/21093  e.bankapp        -> openat(AT_FDCWD, O_RDONLY|O_CLOEXEC) "/proc/self/maps"
[   1234.568] 21093/21093  e.bankapp        <- openat = 42 [+123 µs]
[   1235.001] 21093/21157  e.bankapp        -> connect(AF_INET, SOCK_STREAM) "AF_INET 52.19.245.87:443"
[   1235.008] 21093/21157  e.bankapp        <- connect = 0 [+7234 µs]
[   1236.100] 21093/21093  e.bankapp        [!RWX] -> mmap(0x0, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0)
[   1237.000] 21093/21093  e.bankapp        -> BINDER_TXN to_proc=1234 code=2 flags=0x10 reply=false node=7
```

## JSON Format (`--json`)

One JSON object per line. All numeric types are unquoted; all string
types are quoted. Optional fields are omitted (rather than `null`) when
absent.

### Syscall Event

```json
{
  "type":           "syscall",
  "ts_ns":          1712345678901234,
  "pid":            21093,
  "tid":            21157,
  "uid":            10147,
  "nr":             203,
  "name":           "connect",
  "comm":           "e.bankapp",
  "enter":          false,
  "phase":          "exit",
  "ret":            0,
  "ok":             true,
  "args":           [17, 140234567890, 16, 0, 0, 0],
  "data":           "AF_INET 52.19.245.87:443",
  "data_phase":     "enter",
  "rwx_alert":      "RWX",
  "kernel_stackid": 17,
  "user_stackid":   42,
  "latency_us":     7234,
  "stack":          "libc.so:__connect+0x10 <- libnative.so:do_call+0x80 ;; vfs_socket_connect+0x40",
  "event_id":       18437
}
```

A failed call carries `ok:false` plus the decoded `errno`:

```json
{ "type":"syscall", "name":"openat", "phase":"exit", "ret":-2, "ok":false, "errno":2, ... }
```

### Binder Event

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

Binder transactions are point-in-time, so `phase` is always `"enter"` — there is no symmetric exit event. There is no `ok`/`errno`/`ret` because the binder tracepoint does not expose a return code.

### FD Snapshot Event

Sprint-1 PR 3 introduces a third event class emitted by the periodic
`/proc/<pid>/fd` poller. One line per in-scope PID per `--fdgraph-interval`
tick. Drives the `R001_fd_table_exhaustion`-class rules and gives operators
a first-class "HAL fd table grew to N/M" signal.

```json
{
  "type":               "fd_snapshot",
  "ts_ns":              1234567890,
  "pid":                540,
  "uid":                1000,
  "comm":               "vendor.qti.cam",
  "fd_count":           16380,
  "fd_rlimit":          32768,
  "fd_pct_of_rlimit":   49,
  "high_water_mark":    16380,
  "growth_rate_per_sec": 124.5,
  "top_paths":          [
    {"path":"/dev/dma_heap/system","count":8190},
    {"path":"/dev/dma_heap/count-negative","count":8190}
  ],
  "event_id":           18234
}
```

| Field                  | JSON type    | Notes                                                                 |
|------------------------|--------------|-----------------------------------------------------------------------|
| `type`                 | string       | Always `"fd_snapshot"`.                                               |
| `pid`, `uid`, `comm`   | as elsewhere | Identifying triplet.                                                  |
| `fd_count`             | u32          | Authoritative count from `/proc/<pid>/fd` at sample time.             |
| `fd_rlimit`            | u32          | Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. `0` = unknown.        |
| `fd_pct_of_rlimit`     | u8           | `0..=100`. **Omitted** when `fd_rlimit == 0`. Rule predicates skip.   |
| `high_water_mark`      | u32          | Maximum `fd_count` ever observed for this PID, this session.          |
| `growth_rate_per_sec`  | f32          | (fds gained since last sample) / interval. Negative deltas → `0.0`.   |
| `top_paths`            | array        | Top-N `(path, count)` pairs from readlinks. Empty unless `--fdgraph-top-paths-n > 0`. |
| `event_id`             | u64          | Monotonic correlation token. |

The poller scope is controlled by `--fdgraph-pids`: `active` (default) covers
the explicit `--pid` target plus any PID that produced a traced event;
`traced` is equivalent today; `all` walks all of `/proc` (heavy); `uid` is a
sprint-2 stub that degrades to `active` with a warning. Set `--fdgraph-interval off`
to disable polling entirely.

### Binder Call Event (`type == "binder_call"`)

Sprint-2 PR 2. Synthesised pair: caller-side `binder_transaction` plus
callee-side `binder_transaction_received` matched by `debug_id`. On callee
crash, in-flight transactions are flushed with `status:"callee_crashed"`.
Raw `type:"binder"` (caller) and `type:"binder_received"` (callee) lines
continue to flow alongside the synthesised `binder_call` so operators can
see low-level detail.

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
  "target_node":    1,
  "sent_ts_ns":     1234567890,
  "received_ts_ns": 1234568390,
  "latency_us":     500,
  "status":         "completed",
  "service":        "android.hardware.camera2",
  "event_id":       18234
}
```

| Field            | JSON type | Notes                                                                  |
|------------------|-----------|------------------------------------------------------------------------|
| `type`           | string    | Always `"binder_call"`.                                                |
| `debug_id`       | i32       | Kernel-assigned binder transaction id; matching key.                    |
| `caller_pid`     | u32       | Sending process (TGID).                                                |
| `callee_pid`     | u32       | Receiving process — taken from caller-side `to_proc`.                  |
| `code`           | u32       | AIDL transaction code.                                                 |
| `flags`          | u32       | TF_* flags (`0x01` = TF_ONE_WAY async).                               |
| `target_node`    | i32       | Binder handle. Combined with `callee_pid`, identifies a specific service. (1.2.0) |
| `received_ts_ns` | u64       | Omitted for `callee_crashed` pairs.                                    |
| `latency_us`     | u64       | Omitted when `received_ts_ns` is absent.                               |
| `status`         | string    | `"completed"`, `"callee_crashed"`, or `"unmatched"`.                  |
| `service`        | string    | Optional. Surfaces when `--binder-services <FILE>` was supplied and the `(callee_pid, target_node)` pair is mapped. (1.2.0) |

Disable the correlator with `--binder-inflight 0`. The default cap (1024
in-flight transactions) is enough for ~steady-state Pixel HAL traffic;
heavily multiplexed workloads can raise it.

### Marker Event (`type == "marker"`, 1.2.0)

Operator-supplied scenario marker emitted by `neutron mark <name>
[--phase start|end] [--meta k=v]`. The live tracer never produces
these on its own; they exist solely to bracket external stimuli for
later window-cutting via `neutron window --anchor marker:<name>`.

```json
{ "type":"marker", "ts_ns":1712345678901234, "name":"scenario",
  "phase":"start", "meta":{"build":"v1","device":"oriole"} }
```

`phase` and `meta` are both optional; omitted when not set.

### Capture Health Event (`type == "capture_health"`, 1.2.0)

Emitted as the final NDJSON line on shutdown when `--json` is on.
Same counter set as the stderr capture-summary block, plus a
`degraded:bool` flag mirroring the WARNING banner predicate.

```json
{ "type":"capture_health", "events_userspace":99999,
  "events_submitted":99999, "ringbuf_reserve_failed":0,
  "inflight_lookup_missed":0, "user_stack_failed":0,
  "kernel_stack_failed":0, "path_truncated":0,
  "fd_lookup_missed":0, "ioctl_refresh_missed":0,
  "unix_msg_control_truncated":0, "unix_msg_control_nested":0,
  "fd_graph_miss":0, "fd_graph_backfilled":0,
  "degraded":false, "driver_packs":["kgsl"],
  "attached_programs":["trace_sys_enter","trace_sys_exit"],
  "ioctl_refresh_types":["0x9"] }
```

A downstream pipeline gating on "absence of finding is conclusive"
should require `degraded:false`.

### Process Exit Event (`type == "process_exit"`)

Sprint-2 PR 1 introduces a fourth event class. Three independent sources can
emit `process_exit` lines: the `sched_process_exit` BPF tracepoint, the
logcat tail (`FATAL EXCEPTION`, native `DEBUG`, `ANR in`), and a poll-based
watcher over `/data/tombstones/`. Per-process aggregation in the rule engine
collapses the typical fan-out.

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
  "crash_context":  ["{\"type\":\"syscall\",\"nr\":29,...}", "..."],
  "event_id":       18234
}
```

| Field            | JSON type | Notes                                                                  |
|------------------|-----------|------------------------------------------------------------------------|
| `type`           | string    | Always `"process_exit"`.                                               |
| `source`         | string    | `"tracepoint"` (BPF), `"logcat"`, or `"tombstone"`.                    |
| `classification` | string    | `"crash"`, `"signal_exit"`, `"abnormal_exit"`, or `"normal_exit"`.     |
| `exit_signal`    | u32       | POSIX signal number. Omitted when 0.                                   |
| `signal_name`    | string    | Symbolic name (`"SIGSEGV"`). Omitted when not in the lookup table.     |
| `exit_code`      | u8        | exit(2) status. Omitted when 0.                                        |
| `crash_context`  | array     | Last N raw NDJSON lines neutron observed for this PID before the exit. |
| `event_id`       | u64       | Monotonic correlation token.                                           |

`crash_context` entries are JSON-escaped strings of the original NDJSON
lines. Disable with `--lookback-events 0`. Disable the tombstone watcher
with `--tombstone-dir ""` and the logcat tail with `--no-logcat`.

## Field Reference

### Common Fields

| Field      | JSON type | Notes                                                                      |
|------------|-----------|----------------------------------------------------------------------------|
| `type`     | string    | Event class: `"syscall"`, `"binder"`, `"binder_received"`, `"binder_call"`, `"fd_snapshot"`, `"process_exit"`, `"finding"`, `"marker"` (1.2.0), `"capture_health"` (1.2.0). Stable identifier. |
| `ts_ns`    | number    | Kernel monotonic nanoseconds since boot                                    |
| `pid`      | number    | Linux PID (= POSIX process ID = `tgid`)                                    |
| `tid`      | number    | Linux TID (= POSIX thread ID = kernel `pid`)                               |
| `uid`      | number    | Effective user ID                                                          |
| `comm`     | string    | Process comm name (up to 15 chars, from kernel)                            |
| `phase`    | string    | `"enter"` or `"exit"`. Canonical replacement for `enter:bool`.             |
| `event_id` | number (optional) | Session-scoped monotonic correlation token. Resets on neutron restart. |

### Syscall-Specific Fields

| Field             | JSON type           | Notes                                                       |
|-------------------|---------------------|-------------------------------------------------------------|
| `nr`              | number              | Syscall number; `-1` for binder synthetic events            |
| `name`            | string              | Human-readable name or `"syscall_NR"` for unknown           |
| `enter`           | boolean             | **Deprecated.** Mirrors `phase`; kept for one release for backward compatibility. New consumers should read `phase`. |
| `ret`             | number              | Return value (exit only; `0` on enter events).              |
| `ok`              | boolean (exit only) | `true` when `ret >= 0`. Convenience derivation; omitted on enter events.   |
| `errno`           | number (optional)   | `-ret` for failed exit events (`ok:false`). Omitted otherwise.             |
| `args`            | number[6]           | Raw syscall arguments. All six positions reflect the actual ABI args (no field hijacking — the enter timestamp lives in its own field). |
| `data`            | string (optional)   | Decoded argument data (path, sockaddr, hex, …); omitted if empty |
| `data_phase`      | string              | `"enter"` when `data[]` carries the pre-call buffer; `"exit"` when the BPF program refreshed the buffer post-call. Built-in refresh covers dma-heap/binder/dma-buf/ashmem; `--driver-pack` can enable runtime refresh for KGSL, Mali, ALSA, LWIS, and GXP families. |
| `ioctl_family`    | string (optional)   | Family classification for `ioctl(2)` events: `"dma_heap"`, `"binder"`, `"dma_buf"`, `"ashmem"`, `"kgsl"`, `"mali"`, `"alsa"`, `"lwis"`, `"gxp"`, or `"unknown"`. Magic collisions are disambiguated with FD-graph path/kind when available. |
| `ioctl_name`      | string (optional)   | Human name for the cmd when the decoder registry knows it (e.g. `"DMA_HEAP_IOCTL_ALLOC"`, `"BINDER_WRITE_READ"`, `"IOCTL_KGSL_GPUMEM_ALLOC"`). |
| `dma_heap`        | object (optional)   | Decoded `struct dma_heap_allocation_data`: `{ "len":N, "returned_fd":N, "fd_flags":N, "fd_flags_str":"O_RDWR\|O_CLOEXEC", "heap_flags":N }`. Meaningful only when `data_phase == "exit"` (the kernel writes `fd` post-call). |
| `binder_write_read` | object (optional) | Scalar `BINDER_WRITE_READ` header: `write_size`, `write_consumed`, `read_size`, `read_consumed`. Nested Parcel buffers are not dereferenced. |
| `kgsl` / `mali`   | object (optional)   | First four captured scalar words as `arg0..arg3` for driver harness timelines. Nested pointers are not followed. |
| `alsa`            | object (optional)   | ALSA scalar marker with `compat_candidate`, `arg0`, and `arg1`. |
| `unix_msg_control` | object (optional)  | Bounded sendmsg/recvmsg control metadata: `flags`, `controllen`, first `cmsg_len`/`cmsg_level`/`cmsg_type`, bounded `scm_rights_fds`, and `msg_peek`. |
| `rwx_alert`       | `"RWX" \| "WX"`     | Set on `mmap`/`mprotect` with PROT_EXEC; omitted otherwise  |
| `latency_us`      | number (optional)   | Syscall duration in µs (exit only); omitted if `INFLIGHT` evicted |
| `kernel_stackid`  | number (optional)   | Stack trace map key; omitted if both stack ids are negative |
| `user_stackid`    | number (optional)   | Stack trace map key; omitted if both stack ids are negative |
| `stack`           | string (optional)   | Resolved stack trace string (see below); only present with `--stacks` |

### `stack` field rendering

Format: `<kernel_frames> ;; <user_frames>`. Either side is omitted when
empty. Frames within a side are joined by ` <- ` (caller on the right).

Per-frame format:

| Frame kind                                  | Render                                |
|---------------------------------------------|---------------------------------------|
| Native ELF, symbol resolved                 | `<file>:<symbol>+0xN`                 |
| Native ELF, no symbol match                 | `<file>+0xN`                          |
| ART JIT (`[anon:dalvik-jit-code-cache]`)    | `<JIT>+0xN`                           |
| Kernel symbol via kallsyms                  | `<symbol>+0xN`                        |
| Unresolved (kallsyms masked, IP outside any mapping) | `0xfffffabc12340000` (raw hex) |

The same `stack` string is what the rule engine sees for
`stack_contains` / `stack_not_contains` matches. See
[writing-rules.md](writing-rules.md).

## Findings

When the rule engine fires, findings emit alongside (or instead of) raw
events.

### Text Format

```
[FINDING] T001_proc_self_maps_polling root_detection MEDIUM
  rule:    Periodic /proc/self/maps inspection
  process: example.app (pid 21093)
  events:  130 over 260000.0ms, period 2033.000ms
  evidence:
    [1037686946] <- openat(/proc/self/maps) ret=79
    [1037686947] -> openat(/proc/self/maps)
    ...
```

### JSON Format

```json
{
  "type": "finding",
  "rule_id": "T001_proc_self_maps_polling",
  "rule_name": "Periodic /proc/self/maps inspection",
  "category": "root_detection",
  "severity": "medium",
  "process": {"comm": "example.app", "pid": 21093},
  "event_count": 130,
  "first_seen_ms": 1037686.946,
  "last_seen_ms": 1037946.946,
  "period_ms": 2033.000,
  "evidence": [...],
  "aggregates": {
    "events_per_sec":   0.49,
    "min_interval_ms":  1850.0,
    "max_interval_ms":  2200.0,
    "distinct_targets": 1
  },
  "raw_window": [
    "{\"type\":\"syscall\",\"nr\":56,\"data\":\"/proc/self/maps\",...}",
    "{\"type\":\"syscall\",\"nr\":56,\"data\":\"/proc/self/maps\",...}"
  ]
}
```

Sprint-2 PR 4 introduced the `aggregates` and `raw_window` blocks. Both
are additive and omitted from the JSON when empty:

- `aggregates` carries numerical aggregates over contributing events
  (`events_per_sec`, `min_interval_ms`, `max_interval_ms`,
  `distinct_targets`, `peak_fd_count`, `peak_fd_pct_of_rlimit`,
  `distinct_callee_pids`, `distinct_binder_codes`). Whichever fields
  apply to the matched event kinds populate; the rest stay omitted.
- `raw_window` carries up to `--finding-raw-window N` (default 10) full
  NDJSON lines from the events that contributed to this finding, in
  matching order. Disable with `--finding-raw-window 0`.

See [REFERENCE.md](../REFERENCE.md#finding-event) for the full field table.

## Parsing Examples

### Python

```python
import json

with open('trace.ndjson') as f:
    for line in f:
        event = json.loads(line)
        if event.get('nr') == 56 and not event.get('enter'):
            if event.get('ret', 0) > 0:
                print(f"opened: {event.get('data')} -> fd {event['ret']}")
```

### jq

```bash
# All successful connect() calls
jq -r 'select(.nr == 203 and .enter == false and .ret == 0) | .data' trace.ndjson

# Events whose stack mentions libc
jq -c 'select(.stack and (.stack | contains("libc")))' trace.ndjson

# Events with latency > 1ms
jq -r 'select(.latency_us != null and .latency_us > 1000) |
  "\(.name) \(.latency_us)µs"' trace.ndjson | sort -t' ' -k2 -rn | head -20

# Findings only
jq -c 'select(.type == "finding")' trace.ndjson
```

### Rust

```rust
use std::io::{BufRead, BufReader};
use std::fs::File;

fn main() -> anyhow::Result<()> {
    let file = BufReader::new(File::open("trace.ndjson")?);
    for line in file.lines() {
        let line = line?;
        let event: serde_json::Value = serde_json::from_str(&line)?;
        if event["nr"] == 56 && event["enter"] == false {
            println!("openat: {}", event["data"]);
        }
    }
    Ok(())
}
```

## Timestamps

`ts_ns` is `CLOCK_MONOTONIC` in nanoseconds since system boot. To
convert to wall clock time, capture a reference point at session start.

```python
import time
boot_offset_s = time.time() - time.monotonic()  # approximate

def ts_to_wall(ts_ns):
    return boot_offset_s + ts_ns / 1e9
```

## Latency Computation

`latency_us` on exit events is computed from `args[5]` (enter event's
`ts_ns`) subtracted from the exit event's `ts_ns`, divided by 1000.
This is available only for exit events where the `INFLIGHT` map lookup
succeeded. Events evicted from `INFLIGHT` (4096-entry cap) have
`latency_us` omitted.

## File vs Stdout

When `--output PATH` is set, all events go to the file. Stderr still
receives:

- `--verbose` diagnostic messages.
- Aya verifier logs on a failed `prog.load()`.

Redirect stderr separately:

```bash
neutron --json --output trace.ndjson 2>diag.log
```
