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
  "ts_ns":          1712345678901234,
  "pid":            21093,
  "tid":            21157,
  "uid":            10147,
  "nr":             203,
  "name":           "connect",
  "comm":           "e.bankapp",
  "enter":          false,
  "ret":            0,
  "args":           [17, 140234567890, 16, 0, 0, 1712345678800000],
  "data":           "AF_INET 52.19.245.87:443",
  "rwx_alert":      "RWX",
  "kernel_stackid": 17,
  "user_stackid":   42,
  "latency_us":     7234,
  "stack":          "libc.so:__connect+0x10 <- libnative.so:do_call+0x80 ;; vfs_socket_connect+0x40"
}
```

### Binder Event

```json
{
  "ts_ns":       1712345678901234,
  "pid":         21093,
  "tgid":        21093,
  "uid":         10147,
  "type":        "binder",
  "comm":        "e.bankapp",
  "reply":       false,
  "to_proc":     1234,
  "to_thread":   0,
  "target_node": 7,
  "code":        2,
  "flags":       16,
  "stack":       "..."
}
```

## Field Reference

### Common Fields

| Field   | JSON type | Notes                                               |
|---------|-----------|-----------------------------------------------------|
| `ts_ns` | number    | Kernel monotonic nanoseconds since boot             |
| `pid`   | number    | Linux PID (= POSIX process ID = `tgid`)             |
| `tid`   | number    | Linux TID (= POSIX thread ID = kernel `pid`)        |
| `uid`   | number    | Effective user ID                                   |
| `comm`  | string    | Process comm name (up to 15 chars, from kernel)     |

### Syscall-Specific Fields

| Field             | JSON type           | Notes                                                       |
|-------------------|---------------------|-------------------------------------------------------------|
| `nr`              | number              | Syscall number; `-1` for binder synthetic events            |
| `name`            | string              | Human-readable name or `"syscall_NR"` for unknown           |
| `enter`           | boolean             | `true` on enter, `false` on exit                            |
| `ret`             | number              | Return value; `0` on enter events                           |
| `args`            | number[6]           | Raw syscall arguments. `args[5]` = enter timestamp on exit  |
| `data`            | string (optional)   | Decoded argument data (path, sockaddr, hex, …); omitted if empty |
| `rwx_alert`       | `"RWX" \| "WX"`     | Set on `mmap`/`mprotect` with PROT_EXEC; omitted otherwise  |
| `latency_us`      | number (optional)   | Syscall duration in µs (exit only); omitted if `INFLIGHT` evicted |
| `kernel_stackid`  | number (optional)   | Stack trace map key; omitted if both stack ids are negative |
| `user_stackid`    | number (optional)   | Stack trace map key; omitted if both stack ids are negative |
| `stack`           | string (optional)   | **NEW in 1.0.** Resolved stack trace string (see below); only present with `--stacks` |

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
  "evidence": [...]
}
```

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
