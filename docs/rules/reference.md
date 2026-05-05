# Rules reference

The `neutron-rules` crate implements a small declarative DSL for matching
syscall events and emitting findings. Rules are YAML; the engine evaluates
them against the same JSON event schema produced by `neutron --json`.

## Schema

A rule file is a top-level YAML list of rule objects:

```yaml
- id: T0xx_unique_id
  name: Short human-readable title
  description: |
    Multi-line description of what this rule detects and why it matters.
  severity: low | medium | high | critical | info
  category: root_detection | antitamper | network | network_recon
          | memory | ipc | recon | resource_exhaustion | crash
  references:
    - "URL or citation"
  conditions:
    - <condition>
    - <condition>
  frequency:                # optional
    window_ms: 10000
    min_count: 2
  aggregate: per_process | per_target | every_event
  disabled: false           # optional, default false
```

### Top-level fields

| Field         | Required | Description                                                       |
|---------------|----------|-------------------------------------------------------------------|
| `id`          | yes      | Stable identifier. Convention: `T0xx_short_slug`.                |
| `name`        | yes      | Human-readable title.                                             |
| `description` | yes      | Full description; shown in findings.                              |
| `severity`    | yes      | `info` / `low` / `medium` / `high` / `critical`.                  |
| `category`    | yes      | One of the seven categories above.                                |
| `references`  | no       | List of strings. Free-form citations.                             |
| `conditions`  | yes      | Non-empty list. AND-joined.                                       |
| `frequency`   | no       | Sliding-window trigger. If absent, rule fires per match.          |
| `aggregate`   | no       | How matches collapse into findings. Default `per_process`.        |
| `disabled`    | no       | Loaded but inert. Useful for staging experimental rules.          |

### Condition fields

Each condition is a struct with all-optional fields. Every set field must
match (implicit AND). To require multiple constraints, set multiple fields
in one condition entry, or use multiple condition entries.

| Field               | Type           | Matches when ...                                                  |
|---------------------|----------------|-------------------------------------------------------------------|
| `syscall_in`        | `[i32]`        | Event is a syscall and `nr` is in the list.                       |
| `binder`            | `bool`         | If `true`, event is a binder transaction.                         |
| `path_prefix`       | `string`       | `data` field starts with the given string.                        |
| `path_contains`     | `string`       | `data` field contains the given substring.                        |
| `path_in`           | `[string]`     | `data` field equals one of these exactly.                         |
| `data_any`          | `[string]`     | `data` field contains *any* of these substrings.                  |
| `path_not_contains` | `[string]`     | `data` field does NOT contain any of these substrings (negation). |
| `comm_contains`     | `[string]`     | Process `comm` contains *any* of these substrings.                |
| `comm_not_contains` | `[string]`     | Process `comm` contains *none* of these substrings.               |
| `enter_only`        | `bool`         | `true` for enter-only, `false` for exit-only.                     |
| `ret_lt`            | `i64`          | `ret < value` (e.g. `0` for failed access checks).                |
| `ret_eq`            | `i64`          | `ret == value`.                                                   |
| `rwx_alert_in`      | `[string]`     | `rwx_alert` field equals one of `["RWX", "WX"]`.                  |
| `arg0_eq`           | `u64`          | `args[0] == value` (used for `prctl(option, ...)` etc).           |
| `arg0_in`           | `[u64]`        | `args[0]` is in the list.                                         |
| `stack_contains`    | `[string]`     | Resolved `stack` field contains *any* of these substrings.        |
| `stack_not_contains`| `[string]`     | Resolved `stack` field contains *none* of these substrings.       |
| `fd_snapshot`       | `bool`         | Event is a `type:"fd_snapshot"` poller sample. Sprint-1.          |
| `fd_count_gt`       | `u32`          | Snapshot's `fd_count > value` (snapshot events only).             |
| `fd_count_pct_of_rlimit_gt` | `u8`   | Snapshot's `fd_pct_of_rlimit > value` (rlimit must be known).     |
| `ioctl_family_in`   | `[string]`     | Decoded `ioctl_family` ∈ list (`dma_heap`, `binder`, `dma_buf`, `ashmem`). |
| `ioctl_name_in`     | `[string]`     | Decoded `ioctl_name` ∈ list (e.g. `DMA_HEAP_IOCTL_ALLOC`).        |
| `process_exit`      | `bool`         | Event is a `type:"process_exit"` line. Sprint-2.                  |
| `exit_signal_in`    | `[u32]`        | Exit's `exit_signal` ∈ list (POSIX numbers; `11`=SIGSEGV).        |
| `exit_classification_in` | `[string]` | `classification` ∈ list (`crash`, `signal_exit`, `abnormal_exit`, `normal_exit`). |
| `exit_source_in`    | `[string]`     | `source` ∈ list (`tracepoint`, `logcat`, `tombstone`).            |
| `binder_call`       | `bool`         | Event is a `type:"binder_call"` synthesised pair. Sprint-2.       |
| `binder_status_in`  | `[string]`     | binder_call's `status` ∈ list (`completed`, `callee_crashed`, `unmatched`). |
| `binder_code_in`    | `[u32]`        | binder_call's AIDL `code` ∈ list.                                 |

### Frequency

```yaml
frequency:
  window_ms: 10000
  min_count: 2
```

The engine maintains a sliding window of recent match timestamps per
`(rule, pid)`. The rule emits a finding when the window contains at least
`min_count` matches. After emission the rule continues to update its
state but does not re-emit.

### Aggregate modes

| Mode           | Meaning                                                                 |
|----------------|-------------------------------------------------------------------------|
| `per_process`  | One finding per `(rule, pid)`. Default.                                 |
| `per_target`   | One finding per `(rule, pid, first matched data string)`. Use for rules |
|                | probing many distinct targets (su paths, Magisk artifacts, etc.).       |
| `every_event`  | Emit a separate finding for every match. Use only for rare events.      |

## Built-in rules

The bundled detector pack ships twenty-six rules. Each is described inline in
[`neutron-rules/rules/default.yaml`](../../neutron-rules/rules/default.yaml).
Summary table:

| ID     | Category             | Pattern                                                 | Severity |
|--------|----------------------|---------------------------------------------------------|----------|
| T001   | root_detection       | Periodic `/proc/self/maps` reads                        | medium   |
| T002   | root_detection       | Mount-table inspection                                  | medium   |
| T003   | antitamper           | `/proc/self/status` read                                | low      |
| T004   | root_detection       | `su` binary probe                                       | high     |
| T005   | root_detection       | Magisk artifact probe                                   | high     |
| T006   | antitamper           | Frida artifact probe                                    | high     |
| T007   | antitamper           | Xposed / EdXposed artifact probe                        | high     |
| T008   | root_detection       | `Runtime.exec` of root-related binaries                 | critical |
| T009   | antitamper           | `ptrace` syscall observed                               | medium   |
| T010   | antitamper           | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`              | low      |
| T011   | memory               | RWX or W^X-violating memory mapping                     | high     |
| T012   | network_recon        | `/proc/net/tcp*` enumeration                            | medium   |
| T013   | antitamper           | SELinux enforcement state probe                         | low      |
| T014   | antitamper           | Android property service access                         | low      |
| T015   | recon                | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads    | medium   |
| T016   | root_detection       | `fstatat` on `su` binary with `libc` on the stack       | high     |
| T017   | antitamper           | Syscalls from inside the ART JIT code cache             | low      |
| T018   | antitamper           | `ptrace` resolved to `sys_ptrace` from native code      | medium   |
| T019   | recon                | `/system/lib64/*` probing excluding RenderScript / Skia | low      |
| T020   | antitamper           | `/proc/self/*` from anonymous executable mapping        | high     |
| T021   | antitamper           | Frida thread-comm enumeration via `/proc/<pid>/task`    | medium   |
| T022   | antitamper           | `bpf(2)` syscall from a non-system app process          | high     |
| R001   | resource_exhaustion  | FD table > 90% of `RLIMIT_NOFILE` (FD-graph poller)     | high     |
| R002   | resource_exhaustion  | DMA-heap allocation burst (50+ in 5 s)                  | medium   |
| R003   | crash                | Process killed by fatal signal (SEGV/ABRT/BUS/ILL/FPE/SYS) | critical |
| R004   | crash                | Binder callee crashed mid-transaction                   | high     |

## Findings

A finding is a structured object emitted when a rule fires:

```json
{
  "type": "finding",
  "rule_id": "T001_proc_self_maps_polling",
  "rule_name": "Periodic /proc/self/maps inspection",
  "severity": "medium",
  "category": "root_detection",
  "pid": 21093,
  "comm": "example.app",
  "first_seen_ns": 1037686946,
  "last_seen_ns": 1037948093,
  "event_count": 130,
  "period_ms": 2033.0,
  "evidence": [
    {
      "ts_ns": 1037686946,
      "name": "openat",
      "is_enter": false,
      "ret": 79,
      "data": "/proc/self/maps"
    }
  ],
  "references": [...]
}
```

`period_ms` is present only on frequency-rule findings. `target` is present
on `per_target` aggregations. Up to five evidence events are kept per
finding; rules that match more events update `event_count` but do not grow
the evidence array.

### Sprint-2 additions

Findings v2 additionally carry two optional blocks:

- **`aggregates`** — numerical / counting aggregates over contributing
  events (`events_per_sec`, `min_interval_ms`, `max_interval_ms`,
  `distinct_targets`, `peak_fd_count`, `peak_fd_pct_of_rlimit`,
  `distinct_callee_pids`, `distinct_binder_codes`). Whichever fields
  apply to the matched event kinds populate; the rest stay omitted.
  Distinct-set trackers cap at 1024 entries per finding.
- **`raw_window`** — up to `--finding-raw-window` (default 10) full
  NDJSON lines from contributing events, byte-exact, in matching
  order. `0` disables. Useful for re-feeding the events through the
  rule engine offline or for embedding evidence directly into a
  finding ticket.

Both blocks are additive and omitted from the JSON when empty; older
consumers continue to parse without changes.
