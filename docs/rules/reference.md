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
          | memory | ipc | recon
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

The bundled detector pack ships fifteen rules. Each is described inline in
[`neutron-rules/rules/default.yaml`](../../neutron-rules/rules/default.yaml).
Summary table:

| ID     | Category        | Pattern                                                 | Severity |
|--------|-----------------|---------------------------------------------------------|----------|
| T001   | root_detection  | Periodic `/proc/self/maps` reads                        | medium   |
| T002   | root_detection  | Mount-table inspection                                  | medium   |
| T003   | antitamper      | `/proc/self/status` read                                | low      |
| T004   | root_detection  | `su` binary probe                                       | high     |
| T005   | root_detection  | Magisk artifact probe                                   | high     |
| T006   | antitamper      | Frida artifact probe                                    | high     |
| T007   | antitamper      | Xposed / EdXposed artifact probe                        | high     |
| T008   | root_detection  | `Runtime.exec` of root-related binaries                 | critical |
| T009   | antitamper      | `ptrace` syscall observed                               | medium   |
| T010   | antitamper      | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`              | low      |
| T011   | memory          | RWX or W^X-violating memory mapping                     | high     |
| T012   | network_recon   | `/proc/net/tcp*` enumeration                            | medium   |
| T013   | antitamper      | SELinux enforcement state probe                         | low      |
| T014   | antitamper      | Android property service access                         | low      |
| T015   | recon           | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads    | medium   |

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
