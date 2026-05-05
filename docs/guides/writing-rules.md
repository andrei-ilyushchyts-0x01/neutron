# Writing rules

This guide walks through authoring a custom detector for `neutron`. For the
full schema reference see [docs/rules/reference.md](../rules/reference.md);
this page is task-oriented.

## When you need a rule

A rule is the right tool when the same observable pattern recurs across
captures and you want it surfaced as a single named finding instead of
showing up scattered through a raw event log. Typical triggers:

- A specific syscall plus a path or argument predicate.
- A periodic pattern (count over a time window).
- A failed access check (`ret < 0`) on a path of interest.
- A combination that never occurs benignly.

If you only need to look at the data once, a `jq` filter on the JSON output
is faster than authoring a rule.

## Anatomy of a rule

```yaml
- id: T101_example_detector
  name: Example detector
  description: |
    Short paragraph describing what this rule detects, why it matters, and
    any caveats (e.g. known false-positive sources).
  severity: medium
  category: antitamper
  references:
    - "https://example.com/some-doc"
  conditions:
    - syscall_in: [56]
      path_prefix: /proc/self/example
  aggregate: per_process
```

Conditions in the same list entry AND together. In the example above the
event must be both `openat` *and* have a path starting with
`/proc/self/example`.

## Available conditions

| Condition             | Type       | Matches                                                 |
|-----------------------|------------|---------------------------------------------------------|
| `syscall_in`          | `[i32]`    | `event.nr` ∈ list                                       |
| `syscall_not_in`      | `[i32]`    | `event.nr` ∉ list                                       |
| `path_in`             | `[string]` | `event.data` exactly equals one of the strings          |
| `path_prefix`         | string     | `event.data` starts with the given string               |
| `path_contains`       | `[string]` | `event.data` contains any of the substrings             |
| `path_not_contains`   | `[string]` | `event.data` contains **none** of the substrings        |
| `data_any`            | `[string]` | substring match against `event.data` (OR)               |
| `comm_in`             | `[string]` | `event.comm` ∈ list                                     |
| `ret_lt`              | `i64`      | `event.ret < value` (exit events only)                  |
| `ret_eq`              | `i64`      | `event.ret == value`                                    |
| `stack_contains`      | `[string]` | resolved `event.stack` contains any of the substrings   |
| `stack_not_contains`  | `[string]` | resolved `event.stack` contains **none** of the strings |
| `fd_snapshot`             | `bool`     | event is a `type:"fd_snapshot"` poller sample           |
| `fd_count_gt`             | `u32`      | snapshot's `fd_count > value` (snapshot events only)    |
| `fd_count_pct_of_rlimit_gt` | `u8`     | snapshot's `fd_pct_of_rlimit > value` (rlimit must be known) |
| `ioctl_family_in`         | `[string]` | decoded `ioctl_family` ∈ list (e.g. `dma_heap`, `binder`) |
| `ioctl_name_in`           | `[string]` | decoded `ioctl_name` ∈ list (e.g. `DMA_HEAP_IOCTL_ALLOC`) |
| `process_exit`            | `bool`     | event is a `type:"process_exit"` line                    |
| `exit_signal_in`          | `[u32]`    | exit's `exit_signal` ∈ list (POSIX numbers, `11`=SIGSEGV)|
| `exit_classification_in`  | `[string]` | `classification` ∈ list (`crash`, `signal_exit`, ...)    |
| `exit_source_in`          | `[string]` | `source` ∈ list (`tracepoint`, `logcat`, `tombstone`)    |

`stack_contains` / `stack_not_contains` require the tracer to be running
with `--stacks`. The substrings match against the rendered stack string
(see [output-formats.md](output-formats.md) for the format).

The `fd_*` predicates only match against `type:"fd_snapshot"` events
emitted by the periodic FD-graph poller (sprint-1 PR 3). Enable the
poller with `--fdgraph-pids active` (default) and an interval other than
`off`. `fd_count_pct_of_rlimit_gt` requires a non-zero `RLIMIT_NOFILE`
in the snapshot — events with unknown rlimit never match (fail-closed).

The `ioctl_*_in` predicates only match events the userspace decoder
registry recognises (sprint-1 PR 2). The decoder fills `ioctl_family`
for known type bytes (`dma_heap`, `binder`, `dma_buf`, `ashmem`) and
fills `ioctl_name` for commands in its registry. Unknown commands carry
no decoded fields and never match these predicates.

The `exit_*` predicates only match `type:"process_exit"` events (sprint-2
PR 1). These are emitted by the BPF `sched_process_exit` tracepoint, the
logcat tail, and the `/data/tombstones/` watcher. `exit_classification_in`
accepts `crash` (fatal signal), `signal_exit` (non-fatal signal like
SIGKILL), `abnormal_exit` (`exit(N)` with `N != 0`), and `normal_exit`.
`exit_source_in` is useful when only userspace-attributed crashes carry
enough info to act on — the bare BPF tracepoint emits `exit_signal: 0`
because reading `task_struct->exit_code` requires BTF and is deferred.

### Stack-aware example

```yaml
- id: T016_native_root_check_via_libc
  name: fstatat on su path from libc
  severity: high
  category: root_detection
  conditions:
    - syscall_in: [79]                # newfstatat
    - path_in:
        - /system/xbin/su
        - /system/bin/su
        - /sbin/su
    - stack_contains:
        - libc
  frequency:
    window_ms: 5000
    min_count: 1
  aggregate: per_process
```

This fires once per process when `fstatat` on a known su path resolves
to a stack containing the substring `libc`. The default ruleset uses
`stack_not_contains` to exclude RenderScript / Skia from
`/system/lib64/*` probing in T019.

### FD-graph example (R001)

Sprint-1 PR 3 introduced periodic `/proc/<pid>/fd` snapshots. Rules can
match those snapshots directly without needing a frequency window — the
poller's interval already drives the cadence.

```yaml
- id: R001_fd_table_exhaustion
  name: FD table approaching rlimit
  severity: high
  category: resource_exhaustion
  conditions:
    - fd_snapshot: true
      fd_count_pct_of_rlimit_gt: 90
  aggregate: per_process
```

This fires for any traced process whose live FD count crosses 90% of its
`RLIMIT_NOFILE` allowance. The default poller interval is 1 s, so the
rule produces at most one finding per process even during sustained
exhaustion thanks to `per_process` aggregation.

### Crash-correlation example (R003)

Sprint-2 PR 1 introduced `process_exit` events. They are emitted by three
independent sources (BPF tracepoint, logcat tail, tombstone watcher); the
default rule R003 fires once per fatal-signal crash regardless of which
source observed it first:

```yaml
- id: R003_process_crash
  name: Process killed by fatal signal
  severity: critical
  category: crash
  conditions:
    - process_exit: true
      exit_classification_in: [crash]
  aggregate: per_process
```

`per_process` aggregation collapses the typical fan-out (a single SIGSEGV
yields a `tracepoint` line, then a `tombstone` line, then a `logcat` line).
The emitted JSON carries `crash_context` — the last `--lookback-events`
NDJSON lines neutron observed for the PID — so a finding is self-contained
evidence without needing to grep the full stream.

### Decoded-ioctl example (R002)

Sprint-1 PR 2 introduced post-exit ioctl decoding. Combine the family /
name predicates with a frequency window to catch DMA-heap allocation
storms:

```yaml
- id: R002_dma_heap_allocation_burst
  name: DMA-heap allocation burst
  severity: medium
  category: resource_exhaustion
  conditions:
    - syscall_in: [29]                # ioctl
      ioctl_family_in: [dma_heap]
      ioctl_name_in: [DMA_HEAP_IOCTL_ALLOC]
  frequency:
    window_ms: 5000
    min_count: 50
  aggregate: per_process
```

`syscall_in: [29]` keeps the predicate cheap — non-ioctl events skip
the family/name checks entirely.

## Frequency rules

Use a `frequency:` block when "any single hit" is too noisy and the
diagnostic value is in the rate.

```yaml
frequency:
  window_ms: 10000
  min_count: 2
```

This says: "emit only once at least 2 events match within a 10s window".
After emission the rule keeps updating `event_count` and `last_seen_ns`
but does not re-emit. The final flush at end of capture will produce a
summary finding with the cumulative count and computed `period_ms`.

Pick `min_count` so that benign occurrences do not trigger. For a process
that opens `/proc/self/maps` once at startup (e.g. for legitimate JIT
metadata), `min_count: 2` already filters that out.

## Aggregate modes

- `per_process` (default) — emit once per matching process. Good for
  "this app does X".
- `per_target` — emit once per `(process, first matched data string)`.
  Use when the same syscall pattern probes many distinct targets and
  you want each target on its own line.
- `every_event` — emit on every match. Reserve for rare events
  (e.g. RWX mmap) where you really do want every occurrence.

## Authoring workflow

1. Capture a session with `--raw --json` while the behavior is reproducible.
2. Inspect the NDJSON to find the events you want to match. `jq` works:
   ```bash
   jq 'select(.name == "openat" and (.data // "") | startswith("/proc/self"))' < capture.ndjson
   ```
3. Sketch the rule in a separate YAML file:
   ```bash
   cp neutron-rules/rules/default.yaml my-rules.yaml
   $EDITOR my-rules.yaml
   ```
4. Re-run the capture with `--rules my-rules.yaml`.
5. Iterate until the rule fires when expected and stays silent otherwise.

## Adding tests

Once a rule lives in the default pack, add coverage to
`neutron-rules/tests/engine.rs`:

```rust
#[test]
fn t101_example_detector_fires() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(&mut engine, &[
        r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/proc/self/example"}"#,
    ]);
    let findings = engine.drain_ready();
    assert!(findings.iter().any(|f| f.rule_id == "T101_example_detector"));
}

#[test]
fn t101_example_detector_does_not_fire_on_unrelated_path() {
    let mut engine = RuleEngine::with_default_rules().unwrap();
    feed_lines(&mut engine, &[
        r#"{"ts_ns":1000,"pid":42,"tid":42,"uid":1000,"nr":56,"name":"openat","comm":"app","enter":false,"ret":7,"args":[0,0,0,0,0,0],"data":"/data/data/app/cache.bin"}"#,
    ]);
    let findings = engine.drain_ready();
    assert!(!findings.iter().any(|f| f.rule_id == "T101_example_detector"));
}
```

Both a positive and a negative case are required for new rules going into
the default pack.

## Common pitfalls

- **Empty data field.** On kernel 6.1+ the BPF user-string read is
  generally reliable, but for `connect()` exits that race with `close()`
  the in-kernel read can return an empty buffer. Add `--resolve-paths`
  to enable the userspace fallback (`/proc/<pid>/fd/<fd>` readlink,
  `/proc/<pid>/net/tcp*`).
- **Stack rules without `--stacks`.** `stack_contains` /
  `stack_not_contains` only match when the tracer is run with `--stacks`.
  Without it, `event.stack` is empty and the rule never fires (or always
  fires, for `stack_not_contains`).
- **Catch-all `data_any`.** `data_any` is substring-OR. A short generic
  needle like `"su"` will match `"sudo"`, `"susceptible"`, paths under
  `/system/usr/`, and many others. Anchor with `path_in` or
  `path_prefix` when you can.
- **Frequency on `every_event` rules.** They are mutually exclusive in
  practice — every-event already emits per match. The engine accepts the
  combination but it is rarely useful.
- **`ret_lt: 0` and missing exit events.** A rule that requires `ret < 0`
  only matches on exit events. Make sure the `--profile` you use captures
  exits for the relevant syscalls.
