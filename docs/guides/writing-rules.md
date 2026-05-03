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

`stack_contains` / `stack_not_contains` require the tracer to be running
with `--stacks`. The substrings match against the rendered stack string
(see [output-formats.md](output-formats.md) for the format).

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
