# `neutron window` — host-side capture post-processor

`neutron window` cuts time- or event-bounded windows of NDJSON events
around an "anchor" (a finding, a crash, a PID, etc.) from a previously
captured trace file. It is the host-side companion of the in-memory
`crash_context` lookback that ships in `process_exit` events; the same
intuition, but operating on the full capture file instead of the bounded
ring buffer.

Sprint-2 PR 3.

## Quick start

```bash
# 5-second window (±) around every R003 finding.
neutron window capture.ndjson --anchor finding:R003_process_crash --around 5s

# 100 events before / 50 after every crash.
neutron window capture.ndjson --anchor crash --before-events 100 --after-events 50

# Just the events for a specific PID.
neutron window capture.ndjson --anchor pid:12345 --around-events 0

# Show only one summary line per merged window.
neutron window capture.ndjson --anchor crash --around 2s --summary
```

Reads from `-` for stdin: `cat capture.ndjson | neutron window - --anchor crash`.

## Anchors

| Spec                       | Matches                                                        |
|----------------------------|----------------------------------------------------------------|
| `finding:<RULE_ID>`        | `type:"finding"` with `rule_id == RULE_ID`                     |
| `crash`                    | `type:"process_exit"` with `classification == "crash"`         |
| `pid:<N>`                  | any event with `pid == N` (also `caller_pid` for `binder_call`)|
| `event_id:<N>`             | single event with the matching `event_id` correlation token    |
| `comm:<substring>`         | any event whose `comm` (or `caller_comm`) contains the string  |
| `binder_call:<status>`     | `type:"binder_call"` with `status == <status>`                 |

Multiple `--anchor` flags can be combined; each match becomes its own
anchor and the resulting windows are merged.

## Window sizing

Time-based and event-count windows are mutually exclusive — pick one.

### Time-based

| Flag                  | Meaning                                                    |
|-----------------------|------------------------------------------------------------|
| `--before <DURATION>` | how far back from the anchor's `ts_ns`                     |
| `--after  <DURATION>` | how far forward                                            |
| `--around <DURATION>` | shorthand: same value applied as both `--before` & `--after` |

Duration grammar: `5s` / `500ms` / `100us` / `1000ns`.

### Event-count

| Flag                       | Meaning                              |
|----------------------------|--------------------------------------|
| `--before-events <N>`      | how many lines back                  |
| `--after-events  <N>`      | how many lines forward               |
| `--around-events <N>`      | shorthand for both                   |

### Default

When no window flag is supplied, the default is **100 events on each
side** — the same instinct as the in-memory `--lookback-events 100`.

## Output

- Default: NDJSON of every line in the merged windows, in the original
  capture order. Overlapping windows are deduplicated; adjacent windows
  (touching at the boundary) merge.
- `--summary`: one line per merged window, format:

  ```
  [<from_ts_ns>..<to_ts_ns>] events=<N> anchors=<spec_list>
  ```

  where `<spec_list>` is the comma-joined list of anchor specs whose
  matches fell into the merged window.

## Cookbook

### "Show me everything 2 s around each crash"

```bash
neutron window capture.ndjson --anchor crash --around 2s
```

### "What did app PID 12345 see right before it crashed?"

```bash
neutron window capture.ndjson \
  --anchor pid:12345 \
  --before-events 200 --after-events 50
```

### "Trace the SurfaceFlinger binder calls leading up to its crash"

Combine `comm` and `crash` anchors so a single window covers both:

```bash
neutron window capture.ndjson \
  --anchor comm:surfaceflinger \
  --anchor crash \
  --around 1s --summary
```

### Pipe windows back into the rule engine

```bash
neutron window capture.ndjson --anchor crash --around 5s \
  | neutron --raw --json --rules custom-rules.yaml
```
