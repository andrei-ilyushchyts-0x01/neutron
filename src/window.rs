//! `neutron window` — host-side post-processor that cuts windows of events
//! around an anchor from a previously-captured NDJSON file.
//!
//! Sprint-2 PR 3.
//!
//! # Anchors
//!
//! - `finding:<RULE_ID>` — every `type:"finding"` event with matching `rule_id`.
//! - `crash` — every `type:"process_exit"` with `classification == "crash"`.
//! - `pid:<N>` — every event with `pid == N`.
//! - `event_id:<N>` — single event by `event_id`.
//! - `comm:<substring>` — every event whose `comm` contains the substring.
//! - `binder_call:<status>` — every `type:"binder_call"` with matching `status`.
//!
//! # Windows
//!
//! - **Time-based:** `--before 5s --after 1s` (or shorthand `--around 2s`).
//!   Walks left/right from the anchor index while `ts_ns` is within range.
//! - **Event-count:** `--before-events 100 --after-events 50` (or
//!   `--around-events`). Pure index arithmetic, ignores timestamps.
//!
//! Time and event-count specs are mutually exclusive per side.
//!
//! # Output
//!
//! - Default: NDJSON of all events in the merged windows, in original
//!   capture order. Overlapping windows are deduplicated.
//! - `--summary`: one line per merged window with the `ts_ns` range,
//!   event count, and the anchor specs that contributed to it.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;

use crate::cli::WindowArgs;

/// Parsed minimal view of one NDJSON line — only the fields anchors care
/// about. Holds the original raw line so output is byte-exact.
#[derive(Debug)]
struct ParsedLine {
    raw: String,
    ts_ns: Option<u64>,
    pid: Option<u32>,
    event_id: Option<u64>,
    type_str: Option<String>,
    rule_id: Option<String>,
    classification: Option<String>,
    comm: Option<String>,
    status: Option<String>,
}

impl ParsedLine {
    fn from_line(raw: String) -> Self {
        let mut p = ParsedLine {
            raw,
            ts_ns: None,
            pid: None,
            event_id: None,
            type_str: None,
            rule_id: None,
            classification: None,
            comm: None,
            status: None,
        };
        if let Ok(v) = serde_json::from_str::<Value>(&p.raw) {
            if let Some(obj) = v.as_object() {
                p.ts_ns = obj.get("ts_ns").and_then(Value::as_u64);
                p.pid = obj
                    .get("pid")
                    .and_then(Value::as_u64)
                    .map(|n| n as u32)
                    .or_else(|| {
                        // binder_call carries caller_pid; map for pid: anchors.
                        obj.get("caller_pid")
                            .and_then(Value::as_u64)
                            .map(|n| n as u32)
                    });
                p.event_id = obj.get("event_id").and_then(Value::as_u64);
                p.type_str = obj.get("type").and_then(Value::as_str).map(str::to_string);
                p.rule_id = obj
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                p.classification = obj
                    .get("classification")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                p.comm = obj
                    .get("comm")
                    .and_then(Value::as_str)
                    .or_else(|| obj.get("caller_comm").and_then(Value::as_str))
                    .map(str::to_string);
                p.status = obj
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
        }
        p
    }
}

/// One parsed `--anchor` flag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Anchor {
    Finding(String),
    Crash,
    Pid(u32),
    EventId(u64),
    Comm(String),
    BinderCall(String),
}

impl Anchor {
    pub fn parse(spec: &str) -> Result<Self> {
        // Bare anchors (no value).
        if spec == "crash" {
            return Ok(Anchor::Crash);
        }
        let (kind, value) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("anchor '{spec}' missing ':<value>' suffix"))?;
        if value.is_empty() {
            bail!("anchor '{spec}' has empty value");
        }
        match kind {
            "finding" => Ok(Anchor::Finding(value.to_string())),
            "pid" => {
                Ok(Anchor::Pid(value.parse().with_context(|| {
                    format!("pid anchor: '{value}' is not a u32")
                })?))
            }
            "event_id" => {
                Ok(Anchor::EventId(value.parse().with_context(|| {
                    format!("event_id anchor: '{value}' is not a u64")
                })?))
            }
            "comm" => Ok(Anchor::Comm(value.to_string())),
            "binder_call" => Ok(Anchor::BinderCall(value.to_string())),
            other => bail!("unknown anchor kind '{other}' in '{spec}'"),
        }
    }

    /// Returns `true` if this anchor matches `line`.
    fn matches(&self, line: &ParsedLine) -> bool {
        match self {
            Anchor::Finding(rule) => {
                line.type_str.as_deref() == Some("finding")
                    && line.rule_id.as_deref() == Some(rule.as_str())
            }
            Anchor::Crash => {
                line.type_str.as_deref() == Some("process_exit")
                    && line.classification.as_deref() == Some("crash")
            }
            Anchor::Pid(p) => line.pid == Some(*p),
            Anchor::EventId(id) => line.event_id == Some(*id),
            Anchor::Comm(needle) => line
                .comm
                .as_deref()
                .map(|c| c.contains(needle.as_str()))
                .unwrap_or(false),
            Anchor::BinderCall(want_status) => {
                line.type_str.as_deref() == Some("binder_call")
                    && line.status.as_deref() == Some(want_status.as_str())
            }
        }
    }

    /// Short label for `--summary` output.
    fn label(&self) -> String {
        match self {
            Anchor::Finding(r) => format!("finding:{r}"),
            Anchor::Crash => "crash".to_string(),
            Anchor::Pid(p) => format!("pid:{p}"),
            Anchor::EventId(id) => format!("event_id:{id}"),
            Anchor::Comm(c) => format!("comm:{c}"),
            Anchor::BinderCall(s) => format!("binder_call:{s}"),
        }
    }
}

/// Parsed window spec — one of: time-based, event-count, or unbounded
/// (default 100 events on each side when no flags supplied).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowSpec {
    Time { before: Duration, after: Duration },
    Events { before: usize, after: usize },
}

impl WindowSpec {
    /// Build from CLI flags. Errors if both time and event-count are set
    /// for the same side, or if a duration string fails to parse.
    pub fn from_args(args: &WindowArgs) -> Result<Self> {
        let around = args.around.as_deref().map(parse_duration).transpose()?;
        let before_t = args.before.as_deref().map(parse_duration).transpose()?;
        let after_t = args.after.as_deref().map(parse_duration).transpose()?;
        let before_t = before_t.or(around);
        let after_t = after_t.or(around);

        let around_e = args.around_events;
        let before_e = args.before_events.or(around_e);
        let after_e = args.after_events.or(around_e);

        let has_time = before_t.is_some() || after_t.is_some();
        let has_events = before_e.is_some() || after_e.is_some();
        if has_time && has_events {
            bail!(
                "cannot mix time-based (--before/--after/--around) and \
                 event-count (--before-events/--after-events/--around-events) windows"
            );
        }
        if has_time {
            return Ok(WindowSpec::Time {
                before: before_t.unwrap_or(Duration::ZERO),
                after: after_t.unwrap_or(Duration::ZERO),
            });
        }
        if has_events {
            return Ok(WindowSpec::Events {
                before: before_e.unwrap_or(0),
                after: after_e.unwrap_or(0),
            });
        }
        // Default: 100-event window on each side. Matches the in-memory
        // crash_context lookback default — same instinct, host-side.
        Ok(WindowSpec::Events {
            before: 100,
            after: 100,
        })
    }
}

/// Parse `5s` / `500ms` / `2000ns` duration strings. Same grammar as
/// `--fdgraph-interval`; lifted into a free function for reuse.
fn parse_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_suffix("ms") {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid ms duration: '{trimmed}'"))?;
        return Ok(Duration::from_millis(n));
    }
    if let Some(rest) = trimmed.strip_suffix("us") {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid us duration: '{trimmed}'"))?;
        return Ok(Duration::from_micros(n));
    }
    if let Some(rest) = trimmed.strip_suffix("ns") {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid ns duration: '{trimmed}'"))?;
        return Ok(Duration::from_nanos(n));
    }
    if let Some(rest) = trimmed.strip_suffix('s') {
        let n: u64 = rest
            .parse()
            .with_context(|| format!("invalid s duration: '{trimmed}'"))?;
        return Ok(Duration::from_secs(n));
    }
    bail!("invalid duration '{trimmed}' (expected '5s', '500ms', '100us', '1000ns')")
}

/// Inclusive line-index range for a single window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Range {
    start: usize,
    end: usize,
}

/// One merged window with its contributing anchors. `anchors` is the list
/// of anchor labels that landed inside this window; useful for `--summary`.
#[derive(Debug)]
struct MergedWindow {
    range: Range,
    anchors: Vec<String>,
    /// First and last `ts_ns` observed across the included lines (skipping
    /// lines without ts_ns). Both `None` if no included line had ts_ns.
    from_ts_ns: Option<u64>,
    to_ts_ns: Option<u64>,
}

/// Compute the inclusive range of line indices for a single anchor index
/// under the given window spec.
fn window_for(lines: &[ParsedLine], anchor_idx: usize, spec: WindowSpec) -> Range {
    let n = lines.len();
    debug_assert!(anchor_idx < n);
    match spec {
        WindowSpec::Events { before, after } => Range {
            start: anchor_idx.saturating_sub(before),
            end: (anchor_idx + after).min(n - 1),
        },
        WindowSpec::Time { before, after } => {
            // Anchor must have ts_ns to use time-based windows; if it
            // doesn't (e.g. a finding without ts_ns), fall back to the
            // single anchor line.
            let Some(anchor_ts) = lines[anchor_idx].ts_ns else {
                return Range {
                    start: anchor_idx,
                    end: anchor_idx,
                };
            };
            let lo = anchor_ts.saturating_sub(before.as_nanos() as u64);
            let hi = anchor_ts.saturating_add(after.as_nanos() as u64);
            // Walk left while we're within range or have no ts (carry along).
            let mut start = anchor_idx;
            while start > 0 {
                let prev = start - 1;
                match lines[prev].ts_ns {
                    Some(t) if t >= lo => start = prev,
                    Some(_) => break,
                    None => start = prev, // include null-ts lines flanking us
                }
            }
            let mut end = anchor_idx;
            while end + 1 < n {
                let next = end + 1;
                match lines[next].ts_ns {
                    Some(t) if t <= hi => end = next,
                    Some(_) => break,
                    None => end = next,
                }
            }
            Range { start, end }
        }
    }
}

/// Merge overlapping or adjacent ranges. `entries` is a list of
/// `(range, anchor_label)` pairs; returns merged windows with the union
/// of contributing anchors per merge.
fn merge_windows(mut entries: Vec<(Range, String)>, lines: &[ParsedLine]) -> Vec<MergedWindow> {
    if entries.is_empty() {
        return Vec::new();
    }
    entries.sort_by_key(|(r, _)| r.start);
    let mut out: Vec<MergedWindow> = Vec::new();
    for (r, label) in entries {
        if let Some(last) = out.last_mut() {
            // Adjacent windows (end+1 == next.start) also merge — no point
            // emitting back-to-back ranges that share a boundary.
            if r.start <= last.range.end + 1 {
                last.range.end = last.range.end.max(r.end);
                if !last.anchors.contains(&label) {
                    last.anchors.push(label);
                }
                continue;
            }
        }
        out.push(MergedWindow {
            range: r,
            anchors: vec![label],
            from_ts_ns: None,
            to_ts_ns: None,
        });
    }
    // Fill in ts_ns extents for summary mode.
    for w in out.iter_mut() {
        for line in &lines[w.range.start..=w.range.end] {
            if let Some(t) = line.ts_ns {
                w.from_ts_ns = Some(w.from_ts_ns.map(|x| x.min(t)).unwrap_or(t));
                w.to_ts_ns = Some(w.to_ts_ns.map(|x| x.max(t)).unwrap_or(t));
            }
        }
    }
    out
}

/// Read every line from `path` (or stdin when `-`) into `Vec<ParsedLine>`.
/// Empty lines are silently dropped; malformed JSON lines are kept (their
/// fields stay `None`) so byte-exact pass-through is preserved.
fn load_capture(path: &str) -> Result<Vec<ParsedLine>> {
    let reader: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(io::stdin().lock()))
    } else {
        Box::new(BufReader::new(
            File::open(path).with_context(|| format!("opening capture file {path}"))?,
        ))
    };
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = line.context("reading capture line")?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(ParsedLine::from_line(line));
    }
    Ok(out)
}

/// Entry point — invoked from `main.rs` when the user runs
/// `neutron window <capture> ...`.
pub fn run(args: WindowArgs) -> Result<()> {
    if args.anchor.is_empty() {
        bail!("at least one --anchor is required");
    }
    let anchors: Vec<Anchor> = args
        .anchor
        .iter()
        .map(|s| Anchor::parse(s.as_str()))
        .collect::<Result<_>>()?;
    let spec = WindowSpec::from_args(&args)?;
    let lines = load_capture(&args.capture)?;

    let mut entries: Vec<(Range, String)> = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        for anchor in &anchors {
            if anchor.matches(line) {
                entries.push((window_for(&lines, idx, spec), anchor.label()));
            }
        }
    }
    let windows = merge_windows(entries, &lines);

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.summary {
        emit_summary(&windows, &mut out)
    } else {
        emit_ndjson(&windows, &lines, &mut out)
    }
}

fn emit_ndjson(windows: &[MergedWindow], lines: &[ParsedLine], out: &mut dyn Write) -> Result<()> {
    for w in windows {
        for line in &lines[w.range.start..=w.range.end] {
            writeln!(out, "{}", line.raw).context("writing window line")?;
        }
    }
    Ok(())
}

fn emit_summary(windows: &[MergedWindow], out: &mut dyn Write) -> Result<()> {
    if windows.is_empty() {
        eprintln!("neutron window: no anchors matched");
        return Ok(());
    }
    for w in windows {
        let count = w.range.end - w.range.start + 1;
        let from = w.from_ts_ns.map(|x| x.to_string()).unwrap_or("?".into());
        let to = w.to_ts_ns.map(|x| x.to_string()).unwrap_or("?".into());
        let anchors = w.anchors.join(",");
        writeln!(out, "[{from}..{to}] events={count} anchors={anchors}")
            .context("writing summary line")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_lines() -> Vec<ParsedLine> {
        let raws = [
            r#"{"type":"syscall","ts_ns":1000,"pid":42,"comm":"app","nr":56,"event_id":1}"#,
            r#"{"type":"syscall","ts_ns":2000,"pid":42,"comm":"app","nr":56,"event_id":2}"#,
            r#"{"type":"syscall","ts_ns":3000,"pid":99,"comm":"other","nr":56,"event_id":3}"#,
            r#"{"type":"finding","rule_id":"R003","ts_ns":3500,"pid":42,"event_id":4}"#,
            r#"{"type":"process_exit","ts_ns":4000,"pid":42,"comm":"app","classification":"crash","event_id":5}"#,
            r#"{"type":"binder_call","ts_ns":5000,"caller_pid":7,"caller_comm":"x","callee_pid":42,"status":"callee_crashed","event_id":6}"#,
            r#"{"type":"syscall","ts_ns":6000,"pid":99,"comm":"other","nr":56,"event_id":7}"#,
        ];
        raws.iter()
            .map(|r| ParsedLine::from_line((*r).into()))
            .collect()
    }

    #[test]
    fn anchor_parser_accepts_all_kinds() {
        assert_eq!(Anchor::parse("crash").unwrap(), Anchor::Crash);
        assert_eq!(
            Anchor::parse("finding:R003").unwrap(),
            Anchor::Finding("R003".into())
        );
        assert_eq!(Anchor::parse("pid:42").unwrap(), Anchor::Pid(42));
        assert_eq!(Anchor::parse("event_id:7").unwrap(), Anchor::EventId(7));
        assert_eq!(
            Anchor::parse("comm:app").unwrap(),
            Anchor::Comm("app".into())
        );
        assert_eq!(
            Anchor::parse("binder_call:callee_crashed").unwrap(),
            Anchor::BinderCall("callee_crashed".into())
        );
    }

    #[test]
    fn anchor_parser_rejects_garbage() {
        assert!(Anchor::parse("").is_err());
        assert!(Anchor::parse("unknown:x").is_err());
        assert!(Anchor::parse("pid:not_a_number").is_err());
        assert!(Anchor::parse("comm:").is_err()); // empty value
    }

    #[test]
    fn finding_anchor_matches_only_correct_rule() {
        let lines = sample_lines();
        let a = Anchor::Finding("R003".into());
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| a.matches(l))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits, vec![3]);
        let other = Anchor::Finding("R001".into());
        assert!(lines.iter().all(|l| !other.matches(l)));
    }

    #[test]
    fn crash_anchor_matches_only_process_exit_with_crash_class() {
        let lines = sample_lines();
        let a = Anchor::Crash;
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| a.matches(l))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits, vec![4]);
    }

    #[test]
    fn pid_anchor_uses_caller_pid_for_binder_call() {
        let lines = sample_lines();
        let a = Anchor::Pid(7);
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| a.matches(l))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits, vec![5], "binder_call.caller_pid=7 should be matched");
    }

    #[test]
    fn comm_anchor_substring_matches_in_caller_comm_too() {
        let lines = sample_lines();
        let a = Anchor::Comm("app".into());
        let hits: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| a.matches(l))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(hits, vec![0, 1, 4], "matches comm='app' on syscalls + exit");
    }

    #[test]
    fn event_window_clamps_to_bounds() {
        let lines = sample_lines();
        let r = window_for(
            &lines,
            0,
            WindowSpec::Events {
                before: 10,
                after: 2,
            },
        );
        assert_eq!(r, Range { start: 0, end: 2 });
        let r = window_for(
            &lines,
            6,
            WindowSpec::Events {
                before: 2,
                after: 10,
            },
        );
        assert_eq!(r, Range { start: 4, end: 6 });
    }

    #[test]
    fn time_window_walks_outward_until_outside_range() {
        // sample_lines() uses tiny ts_ns values (1000..6000) so the test
        // window is sized in nanoseconds to keep arithmetic readable.
        let lines = sample_lines();
        // Anchor at idx 3 (ts=3500); ±1500ns gives lo=2000, hi=5000.
        // Inclusive bounds → indices with ts ∈ [2000, 5000] = [1..5].
        let r = window_for(
            &lines,
            3,
            WindowSpec::Time {
                before: Duration::from_nanos(1500),
                after: Duration::from_nanos(1500),
            },
        );
        assert_eq!(
            r,
            Range { start: 1, end: 5 },
            "inclusive ±1500ns walk should include ts 2000..=5000"
        );
    }

    #[test]
    fn time_window_strict_excludes_outside_range() {
        let lines = sample_lines();
        // Anchor at idx 3 (ts=3500); ±400ns gives lo=3100, hi=3900.
        // Only the anchor itself qualifies (ts=3500).
        let r = window_for(
            &lines,
            3,
            WindowSpec::Time {
                before: Duration::from_nanos(400),
                after: Duration::from_nanos(400),
            },
        );
        assert_eq!(r, Range { start: 3, end: 3 });
    }

    #[test]
    fn merge_combines_overlapping_ranges() {
        let lines = sample_lines();
        let entries = vec![
            (Range { start: 0, end: 2 }, "a".into()),
            (Range { start: 2, end: 4 }, "b".into()),
            (Range { start: 6, end: 6 }, "c".into()),
        ];
        let merged = merge_windows(entries, &lines);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].range, Range { start: 0, end: 4 });
        assert_eq!(merged[0].anchors, vec!["a", "b"]);
        assert_eq!(merged[1].range, Range { start: 6, end: 6 });
        assert_eq!(merged[1].anchors, vec!["c"]);
    }

    #[test]
    fn merge_combines_adjacent_ranges() {
        let lines = sample_lines();
        // [0..2] and [3..4] are adjacent (gap == 0 lines between them).
        let entries = vec![
            (Range { start: 0, end: 2 }, "a".into()),
            (Range { start: 3, end: 4 }, "b".into()),
        ];
        let merged = merge_windows(entries, &lines);
        assert_eq!(merged.len(), 1, "adjacent ranges should merge");
        assert_eq!(merged[0].range, Range { start: 0, end: 4 });
    }

    #[test]
    fn merge_keeps_disjoint_ranges_separate() {
        let lines = sample_lines();
        let entries = vec![
            (Range { start: 0, end: 1 }, "a".into()),
            (Range { start: 4, end: 6 }, "b".into()),
        ];
        let merged = merge_windows(entries, &lines);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merged_window_records_ts_extents() {
        let lines = sample_lines();
        let entries = vec![(Range { start: 0, end: 4 }, "a".into())];
        let merged = merge_windows(entries, &lines);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].from_ts_ns, Some(1000));
        assert_eq!(merged[0].to_ts_ns, Some(4000));
    }

    #[test]
    fn duration_parser_accepts_canonical_units() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("100us").unwrap(), Duration::from_micros(100));
        assert_eq!(
            parse_duration("1000ns").unwrap(),
            Duration::from_nanos(1000)
        );
        assert!(parse_duration("five seconds").is_err());
        assert!(parse_duration("5").is_err()); // missing unit
    }

    #[test]
    fn window_spec_default_is_event_count_100_each_side() {
        let args = WindowArgs {
            capture: String::new(),
            anchor: vec![],
            before: None,
            after: None,
            around: None,
            before_events: None,
            after_events: None,
            around_events: None,
            summary: false,
        };
        let spec = WindowSpec::from_args(&args).unwrap();
        assert_eq!(
            spec,
            WindowSpec::Events {
                before: 100,
                after: 100,
            }
        );
    }

    #[test]
    fn window_spec_around_expands_to_before_and_after() {
        let args = WindowArgs {
            capture: String::new(),
            anchor: vec![],
            before: None,
            after: None,
            around: Some("2s".into()),
            before_events: None,
            after_events: None,
            around_events: None,
            summary: false,
        };
        let spec = WindowSpec::from_args(&args).unwrap();
        assert_eq!(
            spec,
            WindowSpec::Time {
                before: Duration::from_secs(2),
                after: Duration::from_secs(2),
            }
        );
    }

    #[test]
    fn window_spec_rejects_mixed_time_and_event_count() {
        let args = WindowArgs {
            capture: String::new(),
            anchor: vec![],
            before: Some("1s".into()),
            after: None,
            around: None,
            before_events: None,
            after_events: Some(10),
            around_events: None,
            summary: false,
        };
        assert!(WindowSpec::from_args(&args).is_err());
    }
}
