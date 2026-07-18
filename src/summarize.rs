//! `neutron summarize <capture> --by <keys> [--samples N] [--top K]`
//!
//! Host-side aggregation post-processor for NDJSON captures. Counts
//! events by user-chosen key tuple and optionally retains a small
//! reservoir of full lines per group. Designed to make 1.4 GB traces
//! analyzable without a database — the assessment's loudest pain point
//! after Phase 1's volume reduction.
//!
//! The streaming-parse pattern (line-by-line `BufRead`, lossy JSON,
//! malformed lines kept verbatim) follows `window.rs` so behavioural
//! changes show up consistently across host-side subcommands.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::capture_input::{
    read_capture_record, validate_capture_strings, MAX_CAPTURE_STRING_BYTES,
};

const MAX_AGGREGATION_GROUPS: usize = 100_000;
const MAX_AGGREGATION_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_AGGREGATION_EXEMPLAR_BYTES: usize = 64 * 1024 * 1024;

/// One column of the group-by key. Each variant maps to a specific JSON
/// field on the event line. Unknown fields → an explicit string sentinel
/// (`<none>`) instead of being skipped, so groups don't collapse silently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyField {
    Syscall,
    Pid,
    Tid,
    Uid,
    Comm,
    FdPath,
    IoctlCmd,
    IoctlName,
    IoctlFamily,
    Ret,
    /// `ok` / `errno` / `unset` based on the `ret` value (exit events only).
    RetClass,
    /// Event `type` field (syscall/binder/finding/...).
    Type,
    IsEnter,
}

impl KeyField {
    pub fn parse(s: &str) -> Result<Self> {
        let key = match s.trim() {
            "syscall" => KeyField::Syscall,
            "pid" => KeyField::Pid,
            "tid" => KeyField::Tid,
            "uid" => KeyField::Uid,
            "comm" => KeyField::Comm,
            "fd_path" => KeyField::FdPath,
            "ioctl_cmd" => KeyField::IoctlCmd,
            "ioctl_name" => KeyField::IoctlName,
            "ioctl_family" => KeyField::IoctlFamily,
            "ret" => KeyField::Ret,
            "ret_class" => KeyField::RetClass,
            "type" => KeyField::Type,
            "is_enter" => KeyField::IsEnter,
            other => bail!(
                "unknown --by field '{other}' \
                 (supported: syscall,pid,tid,uid,comm,fd_path,\
                 ioctl_cmd,ioctl_name,ioctl_family,ret,ret_class,type,is_enter)"
            ),
        };
        Ok(key)
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyField::Syscall => "syscall",
            KeyField::Pid => "pid",
            KeyField::Tid => "tid",
            KeyField::Uid => "uid",
            KeyField::Comm => "comm",
            KeyField::FdPath => "fd_path",
            KeyField::IoctlCmd => "ioctl_cmd",
            KeyField::IoctlName => "ioctl_name",
            KeyField::IoctlFamily => "ioctl_family",
            KeyField::Ret => "ret",
            KeyField::RetClass => "ret_class",
            KeyField::Type => "type",
            KeyField::IsEnter => "is_enter",
        }
    }

    fn extract(self, obj: &serde_json::Map<String, Value>) -> String {
        const NONE: &str = "<none>";
        match self {
            KeyField::Syscall => obj
                // Live `--json` output uses `"name":"ioctl"`. The
                // legacy `"syscall":"…"` key was hypothetical and does
                // not appear on real captures — accept it as a
                // fallback so synthetic test fixtures keep working,
                // but read `name` first.
                .get("name")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| obj.get("syscall").and_then(Value::as_str).map(String::from))
                .or_else(|| obj.get("nr").and_then(Value::as_i64).map(|n| n.to_string()))
                .or_else(|| {
                    obj.get("syscall_nr")
                        .and_then(Value::as_i64)
                        .map(|n| n.to_string())
                })
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::Pid => obj
                .get("pid")
                .and_then(Value::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::Tid => obj
                .get("tid")
                .and_then(Value::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::Uid => obj
                .get("uid")
                .and_then(Value::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::Comm => obj
                .get("comm")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::FdPath => obj
                .get("fd_path")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::IoctlCmd => obj
                .get("ioctl_cmd")
                .and_then(Value::as_str)
                .map(String::from)
                .or_else(|| {
                    // Many older lines carry the request as part of the
                    // human-decoded `data` string instead. Best-effort:
                    // skip when missing.
                    obj.get("data")
                        .and_then(Value::as_str)
                        .filter(|s| s.contains("_IOC("))
                        .map(String::from)
                })
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::IoctlName => obj
                .get("ioctl_name")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::IoctlFamily => obj
                .get("ioctl_family")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::Ret => obj
                .get("ret")
                .and_then(Value::as_i64)
                .map(|n| n.to_string())
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::RetClass => match (
                obj.get("phase").and_then(Value::as_str),
                obj.get("ret").and_then(Value::as_i64),
            ) {
                (Some("exit"), Some(0)) => "ok".to_string(),
                (Some("exit"), Some(n)) if n < 0 => "errno".to_string(),
                (Some("exit"), Some(_)) => "ok_nonzero".to_string(),
                _ => "unset".to_string(),
            },
            KeyField::Type => obj
                .get("type")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| NONE.to_string()),
            KeyField::IsEnter => match obj.get("phase").and_then(Value::as_str) {
                Some("enter") => "true".to_string(),
                Some("exit") => "false".to_string(),
                _ => NONE.to_string(),
            },
        }
    }
}

/// Per-group accumulator. `exemplars` holds up to `samples_cap` raw
/// NDJSON lines, useful when the operator wants to inspect a few real
/// examples from a high-count group.
#[derive(Clone, Debug, Default)]
pub struct Aggregate {
    pub count: u64,
    pub exemplars: Vec<String>,
}

/// Map of `key tuple → counts` keyed by Vec<String> so the BTreeMap
/// ordering is deterministic.
pub type Aggregation = BTreeMap<Vec<String>, Aggregate>;

/// Streaming aggregation. Keeps memory bounded to `O(unique_groups)` plus
/// `O(samples_cap)` line clones per group.
pub fn summarize<R: BufRead>(
    reader: R,
    keys: &[KeyField],
    samples_cap: usize,
) -> Result<Aggregation> {
    summarize_impl(reader, keys, samples_cap, None)
}

/// Aggregate only behavior records causally tagged with one of the validated
/// scenario IDs. Marker and health records define the evidence boundary but
/// are never counted as behavior.
pub fn summarize_scenarios<R: BufRead>(
    reader: R,
    keys: &[KeyField],
    samples_cap: usize,
    scenario_traces: &BTreeMap<String, String>,
) -> Result<Aggregation> {
    summarize_impl(reader, keys, samples_cap, Some(scenario_traces))
}

fn summarize_impl<R: BufRead>(
    mut reader: R,
    keys: &[KeyField],
    samples_cap: usize,
    scenario_traces: Option<&BTreeMap<String, String>>,
) -> Result<Aggregation> {
    if keys.is_empty() {
        bail!("at least one --by field is required");
    }
    let mut out = Aggregation::new();
    let mut line = Vec::new();
    let mut record_number = 1usize;
    let mut key_bytes = 0usize;
    let mut exemplar_bytes = 0usize;
    while read_capture_record(&mut reader, &mut line, record_number)? {
        let text = std::str::from_utf8(&line)
            .with_context(|| format!("capture record {record_number} is not UTF-8"))?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            record_number += 1;
            continue;
        }
        let v: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                record_number += 1;
                continue; // keep behaviour parallel to window.rs
            }
        };
        validate_capture_strings(&v, record_number)?;
        let obj = match v.as_object() {
            Some(o) => o,
            None => {
                record_number += 1;
                continue;
            }
        };
        if let Some(scenario_traces) = scenario_traces {
            let kind = obj.get("type").and_then(Value::as_str);
            let scenario_id = obj.get("scenario_id").and_then(Value::as_str);
            let trace_id = obj.get("trace_id").and_then(Value::as_str);
            if matches!(kind, Some("marker" | "capture_health"))
                || !scenario_id.is_some_and(|scenario| {
                    scenario_traces.get(scenario).map(String::as_str) == trace_id
                })
            {
                record_number += 1;
                continue;
            }
        }
        let key: Vec<String> = keys.iter().map(|k| k.extract(obj)).collect();
        if key
            .iter()
            .any(|value| value.len() > MAX_CAPTURE_STRING_BYTES)
        {
            bail!(
                "capture record {record_number} group key exceeds {MAX_CAPTURE_STRING_BYTES} bytes"
            );
        }
        if !out.contains_key(&key) {
            if out.len() >= MAX_AGGREGATION_GROUPS {
                bail!("capture aggregation exceeds {MAX_AGGREGATION_GROUPS} groups");
            }
            let added = key.iter().try_fold(0usize, |total, value| {
                total
                    .checked_add(value.len())
                    .context("aggregation key byte count overflow")
            })?;
            key_bytes = key_bytes
                .checked_add(added)
                .context("aggregation key byte count overflow")?;
            if key_bytes > MAX_AGGREGATION_KEY_BYTES {
                bail!("capture aggregation keys exceed {MAX_AGGREGATION_KEY_BYTES} bytes");
            }
        }
        let entry = out.entry(key).or_default();
        entry.count = entry.count.saturating_add(1);
        if entry.exemplars.len() < samples_cap {
            exemplar_bytes = exemplar_bytes
                .checked_add(trimmed.len())
                .context("aggregation exemplar byte count overflow")?;
            if exemplar_bytes > MAX_AGGREGATION_EXEMPLAR_BYTES {
                bail!(
                    "capture aggregation exemplars exceed {MAX_AGGREGATION_EXEMPLAR_BYTES} bytes"
                );
            }
            entry.exemplars.push(trimmed.to_string());
        }
        record_number += 1;
    }
    Ok(out)
}

/// Render the aggregation as a human-readable table. `top` of `0` means
/// "show all groups". The table is sorted by count descending; ties
/// break on the key tuple lexicographically.
pub fn render_table(agg: &Aggregation, keys: &[KeyField], top: usize, samples: usize) -> String {
    let mut rows: Vec<(&Vec<String>, &Aggregate)> = agg.iter().collect();
    rows.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
    if top > 0 && rows.len() > top {
        rows.truncate(top);
    }
    if rows.is_empty() {
        return "no events matched the configured group keys\n".to_string();
    }
    // Compute column widths for alignment. `count` and each key column.
    let mut widths: Vec<usize> = keys.iter().map(|k| k.label().len()).collect();
    let count_w = "count".len().max(
        rows.iter()
            .map(|(_, a)| a.count.to_string().len())
            .max()
            .unwrap_or(5),
    );
    let escaped_rows: Vec<(Vec<String>, &Aggregate)> = rows
        .iter()
        .map(|(key, aggregate)| {
            (
                key.iter()
                    .map(|value| crate::decode::escape_text(value))
                    .collect(),
                *aggregate,
            )
        })
        .collect();
    for (key, _) in &escaped_rows {
        for (i, v) in key.iter().enumerate() {
            widths[i] = widths[i].max(v.chars().count());
        }
    }
    let mut out = String::new();
    // Header
    let mut header = format!("{:>w$}", "count", w = count_w);
    for (i, k) in keys.iter().enumerate() {
        header.push_str("  ");
        header.push_str(&format!("{:<w$}", k.label(), w = widths[i]));
    }
    out.push_str(&header);
    out.push('\n');
    out.push_str(&"─".repeat(header.chars().count()));
    out.push('\n');
    for (key, agg) in &escaped_rows {
        let mut row = format!("{:>w$}", agg.count, w = count_w);
        for (i, v) in key.iter().enumerate() {
            row.push_str("  ");
            row.push_str(&format!("{:<w$}", v, w = widths[i]));
        }
        out.push_str(&row);
        out.push('\n');
        if samples > 0 {
            for ex in agg.exemplars.iter().take(samples) {
                out.push_str("    ");
                out.push_str(&crate::decode::escape_text(ex));
                out.push('\n');
            }
        }
    }
    let total: u64 = agg.values().map(|a| a.count).sum();
    out.push_str(&format!(
        "\n{} groups, {} events total{}\n",
        agg.len(),
        total,
        if top > 0 && agg.len() > top {
            format!(" (showing top {top})")
        } else {
            String::new()
        }
    ));
    out
}

/// Open an NDJSON capture by path (or stdin when `-`).
pub fn open_capture(path: &str) -> Result<Box<dyn BufRead>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(io::stdin().lock())))
    } else {
        let f = File::open(path).with_context(|| format!("opening capture file {path}"))?;
        Ok(Box::new(BufReader::new(f)))
    }
}

/// Parse `--by` into a list of [`KeyField`]s.
pub fn parse_by(s: &str) -> Result<Vec<KeyField>> {
    let mut keys = Vec::new();
    for piece in s.split(',') {
        let trimmed = piece.trim();
        if trimmed.is_empty() {
            continue;
        }
        keys.push(KeyField::parse(trimmed)?);
    }
    if keys.is_empty() {
        bail!("--by must list at least one field");
    }
    Ok(keys)
}

/// Entry point — invoked from `main.rs` when the user runs
/// `neutron summarize <capture> ...`.
pub fn run(args: SummarizeArgs) -> Result<()> {
    let keys = parse_by(&args.by)?;
    let reader = open_capture(&args.capture)?;
    let agg = summarize(reader, &keys, args.samples)?;
    let mut stdout = io::stdout().lock();
    let table = render_table(&agg, &keys, args.top, args.samples);
    stdout
        .write_all(table.as_bytes())
        .context("writing summary to stdout")?;
    Ok(())
}

/// CLI args for `neutron summarize`. Lives in this module so the parser
/// definition and the runtime stay in sync.
#[derive(clap::Parser, Debug)]
pub struct SummarizeArgs {
    /// Path to the NDJSON capture file (`-` for stdin).
    pub capture: String,

    /// Comma-separated list of group-by fields. Supported:
    /// `syscall, pid, tid, uid, comm, fd_path, ioctl_cmd, ioctl_name,
    /// ioctl_family, ret, ret_class, type, is_enter`.
    #[arg(long, value_name = "FIELDS")]
    pub by: String,

    /// Keep up to N raw NDJSON exemplars per group. `0` (default)
    /// disables exemplar collection.
    #[arg(long, default_value_t = 0)]
    pub samples: usize,

    /// Print only the top K groups by count. `0` (default) prints all.
    #[arg(long, default_value_t = 0)]
    pub top: usize,
}

/// Convenience constructor for tests / programmatic callers that don't
/// want to go through clap.
impl SummarizeArgs {
    pub fn new(capture: impl Into<String>, by: impl Into<String>) -> Self {
        SummarizeArgs {
            capture: capture.into(),
            by: by.into(),
            samples: 0,
            top: 0,
        }
    }
}

/// Public re-export so downstream callers can avoid `use` of the
/// private module path.
pub use Aggregate as GroupAggregate;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn s(input: &str) -> Cursor<&str> {
        Cursor::new(input)
    }

    #[test]
    fn parses_known_keys() {
        let keys = parse_by("syscall,fd_path,ret_class").unwrap();
        assert_eq!(
            keys,
            vec![KeyField::Syscall, KeyField::FdPath, KeyField::RetClass]
        );
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = parse_by("garbage").unwrap_err();
        assert!(format!("{err:#}").contains("unknown --by field"));
    }

    #[test]
    fn rejects_empty_by_list() {
        assert!(parse_by("").is_err());
        assert!(parse_by(",,,").is_err());
    }

    #[test]
    fn syscall_key_reads_name_field_from_live_schema() {
        // Live `--json` output puts the syscall name under "name", not
        // "syscall". The 2026-05-06 device test surfaced this: every
        // group landed in the `<none>` bucket. Verify we now read
        // "name" first.
        let lines = r#"{"type":"syscall","name":"ioctl","pid":970,"phase":"exit"}
{"type":"syscall","name":"ioctl","pid":970,"phase":"exit"}
{"type":"syscall","name":"openat","pid":1234,"phase":"exit"}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let by_label: BTreeMap<String, u64> =
            agg.iter().map(|(k, v)| (k[0].clone(), v.count)).collect();
        assert_eq!(by_label.get("ioctl").copied(), Some(2));
        assert_eq!(by_label.get("openat").copied(), Some(1));
        assert!(!by_label.contains_key("<none>"), "name field must resolve");
    }

    #[test]
    fn syscall_key_falls_back_to_nr_when_no_name() {
        // Capture lines that carry only `nr` (e.g. legacy or unrecognised
        // syscalls): we still surface a usable group key.
        let lines = r#"{"type":"syscall","nr":29}
{"type":"syscall","nr":222}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let by_label: BTreeMap<String, u64> =
            agg.iter().map(|(k, v)| (k[0].clone(), v.count)).collect();
        assert_eq!(by_label.get("29").copied(), Some(1));
        assert_eq!(by_label.get("222").copied(), Some(1));
    }

    #[test]
    fn aggregates_by_syscall_and_pid() {
        let lines = r#"{"syscall":"ioctl","pid":970,"phase":"exit","ret":0}
{"syscall":"ioctl","pid":970,"phase":"exit","ret":0}
{"syscall":"openat","pid":1234,"phase":"exit","ret":3}
{"syscall":"openat","pid":1234,"phase":"exit","ret":3}
{"syscall":"openat","pid":1234,"phase":"exit","ret":-22}"#;
        let keys = parse_by("syscall,pid").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        assert_eq!(agg.len(), 2);
        let ioctl_key = vec!["ioctl".to_string(), "970".to_string()];
        let openat_key = vec!["openat".to_string(), "1234".to_string()];
        assert_eq!(agg[&ioctl_key].count, 2);
        assert_eq!(agg[&openat_key].count, 3);
    }

    #[test]
    fn ret_class_categorises_correctly() {
        let lines = r#"{"syscall":"ioctl","phase":"exit","ret":0}
{"syscall":"ioctl","phase":"exit","ret":-22}
{"syscall":"ioctl","phase":"exit","ret":42}
{"syscall":"ioctl","phase":"enter","ret":0}"#;
        let keys = parse_by("ret_class").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let by_label: BTreeMap<String, u64> =
            agg.iter().map(|(k, v)| (k[0].clone(), v.count)).collect();
        assert_eq!(by_label.get("ok").copied(), Some(1));
        assert_eq!(by_label.get("errno").copied(), Some(1));
        assert_eq!(by_label.get("ok_nonzero").copied(), Some(1));
        assert_eq!(by_label.get("unset").copied(), Some(1));
    }

    #[test]
    fn fd_path_substitutes_none_when_missing() {
        let lines = r#"{"syscall":"ioctl"}
{"syscall":"ioctl","fd_path":"/dev/lwis-top"}"#;
        let keys = parse_by("fd_path").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let with_path = vec!["/dev/lwis-top".to_string()];
        let without = vec!["<none>".to_string()];
        assert_eq!(agg[&with_path].count, 1);
        assert_eq!(agg[&without].count, 1);
    }

    #[test]
    fn samples_cap_limits_exemplars_per_group() {
        let lines = r#"{"syscall":"ioctl"}
{"syscall":"ioctl"}
{"syscall":"ioctl"}
{"syscall":"ioctl"}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 2).unwrap();
        let key = vec!["ioctl".to_string()];
        assert_eq!(agg[&key].count, 4);
        assert_eq!(agg[&key].exemplars.len(), 2);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let lines = "garbage line\n{\"syscall\":\"ioctl\"}\n  \n{not-json";
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        assert_eq!(agg.values().map(|a| a.count).sum::<u64>(), 1);
    }

    #[test]
    fn render_table_shows_count_and_keys() {
        let lines = r#"{"syscall":"ioctl","pid":970,"phase":"exit","ret":0}
{"syscall":"ioctl","pid":970,"phase":"exit","ret":-22}
{"syscall":"openat","pid":1234,"phase":"exit","ret":3}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let table = render_table(&agg, &keys, 0, 0);
        assert!(table.contains("syscall"));
        assert!(table.contains("ioctl"));
        assert!(table.contains("openat"));
        assert!(table.contains("3 events total") || table.contains("3 events"));
    }

    #[test]
    fn render_table_top_n_truncates_and_notes_truncation() {
        let lines = r#"{"syscall":"a"}
{"syscall":"a"}
{"syscall":"b"}
{"syscall":"c"}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 0).unwrap();
        let table = render_table(&agg, &keys, 1, 0);
        // Top-1: only "a" (count 2) is in the body.
        assert!(table.contains("  a "));
        assert!(table.contains("showing top 1"));
    }

    #[test]
    fn render_table_includes_exemplars_when_requested() {
        let lines = r#"{"syscall":"ioctl","note":"first"}
{"syscall":"ioctl","note":"second"}"#;
        let keys = parse_by("syscall").unwrap();
        let agg = summarize(s(lines), &keys, 5).unwrap();
        let table = render_table(&agg, &keys, 0, 5);
        assert!(table.contains("\\\"note\\\":\\\"first\\\""));
        assert!(table.contains("\\\"note\\\":\\\"second\\\""));
    }

    #[test]
    fn render_table_escapes_untrusted_values_and_exemplars() {
        let lines = "{\"comm\":\"bad\\u001b[2J\\nrow\"}";
        let keys = parse_by("comm").unwrap();
        let agg = summarize(s(lines), &keys, 1).unwrap();
        let table = render_table(&agg, &keys, 0, 1);

        assert!(!table.contains('\u{1b}'));
        assert!(!table.contains("\nrow"));
        assert!(table.contains("\\u{1b}[2J\\nrow"));
    }

    #[test]
    fn summarize_requires_at_least_one_key() {
        let agg = summarize(s("{}\n"), &[], 0);
        assert!(agg.is_err());
    }

    #[test]
    fn oversized_capture_record_is_rejected() {
        let input = format!(r#"{{"comm":"{}"}}"#, "x".repeat(4 * 1024 * 1024 + 1));
        let keys = parse_by("comm").unwrap();
        let error = summarize(Cursor::new(input), &keys, 0).unwrap_err();

        assert!(format!("{error:#}").contains("capture record 1 exceeds"));
    }

    #[test]
    fn oversized_json_string_is_rejected() {
        let input = format!(r#"{{"comm":"{}"}}"#, "x".repeat(64 * 1024 + 1));
        let keys = parse_by("comm").unwrap();
        let error = summarize(Cursor::new(input), &keys, 0).unwrap_err();

        assert!(format!("{error:#}").contains("contains a string exceeding"));
    }

    #[test]
    fn excessive_group_cardinality_is_rejected() {
        let mut input = String::new();
        for index in 0..=100_000 {
            input.push_str(&format!("{{\"comm\":\"group-{index}\"}}\n"));
        }
        let keys = parse_by("comm").unwrap();
        let error = summarize(Cursor::new(input), &keys, 0).unwrap_err();

        assert!(format!("{error:#}").contains("aggregation exceeds 100000 groups"));
    }
}
