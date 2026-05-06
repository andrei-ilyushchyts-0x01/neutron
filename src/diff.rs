//! `neutron diff <baseline> <test> --by <keys> [--top K]`
//!
//! Aggregates two NDJSON captures with [`crate::summarize`] and emits a
//! sorted table of `Δ count` rows per group key. Supports the negative-
//! evidence workflow from the assessment: "scenario A and scenario B
//! both ran the camera, but only B touched `/dev/lwis-isp-fe` more than
//! 10× — what changed?"
//!
//! Categorisation:
//! - **added** — the group exists only in `<test>`
//! - **removed** — the group exists only in `<baseline>`
//! - **changed** — count differs in the two captures (the row shows
//!   baseline → test count and the delta)
//! - **same** — counts are equal (suppressed by default, `--show-same`
//!   to include)
//!
//! Sort order: |Δ| descending, ties broken on the key tuple. The user
//! sees the loudest behavioural changes at the top of the diff.

use std::collections::BTreeSet;
use std::io::{self, Write};

use anyhow::{Context, Result};

use crate::summarize::{open_capture, parse_by, summarize, Aggregation, KeyField};

/// CLI args for `neutron diff`.
#[derive(clap::Parser, Debug)]
pub struct DiffArgs {
    /// Baseline NDJSON capture path (`-` for stdin).
    pub baseline: String,
    /// Test NDJSON capture path (`-` for stdin). Cannot also be `-` if
    /// baseline is — only one stdin source is allowed.
    pub test: String,

    /// Comma-separated list of group-by fields. Identical vocabulary to
    /// `neutron summarize --by`.
    #[arg(long, value_name = "FIELDS")]
    pub by: String,

    /// Print only the top K rows by absolute delta. `0` (default) prints
    /// all rows.
    #[arg(long, default_value_t = 0)]
    pub top: usize,

    /// Include rows where baseline and test counts are equal. Off by
    /// default — usually the noise hides the signal.
    #[arg(long)]
    pub show_same: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
    Same,
}

impl DiffKind {
    pub fn label(self) -> &'static str {
        match self {
            DiffKind::Added => "added",
            DiffKind::Removed => "removed",
            DiffKind::Changed => "changed",
            DiffKind::Same => "same",
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiffRow {
    pub key: Vec<String>,
    pub baseline: u64,
    pub test: u64,
    pub kind: DiffKind,
}

impl DiffRow {
    pub fn delta(&self) -> i64 {
        self.test as i64 - self.baseline as i64
    }
}

/// Compare two aggregations and produce one row per group present in
/// either side. Memory bound: `O(unique_groups)` across both inputs.
pub fn diff(baseline: &Aggregation, test: &Aggregation) -> Vec<DiffRow> {
    let mut keys: BTreeSet<&Vec<String>> = BTreeSet::new();
    keys.extend(baseline.keys());
    keys.extend(test.keys());
    let mut out: Vec<DiffRow> = Vec::with_capacity(keys.len());
    for k in keys {
        let b = baseline.get(k).map(|a| a.count).unwrap_or(0);
        let t = test.get(k).map(|a| a.count).unwrap_or(0);
        let kind = match (b, t) {
            (0, _) => DiffKind::Added,
            (_, 0) => DiffKind::Removed,
            (a, c) if a == c => DiffKind::Same,
            _ => DiffKind::Changed,
        };
        out.push(DiffRow {
            key: k.clone(),
            baseline: b,
            test: t,
            kind,
        });
    }
    out
}

/// Render the diff rows as a human-readable table. Sorted by
/// `|delta|` descending, then key tuple lexicographically.
pub fn render_table(
    mut rows: Vec<DiffRow>,
    keys: &[KeyField],
    top: usize,
    show_same: bool,
) -> String {
    if !show_same {
        rows.retain(|r| r.kind != DiffKind::Same);
    }
    rows.sort_by(|a, b| {
        b.delta()
            .abs()
            .cmp(&a.delta().abs())
            .then(a.key.cmp(&b.key))
    });
    if top > 0 && rows.len() > top {
        rows.truncate(top);
    }
    if rows.is_empty() {
        return "no differences (all groups have equal counts)\n".to_string();
    }

    // Column widths.
    let kind_w = "kind"
        .len()
        .max(rows.iter().map(|r| r.kind.label().len()).max().unwrap_or(0));
    let baseline_w = "baseline".len().max(
        rows.iter()
            .map(|r| r.baseline.to_string().len())
            .max()
            .unwrap_or(0),
    );
    let test_w = "test".len().max(
        rows.iter()
            .map(|r| r.test.to_string().len())
            .max()
            .unwrap_or(0),
    );
    let delta_w = "delta".len().max(
        rows.iter()
            .map(|r| format_delta(r.delta()).len())
            .max()
            .unwrap_or(0),
    );
    let mut key_widths: Vec<usize> = keys.iter().map(|k| k.label().len()).collect();
    for r in &rows {
        for (i, v) in r.key.iter().enumerate() {
            key_widths[i] = key_widths[i].max(v.len());
        }
    }

    let mut out = String::new();
    let mut header = format!(
        "{:<kw$}  {:>bw$}  {:>tw$}  {:>dw$}",
        "kind",
        "baseline",
        "test",
        "delta",
        kw = kind_w,
        bw = baseline_w,
        tw = test_w,
        dw = delta_w
    );
    for (i, k) in keys.iter().enumerate() {
        header.push_str("  ");
        header.push_str(&format!("{:<w$}", k.label(), w = key_widths[i]));
    }
    out.push_str(&header);
    out.push('\n');
    out.push_str(&"─".repeat(header.chars().count()));
    out.push('\n');

    for r in &rows {
        let mut row = format!(
            "{:<kw$}  {:>bw$}  {:>tw$}  {:>dw$}",
            r.kind.label(),
            r.baseline,
            r.test,
            format_delta(r.delta()),
            kw = kind_w,
            bw = baseline_w,
            tw = test_w,
            dw = delta_w
        );
        for (i, v) in r.key.iter().enumerate() {
            row.push_str("  ");
            row.push_str(&format!("{:<w$}", v, w = key_widths[i]));
        }
        out.push_str(&row);
        out.push('\n');
    }
    out.push('\n');
    let added = rows.iter().filter(|r| r.kind == DiffKind::Added).count();
    let removed = rows.iter().filter(|r| r.kind == DiffKind::Removed).count();
    let changed = rows.iter().filter(|r| r.kind == DiffKind::Changed).count();
    let same = rows.iter().filter(|r| r.kind == DiffKind::Same).count();
    out.push_str(&format!(
        "{} added, {} removed, {} changed{}\n",
        added,
        removed,
        changed,
        if show_same {
            format!(", {same} same")
        } else {
            String::new()
        }
    ));
    out
}

fn format_delta(d: i64) -> String {
    if d >= 0 {
        format!("+{d}")
    } else {
        d.to_string()
    }
}

/// Entry point — invoked from `main.rs` when the user runs
/// `neutron diff <baseline> <test> ...`.
pub fn run(args: DiffArgs) -> Result<()> {
    if args.baseline == "-" && args.test == "-" {
        anyhow::bail!("only one of <baseline>/<test> can be '-' (stdin)");
    }
    let keys = parse_by(&args.by)?;
    let baseline =
        summarize(open_capture(&args.baseline)?, &keys, 0).context("aggregating baseline")?;
    let test = summarize(open_capture(&args.test)?, &keys, 0).context("aggregating test")?;
    let rows = diff(&baseline, &test);
    let table = render_table(rows, &keys, args.top, args.show_same);
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(table.as_bytes())
        .context("writing diff to stdout")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::summarize::{summarize, Aggregation};
    use std::io::Cursor;

    fn agg(input: &str, keys: &[KeyField]) -> Aggregation {
        summarize(Cursor::new(input), keys, 0).unwrap()
    }

    #[test]
    fn classifies_added_removed_changed() {
        let keys = parse_by("syscall").unwrap();
        let base = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"ioctl"}
{"syscall":"openat"}"#,
            &keys,
        );
        let test = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"openat"}
{"syscall":"openat"}
{"syscall":"close"}"#,
            &keys,
        );
        let rows = diff(&base, &test);
        let by_key: std::collections::BTreeMap<String, &DiffRow> =
            rows.iter().map(|r| (r.key[0].clone(), r)).collect();
        assert_eq!(by_key["ioctl"].kind, DiffKind::Changed);
        assert_eq!(by_key["ioctl"].delta(), -1);
        assert_eq!(by_key["openat"].kind, DiffKind::Changed);
        assert_eq!(by_key["openat"].delta(), 1);
        assert_eq!(by_key["close"].kind, DiffKind::Added);
        assert_eq!(by_key["close"].delta(), 1);
    }

    #[test]
    fn classifies_removed_when_only_in_baseline() {
        let keys = parse_by("syscall").unwrap();
        let base = agg(r#"{"syscall":"futex"}"#, &keys);
        let test = agg(r#"{"syscall":"ioctl"}"#, &keys);
        let rows = diff(&base, &test);
        let futex = rows.iter().find(|r| r.key[0] == "futex").unwrap();
        assert_eq!(futex.kind, DiffKind::Removed);
        assert_eq!(futex.delta(), -1);
    }

    #[test]
    fn classifies_same_when_counts_equal() {
        let keys = parse_by("syscall").unwrap();
        let same = r#"{"syscall":"ioctl"}
{"syscall":"ioctl"}"#;
        let base = agg(same, &keys);
        let test = agg(same, &keys);
        let rows = diff(&base, &test);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, DiffKind::Same);
        assert_eq!(rows[0].delta(), 0);
    }

    #[test]
    fn render_default_hides_same_rows() {
        let keys = parse_by("syscall").unwrap();
        let base = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"openat"}"#,
            &keys,
        );
        let test = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"close"}"#,
            &keys,
        );
        let table = render_table(diff(&base, &test), &keys, 0, false);
        assert!(table.contains("close")); // added
        assert!(table.contains("openat")); // removed
                                           // ioctl is unchanged → suppressed under default
        assert!(!table.contains(" ioctl"));
    }

    #[test]
    fn render_show_same_includes_unchanged_rows() {
        let keys = parse_by("syscall").unwrap();
        let base = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"openat"}"#,
            &keys,
        );
        let test = agg(
            r#"{"syscall":"ioctl"}
{"syscall":"close"}"#,
            &keys,
        );
        let table = render_table(diff(&base, &test), &keys, 0, true);
        assert!(table.contains("ioctl"));
    }

    #[test]
    fn render_sort_order_is_abs_delta_desc() {
        let keys = parse_by("syscall").unwrap();
        let base = agg(
            r#"{"syscall":"a"}
{"syscall":"a"}
{"syscall":"b"}
{"syscall":"b"}
{"syscall":"b"}"#,
            &keys,
        );
        let test = agg(
            r#"{"syscall":"a"}
{"syscall":"a"}
{"syscall":"a"}
{"syscall":"a"}
{"syscall":"a"}
{"syscall":"b"}"#,
            &keys,
        );
        // a: 2 → 5 (delta +3); b: 3 → 1 (delta -2). |delta|: a > b.
        let table = render_table(diff(&base, &test), &keys, 0, false);
        let a_pos = table.find(" a ").unwrap();
        let b_pos = table.find(" b ").unwrap();
        assert!(a_pos < b_pos, "a (|+3|) should come before b (|-2|)");
    }

    #[test]
    fn render_top_limits_rows_after_sort() {
        let keys = parse_by("syscall").unwrap();
        let base = agg("{}", &keys);
        let test = agg(
            r#"{"syscall":"a"}
{"syscall":"a"}
{"syscall":"b"}
{"syscall":"c"}"#,
            &keys,
        );
        let table = render_table(diff(&base, &test), &keys, 1, false);
        // Only the top row by delta is in the body.
        assert!(table.contains(" a "));
        assert!(!table.contains(" b "));
    }

    #[test]
    fn empty_diff_when_inputs_identical() {
        let keys = parse_by("syscall").unwrap();
        let same = r#"{"syscall":"ioctl"}"#;
        let base = agg(same, &keys);
        let test = agg(same, &keys);
        let table = render_table(diff(&base, &test), &keys, 0, false);
        assert!(table.contains("no differences"));
    }
}
