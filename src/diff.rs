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
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::capture_normalize::{normalize_capture, validated_scenario_contract, ScenarioContract};
use crate::health::CaptureScope;
use crate::summarize::{parse_by, summarize_scenarios, Aggregation, KeyField};

/// CLI args for `neutron diff`.
#[derive(clap::Parser, Debug)]
pub struct DiffArgs {
    /// Baseline NDJSON capture path. Stable diffs require a seekable file so
    /// capture integrity can be validated before aggregation.
    pub baseline: String,
    /// Test NDJSON capture path. Stable diffs require a seekable file so
    /// capture integrity can be validated before aggregation.
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
    let escaped_keys: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            row.key
                .iter()
                .map(|value| crate::decode::escape_text(value))
                .collect()
        })
        .collect();
    let mut key_widths: Vec<usize> = keys.iter().map(|k| k.label().len()).collect();
    for key in &escaped_keys {
        for (i, v) in key.iter().enumerate() {
            key_widths[i] = key_widths[i].max(v.chars().count());
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

    for (r, escaped_key) in rows.iter().zip(&escaped_keys) {
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
        for (i, v) in escaped_key.iter().enumerate() {
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

fn require_complete_capture<R: BufRead>(
    reader: R,
    label: &str,
) -> Result<(CaptureScope, ScenarioContract)> {
    let capture = normalize_capture(reader)
        .with_context(|| format!("validating {label} capture integrity"))?;
    let Some(health) = capture.health.as_ref() else {
        bail!("{label} capture has no final capture_health record; diff is nonconclusive");
    };
    if health.status != "complete"
        || health.degraded
        || health.output_cap_hit
        || !capture.health_warnings.is_empty()
    {
        let warnings = if capture.health_warnings.is_empty() {
            "none".to_string()
        } else {
            capture
                .health_warnings
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        };
        bail!(
            "{label} capture is not conclusive (status={}, warnings={warnings}); refusing to emit added/removed claims",
            health.status
        );
    }
    let scope = health
        .capture_scope
        .clone()
        .with_context(|| format!("{label} capture lacks a validated effective capture scope"))?;
    if !scope.claim_scope_complete {
        bail!(
            "{label} capture has a restricted effective scope; diff is nonconclusive ({})",
            scope.claim_scope_reasons.join(", ")
        );
    }
    let scenario = validated_scenario_contract(&capture)
        .with_context(|| format!("{label} capture lacks a valid bounded scenario lifecycle"))?;
    Ok((scope, scenario))
}

fn require_matching_scopes(baseline: &CaptureScope, test: &CaptureScope) -> Result<()> {
    if baseline != test {
        bail!(
            "baseline and test effective capture scopes differ; refusing to emit added/removed claims"
        );
    }
    Ok(())
}

fn open_pinned_capture(path: &str, label: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(Path::new(path))
        .with_context(|| format!("opening {label} capture {path}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} capture {path}"))?;
    if !metadata.is_file() {
        bail!("{label} capture must be a regular file: {path}");
    }
    Ok(file)
}

fn validate_and_rewind(file: &mut File, label: &str) -> Result<(CaptureScope, ScenarioContract)> {
    let contract = require_complete_capture(BufReader::new(&mut *file), label)?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("rewinding pinned {label} capture"))?;
    Ok(contract)
}

fn require_distinct_files(baseline: &File, test: &File) -> Result<()> {
    let baseline = baseline
        .metadata()
        .context("inspecting baseline identity")?;
    let test = test.metadata().context("inspecting test identity")?;
    if baseline.dev() == test.dev() && baseline.ino() == test.ino() {
        bail!("baseline and test refer to the same capture file; refusing a self-comparison");
    }
    Ok(())
}

/// Entry point — invoked from `main.rs` when the user runs
/// `neutron diff <baseline> <test> ...`.
pub fn run(args: DiffArgs) -> Result<()> {
    if args.baseline == "-" || args.test == "-" {
        bail!(
            "stable diff requires file paths for both captures so health can be validated before aggregation"
        );
    }
    let keys = parse_by(&args.by)?;
    let mut baseline_file = open_pinned_capture(&args.baseline, "baseline")?;
    let mut test_file = open_pinned_capture(&args.test, "test")?;
    require_distinct_files(&baseline_file, &test_file)?;
    let (baseline_scope, baseline_scenario) = validate_and_rewind(&mut baseline_file, "baseline")?;
    let (test_scope, test_scenario) = validate_and_rewind(&mut test_file, "test")?;
    require_matching_scopes(&baseline_scope, &test_scope)?;
    if baseline_scenario.scenarios != test_scenario.scenarios {
        bail!(
            "baseline and test bounded scenario contracts differ; refusing to emit added/removed claims"
        );
    }
    let baseline = summarize_scenarios(
        BufReader::new(baseline_file),
        &keys,
        0,
        &baseline_scenario.trace_ids,
    )
    .context("aggregating pinned baseline")?;
    let test = summarize_scenarios(
        BufReader::new(test_file),
        &keys,
        0,
        &test_scenario.trace_ids,
    )
    .context("aggregating pinned test")?;
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
    use crate::health::{
        format_capture_health_json_with_metadata, CaptureHealth, CaptureMetadata, UserspaceHealth,
    };
    use crate::summarize::{summarize, Aggregation};
    use std::io::Cursor;

    fn agg(input: &str, keys: &[KeyField]) -> Aggregation {
        summarize(Cursor::new(input), keys, 0).unwrap()
    }

    fn complete_health() -> String {
        let mut health = CaptureHealth::default();
        health.slots[neutron_common::COUNTER_EVENTS_SUBMITTED as usize] = 1;
        let capture_scope = CaptureScope::unfiltered_raw_ndjson();
        format_capture_health_json_with_metadata(
            &health,
            &UserspaceHealth::default(),
            1,
            &CaptureMetadata {
                attached_programs: vec![
                    "trace_sys_enter".into(),
                    "trace_sys_exit".into(),
                    "trace_sched_process_exit".into(),
                ],
                max_depth: capture_scope.instrumentation.max_depth,
                max_processes: capture_scope.instrumentation.max_processes,
                boot_id: Some("11111111-2222-3333-4444-555555555555".into()),
                bpf_object_sha256: Some("1".repeat(64)),
                bpf_build_id: Some("2".repeat(40)),
                bpf_abi_major: Some(neutron_common::BPF_ABI_MAJOR),
                bpf_abi_minor: Some(neutron_common::BPF_ABI_MINOR),
                bpf_event_size: Some(core::mem::size_of::<neutron_common::SyscallEvent>() as u32),
                bpf_feature_bits: Some(
                    neutron_common::BPF_FEATURE_SYSCALL_TRACE
                        | neutron_common::BPF_FEATURE_PROCESS_EXIT
                        | neutron_common::BPF_FEATURE_PER_CPU_HEALTH,
                ),
                ring_size_bytes: Some(1 << 20),
                capture_scope: Some(capture_scope),
                ..CaptureMetadata::default()
            },
        )
    }

    fn bounded_complete_capture(event: &str) -> String {
        format!(
            "{}\n{}\n{}\n{}\n",
            r#"{"type":"marker","ts_ns":1,"name":"procedure","phase":"start","scenario_id":"procedure","trace_id":"trace-a","root_pid":1}"#,
            event,
            r#"{"type":"marker","ts_ns":3,"name":"procedure","phase":"end","scenario_id":"procedure","trace_id":"trace-a","root_pid":1}"#,
            complete_health(),
        )
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

    #[test]
    fn integrity_gate_requires_one_final_complete_health_record() {
        let missing = require_complete_capture(
            Cursor::new(r#"{"type":"syscall","pid":1,"name":"ioctl"}"#),
            "baseline",
        )
        .unwrap_err();
        assert!(format!("{missing:#}").contains("no final capture_health"));

        let complete = bounded_complete_capture(
            r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
        );
        require_complete_capture(Cursor::new(complete), "baseline").unwrap();
    }

    #[test]
    fn integrity_gate_rejects_unmarked_and_unfinished_scenarios() {
        let unmarked = format!(
            "{}\n{}\n",
            r#"{"type":"syscall","pid":1,"name":"ioctl"}"#,
            complete_health()
        );
        assert!(format!(
            "{:#}",
            require_complete_capture(Cursor::new(unmarked), "test").unwrap_err()
        )
        .contains("no paired scenario"));

        let unfinished = format!(
            "{}\n{}\n{}\n",
            r#"{"type":"marker","ts_ns":1,"name":"procedure","phase":"start","scenario_id":"procedure","trace_id":"trace-a","root_pid":1}"#,
            r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
            complete_health(),
        );
        assert!(format!(
            "{:#}",
            require_complete_capture(Cursor::new(unfinished), "test").unwrap_err()
        )
        .contains("no matching end"));
    }

    #[test]
    fn scenario_aggregation_ignores_events_outside_the_completed_boundary() {
        let capture = bounded_complete_capture(
            r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
        );
        let capture = format!(
            "{}\n{}",
            r#"{"type":"syscall","pid":1,"name":"outside"}"#, capture
        );
        let normalized = normalize_capture(Cursor::new(capture.as_bytes())).unwrap();
        let contract = validated_scenario_contract(&normalized).unwrap();
        let keys = parse_by("syscall").unwrap();
        let aggregation =
            summarize_scenarios(Cursor::new(capture), &keys, 0, &contract.trace_ids).unwrap();
        assert!(aggregation.contains_key(&vec!["ioctl".into()]));
        assert!(!aggregation.contains_key(&vec!["outside".into()]));
    }

    #[test]
    fn different_scenario_names_are_not_comparable() {
        let baseline = require_complete_capture(
            Cursor::new(bounded_complete_capture(
                r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
            )),
            "baseline",
        )
        .unwrap();
        let test_raw = bounded_complete_capture(
            r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
        )
        .replace("procedure", "different");
        let test = require_complete_capture(Cursor::new(test_raw), "test").unwrap();
        assert_ne!(baseline.1.scenarios, test.1.scenarios);
    }

    #[test]
    fn diff_requires_identical_effective_scopes() {
        let baseline = CaptureScope::unfiltered_raw_ndjson();
        let mut test = baseline.clone();
        test.observation.target_pid = 42;

        let error = require_matching_scopes(&baseline, &test).unwrap_err();
        assert!(format!("{error:#}").contains("effective capture scopes differ"));
    }

    #[test]
    fn validation_and_aggregation_use_the_same_pinned_file() {
        let directory = std::env::temp_dir().join(format!(
            "neutron-diff-pinned-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("capture.ndjson");
        let original = bounded_complete_capture(
            r#"{"type":"syscall","pid":1,"name":"ioctl","scenario_id":"procedure","trace_id":"trace-a"}"#,
        );
        std::fs::write(&path, original).unwrap();

        let mut pinned = open_pinned_capture(path.to_str().unwrap(), "baseline").unwrap();
        std::fs::rename(&path, directory.join("original.ndjson")).unwrap();
        std::fs::write(&path, r#"{"type":"syscall","pid":1,"name":"socket"}"#).unwrap();

        validate_and_rewind(&mut pinned, "baseline").unwrap();
        let keys = parse_by("syscall").unwrap();
        let aggregation = summarize(BufReader::new(pinned), &keys, 0).unwrap();
        assert!(aggregation.contains_key(&vec!["ioctl".into()]));
        assert!(!aggregation.contains_key(&vec!["socket".into()]));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hard_linked_inputs_are_rejected_as_self_comparison() {
        let directory = std::env::temp_dir().join(format!(
            "neutron-diff-hardlink-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir(&directory).unwrap();
        let baseline_path = directory.join("baseline.ndjson");
        let test_path = directory.join("test.ndjson");
        std::fs::write(&baseline_path, b"capture").unwrap();
        std::fs::hard_link(&baseline_path, &test_path).unwrap();
        let baseline = open_pinned_capture(baseline_path.to_str().unwrap(), "baseline").unwrap();
        let test = open_pinned_capture(test_path.to_str().unwrap(), "test").unwrap();

        let error = require_distinct_files(&baseline, &test).unwrap_err();
        assert!(format!("{error:#}").contains("same capture file"));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn render_escapes_untrusted_group_values() {
        let keys = parse_by("comm").unwrap();
        let base = agg(r#"{"comm":"safe"}"#, &keys);
        let test = agg("{\"comm\":\"bad\\u001b[2J\\nrow\"}", &keys);
        let table = render_table(diff(&base, &test), &keys, 0, false);

        assert!(!table.contains('\u{1b}'));
        assert!(!table.contains("\nrow"));
        assert!(table.contains("\\u{1b}[2J\\nrow"));
    }
}
