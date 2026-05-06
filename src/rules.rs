//! Wiring between the CLI and the `neutron-rules` engine: build, format, emit.

use std::collections::BTreeMap;
use std::io::Write as IoWrite;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::cli::Args;
use crate::fdinfo::{self, FdInfo};

/// Build a rule engine from `--rules <file>` if given, otherwise the bundled
/// default ruleset. Returns `Ok(None)` if findings are disabled
/// (`--no-findings`).
pub fn build_rule_engine(args: &Args) -> Result<Option<neutron_rules::RuleEngine>> {
    if args.no_findings {
        return Ok(None);
    }
    let mut engine = match &args.rules {
        Some(path) => {
            let rules = neutron_rules::load_rules_yaml_file(path)
                .with_context(|| format!("loading rules from {path}"))?;
            eprintln!("  loaded {} custom rules from {path}", rules.len());
            neutron_rules::RuleEngine::new(rules)?
        }
        None => {
            let engine = neutron_rules::RuleEngine::with_default_rules()
                .context("loading bundled default rules")?;
            eprintln!("  loaded {} default rules", engine.rule_count());
            engine
        }
    };
    engine.set_raw_window_cap(args.finding_raw_window);
    Ok(Some(engine))
}

/// Format a finding for human-readable text output.
pub fn format_finding_text(f: &neutron_rules::Finding) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(256);
    let span_ms = (f.last_seen_ns.saturating_sub(f.first_seen_ns)) as f64 / 1_000_000.0;
    let _ = writeln!(
        s,
        "[FINDING] {} {} {}",
        f.rule_id,
        format!("{:?}", f.category).to_lowercase(),
        f.severity.as_str().to_uppercase()
    );
    let _ = writeln!(s, "  rule:    {}", f.rule_name);
    let _ = writeln!(s, "  process: {} (pid {})", f.comm, f.pid);
    if let Some(period) = f.period_ms {
        let _ = writeln!(
            s,
            "  events:  {} over {:.1}ms, period {:.3}ms",
            f.event_count, span_ms, period
        );
    } else {
        let _ = writeln!(s, "  events:  {} over {:.1}ms", f.event_count, span_ms);
    }
    if let Some(t) = &f.target {
        let _ = writeln!(s, "  target:  {}", t);
    }
    if !f.evidence.is_empty() {
        let _ = writeln!(s, "  evidence:");
        for e in &f.evidence {
            let data = e.data.as_deref().unwrap_or("");
            let arrow = if e.is_enter { "->" } else { "<-" };
            let _ = writeln!(
                s,
                "    [{}] {} {}({}) ret={}",
                e.ts_ns, arrow, e.name, data, e.ret
            );
        }
    }
    s
}

/// Emit findings drained from the engine. Format depends on `use_json`.
/// Equivalent to [`emit_findings_with`] with `fd_snapshot=false`.
pub fn emit_findings(findings: &[neutron_rules::Finding], out: &mut dyn IoWrite, use_json: bool) {
    emit_findings_with(findings, out, use_json, false);
}

/// Same as [`emit_findings`], but optionally splices a Phase 4a
/// `fdinfo_at_event` enrichment map into each finding's JSON form. The
/// extra read happens once per emit, not per evidence event, so the
/// hot path stays bounded.
pub fn emit_findings_with(
    findings: &[neutron_rules::Finding],
    out: &mut dyn IoWrite,
    use_json: bool,
    fd_snapshot: bool,
) {
    for f in findings {
        if use_json {
            match serde_json::to_value(f) {
                Ok(mut v) => {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("type".into(), Value::String("finding".into()));
                        if fd_snapshot {
                            if let Some(map) = build_fdinfo_map(f) {
                                obj.insert(
                                    "fdinfo_at_event".into(),
                                    serde_json::to_value(map).unwrap_or(Value::Null),
                                );
                            }
                        }
                    }
                    let _ = writeln!(out, "{}", v);
                }
                Err(_) => continue,
            }
        } else {
            let _ = writeln!(out, "{}", format_finding_text(f));
        }
    }
}

/// Walk a finding's evidence and pull a synchronous fdinfo snapshot for
/// every ioctl event. Keyed by fd as a string so the JSON object is
/// stable. Returns `None` when no ioctl evidence yielded a usable fd —
/// the caller suppresses an empty `fdinfo_at_event` field rather than
/// emitting a noisy `{}`.
fn build_fdinfo_map(f: &neutron_rules::Finding) -> Option<BTreeMap<String, FdInfo>> {
    let mut out: BTreeMap<String, FdInfo> = BTreeMap::new();
    for ev in &f.evidence {
        // Only ioctl evidence has a meaningful fd in args[0]. Other
        // syscalls store paths or sockaddrs there.
        if ev.name != "ioctl" {
            continue;
        }
        let raw = match ev.raw.as_ref() {
            Some(r) => r,
            None => continue,
        };
        let pid = raw
            .get("pid")
            .and_then(Value::as_u64)
            .map(|n| n as u32)
            .unwrap_or(f.pid);
        let fd = match raw.get("args").and_then(Value::as_array) {
            Some(arr) => arr.first().and_then(Value::as_i64),
            None => None,
        };
        let fd = match fd {
            Some(v) => v,
            None => continue,
        };
        if let Some(info) = fdinfo::read(pid, fd) {
            out.insert(fd.to_string(), info);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_rules::finding::{Aggregates, CaptureHealthSnapshot, EventSnapshot, Finding};
    use neutron_rules::rule::{Category, Severity};
    use serde_json::json;

    fn make_finding(evidence: Vec<EventSnapshot>) -> Finding {
        Finding {
            rule_id: "T1_test".into(),
            rule_name: "test".into(),
            severity: Severity::Low,
            category: Category::Antitamper,
            pid: 1,
            comm: "test".into(),
            first_seen_ns: 0,
            last_seen_ns: 0,
            event_count: evidence.len() as u32,
            period_ms: None,
            target: None,
            evidence,
            references: vec![],
            behavior: None,
            interpretation: vec![],
            confidence: None,
            false_positives: vec![],
            evidence_quality: None,
            capture_health: CaptureHealthSnapshot::default(),
            aggregates: Aggregates::default(),
            raw_window: vec![],
        }
    }

    #[test]
    fn build_fdinfo_map_skips_non_ioctl_evidence() {
        let f = make_finding(vec![EventSnapshot {
            ts_ns: 0,
            name: "openat".into(),
            is_enter: false,
            ret: 3,
            data: Some("/dev/null".into()),
            raw: Some(json!({"pid": 1, "args": [0, 0, 0]})),
        }]);
        // No ioctl in evidence → no fdinfo lookup attempted, returns None.
        assert!(build_fdinfo_map(&f).is_none());
    }

    #[test]
    fn build_fdinfo_map_returns_none_for_missing_pid_fd() {
        // pid=999999 almost certainly doesn't exist; the read should fail
        // and the function returns None instead of an empty map.
        let f = make_finding(vec![EventSnapshot {
            ts_ns: 0,
            name: "ioctl".into(),
            is_enter: false,
            ret: 0,
            data: None,
            raw: Some(json!({"pid": 999_999u64, "args": [42, 0, 0]})),
        }]);
        assert!(build_fdinfo_map(&f).is_none());
    }

    #[test]
    fn build_fdinfo_map_returns_some_for_self_open_fd() {
        // Use a real fd of the test process. Reading our own fdinfo is
        // always permitted on Linux.
        #[cfg(target_os = "linux")]
        {
            use std::fs::File;
            use std::os::fd::AsRawFd;
            let f_handle = File::open("/proc/self/cmdline").expect("open");
            let pid = std::process::id() as u64;
            let fd = f_handle.as_raw_fd() as i64;
            let f = make_finding(vec![EventSnapshot {
                ts_ns: 0,
                name: "ioctl".into(),
                is_enter: false,
                ret: 0,
                data: None,
                raw: Some(json!({"pid": pid, "args": [fd, 0, 0]})),
            }]);
            let map = build_fdinfo_map(&f).expect("map populated");
            assert!(map.contains_key(&fd.to_string()));
        }
    }

    #[test]
    fn emit_findings_with_splices_fdinfo_when_enabled() {
        #[cfg(target_os = "linux")]
        {
            use std::fs::File;
            use std::os::fd::AsRawFd;
            let f_handle = File::open("/proc/self/cmdline").expect("open");
            let pid = std::process::id() as u64;
            let fd = f_handle.as_raw_fd() as i64;
            let f = make_finding(vec![EventSnapshot {
                ts_ns: 0,
                name: "ioctl".into(),
                is_enter: false,
                ret: 0,
                data: None,
                raw: Some(json!({"pid": pid, "args": [fd, 0, 0]})),
            }]);
            let mut buf = Vec::new();
            emit_findings_with(&[f], &mut buf, true, true);
            let s = String::from_utf8(buf).unwrap();
            assert!(
                s.contains("fdinfo_at_event"),
                "expected fdinfo_at_event in output: {s}"
            );
        }
    }

    #[test]
    fn emit_findings_with_omits_fdinfo_when_disabled() {
        let f = make_finding(vec![EventSnapshot {
            ts_ns: 0,
            name: "ioctl".into(),
            is_enter: false,
            ret: 0,
            data: None,
            raw: Some(json!({"pid": 1, "args": [3, 0, 0]})),
        }]);
        let mut buf = Vec::new();
        emit_findings_with(&[f], &mut buf, true, false);
        let s = String::from_utf8(buf).unwrap();
        assert!(
            !s.contains("fdinfo_at_event"),
            "fd_snapshot=false must NOT splice the field"
        );
    }
}
