//! Wiring between the CLI and the `neutron-rules` engine: build, format, emit.

use crate::cli::Args;
use anyhow::{Context, Result};
use std::io::Write as IoWrite;

/// Build a rule engine from `--rules <file>` if given, otherwise the bundled
/// default ruleset. Returns `Ok(None)` if findings are disabled
/// (`--no-findings`).
pub fn build_rule_engine(args: &Args) -> Result<Option<neutron_rules::RuleEngine>> {
    if args.no_findings {
        return Ok(None);
    }
    let engine = match &args.rules {
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
pub fn emit_findings(findings: &[neutron_rules::Finding], out: &mut dyn IoWrite, use_json: bool) {
    for f in findings {
        if use_json {
            // Tag the line so a mixed stream can be demultiplexed downstream.
            match serde_json::to_value(f) {
                Ok(mut v) => {
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("type".into(), serde_json::Value::String("finding".into()));
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
