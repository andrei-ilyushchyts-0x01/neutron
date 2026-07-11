//! `neutron mark <name> [--phase start|end] [--meta k=v]`
//!
//! A phased marker uses the live tracer's control socket by default. The
//! tracer validates lifecycle, assigns causal IDs and a monotonic timestamp,
//! then writes the marker into its own NDJSON stream:
//!
//! ```sh
//! neutron trace --package com.example --output trace.ndjson &
//! neutron mark scenario --phase start
//! ./trigger-camera-extension-night                  # stimulus
//! neutron mark scenario --phase end
//! kill %1
//! ```
//!
//! Explicit `--output` retains the 1.2 append-only path and does not switch a
//! live scenario. Downstream `neutron window` still anchors on marker names.
//!
//! Concurrency: when `--output <file>` is given, the line is appended
//! with `O_APPEND` semantics. On Linux a write of `<= PIPE_BUF` (4096
//! bytes) is atomic, so two concurrent writers never interleave.
//! Marker lines are well below that limit. Without `--output`, the
//! line goes to stdout — the caller is responsible for redirection.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// CLI args for `neutron mark`.
#[derive(clap::Parser, Debug)]
pub struct MarkArgs {
    /// Scenario or stage name. Free-form; recommended to keep it short
    /// and a stable identifier (`camera_night`, `gxp_warmup`).
    pub name: String,

    /// Phase indicator. Accepts `start`, `end`, or omitted (a one-shot
    /// marker without a paired counterpart).
    #[arg(long, value_name = "PHASE")]
    pub phase: Option<String>,

    /// Optional `key=value` metadata, repeatable. Values are stored as
    /// strings — they're operator-controlled and we don't try to be
    /// clever about types.
    #[arg(long, value_name = "K=V")]
    pub meta: Vec<String>,

    /// Append the line to this file instead of stdout. Created if it
    /// doesn't exist, opened with `O_APPEND` so concurrent writers
    /// don't interleave on Linux.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,

    /// Live tracer control socket. Used first unless --output requests the
    /// legacy append-only path. Use `off` to skip live control.
    #[arg(
        long,
        default_value = "/data/local/tmp/neutron.control.sock",
        value_name = "PATH|off"
    )]
    pub control_socket: String,

    /// Override the wall-clock timestamp (nanoseconds since
    /// epoch). Tests use this; operators rarely need it.
    #[arg(long, value_name = "TS_NS")]
    pub ts_ns: Option<u64>,
}

/// Validate the phase string. Allowed: `start`, `end`, or `None`.
fn normalize_phase(p: Option<&str>) -> Result<Option<&'static str>> {
    let Some(raw) = p else { return Ok(None) };
    match raw.trim().to_ascii_lowercase().as_str() {
        "start" | "begin" => Ok(Some("start")),
        "end" | "stop" | "finish" => Ok(Some("end")),
        "" => Ok(None),
        other => bail!("invalid --phase '{other}' (expected start|end)"),
    }
}

/// Render the marker NDJSON line. Public for unit tests; the entry
/// point [`run`] writes it.
pub fn render_line(args: &MarkArgs) -> Result<String> {
    if args.name.trim().is_empty() {
        bail!("marker name must be non-empty");
    }
    let phase = normalize_phase(args.phase.as_deref())?;

    let ts_ns = match args.ts_ns {
        Some(v) => v,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX_EPOCH")?
            .as_nanos() as u64,
    };

    // JSON-escape the name so quotes/backslashes round-trip.
    let escaped_name = args.name.replace('\\', "\\\\").replace('"', "\\\"");

    let phase_field = match phase {
        Some(p) => format!(r#","phase":"{p}""#),
        None => String::new(),
    };

    let meta_field = if args.meta.is_empty() {
        String::new()
    } else {
        let mut parts: Vec<String> = Vec::with_capacity(args.meta.len());
        for kv in &args.meta {
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--meta entry '{kv}' missing '=' separator"))?;
            let k_esc = k.trim().replace('\\', "\\\\").replace('"', "\\\"");
            let v_esc = v.replace('\\', "\\\\").replace('"', "\\\"");
            if k_esc.is_empty() {
                bail!("--meta entry '{kv}' has empty key");
            }
            parts.push(format!(r#""{k_esc}":"{v_esc}""#));
        }
        format!(r#","meta":{{{}}}"#, parts.join(","))
    };

    Ok(format!(
        r#"{{"type":"marker","ts_ns":{ts_ns},"name":"{escaped_name}"{phase_field}{meta_field}}}"#,
    ))
}

/// Entry point — invoked from `main.rs` when the user runs
/// `neutron mark <name> ...`.
pub fn run(args: MarkArgs) -> Result<()> {
    if args.output.is_none()
        && args.phase.is_some()
        && args.control_socket != "off"
        && Path::new(&args.control_socket).exists()
    {
        let phase = normalize_phase(args.phase.as_deref())?.context("marker phase required")?;
        let mut meta = std::collections::BTreeMap::new();
        for kv in &args.meta {
            let (key, value) = kv
                .split_once('=')
                .with_context(|| format!("--meta entry '{kv}' missing '=' separator"))?;
            if key.trim().is_empty() {
                bail!("--meta entry '{kv}' has empty key");
            }
            meta.insert(key.trim().to_string(), value.to_string());
        }
        crate::causal::send_mark_request(
            &args.control_socket,
            &crate::causal::MarkRequest {
                name: args.name.clone(),
                phase: phase.to_string(),
                meta,
            },
        )?;
        return Ok(());
    }
    let line = render_line(&args)?;
    match &args.output {
        Some(path) => {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("opening {path} for append"))?;
            writeln!(f, "{line}").with_context(|| format!("writing marker to {path}"))?;
        }
        None => {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{line}").context("writing marker to stdout")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn args(name: &str) -> MarkArgs {
        MarkArgs {
            name: name.into(),
            phase: None,
            meta: vec![],
            output: None,
            control_socket: "off".into(),
            ts_ns: Some(1_234_567),
        }
    }

    #[test]
    fn renders_minimal_marker() {
        let line = render_line(&args("camera_night")).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["type"], "marker");
        assert_eq!(v["name"], "camera_night");
        assert_eq!(v["ts_ns"], 1_234_567u64);
        assert!(v.get("phase").is_none());
        assert!(v.get("meta").is_none());
    }

    #[test]
    fn renders_phase_when_set() {
        let mut a = args("scenario");
        a.phase = Some("start".into());
        let v: Value = serde_json::from_str(&render_line(&a).unwrap()).unwrap();
        assert_eq!(v["phase"], "start");

        let mut b = args("scenario");
        b.phase = Some("END".into());
        let v: Value = serde_json::from_str(&render_line(&b).unwrap()).unwrap();
        assert_eq!(v["phase"], "end");
    }

    #[test]
    fn rejects_invalid_phase() {
        let mut a = args("scenario");
        a.phase = Some("garbage".into());
        let err = render_line(&a).unwrap_err();
        assert!(format!("{err:#}").contains("invalid --phase"));
    }

    #[test]
    fn phased_marker_requires_a_live_control_socket() {
        let mut a = args("scenario");
        a.phase = Some("start".into());
        a.control_socket = std::env::temp_dir()
            .join(format!("neutron-missing-control-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned();

        let error = run(a).expect_err("a phased live marker must not fall back to stdout");
        assert!(format!("{error:#}").contains("control socket"));
    }

    #[test]
    fn meta_renders_as_nested_object() {
        let mut a = args("camera");
        a.meta = vec!["build=1".into(), "device=oriole".into()];
        let v: Value = serde_json::from_str(&render_line(&a).unwrap()).unwrap();
        let m = v["meta"].as_object().unwrap();
        assert_eq!(m["build"], "1");
        assert_eq!(m["device"], "oriole");
    }

    #[test]
    fn meta_rejects_missing_equals() {
        let mut a = args("camera");
        a.meta = vec!["broken_no_equals".into()];
        let err = render_line(&a).unwrap_err();
        assert!(format!("{err:#}").contains("missing '=' separator"));
    }

    #[test]
    fn meta_rejects_empty_key() {
        let mut a = args("camera");
        a.meta = vec!["=value".into()];
        let err = render_line(&a).unwrap_err();
        assert!(format!("{err:#}").contains("empty key"));
    }

    #[test]
    fn empty_name_rejected() {
        let a = args("   ");
        let err = render_line(&a).unwrap_err();
        assert!(format!("{err:#}").contains("non-empty"));
    }

    #[test]
    fn name_quotes_and_backslashes_are_escaped() {
        let a = args(r#"weird"name\with"#);
        let line = render_line(&a).unwrap();
        let v: Value = serde_json::from_str(&line).expect("must round-trip");
        assert_eq!(v["name"], r#"weird"name\with"#);
    }

    #[test]
    fn run_writes_to_output_file() {
        use std::io::Read;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("neutron-mark-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut a = args("camera");
        a.phase = Some("start".into());
        a.output = Some(path.to_string_lossy().into_owned());
        run(a).expect("write to file");

        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let line = content.trim_end_matches('\n');
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["type"], "marker");
        assert_eq!(v["phase"], "start");

        // Append again; second invocation must not clobber the first.
        let mut b = args("camera");
        b.phase = Some("end".into());
        b.output = Some(path.to_string_lossy().into_owned());
        run(b).expect("append");
        let mut content = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "second run appended, did not truncate");
        let _ = std::fs::remove_file(&path);
    }
}
