//! Build orchestration for neutron.
//!
//! Usage:
//!   cargo xtask build-ebpf          # debug build
//!   cargo xtask build-ebpf release  # release build
//!   cargo xtask build               # build everything (ebpf + userspace aarch64-musl)
//!   cargo xtask deploy              # build + adb push to device
//!   cargo xtask demo                # build + push demo target; print run instructions
//!   cargo xtask demo-hal            # host-only ioctl decoder fixture; prints
//!                                   # synthetic NDJSON and diffs it against
//!                                   # examples/expected/dma-heap.ndjson
//!   cargo xtask demo-window         # runs `neutron window` against
//!                                   # examples/expected/window-capture.ndjson
//!                                   # and diffs against window-output.ndjson
//!   cargo xtask check-findings <file>
//!                                   # diff a captured NDJSON trace against
//!                                   # examples/expected/findings.txt

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const EBPF_OBJ_NAME: &str = "neutron.bpf.elf";
const DEMO_BIN: &str = "demo-target";

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build-ebpf") => {
            let release = args.next().as_deref() == Some("release");
            build_ebpf(release)
        }
        Some("build") => {
            build_ebpf(true)?;
            build_userspace()
        }
        Some("deploy") => {
            build_ebpf(true)?;
            build_userspace()?;
            deploy()
        }
        Some("demo") => demo(),
        Some("demo-hal") => demo_hal(),
        Some("demo-window") => demo_window(),
        Some("check-findings") => {
            let path = args
                .next()
                .context("usage: cargo xtask check-findings <ndjson_file>")?;
            check_findings(&path)
        }
        Some("bench") => {
            // Optional duration argument; defaults to 30 seconds per profile.
            let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(30);
            bench(secs)
        }
        Some("bench-parse") => {
            // Reads a previously-captured `neutron` stderr from stdin and
            // emits a single Markdown table row.
            let profile = args
                .next()
                .context("usage: cargo xtask bench-parse <profile_name>")?;
            let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(30);
            bench_parse_stdin(&profile, secs)
        }
        Some(cmd) => bail!("unknown command: {cmd}"),
        None => {
            println!(
                "Usage: cargo xtask <build-ebpf [release] | build | deploy \
                | demo | demo-hal | check-findings <file>>"
            );
            Ok(())
        }
    }
}

fn workspace_root() -> PathBuf {
    // xtask is a workspace member — its manifest dir is workspace_root/xtask/
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn command_ok(program: &str, args: &[&str]) -> std::result::Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program} {}: {e}", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    Err(format!(
        "{program} {} exited with {}{}",
        args.join(" "),
        output.status,
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    ))
}

fn format_ebpf_preflight_error(
    cargo_nightly: std::result::Result<(), String>,
    bpf_linker: std::result::Result<(), String>,
) -> Option<String> {
    let mut lines = Vec::new();
    if let Err(detail) = cargo_nightly {
        lines.push(format!(
            "- cargo +nightly is unavailable or unusable ({detail}). \
             Install it with: rustup toolchain install nightly"
        ));
    }
    if let Err(detail) = bpf_linker {
        lines.push(format!(
            "- bpf-linker is unavailable ({detail}). Install it with: \
             cargo install bpf-linker"
        ));
    }
    if lines.is_empty() {
        None
    } else {
        Some(format!(
            "BPF build preflight failed:\n{}\n\n\
             neutron builds eBPF with `cargo +nightly -Z build-std=core` \
             for target bpfel-unknown-none.",
            lines.join("\n")
        ))
    }
}

fn preflight_ebpf_build() -> Result<()> {
    let cargo_nightly = command_ok("cargo", &["+nightly", "--version"]);
    let bpf_linker = command_ok("bpf-linker", &["--version"]);
    if let Some(msg) = format_ebpf_preflight_error(cargo_nightly, bpf_linker) {
        bail!("{msg}");
    }
    Ok(())
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("neutron-ebpf");

    println!(
        "=== Building BPF programs ({}) ===",
        if release { "release" } else { "debug" }
    );
    preflight_ebpf_build()?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .args(["+nightly", "build"])
        .args(["-Z", "build-std=core"])
        .args(["--target", "bpfel-unknown-none"])
        // Fat LTO + a single codegen unit produce a smaller BPF object and
        // shorter verifier paths. On kernel 6.1+ this is purely an
        // optimisation — BPF-to-BPF calls are accepted, so it's no longer
        // load-bearing. Set via env so the userspace build (separate cargo
        // invocation) stays on its default thin LTO.
        .env("CARGO_PROFILE_RELEASE_LTO", "fat")
        .env("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", "1")
        .env("CARGO_PROFILE_DEV_LTO", "fat")
        .env("CARGO_PROFILE_DEV_CODEGEN_UNITS", "1");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("cargo build for BPF failed")?;
    if !status.success() {
        bail!("BPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let obj = root
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("neutron-ebpf");

    println!("  BPF object: {}", obj.display());

    let dest = root.join(EBPF_OBJ_NAME);
    std::fs::copy(&obj, &dest)
        .with_context(|| format!("copy {} -> {}", obj.display(), dest.display()))?;
    println!("  Copied to: {}", dest.display());

    Ok(())
}

fn build_userspace() -> Result<()> {
    let root = workspace_root();
    println!("=== Building userspace (aarch64-unknown-linux-musl) ===");

    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--target",
            "aarch64-unknown-linux-musl",
        ])
        .status()
        .context("cargo build for userspace failed")?;

    if !status.success() {
        bail!("userspace build failed");
    }

    println!("  Binary: target/aarch64-unknown-linux-musl/release/neutron");
    Ok(())
}

fn build_demo_target() -> Result<PathBuf> {
    let root = workspace_root();
    println!("=== Building demo-target (aarch64-unknown-linux-musl) ===");

    let status = Command::new("cargo")
        .current_dir(&root)
        .args([
            "build",
            "--release",
            "--example",
            DEMO_BIN,
            "--target",
            "aarch64-unknown-linux-musl",
        ])
        .status()
        .context("cargo build for demo-target failed")?;
    if !status.success() {
        bail!("demo-target build failed");
    }

    let path = root
        .join("target/aarch64-unknown-linux-musl/release/examples")
        .join(DEMO_BIN);
    if !path.exists() {
        bail!("demo-target binary not found at {}", path.display());
    }
    println!("  Binary: {}", path.display());
    Ok(path)
}

fn demo() -> Result<()> {
    let root = workspace_root();

    // Always build the BPF object + userspace binary so the device has a
    // matching neutron and BPF ELF.
    build_ebpf(true)?;
    build_userspace()?;
    let demo_bin = build_demo_target()?;

    println!("\n=== Pushing demo-target to /data/local/tmp ===");
    let state = Command::new("adb")
        .args(["get-state"])
        .output()
        .context("adb not found")?;
    if !state.status.success() {
        bail!("no adb device connected — connect a Pixel and re-run");
    }

    // Push everything together.
    for (src, dst) in &[
        (root.join(EBPF_OBJ_NAME), "/data/local/tmp/neutron.bpf.elf"),
        (
            root.join("target/aarch64-unknown-linux-musl/release/neutron"),
            "/data/local/tmp/neutron",
        ),
        (demo_bin.clone(), "/data/local/tmp/demo-target"),
    ] {
        println!("  push {} -> {}", src.display(), dst);
        let status = Command::new("adb")
            .args(["push", src.to_str().unwrap(), dst])
            .status()
            .context("adb push failed")?;
        if !status.success() {
            bail!("adb push failed for {}", src.display());
        }
    }
    let _ = Command::new("adb")
        .args([
            "shell",
            "chmod",
            "+x",
            "/data/local/tmp/neutron",
            "/data/local/tmp/demo-target",
        ])
        .status();

    println!("\n=== How to run on-device ===");
    println!("Two terminals:");
    println!();
    println!("  # Terminal A — start neutron in the background, capture JSON.");
    println!("  adb shell su -c '/data/local/tmp/neutron --pid 0 --json' \\");
    println!("      > demo-trace.ndjson");
    println!();
    println!("  # Terminal B — once neutron is attached, run the demo.");
    println!("  adb shell '/data/local/tmp/demo-target'");
    println!();
    println!("  # Stop neutron with Ctrl-C; verify findings:");
    println!("  cargo xtask check-findings demo-trace.ndjson");
    println!();
    println!("Expected rule IDs: see examples/expected/findings.txt");
    Ok(())
}

/// Run the host-only `demo-hal` example, capture its NDJSON output, and diff
/// it against `examples/expected/dma-heap.ndjson`. Sprint-1 PR 2 fixture.
///
/// This validates ioctl decoder semantics (DMA_HEAP_IOCTL_ALLOC field
/// extraction, `b` magic disambiguation by FD-graph kind, defensive handling
/// of zero-payload captures) without needing a Pixel device. On a mismatch
/// it prints both blocks and exits non-zero so CI catches schema drift.
fn demo_hal() -> Result<()> {
    let root = workspace_root();
    println!("=== running examples/demo-hal.rs ===");
    let out = Command::new("cargo")
        .current_dir(&root)
        .args(["run", "--quiet", "--example", "demo-hal"])
        .output()
        .context("invoking cargo run --example demo-hal")?;
    if !out.status.success() {
        bail!(
            "demo-hal example failed:\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let actual = String::from_utf8(out.stdout).context("demo-hal stdout is not valid UTF-8")?;
    let expected_path = root.join("examples/expected/dma-heap.ndjson");
    let expected = std::fs::read_to_string(&expected_path)
        .with_context(|| format!("reading {}", expected_path.display()))?;

    if actual.trim() == expected.trim() {
        println!(
            "OK demo-hal output matches {} ({} line(s))",
            expected_path.display(),
            actual.lines().count()
        );
        return Ok(());
    }

    println!("=== EXPECTED ({}) ===", expected_path.display());
    print!("{expected}");
    println!("=== ACTUAL ===");
    print!("{actual}");
    bail!(
        "demo-hal NDJSON mismatch — update {} or fix the regression",
        expected_path.display()
    );
}

/// Run `neutron window` against `examples/expected/window-capture.ndjson`
/// with a fixed anchor + size and diff against
/// `examples/expected/window-output.ndjson`. Sprint-2 PR 3 fixture —
/// catches schema drift in the window subcommand without needing a real
/// capture.
fn demo_window() -> Result<()> {
    let root = workspace_root();
    let capture = root.join("examples/expected/window-capture.ndjson");
    let expected_path = root.join("examples/expected/window-output.ndjson");
    println!(
        "=== running neutron window against {} ===",
        capture.display()
    );
    let out = Command::new("cargo")
        .current_dir(&root)
        .args([
            "run",
            "--quiet",
            "--bin",
            "neutron",
            "--",
            "window",
            capture.to_str().unwrap(),
            "--anchor",
            "crash",
            "--before-events",
            "2",
            "--after-events",
            "2",
        ])
        .output()
        .context("invoking cargo run -- window")?;
    if !out.status.success() {
        bail!(
            "neutron window failed:\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let actual = String::from_utf8(out.stdout).context("window stdout is not valid UTF-8")?;
    let expected = std::fs::read_to_string(&expected_path)
        .with_context(|| format!("reading {}", expected_path.display()))?;
    if actual.trim() == expected.trim() {
        println!(
            "OK demo-window output matches {} ({} line(s))",
            expected_path.display(),
            actual.lines().count()
        );
        return Ok(());
    }
    println!("=== EXPECTED ({}) ===", expected_path.display());
    print!("{expected}");
    println!("=== ACTUAL ===");
    print!("{actual}");
    bail!(
        "demo-window NDJSON mismatch — update {} or fix the regression",
        expected_path.display()
    );
}

/// Compare findings emitted by neutron (read from `path` — an NDJSON file
/// containing both event lines and finding lines) against the canonical
/// `examples/expected/findings.txt` list. Prints a unified diff of the
/// rule_id sets and exits non-zero if they don't match.
fn check_findings(path: &str) -> Result<()> {
    let contents = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;

    // Extract rule_id values from JSON lines that contain them. We use a
    // simple substring scan rather than a JSON parser to avoid pulling
    // serde_json into xtask just for this.
    let mut actual: std::collections::BTreeSet<String> = Default::default();
    for line in contents.lines() {
        if let Some(start) = line.find(r#""rule_id":""#) {
            let after = &line[start + r#""rule_id":""#.len()..];
            if let Some(end) = after.find('"') {
                actual.insert(after[..end].to_string());
            }
        }
    }

    let expected_path = workspace_root().join("examples/expected/findings.txt");
    let expected_text = std::fs::read_to_string(&expected_path)
        .with_context(|| format!("reading {}", expected_path.display()))?;

    let expected: std::collections::BTreeSet<String> = expected_text
        .lines()
        .map(|l| l.trim_start())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            // Strip trailing comments and whitespace.
            l.split_whitespace().next().unwrap_or("").to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();

    let missing: Vec<_> = expected.difference(&actual).collect();
    let extra: Vec<_> = actual.difference(&expected).collect();

    println!(
        "expected: {} rules; got: {} rules",
        expected.len(),
        actual.len()
    );
    if !missing.is_empty() {
        println!("\n  MISSING (expected but not seen):");
        for m in &missing {
            println!("    - {m}");
        }
    }
    if !extra.is_empty() {
        println!("\n  EXTRA (seen but not expected — additional rules fired):");
        for e in &extra {
            println!("    + {e}");
        }
    }
    if missing.is_empty() && extra.is_empty() {
        println!("OK: every expected rule fired and no surprise rules appeared");
        Ok(())
    } else if missing.is_empty() {
        println!(
            "\nNote: extras are not a failure — they may be stack-aware or \
                 environment-specific rules that happened to match."
        );
        Ok(())
    } else {
        bail!(
            "{} expected rule(s) did not fire — capture may be incomplete or buggy",
            missing.len()
        );
    }
}

/// Print the bench instructions. Real benchmark numbers can only be
/// produced on a connected Pixel — this command lays out the exact
/// commands an operator should run, then parses the resulting
/// `neutron`-stderr captures via `bench-parse`.
fn bench(secs: u64) -> Result<()> {
    println!("=== neutron bench harness ===\n");
    println!("Each profile runs for {secs}s under demo-target's --loop. We capture");
    println!("neutron's stderr (which prints the capture summary on Ctrl-C),");
    println!("then parse events_submitted / drops / fd-graph misses out of it.\n");

    println!("Step 1 — push artifacts:");
    println!("  cargo xtask demo            # builds + pushes neutron + demo-target\n");

    println!("Step 2 — run each profile on-device. Use adb shell. Repeat for each:");
    println!("  PROFILE=security_no_stacks");
    println!("  PROFILE=security_with_stacks");
    println!("  PROFILE=raw");
    println!("  PROFILE=binder\n");

    println!("Use this on-device snippet (paste into `adb shell su -c '...'`):\n");
    println!("  cat <<'EOSH' > /data/local/tmp/bench-once.sh");
    println!("  #!/system/bin/sh");
    println!("  PROFILE=\"$1\"");
    println!("  case \"$PROFILE\" in");
    println!("    security_no_stacks)   FLAGS=\"--profile security\" ;;");
    println!("    security_with_stacks) FLAGS=\"--profile security --stacks\" ;;");
    println!("    raw)                  FLAGS=\"--raw --no-findings\" ;;");
    println!("    binder)               FLAGS=\"--binder --profile security\" ;;");
    println!("    *) echo \"unknown profile: $PROFILE\" >&2; exit 1 ;;");
    println!("  esac");
    println!("  /data/local/tmp/demo-target --loop {secs} > /dev/null 2>&1 &");
    println!("  TARGET=$!");
    println!("  /data/local/tmp/neutron --pid $TARGET --json $FLAGS \\");
    println!("      > /data/local/tmp/bench-$PROFILE.ndjson \\");
    println!("      2> /data/local/tmp/bench-$PROFILE.stderr &");
    println!("  NEUTRON=$!");
    println!("  wait $TARGET");
    println!("  kill -INT $NEUTRON");
    println!("  wait $NEUTRON 2>/dev/null");
    println!("  EOSH");
    println!("  chmod +x /data/local/tmp/bench-once.sh");
    println!();
    println!("  for PROFILE in security_no_stacks security_with_stacks raw binder; do");
    println!("    /data/local/tmp/bench-once.sh $PROFILE");
    println!("  done\n");

    println!("Step 3 — pull and parse:\n");
    println!("  for PROFILE in security_no_stacks security_with_stacks raw binder; do");
    println!("    adb pull /data/local/tmp/bench-$PROFILE.stderr /tmp/");
    println!("    cargo xtask bench-parse $PROFILE {secs} \\");
    println!("        < /tmp/bench-$PROFILE.stderr");
    println!("  done\n");

    println!("Each parse emits one Markdown table row.");
    Ok(())
}

/// Parse a captured `neutron` stderr (capture summary block) from stdin and
/// emit a single Markdown row. Tolerates lines neutron prints in any order
/// and silently produces "—" for any field that wasn't found.
fn bench_parse_stdin(profile: &str, secs: u64) -> Result<()> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading stdin")?;

    let mut events: Option<u64> = None;
    let mut drops: Option<u64> = None;
    let mut stack_user_failed: Option<u64> = None;
    let mut stack_kernel_failed: Option<u64> = None;
    let mut fd_misses: Option<u64> = None;

    for line in buf.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("events submitted:") {
            events = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("ringbuf reserve failed:") {
            drops = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("user stack failed:") {
            stack_user_failed = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("kernel stack failed:") {
            stack_kernel_failed = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("fd graph:") {
            // "fd graph: 12 miss(es), 9 resolved via /proc/<pid>/fd"
            fd_misses = rest.split_whitespace().next().and_then(|s| s.parse().ok());
        }
    }

    let fmt = |v: Option<u64>| v.map(|n| n.to_string()).unwrap_or_else(|| "—".into());
    let throughput = events
        .map(|e| (e as f64 / secs as f64).round() as u64)
        .map(|t| format!("{t}/s"))
        .unwrap_or_else(|| "—".into());
    let drop_rate = match (events, drops) {
        (Some(e), Some(d)) if e > 0 => format!("{:.3}%", (d as f64 / e as f64) * 100.0),
        (_, Some(_)) => "—".into(),
        _ => "—".into(),
    };

    println!(
        "| {profile:<22} | {} | {throughput:>9} | {} | {drop_rate:>7} | {} | {} | {} |",
        fmt(events),
        fmt(drops),
        fmt(stack_user_failed),
        fmt(stack_kernel_failed),
        fmt(fd_misses),
    );
    Ok(())
}

fn deploy() -> Result<()> {
    let root = workspace_root();
    println!("=== Deploying to device ===");

    let state = Command::new("adb")
        .args(["get-state"])
        .output()
        .context("adb not found")?;
    if !state.status.success() {
        bail!("no adb device connected");
    }

    for (src, dst) in &[
        (EBPF_OBJ_NAME, "/data/local/tmp/neutron.bpf.elf"),
        (
            "target/aarch64-unknown-linux-musl/release/neutron",
            "/data/local/tmp/neutron",
        ),
    ] {
        let src_path = root.join(src);
        println!("  push {} -> {}", src_path.display(), dst);
        let status = Command::new("adb")
            .args(["push", src_path.to_str().unwrap(), dst])
            .status()
            .context("adb push failed")?;
        if !status.success() {
            bail!("adb push failed for {}", src);
        }
    }

    Command::new("adb")
        .args(["shell", "chmod", "+x", "/data/local/tmp/neutron"])
        .status()?;

    println!("\n=== Done. On device run: ===");
    println!("  adb shell su -c '/data/local/tmp/neutron --pid <PID>'");
    println!("  # default --object is /data/local/tmp/neutron.bpf.elf");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ebpf_preflight_mentions_nightly_install_when_missing() {
        let err = format_ebpf_preflight_error(
            Err("cargo +nightly --version exited with status 1".into()),
            Ok(()),
        )
        .expect("missing nightly should produce an error");

        assert!(err.contains("cargo +nightly"));
        assert!(err.contains("rustup toolchain install nightly"));
    }

    #[test]
    fn ebpf_preflight_mentions_bpf_linker_install_when_missing() {
        let err = format_ebpf_preflight_error(Ok(()), Err("bpf-linker not found in PATH".into()))
            .expect("missing bpf-linker should produce an error");

        assert!(err.contains("bpf-linker"));
        assert!(err.contains("cargo install bpf-linker"));
    }

    #[test]
    fn ebpf_stackless_build_plan_is_the_default_object_without_stack_feature() {
        let plan = EbpfBuildPlan::new(false, EbpfStackMode::Stackless);

        assert_eq!(plan.output_name(), "neutron.bpf.elf");
        assert!(plan.cargo_feature_args().is_empty());
    }

    #[test]
    fn ebpf_stacks_build_plan_uses_separate_object_and_feature() {
        let plan = EbpfBuildPlan::new(true, EbpfStackMode::Stacks);

        assert_eq!(plan.output_name(), "neutron-stacks.bpf.elf");
        assert_eq!(plan.cargo_feature_args(), ["--features", "stacks"]);
    }
}
