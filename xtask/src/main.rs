//! Build orchestration for neutron.
//!
//! Usage:
//!   cargo xtask build-ebpf          # debug build
//!   cargo xtask build-ebpf release  # release build
//!   cargo xtask build-ebpf --stacks # stackful object for --stacks captures
//!   cargo xtask build               # build everything (ebpf + userspace aarch64-musl)
//!   cargo xtask deploy --serial ID  # build + adb push to one explicit device
//!   cargo xtask demo --serial ID    # build + push demo target; print run instructions
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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const EBPF_OBJ_NAME: &str = "neutron.bpf.elf";
const EBPF_STACKS_OBJ_NAME: &str = "neutron-stacks.bpf.elf";
const DEMO_BIN: &str = "demo-target";
const DEVICE_INSTALL_DIR: &str = "/data/local/share/neutron";
const DEVICE_RUNTIME_DIR: &str = "/data/local/share/neutron/runtime";
const DEVICE_RUNS_DIR: &str = "/data/local/share/neutron/runs";
const DEVICE_AGENT_PATH: &str = "/data/local/share/neutron/neutron-agent";
const DEVICE_EBPF_PATH: &str = "/data/local/share/neutron/neutron.bpf.elf";
const DEVICE_EBPF_STACKS_PATH: &str = "/data/local/share/neutron/neutron-stacks.bpf.elf";
const DEVICE_DEMO_PATH: &str = "/data/local/tmp/demo-target";
const DEVICE_STAGE_PREFIX: &str = "/data/local/tmp/neutron-install";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeployArtifact {
    source: PathBuf,
    stage_name: &'static str,
    destination: &'static str,
    mode: &'static str,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build-ebpf") => {
            let plan = parse_ebpf_build_args(args, EbpfStackMode::Stackless)?;
            build_ebpf_plan(plan)
        }
        Some("build-ebpf-stacks") => {
            let plan = parse_ebpf_build_args(args, EbpfStackMode::Stacks)?;
            build_ebpf_plan(plan)
        }
        Some("build") => {
            build_ebpf(true)?;
            build_userspace()
        }
        Some("deploy") => {
            let serial = parse_serial(args, "cargo xtask deploy --serial SERIAL")?;
            require_physical_usb_device(&serial)?;
            build_ebpf(true)?;
            build_ebpf_plan(EbpfBuildPlan::new(true, EbpfStackMode::Stacks))?;
            build_userspace()?;
            deploy(&serial)
        }
        Some("demo") => {
            let serial = parse_serial(args, "cargo xtask demo --serial SERIAL")?;
            require_physical_usb_device(&serial)?;
            demo(&serial)
        }
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
                "Usage: cargo xtask <build-ebpf [--stacks] [release] | build-ebpf-stacks [release] | build \
                | deploy --serial SERIAL | demo --serial SERIAL | demo-hal | check-findings <file>>"
            );
            Ok(())
        }
    }
}

fn parse_serial(mut args: impl Iterator<Item = String>, usage: &str) -> Result<String> {
    match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(serial), None)
            if flag == "--serial"
                && !serial.starts_with("emulator-")
                && !serial.is_empty()
                && serial.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                }) =>
        {
            Ok(serial)
        }
        _ => bail!("usage: {usage}"),
    }
}

fn adb_host() -> Command {
    Command::new("adb")
}

fn adb(serial: &str) -> Command {
    let mut command = adb_host();
    command.args(["-s", serial]);
    command
}

fn checked_command_output(mut command: Command, args: &[&str], action: &str) -> Result<String> {
    let output = command
        .args(args)
        .output()
        .with_context(|| format!("{action}: adb not found"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        bail!(
            "{action} failed with {}{}",
            output.status,
            if detail.trim().is_empty() {
                String::new()
            } else {
                format!(": {}", detail.trim())
            }
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("{action}: adb output is not UTF-8"))
}

fn checked_adb_output(serial: &str, args: &[&str], action: &str) -> Result<String> {
    checked_command_output(adb(serial), args, action)
}

fn checked_su_output(serial: &str, command: &str, action: &str) -> Result<String> {
    checked_adb_output(serial, &["shell", "su", "-c", command], action)
}

fn device_list_has_physical_usb_serial(output: &str, serial: &str) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some(serial)
            && fields.next() == Some("device")
            && fields.any(|field| field.starts_with("usb:"))
    })
}

fn require_physical_usb_device(serial: &str) -> Result<()> {
    let output = checked_command_output(
        adb_host(),
        &["devices", "-l"],
        "enumerating authorized ADB devices",
    )?;
    if !device_list_has_physical_usb_serial(&output, serial) {
        bail!("serial {serial} is not an attached authorized physical USB device");
    }
    Ok(())
}

fn parse_sha256_output(output: &str) -> Result<String> {
    let digest = output
        .split_whitespace()
        .next()
        .context("sha256sum returned no digest")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("sha256sum returned an invalid digest");
    }
    Ok(digest.to_ascii_lowercase())
}

fn local_sha256(path: &Path) -> Result<String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .with_context(|| format!("hashing {}: sha256sum not found", path.display()))?;
    if !output.status.success() {
        bail!("sha256sum failed for {}", path.display());
    }
    parse_sha256_output(&String::from_utf8_lossy(&output.stdout))
        .with_context(|| format!("parsing SHA-256 for {}", path.display()))
}

fn device_sha256(serial: &str, path: &str) -> Result<String> {
    let command = format!("sha256sum {path}");
    let output = checked_su_output(serial, &command, &format!("hashing installed {path}"))?;
    parse_sha256_output(&output).with_context(|| format!("parsing device SHA-256 for {path}"))
}

fn neutron_deploy_artifacts(root: &Path) -> [DeployArtifact; 3] {
    [
        DeployArtifact {
            source: root.join(EBPF_OBJ_NAME),
            stage_name: EBPF_OBJ_NAME,
            destination: DEVICE_EBPF_PATH,
            mode: "0600",
        },
        DeployArtifact {
            source: root.join(EBPF_STACKS_OBJ_NAME),
            stage_name: EBPF_STACKS_OBJ_NAME,
            destination: DEVICE_EBPF_STACKS_PATH,
            mode: "0600",
        },
        DeployArtifact {
            source: root.join("target/aarch64-unknown-linux-musl/release/neutron"),
            stage_name: "neutron-agent",
            destination: DEVICE_AGENT_PATH,
            mode: "0700",
        },
    ]
}

fn device_staging_dir() -> Result<String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates Unix epoch")?
        .as_nanos();
    Ok(format!(
        "{DEVICE_STAGE_PREFIX}-{}-{nonce}",
        std::process::id()
    ))
}

fn transactional_publish_command(
    artifacts: &[DeployArtifact],
    candidate_suffix: &str,
    backup_root: &str,
) -> String {
    let mut restore = String::from("restore_backup() {\n");
    let mut rollback = String::from("rollback_publish() {\n  rm -f");
    let mut preflight = Vec::with_capacity(artifacts.len());
    let mut backup = Vec::with_capacity(artifacts.len());
    let mut publish = Vec::with_capacity(artifacts.len());

    for artifact in artifacts {
        let previous = format!("{backup_root}/{}", artifact.stage_name);
        restore.push_str(&format!(
            "  if [ -e {previous} ] || [ -L {previous} ]; then rm -f {destination} && mv {previous} {destination} || return 1; fi\n",
            destination = artifact.destination,
        ));
        rollback.push_str(&format!(" {}", artifact.destination));
        preflight.push(format!(
            "test -f {destination}{candidate_suffix} && test ! -L {destination}{candidate_suffix}",
            destination = artifact.destination,
        ));
        backup.push(format!(
            "{{ {{ [ ! -e {destination} ] && [ ! -L {destination} ]; }} || mv {destination} {previous}; }}",
            destination = artifact.destination,
        ));
        publish.push(format!(
            "mv {destination}{candidate_suffix} {destination}",
            destination = artifact.destination,
        ));
    }

    restore.push_str(&format!("  rmdir {backup_root}\n}}\n"));
    rollback.push_str(" && restore_backup\n}\n");

    format!(
        "set -u\nrm -rf {backup_root} && mkdir -m 0700 {backup_root} || exit 1\n\
{restore}{rollback}\
if\n  {preflight}\nthen\n  :\nelse\n  rmdir {backup_root}\n  exit 1\nfi\n\
trap 'restore_backup; exit 1' 1 2 15\n\
if\n  {backup}\nthen\n  :\nelse\n  restore_backup\n  exit 1\nfi\n\
trap 'rollback_publish; exit 1' 1 2 15\n\
if\n  {publish}\nthen\n  trap - 1 2 15\n  rm -rf {backup_root}\nelse\n  rollback_publish\n  exit 1\nfi",
        preflight = preflight.join(" &&\n  "),
        backup = backup.join(" &&\n  "),
        publish = publish.join(" &&\n  "),
    )
}

fn install_neutron_artifacts(serial: &str, artifacts: &[DeployArtifact]) -> Result<()> {
    for artifact in artifacts {
        let metadata = std::fs::metadata(&artifact.source)
            .with_context(|| format!("reading {}", artifact.source.display()))?;
        if !metadata.is_file() {
            bail!(
                "deployment source is not a file: {}",
                artifact.source.display()
            );
        }
    }

    let staging_dir = device_staging_dir()?;
    let deployment_id = staging_dir
        .rsplit('/')
        .next()
        .context("device staging directory has no basename")?;
    let candidate_suffix = format!(".new.{deployment_id}");
    let backup_root = format!("{DEVICE_INSTALL_DIR}/previous.{deployment_id}");
    checked_adb_output(
        serial,
        &["shell", "mkdir", "-m", "0700", &staging_dir],
        "creating private device staging directory",
    )?;

    let install_result = (|| -> Result<()> {
        let mut expected_hashes = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            let local_hash = local_sha256(&artifact.source)?;
            let stage_path = format!("{staging_dir}/{}", artifact.stage_name);
            println!("  stage {} -> {stage_path}", artifact.source.display());
            checked_adb_output(
                serial,
                &[
                    "push",
                    artifact
                        .source
                        .to_str()
                        .context("deployment source path is not UTF-8")?,
                    &stage_path,
                ],
                &format!("staging {}", artifact.source.display()),
            )?;
            expected_hashes.push((artifact, stage_path, local_hash));
        }

        let prepare = format!(
            "test ! -L {DEVICE_INSTALL_DIR} && test ! -L {DEVICE_RUNTIME_DIR} && \
             test ! -L {DEVICE_RUNS_DIR} && \
             mkdir -p {DEVICE_INSTALL_DIR} {DEVICE_RUNTIME_DIR} {DEVICE_RUNS_DIR} && \
             chown 0:0 {DEVICE_INSTALL_DIR} {DEVICE_RUNTIME_DIR} {DEVICE_RUNS_DIR} && \
             chmod 0700 {DEVICE_INSTALL_DIR} {DEVICE_RUNTIME_DIR} {DEVICE_RUNS_DIR}"
        );
        checked_su_output(serial, &prepare, "preparing root-owned Neutron directories")?;

        for (artifact, stage_path, expected_hash) in expected_hashes {
            let candidate = format!("{}{candidate_suffix}", artifact.destination);
            let install = format!(
                "rm -f {candidate} && test -f {stage_path} && test ! -L {stage_path} && \
                 install -m {mode} {stage_path} {candidate} && \
                 chown 0:0 {candidate} && chmod {mode} {candidate}",
                mode = artifact.mode,
            );
            checked_su_output(
                serial,
                &install,
                &format!("preparing candidate for {}", artifact.destination),
            )?;

            let actual_hash = device_sha256(serial, &candidate)?;
            if actual_hash != expected_hash {
                bail!(
                    "candidate SHA-256 mismatch for {}: local={}, device={}",
                    artifact.destination,
                    expected_hash,
                    actual_hash
                );
            }
            println!(
                "  verified candidate {} mode={} sha256={}",
                artifact.destination, artifact.mode, actual_hash
            );
        }

        checked_su_output(
            serial,
            &transactional_publish_command(artifacts, &candidate_suffix, &backup_root),
            "publishing the Neutron artifact set transactionally",
        )?;
        Ok(())
    })();

    let candidate_cleanup_result = if install_result.is_err() {
        let candidates = artifacts
            .iter()
            .map(|artifact| format!("{}{}", artifact.destination, candidate_suffix))
            .collect::<Vec<_>>()
            .join(" ");
        checked_su_output(
            serial,
            &format!("rm -f {candidates}"),
            "cleaning unpublished Neutron candidates",
        )
        .map(|_| ())
    } else {
        Ok(())
    };
    let install_result = match (install_result, candidate_cleanup_result) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("candidate cleanup also failed: {cleanup:#}")))
        }
        (result, _) => result,
    };

    let cleanup_result = checked_adb_output(
        serial,
        &["shell", "rm", "-rf", &staging_dir],
        "cleaning device staging directory",
    );
    match (install_result, cleanup_result) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("device staging cleanup also failed: {cleanup:#}")))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EbpfStackMode {
    Stackless,
    Stacks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EbpfBuildPlan {
    release: bool,
    stack_mode: EbpfStackMode,
}

impl EbpfBuildPlan {
    fn new(release: bool, stack_mode: EbpfStackMode) -> Self {
        Self {
            release,
            stack_mode,
        }
    }

    fn label(self) -> &'static str {
        match self.stack_mode {
            EbpfStackMode::Stackless => "stackless",
            EbpfStackMode::Stacks => "stacks",
        }
    }

    fn output_name(self) -> &'static str {
        match self.stack_mode {
            EbpfStackMode::Stackless => EBPF_OBJ_NAME,
            EbpfStackMode::Stacks => EBPF_STACKS_OBJ_NAME,
        }
    }

    fn cargo_feature_args(self) -> &'static [&'static str] {
        match self.stack_mode {
            EbpfStackMode::Stackless => &[],
            EbpfStackMode::Stacks => &["--features", "stacks"],
        }
    }
}

fn parse_ebpf_build_args(
    args: impl IntoIterator<Item = String>,
    default_mode: EbpfStackMode,
) -> Result<EbpfBuildPlan> {
    let mut release = false;
    let mut stack_mode = default_mode;
    for arg in args {
        match arg.as_str() {
            "release" => release = true,
            "--stacks" => stack_mode = EbpfStackMode::Stacks,
            other => bail!(
                "unknown build-ebpf argument `{other}`; usage: cargo xtask build-ebpf [--stacks] [release]"
            ),
        }
    }
    Ok(EbpfBuildPlan::new(release, stack_mode))
}

fn workspace_root() -> PathBuf {
    // xtask is a workspace member — its manifest dir is workspace_root/xtask/
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_owned()
}

fn source_commit(root: &Path) -> Result<String> {
    let value = match std::env::var("NEUTRON_BUILD_GIT_COMMIT") {
        Ok(value) => value,
        Err(_) => {
            let output = Command::new("git")
                .current_dir(root)
                .args(["rev-parse", "HEAD"])
                .output()
                .context("reading source commit for BPF build ID")?;
            if !output.status.success() {
                bail!("git rev-parse HEAD failed while deriving BPF build ID");
            }
            String::from_utf8(output.stdout)
                .context("git commit is not UTF-8")?
                .trim()
                .to_string()
        }
    };
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("BPF build ID requires a full 40-hex source commit");
    }
    Ok(value)
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
    cargo_toolchain: std::result::Result<(), String>,
    bpf_linker: std::result::Result<(), String>,
) -> Option<String> {
    let mut lines = Vec::new();
    if let Err(detail) = cargo_toolchain {
        lines.push(format!(
            "- the pinned Cargo toolchain is unavailable or unusable ({detail}). \
             Install it with: rustup toolchain install nightly-2026-07-15"
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
             neutron builds eBPF with the workspace-pinned nightly and \
             `-Z build-std=core` \
             for target bpfel-unknown-none.",
            lines.join("\n")
        ))
    }
}

fn preflight_ebpf_build() -> Result<()> {
    let cargo_toolchain = command_ok("cargo", &["--version"]);
    let bpf_linker = command_ok("bpf-linker", &["--version"]);
    if let Some(msg) = format_ebpf_preflight_error(cargo_toolchain, bpf_linker) {
        bail!("{msg}");
    }
    Ok(())
}

fn copy_bpf_artifact(source: &Path, destination: &Path) -> Result<()> {
    std::fs::copy(source, destination)
        .with_context(|| format!("copy {} -> {}", source.display(), destination.display()))?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("setting safe BPF object mode on {}", destination.display()))
}

fn build_ebpf(release: bool) -> Result<()> {
    build_ebpf_plan(EbpfBuildPlan::new(release, EbpfStackMode::Stackless))
}

fn build_ebpf_plan(plan: EbpfBuildPlan) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("neutron-ebpf");
    let commit = source_commit(&root)?;

    println!(
        "=== Building BPF programs ({} {}) ===",
        if plan.release { "release" } else { "debug" },
        plan.label(),
    );
    preflight_ebpf_build()?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
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
        .env("CARGO_PROFILE_DEV_CODEGEN_UNITS", "1")
        .env("NEUTRON_GIT_COMMIT", commit);

    cmd.args(plan.cargo_feature_args());

    if plan.release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("cargo build for BPF failed")?;
    if !status.success() {
        bail!("BPF build failed");
    }

    let profile = if plan.release { "release" } else { "debug" };
    let obj = root
        .join("target/bpfel-unknown-none")
        .join(profile)
        .join("neutron-ebpf");

    println!("  BPF object: {}", obj.display());

    let dest = root.join(plan.output_name());
    copy_bpf_artifact(&obj, &dest)?;
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

fn demo(serial: &str) -> Result<()> {
    let root = workspace_root();

    // Always build the BPF object + userspace binary so the device has a
    // matching neutron and BPF ELF.
    build_ebpf(true)?;
    build_ebpf_plan(EbpfBuildPlan::new(true, EbpfStackMode::Stacks))?;
    build_userspace()?;
    let demo_bin = build_demo_target()?;

    println!("\n=== Installing Neutron and demo-target ===");
    let state = adb(serial)
        .args(["get-state"])
        .output()
        .context("adb not found")?;
    if !state.status.success() {
        bail!("no adb device connected — connect a Pixel and re-run");
    }

    install_neutron_artifacts(serial, &neutron_deploy_artifacts(&root))?;

    println!("  push {} -> {DEVICE_DEMO_PATH}", demo_bin.display());
    checked_adb_output(
        serial,
        &[
            "push",
            demo_bin.to_str().context("demo-target path is not UTF-8")?,
            DEVICE_DEMO_PATH,
        ],
        "pushing demo-target",
    )?;
    checked_adb_output(
        serial,
        &["shell", "chmod", "0700", DEVICE_DEMO_PATH],
        "setting demo-target permissions",
    )?;

    println!("\n=== How to run on-device ===");
    println!("Two terminals:");
    println!();
    println!("  # Terminal A — start neutron in the background, capture JSON.");
    println!("  adb -s {serial} shell su -c '{DEVICE_AGENT_PATH} --pid 0 --json' \\");
    println!("      > demo-trace.ndjson");
    println!();
    println!("  # Terminal B — once neutron is attached, run the demo.");
    println!("  adb -s {serial} shell '{DEVICE_DEMO_PATH}'");
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
    println!("  cargo xtask demo --serial SERIAL  # builds + installs neutron + demo-target\n");

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
    println!("  {DEVICE_AGENT_PATH} --pid $TARGET --json $FLAGS \\");
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
    println!("    adb -s SERIAL pull /data/local/tmp/bench-$PROFILE.stderr /tmp/");
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

fn deploy(serial: &str) -> Result<()> {
    let root = workspace_root();
    println!("=== Deploying to device ===");

    let state = adb(serial)
        .args(["get-state"])
        .output()
        .context("adb not found")?;
    if !state.status.success() {
        bail!("no adb device connected");
    }

    install_neutron_artifacts(serial, &neutron_deploy_artifacts(&root))?;

    println!("\n=== Done. On device run: ===");
    println!("  adb -s {serial} shell su -c '{DEVICE_AGENT_PATH} --pid <PID>'");
    println!("  # default --object is {DEVICE_EBPF_PATH}");
    println!("  # runtime state: {DEVICE_RUNTIME_DIR}; run bundles: {DEVICE_RUNS_DIR}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_serial_parser_requires_explicit_serial() {
        assert!(parse_serial(Vec::<String>::new().into_iter(), "deploy").is_err());
        assert!(parse_serial(["USB123".into()].into_iter(), "deploy").is_err());
        assert!(parse_serial(
            ["--serial".into(), "emulator-5554".into()].into_iter(),
            "deploy"
        )
        .is_err());
        assert!(parse_serial(["--serial".into(), "USB 123".into()].into_iter(), "deploy").is_err());
        assert_eq!(
            parse_serial(["--serial".into(), "USB123".into()].into_iter(), "deploy").unwrap(),
            "USB123"
        );
    }

    #[test]
    fn physical_device_selection_requires_the_exact_authorized_usb_row() {
        let devices = "List of devices attached\nUSB123 device usb:1-2 product:husky\nUSB124 unauthorized usb:1-3\nemulator-5554 device product:sdk\n";

        assert!(device_list_has_physical_usb_serial(devices, "USB123"));
        assert!(!device_list_has_physical_usb_serial(devices, "USB124"));
        assert!(!device_list_has_physical_usb_serial(
            devices,
            "emulator-5554"
        ));
        assert!(!device_list_has_physical_usb_serial(devices, "USB12"));
    }

    #[test]
    fn adb_command_contains_explicit_serial() {
        let command = adb("USB123");
        let args: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_str().unwrap())
            .collect();
        assert_eq!(args.as_slice(), ["-s", "USB123"]);
    }

    #[test]
    fn su_command_is_quoted_as_one_remote_shell_word() {
        assert_eq!(
            quote_remote_shell_word("test -f /data/local/share/neutron && chmod 0700 /data/local/share/neutron"),
            "'test -f /data/local/share/neutron && chmod 0700 /data/local/share/neutron'"
        );
        assert_eq!(quote_remote_shell_word("printf '%s' safe"), "'printf '\"'\"'%s'\"'\"' safe'");
    }

    #[test]
    fn deploy_plan_uses_private_root_owned_paths_and_modes() {
        let artifacts = neutron_deploy_artifacts(Path::new("/workspace"));

        assert_eq!(DEVICE_RUNTIME_DIR, "/data/local/share/neutron/runtime");
        assert_eq!(DEVICE_RUNS_DIR, "/data/local/share/neutron/runs");
        assert_eq!(artifacts[0].destination, DEVICE_EBPF_PATH);
        assert_eq!(artifacts[0].mode, "0600");
        assert_eq!(artifacts[1].destination, DEVICE_EBPF_STACKS_PATH);
        assert_eq!(artifacts[1].mode, "0600");
        assert_eq!(artifacts[2].destination, DEVICE_AGENT_PATH);
        assert_eq!(artifacts[2].mode, "0700");
        assert!(artifacts
            .iter()
            .all(|artifact| artifact.destination.starts_with(DEVICE_INSTALL_DIR)));
        assert!(artifacts
            .iter()
            .all(|artifact| !artifact.destination.starts_with("/data/local/tmp/")));
    }

    #[test]
    fn publish_command_restores_the_previous_artifact_set_on_failure() {
        let artifacts = neutron_deploy_artifacts(Path::new("/workspace"));
        let command = transactional_publish_command(
            &artifacts,
            ".new.test",
            "/data/local/share/neutron/previous.test",
        );

        assert!(command.contains("rollback_publish"));
        assert!(command.contains("restore_backup"));
        for artifact in &artifacts {
            let name = Path::new(artifact.destination)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap();
            assert!(command.contains(&format!(
                "mv {} /data/local/share/neutron/previous.test/{name}",
                artifact.destination
            )));
            assert!(command.contains(&format!(
                "mv {}.new.test {}",
                artifact.destination, artifact.destination
            )));
            assert!(command.contains(&format!(
                "mv /data/local/share/neutron/previous.test/{name} {}",
                artifact.destination
            )));
        }
    }

    #[test]
    fn publish_command_does_not_mask_an_early_move_failure() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "neutron-xtask-publish-{}-{nonce}",
            std::process::id()
        ));
        let destinations = [root.join("one"), root.join("two"), root.join("three")];
        let backup = root.join("backup");
        std::fs::create_dir_all(&root).unwrap();
        for destination in &destinations {
            std::fs::write(destination, b"old").unwrap();
            std::fs::write(format!("{}.new.test", destination.display()), b"new").unwrap();
        }
        let destination_strings: Vec<&'static str> = destinations
            .iter()
            .map(|path| Box::leak(path.to_string_lossy().into_owned().into_boxed_str()) as &str)
            .collect();
        let artifacts = [
            DeployArtifact {
                source: PathBuf::new(),
                stage_name: "one",
                destination: destination_strings[0],
                mode: "0600",
            },
            DeployArtifact {
                source: PathBuf::new(),
                stage_name: "two",
                destination: destination_strings[1],
                mode: "0600",
            },
            DeployArtifact {
                source: PathBuf::new(),
                stage_name: "three",
                destination: destination_strings[2],
                mode: "0600",
            },
        ];
        let command =
            transactional_publish_command(&artifacts, ".new.test", backup.to_str().unwrap());

        let fake_bin = root.join("bin");
        let fake_mv = fake_bin.join("mv");
        let fake_state = root.join("failed-first-publish");
        std::fs::create_dir(&fake_bin).unwrap();
        std::fs::write(
            &fake_mv,
            b"#!/bin/sh\ncase \"$1\" in\n  *.new.test)\n    if [ ! -e \"$NEUTRON_FAKE_MV_STATE\" ]; then\n      : > \"$NEUTRON_FAKE_MV_STATE\"\n      exit 71\n    fi\n    ;;\nesac\nexec /bin/mv \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_mv, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .env("NEUTRON_FAKE_MV_STATE", &fake_state)
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();

        assert!(!status.success());
        assert!(fake_state.exists());
        for destination in &destinations {
            assert_eq!(std::fs::read(destination).unwrap(), b"old");
        }
        assert!(!backup.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sha256_parser_rejects_missing_or_malformed_digests() {
        let upper = "A".repeat(64);
        assert_eq!(
            parse_sha256_output(&format!("{upper}  file\n")).unwrap(),
            "a".repeat(64)
        );
        assert!(parse_sha256_output("").is_err());
        assert!(parse_sha256_output("abc  file").is_err());
        assert!(parse_sha256_output(&format!("{}g  file", "a".repeat(63))).is_err());
    }

    #[test]
    fn staging_directory_is_bounded_under_data_local_tmp() {
        let path = device_staging_dir().unwrap();
        assert!(path.starts_with(&format!("{DEVICE_STAGE_PREFIX}-")));
        assert!(!path.contains(".."));
        assert!(path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-')));
    }

    #[test]
    fn copied_bpf_artifact_is_never_group_or_other_writable() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "neutron-xtask-bpf-mode-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let destination = root.join("destination");
        std::fs::write(&source, b"bpf").unwrap();
        std::fs::write(&destination, b"old").unwrap();
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o666)).unwrap();

        copy_bpf_artifact(&source, &destination).unwrap();

        let mode = std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        assert_eq!(std::fs::read(&destination).unwrap(), b"bpf");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ebpf_preflight_mentions_pinned_nightly_install_when_missing() {
        let err =
            format_ebpf_preflight_error(Err("cargo --version exited with status 1".into()), Ok(()))
                .expect("missing pinned toolchain should produce an error");

        assert!(err.contains("pinned Cargo toolchain"));
        assert!(err.contains("rustup toolchain install nightly-2026-07-15"));
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
