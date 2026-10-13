//! Disposable native FD stimulus. Run --help; writes only inside a private directory.
use anyhow::{bail, Context, Result};
use clap::Parser;
use neutron::evidence::{
    ExternalClaimScope, ExternalStimulusIdentity, NativeProcessRuntimeIdentity,
};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, os::unix::fs::MetadataExt, path::PathBuf};

#[derive(Parser)]
struct Args {
    /// Existing absolute, owned mode-0700 session directory.
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=32))]
    attempts: u32,
    /// Without this flag, print the procedure without performing it.
    #[arg(long)]
    execute: bool,
}

fn identity() -> Result<NativeProcessRuntimeIdentity> {
    let pid = std::process::id();
    let starttime = neutron::native::read_starttime(pid).context("reading self starttime")?;
    let mut binary = Vec::new();
    fs::File::open("/proc/self/exe")?
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut binary)?;
    if binary.len() > 512 * 1024 * 1024 {
        bail!("self executable exceeds 512 MiB");
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let capabilities = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .context("self capabilities unavailable")?
        .trim()
        .to_owned();
    let domain = fs::read_to_string("/proc/self/attr/current")?
        .trim()
        .to_owned();
    if !domain.starts_with("u:r:") || domain.split(':').count() < 4 {
        bail!("this collector requires a readable Android SELinux process context");
    }
    Ok(NativeProcessRuntimeIdentity {
        schema: "neutron.native-process-runtime/v1".into(),
        device_boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        pid,
        starttime,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        executable_path: fs::read_link("/proc/self/exe")?
            .to_str()
            .context("executable path is not UTF-8")?
            .into(),
        binary_sha256: format!("{:x}", Sha256::digest(&binary)),
        build_id: neutron::native::elf_map_metadata(&binary, 0, 0).and_then(|elf| elf.build_id),
        selinux_domain: domain,
        effective_capabilities: capabilities,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    if !args.execute {
        println!(
            "Dry run: {} private-file create/dup/close attempts; no service or driver invocation.",
            args.attempts
        );
        return Ok(());
    }
    let metadata = fs::symlink_metadata(&args.output_dir)?;
    if !args.output_dir.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("output directory must be absolute, owned, private, and not a symlink");
    }
    let initial = identity()?;
    let caller = match initial.uid {
        0 => "native_root",
        2000 => "native_shell",
        _ => "native_process",
    };
    let scope = ExternalClaimScope {
        procedure: "private_file_create_dup_close".into(),
        caller: caller.into(),
        attempt_count: args.attempts,
    };
    let mut attempts = Vec::new();
    for attempt in 0..args.attempts {
        let before = identity()?;
        if before != initial {
            bail!("stimulus identity changed before attempt");
        }
        let file = neutron::private_output::open_private_file(
            &args.output_dir.join(format!("attempt-{attempt}")),
            neutron::private_output::PrivateFileMode::CreateNew,
        )?;
        drop(file.try_clone()?);
        drop(file);
        if identity()? != initial {
            bail!("stimulus identity changed during attempt");
        }
        attempts.push(serde_json::json!({"identity": before, "outcome": "private_file_create_dup_close_succeeded"}));
    }
    neutron::private_output::write_json(
        &args.output_dir.join("stimulus-identity.json"),
        &ExternalStimulusIdentity::NativeProcess(initial.clone()),
        false,
    )?;
    neutron::private_output::write_json(
        &args.output_dir.join("stimulus-observation.json"),
        &serde_json::json!({"schema":"neutron.native-stimulus-observation/v1", "identity": initial,
            "claim_scope": scope, "attempts": attempts}),
        false,
    )?;
    Ok(())
}
