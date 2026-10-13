//! Deprecated 1.x compatibility entry point. All loading belongs to neutron.
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Deprecated: use neutron doctor --smoke or neutron trace")]
struct Opts {
    #[arg(long, short = 'o', default_value = "/data/local/tmp/neutron.bpf.elf")]
    object: String,
    #[arg(long, short = 'p', default_value_t = 0)]
    pid: u32,
    #[arg(long, short = 'd')]
    duration: Option<u64>,
    #[arg(long, short = 'n')]
    max_events: Option<u64>,
    #[arg(long)]
    resolve_paths: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, short = 'q')]
    quiet: bool,
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    if opts.max_events.is_some() || opts.duration.is_some() || opts.quiet {
        bail!("legacy --duration/--max-events/--quiet have no exact maintained mapping; use timeout --signal=INT SECONDS neutron trace --pid PID --max-output-size SIZE, or neutron doctor --smoke for a bounded diagnostic");
    }
    if opts.pid == 0 && opts.resolve_paths {
        bail!("--resolve-paths requires an explicit --pid; no system-wide fallback is supported");
    }
    let executable = std::env::current_exe()?.with_file_name("neutron");
    let mut command = Command::new(&executable);
    if opts.pid == 0 {
        command.args(["doctor", "--smoke"]);
    } else {
        command.args(["trace", "--pid", &opts.pid.to_string(), "--raw"]);
        if opts.resolve_paths {
            command.arg("--resolve-paths");
        }
    }
    command.args(["--object", &opts.object]);
    if opts.json {
        command.arg("--json");
    }
    eprintln!(
        "neutron-spike is deprecated; forwarding to {}",
        executable.display()
    );
    Err(command.exec()).context("executing maintained neutron diagnostic")
}
