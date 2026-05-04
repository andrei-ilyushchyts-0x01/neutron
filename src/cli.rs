//! CLI definition for the neutron production (Aya) binary.
//!
//! The default mode (no subcommand) runs the syscall tracer. Subcommands
//! cover diagnostic and offline workflows: today only `doctor` is available;
//! `timeline`, `diff`, and `bench` arrive in later P0/P1 phases.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "neutron",
    version,
    about = "Low-intrusion eBPF syscall tracer for authorized Android security assessment"
)]
pub struct Cli {
    /// Optional subcommand. When omitted, neutron runs in trace mode using
    /// the flags in [`Args`].
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Trace-mode arguments. Used when `command` is `None`.
    #[command(flatten)]
    pub args: Args,
}

/// Subcommand registry. Add new subcommands here.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Preflight environment checks. Verifies that the device kernel,
    /// privileges, and BPF subsystem are in a state where neutron can attach.
    /// Prints PASS/WARN/FAIL per check and exits non-zero on any FAIL.
    Doctor,
}

#[derive(Parser, Debug, Default)]
pub struct Args {
    /// Target PID (0 = all processes)
    #[arg(long, default_value_t = 0)]
    pub pid: u32,

    /// Path to compiled Aya BPF ELF object
    #[arg(long, default_value = "/data/local/tmp/neutron.bpf.elf")]
    pub object: String,

    /// (Deprecated as of CORE V1 — kept for backward compatibility. The
    /// kernel BPF ring buffer size is fixed in the BPF object; this flag is
    /// ignored.)
    #[arg(long, default_value_t = 64)]
    pub pages: usize,

    /// Verbose diagnostic output
    #[arg(short, long)]
    pub verbose: bool,

    /// Exclude events from these comm names (comma-separated, substring match)
    #[arg(long, value_delimiter = ',')]
    pub exclude_comm: Vec<String>,

    /// Write output to file instead of stdout
    #[arg(long)]
    pub output: Option<String>,

    /// Output events as NDJSON
    #[arg(long)]
    pub json: bool,

    /// Tracing profile: "security" filters to security-relevant syscalls only
    #[arg(long)]
    pub profile: Option<String>,

    /// Enable binder transaction tracing via kprobe
    #[arg(long)]
    pub binder: bool,

    /// Enable kernel + userspace stack trace collection
    #[arg(long)]
    pub stacks: bool,

    /// Highlight/filter RWX memory operations (mmap/mprotect with PROT_READ|PROT_WRITE|PROT_EXEC)
    #[arg(long)]
    pub alert_rwx: bool,

    /// Resolve file paths via /proc/<pid>/fd/<fd> readlink when BPF capture returns zeros
    #[arg(long)]
    pub resolve_paths: bool,

    /// Follow child processes spawned via clone() by the target --pid
    #[arg(long)]
    pub follow_children: bool,

    /// Capture content of read() calls on watched FDs (/proc/*, /sys/*)
    #[arg(long)]
    pub capture_reads: bool,

    // ── Rule engine ────────────────────────────────────────────────────────
    /// Path to a custom YAML rule file. Defaults to the bundled detector pack
    /// (15 starter rules — see docs/rules/reference.md).
    #[arg(long)]
    pub rules: Option<String>,

    /// Output raw syscall events instead of (or in addition to) findings.
    /// Without this flag, neutron emits only rule-engine findings.
    #[arg(long)]
    pub raw: bool,

    /// Suppress findings output. Useful with `--raw` for the legacy
    /// per-event behavior of pre-rule-engine versions.
    #[arg(long)]
    pub no_findings: bool,

    /// Print every N events, drain findings produced so far. Default 256.
    #[arg(long, default_value_t = 256)]
    pub findings_drain_interval: u64,

    // ── FD poller (sprint-1 PR 3) ──────────────────────────────────────────
    /// PID scope for the periodic `/proc/<pid>/fd` poller.
    /// `traced` = `--pid` target + followed children + (under `--pid 0`)
    /// PIDs that already produced fd-bearing events.
    /// `active` (default) = same as `traced` but excludes followed children.
    /// `uid` = sprint-2 stub; falls back to `active` with a stderr warning.
    /// `all` = scan all PIDs in `/proc` (heavy; use only for one-off audits).
    #[arg(long, default_value = "active")]
    pub fdgraph_pids: String,

    /// Periodic FD-poller interval. Accepts `1s`, `500ms`, or `off` to
    /// disable polling entirely. Default 1 second.
    #[arg(long, default_value = "1s")]
    pub fdgraph_interval: String,

    /// Comma-separated FD-count alert tiers (e.g. `1024,8192,90%`). Parsed
    /// for forward-compatibility but advisory in sprint-1; rule predicates
    /// (`R001_fd_table_exhaustion` etc.) carry their own thresholds. A
    /// future PR may surface these as `--alert-tier`-style banners.
    #[arg(long, default_value = "1024,8192,90%")]
    pub fdgraph_thresholds: String,

    /// Top-N FD path aggregation per snapshot. `0` (default) disables the
    /// per-PID readlink scan; set to e.g. `5` to populate the
    /// `top_paths` field on every `fd_snapshot` JSON line. Has cost
    /// proportional to fd count for in-scope PIDs.
    #[arg(long, default_value_t = 0)]
    pub fdgraph_top_paths_n: usize,
}
