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
    /// Trace syscalls and optional causal Binder/service/HAL descendants.
    /// The same flags remain accepted without this explicit subcommand.
    Trace(Box<Args>),

    /// Preflight environment checks. Verifies that the device kernel,
    /// privileges, and BPF subsystem are in a state where neutron can attach.
    /// Prints PASS/WARN/FAIL per check and exits non-zero on any FAIL.
    Doctor,

    /// Host-side post-processor: cut a window of events around an anchor
    /// (finding, crash, pid, etc.) from a previously-captured NDJSON file.
    /// Sprint-2 PR 3.
    Window(WindowArgs),

    /// Aggregate an NDJSON capture by a user-chosen group key. Emits a
    /// sorted table of `count + group fields`, optionally with raw
    /// exemplars per group. Phase 2.
    Summarize(crate::summarize::SummarizeArgs),

    /// Compare two NDJSON captures aggregated on a shared key. Useful
    /// for negative-evidence workflows ("scenario A and scenario B
    /// both ran, what's different?"). Phase 2.
    Diff(crate::diff::DiffArgs),

    /// Render a Markdown kernel-boundary report from an NDJSON capture.
    Report(crate::report::ReportArgs),

    /// Build Binder attribution helper JSON files from captures and
    /// Android `service list -p` output.
    #[command(subcommand)]
    BinderMap(crate::report::BinderMapCommand),

    /// Append a `type:"marker"` NDJSON line to an output file (or
    /// stdout). Used to correlate external scenarios with the live
    /// trace; downstream `neutron window --anchor marker:<name>` cuts
    /// a window around the marker. Phase 5a.
    Mark(crate::mark::MarkArgs),

    /// Render a causal capture as a Mermaid flowchart.
    Graph(crate::graph::GraphArgs),

    /// Build and query an Android service/HAL/device surface snapshot.
    #[command(subcommand)]
    Surface(crate::surface::SurfaceCommand),

    /// Print built-in workflow recipes for common Android security
    /// research tasks.
    #[command(subcommand)]
    Recipes(crate::recipes::RecipesCommand),

    /// Generate and inspect data-only ioctl ABI schema packs.
    #[command(subcommand)]
    Ioctl(IoctlCommand),

    /// Capture, minimize, and replay authorized regression testcases.
    #[command(subcommand)]
    Harness(HarnessCommand),
}

#[derive(Subcommand, Debug)]
pub enum HarnessCommand {
    /// Extract one captured event and its dependencies into a testcase directory.
    Extract(crate::harness::ExtractArgs),
    /// Minimize a testcase without synthesizing new values.
    Minimize(crate::harness::MinimizeArgs),
    /// Replay a testcase on one explicitly selected physical USB device.
    Replay(crate::harness::ReplayArgs),
}

#[derive(Subcommand, Debug)]
pub enum IoctlCommand {
    /// Extract ioctl constants and record layouts from kernel headers with clang.
    Generate(crate::ioctl_schema::GenerateArgs),
}

#[derive(Parser, Debug)]
pub struct WindowArgs {
    /// Path to the NDJSON capture file (`-` for stdin).
    pub capture: String,

    /// Anchor specification. One of:
    /// `finding:<RULE_ID>`, `crash`, `pid:<N>`, `event_id:<N>`,
    /// `comm:<substring>`, `binder_call:<status>`, or `marker:<name>`.
    /// Multiple `--anchor` flags are AND-joined inside one window per match
    /// (i.e. each matching event becomes its own anchor; windows are then
    /// merged across all anchors).
    #[arg(long, value_name = "SPEC")]
    pub anchor: Vec<String>,

    /// Time window before each anchor (e.g. `5s`, `500ms`). Mutually
    /// exclusive with `--before-events`.
    #[arg(long, value_name = "DURATION")]
    pub before: Option<String>,

    /// Time window after each anchor.
    #[arg(long, value_name = "DURATION")]
    pub after: Option<String>,

    /// Shorthand: `--around 2s` is equivalent to `--before 2s --after 2s`.
    #[arg(long, value_name = "DURATION")]
    pub around: Option<String>,

    /// Event-count window before each anchor. Mutually exclusive with
    /// `--before`.
    #[arg(long, value_name = "N")]
    pub before_events: Option<usize>,

    /// Event-count window after each anchor.
    #[arg(long, value_name = "N")]
    pub after_events: Option<usize>,

    /// Shorthand: `--around-events 100` is `--before-events 100
    /// --after-events 100`.
    #[arg(long, value_name = "N")]
    pub around_events: Option<usize>,

    /// Print one summary line per merged window instead of the raw NDJSON.
    /// Format: `[<from_ts_ns>..<to_ts_ns>] events=<N> anchors=<list>`.
    #[arg(long)]
    pub summary: bool,
}

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Save replay-grade ioctl/Binder resources in an adjacent .blobs directory.
    /// Requires --output and either --package or a non-zero --pid.
    #[arg(long)]
    pub harness_capture: bool,

    /// Root Android package for causal tracing. Unlike --match-package, this
    /// identifies root processes by UID plus /proc/<pid>/cmdline.
    #[arg(long)]
    pub package: Option<String>,

    /// Root Android UID for causal tracing. Matching processes are admitted
    /// on their first kernel event; /proc refresh reconciles limits and exits.
    #[arg(long, conflicts_with_all = ["package", "pid"])]
    pub root_uid: Option<u32>,

    /// Add Binder callees to the dynamic traced-process set.
    #[arg(
        long,
        default_value_if("follow_services", "true", "true"),
        default_value_if("follow_hal", "true", "true")
    )]
    pub follow_binder: bool,

    /// Discover candidate service PIDs with `service list -p`.
    #[arg(long)]
    pub follow_services: bool,

    /// Discover candidate AIDL/HIDL HAL PIDs with `service list -p` and `lshal -ip`.
    #[arg(long)]
    pub follow_hal: bool,

    /// Maximum Binder expansion depth.
    #[arg(long, default_value_t = 4)]
    pub max_depth: u8,

    /// Maximum number of processes in the dynamic causal trace set.
    #[arg(
        long,
        default_value_t = 64,
        value_parser = clap::value_parser!(u32).range(1..=1024)
    )]
    pub max_processes: u32,

    /// Live marker control socket path. Use `off` to disable it.
    #[arg(
        long,
        default_value = "/data/local/tmp/neutron.control.sock",
        value_name = "PATH|off"
    )]
    pub control_socket: String,

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

    /// Stop capture after writing this many bytes to the output stream.
    /// Accepts bare bytes or binary suffixes like `500mb`, `1gb`.
    #[arg(long, value_name = "SIZE")]
    pub max_output_size: Option<String>,

    /// Rotate file output into numbered segments after this many bytes.
    /// Requires `--output`; writes PATH, PATH.1, PATH.2, ...
    #[arg(long, value_name = "SIZE")]
    pub rotate_output_size: Option<String>,

    /// Write the final type:"capture_health" JSON line to this separate file.
    /// Useful with --max-output-size because the primary output cap can prevent
    /// the shutdown health line from being appended to the main NDJSON stream.
    #[arg(long, value_name = "PATH")]
    pub health_output: Option<String>,

    /// Inter-process capture lock path. "auto" uses /data/local/tmp on Android
    /// when present, otherwise the host temp directory. "off" disables the
    /// lock for advanced debugging.
    #[arg(long, default_value = "auto", value_name = "PATH|auto|off")]
    pub capture_lock: String,

    /// Output events as NDJSON
    #[arg(long)]
    pub json: bool,

    /// Tracing profile. Available: "security", "kernel-lpe", "driver-harness".
    #[arg(long)]
    pub profile: Option<String>,

    /// BPF-first decoder/matcher pack. Repeat or comma-separate.
    /// Available: binder, kgsl, mali, alsa, unix-socket, media-hal.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub driver_pack: Vec<String>,

    /// Data-only ioctl schema pack name or path. Repeat to merge in order.
    /// Supplying any explicit pack disables automatic selection.
    #[arg(long, value_name = "NAME|PATH")]
    pub schema_pack: Vec<String>,

    /// Disable automatic selection from trusted system schema directories.
    #[arg(long)]
    pub no_schema_auto: bool,

    /// Explicit research-mode kprobe pack. Best-effort attach; missing
    /// kernel symbols or absent BPF programs warn and capture continues.
    /// Available: binder, kgsl, mali, alsa, unix-socket.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub kprobe_pack: Vec<String>,

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

    /// Per-finding `raw_window` cap — number of full NDJSON lines from
    /// contributing events embedded in each emitted finding. `0` disables.
    /// Sprint-2 PR 4. Default 10.
    #[arg(long, default_value_t = 10)]
    pub finding_raw_window: usize,

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

    // ── Crash correlation (sprint-2 PR 1) ──────────────────────────────────
    /// Per-PID ring-buffer depth for the crash-context lookback. Each
    /// emitted JSON line is buffered; on `process_exit` the buffer is dumped
    /// into the `crash_context` field. `0` disables lookback. Default 100.
    #[arg(long, default_value_t = 100)]
    pub lookback_events: usize,

    /// Directory the tombstone watcher polls. Default
    /// `/data/tombstones` (Android). Set to empty string to disable the
    /// watcher entirely. Polled at 1 Hz alongside the FD-graph drain.
    #[arg(long, default_value = "/data/tombstones")]
    pub tombstone_dir: String,

    /// Skip spawning the `logcat` tail. Useful for hosts without the
    /// Android `logcat` binary, or to silence its overhead in raw-only
    /// captures where the rule engine is disabled.
    #[arg(long)]
    pub no_logcat: bool,

    // ── Binder causality (sprint-2 PR 2) ───────────────────────────────────
    /// Maximum in-flight binder transactions tracked by the userspace
    /// correlator. When the cap is exceeded the least-recently-touched
    /// entry is silently dropped. `0` disables the correlator entirely
    /// (raw `binder` / `binder_received` events still flow). Default 1024.
    #[arg(long, default_value_t = 1024)]
    pub binder_inflight: usize,

    // ── Phase 1a — generic capture predicates ──────────────────────────────
    //
    // Each `--match-*` flag is one clause of an AND-conjunction. The
    // BPF-evaluable subset (pid/uid/syscall/ioctl-shape/ret/latency/
    // arg.u32@N) is pushed into the kernel-side filter so events are
    // dropped before the ringbuf; the rest (fd path globs, comm globs,
    // arg.u8/u16/u64, binder fields) is applied by the userspace
    // post-filter on every event that survives the BPF pre-filter.
    //
    // All flags accept comma-separated values. Numeric values accept
    // decimal, `0x` hex, `0b` binary, `0o` octal. UID flag also accepts
    // inclusive `LO..HI` ranges (capped at 1024 entries per range).
    /// Multi-PID match. Equivalent to `--pid` for one PID; for several,
    /// passes the extra PIDs through the existing `PID_WHITELIST` map.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_pid: Vec<String>,

    /// UID match (single, comma-separated, or `LO..HI` ranges).
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_uid: Vec<String>,

    /// Android package-name match. Resolved on-device to UID(s), then
    /// applied through the same BPF UID prefilter as `--match-uid`.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_package: Vec<String>,

    /// Android content-provider authority match. Accepts a bare authority
    /// or `content://authority/path`, resolves it on-device to the
    /// provider package UID, then applies the BPF UID prefilter.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_android_provider: Vec<String>,

    /// Syscall whitelist by aarch64 generic syscall number. Reuses the
    /// existing `SYSCALL_FILTER` BPF map.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_syscall: Vec<String>,

    /// Glob-matched fd path (e.g. `'/dev/lwis*'`). Userspace-only — needs
    /// `--resolve-paths` or an established fdgraph entry to match.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_fd: Vec<String>,

    /// Glob-matched comm name (e.g. `'cameraserver*'`). Userspace-only.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_comm: Vec<String>,

    /// ioctl `cmd` word (32-bit). Multiple values OR'd together.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_ioctl_cmd: Vec<String>,

    /// `_IOC_TYPE` byte, e.g. `0x4c` for LWIS.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_ioctl_type: Vec<String>,

    /// `_IOC_NR` byte.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_ioctl_nr: Vec<String>,

    /// `_IOC_DIR`: one of `none|r|w|rw`.
    #[arg(long)]
    pub match_ioctl_dir: Option<String>,

    /// Return-code class: one of `any|nonzero|negative|zero`. Default
    /// `any`. Exit-only.
    #[arg(long)]
    pub match_ret: Option<String>,

    /// Minimum exit-side latency. Accepts `100us`, `5ms`, `2s`, or a bare
    /// integer (microseconds).
    #[arg(long)]
    pub match_latency_min: Option<String>,

    /// Match `mmap`/`mprotect` events with `PROT_READ|PROT_WRITE|PROT_EXEC`.
    #[arg(long)]
    pub match_prot_rwx: bool,

    /// Match `mmap`/`mprotect` with `PROT_WRITE|PROT_EXEC` (no read).
    #[arg(long)]
    pub match_prot_wx: bool,

    /// Typed equality on a slice of the captured ioctl arg snapshot. Form:
    /// `<width>@<offset>=<v>[,<v>...]` — for example
    /// `--match-arg-u32 '0=0x20200,0x40200'` reads `data[4..8]` as u32 LE
    /// and compares against the value set. Width is one of
    /// `u8`/`u16`/`u32`/`u64`. The flag may be repeated for AND-joined
    /// clauses at different offsets (multi-offset cases evaluate
    /// userspace-side).
    #[arg(long, num_args = 1..)]
    pub match_arg_u32: Vec<String>,

    /// Same as `--match-arg-u32` but with `u8` width.
    #[arg(long, num_args = 1..)]
    pub match_arg_u8: Vec<String>,

    /// Same as `--match-arg-u32` but with `u16` width.
    #[arg(long, num_args = 1..)]
    pub match_arg_u16: Vec<String>,

    /// Same as `--match-arg-u32` but with `u64` width.
    #[arg(long, num_args = 1..)]
    pub match_arg_u64: Vec<String>,

    /// Binder `code` (request ID). Comma-separated u32 set.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_binder_code: Vec<String>,

    /// Binder `flags` (transaction flags). Comma-separated u32 set.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_binder_flags: Vec<String>,

    /// Binder `to_proc` (callee PID). Comma-separated.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_binder_to_proc: Vec<String>,

    /// Binder `to_thread` (callee TID). Comma-separated.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_binder_to_thread: Vec<String>,

    /// Binder `target_node` (handle). Comma-separated, signed.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub match_binder_target_node: Vec<String>,

    /// Binder `reply` flag — one of `true|false`.
    #[arg(long)]
    pub match_binder_reply: Option<bool>,

    // ── Phase 1b — `--match` boolean expression ────────────────────────────
    //
    // Recursive-descent parser for AND/OR/NOT over the same field
    // vocabulary as the individual `--match-*` flags. Mutually exclusive
    // with the individual flags: pick the expression form for power, the
    // individual flags for terse one-clause filters.
    //
    // Example:
    //   --match 'syscall = 29 AND fd_path GLOB "/dev/lwis*"'
    //   --match 'ret < 0 OR latency_us >= 5000'
    //   --match 'pid = 970 AND (ioctl.cmd IN (0xc0104c64, 0xc0084c01))'
    /// Boolean predicate expression. See man page for grammar.
    #[arg(long, value_name = "EXPR")]
    pub match_expr: Option<String>,

    // ── Phase 1c — capture mode ────────────────────────────────────────────
    /// Capture mode: when set to `matched+context=<DUR>`, neutron keeps a
    /// rolling buffer of recently-rejected events and, on the first
    /// matching event, flushes the previous `<DUR>` of context plus the
    /// next `<DUR>` of forward window. `<DUR>` accepts the same unit
    /// suffixes as `--match-latency-min` (`100ms`, `2s`, `5000` is
    /// microseconds). Capped at 30 seconds — anything larger is rejected
    /// to keep the in-memory ring bounded.
    ///
    /// When unset, neutron emits only events that match the predicate
    /// (which is also the default when no `--match-*` flag is in use, in
    /// which case every BPF-surviving event matches vacuously).
    #[arg(long, value_name = "MODE")]
    pub capture: Option<String>,

    // ── Phase 1d — sampling ────────────────────────────────────────────────
    /// Uniform Bernoulli sample probability in `[0.0, 1.0]`. `1.0`
    /// (default) keeps every event; `0.01` keeps 1%. State-tracking
    /// syscalls (open/close/dup/socket/...) are NEVER sampled — their
    /// drop would silently break userspace fdgraph and downstream
    /// `fd_path` matching. `--match`-rejected events are decided before
    /// sampling, so this flag only thins the matched stream.
    #[arg(long, value_name = "P")]
    pub sample: Option<f64>,

    /// Cap on emitted events per second across the matched stream.
    /// Implements a leaky token-bucket: when the bucket is empty, the
    /// excess is dropped. State-tracking syscalls bypass this cap for
    /// the same fdgraph-consistency reason as `--sample`.
    #[arg(long, value_name = "N")]
    pub rate_limit: Option<u64>,

    // ── Phase 4a — fd snapshot on finding ──────────────────────────────────
    /// When enabled, every finding whose contributing evidence includes an
    /// ioctl event is enriched with a synchronous read of
    /// `/proc/<pid>/fdinfo/<fd>`. Useful for transient fds that the
    /// 1-Hz fdgraph poller misses. Best-effort: a failed read is silent.
    #[arg(long)]
    pub fd_snapshot_on_finding: bool,

    // ── Phase 4b — binder service descriptor map ───────────────────────────
    /// Path to a JSON file mapping `(callee_pid, target_node)` to a
    /// human service name. When set, every emitted `binder_call` line
    /// gains a `"service":"<name>"` field for known pairs. See
    /// `docs/guides/binder-service-map.md` for the format. Unknown
    /// pairs surface no service field — never a placeholder.
    #[arg(long, value_name = "FILE")]
    pub binder_services: Option<String>,

    /// JSON map from `service + transaction code` to a verified method name.
    #[arg(long, value_name = "FILE")]
    pub binder_methods: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn window_help_lists_marker_anchor() {
        let mut cmd = Cli::command();
        let window = cmd
            .find_subcommand_mut("window")
            .expect("window subcommand registered");
        let mut help = Vec::new();
        window.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(
            help.contains("marker:<name>"),
            "window help should document marker anchors:\n{help}"
        );
    }

    #[test]
    fn top_level_help_lists_output_bounds() {
        let mut cmd = Cli::command();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(
            help.contains("--max-output-size") && help.contains("--rotate-output-size"),
            "top-level help should document output bounding flags:\n{help}"
        );
    }

    #[test]
    fn top_level_help_lists_recipes_subcommand() {
        let mut cmd = Cli::command();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(
            help.contains("recipes"),
            "top-level help should list recipes subcommand:\n{help}"
        );
    }

    #[test]
    fn top_level_help_lists_bpf_driver_pack_flags() {
        let mut cmd = Cli::command();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        assert!(
            help.contains("--driver-pack")
                && help.contains("--kprobe-pack")
                && help.contains("kernel-lpe")
                && help.contains("driver-harness"),
            "top-level help should document BPF driver pack flags and profiles:\n{help}"
        );
    }

    #[test]
    fn driver_and_kprobe_packs_accept_comma_lists() {
        let cli = Cli::try_parse_from([
            "neutron",
            "--driver-pack",
            "binder,kgsl",
            "--kprobe-pack",
            "mali,alsa",
        ])
        .expect("parse driver/kprobe packs");
        assert_eq!(cli.args.driver_pack, vec!["binder", "kgsl"]);
        assert_eq!(cli.args.kprobe_pack, vec!["mali", "alsa"]);
    }
}
