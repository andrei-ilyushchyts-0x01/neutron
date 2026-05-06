//! Phase 1a — generic capture-reduction predicates.
//!
//! The matcher embodies the "predicate-based capture reduction with exact
//! userspace matching and conservative BPF prefiltering" architecture
//! agreed in the Phase 1 plan. A [`MatchSpec`] is the parsed,
//! type-checked, layer-agnostic AND-conjunction of `--match-*` flags. It
//! splits naturally into:
//!
//! - **BPF-evaluable subset**: pid/uid/syscall/ioctl-shape/ret/latency/
//!   `arg.u32@N`. Userspace populates the corresponding BPF maps and
//!   FILTER_MAP slots; the kernel-side evaluator in `neutron-ebpf` drops
//!   events that don't match before they hit the ringbuf.
//! - **Userspace-only subset**: fd-path globs, comm globs,
//!   `arg.{u8,u16,u64}@N`, binder-field matches. Evaluated on each event
//!   that survives the BPF prefilter.
//!
//! The evaluator is deliberately a closed-form AND of equalities / set
//! membership / ranges — no expression language here. Phase 1b adds a
//! recursive-descent parser that compiles `--match '<expr>'` down to the
//! same struct (with safe BPF over-approximation when an `OR` or `NOT`
//! mixes BPF and userspace clauses).

use std::collections::BTreeSet;

use anyhow::{anyhow, bail, Context, Result};

/// Direction byte for `_IOC_DIR`. Mirrors the kernel encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoctlDir {
    None = 0,
    Write = 1,
    Read = 2,
    Rw = 3,
}

impl IoctlDir {
    pub fn from_str_relaxed(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "n" => Ok(IoctlDir::None),
            "w" | "write" => Ok(IoctlDir::Write),
            "r" | "read" => Ok(IoctlDir::Read),
            "rw" | "wr" | "readwrite" => Ok(IoctlDir::Rw),
            other => Err(anyhow!("invalid --match-ioctl-dir value: {other}")),
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Discrete equivalence class for `ret`. Mirrors `RET_CLASS_*` in
/// `neutron-common`. Stored in `FILTER_MAP[FILTER_KEY_RET_CLASS]` when
/// `MATCH_BIT_RET` is set. `Any` is the default (vacuously true).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RetClass {
    #[default]
    Any,
    Nonzero,
    Negative,
    Zero,
}

impl RetClass {
    pub fn from_str_relaxed(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "any" | "" => Ok(RetClass::Any),
            "nonzero" | "nz" | "!=0" => Ok(RetClass::Nonzero),
            "negative" | "neg" | "<0" => Ok(RetClass::Negative),
            "zero" | "==0" => Ok(RetClass::Zero),
            other => Err(anyhow!("invalid --match-ret value: {other}")),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            RetClass::Any => neutron_common::RET_CLASS_ANY,
            RetClass::Nonzero => neutron_common::RET_CLASS_NONZERO,
            RetClass::Negative => neutron_common::RET_CLASS_NEGATIVE,
            RetClass::Zero => neutron_common::RET_CLASS_ZERO,
        }
    }

    pub fn matches(self, ret: i64) -> bool {
        neutron_common::ret_matches_class(ret, self.as_u32())
    }
}

/// Width of an `arg.u*@N` accessor. Stored separately from the offset so
/// the parser can complain about unsupported widths early.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgWidth {
    U8,
    U16,
    U32,
    U64,
}

impl ArgWidth {
    pub fn size_bytes(self) -> usize {
        match self {
            ArgWidth::U8 => 1,
            ArgWidth::U16 => 2,
            ArgWidth::U32 => 4,
            ArgWidth::U64 => 8,
        }
    }
}

/// One typed-arg equality clause. Keyed by `(width, offset)`; the value is
/// a set so `arg.u32@0 IN (a, b, c)` round-trips. Offsets are bytes from
/// the start of the post-cmd arg snapshot (i.e. `data[4..]` in the wire).
#[derive(Clone, Debug, Default)]
pub struct ArgClause {
    pub width: Option<ArgWidth>,
    pub offset: u32,
    pub values: BTreeSet<u64>,
}

/// Binder predicate fields available in Phase 1. `status` is deliberately
/// out-of-scope (see plan #5): the BPF binder tracepoint exposes
/// `to_proc/to_thread/code/flags/reply/target_node` directly; status comes
/// from userspace correlation and lives in a later phase.
#[derive(Clone, Debug, Default)]
pub struct BinderClause {
    pub to_proc: BTreeSet<u32>,
    pub to_thread: BTreeSet<u32>,
    pub code: BTreeSet<u32>,
    pub flags: BTreeSet<u32>,
    pub target_node: BTreeSet<i32>,
    pub reply: Option<bool>,
}

impl BinderClause {
    pub fn is_empty(&self) -> bool {
        self.to_proc.is_empty()
            && self.to_thread.is_empty()
            && self.code.is_empty()
            && self.flags.is_empty()
            && self.target_node.is_empty()
            && self.reply.is_none()
    }
}

/// Closed-form AND-conjunction of `--match-*` flags. Empty fields are
/// vacuously true; a fully-default `MatchSpec` matches everything. Field
/// invariants:
///
/// - `pids` populates the BPF `PID_WHITELIST` map; if empty AND
///   [`Args::pid`] is `0`, no PID filter is applied.
/// - `syscalls` populates the BPF `SYSCALL_FILTER` map and toggles
///   `FILTER_KEY_ACTIVE` to `1`.
/// - `arg_u32` always carries at most one offset for the BPF-evaluable
///   path; multiple offsets degrade to userspace-only (Phase 1b will use
///   this when the parser sees mixed-offset clauses).
#[derive(Clone, Debug, Default)]
pub struct MatchSpec {
    pub pids: BTreeSet<u32>,
    pub uids: BTreeSet<u32>,
    pub syscalls: BTreeSet<i32>,
    pub fd_globs: Vec<String>,
    pub comm_globs: Vec<String>,
    pub ioctl_cmds: BTreeSet<u32>,
    pub ioctl_types: BTreeSet<u32>,
    pub ioctl_nrs: BTreeSet<u32>,
    pub ioctl_dir: Option<IoctlDir>,
    pub ret_class: RetClass,
    pub latency_min_us: Option<u64>,
    pub prot_rwx: bool,
    pub prot_wx: bool,
    pub arg_clauses: Vec<ArgClause>,
    pub binder: BinderClause,
}

impl MatchSpec {
    /// `true` when no `--match-*` flag is configured. Callers use this to
    /// short-circuit the post-filter and audit-print paths.
    pub fn is_empty(&self) -> bool {
        self.pids.is_empty()
            && self.uids.is_empty()
            && self.syscalls.is_empty()
            && self.fd_globs.is_empty()
            && self.comm_globs.is_empty()
            && self.ioctl_cmds.is_empty()
            && self.ioctl_types.is_empty()
            && self.ioctl_nrs.is_empty()
            && self.ioctl_dir.is_none()
            && self.ret_class == RetClass::Any
            && self.latency_min_us.is_none()
            && !self.prot_rwx
            && !self.prot_wx
            && self.arg_clauses.is_empty()
            && self.binder.is_empty()
    }

    /// `true` when any clause depends on userspace-derived state: fd-graph
    /// path resolution, comm globbing, binder semantics, or arg accessors
    /// at non-u32 widths. Drives the BPF
    /// `FILTER_KEY_STATE_EMIT_REQUIRED` toggle.
    pub fn needs_state_events(&self) -> bool {
        !self.fd_globs.is_empty()
    }

    /// Render a human-readable audit of where each active clause lands —
    /// `bpf` for kernel-side prefilter, `user` for userspace post-filter.
    /// One line per non-empty clause; empty result for an empty spec.
    pub fn audit_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let fmt_set = |s: &BTreeSet<u32>| -> String {
            let mut v: Vec<String> = s.iter().map(|x| format!("{x:#x}")).collect();
            v.sort();
            format!("{{{}}}", v.join(","))
        };
        let fmt_iset = |s: &BTreeSet<i32>| -> String {
            let mut v: Vec<String> = s.iter().map(|x| x.to_string()).collect();
            v.sort();
            format!("{{{}}}", v.join(","))
        };
        if !self.pids.is_empty() {
            let v: Vec<String> = self.pids.iter().map(|p| p.to_string()).collect();
            lines.push(format!("[bpf]  pid IN {{{}}}", v.join(",")));
        }
        if !self.uids.is_empty() {
            let v: Vec<String> = self.uids.iter().map(|p| p.to_string()).collect();
            lines.push(format!("[bpf]  uid IN {{{}}}", v.join(",")));
        }
        if !self.syscalls.is_empty() {
            lines.push(format!("[bpf]  syscall IN {}", fmt_iset(&self.syscalls)));
        }
        if !self.ioctl_cmds.is_empty() {
            lines.push(format!("[bpf]  ioctl.cmd IN {}", fmt_set(&self.ioctl_cmds)));
        }
        if !self.ioctl_types.is_empty() {
            lines.push(format!(
                "[bpf]  ioctl.type IN {}",
                fmt_set(&self.ioctl_types)
            ));
        }
        if !self.ioctl_nrs.is_empty() {
            lines.push(format!("[bpf]  ioctl.nr IN {}", fmt_set(&self.ioctl_nrs)));
        }
        if let Some(d) = self.ioctl_dir {
            lines.push(format!("[bpf]  ioctl.dir = {d:?}"));
        }
        if self.ret_class != RetClass::Any {
            lines.push(format!("[bpf]  ret = {:?}", self.ret_class));
        }
        if let Some(min_us) = self.latency_min_us {
            lines.push(format!("[bpf]  latency_us >= {min_us}"));
        }
        if let Some(c) = self.bpf_arg_u32() {
            let mut vals: Vec<String> = c.values.iter().map(|x| format!("{x:#x}")).collect();
            vals.sort();
            lines.push(format!(
                "[bpf]  arg.u32@{} IN {{{}}}",
                c.offset,
                vals.join(",")
            ));
        }
        if !self.fd_globs.is_empty() {
            lines.push(format!(
                "[user] fd_path glob {{{}}}",
                self.fd_globs.join(",")
            ));
        }
        if !self.comm_globs.is_empty() {
            lines.push(format!(
                "[user] comm glob {{{}}}",
                self.comm_globs.join(",")
            ));
        }
        for c in &self.arg_clauses {
            // bpf_arg_u32 already covered; here cover the remaining widths
            // and any multi-offset u32 fallbacks.
            let bpf_one = self.bpf_arg_u32();
            let is_bpf = bpf_one.map(|b| std::ptr::eq(b, c)).unwrap_or(false);
            if is_bpf {
                continue;
            }
            let w = match c.width {
                Some(ArgWidth::U8) => "u8",
                Some(ArgWidth::U16) => "u16",
                Some(ArgWidth::U32) => "u32",
                Some(ArgWidth::U64) => "u64",
                None => "?",
            };
            let mut vals: Vec<String> = c.values.iter().map(|x| format!("{x:#x}")).collect();
            vals.sort();
            lines.push(format!(
                "[user] arg.{}@{} IN {{{}}}",
                w,
                c.offset,
                vals.join(",")
            ));
        }
        if self.prot_rwx {
            lines.push("[user] prot.rwx".to_string());
        }
        if self.prot_wx {
            lines.push("[user] prot.wx".to_string());
        }
        if !self.binder.code.is_empty() {
            lines.push(format!(
                "[user] binder.code IN {}",
                fmt_set(&self.binder.code)
            ));
        }
        if !self.binder.flags.is_empty() {
            lines.push(format!(
                "[user] binder.flags IN {}",
                fmt_set(&self.binder.flags)
            ));
        }
        if !self.binder.to_proc.is_empty() {
            lines.push(format!(
                "[user] binder.to_proc IN {}",
                fmt_set(&self.binder.to_proc)
            ));
        }
        if !self.binder.to_thread.is_empty() {
            lines.push(format!(
                "[user] binder.to_thread IN {}",
                fmt_set(&self.binder.to_thread)
            ));
        }
        if !self.binder.target_node.is_empty() {
            lines.push(format!(
                "[user] binder.target_node IN {}",
                fmt_iset(&self.binder.target_node)
            ));
        }
        if let Some(r) = self.binder.reply {
            lines.push(format!("[user] binder.reply = {r}"));
        }
        lines
    }

    /// Returns the single BPF-evaluable u32 arg offset, if any.
    /// Multi-offset cases collapse to userspace-only and return `None` here.
    pub fn bpf_arg_u32(&self) -> Option<&ArgClause> {
        let candidates: Vec<&ArgClause> = self
            .arg_clauses
            .iter()
            .filter(|c| matches!(c.width, Some(ArgWidth::U32)))
            .collect();
        if candidates.len() == 1 {
            Some(candidates[0])
        } else {
            None
        }
    }
}

// ── CLI parsing helpers ─────────────────────────────────────────────────────

/// Parse a comma-separated list of u32 values. Accepts decimal and `0x`
/// hex. Empty entries are skipped.
pub fn parse_u32_list(s: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for raw in s.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        out.push(parse_u32_one(t).with_context(|| format!("parsing {t}"))?);
    }
    Ok(out)
}

/// Parse a comma-separated list of u32 values, supporting `LO..HI`
/// inclusive ranges (e.g. `--match-uid 10100..10199`).
pub fn parse_u32_list_with_ranges(s: &str) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for raw in s.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = t.split_once("..") {
            let lo = parse_u32_one(lo).with_context(|| format!("range lower: {lo}"))?;
            let hi = parse_u32_one(hi).with_context(|| format!("range upper: {hi}"))?;
            if lo > hi {
                bail!("range {lo}..{hi}: lower > upper");
            }
            // Cap at 1024 entries per range to avoid run-away CLI expansion.
            if hi.saturating_sub(lo) > 1024 {
                bail!("range {lo}..{hi} too large (max 1024 entries)");
            }
            for v in lo..=hi {
                out.push(v);
            }
        } else {
            out.push(parse_u32_one(t).with_context(|| format!("parsing {t}"))?);
        }
    }
    Ok(out)
}

/// Parse a single u32. Decimal by default, `0x` prefix for hex, `0b` for
/// binary, `0o` for octal.
pub fn parse_u32_one(s: &str) -> Result<u32> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u32::from_str_radix(rest, 16)?)
    } else if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        Ok(u32::from_str_radix(rest, 2)?)
    } else if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        Ok(u32::from_str_radix(rest, 8)?)
    } else {
        Ok(s.parse()?)
    }
}

pub fn parse_u64_one(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u64::from_str_radix(rest, 16)?)
    } else if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        Ok(u64::from_str_radix(rest, 2)?)
    } else if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        Ok(u64::from_str_radix(rest, 8)?)
    } else {
        Ok(s.parse()?)
    }
}

/// Parse a duration suffix (`Nms`, `Nus`, `Ns`). Returns the value in
/// microseconds. Bare integers are interpreted as microseconds — no unit
/// guessing.
pub fn parse_latency_us(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix("us") {
        Ok(rest.trim().parse::<u64>()?)
    } else if let Some(rest) = s.strip_suffix("ms") {
        Ok(rest.trim().parse::<u64>()? * 1_000)
    } else if let Some(rest) = s.strip_suffix('s') {
        Ok(rest.trim().parse::<u64>()? * 1_000_000)
    } else {
        Ok(s.parse::<u64>()?)
    }
}

/// Match a glob pattern against `text`. Supports only `*` (zero or more
/// chars) and `?` (one char). Anchored at both ends. Trivial implementation
/// — no character classes — which is enough for the path/comm patterns in
/// the assessment (e.g. `'/dev/lwis*'`, `'cameraserver*'`).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pat: &[u8], text: &[u8]) -> bool {
    // Iterative two-pointer with backtracking on `*`. O(len(pat) * len(text))
    // worst case which is fine for our short patterns and short paths.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (usize::MAX, 0usize);
    while t < text.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_p = p;
            star_t = t;
            p += 1;
        } else if star_p != usize::MAX {
            p = star_p + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

// ── CLI → MatchSpec ────────────────────────────────────────────────────────

/// Build a [`MatchSpec`] from parsed CLI args. Returns an error if any
/// individual flag fails to parse.
pub fn build_from_args(args: &crate::cli::Args) -> Result<MatchSpec> {
    let mut spec = MatchSpec::default();

    // Implicit single PID from the legacy `--pid N` flag — only fold it
    // into the multi-PID set when `--match-pid` was also given, so the
    // BPF FILTER_KEY_PID slot stays in charge of the simple case.
    let mut pids = Vec::new();
    for s in &args.match_pid {
        for v in parse_u32_list_with_ranges(s)? {
            pids.push(v);
        }
    }
    spec.pids = pids.into_iter().collect();
    if !spec.pids.is_empty() && args.pid != 0 {
        spec.pids.insert(args.pid);
    }

    let mut uids = Vec::new();
    for s in &args.match_uid {
        for v in parse_u32_list_with_ranges(s)? {
            uids.push(v);
        }
    }
    spec.uids = uids.into_iter().collect();

    for s in &args.match_syscall {
        for v in parse_u32_list(s)? {
            // Re-cast as i32 — syscall numbers are signed (sentinels exist).
            spec.syscalls.insert(v as i32);
        }
    }

    spec.fd_globs = collect_globs(&args.match_fd);
    spec.comm_globs = collect_globs(&args.match_comm);

    for s in &args.match_ioctl_cmd {
        for v in parse_u32_list(s)? {
            spec.ioctl_cmds.insert(v);
        }
    }
    for s in &args.match_ioctl_type {
        for v in parse_u32_list(s)? {
            if v > 0xff {
                bail!("--match-ioctl-type: {v:#x} exceeds 0xff");
            }
            spec.ioctl_types.insert(v);
        }
    }
    for s in &args.match_ioctl_nr {
        for v in parse_u32_list(s)? {
            if v > 0xff {
                bail!("--match-ioctl-nr: {v:#x} exceeds 0xff");
            }
            spec.ioctl_nrs.insert(v);
        }
    }
    if let Some(d) = &args.match_ioctl_dir {
        spec.ioctl_dir = Some(IoctlDir::from_str_relaxed(d)?);
    }

    if let Some(r) = &args.match_ret {
        spec.ret_class = RetClass::from_str_relaxed(r)?;
    }
    if let Some(l) = &args.match_latency_min {
        spec.latency_min_us = Some(parse_latency_us(l)?);
    }
    spec.prot_rwx = args.match_prot_rwx;
    spec.prot_wx = args.match_prot_wx;

    for s in &args.match_arg_u8 {
        spec.arg_clauses.push(parse_arg_clause(s, ArgWidth::U8)?);
    }
    for s in &args.match_arg_u16 {
        spec.arg_clauses.push(parse_arg_clause(s, ArgWidth::U16)?);
    }
    for s in &args.match_arg_u32 {
        spec.arg_clauses.push(parse_arg_clause(s, ArgWidth::U32)?);
    }
    for s in &args.match_arg_u64 {
        spec.arg_clauses.push(parse_arg_clause(s, ArgWidth::U64)?);
    }

    for s in &args.match_binder_code {
        for v in parse_u32_list(s)? {
            spec.binder.code.insert(v);
        }
    }
    for s in &args.match_binder_flags {
        for v in parse_u32_list(s)? {
            spec.binder.flags.insert(v);
        }
    }
    for s in &args.match_binder_to_proc {
        for v in parse_u32_list(s)? {
            spec.binder.to_proc.insert(v);
        }
    }
    for s in &args.match_binder_to_thread {
        for v in parse_u32_list(s)? {
            spec.binder.to_thread.insert(v);
        }
    }
    for s in &args.match_binder_target_node {
        for v in parse_u32_list(s)? {
            // target_node ranges into negative i32 territory in practice;
            // accept the round-trip.
            spec.binder.target_node.insert(v as i32);
        }
    }
    spec.binder.reply = args.match_binder_reply;

    Ok(spec)
}

fn collect_globs(values: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for s in values {
        for piece in s.split(',') {
            let t = piece.trim();
            if !t.is_empty() {
                out.push(t.to_string());
            }
        }
    }
    out
}

/// Parse one `--match-arg-*` value of the form `<offset>=<v>[,<v>...]`.
/// `width` comes from the flag (`u8`/`u16`/`u32`/`u64`).
fn parse_arg_clause(s: &str, width: ArgWidth) -> Result<ArgClause> {
    let (off_part, vals_part) = s
        .split_once('=')
        .ok_or_else(|| anyhow!("expected '<off>=<v>...' got: {s}"))?;
    let offset = parse_u32_one(off_part).with_context(|| format!("offset {off_part}"))?;
    let max_offset = (124 - width.size_bytes()) as u32;
    if offset > max_offset {
        bail!(
            "arg.{}@{}: offset out of range (max {})",
            match width {
                ArgWidth::U8 => "u8",
                ArgWidth::U16 => "u16",
                ArgWidth::U32 => "u32",
                ArgWidth::U64 => "u64",
            },
            offset,
            max_offset
        );
    }
    let mut values = BTreeSet::new();
    for raw in vals_part.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        let v = parse_u64_one(t).with_context(|| format!("value {t}"))?;
        values.insert(v);
    }
    if values.is_empty() {
        bail!("arg clause {s}: empty value set");
    }
    Ok(ArgClause {
        width: Some(width),
        offset,
        values,
    })
}

// ── SyscallEvent adapter ───────────────────────────────────────────────────

use neutron_common::SyscallEvent;

/// Owned snapshot of the fields the matcher reads from a `SyscallEvent`.
/// Owning the data sidesteps the `#[repr(C, packed)]` borrow restriction
/// and keeps the trait object lifetime-clean.
pub struct SyscallEventLens<'a> {
    pid: u32,
    uid: u32,
    nr: i32,
    is_enter: bool,
    ret: i64,
    latency_us: Option<u64>,
    comm: String,
    fd_path: Option<&'a str>,
    ioctl_cmd: Option<u32>,
    arg_payload: Option<[u8; 124]>,
    rwx_marker: Option<u8>,
    binder_args: Option<[u64; 6]>,
}

impl<'a> SyscallEventLens<'a> {
    /// Build a lens from a `SyscallEvent`. `comm` and `fd_path` are passed
    /// in pre-resolved (the caller already does both for the JSON
    /// formatter). `latency_us` is the value computed by
    /// `decode::compute_latency_us` for exit events.
    pub fn new(
        ev: &SyscallEvent,
        comm: String,
        fd_path: Option<&'a str>,
        latency_us: Option<u64>,
    ) -> Self {
        let nr = { ev.syscall_nr };
        let is_enter = { ev.is_enter } == 1;
        let data = { ev.data };
        let args = { ev.args };

        let ioctl_cmd = if nr == 29 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        };
        let arg_payload = if nr == 29 {
            let mut buf = [0u8; 124];
            buf.copy_from_slice(&data[4..128]);
            Some(buf)
        } else {
            None
        };
        let rwx_marker = if matches!(nr, 222 | 226) {
            match data[0] {
                v @ (1 | 2) => Some(v),
                _ => None,
            }
        } else {
            None
        };
        let binder_args = if nr == -1 { Some(args) } else { None };

        Self {
            pid: { ev.pid },
            uid: { ev.uid },
            nr,
            is_enter,
            ret: { ev.ret },
            latency_us,
            comm,
            fd_path,
            ioctl_cmd,
            arg_payload,
            rwx_marker,
            binder_args,
        }
    }
}

impl<'a> EventLens for SyscallEventLens<'a> {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn uid(&self) -> u32 {
        self.uid
    }
    fn syscall_nr(&self) -> i32 {
        self.nr
    }
    fn is_enter(&self) -> bool {
        self.is_enter
    }
    fn ret(&self) -> i64 {
        self.ret
    }
    fn latency_us(&self) -> Option<u64> {
        self.latency_us
    }
    fn comm(&self) -> &str {
        &self.comm
    }
    fn fd_path(&self) -> Option<&str> {
        self.fd_path
    }
    fn ioctl_cmd(&self) -> Option<u32> {
        self.ioctl_cmd
    }
    fn arg_payload(&self) -> Option<&[u8]> {
        self.arg_payload.as_ref().map(|b| b.as_slice())
    }
    fn rwx_marker(&self) -> Option<u8> {
        self.rwx_marker
    }
    fn binder_to_proc(&self) -> Option<u32> {
        self.binder_args.map(|a| a[0] as u32)
    }
    fn binder_to_thread(&self) -> Option<u32> {
        self.binder_args.map(|a| a[3] as u32)
    }
    fn binder_code(&self) -> Option<u32> {
        self.binder_args.map(|a| a[1] as u32)
    }
    fn binder_flags(&self) -> Option<u32> {
        self.binder_args.map(|a| a[2] as u32)
    }
    fn binder_target_node(&self) -> Option<i32> {
        self.binder_args.map(|a| a[5] as i32)
    }
    fn binder_reply(&self) -> Option<bool> {
        self.binder_args.map(|a| a[4] != 0)
    }
}

// ── Userspace evaluator (post-filter) ───────────────────────────────────────

/// Trait the matcher uses to read fields from a parsed event. Decouples
/// the evaluator from `SyscallEvent` / `neutron_rules::Event` so it can be
/// unit-tested without either dependency.
pub trait EventLens {
    fn pid(&self) -> u32;
    fn uid(&self) -> u32;
    fn syscall_nr(&self) -> i32;
    fn is_enter(&self) -> bool;
    fn ret(&self) -> i64;
    fn latency_us(&self) -> Option<u64>;
    fn comm(&self) -> &str;
    fn fd_path(&self) -> Option<&str>;
    fn ioctl_cmd(&self) -> Option<u32>;
    fn arg_payload(&self) -> Option<&[u8]>;
    fn rwx_marker(&self) -> Option<u8>; // 1 = RWX, 2 = WX
    /// Binder field accessors. For non-binder events these return `None`.
    fn binder_to_proc(&self) -> Option<u32>;
    fn binder_to_thread(&self) -> Option<u32>;
    fn binder_code(&self) -> Option<u32>;
    fn binder_flags(&self) -> Option<u32>;
    fn binder_target_node(&self) -> Option<i32>;
    fn binder_reply(&self) -> Option<bool>;
}

/// Evaluate the full predicate against an event view. Used as the post-
/// BPF userspace filter (so arg.u8/u16/u64, fd_path globs, comm globs,
/// and binder fields are honoured) AND as the unit-test entry point.
///
/// Semantics: AND-conjunction. Empty clauses are vacuously true.
pub fn evaluate(spec: &MatchSpec, ev: &dyn EventLens) -> bool {
    if !spec.pids.is_empty() && !spec.pids.contains(&ev.pid()) {
        return false;
    }
    if !spec.uids.is_empty() && !spec.uids.contains(&ev.uid()) {
        return false;
    }
    if !spec.syscalls.is_empty() && !spec.syscalls.contains(&ev.syscall_nr()) {
        return false;
    }
    if !spec.comm_globs.is_empty() {
        let comm = ev.comm();
        if !spec.comm_globs.iter().any(|g| glob_match(g, comm)) {
            return false;
        }
    }
    if !spec.fd_globs.is_empty() {
        match ev.fd_path() {
            None => return false,
            Some(path) => {
                if !spec.fd_globs.iter().any(|g| glob_match(g, path)) {
                    return false;
                }
            }
        }
    }
    // ioctl-shape predicates only apply when this is an ioctl event.
    let any_ioctl_clause = !spec.ioctl_cmds.is_empty()
        || !spec.ioctl_types.is_empty()
        || !spec.ioctl_nrs.is_empty()
        || spec.ioctl_dir.is_some()
        || !spec.arg_clauses.is_empty();
    if any_ioctl_clause {
        let cmd = match ev.ioctl_cmd() {
            Some(c) => c,
            None => return false,
        };
        if !spec.ioctl_cmds.is_empty() && !spec.ioctl_cmds.contains(&cmd) {
            return false;
        }
        let ty = (cmd >> 8) & 0xff;
        if !spec.ioctl_types.is_empty() && !spec.ioctl_types.contains(&ty) {
            return false;
        }
        let nr = cmd & 0xff;
        if !spec.ioctl_nrs.is_empty() && !spec.ioctl_nrs.contains(&nr) {
            return false;
        }
        if let Some(want) = spec.ioctl_dir {
            let dir = (cmd >> 30) & 0x3;
            if dir != want.as_u32() {
                return false;
            }
        }
        if !spec.arg_clauses.is_empty() {
            let payload = match ev.arg_payload() {
                Some(p) => p,
                None => return false,
            };
            for clause in &spec.arg_clauses {
                if !arg_clause_matches(clause, payload) {
                    return false;
                }
            }
        }
    }
    if spec.ret_class != RetClass::Any && !ev.is_enter() {
        // Only meaningful for exit events. Enter events pass through; the
        // pair-event for the exit will be evaluated separately.
        if !spec.ret_class.matches(ev.ret()) {
            return false;
        }
    }
    if let Some(min_us) = spec.latency_min_us {
        if !ev.is_enter() {
            match ev.latency_us() {
                Some(l) if l >= min_us => {}
                _ => return false,
            }
        }
    }
    if spec.prot_rwx || spec.prot_wx {
        let marker = ev.rwx_marker();
        let rwx_ok = spec.prot_rwx && marker == Some(1);
        let wx_ok = spec.prot_wx && marker == Some(2);
        if !(rwx_ok || wx_ok) {
            return false;
        }
    }
    if !spec.binder.is_empty() && !binder_clause_matches(&spec.binder, ev) {
        return false;
    }
    true
}

fn arg_clause_matches(clause: &ArgClause, payload: &[u8]) -> bool {
    let width = match clause.width {
        Some(w) => w,
        None => return true, // never instantiated without width — defensive.
    };
    let off = clause.offset as usize;
    let size = width.size_bytes();
    if off.saturating_add(size) > payload.len() {
        return false;
    }
    let v: u64 = match width {
        ArgWidth::U8 => payload[off] as u64,
        ArgWidth::U16 => u16::from_le_bytes([payload[off], payload[off + 1]]) as u64,
        ArgWidth::U32 => u32::from_le_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
        ]) as u64,
        ArgWidth::U64 => u64::from_le_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]),
    };
    clause.values.contains(&v)
}

fn binder_clause_matches(c: &BinderClause, ev: &dyn EventLens) -> bool {
    if !c.to_proc.is_empty() {
        match ev.binder_to_proc() {
            Some(v) if c.to_proc.contains(&v) => {}
            _ => return false,
        }
    }
    if !c.to_thread.is_empty() {
        match ev.binder_to_thread() {
            Some(v) if c.to_thread.contains(&v) => {}
            _ => return false,
        }
    }
    if !c.code.is_empty() {
        match ev.binder_code() {
            Some(v) if c.code.contains(&v) => {}
            _ => return false,
        }
    }
    if !c.flags.is_empty() {
        match ev.binder_flags() {
            Some(v) if c.flags.contains(&v) => {}
            _ => return false,
        }
    }
    if !c.target_node.is_empty() {
        match ev.binder_target_node() {
            Some(v) if c.target_node.contains(&v) => {}
            _ => return false,
        }
    }
    if let Some(want) = c.reply {
        match ev.binder_reply() {
            Some(v) if v == want => {}
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory event view for unit tests. Mirrors the production
    /// adapter at the field level so behavioural changes show up here too.
    #[derive(Default)]
    struct TestEvent {
        pid: u32,
        uid: u32,
        nr: i32,
        is_enter: bool,
        ret: i64,
        latency_us: Option<u64>,
        comm: String,
        fd_path: Option<String>,
        ioctl_cmd: Option<u32>,
        arg_payload: Option<Vec<u8>>,
        rwx_marker: Option<u8>,
        binder_to_proc: Option<u32>,
        binder_code: Option<u32>,
    }

    impl EventLens for TestEvent {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn uid(&self) -> u32 {
            self.uid
        }
        fn syscall_nr(&self) -> i32 {
            self.nr
        }
        fn is_enter(&self) -> bool {
            self.is_enter
        }
        fn ret(&self) -> i64 {
            self.ret
        }
        fn latency_us(&self) -> Option<u64> {
            self.latency_us
        }
        fn comm(&self) -> &str {
            &self.comm
        }
        fn fd_path(&self) -> Option<&str> {
            self.fd_path.as_deref()
        }
        fn ioctl_cmd(&self) -> Option<u32> {
            self.ioctl_cmd
        }
        fn arg_payload(&self) -> Option<&[u8]> {
            self.arg_payload.as_deref()
        }
        fn rwx_marker(&self) -> Option<u8> {
            self.rwx_marker
        }
        fn binder_to_proc(&self) -> Option<u32> {
            self.binder_to_proc
        }
        fn binder_to_thread(&self) -> Option<u32> {
            None
        }
        fn binder_code(&self) -> Option<u32> {
            self.binder_code
        }
        fn binder_flags(&self) -> Option<u32> {
            None
        }
        fn binder_target_node(&self) -> Option<i32> {
            None
        }
        fn binder_reply(&self) -> Option<bool> {
            None
        }
    }

    #[test]
    fn empty_spec_matches_anything() {
        let s = MatchSpec::default();
        let ev = TestEvent::default();
        assert!(evaluate(&s, &ev));
        assert!(s.is_empty());
    }

    #[test]
    fn pid_set_filters_correctly() {
        let mut s = MatchSpec::default();
        s.pids.insert(970);
        let ev_a = TestEvent {
            pid: 970,
            ..TestEvent::default()
        };
        let ev_b = TestEvent {
            pid: 1234,
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &ev_a));
        assert!(!evaluate(&s, &ev_b));
    }

    #[test]
    fn syscall_set_filters_by_nr() {
        let mut s = MatchSpec::default();
        s.syscalls.insert(29);
        let ioctl = TestEvent {
            nr: 29,
            ..TestEvent::default()
        };
        let mmap = TestEvent {
            nr: 222,
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &ioctl));
        assert!(!evaluate(&s, &mmap));
    }

    #[test]
    fn ioctl_clauses_require_ioctl_event() {
        let mut s = MatchSpec::default();
        s.ioctl_types.insert(0x4c);
        let non_ioctl = TestEvent {
            nr: 222,
            ..TestEvent::default()
        };
        assert!(
            !evaluate(&s, &non_ioctl),
            "non-ioctl event must fail an ioctl-shape clause"
        );
    }

    #[test]
    fn ioctl_cmd_extracts_type_and_nr() {
        // _IOWR('L', 100, ...) = 0xc0xx_4c64. Build a synthetic cmd with
        // type=0x4c, nr=0x64.
        let cmd = (3u32 << 30) | (16u32 << 16) | (0x4cu32 << 8) | 0x64;
        let mut s = MatchSpec::default();
        s.ioctl_types.insert(0x4c);
        s.ioctl_nrs.insert(0x64);
        let ev = TestEvent {
            nr: 29,
            ioctl_cmd: Some(cmd),
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &ev));
        let mut s2 = MatchSpec::default();
        s2.ioctl_types.insert(0x99);
        assert!(!evaluate(&s2, &ev));
    }

    #[test]
    fn fd_glob_matches_path_prefix() {
        let mut s = MatchSpec::default();
        s.fd_globs.push("/dev/lwis*".into());
        let on = TestEvent {
            nr: 29,
            fd_path: Some("/dev/lwis-top".into()),
            ..TestEvent::default()
        };
        let off = TestEvent {
            nr: 29,
            fd_path: Some("/dev/binder".into()),
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &on));
        assert!(!evaluate(&s, &off));
    }

    #[test]
    fn fd_glob_requires_fd_path_to_be_present() {
        let mut s = MatchSpec::default();
        s.fd_globs.push("/dev/*".into());
        let no_fd = TestEvent {
            nr: 29,
            fd_path: None,
            ..TestEvent::default()
        };
        assert!(
            !evaluate(&s, &no_fd),
            "events without resolved fd_path must fail"
        );
    }

    #[test]
    fn arg_u32_at_offset_matches_lwis_cmd_id() {
        // LWIS_CMD_PACKET ioctl: cmd_id at arg.u32@0 = 0x20200.
        let mut payload = vec![0u8; 16];
        payload[..4].copy_from_slice(&0x20200u32.to_le_bytes());
        let mut s = MatchSpec::default();
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U32),
            offset: 0,
            values: [0x20200u64].into_iter().collect(),
        });
        s.ioctl_cmds.insert(0xc010_4c64); // arbitrary, just to drive the ioctl branch
        let ev = TestEvent {
            nr: 29,
            ioctl_cmd: Some(0xc010_4c64),
            arg_payload: Some(payload),
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &ev));
    }

    #[test]
    fn arg_u32_offset_out_of_range_fails_safely() {
        let mut s = MatchSpec::default();
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U32),
            offset: 8, // payload is only 4 bytes
            values: [0u64].into_iter().collect(),
        });
        s.ioctl_cmds.insert(0x1234);
        let ev = TestEvent {
            nr: 29,
            ioctl_cmd: Some(0x1234),
            arg_payload: Some(vec![0u8; 4]),
            ..TestEvent::default()
        };
        assert!(!evaluate(&s, &ev));
    }

    #[test]
    fn ret_class_negative_matches_negative_only() {
        let s = MatchSpec {
            ret_class: RetClass::Negative,
            ..MatchSpec::default()
        };
        let ok = TestEvent {
            nr: 29,
            is_enter: false,
            ret: -22,
            ..TestEvent::default()
        };
        let bad = TestEvent {
            nr: 29,
            is_enter: false,
            ret: 0,
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &ok));
        assert!(!evaluate(&s, &bad));
    }

    #[test]
    fn latency_min_filters_exit_only() {
        let s = MatchSpec {
            latency_min_us: Some(1_000),
            ..MatchSpec::default()
        };
        let slow = TestEvent {
            nr: 29,
            is_enter: false,
            latency_us: Some(5_000),
            ..TestEvent::default()
        };
        let fast = TestEvent {
            nr: 29,
            is_enter: false,
            latency_us: Some(10),
            ..TestEvent::default()
        };
        let enter = TestEvent {
            nr: 29,
            is_enter: true,
            latency_us: None,
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &slow));
        assert!(!evaluate(&s, &fast));
        // enter events should not be filtered by latency (it's exit-only).
        assert!(evaluate(&s, &enter));
    }

    #[test]
    fn comm_glob_matches_substring_pattern() {
        let mut s = MatchSpec::default();
        s.comm_globs.push("camera*".into());
        let on = TestEvent {
            nr: 29,
            comm: "cameraserver".into(),
            ..TestEvent::default()
        };
        let off = TestEvent {
            nr: 29,
            comm: "audioserver".into(),
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &on));
        assert!(!evaluate(&s, &off));
    }

    #[test]
    fn binder_code_filters_only_when_provided() {
        let mut s = MatchSpec::default();
        s.binder.code.insert(42);
        let bind_match = TestEvent {
            nr: -1,
            binder_code: Some(42),
            binder_to_proc: Some(100),
            ..TestEvent::default()
        };
        let bind_miss = TestEvent {
            nr: -1,
            binder_code: Some(7),
            binder_to_proc: Some(100),
            ..TestEvent::default()
        };
        assert!(evaluate(&s, &bind_match));
        assert!(!evaluate(&s, &bind_miss));
    }

    #[test]
    fn glob_match_handles_question_mark_and_star() {
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(glob_match("a*", "abc"));
        assert!(glob_match("*c", "abc"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "abdc"));
        assert!(glob_match("/dev/lwis*", "/dev/lwis-top"));
        assert!(!glob_match("/dev/lwis*", "/dev/binder"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn parse_u32_one_supports_radix_prefixes() {
        assert_eq!(parse_u32_one("42").unwrap(), 42);
        assert_eq!(parse_u32_one("0x4c").unwrap(), 0x4c);
        assert_eq!(parse_u32_one("0X4C").unwrap(), 0x4c);
        assert_eq!(parse_u32_one("0b1010").unwrap(), 10);
        assert_eq!(parse_u32_one("0o17").unwrap(), 15);
    }

    #[test]
    fn parse_u32_list_with_ranges_expands_inclusive() {
        let v = parse_u32_list_with_ranges("10100..10103,20000").unwrap();
        assert_eq!(v, vec![10100, 10101, 10102, 10103, 20000]);
    }

    #[test]
    fn parse_u32_list_with_ranges_rejects_too_large() {
        let err = parse_u32_list_with_ranges("0..10000").unwrap_err();
        assert!(format!("{err:#}").contains("too large"));
    }

    #[test]
    fn parse_latency_us_supports_unit_suffix() {
        assert_eq!(parse_latency_us("100").unwrap(), 100);
        assert_eq!(parse_latency_us("100us").unwrap(), 100);
        assert_eq!(parse_latency_us("5ms").unwrap(), 5_000);
        assert_eq!(parse_latency_us("2s").unwrap(), 2_000_000);
    }

    #[test]
    fn ret_class_round_trips_via_string() {
        assert_eq!(
            RetClass::from_str_relaxed("nonzero").unwrap(),
            RetClass::Nonzero
        );
        assert_eq!(
            RetClass::from_str_relaxed("negative").unwrap(),
            RetClass::Negative
        );
        assert_eq!(RetClass::from_str_relaxed("any").unwrap(), RetClass::Any);
        assert!(RetClass::from_str_relaxed("garbage").is_err());
    }

    #[test]
    fn ioctl_dir_round_trips_via_string() {
        assert_eq!(IoctlDir::from_str_relaxed("rw").unwrap(), IoctlDir::Rw);
        assert_eq!(IoctlDir::from_str_relaxed("Read").unwrap(), IoctlDir::Read);
        assert_eq!(IoctlDir::from_str_relaxed("None").unwrap(), IoctlDir::None);
        assert!(IoctlDir::from_str_relaxed("xy").is_err());
    }

    #[test]
    fn needs_state_events_only_when_fd_globs_present() {
        let mut s = MatchSpec::default();
        s.syscalls.insert(29);
        assert!(!s.needs_state_events());
        s.fd_globs.push("/dev/*".into());
        assert!(s.needs_state_events());
    }

    #[test]
    fn build_from_args_translates_flag_set() {
        use crate::cli::Args;
        let args = Args {
            pid: 970,
            match_pid: vec!["1000,2000".into()],
            match_uid: vec!["10100..10102,1047".into()],
            match_syscall: vec!["29".into(), "222".into()],
            match_fd: vec!["/dev/lwis*,/dev/gxp".into()],
            match_comm: vec!["camera*".into()],
            match_ioctl_cmd: vec!["0xc0104c64".into()],
            match_ioctl_type: vec!["0x4c".into()],
            match_ioctl_nr: vec!["100".into()],
            match_ioctl_dir: Some("rw".into()),
            match_ret: Some("nonzero".into()),
            match_latency_min: Some("5ms".into()),
            match_prot_rwx: true,
            match_arg_u32: vec!["0=0x20200,0x40200".into()],
            match_binder_code: vec!["42".into()],
            ..Args::default()
        };
        let spec = build_from_args(&args).expect("parse");

        // pid: --pid 970 + --match-pid 1000,2000 → 970,1000,2000
        let pids: Vec<u32> = spec.pids.iter().copied().collect();
        assert_eq!(pids, vec![970, 1000, 2000]);

        // uid range expanded
        let uids: Vec<u32> = spec.uids.iter().copied().collect();
        assert_eq!(uids, vec![1047, 10100, 10101, 10102]);

        let mut nrs: Vec<i32> = spec.syscalls.iter().copied().collect();
        nrs.sort();
        assert_eq!(nrs, vec![29, 222]);

        assert_eq!(
            spec.fd_globs,
            vec!["/dev/lwis*".to_string(), "/dev/gxp".to_string()]
        );
        assert_eq!(spec.comm_globs, vec!["camera*".to_string()]);
        assert!(spec.ioctl_cmds.contains(&0xc010_4c64));
        assert!(spec.ioctl_types.contains(&0x4c));
        assert!(spec.ioctl_nrs.contains(&100));
        assert_eq!(spec.ioctl_dir, Some(IoctlDir::Rw));
        assert_eq!(spec.ret_class, RetClass::Nonzero);
        assert_eq!(spec.latency_min_us, Some(5_000));
        assert!(spec.prot_rwx);
        assert!(!spec.prot_wx);

        let arg = spec.bpf_arg_u32().expect("single arg.u32");
        assert_eq!(arg.offset, 0);
        assert!(arg.values.contains(&0x20200));
        assert!(arg.values.contains(&0x40200));

        assert!(spec.binder.code.contains(&42));
    }

    #[test]
    fn build_from_args_rejects_oversized_ioctl_byte() {
        use crate::cli::Args;
        let args = Args {
            match_ioctl_type: vec!["0x100".into()],
            ..Args::default()
        };
        let err = build_from_args(&args).unwrap_err();
        assert!(format!("{err:#}").contains("exceeds 0xff"));
    }

    #[test]
    fn build_from_args_rejects_arg_offset_out_of_window() {
        use crate::cli::Args;
        let args = Args {
            match_arg_u32: vec!["121=0".into()],
            ..Args::default()
        };
        let err = build_from_args(&args).unwrap_err();
        assert!(format!("{err:#}").contains("out of range"));
    }

    #[test]
    fn audit_lines_split_bpf_and_userspace() {
        let mut s = MatchSpec::default();
        s.syscalls.insert(29);
        s.fd_globs.push("/dev/lwis*".into());
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U32),
            offset: 0,
            values: [0x20200u64].into_iter().collect(),
        });
        let lines = s.audit_lines();
        let bpf_lines: Vec<&String> = lines.iter().filter(|l| l.starts_with("[bpf]")).collect();
        let user_lines: Vec<&String> = lines.iter().filter(|l| l.starts_with("[user]")).collect();
        assert!(
            bpf_lines.iter().any(|l| l.contains("syscall")),
            "syscall must be classified as bpf-side"
        );
        assert!(
            bpf_lines.iter().any(|l| l.contains("arg.u32@0")),
            "single-offset arg.u32 must land on bpf side"
        );
        assert!(
            user_lines.iter().any(|l| l.contains("fd_path")),
            "fd_path must always be userspace-only"
        );
    }

    #[test]
    fn audit_lines_promote_extra_arg_widths_to_userspace() {
        let mut s = MatchSpec::default();
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U16),
            offset: 4,
            values: [0xabcdu64].into_iter().collect(),
        });
        let lines = s.audit_lines();
        assert!(lines.iter().any(|l| l.starts_with("[user] arg.u16@4")));
    }

    #[test]
    fn bpf_arg_u32_returns_single_offset_only() {
        let mut s = MatchSpec::default();
        assert!(s.bpf_arg_u32().is_none());
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U32),
            offset: 0,
            values: [0x20200u64].into_iter().collect(),
        });
        assert!(s.bpf_arg_u32().is_some());
        s.arg_clauses.push(ArgClause {
            width: Some(ArgWidth::U32),
            offset: 4,
            values: [0u64].into_iter().collect(),
        });
        assert!(s.bpf_arg_u32().is_none(), "two offsets must degrade");
    }
}
