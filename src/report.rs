//! Markdown boundary reports and Binder attribution helpers.
//!
//! The report path intentionally works over `serde_json::Value` instead of
//! the live `SyscallEvent` wire type. Captures contain synthesized events
//! (`binder_call`, `finding`, `capture_health`, markers, snapshots) and older
//! field variants, so the post-processor stays tolerant and streaming.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

use crate::aidl::{normalize_descriptor, AidlCatalog};
use crate::binder_services::BinderServiceMap;
use crate::capture_input::{read_capture_record, validate_capture_strings, MAX_CAPTURE_RECORDS};
use crate::summarize::open_capture;

const MAX_REPORT_GROUPS: usize = 100_000;
const MAX_REPORT_STRING_BYTES: usize = 64 * 1024 * 1024;
const MAX_AUXILIARY_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Parser, Debug)]
pub struct ReportArgs {
    /// Path to the NDJSON capture file (`-` for stdin).
    pub capture: String,

    /// Optional baseline NDJSON capture. Adds a "New Behavior" diff section.
    #[arg(long, value_name = "NDJSON")]
    pub baseline: Option<String>,

    /// Markdown title. Defaults to "Neutron Boundary Report".
    #[arg(long)]
    pub title: Option<String>,

    /// Package label to show in the traced scope. Neutron does not infer this
    /// from `comm`; pass it explicitly or capture with --match-package.
    #[arg(long)]
    pub package: Option<String>,

    /// JSON file mapping exact `(callee_pid,target_node) -> service` Binder labels.
    #[arg(long, value_name = "FILE")]
    pub binder_services: Option<String>,

    /// Candidate PID -> services catalog, usually from `binder-map service-list`.
    #[arg(long, value_name = "FILE")]
    pub binder_catalog: Option<String>,

    /// Descriptor-centric AIDL transaction catalog used with exact service maps.
    #[arg(long, value_name = "FILE")]
    pub aidl_catalog: Option<String>,

    /// Maximum rows per table. `0` prints all rows.
    #[arg(long, default_value_t = 10)]
    pub top: usize,

    /// Write Markdown to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum BinderMapCommand {
    /// Build an editable service-map template from unresolved binder_call pairs.
    Template(BinderTemplateArgs),
    /// Parse best-effort `service list -p` output into a PID candidate catalog.
    ServiceList(ServiceListArgs),
}

#[derive(Parser, Debug)]
pub struct BinderTemplateArgs {
    /// Path to the NDJSON capture file (`-` for stdin).
    pub capture: String,

    /// Write JSON to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ServiceListArgs {
    /// Input from `adb shell service list -p` (`-` or omitted for stdin).
    #[arg(long, default_value = "-", value_name = "FILE|-")]
    pub input: String,

    /// Write JSON to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ReportOptions {
    pub title: Option<String>,
    pub package: Option<String>,
    pub binder_services_json: Option<String>,
    pub binder_catalog_json: Option<String>,
    pub aidl_catalog_json: Option<String>,
    pub baseline_capture: Option<String>,
    pub top: usize,
}

#[derive(Clone, Debug, Default)]
struct Snapshot {
    parsed_events: u64,
    health: Option<Value>,
    malformed_records: u64,
    unusable_binder_identity_records: u64,
    scenario_unusable_binder_identity_records: u64,
    health_records: u64,
    final_record_is_health: bool,
    pids: CountMap,
    uids: CountMap,
    comms: CountMap,
    packages: BTreeSet<String>,
    syscalls: CountMap,
    sensitive_paths: CountMap,
    sockets: CountMap,
    binder_targets: CountMap,
    ioctl_families: CountMap,
    rwx: CountMap,
    findings: CountMap,
    crashes: CountMap,
    markers: Vec<crate::capture_normalize::Marker>,
    scenario_event_bindings: BTreeSet<(String, String)>,
    scenario_syscalls: CountMap,
    scenario_sensitive_paths: CountMap,
    scenario_sockets: CountMap,
    scenario_binder_targets: CountMap,
    scenario_ioctl_families: CountMap,
    scenario_rwx: CountMap,
    scenario_findings: CountMap,
    scenario_crashes: CountMap,
}

type CountMap = BTreeMap<String, u64>;
type BinderCatalog = BTreeMap<u32, Vec<String>>;

#[derive(Clone, Debug, Default)]
struct BinderAttribution {
    services: Option<BinderServiceMap>,
    catalog: BinderCatalog,
    aidl: Option<AidlCatalog>,
}

impl BinderAttribution {
    fn from_options(opts: &ReportOptions) -> Result<Self> {
        let services = match opts.binder_services_json.as_deref() {
            Some(raw) => {
                validate_auxiliary_input(raw, "binder services")?;
                Some(BinderServiceMap::from_json(raw).context("parsing binder services")?)
            }
            None => None,
        };
        let catalog = match opts.binder_catalog_json.as_deref() {
            Some(raw) => {
                validate_auxiliary_input(raw, "binder catalog")?;
                parse_binder_catalog_json(raw).context("parsing binder catalog")?
            }
            None => BinderCatalog::new(),
        };
        if let Some(raw) = opts.aidl_catalog_json.as_deref() {
            validate_auxiliary_input(raw, "AIDL catalog")?;
        }
        let aidl = opts
            .aidl_catalog_json
            .as_deref()
            .map(AidlCatalog::from_json)
            .transpose()
            .context("parsing AIDL catalog")?;
        Ok(Self {
            services,
            catalog,
            aidl,
        })
    }

    fn label_for(&self, obj: &serde_json::Map<String, Value>) -> Option<String> {
        if let Some(service) = str_field(obj, "service") {
            let method = str_field(obj, "method").or_else(|| {
                (str_field(obj, "attribution_confidence") != Some("candidate"))
                    .then(|| {
                        u32_field(obj, "code").and_then(|code| {
                            self.aidl.as_ref().and_then(|catalog| {
                                catalog
                                    .lookup(normalize_descriptor(service), code)
                                    .map(|lookup| lookup.method.method.as_str())
                            })
                        })
                    })
                    .flatten()
            });
            return Some(method.map_or_else(
                || service.to_string(),
                |method| format!("{service}.{method}"),
            ));
        }
        let callee_pid = u32_field(obj, "callee_pid")
            .or_else(|| u32_field(obj, "to_proc"))
            .filter(|pid| *pid > 0)?;
        let target_node = i32_field(obj, "target_node").unwrap_or_default();
        let code = u32_field(obj, "code");
        if let Some(service) = self
            .services
            .as_ref()
            .and_then(|m| m.lookup(callee_pid, target_node))
        {
            let method = code.and_then(|code| {
                self.aidl
                    .as_ref()
                    .and_then(|catalog| catalog.lookup(normalize_descriptor(service), code))
                    .map(|lookup| lookup.method.method.as_str())
            });
            return Some(method.map_or_else(
                || service.to_string(),
                |method| format!("{service}.{method}"),
            ));
        }
        let raw = raw_binder_label(callee_pid, target_node, code);
        if let Some(candidates) = self.catalog.get(&callee_pid).filter(|v| !v.is_empty()) {
            return Some(format!("{raw} (candidates: {})", candidates.join(", ")));
        }
        Some(raw)
    }
}

pub fn run_report(args: ReportArgs) -> Result<()> {
    let (reader, capture_identity) = open_report_capture(&args.capture, "capture")?;
    let baseline_reader = match args.baseline.as_deref() {
        Some("-") if args.capture == "-" => {
            bail!("only one of <capture>/--baseline can be '-' (stdin)");
        }
        Some(path) => {
            let (reader, identity) = open_report_capture(path, "baseline")?;
            if capture_identity.is_some() && capture_identity == identity {
                bail!("capture and baseline refer to the same file; refusing a self-comparison");
            }
            Some(reader)
        }
        None => None,
    };
    let binder_services_json = args
        .binder_services
        .as_deref()
        .map(read_input_to_string)
        .transpose()?;
    let binder_catalog_json = args
        .binder_catalog
        .as_deref()
        .map(read_input_to_string)
        .transpose()?;
    let aidl_catalog_json = args
        .aidl_catalog
        .as_deref()
        .map(read_input_to_string)
        .transpose()?;
    let opts = ReportOptions {
        title: args.title,
        package: args.package,
        binder_services_json,
        binder_catalog_json,
        aidl_catalog_json,
        baseline_capture: None,
        top: args.top,
    };
    let attribution = BinderAttribution::from_options(&opts)?;
    let mut snapshot = collect_snapshot(reader, &attribution).context("reading capture")?;
    if let Some(package) = opts.package.as_deref() {
        snapshot.packages.insert(package.to_string());
    }
    ensure_snapshot_bounds(&snapshot)?;
    let baseline = baseline_reader
        .map(|reader| collect_snapshot(reader, &attribution).context("reading baseline capture"))
        .transpose()?;
    let markdown = render_markdown(&snapshot, baseline.as_ref(), &opts);
    write_output(args.output.as_deref(), markdown.as_bytes())
}

type ReportCaptureReader = (Box<dyn BufRead>, Option<(u64, u64)>);

fn open_report_capture(path: &str, label: &str) -> Result<ReportCaptureReader> {
    if path == "-" {
        return Ok((open_capture(path)?, None));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {label} capture {path}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} capture {path}"))?;
    if !metadata.is_file() {
        bail!("{label} capture must be a regular file: {path}");
    }
    let identity = (metadata.dev(), metadata.ino());
    Ok((Box::new(BufReader::new(file)), Some(identity)))
}

pub fn run_binder_map(command: BinderMapCommand) -> Result<()> {
    match command {
        BinderMapCommand::Template(args) => {
            let reader = open_capture(&args.capture)?;
            let json = render_binder_template_from_reader(reader)?;
            write_output(args.output.as_deref(), json.as_bytes())
        }
        BinderMapCommand::ServiceList(args) => {
            let reader = open_text_input(&args.input)?;
            let json = render_service_catalog_from_reader(reader)?;
            write_output(args.output.as_deref(), json.as_bytes())
        }
    }
}

pub fn render_report_from_reader<R: BufRead>(reader: R, opts: ReportOptions) -> Result<String> {
    let attribution = BinderAttribution::from_options(&opts)?;
    let mut snapshot = collect_snapshot(reader, &attribution).context("reading capture")?;
    if let Some(package) = opts.package.as_deref() {
        snapshot.packages.insert(package.to_string());
    }

    let baseline = match opts.baseline_capture.as_deref() {
        Some(raw) => Some(
            collect_snapshot(BufReader::new(raw.as_bytes()), &attribution)
                .context("reading baseline capture")?,
        ),
        None => None,
    };

    Ok(render_markdown(&snapshot, baseline.as_ref(), &opts))
}

fn collect_snapshot<R: BufRead>(
    mut reader: R,
    attribution: &BinderAttribution,
) -> Result<Snapshot> {
    let mut snapshot = Snapshot::default();
    let mut record = Vec::new();
    let mut record_number = 1usize;
    let mut string_bytes = 0usize;
    while read_capture_record(&mut reader, &mut record, record_number)? {
        if record_number > MAX_CAPTURE_RECORDS {
            bail!("capture exceeds {MAX_CAPTURE_RECORDS} records");
        }
        let current_record = record_number;
        record_number += 1;
        let trimmed = std::str::from_utf8(&record)
            .with_context(|| format!("capture record {current_record} is not UTF-8"))?
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        snapshot.final_record_is_health = false;
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => {
                snapshot.malformed_records = snapshot.malformed_records.saturating_add(1);
                continue;
            }
        };
        string_bytes = string_bytes
            .checked_add(validate_capture_strings(&value, current_record)?)
            .context("report capture string byte count overflow")?;
        if string_bytes > MAX_REPORT_STRING_BYTES {
            bail!("report capture strings exceed {MAX_REPORT_STRING_BYTES} bytes");
        }
        let Some(obj) = value.as_object() else {
            snapshot.malformed_records = snapshot.malformed_records.saturating_add(1);
            continue;
        };
        let Some(kind) = str_field(obj, "type") else {
            snapshot.malformed_records = snapshot.malformed_records.saturating_add(1);
            continue;
        };
        if kind == "capture_health" {
            ingest_health(&mut snapshot, &value);
            snapshot.final_record_is_health = true;
            ensure_snapshot_bounds(&snapshot)?;
            continue;
        }
        snapshot.parsed_events = snapshot.parsed_events.saturating_add(1);
        if !recognized_event_valid(kind, obj) {
            snapshot.malformed_records = snapshot.malformed_records.saturating_add(1);
            continue;
        }
        if unusable_raw_binder_identity(kind, obj) {
            snapshot.unusable_binder_identity_records =
                snapshot.unusable_binder_identity_records.saturating_add(1);
            if obj.contains_key("scenario_id") || obj.contains_key("trace_id") {
                snapshot.scenario_unusable_binder_identity_records = snapshot
                    .scenario_unusable_binder_identity_records
                    .saturating_add(1);
            }
        }
        if kind == "marker" {
            snapshot.markers.push(crate::capture_normalize::Marker {
                ts_ns: u64_field(obj, "ts_ns"),
                name: str_field(obj, "name").unwrap_or_default().to_string(),
                phase: str_field(obj, "phase").map(str::to_string),
                scenario_id: str_field(obj, "scenario_id").map(str::to_string),
                trace_id: str_field(obj, "trace_id").map(str::to_string),
                root_package: str_field(obj, "root_package").map(str::to_string),
                root_uid: u32_field(obj, "root_uid"),
                root_pid: u32_field(obj, "root_pid"),
            });
        }
        ingest_scope(&mut snapshot, obj);
        ingest_event(&mut snapshot, obj, attribution);
        ensure_snapshot_bounds(&snapshot)?;
    }
    Ok(snapshot)
}

fn ensure_snapshot_bounds(snapshot: &Snapshot) -> Result<()> {
    let groups = snapshot
        .pids
        .len()
        .saturating_add(snapshot.uids.len())
        .saturating_add(snapshot.comms.len())
        .saturating_add(snapshot.packages.len())
        .saturating_add(snapshot.syscalls.len())
        .saturating_add(snapshot.sensitive_paths.len())
        .saturating_add(snapshot.sockets.len())
        .saturating_add(snapshot.binder_targets.len())
        .saturating_add(snapshot.ioctl_families.len())
        .saturating_add(snapshot.rwx.len())
        .saturating_add(snapshot.findings.len())
        .saturating_add(snapshot.crashes.len());
    if groups > MAX_REPORT_GROUPS {
        bail!("report capture exceeds {MAX_REPORT_GROUPS} aggregate groups");
    }
    Ok(())
}

fn recognized_event_valid(kind: &str, obj: &serde_json::Map<String, Value>) -> bool {
    let nonzero = |key| u64_field(obj, key).is_some_and(|value| value > 0);
    match kind {
        "syscall" => nonzero("pid") && syscall_name(obj).is_some(),
        "binder" => {
            nonzero("pid")
                && u32_field(obj, "to_proc").is_some()
                && i64_field(obj, "debug_id").is_some()
        }
        "binder_call" => {
            nonzero("caller_pid")
                && nonzero("callee_pid")
                && i64_field(obj, "debug_id").is_some_and(|value| value != 0)
        }
        "binder_received" => nonzero("pid") && i64_field(obj, "debug_id").is_some(),
        "process_exit" | "selinux_denial" | "fd_snapshot" => nonzero("pid"),
        "finding" => str_field(obj, "rule_id").is_some_and(|value| !value.is_empty()),
        "marker" => str_field(obj, "name").is_some_and(|value| !value.is_empty()),
        "process_maps" => nonzero("pid") && obj.get("mappings").is_some_and(Value::is_array),
        "stack_trace" => {
            nonzero("pid")
                && str_field(obj, "stack_trace_ref").is_some_and(|value| !value.is_empty())
        }
        "follow_guardrail" => {
            nonzero("caller_pid")
                && nonzero("callee_pid")
                && str_field(obj, "status").is_some()
                && str_field(obj, "reason").is_some()
        }
        _ => false,
    }
}

fn unusable_raw_binder_identity(kind: &str, obj: &serde_json::Map<String, Value>) -> bool {
    match kind {
        "binder" => i64_field(obj, "debug_id") == Some(0) || u32_field(obj, "to_proc") == Some(0),
        "binder_received" => i64_field(obj, "debug_id") == Some(0),
        _ => false,
    }
}

fn ingest_health(snapshot: &mut Snapshot, value: &Value) {
    if let Some(obj) = value.as_object() {
        snapshot.health_records = snapshot.health_records.saturating_add(1);
        if !crate::health::capture_health_contract_errors(obj).is_empty() {
            snapshot.malformed_records = snapshot.malformed_records.saturating_add(1);
        }
        for pkg in string_array(obj.get("match_packages")) {
            snapshot.packages.insert(pkg);
        }
        for uid in string_array(obj.get("match_uids")) {
            increment(&mut snapshot.uids, uid);
        }
        for pid in string_array(obj.get("match_pids")) {
            increment(&mut snapshot.pids, pid);
        }
    }
    snapshot.health = Some(value.clone());
}

fn ingest_scope(snapshot: &mut Snapshot, obj: &serde_json::Map<String, Value>) {
    if let Some(pid) = u64_field(obj, "pid")
        .or_else(|| u64_field(obj, "caller_pid"))
        .or_else(|| u64_field(obj, "callee_pid"))
    {
        increment(&mut snapshot.pids, pid.to_string());
    }
    if let Some(uid) = u64_field(obj, "uid").or_else(|| u64_field(obj, "caller_uid")) {
        increment(&mut snapshot.uids, uid.to_string());
    }
    if let Some(comm) = str_field(obj, "comm").or_else(|| str_field(obj, "caller_comm")) {
        increment(&mut snapshot.comms, comm.to_string());
    }
}

fn ingest_event(
    snapshot: &mut Snapshot,
    obj: &serde_json::Map<String, Value>,
    attribution: &BinderAttribution,
) {
    let ty = str_field(obj, "type").unwrap_or("");
    let syscall = syscall_name(obj);
    if let Some(name) = syscall.as_deref() {
        increment(&mut snapshot.syscalls, name.to_string());
    }
    if let Some(path) = event_path(obj).filter(|path| is_sensitive_path(path)) {
        increment(&mut snapshot.sensitive_paths, path.to_string());
    }
    if is_socket_event(obj, syscall.as_deref()) {
        increment(&mut snapshot.sockets, socket_label(obj));
    }
    if matches!(ty, "binder_call" | "binder") {
        if let Some(label) = attribution.label_for(obj) {
            increment(&mut snapshot.binder_targets, label);
        }
    }
    if let Some(label) = ioctl_label(obj) {
        increment(&mut snapshot.ioctl_families, label);
    }
    if let Some(label) = rwx_label(obj, syscall.as_deref()) {
        increment(&mut snapshot.rwx, label);
    }
    if ty == "finding" {
        increment(&mut snapshot.findings, finding_label(obj));
    }
    if ty == "process_exit"
        && (str_field(obj, "classification") == Some("crash")
            || bool_field(obj, "crashed").unwrap_or(false))
    {
        increment(&mut snapshot.crashes, crash_label(obj));
    }
    let Some(scenario_id) = str_field(obj, "scenario_id").filter(|value| !value.is_empty()) else {
        return;
    };
    if ty == "marker" {
        return;
    }
    snapshot.scenario_event_bindings.insert((
        scenario_id.to_string(),
        str_field(obj, "trace_id").unwrap_or_default().to_string(),
    ));
    if let Some(name) = syscall.as_deref() {
        increment(&mut snapshot.scenario_syscalls, name.to_string());
    }
    if let Some(path) = event_path(obj).filter(|path| is_sensitive_path(path)) {
        increment(&mut snapshot.scenario_sensitive_paths, path.to_string());
    }
    if is_socket_event(obj, syscall.as_deref()) {
        increment(&mut snapshot.scenario_sockets, socket_label(obj));
    }
    if matches!(ty, "binder_call" | "binder") {
        if let Some(label) = attribution.label_for(obj) {
            increment(&mut snapshot.scenario_binder_targets, label);
        }
    }
    if let Some(label) = ioctl_label(obj) {
        increment(&mut snapshot.scenario_ioctl_families, label);
    }
    if let Some(label) = rwx_label(obj, syscall.as_deref()) {
        increment(&mut snapshot.scenario_rwx, label);
    }
    if ty == "finding" {
        increment(&mut snapshot.scenario_findings, finding_label(obj));
    }
    if ty == "process_exit"
        && (str_field(obj, "classification") == Some("crash")
            || bool_field(obj, "crashed").unwrap_or(false))
    {
        increment(&mut snapshot.scenario_crashes, crash_label(obj));
    }
}

fn render_markdown(
    snapshot: &Snapshot,
    baseline: Option<&Snapshot>,
    opts: &ReportOptions,
) -> String {
    let mut out = String::new();
    out.push_str("# ");
    out.push_str(&markdown_text(
        opts.title.as_deref().unwrap_or("Neutron Boundary Report"),
    ));
    out.push_str("\n\n");
    render_health(&mut out, snapshot);
    render_scope(&mut out, snapshot);
    render_count_section(&mut out, "Top Syscalls", &snapshot.syscalls, opts.top);
    render_count_section(
        &mut out,
        "Sensitive Paths",
        &snapshot.sensitive_paths,
        opts.top,
    );
    render_count_section(&mut out, "Sockets", &snapshot.sockets, opts.top);
    render_count_section(
        &mut out,
        "Binder Targets",
        &snapshot.binder_targets,
        opts.top,
    );
    render_count_section(
        &mut out,
        "Ioctl Families",
        &snapshot.ioctl_families,
        opts.top,
    );
    render_count_section(&mut out, "mmap / RWX", &snapshot.rwx, opts.top);
    render_findings(&mut out, snapshot, opts.top);
    if let Some(baseline) = baseline {
        let scopes_match = snapshot_capture_scope(snapshot)
            .zip(snapshot_capture_scope(baseline))
            .is_some_and(|(current, baseline)| {
                current.claim_scope_complete && baseline.claim_scope_complete && current == baseline
            });
        let scenarios_match = snapshot_scenario_contract(snapshot)
            .zip(snapshot_scenario_contract(baseline))
            .is_some_and(|(current, baseline)| current.scenarios == baseline.scenarios);
        if snapshot_health_is_complete(snapshot)
            && snapshot_health_is_complete(baseline)
            && scopes_match
            && scenarios_match
        {
            render_diff_section(&mut out, baseline, snapshot, opts.top);
        } else {
            out.push_str("## New Behavior\n\n");
            out.push_str(
                "**WARNING:** behavior diff is nonconclusive because the current capture or baseline lacks exactly one final, structurally valid `complete` health record, an identical claim-complete effective capture scope, or an identical paired scenario lifecycle/root contract.\n\n",
            );
        }
    }
    out
}

fn snapshot_scenario_contract(
    snapshot: &Snapshot,
) -> Option<crate::capture_normalize::ScenarioContract> {
    let contract = crate::capture_normalize::validated_marker_contract(&snapshot.markers).ok()?;
    snapshot
        .scenario_event_bindings
        .iter()
        .all(|(scenario_id, trace_id)| {
            contract.trace_ids.get(scenario_id).map(String::as_str) == Some(trace_id.as_str())
        })
        .then_some(contract)
}

fn snapshot_capture_scope(snapshot: &Snapshot) -> Option<crate::health::CaptureScope> {
    let value = snapshot
        .health
        .as_ref()?
        .as_object()?
        .get("capture_scope")?;
    crate::health::CaptureScope::from_json_value(value).ok()
}

fn snapshot_health_is_complete(snapshot: &Snapshot) -> bool {
    snapshot.malformed_records == 0
        && !invalid_scenario_marker_contract(snapshot)
        && health_scoped_unusable_binder_identities(snapshot) == 0
        && snapshot.health_records == 1
        && snapshot.final_record_is_health
        && snapshot
            .health
            .as_ref()
            .and_then(Value::as_object)
            .is_some_and(crate::health::capture_health_is_complete)
}

fn health_scoped_unusable_binder_identities(snapshot: &Snapshot) -> u64 {
    if snapshot_scenario_contract(snapshot).is_some() {
        snapshot.scenario_unusable_binder_identity_records
    } else {
        snapshot.unusable_binder_identity_records
    }
}

fn invalid_scenario_marker_contract(snapshot: &Snapshot) -> bool {
    !snapshot.markers.is_empty() && snapshot_scenario_contract(snapshot).is_none()
}

fn render_health(out: &mut String, snapshot: &Snapshot) {
    out.push_str("## Capture Health\n\n");
    out.push_str(&format!("Parsed events: {}\n\n", snapshot.parsed_events));
    if snapshot.malformed_records > 0 {
        out.push_str(&format!(
            "**WARNING:** {} malformed, invalid, or unknown NDJSON record(s) were encountered; capture health is `unknown`. Absence of evidence is not conclusive.\n\n",
            snapshot.malformed_records
        ));
    }
    let Some(health) = snapshot.health.as_ref().and_then(Value::as_object) else {
        out.push_str(
            "**WARNING:** no final `capture_health` event was present; the run is incomplete and absence of evidence is not conclusive.\n\n",
        );
        return;
    };
    let degraded = bool_field(health, "degraded").unwrap_or(false);
    let cap_hit = bool_field(health, "output_cap_hit").unwrap_or(false);
    let explicit_status = health.get("status");
    let parsed_status = explicit_status
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "complete" | "degraded" | "incomplete" | "unknown"));
    let mut status = parsed_status.unwrap_or(if explicit_status.is_some() {
        "unknown"
    } else if cap_hit {
        "incomplete"
    } else if degraded {
        "degraded"
    } else {
        "complete"
    });
    let contradictory = parsed_status.is_some_and(|value| {
        (value == "complete" && (degraded || cap_hit))
            || (value != "complete" && bool_field(health, "degraded") == Some(false))
            || (cap_hit && !matches!(value, "incomplete" | "unknown"))
    });
    let binder_identity_contradiction =
        health_scoped_unusable_binder_identities(snapshot) > 0 && parsed_status == Some("complete");
    let marker_contract_invalid = invalid_scenario_marker_contract(snapshot);
    if contradictory
        || binder_identity_contradiction
        || marker_contract_invalid
        || snapshot.malformed_records > 0
        || snapshot.health_records != 1
    {
        status = "unknown";
    } else if !snapshot.final_record_is_health && status != "unknown" {
        status = "incomplete";
    }
    if !snapshot.final_record_is_health {
        out.push_str(
            "**WARNING:** `capture_health` was not the final non-empty record; the run is incomplete.\n\n",
        );
    }
    if contradictory {
        out.push_str(
            "**WARNING:** `capture_health` fields contradict each other; status is `unknown`.\n\n",
        );
    }
    if snapshot.unusable_binder_identity_records > 0 {
        out.push_str(&format!(
            "**WARNING:** capture contains {} raw Binder record(s) with an unusable Binder identity; those records are excluded from causal attribution.\n\n",
            snapshot.unusable_binder_identity_records
        ));
        if binder_identity_contradiction {
            out.push_str(
                "**WARNING:** the raw Binder identity evidence contradicts a `complete` health status; status is `unknown`.\n\n",
            );
        }
    }
    if marker_contract_invalid {
        out.push_str("**WARNING:** scenario marker lifecycle is invalid; status is `unknown`.\n\n");
    }
    if snapshot.health_records > 1 {
        out.push_str(&format!(
            "**WARNING:** capture contains {} `capture_health` records; status is `unknown`.\n\n",
            snapshot.health_records
        ));
    }
    if status != "complete" {
        out.push_str("**WARNING:** capture health is not clean");
        out.push_str(&format!("; status is `{status}`"));
        out.push_str(". Absence of evidence is not conclusive.\n\n");
    }
    if let Some(scope) = health
        .get("capture_scope")
        .and_then(|value| crate::health::CaptureScope::from_json_value(value).ok())
        .filter(|scope| !scope.claim_scope_complete)
    {
        out.push_str(
            "**WARNING:** transport health may be complete, but the effective capture scope is restricted; unfiltered negative claims are not supported. Reasons: ",
        );
        out.push_str(&markdown_text(&scope.claim_scope_reasons.join(", ")));
        out.push_str(".\n\n");
    }
    if cap_hit {
        out.push_str(
            "**WARNING:** the output cap truncated this capture; required evidence may be missing.\n\n",
        );
    }
    for key in [
        "events_userspace",
        "events_submitted",
        "events_matched",
        "events_sampled_out",
        "events_emitted",
        "ringbuf_reserve_failed",
        "fd_graph_miss",
        "fd_graph_backfilled",
        "status",
        "degraded",
        "output_cap_hit",
    ] {
        if let Some(value) = health.get(key) {
            out.push_str(&format!("- `{key}`: {}\n", scalar_to_string(value)));
        }
    }
    out.push('\n');
}

fn render_scope(out: &mut String, snapshot: &Snapshot) {
    out.push_str("## Traced Scope\n\n");
    render_inline_set(out, "Packages", &snapshot.packages);
    render_inline_counts(out, "PIDs", &snapshot.pids, 12);
    render_inline_counts(out, "UIDs", &snapshot.uids, 12);
    render_inline_counts(out, "Comms", &snapshot.comms, 12);
    out.push('\n');
}

fn render_count_section(out: &mut String, title: &str, counts: &CountMap, top: usize) {
    out.push_str("## ");
    out.push_str(title);
    out.push_str("\n\n");
    if counts.is_empty() {
        out.push_str("_No entries observed._\n\n");
        return;
    }
    for (key, count) in sorted_counts(counts, top) {
        out.push_str(&format!("- `{}`: {count}\n", markdown_code(key)));
    }
    if top > 0 && counts.len() > top {
        out.push_str(&format!(
            "- _{} more entries omitted._\n",
            counts.len() - top
        ));
    }
    out.push('\n');
}

fn render_findings(out: &mut String, snapshot: &Snapshot, top: usize) {
    out.push_str("## Crashes / Findings\n\n");
    if snapshot.findings.is_empty() && snapshot.crashes.is_empty() {
        out.push_str("_No finding or crash events observed._\n\n");
        return;
    }
    for (key, count) in sorted_counts(&snapshot.findings, top) {
        out.push_str(&format!("- finding `{}`: {count}\n", markdown_code(key)));
    }
    for (key, count) in sorted_counts(&snapshot.crashes, top) {
        out.push_str(&format!("- crash `{}`: {count}\n", markdown_code(key)));
    }
    out.push('\n');
}

fn render_diff_section(out: &mut String, baseline: &Snapshot, test: &Snapshot, top: usize) {
    out.push_str("## New Behavior\n\n");
    render_count_diff(
        out,
        "syscalls",
        &baseline.scenario_syscalls,
        &test.scenario_syscalls,
        top,
    );
    render_count_diff(
        out,
        "sensitive paths",
        &baseline.scenario_sensitive_paths,
        &test.scenario_sensitive_paths,
        top,
    );
    render_count_diff(
        out,
        "ioctl families",
        &baseline.scenario_ioctl_families,
        &test.scenario_ioctl_families,
        top,
    );
    render_count_diff(
        out,
        "binder targets",
        &baseline.scenario_binder_targets,
        &test.scenario_binder_targets,
        top,
    );
}

fn render_count_diff(
    out: &mut String,
    label: &str,
    baseline: &CountMap,
    test: &CountMap,
    top: usize,
) {
    out.push_str("### ");
    out.push_str(label);
    out.push_str("\n\n");

    let mut rows: Vec<(String, u64, u64)> = BTreeSet::from_iter(
        baseline
            .keys()
            .chain(test.keys())
            .map(std::string::String::as_str),
    )
    .into_iter()
    .filter_map(|key| {
        let b = baseline.get(key).copied().unwrap_or(0);
        let t = test.get(key).copied().unwrap_or(0);
        (b != t).then(|| (key.to_string(), b, t))
    })
    .collect();
    rows.sort_by(|a, b| {
        let a_delta = a.2.abs_diff(a.1);
        let b_delta = b.2.abs_diff(b.1);
        b_delta.cmp(&a_delta).then_with(|| a.0.cmp(&b.0))
    });
    if top > 0 && rows.len() > top {
        rows.truncate(top);
    }
    if rows.is_empty() {
        out.push_str("_No changes._\n\n");
        return;
    }
    for (key, b, t) in rows {
        let key = markdown_text(&key);
        match (b, t) {
            (0, _) => out.push_str(&format!("- + {key} ({t})\n")),
            (_, 0) => out.push_str(&format!("- - {key} ({b})\n")),
            _ => out.push_str(&format!("- ~ {key} ({b} -> {t})\n")),
        }
    }
    out.push('\n');
}

#[derive(Debug, Default, Serialize)]
struct BinderTemplateEntry {
    service: String,
    observed_codes: BTreeMap<String, u64>,
    status_counts: BTreeMap<String, u64>,
}

pub fn render_binder_template_from_reader<R: BufRead>(mut reader: R) -> Result<String> {
    let mut out: BTreeMap<String, BTreeMap<String, BinderTemplateEntry>> = BTreeMap::new();
    let mut record = Vec::new();
    let mut record_number = 1usize;
    let mut string_bytes = 0usize;
    while read_capture_record(&mut reader, &mut record, record_number)? {
        if record_number > MAX_CAPTURE_RECORDS {
            bail!("capture exceeds {MAX_CAPTURE_RECORDS} records");
        }
        let current_record = record_number;
        record_number += 1;
        let trimmed = std::str::from_utf8(&record)
            .with_context(|| format!("capture record {current_record} is not UTF-8"))?
            .trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => continue,
        };
        string_bytes = string_bytes
            .checked_add(validate_capture_strings(&value, current_record)?)
            .context("binder template string byte count overflow")?;
        if string_bytes > MAX_REPORT_STRING_BYTES {
            bail!("binder template strings exceed {MAX_REPORT_STRING_BYTES} bytes");
        }
        let Some(obj) = value.as_object() else {
            continue;
        };
        if str_field(obj, "type") != Some("binder_call") || obj.contains_key("service") {
            continue;
        }
        let Some(pid) = u32_field(obj, "callee_pid") else {
            continue;
        };
        let Some(node) = i32_field(obj, "target_node") else {
            continue;
        };
        let entry = out
            .entry(pid.to_string())
            .or_default()
            .entry(node.to_string())
            .or_default();
        if let Some(code) = u32_field(obj, "code") {
            *entry.observed_codes.entry(code.to_string()).or_insert(0) += 1;
        }
        if let Some(status) = str_field(obj, "status") {
            *entry.status_counts.entry(status.to_string()).or_insert(0) += 1;
        }
        let groups = out
            .values()
            .map(|nodes| {
                nodes
                    .values()
                    .map(|entry| {
                        1usize
                            .saturating_add(entry.observed_codes.len())
                            .saturating_add(entry.status_counts.len())
                    })
                    .sum::<usize>()
            })
            .sum::<usize>();
        if groups > MAX_REPORT_GROUPS {
            bail!("binder template exceeds {MAX_REPORT_GROUPS} aggregate groups");
        }
    }
    let mut json = serde_json::to_string_pretty(&out).context("serializing binder template")?;
    json.push('\n');
    Ok(json)
}

#[derive(Debug, Serialize)]
struct ServiceCatalogEntry {
    services: Vec<String>,
    source: &'static str,
}

pub fn render_service_catalog_from_reader<R: BufRead>(mut reader: R) -> Result<String> {
    let mut input = String::new();
    reader
        .by_ref()
        .take(MAX_AUXILIARY_INPUT_BYTES + 1)
        .read_to_string(&mut input)
        .context("reading service list input")?;
    validate_auxiliary_input(&input, "service list")?;
    let parsed = parse_service_list(&input)?;
    let catalog: BTreeMap<String, ServiceCatalogEntry> = parsed
        .into_iter()
        .map(|(pid, services)| {
            (
                pid.to_string(),
                ServiceCatalogEntry {
                    services,
                    source: "service list -p",
                },
            )
        })
        .collect();
    let mut json = serde_json::to_string_pretty(&catalog).context("serializing binder catalog")?;
    json.push('\n');
    Ok(json)
}

pub fn parse_service_list(input: &str) -> Result<BTreeMap<u32, Vec<String>>> {
    validate_auxiliary_input(input, "service list")?;
    let mut out: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("Found ") {
            continue;
        }
        let Some(pid) = extract_pid(line) else {
            continue;
        };
        let Some(service) = extract_service_name(line) else {
            continue;
        };
        let services = out.entry(pid).or_default();
        if !services.iter().any(|s| s == &service) {
            services.push(service);
            let entries = out.values().map(Vec::len).sum::<usize>();
            if entries > MAX_REPORT_GROUPS {
                bail!("service list exceeds {MAX_REPORT_GROUPS} entries");
            }
        }
    }
    for services in out.values_mut() {
        services.sort();
    }
    Ok(out)
}

fn parse_binder_catalog_json(raw: &str) -> Result<BinderCatalog> {
    validate_auxiliary_input(raw, "binder catalog")?;
    let value: Value = serde_json::from_str(raw).context("expected PID -> services object")?;
    validate_capture_strings(&value, 1).context("validating binder catalog strings")?;
    let Some(obj) = value.as_object() else {
        bail!("expected PID -> services object");
    };
    let mut out = BinderCatalog::new();
    for (pid_s, entry) in obj {
        let pid: u32 = pid_s
            .parse()
            .with_context(|| format!("invalid binder catalog pid key '{pid_s}'"))?;
        let services = match entry {
            Value::Array(values) => values
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            Value::String(s) => vec![s.clone()],
            Value::Object(map) => string_array(map.get("services")),
            _ => Vec::new(),
        };
        out.insert(pid, services);
        let entries = out
            .values()
            .map(|services| services.len().saturating_add(1))
            .sum::<usize>();
        if entries > MAX_REPORT_GROUPS {
            bail!("binder catalog exceeds {MAX_REPORT_GROUPS} entries");
        }
    }
    Ok(out)
}

fn read_input_to_string(path: &str) -> Result<String> {
    let mut s = String::new();
    if path == "-" {
        io::stdin()
            .take(MAX_AUXILIARY_INPUT_BYTES + 1)
            .read_to_string(&mut s)
            .context("reading stdin argument")?;
    } else {
        fs::File::open(path)
            .with_context(|| format!("opening {path}"))?
            .take(MAX_AUXILIARY_INPUT_BYTES + 1)
            .read_to_string(&mut s)
            .with_context(|| format!("reading {path}"))?;
    }
    validate_auxiliary_input(&s, path)?;
    Ok(s)
}

fn validate_auxiliary_input(value: &str, label: &str) -> Result<()> {
    if value.len() as u64 > MAX_AUXILIARY_INPUT_BYTES {
        bail!("{label} exceeds {MAX_AUXILIARY_INPUT_BYTES} bytes");
    }
    Ok(())
}

fn open_text_input(path: &str) -> Result<Box<dyn BufRead>> {
    if path == "-" {
        Ok(Box::new(BufReader::new(io::stdin().lock())))
    } else {
        let file = fs::File::open(path).with_context(|| format!("opening {path}"))?;
        Ok(Box::new(BufReader::new(file)))
    }
}

fn write_output(path: Option<&str>, bytes: &[u8]) -> Result<()> {
    if let Some(path) = path {
        crate::private_output::write(Path::new(path), bytes, true)
            .with_context(|| format!("writing {path}"))?;
    } else {
        io::stdout()
            .lock()
            .write_all(bytes)
            .context("writing stdout")?;
    }
    Ok(())
}

fn sorted_counts(counts: &CountMap, top: usize) -> Vec<(&str, u64)> {
    let mut rows: Vec<(&str, u64)> = counts.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    if top > 0 && rows.len() > top {
        rows.truncate(top);
    }
    rows
}

fn increment(counts: &mut CountMap, key: String) {
    *counts.entry(key).or_insert(0) += 1;
}

fn render_inline_set(out: &mut String, label: &str, values: &BTreeSet<String>) {
    if values.is_empty() {
        out.push_str(&format!("- {label}: _none_\n"));
    } else {
        out.push_str(&format!(
            "- {label}: {}\n",
            values
                .iter()
                .map(|v| format!("`{}`", markdown_code(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_inline_counts(out: &mut String, label: &str, counts: &CountMap, top: usize) {
    if counts.is_empty() {
        out.push_str(&format!("- {label}: _none_\n"));
        return;
    }
    let values = sorted_counts(counts, top)
        .into_iter()
        .map(|(value, count)| format!("`{}` ({count})", markdown_code(value)))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("- {label}: {values}\n"));
}

fn syscall_name(obj: &serde_json::Map<String, Value>) -> Option<String> {
    str_field(obj, "name")
        .or_else(|| str_field(obj, "syscall"))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            i64_field(obj, "nr")
                .or_else(|| i64_field(obj, "syscall_nr"))
                .filter(|value| *value >= 0)
                .map(|n| n.to_string())
        })
}

fn event_path(obj: &serde_json::Map<String, Value>) -> Option<&str> {
    str_field(obj, "fd_path")
        .or_else(|| str_field(obj, "path"))
        .or_else(|| str_field(obj, "filename"))
}

fn is_sensitive_path(path: &str) -> bool {
    path.starts_with("/proc/")
        || path == "/proc"
        || path.starts_with("/sys/")
        || path == "/sys"
        || path.starts_with("/dev/")
        || path.starts_with("/system/")
        || path.starts_with("/vendor/")
        || path.starts_with("/odm/")
        || path.starts_with("/apex/")
        || path.starts_with("/data/adb/")
        || path.starts_with("/data/local/tmp/")
        || path.starts_with("/root/")
}

fn is_socket_event(obj: &serde_json::Map<String, Value>, syscall: Option<&str>) -> bool {
    matches!(
        syscall,
        Some(
            "socket" | "connect" | "bind" | "listen" | "accept" | "accept4" | "sendto" | "recvfrom"
        )
    ) || event_path(obj).is_some_and(|path| path.starts_with("socket:"))
        || obj.contains_key("domain")
        || obj.contains_key("sockaddr")
}

fn socket_label(obj: &serde_json::Map<String, Value>) -> String {
    let domain = str_or_num(obj, "domain").unwrap_or_else(|| "<unknown>".to_string());
    let sock_type = str_or_num(obj, "sock_type")
        .or_else(|| str_or_num(obj, "type"))
        .unwrap_or_else(|| "<unknown>".to_string());
    let protocol = str_or_num(obj, "protocol").unwrap_or_else(|| "0".to_string());
    let path = event_path(obj).unwrap_or("");
    if path.is_empty() {
        format!("{domain} {sock_type} proto={protocol}")
    } else {
        format!("{domain} {sock_type} proto={protocol} {path}")
    }
}

fn ioctl_label(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let family = str_field(obj, "ioctl_family")?;
    let mut label = family.to_string();
    if let Some(name) = str_field(obj, "ioctl_name") {
        label.push(' ');
        label.push_str(name);
    }
    if let Some(path) = event_path(obj) {
        label.push_str(" on ");
        label.push_str(path);
    }
    Some(label)
}

fn rwx_label(obj: &serde_json::Map<String, Value>, syscall: Option<&str>) -> Option<String> {
    let syscall = syscall?;
    if !matches!(syscall, "mmap" | "mprotect" | "pkey_mprotect") {
        return None;
    }
    let alert = str_field(obj, "rwx_alert").or_else(|| str_field(obj, "prot"));
    if let Some(alert) = alert.filter(|s| s.contains("RWX") || s.contains("WX")) {
        return Some(format!("{syscall} {alert}"));
    }
    let data = str_field(obj, "data").unwrap_or("");
    if data.contains("PROT_WRITE") && data.contains("PROT_EXEC") {
        return Some(format!("{syscall} WX"));
    }
    None
}

fn finding_label(obj: &serde_json::Map<String, Value>) -> String {
    let rule = str_field(obj, "rule_id").unwrap_or("<unknown>");
    let severity = str_field(obj, "severity").unwrap_or("unknown");
    let category = str_field(obj, "category").unwrap_or("unknown");
    format!("{rule} severity={severity} category={category}")
}

fn crash_label(obj: &serde_json::Map<String, Value>) -> String {
    let pid = u64_field(obj, "pid")
        .map(|n| n.to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    let comm = str_field(obj, "comm").unwrap_or("<unknown>");
    let signal = str_or_num(obj, "signal_name")
        .or_else(|| str_or_num(obj, "exit_signal"))
        .or_else(|| str_or_num(obj, "signal"))
        .unwrap_or_else(|| "unknown".to_string());
    format!("pid={pid} comm={comm} signal={signal}")
}

fn raw_binder_label(callee_pid: u32, target_node: i32, code: Option<u32>) -> String {
    match code {
        Some(code) => format!("pid={callee_pid} node={target_node} code={code}"),
        None => format!("pid={callee_pid} node={target_node}"),
    }
}

fn extract_pid(line: &str) -> Option<u32> {
    let lower = line.to_ascii_lowercase();
    let idx = lower.find("pid")?;
    let after = &line[idx + 3..];
    let digits: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn extract_service_name(line: &str) -> Option<String> {
    let mut rest = line.trim_start();
    let digit_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digit_len > 0 {
        rest = rest[digit_len..].trim_start_matches(|c: char| c.is_ascii_whitespace());
    }
    let end = rest
        .find(':')
        .or_else(|| rest.find('['))
        .or_else(|| rest.find(char::is_whitespace))
        .unwrap_or(rest.len());
    let service = rest[..end].trim();
    (!service.is_empty()).then(|| service.to_string())
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn scalar_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => markdown_text(s),
        other => other.to_string(),
    }
}

/// Render attacker-controlled text without allowing it to introduce Markdown
/// structure, links, or raw HTML. Capture files and service catalogs can come
/// from a hostile device, so report rendering must treat every string as data.
fn markdown_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '(' | ')' | '#' | '+' | '-' | '.'
            | '!' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            control if control.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:04x}}}", control as u32);
            }
            printable => out.push(printable),
        }
    }
    out
}

/// Escape data placed inside an inline-code span. Backticks are rendered as a
/// visible escape so they cannot terminate the span.
fn markdown_code(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '`' => out.push_str("\\x60"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            control if control.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:04x}}}", control as u32);
            }
            printable => out.push(printable),
        }
    }
    out
}

fn str_or_num(obj: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    str_field(obj, key).map(ToOwned::to_owned).or_else(|| {
        i64_field(obj, key)
            .map(|n| n.to_string())
            .or_else(|| u64_field(obj, key).map(|n| n.to_string()))
    })
}

fn str_field<'a>(obj: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

fn bool_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<bool> {
    obj.get(key).and_then(Value::as_bool)
}

fn i64_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    obj.get(key).and_then(Value::as_i64)
}

fn u64_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<u64> {
    obj.get(key).and_then(Value::as_u64)
}

fn u32_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<u32> {
    u64_field(obj, key).and_then(|n| u32::try_from(n).ok())
}

fn i32_field(obj: &serde_json::Map<String, Value>, key: &str) -> Option<i32> {
    i64_field(obj, key).and_then(|n| i32::try_from(n).ok())
}
