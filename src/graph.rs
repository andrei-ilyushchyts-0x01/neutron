//! Streaming NDJSON to Mermaid causal graph renderer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Map, Value};

#[derive(Parser, Debug)]
pub struct GraphArgs {
    /// Path to the NDJSON capture (`-` for stdin).
    pub capture: String,

    /// Select scenarios rooted at this package.
    #[arg(long)]
    pub root_package: Option<String>,

    /// Output format. Neutron 1.3 supports Mermaid only.
    #[arg(long, default_value = "mermaid", value_parser = ["mermaid"])]
    pub format: String,

    /// Write the graph to this file instead of stdout.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GraphOptions {
    pub root_package: Option<String>,
}

pub fn run(args: GraphArgs) -> Result<()> {
    let reader = crate::summarize::open_capture(&args.capture)?;
    let graph = render_mermaid_from_reader(
        reader,
        &GraphOptions {
            root_package: args.root_package,
        },
    )?;
    match args.output {
        Some(path) => fs::write(&path, graph).with_context(|| format!("writing {path}")),
        None => io::stdout()
            .lock()
            .write_all(graph.as_bytes())
            .context("writing Mermaid graph"),
    }
}

#[derive(Clone, Debug)]
struct ParsedEvent {
    kind: String,
    object: Map<String, Value>,
}

#[derive(Clone, Debug, Default)]
struct BinderNode {
    debug_id: i64,
    caller_pid: u32,
    callee_pid: u32,
    caller_comm: Option<String>,
    callee_comm: Option<String>,
    target_node: Option<i64>,
    code: Option<u64>,
    service: Option<String>,
    method: Option<String>,
    latency_us: Option<u64>,
    status: Option<String>,
    span_id: Option<String>,
    parent_span_id: Option<String>,
    relation: Relation,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
enum Relation {
    #[default]
    Exact,
    Inferred,
}

#[derive(Clone, Debug)]
struct SyscallNode {
    pid: u32,
    name: String,
    ioctl_name: Option<String>,
    latency_us: Option<u64>,
    span_id: Option<String>,
    parent_span_id: Option<String>,
    relation: Relation,
    is_exit: bool,
}

#[derive(Clone, Debug)]
struct ExitNode {
    pid: u32,
    label: String,
    span_id: Option<String>,
    parent_span_id: Option<String>,
    relation: Relation,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Edge {
    from: String,
    to: String,
    relation: Relation,
}

pub fn render_mermaid_from_reader<R: BufRead>(reader: R, options: &GraphOptions) -> Result<String> {
    let mut causal = Vec::new();
    let mut legacy = Vec::new();
    let mut enrichments = Vec::new();
    let mut trace_packages = BTreeMap::<String, String>::new();
    let mut health_warnings = BTreeSet::<String>::new();

    for line in reader.lines() {
        let line = line.context("reading capture line")?;
        let value: Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(object) = value.as_object() else {
            continue;
        };
        let Some(kind) = text(object, "type") else {
            continue;
        };
        if kind == "capture_health" {
            for (field, label) in [
                ("traced_process_limit", "traced process limit"),
                ("binder_depth_limit", "Binder depth limit"),
                ("binder_follow_failed", "Binder follow failure"),
            ] {
                if number_u64(object, field).unwrap_or(0) > 0 {
                    health_warnings.insert(label.to_string());
                }
            }
        }
        if let (Some(trace), Some(package)) =
            (text(object, "trace_id"), text(object, "root_package"))
        {
            trace_packages.insert(trace.to_string(), package.to_string());
        }
        let parsed = ParsedEvent {
            kind: kind.to_string(),
            object: object.clone(),
        };
        if kind == "binder_call" {
            enrichments.push(parsed.clone());
        }
        if object.contains_key("trace_id") && object.contains_key("span_id") {
            causal.push(parsed);
        } else if matches!(kind, "binder" | "binder_call" | "syscall" | "process_exit") {
            legacy.push(parsed);
        }
    }

    let has_causal = !causal.is_empty();
    let selected_traces: BTreeSet<String> = trace_packages
        .iter()
        .filter(|(_, package)| {
            options
                .root_package
                .as_deref()
                .map_or(true, |root| root == package.as_str())
        })
        .map(|(trace, _)| trace.clone())
        .collect();
    let events: Vec<ParsedEvent> = if has_causal {
        causal
            .into_iter()
            .filter(|event| {
                options.root_package.is_none()
                    || text(&event.object, "root_package") == options.root_package.as_deref()
                    || text(&event.object, "trace_id")
                        .is_some_and(|trace| selected_traces.contains(trace))
            })
            .collect()
    } else {
        legacy
    };

    let mut binders = BTreeMap::<i64, BinderNode>::new();
    let mut syscalls = BTreeMap::<(u32, u32, u64, i64), SyscallNode>::new();
    let mut exits = Vec::<ExitNode>::new();
    let mut processes = BTreeMap::<u32, String>::new();

    for event in events {
        match event.kind.as_str() {
            "binder" | "binder_call" => merge_binder(&mut binders, &mut processes, &event.object),
            "syscall" => merge_syscall(&mut syscalls, &mut processes, &event.object),
            "process_exit" => merge_exit(&mut exits, &mut processes, &event.object),
            _ => {}
        }
    }
    for event in enrichments {
        if let Some(debug_id) = number_i64(&event.object, "debug_id") {
            if let Some(node) = binders.get_mut(&debug_id) {
                apply_binder_fields(node, &event.object);
            }
        }
    }

    let mut nodes = BTreeMap::<String, String>::new();
    let mut span_nodes = BTreeMap::<String, String>::new();
    for (pid, comm) in &processes {
        nodes.insert(
            process_id(*pid),
            format!("{} (pid {pid})", label_or_pid(comm, *pid)),
        );
    }
    for binder in binders.values() {
        let id = binder_id(binder.debug_id);
        nodes.insert(id.clone(), binder_label(binder));
        if let Some(span) = &binder.span_id {
            span_nodes.insert(span.clone(), id);
        }
    }
    for (key, syscall) in &syscalls {
        let id = syscall_node_id(syscall.span_id.as_deref(), key);
        nodes.insert(id.clone(), syscall_label(syscall));
        if let Some(span) = &syscall.span_id {
            span_nodes.insert(span.clone(), id);
        }
    }
    for (index, exit) in exits.iter().enumerate() {
        let id = exit_node_id(exit.span_id.as_deref(), exit.pid, index);
        nodes.insert(id.clone(), exit.label.clone());
        if let Some(span) = &exit.span_id {
            span_nodes.insert(span.clone(), id);
        }
    }

    let mut edges = BTreeSet::<Edge>::new();
    for binder in binders.values() {
        let node = binder_id(binder.debug_id);
        let parent = binder
            .parent_span_id
            .as_ref()
            .and_then(|span| span_nodes.get(span))
            .cloned()
            .unwrap_or_else(|| process_id(binder.caller_pid));
        edges.insert(Edge {
            from: parent,
            to: node.clone(),
            relation: binder.relation,
        });
        if binder.callee_pid != 0 {
            edges.insert(Edge {
                from: node,
                to: process_id(binder.callee_pid),
                // The Binder tracepoint proves delivery to this PID even when
                // the caller's parent attribution is only process-inferred.
                relation: Relation::Exact,
            });
        }
    }
    for (key, syscall) in &syscalls {
        let node = syscall_node_id(syscall.span_id.as_deref(), key);
        let parent = syscall
            .parent_span_id
            .as_ref()
            .and_then(|span| span_nodes.get(span))
            .cloned()
            .unwrap_or_else(|| process_id(syscall.pid));
        edges.insert(Edge {
            from: parent,
            to: node,
            relation: syscall.relation,
        });
    }
    for (index, exit) in exits.iter().enumerate() {
        let node = exit_node_id(exit.span_id.as_deref(), exit.pid, index);
        let parent = exit
            .parent_span_id
            .as_ref()
            .and_then(|span| span_nodes.get(span))
            .cloned()
            .unwrap_or_else(|| process_id(exit.pid));
        edges.insert(Edge {
            from: parent,
            to: node,
            relation: exit.relation,
        });
    }

    let mut out = String::from("flowchart TD\n");
    for warning in health_warnings {
        out.push_str(&format!(
            "  %% WARNING: {warning} recorded in capture_health.\n"
        ));
    }
    if !has_causal {
        out.push_str(
            "  %% WARNING: capture has no causal metadata; syscall edges are process-level only.\n",
        );
    }
    for (id, label) in nodes {
        out.push_str(&format!("  {id}[\"{}\"]\n", escape_label(&label)));
    }
    for edge in edges {
        match edge.relation {
            Relation::Exact => out.push_str(&format!("  {} --> {}\n", edge.from, edge.to)),
            Relation::Inferred => {
                out.push_str(&format!("  {} -. inferred .-> {}\n", edge.from, edge.to));
            }
        }
    }
    Ok(out)
}

fn merge_binder(
    binders: &mut BTreeMap<i64, BinderNode>,
    processes: &mut BTreeMap<u32, String>,
    object: &Map<String, Value>,
) {
    let Some(debug_id) = number_i64(object, "debug_id") else {
        return;
    };
    let node = binders.entry(debug_id).or_insert_with(|| BinderNode {
        debug_id,
        ..BinderNode::default()
    });
    apply_binder_fields(node, object);
    if node.caller_pid != 0 {
        processes
            .entry(node.caller_pid)
            .or_insert_with(|| node.caller_comm.clone().unwrap_or_default());
    }
    if node.callee_pid != 0 {
        processes
            .entry(node.callee_pid)
            .or_insert_with(|| node.callee_comm.clone().unwrap_or_default());
    }
}

fn apply_binder_fields(node: &mut BinderNode, object: &Map<String, Value>) {
    node.caller_pid = number_u32(object, "caller_pid")
        .or_else(|| number_u32(object, "pid"))
        .unwrap_or(node.caller_pid);
    node.callee_pid = number_u32(object, "callee_pid")
        .or_else(|| number_u32(object, "to_proc"))
        .unwrap_or(node.callee_pid);
    node.caller_comm = text(object, "caller_comm")
        .or_else(|| text(object, "comm"))
        .map(str::to_string)
        .or_else(|| node.caller_comm.clone());
    node.callee_comm = text(object, "callee_comm")
        .map(str::to_string)
        .or_else(|| node.callee_comm.clone());
    node.target_node = number_i64(object, "target_node").or(node.target_node);
    node.code = number_u64(object, "code").or(node.code);
    node.service = text(object, "service")
        .map(str::to_string)
        .or_else(|| node.service.clone());
    node.method = text(object, "method")
        .map(str::to_string)
        .or_else(|| node.method.clone());
    node.latency_us = number_u64(object, "latency_us").or(node.latency_us);
    node.status = text(object, "status")
        .map(str::to_string)
        .or_else(|| node.status.clone());
    node.span_id = text(object, "span_id")
        .map(str::to_string)
        .or_else(|| node.span_id.clone());
    node.parent_span_id = text(object, "parent_span_id")
        .map(str::to_string)
        .or_else(|| node.parent_span_id.clone());
    node.relation = relation(object);
}

fn merge_syscall(
    syscalls: &mut BTreeMap<(u32, u32, u64, i64), SyscallNode>,
    processes: &mut BTreeMap<u32, String>,
    object: &Map<String, Value>,
) {
    let Some(pid) = number_u32(object, "pid") else {
        return;
    };
    let tid = number_u32(object, "tid")
        .or_else(|| number_u32(object, "tgid"))
        .unwrap_or(pid);
    let nr = number_i64(object, "nr")
        .or_else(|| number_i64(object, "syscall_nr"))
        .unwrap_or(-1);
    let ts = number_u64(object, "enter_ts_ns")
        .or_else(|| number_u64(object, "ts_ns"))
        .unwrap_or(0);
    let is_exit = text(object, "phase") == Some("exit")
        || object.get("enter").and_then(Value::as_bool) == Some(false);
    let candidate = SyscallNode {
        pid,
        name: text(object, "name")
            .or_else(|| text(object, "syscall"))
            .map(str::to_string)
            .unwrap_or_else(|| format!("syscall {nr}")),
        ioctl_name: text(object, "ioctl_name").map(str::to_string),
        latency_us: number_u64(object, "latency_us"),
        span_id: text(object, "span_id").map(str::to_string),
        parent_span_id: text(object, "parent_span_id").map(str::to_string),
        relation: relation(object),
        is_exit,
    };
    let key = (pid, tid, ts, nr);
    match syscalls.get(&key) {
        Some(existing) if existing.is_exit && !candidate.is_exit => {}
        _ => {
            syscalls.insert(key, candidate);
        }
    }
    processes
        .entry(pid)
        .or_insert_with(|| text(object, "comm").unwrap_or_default().to_string());
}

fn merge_exit(
    exits: &mut Vec<ExitNode>,
    processes: &mut BTreeMap<u32, String>,
    object: &Map<String, Value>,
) {
    let Some(pid) = number_u32(object, "pid") else {
        return;
    };
    let comm = text(object, "comm").map(str::to_string);
    processes
        .entry(pid)
        .or_insert_with(|| comm.clone().unwrap_or_default());
    let label = text(object, "signal_name")
        .or_else(|| text(object, "classification"))
        .unwrap_or("process exit")
        .to_string();
    exits.push(ExitNode {
        pid,
        label,
        span_id: text(object, "span_id").map(str::to_string),
        parent_span_id: text(object, "parent_span_id").map(str::to_string),
        relation: relation(object),
    });
}

fn binder_label(node: &BinderNode) -> String {
    let code = node.code.unwrap_or_default();
    let base = match (&node.service, &node.method) {
        (Some(service), Some(method)) => format!("{service}.{method}"),
        (Some(service), None) => format!("{service} code={code}"),
        (None, _) => format!(
            "Binder code={code} node={}",
            node.target_node.unwrap_or_default()
        ),
    };
    match (node.latency_us, node.status.as_deref()) {
        (Some(latency), Some(status)) => format!("{base} ({status}, {latency}us)"),
        (Some(latency), None) => format!("{base} ({latency}us)"),
        (None, Some(status)) => format!("{base} ({status})"),
        (None, None) => base,
    }
}

fn syscall_label(node: &SyscallNode) -> String {
    let mut label = node.name.clone();
    if let Some(ioctl) = &node.ioctl_name {
        label.push(' ');
        label.push_str(ioctl);
    }
    if let Some(latency) = node.latency_us {
        label.push_str(&format!(" ({latency}us)"));
    }
    label
}

fn label_or_pid(comm: &str, pid: u32) -> String {
    if comm.is_empty() {
        format!("process {pid}")
    } else {
        comm.to_string()
    }
}

fn process_id(pid: u32) -> String {
    format!("p_{pid}")
}

fn binder_id(debug_id: i64) -> String {
    format!("b_{:08x}", debug_id as u32)
}

fn syscall_node_id(span: Option<&str>, key: &(u32, u32, u64, i64)) -> String {
    span.map(|value| format!("s_{}", safe_id(value)))
        .unwrap_or_else(|| format!("s_{}_{}_{}_{}", key.0, key.1, key.2, key.3.unsigned_abs()))
}

fn exit_node_id(span: Option<&str>, pid: u32, index: usize) -> String {
    span.map(|value| format!("x_{}", safe_id(value)))
        .unwrap_or_else(|| format!("x_{pid}_{index}"))
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn escape_label(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('[', "&#91;")
        .replace(']', "&#93;")
        .replace(['\n', '\r'], " ")
}

fn relation(object: &Map<String, Value>) -> Relation {
    if text(object, "causal_relation") == Some("inferred") {
        Relation::Inferred
    } else {
        Relation::Exact
    }
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn number_u64(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

fn number_u32(object: &Map<String, Value>, key: &str) -> Option<u32> {
    number_u64(object, key).and_then(|value| u32::try_from(value).ok())
}

fn number_i64(object: &Map<String, Value>, key: &str) -> Option<i64> {
    object
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|n| n as i64)))
}
