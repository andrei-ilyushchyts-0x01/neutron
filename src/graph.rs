//! Streaming NDJSON to versioned causal graph documents.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;

use crate::capture_normalize::{
    normalize_capture, BinderSpan, CausalRelation as Relation, ExitSpan, SyscallSpan,
};

#[derive(Parser, Debug)]
pub struct GraphArgs {
    /// Path to the NDJSON capture (`-` for stdin).
    pub capture: String,

    /// Select scenarios rooted at this package.
    #[arg(long)]
    pub root_package: Option<String>,

    /// Output format.
    #[arg(long, default_value = "mermaid", value_parser = ["mermaid", "json"])]
    pub format: String,

    /// Merge identical syscalls that share one causal parent.
    #[arg(long)]
    pub collapse_syscalls: bool,

    /// Write the graph to this file instead of stdout.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GraphOptions {
    pub root_package: Option<String>,
    pub collapse_syscalls: bool,
}

pub fn run(args: GraphArgs) -> Result<()> {
    let reader = crate::summarize::open_capture(&args.capture)?;
    let options = GraphOptions {
        root_package: args.root_package,
        collapse_syscalls: args.collapse_syscalls,
    };
    let graph = match args.format.as_str() {
        "json" => render_json_from_reader(reader, &options)?,
        _ => render_mermaid_from_reader(reader, &options)?,
    };
    match args.output {
        Some(path) => crate::private_output::write(path.as_ref(), graph.as_bytes(), true),
        None => io::stdout()
            .lock()
            .write_all(graph.as_bytes())
            .context("writing causal graph"),
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Edge {
    from: String,
    to: String,
    relation: Relation,
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphDocument {
    pub schema: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub span_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
}

fn build_graph_from_reader<R: BufRead>(reader: R, options: &GraphOptions) -> Result<GraphDocument> {
    let capture = normalize_capture(reader)?;
    let has_causal = capture.has_causal;
    let selected_traces: BTreeSet<String> = capture
        .trace_packages
        .iter()
        .filter(|(_, package)| {
            options
                .root_package
                .as_deref()
                .map_or(true, |root| root == package.as_str())
        })
        .map(|(trace, _)| trace.clone())
        .collect();
    let selected = |trace: Option<&str>, span: Option<&str>, root_package: Option<&str>| {
        if !has_causal {
            return true;
        }
        let (Some(trace), Some(_)) = (trace, span) else {
            return false;
        };
        options.root_package.is_none()
            || root_package == options.root_package.as_deref()
            || selected_traces.contains(trace)
    };
    let binders: Vec<&BinderSpan> = capture
        .binders
        .iter()
        .filter(|node| {
            selected(
                node.trace_id.as_deref(),
                node.span_id.as_deref(),
                node.root_package.as_deref(),
            )
        })
        .collect();
    let syscalls: Vec<&SyscallSpan> = capture
        .syscalls
        .iter()
        .filter(|node| {
            selected(
                node.trace_id.as_deref(),
                node.span_id.as_deref(),
                node.root_package.as_deref(),
            )
        })
        .collect();
    let exits: Vec<&ExitSpan> = capture
        .exits
        .iter()
        .filter(|node| {
            selected(
                node.trace_id.as_deref(),
                node.span_id.as_deref(),
                node.root_package.as_deref(),
            )
        })
        .collect();

    let mut processes = BTreeMap::<u32, String>::new();
    for binder in &binders {
        if binder.caller_pid != 0 {
            insert_process_label(
                &mut processes,
                binder.caller_pid,
                binder.caller_comm.as_deref(),
            );
        }
        if binder.callee_pid != 0 {
            insert_process_label(
                &mut processes,
                binder.callee_pid,
                binder.callee_comm.as_deref(),
            );
        }
    }
    for syscall in &syscalls {
        insert_process_label(&mut processes, syscall.pid, syscall.comm.as_deref());
    }
    for exit in &exits {
        insert_process_label(&mut processes, exit.pid, exit.comm.as_deref());
    }

    let binder_ids = binder_ids(&binders);
    let syscall_ids = syscall_ids(&syscalls, options.collapse_syscalls);
    let exit_ids = exit_ids(&exits);
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut span_nodes = BTreeMap::<(Option<String>, String), String>::new();
    for (pid, comm) in &processes {
        let id = process_id(*pid);
        nodes.insert(
            id.clone(),
            GraphNode {
                id,
                kind: "process".into(),
                label: format!("{} (pid {pid})", label_or_pid(comm, *pid)),
                count: 1,
                pid: Some(*pid),
                trace_ids: Vec::new(),
                span_ids: Vec::new(),
            },
        );
    }
    for (binder, id) in binders.iter().zip(&binder_ids) {
        nodes.insert(
            id.clone(),
            graph_node(
                id,
                "binder",
                binder_label(binder),
                Some(binder.caller_pid),
                binder.trace_id.as_deref(),
                binder.span_id.as_deref(),
            ),
        );
        insert_span_node(
            &mut span_nodes,
            binder.trace_id.as_deref(),
            &binder.span_id,
            id,
        );
    }
    for (syscall, id) in syscalls.iter().zip(&syscall_ids) {
        match nodes.get_mut(id) {
            Some(node) => {
                node.count += 1;
                push_unique(&mut node.trace_ids, syscall.trace_id.as_deref());
                push_unique(&mut node.span_ids, syscall.span_id.as_deref());
            }
            None => {
                nodes.insert(
                    id.clone(),
                    graph_node(
                        id,
                        "syscall",
                        syscall_label(syscall),
                        Some(syscall.pid),
                        syscall.trace_id.as_deref(),
                        syscall.span_id.as_deref(),
                    ),
                );
            }
        }
        insert_span_node(
            &mut span_nodes,
            syscall.trace_id.as_deref(),
            &syscall.span_id,
            id,
        );
    }
    for (exit, id) in exits.iter().zip(&exit_ids) {
        nodes.insert(
            id.clone(),
            graph_node(
                id,
                "process_exit",
                exit.label.clone(),
                Some(exit.pid),
                exit.trace_id.as_deref(),
                exit.span_id.as_deref(),
            ),
        );
        insert_span_node(&mut span_nodes, exit.trace_id.as_deref(), &exit.span_id, id);
    }

    let mut edges = BTreeSet::<Edge>::new();
    for (binder, node) in binders.iter().zip(&binder_ids) {
        let parent = parent_node(
            &span_nodes,
            binder.trace_id.as_deref(),
            binder.parent_span_id.as_deref(),
        )
        .unwrap_or_else(|| process_id(binder.caller_pid));
        edges.insert(Edge {
            from: parent,
            to: node.clone(),
            relation: binder.relation,
        });
        if binder.callee_pid != 0 {
            edges.insert(Edge {
                from: node.clone(),
                to: process_id(binder.callee_pid),
                // Binder delivery proves the callee even if parent attribution
                // is only process-inferred.
                relation: Relation::Exact,
            });
        }
    }
    for (syscall, node) in syscalls.iter().zip(&syscall_ids) {
        let parent = parent_node(
            &span_nodes,
            syscall.trace_id.as_deref(),
            syscall.parent_span_id.as_deref(),
        )
        .unwrap_or_else(|| process_id(syscall.pid));
        edges.insert(Edge {
            from: parent,
            to: node.clone(),
            relation: syscall.relation,
        });
    }
    for (exit, node) in exits.iter().zip(&exit_ids) {
        let parent = parent_node(
            &span_nodes,
            exit.trace_id.as_deref(),
            exit.parent_span_id.as_deref(),
        )
        .unwrap_or_else(|| process_id(exit.pid));
        edges.insert(Edge {
            from: parent,
            to: node.clone(),
            relation: exit.relation,
        });
    }

    let mut warnings: Vec<_> = capture
        .health_warnings
        .into_iter()
        .map(|warning| format!("{warning}."))
        .collect();
    if !has_causal {
        warnings
            .push("capture has no causal metadata; syscall edges are process-level only.".into());
    }
    Ok(GraphDocument {
        schema: "neutron.causal-graph/v1".into(),
        nodes: nodes.into_values().collect(),
        edges: edges
            .into_iter()
            .map(|edge| GraphEdge {
                from: edge.from,
                to: edge.to,
                relation: match edge.relation {
                    Relation::Exact => "exact",
                    Relation::Inferred => "inferred",
                }
                .into(),
            })
            .collect(),
        warnings,
    })
}

pub fn render_json_from_reader<R: BufRead>(reader: R, options: &GraphOptions) -> Result<String> {
    let mut output = serde_json::to_string_pretty(&build_graph_from_reader(reader, options)?)?;
    output.push('\n');
    Ok(output)
}

pub fn render_mermaid_from_reader<R: BufRead>(reader: R, options: &GraphOptions) -> Result<String> {
    let graph = build_graph_from_reader(reader, options)?;
    let mut output = String::from("flowchart TD\n");
    for warning in graph.warnings {
        output.push_str(&format!("  %% WARNING: {warning}\n"));
    }
    for node in graph.nodes {
        let count = if node.count > 1 {
            format!(" ×{}", node.count)
        } else {
            String::new()
        };
        output.push_str(&format!(
            "  {}[\"{}{}\"]\n",
            node.id,
            escape_label(&node.label),
            count
        ));
    }
    for edge in graph.edges {
        if edge.relation == "exact" {
            output.push_str(&format!("  {} --> {}\n", edge.from, edge.to));
        } else {
            output.push_str(&format!("  {} -. inferred .-> {}\n", edge.from, edge.to));
        }
    }
    Ok(output)
}

fn graph_node(
    id: &str,
    kind: &str,
    label: String,
    pid: Option<u32>,
    trace_id: Option<&str>,
    span_id: Option<&str>,
) -> GraphNode {
    GraphNode {
        id: id.into(),
        kind: kind.into(),
        label,
        count: 1,
        pid,
        trace_ids: trace_id.into_iter().map(str::to_string).collect(),
        span_ids: span_id.into_iter().map(str::to_string).collect(),
    }
}

fn push_unique(values: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value {
        if !values.iter().any(|current| current == value) {
            values.push(value.into());
        }
    }
}

fn insert_span_node(
    nodes: &mut BTreeMap<(Option<String>, String), String>,
    trace_id: Option<&str>,
    span_id: &Option<String>,
    node_id: &str,
) {
    if let Some(span_id) = span_id {
        nodes.insert(
            (trace_id.map(str::to_string), span_id.clone()),
            node_id.to_string(),
        );
    }
}

fn parent_node(
    nodes: &BTreeMap<(Option<String>, String), String>,
    trace_id: Option<&str>,
    parent_span_id: Option<&str>,
) -> Option<String> {
    nodes
        .get(&(trace_id.map(str::to_string), parent_span_id?.to_string()))
        .cloned()
}

fn binder_ids(nodes: &[&BinderSpan]) -> Vec<String> {
    let mut counts = BTreeMap::<i64, usize>::new();
    for node in nodes {
        *counts.entry(node.debug_id).or_default() += 1;
    }
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let base = binder_id(node.debug_id);
            if counts[&node.debug_id] == 1 {
                base
            } else {
                format!(
                    "{base}_{}",
                    unique_suffix(node.trace_id.as_deref(), node.span_id.as_deref(), index)
                )
            }
        })
        .collect()
}

fn syscall_ids(nodes: &[&SyscallSpan], collapse: bool) -> Vec<String> {
    if collapse {
        let mut groups = BTreeMap::new();
        return nodes
            .iter()
            .map(|node| {
                let key = (
                    node.trace_id.clone(),
                    node.parent_span_id.clone(),
                    node.pid,
                    node.name.clone(),
                    node.ioctl_name.clone(),
                    node.fd_path.clone(),
                    node.ret.map(|ret| ret >= 0),
                    node.relation,
                );
                let next = groups.len();
                groups
                    .entry(key)
                    .or_insert_with(|| format!("s_group_{next:04}"))
                    .clone()
            })
            .collect();
    }
    let mut counts = BTreeMap::<String, usize>::new();
    for node in nodes {
        if let Some(span) = &node.span_id {
            *counts.entry(span.clone()).or_default() += 1;
        }
    }
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| match &node.span_id {
            Some(span) if counts[span] == 1 => format!("s_{}", safe_id(span)),
            Some(span) => format!(
                "s_{}_{}",
                safe_id(span),
                unique_suffix(node.trace_id.as_deref(), Some(span), index)
            ),
            None => format!(
                "s_{}_{}_{}_{}",
                node.pid,
                node.tid,
                node.enter_ts_ns,
                node.nr.unsigned_abs()
            ),
        })
        .collect()
}

fn exit_ids(nodes: &[&ExitSpan]) -> Vec<String> {
    let mut counts = BTreeMap::<String, usize>::new();
    for node in nodes {
        if let Some(span) = &node.span_id {
            *counts.entry(span.clone()).or_default() += 1;
        }
    }
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| match &node.span_id {
            Some(span) if counts[span] == 1 => format!("x_{}", safe_id(span)),
            Some(span) => format!(
                "x_{}_{}",
                safe_id(span),
                unique_suffix(node.trace_id.as_deref(), Some(span), index)
            ),
            None => format!("x_{}_{}", node.pid, index),
        })
        .collect()
}

fn unique_suffix(trace: Option<&str>, span: Option<&str>, index: usize) -> String {
    trace
        .or(span)
        .map(safe_id)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| index.to_string())
}

fn binder_label(node: &BinderSpan) -> String {
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

fn syscall_label(node: &SyscallSpan) -> String {
    let mut label = node.name.clone();
    if let Some(ioctl) = &node.ioctl_name {
        label.push(' ');
        label.push_str(ioctl);
    }
    if let Some(path) = &node.fd_path {
        label.push(' ');
        label.push_str(path);
    }
    if let Some(latency) = node.latency_us {
        label.push_str(&format!(" ({latency}us)"));
    }
    label
}

fn insert_process_label(processes: &mut BTreeMap<u32, String>, pid: u32, label: Option<&str>) {
    let label = label.unwrap_or_default();
    let current = processes.entry(pid).or_default();
    if current.is_empty() && !label.is_empty() {
        *current = label.to_string();
    }
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
