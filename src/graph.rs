//! Streaming NDJSON to Mermaid causal graph renderer.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};
use clap::Parser;

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

    /// Output format. Neutron 1.4 supports Mermaid only.
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Edge {
    from: String,
    to: String,
    relation: Relation,
}

pub fn render_mermaid_from_reader<R: BufRead>(reader: R, options: &GraphOptions) -> Result<String> {
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
    let syscall_ids = syscall_ids(&syscalls);
    let exit_ids = exit_ids(&exits);
    let mut nodes = BTreeMap::<String, String>::new();
    let mut span_nodes = BTreeMap::<(Option<String>, String), String>::new();
    for (pid, comm) in &processes {
        nodes.insert(
            process_id(*pid),
            format!("{} (pid {pid})", label_or_pid(comm, *pid)),
        );
    }
    for (binder, id) in binders.iter().zip(&binder_ids) {
        nodes.insert(id.clone(), binder_label(binder));
        insert_span_node(
            &mut span_nodes,
            binder.trace_id.as_deref(),
            &binder.span_id,
            id,
        );
    }
    for (syscall, id) in syscalls.iter().zip(&syscall_ids) {
        nodes.insert(id.clone(), syscall_label(syscall));
        insert_span_node(
            &mut span_nodes,
            syscall.trace_id.as_deref(),
            &syscall.span_id,
            id,
        );
    }
    for (exit, id) in exits.iter().zip(&exit_ids) {
        nodes.insert(id.clone(), exit.label.clone());
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

    let mut out = String::from("flowchart TD\n");
    for warning in &capture.health_warnings {
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

fn syscall_ids(nodes: &[&SyscallSpan]) -> Vec<String> {
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
