//! Schema-aware Android surface and OTA comparison.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use clap::Args;
use serde::Serialize;

use super::{
    CaptureRecord, CollectorHealth, Device, DeviceIdentity, Module, Relation, Resource, Service,
    SurfaceHealth, SurfaceSnapshot,
};

const SURFACE_DIFF_SCHEMA: &str = "neutron.surface-diff/v1";

#[derive(Args, Debug)]
pub struct SurfaceDiffArgs {
    /// Baseline `neutron.surface/v1` snapshot (`-` for stdin).
    pub baseline: String,
    /// Current `neutron.surface/v1` snapshot (`-` for stdin).
    pub current: String,
    /// Write JSON to this file (mode 0600) instead of stdout.
    #[arg(long)]
    pub output: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SurfaceDiff {
    pub schema: String,
    pub baseline: SnapshotSummary,
    pub current: SnapshotSummary,
    pub health: HealthDiff,
    pub services: ChangeSet<ServiceProfile>,
    pub hals: ChangeSet<ServiceProfile>,
    pub devices: ChangeSet<Device>,
    pub modules: ChangeSet<Module>,
    pub ioctls: SetDiff,
    pub binaries: SetDiff,
    pub selinux_contexts: SetDiff,
    pub scenarios: ChangeSet<ScenarioProfile>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SnapshotSummary {
    pub neutron_version: String,
    pub collected_at: String,
    pub device: DeviceIdentity,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct HealthDiff {
    pub before: SurfaceHealth,
    pub after: SurfaceHealth,
    pub added_warnings: Vec<String>,
    pub removed_warnings: Vec<String>,
    pub collectors: ChangeSet<CollectorHealth>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ChangeSet<T> {
    pub added: Vec<T>,
    pub removed: Vec<T>,
    pub changed: Vec<Changed<T>>,
    pub unchanged: usize,
}

impl<T> Default for ChangeSet<T> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
            unchanged: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Changed<T> {
    pub id: String,
    pub before: T,
    pub after: T,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SetDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub unchanged: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ServiceProfile {
    pub id: String,
    pub name: String,
    pub transport: String,
    pub descriptor: Option<String>,
    pub running: bool,
    pub selinux_domain: Option<String>,
    pub executable: Option<String>,
    pub libraries: Vec<String>,
    pub devices: Vec<String>,
    pub observed_devices: Vec<String>,
    pub observed_ioctls: Vec<String>,
    pub declared: bool,
    pub hal: bool,
    pub confidence: String,
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ScenarioProfile {
    pub id: String,
    pub scenario_id: String,
    pub root_package: Option<String>,
    pub root_uid: Option<u32>,
    pub capture_health: Vec<String>,
    pub relations: Vec<ScenarioRelation>,
}

#[derive(Clone, Debug, Ord, PartialOrd, Serialize, PartialEq, Eq)]
pub struct ScenarioRelation {
    #[serde(rename = "type")]
    pub relation_type: String,
    pub from: String,
    pub to: String,
    pub ioctl: Option<String>,
    pub confidence: String,
    pub causal_relation: Option<String>,
}

pub fn run(args: SurfaceDiffArgs) -> Result<()> {
    if args.baseline == "-" && args.current == "-" {
        bail!("only one surface diff input can be '-' (stdin)");
    }
    let baseline = super::read_snapshot(&args.baseline)?;
    let current = super::read_snapshot(&args.current)?;
    super::write_json(args.output.as_deref(), &diff_snapshots(&baseline, &current))
}

pub fn diff_snapshots(baseline: &SurfaceSnapshot, current: &SurfaceSnapshot) -> SurfaceDiff {
    let baseline_services = service_profiles(baseline.services.iter());
    let current_services = service_profiles(current.services.iter());
    let baseline_hals: Vec<_> = baseline_services
        .iter()
        .filter(|service| service.hal)
        .cloned()
        .collect();
    let current_hals: Vec<_> = current_services
        .iter()
        .filter(|service| service.hal)
        .cloned()
        .collect();

    SurfaceDiff {
        schema: SURFACE_DIFF_SCHEMA.into(),
        baseline: snapshot_summary(baseline),
        current: snapshot_summary(current),
        health: health_diff(&baseline.health, &current.health),
        services: change_set(baseline_services, current_services, |value| &value.id),
        hals: change_set(baseline_hals, current_hals, |value| &value.id),
        devices: change_set(baseline.devices.clone(), current.devices.clone(), |value| {
            &value.id
        }),
        modules: change_set(baseline.modules.clone(), current.modules.clone(), |value| {
            &value.id
        }),
        ioctls: set_diff(ioctl_set(baseline), ioctl_set(current)),
        binaries: set_diff(binary_set(baseline), binary_set(current)),
        selinux_contexts: set_diff(context_set(baseline), context_set(current)),
        scenarios: change_set(
            scenario_profiles(baseline),
            scenario_profiles(current),
            |value| &value.id,
        ),
        warnings: comparison_warnings(baseline, current),
    }
}

fn snapshot_summary(snapshot: &SurfaceSnapshot) -> SnapshotSummary {
    SnapshotSummary {
        neutron_version: snapshot.neutron_version.clone(),
        collected_at: snapshot.collected_at.clone(),
        device: snapshot.device.clone(),
    }
}

fn health_diff(before: &SurfaceHealth, after: &SurfaceHealth) -> HealthDiff {
    let before_warnings: BTreeSet<_> = before.warnings.iter().cloned().collect();
    let after_warnings: BTreeSet<_> = after.warnings.iter().cloned().collect();
    HealthDiff {
        before: before.clone(),
        after: after.clone(),
        added_warnings: after_warnings
            .difference(&before_warnings)
            .cloned()
            .collect(),
        removed_warnings: before_warnings
            .difference(&after_warnings)
            .cloned()
            .collect(),
        collectors: change_set(
            before.collectors.clone(),
            after.collectors.clone(),
            |value| &value.name,
        ),
    }
}

fn service_profiles<'a>(services: impl Iterator<Item = &'a Service>) -> Vec<ServiceProfile> {
    services
        .map(|service| ServiceProfile {
            id: service.id.clone(),
            name: service.name.clone(),
            transport: service.transport.clone(),
            descriptor: service.descriptor.clone(),
            running: service.pid.is_some(),
            selinux_domain: service.selinux_domain.clone(),
            executable: service.executable.clone(),
            libraries: service.libraries.clone(),
            devices: service.devices.clone(),
            observed_devices: service.observed_devices.clone(),
            observed_ioctls: service.observed_ioctls.clone(),
            declared: service.declared,
            hal: service.hal,
            confidence: service.confidence.clone(),
            sources: service.sources.clone(),
        })
        .collect()
}

fn change_set<T, F>(before: Vec<T>, after: Vec<T>, id: F) -> ChangeSet<T>
where
    T: Clone + Eq,
    F: Fn(&T) -> &str,
{
    let before: BTreeMap<_, _> = before
        .into_iter()
        .map(|value| (id(&value).to_string(), value))
        .collect();
    let after: BTreeMap<_, _> = after
        .into_iter()
        .map(|value| (id(&value).to_string(), value))
        .collect();
    let mut changes = ChangeSet::default();
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    for key in keys {
        match (before.get(&key), after.get(&key)) {
            (None, Some(value)) => changes.added.push(value.clone()),
            (Some(value), None) => changes.removed.push(value.clone()),
            (Some(before), Some(after)) if before != after => changes.changed.push(Changed {
                id: key,
                before: before.clone(),
                after: after.clone(),
            }),
            (Some(_), Some(_)) => changes.unchanged += 1,
            (None, None) => unreachable!(),
        }
    }
    changes
}

fn set_diff(before: BTreeSet<String>, after: BTreeSet<String>) -> SetDiff {
    SetDiff {
        added: after.difference(&before).cloned().collect(),
        removed: before.difference(&after).cloned().collect(),
        unchanged: before.intersection(&after).count(),
    }
}

fn ioctl_set(snapshot: &SurfaceSnapshot) -> BTreeSet<String> {
    snapshot
        .services
        .iter()
        .flat_map(|service| service.observed_ioctls.iter().cloned())
        .chain(
            snapshot
                .relations
                .iter()
                .filter_map(|relation| relation.ioctl.clone()),
        )
        .collect()
}

fn binary_set(snapshot: &SurfaceSnapshot) -> BTreeSet<String> {
    snapshot
        .processes
        .iter()
        .flat_map(|process| {
            process
                .executable
                .iter()
                .cloned()
                .chain(process.libraries.iter().cloned())
        })
        .chain(snapshot.services.iter().flat_map(|service| {
            service
                .executable
                .iter()
                .cloned()
                .chain(service.libraries.iter().cloned())
        }))
        .collect()
}

fn context_set(snapshot: &SurfaceSnapshot) -> BTreeSet<String> {
    snapshot
        .services
        .iter()
        .filter_map(|service| service.selinux_domain.clone())
        .chain(
            snapshot
                .processes
                .iter()
                .map(|process| process.selinux_domain.clone())
                .filter(|value| !value.is_empty()),
        )
        .chain(
            snapshot
                .devices
                .iter()
                .filter_map(|device| device.selinux_context.clone()),
        )
        .collect()
}

fn scenario_profiles(snapshot: &SurfaceSnapshot) -> Vec<ScenarioProfile> {
    let service_processes: BTreeMap<_, _> = snapshot
        .services
        .iter()
        .filter_map(|service| {
            service
                .process_id
                .as_ref()
                .map(|process| (process.clone(), service.id.clone()))
        })
        .collect();
    let device_paths: BTreeMap<_, _> = snapshot
        .devices
        .iter()
        .map(|device| (device.id.clone(), device.path.clone()))
        .collect();
    let resource_labels: BTreeMap<_, _> = snapshot
        .resources
        .iter()
        .map(|resource| {
            (
                resource.id.clone(),
                semantic_resource(resource, &device_paths),
            )
        })
        .collect();
    let mut groups = BTreeMap::<String, (ScenarioProfile, BTreeSet<String>)>::new();
    for capture in &snapshot.captures {
        let id = scenario_id(capture);
        let entry = groups.entry(id.clone()).or_insert_with(|| {
            (
                ScenarioProfile {
                    id,
                    scenario_id: capture.scenario_id.clone(),
                    root_package: capture.root_package.clone(),
                    root_uid: capture.root_uid,
                    capture_health: Vec::new(),
                    relations: Vec::new(),
                },
                BTreeSet::new(),
            )
        });
        entry.0.capture_health.push(capture.health.clone());
        entry.1.insert(capture.trace_id.clone());
    }
    for (profile, trace_ids) in groups.values_mut() {
        let relations: BTreeSet<_> = snapshot
            .relations
            .iter()
            .filter(|relation| {
                relation.scenario_id.as_deref() == Some(profile.scenario_id.as_str())
                    && relation
                        .trace_id
                        .as_ref()
                        .is_some_and(|trace| trace_ids.contains(trace))
            })
            .map(|relation| {
                scenario_relation(
                    relation,
                    &service_processes,
                    &device_paths,
                    &resource_labels,
                )
            })
            .collect();
        profile.capture_health.sort();
        profile.capture_health.dedup();
        profile.relations = relations.into_iter().collect();
    }
    groups.into_values().map(|(profile, _)| profile).collect()
}

fn scenario_id(capture: &CaptureRecord) -> String {
    match (&capture.root_package, capture.root_uid) {
        (Some(package), _) => format!("scenario:{}:package:{package}", capture.scenario_id),
        (None, Some(uid)) => format!("scenario:{}:uid:{uid}", capture.scenario_id),
        (None, None) => format!("scenario:{}:unknown-root", capture.scenario_id),
    }
}

fn scenario_relation(
    relation: &Relation,
    service_processes: &BTreeMap<String, String>,
    device_paths: &BTreeMap<String, String>,
    resource_labels: &BTreeMap<String, String>,
) -> ScenarioRelation {
    ScenarioRelation {
        relation_type: relation.relation_type.clone(),
        from: semantic_endpoint(
            &relation.from,
            service_processes,
            device_paths,
            resource_labels,
        ),
        to: semantic_endpoint(
            &relation.to,
            service_processes,
            device_paths,
            resource_labels,
        ),
        ioctl: relation.ioctl.clone(),
        confidence: relation.confidence.clone(),
        causal_relation: relation.causal_relation.clone(),
    }
}

fn semantic_endpoint(
    endpoint: &str,
    service_processes: &BTreeMap<String, String>,
    device_paths: &BTreeMap<String, String>,
    resource_labels: &BTreeMap<String, String>,
) -> String {
    if let Some(service) = service_processes.get(endpoint) {
        return format!("process-for:{service}");
    }
    if let Some(path) = device_paths.get(endpoint) {
        return format!("device:{path}");
    }
    if let Some(resource) = resource_labels.get(endpoint) {
        return resource.clone();
    }
    if endpoint.starts_with("process:") {
        return "process".into();
    }
    endpoint.to_string()
}

fn semantic_resource(resource: &Resource, device_paths: &BTreeMap<String, String>) -> String {
    let source = resource
        .device_id
        .as_ref()
        .and_then(|device| device_paths.get(device))
        .map(String::as_str)
        .unwrap_or("unknown-device");
    format!(
        "resource:{}:{source}:length={}",
        resource.kind,
        resource.length.unwrap_or_default()
    )
}

fn comparison_warnings(baseline: &SurfaceSnapshot, current: &SurfaceSnapshot) -> Vec<String> {
    let mut warnings = BTreeSet::new();
    if baseline.health.status != "complete" {
        warnings.insert(
            "baseline surface collection is degraded; removals may reflect missing evidence".into(),
        );
    }
    if current.health.status != "complete" {
        warnings.insert(
            "current surface collection is degraded; additions or removals may reflect missing evidence"
                .into(),
        );
    }
    if baseline.device.fingerprint.is_empty() || current.device.fingerprint.is_empty() {
        warnings.insert("one or both device fingerprints are unavailable".into());
    } else if baseline.device.fingerprint != current.device.fingerprint {
        warnings.insert(
            "device fingerprints differ; interpret this as an OTA or cross-device comparison"
                .into(),
        );
    }
    warnings.into_iter().collect()
}
