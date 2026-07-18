use serde::Serialize;

use crate::bpf_abi::{validate_bpf_object_path, BpfAbiRequirements, BpfObjectError};

pub const SELF_INFO_SCHEMA: &str = "neutron.self-info/v1";
pub const BPF_ABI_MAJOR: u16 = neutron_common::BPF_ABI_MAJOR;
pub const SYSCALL_EVENT_SIZE: usize = core::mem::size_of::<neutron_common::SyscallEvent>();
pub const BPF_FEATURE_BITS: &[&str] = &[
    "syscall_trace",
    "binder_trace",
    "per_cpu_health",
    "process_exit",
];

#[derive(Clone, Debug, Serialize)]
pub struct ToolBuildInfo {
    pub version: &'static str,
    pub git_commit: &'static str,
    pub git_dirty: bool,
    pub build_timestamp: &'static str,
    pub rustc_version: &'static str,
    pub target: &'static str,
    pub feature_set: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BpfBuildInfo {
    pub abi_major: u16,
    pub event_size: usize,
    pub feature_bits: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SelfInfo {
    pub schema: &'static str,
    pub tool: ToolBuildInfo,
    pub bpf: BpfBuildInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bpf_objects: Vec<BpfObjectMeasurement>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BpfObjectMeasurement {
    pub path: String,
    pub identity: crate::bpf_abi::BpfObjectIdentity,
}

fn feature_set() -> Vec<&'static str> {
    let features = env!("NEUTRON_FEATURE_SET");
    if features == "none" {
        Vec::new()
    } else {
        features.split(',').collect()
    }
}

pub fn self_info() -> SelfInfo {
    SelfInfo {
        schema: SELF_INFO_SCHEMA,
        tool: ToolBuildInfo {
            version: env!("CARGO_PKG_VERSION"),
            git_commit: env!("NEUTRON_GIT_COMMIT"),
            git_dirty: env!("NEUTRON_GIT_DIRTY") == "true",
            build_timestamp: env!("NEUTRON_BUILD_TIMESTAMP"),
            rustc_version: env!("NEUTRON_RUSTC_VERSION"),
            target: env!("NEUTRON_TARGET"),
            feature_set: feature_set(),
        },
        bpf: BpfBuildInfo {
            abi_major: BPF_ABI_MAJOR,
            event_size: SYSCALL_EVENT_SIZE,
            feature_bits: BPF_FEATURE_BITS.to_vec(),
        },
        bpf_objects: Vec::new(),
    }
}

pub fn self_info_with_bpf_objects(paths: &[String]) -> Result<SelfInfo, BpfObjectError> {
    let requirements = BpfAbiRequirements::default_capture();
    let mut info = self_info();
    for path in paths {
        let validated = validate_bpf_object_path(path, &requirements)?;
        info.bpf_objects.push(BpfObjectMeasurement {
            path: path.clone(),
            identity: validated.identity,
        });
    }
    Ok(info)
}

pub fn verbose_version() -> String {
    let info = self_info();
    let features = if info.tool.feature_set.is_empty() {
        "none".to_string()
    } else {
        info.tool.feature_set.join(",")
    };
    let bpf_features = if info.bpf.feature_bits.is_empty() {
        "none".to_string()
    } else {
        info.bpf.feature_bits.join(",")
    };
    format!(
        "neutron {}\n\
         git_commit: {}\n\
         git_dirty: {}\n\
         build_timestamp: {}\n\
         rustc_version: {}\n\
         target: {}\n\
         feature_set: {}\n\
         bpf_abi_major: {}\n\
         syscall_event_size: {}\n\
         bpf_feature_bits: {}",
        info.tool.version,
        info.tool.git_commit,
        info.tool.git_dirty,
        info.tool.build_timestamp,
        info.tool.rustc_version,
        info.tool.target,
        features,
        info.bpf.abi_major,
        info.bpf.event_size,
        bpf_features,
    )
}

pub fn self_info_json() -> serde_json::Result<String> {
    serde_json::to_string_pretty(&self_info())
}

pub fn self_info_json_with_bpf_objects(paths: &[String]) -> anyhow::Result<String> {
    let info = self_info_with_bpf_objects(paths)?;
    Ok(serde_json::to_string_pretty(&info)?)
}
