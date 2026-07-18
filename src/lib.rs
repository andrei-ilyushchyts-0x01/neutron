//! Reusable building blocks for the neutron Aya-based loader binary.

pub mod aidl;
pub mod android;
pub mod binder_services;
pub mod bpf_abi;
pub mod build_info;
pub mod capture;
pub(crate) mod capture_input;
pub mod capture_normalize;
pub mod causal;
pub mod cli;
pub mod decode;
pub mod diff;
pub mod doctor;
pub mod evidence;
pub mod fdgraph;
pub mod fdinfo;
pub mod format;
pub mod graph;
pub mod harness;
pub mod health;
pub mod ioctl_schema;
pub mod mark;
pub mod matcher;
pub mod native;
pub mod predicate;
#[doc(hidden)]
pub mod private_output;
pub mod recipes;
pub mod report;
pub mod research;
pub mod rules;
pub mod run_manifest;
pub mod sampler;
pub mod selinux;
pub mod sources;
pub mod summarize;
pub mod surface;
pub mod symbolize;
pub mod util;
pub mod window;

pub use neutron_common::SyscallEvent;
