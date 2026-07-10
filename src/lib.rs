//! Reusable building blocks for the neutron Aya-based loader binary.

pub mod android;
pub mod binder_services;
pub mod capture;
pub mod capture_normalize;
pub mod causal;
pub mod cli;
pub mod decode;
pub mod diff;
pub mod doctor;
pub mod fdgraph;
pub mod fdinfo;
pub mod format;
pub mod graph;
pub mod health;
pub mod mark;
pub mod matcher;
pub mod predicate;
pub mod recipes;
pub mod report;
pub mod rules;
pub mod sampler;
pub mod sources;
pub mod summarize;
pub mod surface;
pub mod symbolize;
pub mod util;
pub mod window;

pub use neutron_common::SyscallEvent;
