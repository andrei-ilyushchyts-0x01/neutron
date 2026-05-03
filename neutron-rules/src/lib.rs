//! Rule engine for the neutron syscall tracer.
//!
//! Consumes JSON-shaped syscall events (matching `neutron`'s `--json` output)
//! and emits [`Finding`]s when rule conditions hold. The engine is offline-safe
//! (no I/O, no allocation per event beyond per-process state) and embeddable in
//! the live tracer.
//!
//! ## Design
//!
//! - [`Rule`] declares **what** to look for: a list of [`MatchCondition`]s
//!   (AND-joined), an optional [`FrequencySpec`] (sliding-window trigger), and
//!   an [`AggregateMode`] (single-event vs per-process aggregation).
//! - [`Event`] is a thin parsed view over the JSON line — zero-copy where
//!   possible.
//! - [`RuleEngine::feed`] is the hot path. It evaluates conditions, updates
//!   sliding windows, and stages findings into per-rule state.
//! - [`RuleEngine::flush`] / [`RuleEngine::drain_ready`] returns finalized
//!   findings for emission.
//!
//! ## Example
//!
//! ```no_run
//! use neutron_rules::{RuleEngine, Event};
//!
//! let mut engine = RuleEngine::with_default_rules().unwrap();
//! for line in std::io::stdin().lines().map_while(Result::ok) {
//!     if let Some(owned) = Event::parse_line(&line) {
//!         if let Some(ev) = owned.view() {
//!             engine.feed(&ev);
//!         }
//!     }
//! }
//! for finding in engine.flush_all() {
//!     println!("{}", serde_json::to_string(&finding).unwrap());
//! }
//! ```

#![deny(rust_2018_idioms)]

pub mod builtin;
pub mod condition;
pub mod engine;
pub mod event;
pub mod finding;
pub mod loader;
pub mod rule;
pub mod window;

pub use condition::MatchCondition;
pub use engine::RuleEngine;
pub use event::{Event, EventKind};
pub use finding::{CaptureHealthSnapshot, EventSnapshot, EvidenceQuality, Finding};
pub use loader::{load_rules_yaml_file, load_rules_yaml_str, LoaderError};
pub use rule::{AggregateMode, Category, FrequencySpec, Rule, Severity};
