//! Phase 4b — optional `(callee_pid, target_node) → service_name` map
//! for binder enrichment.
//!
//! On Android the kernel's binder tracepoint exposes only the numeric
//! `target_node` handle; the human-meaningful name (e.g.
//! `android.hardware.camera2`) lives in userland — typically dumped via
//! `service list -p`. Rather than reverse-engineer that dump in-process,
//! neutron accepts a JSON file an operator pre-populates and uses it to
//! splice a `service` field into emitted `binder_call` events.
//!
//! File format — flat, hand-editable:
//!
//! ```json
//! {
//!   "1234": {
//!     "1": "android.hardware.camera2",
//!     "2": "android.hardware.audio"
//!   },
//!   "5678": {
//!     "1": "system_server.activity"
//!   }
//! }
//! ```
//!
//! Outer key: `callee_pid` as a string. Inner key: `target_node` as a
//! string. Both string-keyed because JSON object keys are strings; the
//! loader parses them back to integers. Unknown (pid, node) pairs
//! return `None` from `lookup` — the formatter then omits the
//! `service` field rather than emitting a placeholder.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// In-memory descriptor map. `HashMap<(callee_pid, target_node) → service>`
/// is what the lookup wants — a tuple key keeps the read path branch-free.
#[derive(Clone, Debug, Default)]
pub struct BinderServiceMap {
    by_pair: HashMap<(u32, i32), String>,
}

impl BinderServiceMap {
    /// Load from a JSON file. Empty map for an empty/missing file is
    /// treated as a hard error so the operator notices typos in
    /// `--binder-services`.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        let content = fs::read_to_string(path_ref)
            .with_context(|| format!("reading binder service map: {}", path_ref.display()))?;
        Self::from_json(&content)
            .with_context(|| format!("parsing binder service map: {}", path_ref.display()))
    }

    /// Parse from a JSON string. Public for test use.
    pub fn from_json(content: &str) -> Result<Self> {
        let raw: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(content).context("expected `{pid: {node: name}}` object")?;
        let mut by_pair = HashMap::new();
        for (pid_s, nodes) in raw {
            let pid: u32 = pid_s
                .parse()
                .with_context(|| format!("invalid pid key '{pid_s}'"))?;
            for (node_s, name) in nodes {
                let node: i32 = node_s
                    .parse()
                    .with_context(|| format!("invalid target_node key '{node_s}'"))?;
                by_pair.insert((pid, node), name);
            }
        }
        Ok(Self { by_pair })
    }

    /// `Some(name)` if `(callee_pid, target_node)` is mapped, else `None`.
    pub fn lookup(&self, callee_pid: u32, target_node: i32) -> Option<&str> {
        self.by_pair
            .get(&(callee_pid, target_node))
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_pair.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pair.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_object() {
        let json = r#"{"1234":{"1":"camera","2":"audio"},"5678":{"1":"activity"}}"#;
        let m = BinderServiceMap::from_json(json).unwrap();
        assert_eq!(m.lookup(1234, 1), Some("camera"));
        assert_eq!(m.lookup(1234, 2), Some("audio"));
        assert_eq!(m.lookup(5678, 1), Some("activity"));
        assert_eq!(m.lookup(5678, 99), None);
        assert_eq!(m.lookup(9999, 1), None);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn rejects_non_integer_pid_key() {
        let json = r#"{"abc":{"1":"x"}}"#;
        let err = BinderServiceMap::from_json(json).unwrap_err();
        assert!(format!("{err:#}").contains("invalid pid key"));
    }

    #[test]
    fn rejects_non_integer_node_key() {
        let json = r#"{"1234":{"foo":"x"}}"#;
        let err = BinderServiceMap::from_json(json).unwrap_err();
        assert!(format!("{err:#}").contains("invalid target_node key"));
    }

    #[test]
    fn rejects_malformed_json() {
        let err = BinderServiceMap::from_json("not json").unwrap_err();
        assert!(format!("{err:#}").contains("expected"));
    }

    #[test]
    fn empty_object_yields_empty_map() {
        let m = BinderServiceMap::from_json("{}").unwrap();
        assert!(m.is_empty());
        assert_eq!(m.lookup(1, 1), None);
    }

    #[test]
    fn negative_target_node_round_trips() {
        // Some binder handles surface as negative i32 in the kernel
        // tracepoint format. The map must accept a negative string key.
        let json = r#"{"1":{"-1":"unknown"}}"#;
        let m = BinderServiceMap::from_json(json).unwrap();
        assert_eq!(m.lookup(1, -1), Some("unknown"));
    }
}
