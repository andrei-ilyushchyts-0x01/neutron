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

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::aidl::{normalize_descriptor, AidlCatalog};

/// In-memory descriptor map. `HashMap<(callee_pid, target_node) → service>`
/// is what the lookup wants — a tuple key keeps the read path branch-free.
#[derive(Clone, Debug, Default)]
pub struct BinderServiceMap {
    by_pair: HashMap<(u32, i32), String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributionConfidence {
    Exact,
    Candidate,
}

impl AttributionConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Candidate => "candidate",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BinderMethodMap {
    by_service_code: HashMap<(String, u32), String>,
}

impl BinderMethodMap {
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)
            .with_context(|| format!("reading binder method map: {}", path.display()))?;
        Self::from_json(&content)
            .with_context(|| format!("parsing binder method map: {}", path.display()))
    }

    pub fn from_json(content: &str) -> Result<Self> {
        let raw: HashMap<String, HashMap<String, String>> =
            serde_json::from_str(content).context("expected `{service: {code: method}}` object")?;
        let mut by_service_code = HashMap::new();
        for (service, methods) in raw {
            for (code, method) in methods {
                let code = code
                    .parse::<u32>()
                    .with_context(|| format!("invalid Binder code '{code}' for {service}"))?;
                by_service_code.insert((service.clone(), code), method);
            }
        }
        Ok(Self { by_service_code })
    }

    pub fn lookup(&self, service: &str, code: u32) -> Option<&str> {
        self.by_service_code
            .get(&(service.to_string(), code))
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_service_code.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_service_code.is_empty()
    }

    pub fn validate_catalog(&self, catalog: &AidlCatalog) -> Result<()> {
        for ((service, code), legacy_method) in &self.by_service_code {
            if let Some(lookup) = catalog.lookup(normalize_descriptor(service), *code) {
                if lookup.method.method != *legacy_method {
                    bail!(
                        "conflicting Binder method for {} code {}: catalog='{}', legacy='{}'",
                        normalize_descriptor(service),
                        code,
                        lookup.method.method,
                        legacy_method
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct BinderCatalog {
    by_pid: BTreeMap<u32, Vec<String>>,
    interfaces_by_pid: BTreeMap<u32, Vec<String>>,
}

impl BinderCatalog {
    pub fn discover(include_services: bool, include_hal: bool) -> Self {
        let mut catalog = Self::default();
        if include_services || include_hal {
            if let Ok(output) = crate::android::run_platform_command("service", &["list", "-p"]) {
                if output.status.success() {
                    catalog.merge_service_list(&String::from_utf8_lossy(&output.stdout));
                }
            }
        }
        if include_hal {
            if let Ok(output) = crate::android::run_platform_command("lshal", &["-i", "-p"]) {
                if output.status.success() {
                    catalog.merge_lshal(&String::from_utf8_lossy(&output.stdout));
                }
            }
        }
        catalog
    }

    pub fn merge_service_list(&mut self, output: &str) {
        if let Ok(parsed) = crate::report::parse_service_list(output) {
            self.merge(parsed);
        }
        self.merge_interfaces(parse_service_list_interfaces(output));
    }

    pub fn merge_lshal(&mut self, output: &str) {
        let parsed = parse_lshal(output);
        self.merge_interfaces(parsed.clone());
        self.merge(parsed);
    }

    pub fn candidates(&self, pid: u32) -> &[String] {
        self.by_pid.get(&pid).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn resolve(
        &self,
        exact: &BinderServiceMap,
        methods: &BinderMethodMap,
        pid: u32,
        target_node: i32,
        code: u32,
    ) -> BinderAttribution {
        self.resolve_with_aidl(exact, methods, None, pid, target_node, code)
            .expect("resolution without an AIDL catalog cannot conflict")
    }

    pub fn resolve_with_aidl(
        &self,
        exact: &BinderServiceMap,
        methods: &BinderMethodMap,
        aidl: Option<&AidlCatalog>,
        pid: u32,
        target_node: i32,
        code: u32,
    ) -> Result<BinderAttribution> {
        if let Some(service) = exact.lookup(pid, target_node) {
            let descriptor = normalize_descriptor(service);
            let catalog_match = aidl.and_then(|catalog| catalog.lookup(descriptor, code));
            let legacy_method = methods
                .lookup(service, code)
                .or_else(|| methods.lookup(descriptor, code));
            if let (Some(catalog_match), Some(legacy_method)) = (&catalog_match, legacy_method) {
                if catalog_match.method.method != legacy_method {
                    bail!(
                        "conflicting Binder method for {descriptor} code {code}: catalog='{}', legacy='{legacy_method}'",
                        catalog_match.method.method
                    );
                }
            }
            return Ok(BinderAttribution {
                service: Some(service.to_string()),
                candidates: Vec::new(),
                interface_descriptor: Some(descriptor.to_string()),
                interface_candidates: Vec::new(),
                method: catalog_match
                    .as_ref()
                    .map(|found| found.method.method.clone())
                    .or_else(|| legacy_method.map(str::to_string)),
                aidl_version: catalog_match
                    .as_ref()
                    .and_then(|found| found.version.clone()),
                catalog_source: catalog_match.map(|found| found.source.to_string()),
                confidence: Some(AttributionConfidence::Exact),
                code,
            });
        }
        let candidates = self.candidates(pid).to_vec();
        let service = (candidates.len() == 1).then(|| candidates[0].clone());
        let mut interface_candidates =
            self.interfaces_by_pid
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| {
                    candidates
                        .iter()
                        .map(|candidate| normalize_descriptor(candidate).to_string())
                        .collect()
                });
        interface_candidates.sort();
        interface_candidates.dedup();
        Ok(BinderAttribution {
            service,
            confidence: (!candidates.is_empty()).then_some(AttributionConfidence::Candidate),
            candidates,
            interface_descriptor: None,
            interface_candidates,
            method: None,
            aidl_version: None,
            catalog_source: None,
            code,
        })
    }

    fn merge(&mut self, values: BTreeMap<u32, Vec<String>>) {
        for (pid, names) in values {
            let entry = self.by_pid.entry(pid).or_default();
            for name in names {
                if !entry.contains(&name) {
                    entry.push(name);
                }
            }
            entry.sort();
        }
    }

    fn merge_interfaces(&mut self, values: BTreeMap<u32, Vec<String>>) {
        for (pid, names) in values {
            let entry = self.interfaces_by_pid.entry(pid).or_default();
            for name in names {
                let descriptor = normalize_descriptor(&name).to_string();
                if !entry.contains(&descriptor) {
                    entry.push(descriptor);
                }
            }
            entry.sort();
        }
    }
}

fn parse_service_list_interfaces(output: &str) -> BTreeMap<u32, Vec<String>> {
    let mut parsed = BTreeMap::<u32, Vec<String>>::new();
    for line in output.lines() {
        let Some(pid) = line
            .split_whitespace()
            .find_map(|token| token.strip_prefix("pid="))
            .and_then(|value| {
                value
                    .trim_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
        else {
            continue;
        };
        let Some(start) = line.find('[') else {
            continue;
        };
        let Some(end) = line[start + 1..].find(']').map(|end| start + 1 + end) else {
            continue;
        };
        let descriptor = line[start + 1..end].trim();
        if descriptor.contains('.') {
            parsed.entry(pid).or_default().push(descriptor.to_string());
        }
    }
    for interfaces in parsed.values_mut() {
        interfaces.sort();
        interfaces.dedup();
    }
    parsed
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BinderAttribution {
    pub service: Option<String>,
    pub candidates: Vec<String>,
    pub interface_descriptor: Option<String>,
    pub interface_candidates: Vec<String>,
    pub method: Option<String>,
    pub aidl_version: Option<String>,
    pub catalog_source: Option<String>,
    pub confidence: Option<AttributionConfidence>,
    code: u32,
}

impl BinderAttribution {
    pub fn method_label(&self) -> String {
        self.method
            .clone()
            .unwrap_or_else(|| format!("code={}", self.code))
    }
}

/// Parse the PID-bearing compact output of `lshal -ip`. Both HIDL names
/// (`package@ver::IType/instance`) and AIDL names (`package.IType/instance`)
/// are retained as candidate attribution only.
pub fn parse_lshal(output: &str) -> BTreeMap<u32, Vec<String>> {
    let mut parsed = BTreeMap::<u32, Vec<String>>::new();
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some((service_index, service)) = tokens.iter().enumerate().find(|(_, token)| {
            (token.contains("::") || (token.contains('/') && token.contains('.')))
                && !token.starts_with('/')
        }) else {
            continue;
        };
        let pid = tokens[service_index + 1..]
            .iter()
            .filter_map(|token| {
                token
                    .trim_matches(|c: char| !c.is_ascii_digit())
                    .parse::<u32>()
                    .ok()
            })
            .find(|pid| *pid > 0);
        let Some(pid) = pid else { continue };
        let names = parsed.entry(pid).or_default();
        let service = service.trim_matches(|c: char| matches!(c, ',' | '[' | ']'));
        if !names.iter().any(|name| name == service) {
            names.push(service.to_string());
            names.sort();
        }
    }
    parsed
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
