//! YAML rule loader.
//!
//! The on-disk format is a top-level list:
//! ```yaml
//! - id: T001_proc_self_maps_polling
//!   name: ...
//!   severity: medium
//!   category: root_detection
//!   conditions:
//!     - syscall_in: [56]
//!     - path_prefix: /proc/self/maps
//!   frequency:
//!     window_ms: 10000
//!     min_count: 2
//!   aggregate: per_process
//! - id: T002_...
//! ```

use std::fs;
use std::path::Path;

use thiserror::Error;

use crate::rule::Rule;

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("failed to read rule file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("rule validation failed: {0}")]
    Validation(String),
}

pub fn load_rules_yaml_str(s: &str) -> Result<Vec<Rule>, LoaderError> {
    let rules: Vec<Rule> = serde_yaml::from_str(s)?;
    for r in &rules {
        r.validate().map_err(LoaderError::Validation)?;
    }
    Ok(rules)
}

pub fn load_rules_yaml_file(path: impl AsRef<Path>) -> Result<Vec<Rule>, LoaderError> {
    let contents = fs::read_to_string(path)?;
    load_rules_yaml_str(&contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_minimal_yaml() {
        let yaml = r#"
- id: T999_test
  name: Test rule
  description: Test
  severity: low
  category: recon
  conditions:
    - syscall_in: [56]
"#;
        let rules = load_rules_yaml_str(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "T999_test");
    }

    #[test]
    fn rejects_rule_with_no_conditions() {
        let yaml = r#"
- id: T999_bad
  name: Bad
  description: No conditions
  severity: low
  category: recon
  conditions: []
"#;
        let err = load_rules_yaml_str(yaml).unwrap_err();
        assert!(matches!(err, LoaderError::Validation(_)));
    }
}
