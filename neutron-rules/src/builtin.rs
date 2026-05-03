//! Built-in default rule pack.
//!
//! Embeds `rules/default.yaml` at compile time so the binary works without an
//! external rule file. Users can override with `--rules path/to/custom.yaml`.

/// The default ruleset, bundled into the binary at compile time.
pub const DEFAULT_RULES_YAML: &str = include_str!("../rules/default.yaml");
