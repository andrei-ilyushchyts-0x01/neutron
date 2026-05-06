//! `/proc/modules` reader for module-relative kernel symbolisation.
//!
//! Phase 5b. When `kptr_restrict >= 1` the kallsyms-based
//! [`super::KernelSymbolizer`] sees zeroed addresses and surrenders.
//! `/proc/modules` exposes only module *load* addresses (one per
//! module) plus their byte size — enough to render a kernel IP as
//! `[<module>.ko]+0x<offset>` when the IP falls inside a known module's
//! range. Addresses outside any loaded module fall back to the bare
//! hex form.
//!
//! Format (Linux >= 4.x, stable):
//!
//! ```text
//! nf_conntrack 188416 0 - Live 0xffffffffc0a00000
//! ip_tables    32768  0 - Live 0xffffffffc09f0000
//! ```
//!
//! Columns: name, size (bytes), refcount, deps, state, address.
//! `kptr_restrict` does NOT mask `/proc/modules` (only kallsyms), so
//! this layer remains useful even when the inner-symbol layer is
//! blinded.
//!
//! The reader is one-shot at startup. Live module load/unload after
//! that point is rare on Pixel for security research and would only
//! cost an unresolved frame label, not correctness.

use std::fs;

/// One loaded kernel module's address range. `start..end` is the
/// half-open byte range covered by the module's text+data sections.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ModuleRange {
    name: String,
    start: u64,
    end: u64,
}

/// Sorted snapshot of `/proc/modules` ranges. Lookup is binary search
/// on the start address, then a contains-check.
#[derive(Clone, Debug, Default)]
pub struct KernelModules {
    ranges: Vec<ModuleRange>,
}

impl KernelModules {
    /// Read `/proc/modules` and build the range table. Returns `None`
    /// when the file is unreadable or yielded zero modules — both
    /// cases mean the resolver has nothing to add.
    pub fn load() -> Option<Self> {
        let raw = fs::read_to_string("/proc/modules").ok()?;
        let parsed = Self::from_text(&raw);
        if parsed.ranges.is_empty() {
            None
        } else {
            Some(parsed)
        }
    }

    /// Parse raw `/proc/modules` text. Public for unit tests.
    pub fn from_text(text: &str) -> Self {
        let mut ranges = Vec::new();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let name = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let size: u64 = match parts.next().and_then(|s| s.parse().ok()) {
                Some(s) => s,
                None => continue,
            };
            // Skip the next three columns (refcount, deps, state).
            let addr_col = parts.nth(3);
            let addr_s = match addr_col {
                Some(s) => s,
                None => continue,
            };
            let addr = match parse_hex_addr(addr_s) {
                Some(v) => v,
                None => continue,
            };
            if addr == 0 || size == 0 {
                continue;
            }
            ranges.push(ModuleRange {
                name: name.to_string(),
                start: addr,
                end: addr.saturating_add(size),
            });
        }
        ranges.sort_by_key(|r| r.start);
        KernelModules { ranges }
    }

    /// Look up the module containing `ip`. Returns `Some("[<name>]+0xoff")`
    /// when found, `None` otherwise.
    pub fn resolve(&self, ip: u64) -> Option<String> {
        if self.ranges.is_empty() {
            return None;
        }
        let idx = match self.ranges.binary_search_by_key(&ip, |r| r.start) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let r = &self.ranges[idx];
        if ip >= r.start && ip < r.end {
            let offset = ip - r.start;
            Some(format!("[{}]+{:#x}", r.name, offset))
        } else {
            None
        }
    }

    /// Number of loaded modules in the snapshot.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

fn parse_hex_addr(s: &str) -> Option<u64> {
    let trimmed = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))?;
    u64::from_str_radix(trimmed, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
nf_conntrack 188416 0 - Live 0xffffffffc0a00000
ip_tables 32768 0 - Live 0xffffffffc09f0000
mymod 4096 0 - Live 0xffffffffc09e0000
";

    #[test]
    fn parses_three_modules() {
        let m = KernelModules::from_text(SAMPLE);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn resolve_inside_first_module_returns_label() {
        let m = KernelModules::from_text(SAMPLE);
        let ip = 0xffffffffc09f0010;
        assert_eq!(m.resolve(ip), Some("[ip_tables]+0x10".to_string()));
    }

    #[test]
    fn resolve_just_below_module_returns_none() {
        let m = KernelModules::from_text(SAMPLE);
        // One byte below the lowest module's start address.
        let ip = 0xffffffffc09e0000 - 1;
        assert_eq!(m.resolve(ip), None);
    }

    #[test]
    fn resolve_at_module_end_is_exclusive() {
        let m = KernelModules::from_text(SAMPLE);
        // mymod is 4096 bytes long; +0x1000 sits right past the end.
        let ip = 0xffffffffc09e0000 + 0x1000;
        // Must NOT resolve to mymod.
        let r = m.resolve(ip);
        assert!(r.is_none() || !r.as_ref().unwrap().starts_with("[mymod]"));
    }

    #[test]
    fn resolve_outside_all_modules_returns_none() {
        let m = KernelModules::from_text(SAMPLE);
        assert_eq!(m.resolve(0xffffffffc0000000), None);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let raw = "garbage\n\nincomplete row\nnf_conntrack 4096 0 - Live 0xffffffffc0a00000\n";
        let m = KernelModules::from_text(raw);
        assert_eq!(m.len(), 1);
        assert!(m.resolve(0xffffffffc0a00000).is_some());
    }

    #[test]
    fn zero_size_or_zero_addr_lines_are_skipped() {
        let raw = "\
zero_addr 4096 0 - Live 0x0
zero_size 0 0 - Live 0xffffffffc0a00000
";
        let m = KernelModules::from_text(raw);
        assert!(m.is_empty());
    }

    #[test]
    fn parse_hex_addr_supports_lowercase_and_uppercase() {
        assert_eq!(parse_hex_addr("0xff"), Some(0xff));
        assert_eq!(parse_hex_addr("0X10"), Some(16));
        assert_eq!(parse_hex_addr("ff"), None);
    }

    #[test]
    fn load_returns_some_or_none_on_real_proc() {
        // We can't promise modules exist (containers, custom kernels), so
        // accept either outcome but never panic.
        let _ = KernelModules::load();
    }
}
