//! Kernel symbol resolution via `/proc/kallsyms`.
//!
//! Loaded once at startup, sorted, then binary-searched per IP. When the
//! kernel has `kptr_restrict=2` and we're not running as root, every entry's
//! address reads as `0` — in that case we return `None` so the caller falls
//! back to printing the raw hex IP.

use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernSym {
    addr: u64,
    name: String,
}

/// Sorted /proc/kallsyms snapshot.
pub struct KernelSymbolizer {
    syms: Vec<KernSym>,
}

impl KernelSymbolizer {
    /// Read /proc/kallsyms and build a sorted symbol table. Returns `None` if
    /// every entry has address 0 (kptr_restrict masking) or the file is empty.
    pub fn from_kallsyms() -> Option<Self> {
        let content = fs::read_to_string("/proc/kallsyms").ok()?;
        Self::from_text(&content)
    }

    /// Parse kallsyms-formatted text. Public for unit tests.
    pub fn from_text(text: &str) -> Option<Self> {
        let mut syms = Vec::new();
        for line in text.lines() {
            // Format: `<addr> <type> <name>` (optional `[module]` suffix)
            let mut parts = line.split_whitespace();
            let addr_s = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let _typ = parts.next();
            let name = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let addr = u64::from_str_radix(addr_s, 16).unwrap_or(0);
            if addr == 0 {
                continue; // masked or invalid
            }
            syms.push(KernSym { addr, name: name.to_string() });
        }

        if syms.is_empty() {
            return None;
        }
        syms.sort_by_key(|s| s.addr);
        syms.dedup_by(|a, b| a.addr == b.addr);
        Some(KernelSymbolizer { syms })
    }

    /// Look up the symbol containing `ip`. Returns `"name+0xoffset"` or, on
    /// miss, the raw hex form `"0x..."`.
    pub fn symbolize(&self, ip: u64) -> String {
        let idx = match self.syms.binary_search_by_key(&ip, |s| s.addr) {
            Ok(i) => i,
            Err(0) => return format!("{:#x}", ip),
            Err(i) => i - 1,
        };
        let sym = &self.syms[idx];
        let offset = ip - sym.addr;
        format!("{}+{:#x}", sym.name, offset)
    }

    /// Number of resolvable symbols (for diagnostics / tests).
    pub fn len(&self) -> usize {
        self.syms.len()
    }

    pub fn is_empty(&self) -> bool {
        self.syms.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
ffffffc008000000 T _text
ffffffc008080000 T do_sys_open
ffffffc008080100 T sys_openat
ffffffc008090000 T vfs_read
";

    #[test]
    fn parses_sample_kallsyms() {
        let k = KernelSymbolizer::from_text(SAMPLE).expect("parse");
        assert_eq!(k.len(), 4);
    }

    #[test]
    fn symbolize_returns_name_plus_offset() {
        let k = KernelSymbolizer::from_text(SAMPLE).unwrap();
        assert_eq!(k.symbolize(0xffffffc008080042), "do_sys_open+0x42");
    }

    #[test]
    fn symbolize_picks_largest_addr_le_ip() {
        let k = KernelSymbolizer::from_text(SAMPLE).unwrap();
        assert_eq!(k.symbolize(0xffffffc008090010), "vfs_read+0x10");
    }

    #[test]
    fn symbolize_returns_hex_for_addr_below_first() {
        let k = KernelSymbolizer::from_text(SAMPLE).unwrap();
        let s = k.symbolize(0x1000);
        assert!(s.starts_with("0x"), "got {s}");
    }

    #[test]
    fn returns_none_when_all_addrs_masked() {
        let masked = "\
0000000000000000 T do_sys_open
0000000000000000 T vfs_read
";
        assert!(KernelSymbolizer::from_text(masked).is_none());
    }

    #[test]
    fn returns_none_for_empty_input() {
        assert!(KernelSymbolizer::from_text("").is_none());
    }

    #[test]
    fn parses_module_suffix() {
        let with_module = "ffffffc009000000 t my_init\t[mymod]\n";
        let k = KernelSymbolizer::from_text(with_module).unwrap();
        assert_eq!(k.symbolize(0xffffffc009000010), "my_init+0x10");
    }
}
