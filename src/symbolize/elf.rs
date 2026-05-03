//! ELF symbol-table loader (goblin-backed).
//!
//! For each shared library / executable found in /proc/<pid>/maps we load the
//! function symbols (STT_FUNC) from `.symtab` ∪ `.dynsym`, sort them by virtual
//! address, and binary-search per IP. Cached per file path.
//!
//! Address translation:
//! - Shared library (ET_DYN): runtime address = entry.start + (sym.st_value - segment_file_offset).
//!   In practice we approximate with `entry.start - entry.offset` as the
//!   "load bias" when `entry` is the executable r-xp segment of the .so.
//! - Executable (ET_EXEC): runtime address = sym.st_value (PIE-disabled
//!   binaries are rare on modern Android, so this branch is mostly a fallback).

use goblin::elf::{sym::STT_FUNC, Elf};
use std::fs;

use super::proc_maps::MapEntry;

/// One executable function symbol pulled from an ELF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    /// Symbol virtual address as recorded in the ELF (`st_value`). For ET_DYN
    /// this is the offset from the load bias, not a runtime VA.
    pub vaddr: u64,
    pub size: u64,
    pub name: String,
}

/// Sorted symbol table for one ELF file plus a flag telling us how to
/// translate the file vaddr to a runtime IP.
pub struct ElfSymbols {
    /// Sorted ascending by `vaddr`.
    pub syms: Vec<ElfSymbol>,
    /// `true` for shared objects (ET_DYN) where the runtime IP is biased.
    pub is_dyn: bool,
}

impl ElfSymbols {
    /// Load the function-symbol table from `path`. Returns `None` if the file
    /// cannot be read or parsed as ELF, or if it has no FUNC symbols at all
    /// (stripped binaries — common on Android).
    pub fn load(path: &str) -> Option<Self> {
        let bytes = fs::read(path).ok()?;
        Self::from_bytes(&bytes)
    }

    /// Parse ELF bytes into a symbol table. Public for tests.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let elf = Elf::parse(bytes).ok()?;

        let mut syms = Vec::new();
        // .dynsym (always shipped) + .symtab (often stripped from Android libs).
        let iter = elf.dynsyms.iter().chain(elf.syms.iter());
        let strtab_static = &elf.strtab;
        let dynstrtab_static = &elf.dynstrtab;

        for sym in iter {
            if sym.st_type() != STT_FUNC {
                continue;
            }
            if sym.st_value == 0 {
                continue; // undefined / external
            }
            // Try .symtab strtab first, then .dynsym dynstrtab.
            let name = strtab_static
                .get_at(sym.st_name)
                .or_else(|| dynstrtab_static.get_at(sym.st_name))
                .unwrap_or("");
            if name.is_empty() {
                continue;
            }
            syms.push(ElfSymbol {
                vaddr: sym.st_value,
                size: sym.st_size,
                name: name.to_string(),
            });
        }

        if syms.is_empty() {
            return None;
        }
        syms.sort_by_key(|s| s.vaddr);
        // Dedupe by vaddr (some libs alias the same address with multiple names).
        syms.dedup_by(|a, b| a.vaddr == b.vaddr);

        let is_dyn = matches!(
            elf.header.e_type,
            goblin::elf::header::ET_DYN
        );

        Some(ElfSymbols { syms, is_dyn })
    }

    /// Look up the symbol containing `runtime_ip` given the executable
    /// `MapEntry` it falls into. Returns `Some("name+0xoffset")` on a hit,
    /// `None` if no symbol covers the address.
    pub fn lookup(&self, runtime_ip: u64, entry: &MapEntry) -> Option<String> {
        // Translate runtime IP to ELF file vaddr.
        let file_vaddr = if self.is_dyn {
            // load_bias = entry.start - entry.offset (assumes the entry is the
            // r-xp segment of this ELF file). For multi-segment ELFs this is
            // the correct bias for ANY segment, since p_vaddr alignment = file
            // offset alignment.
            let load_bias = entry.start.wrapping_sub(entry.offset);
            runtime_ip.wrapping_sub(load_bias)
        } else {
            runtime_ip
        };

        // Binary search for the largest vaddr <= file_vaddr.
        let idx = match self.syms.binary_search_by_key(&file_vaddr, |s| s.vaddr) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let sym = &self.syms[idx];
        // Reject if outside the symbol's size band, when known.
        if sym.size > 0 && file_vaddr >= sym.vaddr.saturating_add(sym.size) {
            return None;
        }
        let offset = file_vaddr - sym.vaddr;
        Some(format!("{}+{:#x}", sym.name, offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_function_symbols_from_test_binary() {
        // Use the running test binary itself — it always has at least one
        // FUNC symbol (the test runner's `main`).
        let exe = std::env::current_exe().expect("current_exe");
        let bytes = fs::read(&exe).expect("read self");
        let elf = ElfSymbols::from_bytes(&bytes);
        assert!(elf.is_some(), "expected at least one FUNC symbol in test binary");
        let elf = elf.unwrap();
        assert!(!elf.syms.is_empty());
        // Symbols must be sorted ascending.
        for w in elf.syms.windows(2) {
            assert!(w[0].vaddr <= w[1].vaddr, "symbols not sorted");
        }
    }

    #[test]
    fn lookup_handles_out_of_range_addr() {
        let syms = ElfSymbols {
            syms: vec![ElfSymbol {
                vaddr: 0x1000,
                size: 0x100,
                name: "foo".into(),
            }],
            is_dyn: false,
        };
        let entry = MapEntry {
            start: 0x0,
            end: 0x10000,
            offset: 0,
            perms: "r-xp".into(),
            name: "x".into(),
        };
        // 0x500 is below the lowest symbol → no hit.
        assert!(syms.lookup(0x500, &entry).is_none());
    }

    #[test]
    fn lookup_returns_symbol_plus_offset_for_exec() {
        let syms = ElfSymbols {
            syms: vec![
                ElfSymbol { vaddr: 0x1000, size: 0x100, name: "foo".into() },
                ElfSymbol { vaddr: 0x2000, size: 0x100, name: "bar".into() },
            ],
            is_dyn: false,
        };
        let entry = MapEntry {
            start: 0x0,
            end: 0x10000,
            offset: 0,
            perms: "r-xp".into(),
            name: "x".into(),
        };
        assert_eq!(syms.lookup(0x1042, &entry).as_deref(), Some("foo+0x42"));
        assert_eq!(syms.lookup(0x2010, &entry).as_deref(), Some("bar+0x10"));
    }

    #[test]
    fn lookup_handles_dynamic_load_bias() {
        let syms = ElfSymbols {
            syms: vec![ElfSymbol {
                vaddr: 0x1000,
                size: 0x100,
                name: "malloc".into(),
            }],
            is_dyn: true,
        };
        // Library mapped at 0x7f0000000000, .text segment file offset 0.
        let entry = MapEntry {
            start: 0x7f0000000000,
            end: 0x7f0000010000,
            offset: 0,
            perms: "r-xp".into(),
            name: "libc.so".into(),
        };
        // Runtime IP for symbol vaddr 0x1042: 0x7f0000001042
        let s = syms.lookup(0x7f0000001042, &entry).unwrap();
        assert_eq!(s, "malloc+0x42");
    }

    #[test]
    fn lookup_rejects_addr_past_symbol_size() {
        let syms = ElfSymbols {
            syms: vec![ElfSymbol {
                vaddr: 0x1000,
                size: 0x10,
                name: "tiny".into(),
            }],
            is_dyn: false,
        };
        let entry = MapEntry {
            start: 0,
            end: 0x10000,
            offset: 0,
            perms: "r-xp".into(),
            name: "x".into(),
        };
        // Past the symbol's size.
        assert!(syms.lookup(0x2000, &entry).is_none());
    }
}
