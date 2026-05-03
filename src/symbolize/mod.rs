//! Userspace + kernel symbol resolution.
//!
//! Layered for cache-friendly operation:
//! - [`proc_maps`] parses `/proc/<pid>/maps` once per PID.
//! - [`elf`] loads function symbols from each shared library at most once.
//! - [`art`] tags ART JIT regions before any ELF lookup is attempted.
//! - [`kallsyms`] resolves kernel-side IPs from a one-shot `/proc/kallsyms`.
//!
//! Public types: [`MapEntry`], [`ProcSymbolizer`], [`KernelSymbolizer`].

pub mod art;
pub mod elf;
pub mod kallsyms;
pub mod proc_maps;

use std::collections::HashMap;

pub use kallsyms::KernelSymbolizer;
pub use proc_maps::{parse_proc_maps, MapEntry};

use elf::ElfSymbols;

// ─── Backwards-compatibility shim ───────────────────────────────────────────
//
// The legacy single-file `symbolize.rs` exported `resolve_symbol(ip, &maps)`.
// Keep it so existing callers (and a couple of older tests) keep building.

/// Resolve `ip` using only library+offset (no ELF symbol lookup).
///
/// Prefer [`ProcSymbolizer::symbolize`] for the production path — it adds
/// ELF symbol resolution and ART JIT tagging.
pub fn resolve_symbol(ip: u64, maps: &[MapEntry]) -> String {
    for entry in maps {
        if entry.contains(ip) {
            let offset = ip - entry.start;
            if entry.name.is_empty() {
                return format!("[anon]+{:#x}", offset);
            }
            return format!("{}+{:#x}", entry.name, offset);
        }
    }
    format!("{:#x}", ip)
}

// ─── ProcSymbolizer ────────────────────────────────────────────────────────

/// Per-process symbolizer. Holds a parsed /proc/<pid>/maps snapshot and a
/// per-file ELF symbol cache. Cheap to construct, cheap per-lookup after the
/// first ELF load.
pub struct ProcSymbolizer {
    pid: u32,
    maps: Vec<MapEntry>,
    /// `path -> Some(symbols) | None`. `None` means the load was attempted and
    /// failed (file unreadable, stripped, parse error). Caching the negative
    /// result avoids retrying on every event.
    elf_cache: HashMap<String, Option<ElfSymbols>>,
}

impl ProcSymbolizer {
    /// Build for `pid`. Returns `None` if `/proc/<pid>/maps` is not readable.
    pub fn new(pid: u32) -> Option<Self> {
        let maps = parse_proc_maps(pid)?;
        Some(Self {
            pid,
            maps,
            elf_cache: HashMap::new(),
        })
    }

    /// PID this symbolizer is bound to.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Symbolize `ip`. Returns one of:
    /// - `"file:symbol+0xN"` — full ELF resolution
    /// - `"file+0xN"` — fell back to library + map offset
    /// - `"<JIT>+0xN"` — ART JIT region (no symbol attempted)
    /// - `"[anon]+0xN"` — anonymous mapping
    /// - `"0xN"` — IP outside any mapped region
    pub fn symbolize(&mut self, ip: u64) -> String {
        // Find the map entry covering `ip`.
        let entry_idx = match self.maps.iter().position(|e| e.contains(ip)) {
            Some(i) => i,
            None => return format!("{:#x}", ip),
        };
        // Snapshot fields we need so we can release the borrow before mutating
        // the elf_cache.
        let (name, perms, start) = {
            let e = &self.maps[entry_idx];
            (e.name.clone(), e.perms.clone(), e.start)
        };
        let offset_in_region = ip - start;

        // ART JIT short-circuit.
        if art::is_jit_region(&name) {
            return format!("<JIT>+{:#x}", offset_in_region);
        }

        // Anonymous mapping (no file): fall back to plain offset.
        if name.is_empty() || name.starts_with('[') {
            let label = if name.is_empty() {
                "[anon]"
            } else {
                name.as_str()
            };
            return format!("{}+{:#x}", label, offset_in_region);
        }

        // Need executable permissions for this to be a real code IP. If not
        // executable, the data segment of a shared lib still has a useful
        // file basename, so render `lib+offset` without attempting ELF lookup.
        if !perms.as_bytes().get(2).is_some_and(|c| *c == b'x') {
            let basename = basename(&name);
            return format!("{}+{:#x}", basename, offset_in_region);
        }

        // Try the ELF symbol table. The cache stores `Option<ElfSymbols>` so a
        // previous failure doesn't trigger a re-read on every event.
        let entry_clone = self.maps[entry_idx].clone();
        let elf = self
            .elf_cache
            .entry(name.clone())
            .or_insert_with(|| ElfSymbols::load(&name));

        let basename = basename(&name);
        match elf {
            Some(syms) => {
                if let Some(resolved) = syms.lookup(ip, &entry_clone) {
                    format!("{}:{}", basename, resolved)
                } else {
                    format!("{}+{:#x}", basename, offset_in_region)
                }
            }
            None => format!("{}+{:#x}", basename, offset_in_region),
        }
    }
}

fn basename(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, b)) => b,
        None => path,
    }
}

// ─── Convenience: classify userspace vs kernel addresses ───────────────────

/// Returns `true` if `ip` looks like a kernel-space address on aarch64.
///
/// Linux/Android with VA_BITS=39 or 48 places kernel mappings in the upper
/// canonical half (`0xffff_...`). Userspace addresses fit comfortably below
/// `0xffff_0000_0000_0000`. We use that simple boundary.
pub fn is_kernel_addr(ip: u64) -> bool {
    ip >= 0xffff_0000_0000_0000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_symbol_returns_library_plus_offset_legacy_shim() {
        let maps = vec![MapEntry {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            perms: "r-xp".into(),
            name: "libfoo.so".into(),
        }];
        assert_eq!(resolve_symbol(0x1500, &maps), "libfoo.so+0x500");
    }

    #[test]
    fn resolve_symbol_returns_hex_when_out_of_range() {
        let maps = vec![MapEntry {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            perms: "r-xp".into(),
            name: "libfoo.so".into(),
        }];
        let s = resolve_symbol(0xdeadbeef, &maps);
        assert!(s.starts_with("0x"), "got {s}");
    }

    #[test]
    fn resolve_symbol_handles_empty_maps() {
        let maps: Vec<MapEntry> = Vec::new();
        assert_eq!(resolve_symbol(0x42, &maps), "0x42");
    }

    #[test]
    fn is_kernel_addr_partitions_correctly() {
        assert!(is_kernel_addr(0xffff_8000_1234_5678));
        assert!(is_kernel_addr(0xffffffc008080100));
        assert!(!is_kernel_addr(0x7fff_ffff_ffff));
        assert!(!is_kernel_addr(0));
    }

    #[test]
    fn proc_symbolizer_for_self_returns_some_string() {
        let mut sym = ProcSymbolizer::new(std::process::id()).expect("self symbolizer");
        // Pick an address inside the running test binary's first executable
        // map entry. The test binary is always ET_EXEC or ET_DYN with the
        // .text segment mapped r-xp.
        let exec_entry = sym
            .maps
            .iter()
            .find(|e| e.is_executable())
            .cloned()
            .expect("self has at least one executable mapping");
        let ip = exec_entry.start + 0x10;
        let s = sym.symbolize(ip);
        assert!(!s.is_empty());
        // Either "file:sym+0xN" or "file+0xN" — both valid.
        assert!(s.contains('+'), "got {s}");
    }

    #[test]
    fn proc_symbolizer_tags_jit_regions() {
        // Construct a synthetic symbolizer with a JIT region.
        let mut sym = ProcSymbolizer {
            pid: 0,
            maps: vec![MapEntry {
                start: 0x70a0000000,
                end: 0x70a8000000,
                offset: 0,
                perms: "rwxp".into(),
                name: "[anon:dalvik-jit-code-cache (zygote)]".into(),
            }],
            elf_cache: HashMap::new(),
        };
        let s = sym.symbolize(0x70a0001234);
        assert!(s.starts_with("<JIT>+0x"), "got {s}");
    }

    #[test]
    fn proc_symbolizer_returns_hex_outside_any_map() {
        let mut sym = ProcSymbolizer {
            pid: 0,
            maps: vec![],
            elf_cache: HashMap::new(),
        };
        let s = sym.symbolize(0xdead_beef);
        assert!(s.starts_with("0x"), "got {s}");
    }

    #[test]
    fn proc_symbolizer_anonymous_region_uses_anon_label() {
        let mut sym = ProcSymbolizer {
            pid: 0,
            maps: vec![MapEntry {
                start: 0x10000,
                end: 0x20000,
                offset: 0,
                perms: "rw-p".into(),
                name: "".into(),
            }],
            elf_cache: HashMap::new(),
        };
        let s = sym.symbolize(0x10010);
        assert_eq!(s, "[anon]+0x10");
    }

    #[test]
    fn proc_symbolizer_non_exec_lib_falls_back_to_basename() {
        let mut sym = ProcSymbolizer {
            pid: 0,
            maps: vec![MapEntry {
                start: 0x7f0000010000,
                end: 0x7f0000020000,
                offset: 0x10000,
                perms: "r--p".into(), // no x
                name: "/system/lib64/libc.so".into(),
            }],
            elf_cache: HashMap::new(),
        };
        let s = sym.symbolize(0x7f0000010050);
        assert_eq!(s, "libc.so+0x50");
    }
}
