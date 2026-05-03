//! Parser for `/proc/<pid>/maps`.
//!
//! Each line of /proc/<pid>/maps looks like:
//!     7f8a3c000000-7f8a3c021000 r-xp 00000000 fd:00 12345  /system/lib64/libc.so
//!
//! We capture start, end, file offset, perms, and the trailing pathname
//! (which may be absent or pseudo like `[stack]`, `[anon:dalvik-jit-code-cache]`).

use std::fs;

/// A parsed `/proc/<pid>/maps` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    /// File offset for the mapping (column 3 of /proc/<pid>/maps). Needed to
    /// translate between ELF symbol vaddr and runtime IP for shared libraries.
    pub offset: u64,
    /// Permission string, e.g. `"r-xp"`. The trailing `p` is private vs `s`
    /// shared; the first three characters are r/w/x.
    pub perms: String,
    /// Pathname or pseudo region name. Empty string if /proc/<pid>/maps had no
    /// trailing column (anonymous mappings without a label).
    pub name: String,
}

impl MapEntry {
    /// Returns `true` if this region is mapped executable.
    pub fn is_executable(&self) -> bool {
        self.perms.as_bytes().get(2).copied() == Some(b'x')
    }

    /// Returns `true` if `ip` lies within `[start, end)`.
    pub fn contains(&self, ip: u64) -> bool {
        ip >= self.start && ip < self.end
    }
}

/// Parse `/proc/<pid>/maps` into a list of memory regions.
pub fn parse_proc_maps(pid: u32) -> Option<Vec<MapEntry>> {
    let content = fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;
    Some(parse_maps_text(&content))
}

/// Parse maps-formatted text. Public so unit tests can feed a fixture.
pub fn parse_maps_text(text: &str) -> Vec<MapEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(entry) = parse_line(line) {
            entries.push(entry);
        }
    }
    entries
}

fn parse_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?.to_string();
    let offset_s = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    // The trailing pathname can contain spaces in pseudo names like
    // `[anon:dalvik-jit-code-cache (zygote)]`. `split_whitespace` collapses
    // them, so re-join the rest with a single space.
    let name: String = {
        let rest: Vec<&str> = parts.collect();
        if rest.is_empty() {
            String::new()
        } else {
            rest.join(" ")
        }
    };

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;
    let offset = u64::from_str_radix(offset_s, 16).ok()?;

    Some(MapEntry { start, end, offset, perms, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_maps_line() {
        let line = "7f8a3c000000-7f8a3c021000 r-xp 00000000 fd:00 12345 /system/lib64/libc.so";
        let entry = parse_line(line).expect("parse");
        assert_eq!(entry.start, 0x7f8a3c000000);
        assert_eq!(entry.end, 0x7f8a3c021000);
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.perms, "r-xp");
        assert_eq!(entry.name, "/system/lib64/libc.so");
        assert!(entry.is_executable());
    }

    #[test]
    fn parses_anonymous_mapping_without_name() {
        let line = "7f8a40000000-7f8a40021000 rw-p 00000000 00:00 0";
        let entry = parse_line(line).expect("parse");
        assert_eq!(entry.name, "");
        assert!(!entry.is_executable());
    }

    #[test]
    fn parses_pseudo_name_with_spaces() {
        let line = "70a0000000-70a8000000 rw-p 00000000 00:00 0  [anon:dalvik-jit-code-cache (zygote)]";
        let entry = parse_line(line).expect("parse");
        assert_eq!(entry.name, "[anon:dalvik-jit-code-cache (zygote)]");
    }

    #[test]
    fn parses_offset_for_shared_library_segment() {
        let line = "7f8a3c021000-7f8a3c0a0000 r-xp 00021000 fd:00 12345 /system/lib64/libc.so";
        let entry = parse_line(line).expect("parse");
        assert_eq!(entry.offset, 0x21000);
    }

    #[test]
    fn contains_checks_half_open_range() {
        let entry = MapEntry {
            start: 0x1000,
            end: 0x2000,
            offset: 0,
            perms: "r-xp".into(),
            name: "x".into(),
        };
        assert!(entry.contains(0x1000));
        assert!(entry.contains(0x1fff));
        assert!(!entry.contains(0x2000));
        assert!(!entry.contains(0x0fff));
    }

    #[test]
    fn parse_proc_maps_for_self_returns_some_entries() {
        let maps = parse_proc_maps(std::process::id()).expect("self maps");
        assert!(!maps.is_empty());
        assert!(maps.iter().any(|e| e.end > e.start));
    }
}
