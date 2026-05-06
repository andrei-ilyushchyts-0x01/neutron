//! Synchronous `/proc/<pid>/fdinfo/<fd>` reader for finding enrichment.
//!
//! Phase 4a. The periodic FD-graph poller (sprint-1 PR 3) samples
//! `/proc/<pid>/fd` every ~1s, which is too coarse for transient fds
//! that exist only between adjacent ioctls. This module reads
//! `/proc/<pid>/fdinfo/<fd>` *at finding-emit time*, producing a tight
//! snapshot of the kernel's view of a specific (pid, fd) pair.
//!
//! Output shape (kept JSON-serializable so the enrichment can splice
//! straight into the emitted finding):
//!
//! ```json
//! "fdinfo_at_event": {
//!   "<fd>": { "pos": 0, "flags": "02100002", "mnt_id": 21, "ino": 12345 }
//! }
//! ```
//!
//! `flags` is kept as the kernel's hex string rather than re-decoding —
//! the operator can grep for `O_RDWR|O_CLOEXEC` patterns externally and
//! we avoid inventing a parser that could disagree with `man 2 open`.
//!
//! Errors: any I/O failure (process gone, EACCES under SELinux,
//! truncated read) returns `None`. Failure is best-effort — finding
//! emission must never block on fdinfo.

use std::fs;

use serde::Serialize;

/// Subset of `/proc/<pid>/fdinfo/<fd>` we surface in the emitted JSON.
/// Other lines (encoding/seal flags for memfd, watch entries for
/// inotify, etc.) are ignored — they're driver-specific and add noise
/// to the typical "what fd was this ioctl on" workflow.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FdInfo {
    /// `pos:` line value, file offset in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pos: Option<u64>,
    /// `flags:` line value, kept as the kernel's octal hex string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    /// `mnt_id:` line value, mount-namespace identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnt_id: Option<u64>,
    /// `ino:` line value, inode of the underlying object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ino: Option<u64>,
}

impl FdInfo {
    /// `true` when no field is populated. Suppresses empty objects in
    /// JSON output.
    pub fn is_empty(&self) -> bool {
        self.pos.is_none() && self.flags.is_none() && self.mnt_id.is_none() && self.ino.is_none()
    }
}

/// Read `/proc/<pid>/fdinfo/<fd>` and return the parsed view. Returns
/// `None` on any I/O error or when the file is empty (process gone, fd
/// already closed, EACCES, etc.).
pub fn read(pid: u32, fd: i64) -> Option<FdInfo> {
    if fd < 0 {
        return None;
    }
    let path = format!("/proc/{pid}/fdinfo/{fd}");
    let raw = fs::read_to_string(&path).ok()?;
    let info = parse(&raw);
    if info.is_empty() {
        None
    } else {
        Some(info)
    }
}

/// Parse the textual fdinfo content. Public for testability without
/// touching the filesystem.
pub fn parse(raw: &str) -> FdInfo {
    let mut info = FdInfo::default();
    for line in raw.lines() {
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "pos" => info.pos = value.parse().ok(),
            "flags" => info.flags = Some(value.to_string()),
            "mnt_id" => info.mnt_id = value.parse().ok(),
            "ino" => info.ino = value.parse().ok(),
            _ => {} // ignore driver-specific extension lines
        }
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_fdinfo() {
        let raw = "pos:\t0\nflags:\t02100002\nmnt_id:\t21\nino:\t12345\n";
        let info = parse(raw);
        assert_eq!(info.pos, Some(0));
        assert_eq!(info.flags.as_deref(), Some("02100002"));
        assert_eq!(info.mnt_id, Some(21));
        assert_eq!(info.ino, Some(12345));
        assert!(!info.is_empty());
    }

    #[test]
    fn ignores_unknown_extension_lines() {
        let raw = "pos:\t100\nflags:\t01\nseal:\t0x0\nencoding:\t1\n";
        let info = parse(raw);
        assert_eq!(info.pos, Some(100));
        assert_eq!(info.flags.as_deref(), Some("01"));
        // unknown lines don't crash the parser; they just don't surface.
    }

    #[test]
    fn empty_input_yields_empty_view() {
        let info = parse("");
        assert!(info.is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let raw = "garbage\npos:\nflags: 02\n";
        let info = parse(raw);
        assert_eq!(info.pos, None);
        assert_eq!(info.flags.as_deref(), Some("02"));
    }

    #[test]
    fn read_returns_none_for_negative_fd() {
        assert_eq!(read(1, -1), None);
    }

    #[test]
    fn serializes_only_populated_fields() {
        let info = FdInfo {
            flags: Some("01".into()),
            ..FdInfo::default()
        };
        let s = serde_json::to_string(&info).unwrap();
        assert_eq!(s, r#"{"flags":"01"}"#);
    }

    #[test]
    fn read_self_returns_some_for_open_fd() {
        // Opening a real file gives us a known fd; reading back should
        // succeed on a Linux host. Skip if not on Linux to keep CI portable.
        #[cfg(target_os = "linux")]
        {
            use std::fs::File;
            use std::os::fd::AsRawFd;
            let f = File::open("/proc/self/cmdline").expect("open /proc/self/cmdline");
            let pid = std::process::id();
            let fd = f.as_raw_fd();
            let info = read(pid, fd as i64);
            assert!(info.is_some(), "fdinfo for self/cmdline should exist");
        }
    }
}
