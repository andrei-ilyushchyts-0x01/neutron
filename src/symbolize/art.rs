//! ART JIT code-cache region detection.
//!
//! Frames inside ART's JIT code cache cannot be symbolized — there is no ELF
//! symbol table for JITted Java/Kotlin methods at runtime (perf-jit `.dump`
//! files exist but are out of scope for V1). We tag these frames as `<JIT>`
//! and skip the ELF lookup entirely.
//!
//! Region naming taken from observed `/proc/<pid>/maps` lines on Android 14:
//!     `[anon:dalvik-jit-code-cache]`
//!     `[anon:dalvik-jit-code-cache (zygote)]`
//!     `/memfd:jit-cache (deleted)`
//!     `[anon:dalvik-non-moving-space]` (low-priority, treated as JIT-adjacent)

/// Returns `true` if `name` (a /proc/<pid>/maps trailing path) is an ART JIT
/// code-cache region.
pub fn is_jit_region(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with("[anon:dalvik-jit-code-cache") {
        return true;
    }
    if name.starts_with("/memfd:jit-cache") {
        return true;
    }
    if name.starts_with("[anon:dalvik-non-moving-space") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_dalvik_jit_code_cache() {
        assert!(is_jit_region("[anon:dalvik-jit-code-cache]"));
        assert!(is_jit_region("[anon:dalvik-jit-code-cache (zygote)]"));
    }

    #[test]
    fn matches_memfd_jit_cache() {
        assert!(is_jit_region("/memfd:jit-cache (deleted)"));
        assert!(is_jit_region("/memfd:jit-cache"));
    }

    #[test]
    fn matches_non_moving_space() {
        assert!(is_jit_region("[anon:dalvik-non-moving-space]"));
    }

    #[test]
    fn rejects_libc_so() {
        assert!(!is_jit_region("/system/lib64/libc.so"));
    }

    #[test]
    fn rejects_empty() {
        assert!(!is_jit_region(""));
    }

    #[test]
    fn rejects_stack_and_heap() {
        assert!(!is_jit_region("[stack]"));
        assert!(!is_jit_region("[heap]"));
    }
}
