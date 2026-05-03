//! Misc OS-level helpers shared across binaries.

use anyhow::{Context, Result};
use std::fs;

/// Number of online CPUs as reported by `/sys/devices/system/cpu/online`.
pub fn online_cpus() -> Result<usize> {
    let s = fs::read_to_string("/sys/devices/system/cpu/online")
        .context("cannot read online CPUs")?;
    let s = s.trim();
    if let Some(pos) = s.rfind('-') {
        let max: usize = s[pos + 1..].parse()?;
        Ok(max + 1)
    } else {
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_cpus_returns_at_least_one() {
        let n = online_cpus().expect("read /sys/devices/system/cpu/online");
        assert!(n >= 1, "expected >= 1 CPU, got {n}");
    }
}
