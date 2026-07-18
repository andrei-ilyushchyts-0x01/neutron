use std::env;
use std::process::Command;

const UNKNOWN_COMMIT: &str = "0000000000000000000000000000000000000000";

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
}

fn git_output(args: &[&str]) -> Option<String> {
    command_output("git", args)
}

fn cargo_features() -> String {
    let mut features: Vec<String> = env::vars()
        .filter_map(|(name, value)| {
            if value != "1" {
                return None;
            }
            name.strip_prefix("CARGO_FEATURE_").map(str::to_owned)
        })
        .map(|name| name.to_ascii_lowercase().replace('_', "-"))
        .collect();
    features.sort();
    features.dedup();
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

fn main() {
    for name in [
        "NEUTRON_BUILD_GIT_COMMIT",
        "NEUTRON_BUILD_GIT_DIRTY",
        "NEUTRON_BUILD_TIMESTAMP",
        "SOURCE_DATE_EPOCH",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let commit = env::var("NEUTRON_BUILD_GIT_COMMIT")
        .ok()
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .or_else(|| git_output(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| UNKNOWN_COMMIT.to_string());
    // Cargo does not reliably rerun build scripts when a previously unknown
    // untracked file appears. A locally inferred `false` could therefore go
    // stale and poison evidence provenance. Only a clean-build wrapper may
    // attest `false`; ordinary Cargo builds are conservatively marked dirty.
    let dirty = env::var("NEUTRON_BUILD_GIT_DIRTY")
        .ok()
        .filter(|value| matches!(value.as_str(), "true" | "false"))
        .unwrap_or_else(|| "true".to_string());
    let timestamp = env::var("NEUTRON_BUILD_TIMESTAMP")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env::var("SOURCE_DATE_EPOCH").ok())
        .or_else(|| git_output(&["show", "-s", "--format=%cI", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let rustc = env::var("RUSTC")
        .ok()
        .and_then(|rustc| command_output(&rustc, &["--version"]))
        .unwrap_or_else(|| "rustc unknown".to_string());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=NEUTRON_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=NEUTRON_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=NEUTRON_BUILD_TIMESTAMP={timestamp}");
    println!("cargo:rustc-env=NEUTRON_RUSTC_VERSION={rustc}");
    println!("cargo:rustc-env=NEUTRON_TARGET={target}");
    println!("cargo:rustc-env=NEUTRON_FEATURE_SET={}", cargo_features());
}
