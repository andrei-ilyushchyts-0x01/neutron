use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    process::Command,
};

#[test]
fn invalid_trace_configuration_fails_before_privilege_or_loading() {
    for (flag, value, expected) in [
        ("--capture", "invalid-mode", "--capture: expected"),
        ("--kprobe-pack", "invalid-pack", "unknown kprobe pack"),
        ("--rules", "/nonexistent/neutron-rules.yaml", "rules"),
        (
            "--binder-catalog",
            "/nonexistent/neutron-catalog.json",
            "catalog",
        ),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_neutron"))
            .args([
                "trace",
                "--pid",
                "1",
                "--object",
                "/nonexistent/invalid.elf",
                flag,
                value,
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success());
        assert!(stderr.contains(expected), "{flag}: {stderr}");
        assert!(!stderr.contains("  loading "), "{stderr}");
        assert!(!stderr.contains("privilege preflight"), "{stderr}");
    }
}

#[test]
fn spike_only_forwards_supported_flags_to_the_maintained_entrypoint() {
    let dir = std::env::temp_dir().join(format!("neutron-spike-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_neutron-spike"),
        dir.join("neutron-spike"),
    )
    .unwrap();
    fs::write(dir.join("neutron"), "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
    fs::set_permissions(dir.join("neutron"), fs::Permissions::from_mode(0o700)).unwrap();
    for (args, expected) in [
        (
            vec!["--object", "invalid.elf"],
            "doctor\n--smoke\n--object\ninvalid.elf\n",
        ),
        (
            vec!["--pid", "42", "--json", "--object", "invalid.elf"],
            "trace\n--pid\n42\n--raw\n--object\ninvalid.elf\n--json\n",
        ),
    ] {
        let output = Command::new(dir.join("neutron-spike"))
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
    let rejected = Command::new(dir.join("neutron-spike"))
        .args(["--duration", "10"])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    fs::remove_dir_all(dir).unwrap();
}
