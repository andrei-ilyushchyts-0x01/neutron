use clap::Parser;
use neutron::cli::{Cli, Command};

fn assert_surface(args: &[&str]) {
    let cli = Cli::try_parse_from(args.iter().copied()).expect("surface CLI should parse");
    assert!(matches!(cli.command, Some(Command::Surface(_))));
}

#[test]
fn scan_accepts_static_and_capture_modes() {
    assert_surface(&["neutron", "surface", "scan", "--output", "surface.json"]);
    assert_surface(&[
        "neutron",
        "surface",
        "scan",
        "--capture",
        "capture.ndjson",
        "--output",
        "surface.json",
    ]);
}

#[test]
fn scan_accepts_package_scoped_observation() {
    assert_surface(&[
        "neutron",
        "surface",
        "scan",
        "--observe",
        "30s",
        "--from-package",
        "com.example.app",
        "--output",
        "surface.json",
    ]);
}

#[test]
fn query_commands_accept_input_and_output() {
    for args in [
        &[
            "neutron",
            "surface",
            "services",
            "--input",
            "surface.json",
            "--output",
            "services.json",
        ][..],
        &[
            "neutron",
            "surface",
            "hals",
            "--input",
            "surface.json",
            "--output",
            "hals.json",
        ],
        &[
            "neutron",
            "surface",
            "devices",
            "--input",
            "surface.json",
            "--output",
            "devices.json",
        ],
        &[
            "neutron",
            "surface",
            "process",
            "1234",
            "--input",
            "surface.json",
            "--output",
            "process.json",
        ],
        &[
            "neutron",
            "surface",
            "explain",
            "android.hardware.security.keymint.IKeyMintDevice/default",
            "--input",
            "surface.json",
            "--output",
            "explain.json",
        ],
        &[
            "neutron",
            "surface",
            "reachable",
            "--from-package",
            "com.example.app",
            "--input",
            "surface.json",
            "--output",
            "reachable.json",
        ],
        &[
            "neutron",
            "surface",
            "reachable",
            "--from-uid",
            "10123",
            "--input",
            "surface.json",
            "--output",
            "reachable.json",
        ],
    ] {
        assert_surface(args);
    }
}

#[test]
fn scan_rejects_capture_with_observe() {
    assert!(Cli::try_parse_from([
        "neutron",
        "surface",
        "scan",
        "--capture",
        "capture.ndjson",
        "--observe",
        "30s",
        "--from-package",
        "com.example.app",
    ])
    .is_err());
}

#[test]
fn scan_observe_requires_exactly_one_selector() {
    assert!(Cli::try_parse_from(["neutron", "surface", "scan", "--observe", "30s"]).is_err());
    assert!(Cli::try_parse_from([
        "neutron",
        "surface",
        "scan",
        "--observe",
        "30s",
        "--from-package",
        "com.example.app",
        "--from-uid",
        "10123",
    ])
    .is_err());
}

#[test]
fn trace_accepts_uid_root() {
    let cli = Cli::try_parse_from(["neutron", "trace", "--root-uid", "10123"])
        .expect("trace --root-uid should parse");
    let Some(Command::Trace(args)) = cli.command else {
        panic!("expected trace command");
    };
    assert_eq!(args.root_uid, Some(10123));
}

#[test]
fn trace_uid_root_rejects_package_or_explicit_pid() {
    assert!(Cli::try_parse_from([
        "neutron",
        "trace",
        "--root-uid",
        "10123",
        "--package",
        "com.example.app",
    ])
    .is_err());

    for pid in ["0", "42"] {
        assert!(
            Cli::try_parse_from(["neutron", "trace", "--root-uid", "10123", "--pid", pid,])
                .is_err()
        );
    }
}
