//! End-to-end integration tests for the Phase 1 predicate pipeline.
//!
//! These tests don't load BPF — they drive the userspace evaluator
//! against synthetic events, which is the same logic that runs as
//! Stage 2 of the live tracer. The BPF prefilter is a strict
//! over-approximation, so an event that survives Stage 2 here is
//! exactly an event that the live tool would emit (modulo the
//! capture-mode / sampler stages, which are unit-tested in their own
//! modules).

use neutron::matcher::{ArgClause, ArgWidth, EventLens, MatchSpec, RetClass, SyscallEventLens};
use neutron::predicate;

/// Tiny test lens — enough fields for the assertions below. Anything
/// not set defaults to `0` / `None`.
#[derive(Default)]
struct E {
    pid: u32,
    uid: u32,
    nr: i32,
    is_enter: bool,
    ret: i64,
    latency_us: Option<u64>,
    comm: String,
    fd_path: Option<String>,
    ioctl_cmd: Option<u32>,
    arg_payload: Option<Vec<u8>>,
    rwx_marker: Option<u8>,
    binder_to_proc: Option<u32>,
    binder_code: Option<u32>,
}

impl EventLens for E {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn uid(&self) -> u32 {
        self.uid
    }
    fn syscall_nr(&self) -> i32 {
        self.nr
    }
    fn is_enter(&self) -> bool {
        self.is_enter
    }
    fn ret(&self) -> i64 {
        self.ret
    }
    fn latency_us(&self) -> Option<u64> {
        self.latency_us
    }
    fn comm(&self) -> &str {
        &self.comm
    }
    fn fd_path(&self) -> Option<&str> {
        self.fd_path.as_deref()
    }
    fn ioctl_cmd(&self) -> Option<u32> {
        self.ioctl_cmd
    }
    fn arg_payload(&self) -> Option<&[u8]> {
        self.arg_payload.as_deref()
    }
    fn rwx_marker(&self) -> Option<u8> {
        self.rwx_marker
    }
    fn binder_to_proc(&self) -> Option<u32> {
        self.binder_to_proc
    }
    fn binder_to_thread(&self) -> Option<u32> {
        None
    }
    fn binder_code(&self) -> Option<u32> {
        self.binder_code
    }
    fn binder_flags(&self) -> Option<u32> {
        None
    }
    fn binder_target_node(&self) -> Option<i32> {
        None
    }
    fn binder_reply(&self) -> Option<bool> {
        None
    }
}

#[test]
fn matchspec_evaluates_lwis_filter_chain() {
    // Equivalent CLI: --match-syscall ioctl --match-fd /dev/lwis*
    //                 --match-arg-u32 '0=0x20200,0x40200'
    let mut spec = MatchSpec::default();
    spec.syscalls.insert(29);
    spec.fd_globs.push("/dev/lwis*".into());
    spec.arg_clauses.push(ArgClause {
        width: Some(ArgWidth::U32),
        offset: 0,
        values: [0x20200u64, 0x40200].into_iter().collect(),
    });
    spec.ioctl_cmds.insert(0xc010_4c64);

    let mut payload = vec![0u8; 16];
    payload[..4].copy_from_slice(&0x20200u32.to_le_bytes());
    let on = E {
        nr: 29,
        fd_path: Some("/dev/lwis-top".into()),
        ioctl_cmd: Some(0xc010_4c64),
        arg_payload: Some(payload.clone()),
        ..E::default()
    };
    let off_path = E {
        nr: 29,
        fd_path: Some("/dev/binder".into()),
        ioctl_cmd: Some(0xc010_4c64),
        arg_payload: Some(payload.clone()),
        ..E::default()
    };
    let off_cmdid = E {
        nr: 29,
        fd_path: Some("/dev/lwis-top".into()),
        ioctl_cmd: Some(0xc010_4c64),
        arg_payload: Some(vec![0u8; 16]), // cmd_id == 0
        ..E::default()
    };

    assert!(neutron::matcher::evaluate(&spec, &on));
    assert!(!neutron::matcher::evaluate(&spec, &off_path));
    assert!(!neutron::matcher::evaluate(&spec, &off_cmdid));
}

#[test]
fn predicate_ast_matches_same_set_as_individual_flags() {
    // Same workload, expressed via --match expr.
    let expr = predicate::parse(
        "syscall = 29 AND fd_path GLOB '/dev/lwis*' AND arg.u32@0 IN (0x20200, 0x40200)",
    )
    .unwrap();

    let mut payload = vec![0u8; 16];
    payload[..4].copy_from_slice(&0x40200u32.to_le_bytes());
    let on = E {
        nr: 29,
        fd_path: Some("/dev/lwis-top".into()),
        ioctl_cmd: Some(0xc010_4c64),
        arg_payload: Some(payload),
        ..E::default()
    };
    assert!(predicate::evaluate(&expr, &on));

    // BPF spec extracts syscall + arg.u32 atoms; fd_path stays userspace.
    let bpf_spec = predicate::extract_bpf_spec(&expr);
    assert!(bpf_spec.syscalls.contains(&29));
    assert!(bpf_spec.bpf_arg_u32().is_some());
    assert!(
        bpf_spec.fd_globs.is_empty(),
        "fd_path must NOT lower to BPF"
    );
}

#[test]
fn predicate_ast_or_with_userspace_clause_disables_bpf() {
    let expr = predicate::parse("syscall = 29 OR fd_path GLOB '/dev/lwis*'").unwrap();
    let bpf_spec = predicate::extract_bpf_spec(&expr);
    assert!(
        bpf_spec.is_empty(),
        "OR with userspace clause must disable BPF prefilter"
    );
    let on_a = E {
        nr: 29,
        ..E::default()
    };
    let on_b = E {
        nr: 222,
        fd_path: Some("/dev/lwis-top".into()),
        ..E::default()
    };
    let off = E {
        nr: 222,
        fd_path: Some("/dev/binder".into()),
        ..E::default()
    };
    assert!(predicate::evaluate(&expr, &on_a));
    assert!(predicate::evaluate(&expr, &on_b));
    assert!(!predicate::evaluate(&expr, &off));
}

#[test]
fn ret_negative_classifier_matches_only_failed_exits() {
    let expr = predicate::parse("ret < 0").unwrap();
    let bpf_spec = predicate::extract_bpf_spec(&expr);
    assert_eq!(bpf_spec.ret_class, RetClass::Negative);

    let exit_einval = E {
        nr: 29,
        is_enter: false,
        ret: -22,
        ..E::default()
    };
    let exit_ok = E {
        nr: 29,
        is_enter: false,
        ret: 0,
        ..E::default()
    };
    assert!(predicate::evaluate(&expr, &exit_einval));
    assert!(!predicate::evaluate(&expr, &exit_ok));
}

#[test]
fn syscall_event_lens_renders_arg_payload_for_ioctl() {
    use neutron_common::SyscallEvent;
    let mut data = [0u8; 128];
    data[..4].copy_from_slice(&0xc010_4c64u32.to_le_bytes());
    data[4..8].copy_from_slice(&0x20200u32.to_le_bytes());

    let ev = SyscallEvent {
        pid: 970,
        uid: 1047,
        syscall_nr: 29,
        args: [0, 0xc010_4c64, 0, 0, 0, 0],
        is_enter: 0,
        ret: 0,
        data,
        ..SyscallEvent::default()
    };
    let lens = SyscallEventLens::new(&ev, "cameraserver".into(), Some("/dev/lwis-top"), Some(120));
    assert_eq!(lens.pid(), 970);
    assert_eq!(lens.ioctl_cmd(), Some(0xc010_4c64));
    let payload = lens.arg_payload().expect("payload");
    assert_eq!(&payload[..4], &0x20200u32.to_le_bytes());
    assert_eq!(lens.fd_path(), Some("/dev/lwis-top"));
    assert_eq!(lens.latency_us(), Some(120));
}

#[test]
fn predicate_audit_lines_classify_bpf_vs_user() {
    let expr = predicate::parse("syscall = 29 AND fd_path GLOB '/dev/lwis*'").unwrap();
    let lines = predicate::audit_lines(&expr);
    let bpf_count = lines.iter().filter(|l| l.contains("[bpf]")).count();
    let user_count = lines.iter().filter(|l| l.contains("[user]")).count();
    assert!(bpf_count >= 1, "syscall must be on the bpf side");
    assert!(user_count >= 1, "fd_path must be on the user side");
}
