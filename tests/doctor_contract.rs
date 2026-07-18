use clap::Parser;
use neutron::cli::{Cli, Command};
use neutron::doctor::{validate_tracepoint_format, TracepointCompatibility, TracepointKind};
use serde_json::Value;

// Sanitized Android 17 tracefs excerpts for the release-gate contract. These
// fixtures intentionally retain only kernel-provided format metadata; they are
// not runtime evidence from this test host.
const ANDROID17_SYS_ENTER: &str = r#"name: sys_enter
ID: 23
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:long id;	offset:8;	size:8;	signed:1;
	field:unsigned long args[6];	offset:16;	size:48;	signed:0;

print fmt: "NR %ld (%lx, %lx, %lx, %lx, %lx, %lx)", REC->id, REC->args[0], REC->args[1], REC->args[2], REC->args[3], REC->args[4], REC->args[5]
"#;

const ANDROID17_SYS_EXIT: &str = r#"name: sys_exit
ID: 24
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:long id;	offset:8;	size:8;	signed:1;
	field:long ret;	offset:16;	size:8;	signed:1;

print fmt: "NR %ld = %ld", REC->id, REC->ret
"#;

const ANDROID17_BINDER_TRANSACTION: &str = r#"name: binder_transaction
ID: 919
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int debug_id;	offset:8;	size:4;	signed:1;
	field:int target_node;	offset:12;	size:4;	signed:1;
	field:int to_proc;	offset:16;	size:4;	signed:1;
	field:int to_thread;	offset:20;	size:4;	signed:1;
	field:int reply;	offset:24;	size:4;	signed:1;
	field:unsigned int code;	offset:28;	size:4;	signed:0;
	field:unsigned int flags;	offset:32;	size:4;	signed:0;

print fmt: "transaction=%d dest_node=%d dest_proc=%d dest_thread=%d reply=%d flags=0x%x code=0x%x", REC->debug_id, REC->target_node, REC->to_proc, REC->to_thread, REC->reply, REC->flags, REC->code
"#;

const ANDROID17_BINDER_TRANSACTION_RECEIVED: &str = r#"name: binder_transaction_received
ID: 920
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int debug_id;	offset:8;	size:4;	signed:1;

print fmt: "transaction=%d", REC->debug_id
"#;

const ANDROID17_SCHED_PROCESS_EXIT: &str = r#"name: sched_process_exit
ID: 97
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:char comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:int prio;	offset:28;	size:4;	signed:1;

print fmt: "comm=%s pid=%d prio=%d", REC->comm, REC->pid, REC->prio
"#;

#[test]
fn android17_tracepoint_layouts_are_exactly_compatible() {
    for (kind, input) in [
        (TracepointKind::RawSysEnter, ANDROID17_SYS_ENTER),
        (TracepointKind::RawSysExit, ANDROID17_SYS_EXIT),
        (
            TracepointKind::BinderTransaction,
            ANDROID17_BINDER_TRANSACTION,
        ),
        (
            TracepointKind::BinderTransactionReceived,
            ANDROID17_BINDER_TRANSACTION_RECEIVED,
        ),
        (
            TracepointKind::SchedProcessExit,
            ANDROID17_SCHED_PROCESS_EXIT,
        ),
    ] {
        let kind_label = format!("{kind:?}");
        let report = validate_tracepoint_format(kind, input).expect("parse tracepoint format");
        assert_eq!(
            report.compatibility,
            TracepointCompatibility::Compatible,
            "{kind_label}: {report:#?}"
        );
        assert_eq!(report.normalized_sha256.len(), 64);
        assert!(
            report
                .normalized_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
            "hash must be lowercase/uppercase hexadecimal"
        );
    }
}

#[test]
fn shifted_sys_enter_offset_is_unsupported_and_hash_is_deterministic() {
    let exact = validate_tracepoint_format(TracepointKind::RawSysEnter, ANDROID17_SYS_ENTER)
        .expect("parse exact format");
    let same_layout_different_runtime_id = validate_tracepoint_format(
        TracepointKind::RawSysEnter,
        &ANDROID17_SYS_ENTER.replace("ID: 23", "ID: 999"),
    )
    .expect("parse equivalent format");
    let shifted = validate_tracepoint_format(
        TracepointKind::RawSysEnter,
        &ANDROID17_SYS_ENTER.replace("args[6];\toffset:16", "args[6];\toffset:24"),
    )
    .expect("parse shifted format");

    assert_eq!(
        exact.normalized_sha256, same_layout_different_runtime_id.normalized_sha256,
        "runtime tracepoint IDs must not perturb the normalized layout hash"
    );
    assert_eq!(shifted.compatibility, TracepointCompatibility::Unsupported);
    assert_ne!(exact.normalized_sha256, shifted.normalized_sha256);
}

#[test]
fn doctor_cli_accepts_json_smoke_and_object() {
    let cli = Cli::try_parse_from([
        "neutron",
        "doctor",
        "--json",
        "--smoke",
        "--object",
        "/tmp/neutron.bpf.elf",
    ])
    .expect("doctor contract flags should parse");

    let Some(Command::Doctor(args)) = cli.command else {
        panic!("expected doctor command");
    };
    assert!(args.json);
    assert!(args.smoke);
    assert_eq!(args.object, "/tmp/neutron.bpf.elf");
}

#[test]
fn doctor_schema_accepts_every_shared_health_counter_slot() {
    let schema: Value =
        serde_json::from_str(include_str!("../schemas/neutron.doctor-v1.schema.json"))
            .expect("doctor schema must be valid JSON");
    let health_totals = &schema["$defs"]["smokeReport"]["properties"]["health_totals"];

    assert_eq!(
        health_totals["maxItems"].as_u64(),
        Some(u64::from(neutron_common::COUNTER_SLOT_COUNT)),
        "doctor smoke output must admit every slot returned by the shared per-CPU health map"
    );
}
