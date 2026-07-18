use neutron::bpf_abi::{
    read_bpf_object_path, validate_bpf_abi, BpfAbiError, BpfAbiMetadata, BpfAbiRequirements,
    BpfObjectError, BPF_ABI_MAGIC, BPF_ABI_MAJOR,
};
use neutron::SyscallEvent;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

const REQUIRED_FEATURES: u64 = 0b0101;

fn matching_metadata() -> BpfAbiMetadata {
    BpfAbiMetadata {
        magic: BPF_ABI_MAGIC,
        abi_major: BPF_ABI_MAJOR,
        abi_minor: 0,
        syscall_event_size: std::mem::size_of::<SyscallEvent>() as u32,
        feature_bits: REQUIRED_FEATURES,
        build_id: [0x11; 20],
    }
}

fn requirements() -> BpfAbiRequirements {
    BpfAbiRequirements {
        abi_major: BPF_ABI_MAJOR,
        syscall_event_size: std::mem::size_of::<SyscallEvent>() as u32,
        required_feature_bits: REQUIRED_FEATURES,
        expected_build_id: Some([0x11; 20]),
    }
}

#[test]
fn matching_bpf_abi_round_trips_and_validates() {
    let expected = matching_metadata();
    let decoded = BpfAbiMetadata::decode(&expected.encode()).expect("decode matching metadata");

    assert_eq!(decoded, expected);
    validate_bpf_abi(&decoded, &requirements()).expect("matching ABI should validate");
}

#[test]
fn missing_bpf_abi_metadata_is_rejected() {
    assert!(matches!(
        BpfAbiMetadata::decode(&[]),
        Err(BpfAbiError::MissingMetadata)
    ));
}

#[test]
fn invalid_bpf_abi_magic_is_rejected() {
    let mut metadata = matching_metadata();
    metadata.magic = 0;

    assert!(matches!(
        BpfAbiMetadata::decode(&metadata.encode()),
        Err(BpfAbiError::InvalidMagic { .. })
    ));
}

#[test]
fn bpf_abi_major_mismatch_is_rejected() {
    let mut metadata = matching_metadata();
    metadata.abi_major = BPF_ABI_MAJOR.saturating_add(1);

    assert!(matches!(
        validate_bpf_abi(&metadata, &requirements()),
        Err(BpfAbiError::MajorMismatch { .. })
    ));
}

#[test]
fn syscall_event_size_mismatch_is_rejected() {
    let mut metadata = matching_metadata();
    metadata.syscall_event_size = metadata.syscall_event_size.saturating_add(1);

    assert!(matches!(
        validate_bpf_abi(&metadata, &requirements()),
        Err(BpfAbiError::EventSizeMismatch { .. })
    ));
}

#[test]
fn missing_required_bpf_features_are_rejected() {
    let mut metadata = matching_metadata();
    metadata.feature_bits = 0b0001;

    assert!(matches!(
        validate_bpf_abi(&metadata, &requirements()),
        Err(BpfAbiError::MissingFeatures { .. })
    ));
}

#[test]
fn missing_source_build_id_is_rejected() {
    let mut metadata = matching_metadata();
    metadata.build_id = [0; 20];

    assert!(matches!(
        validate_bpf_abi(&metadata, &requirements()),
        Err(BpfAbiError::MissingBuildId)
    ));
}

#[test]
fn object_from_another_source_commit_is_rejected() {
    let mut metadata = matching_metadata();
    metadata.build_id = [0x22; 20];

    assert!(matches!(
        validate_bpf_abi(&metadata, &requirements()),
        Err(BpfAbiError::BuildIdMismatch { .. })
    ));
}

#[test]
fn bpf_object_reader_rejects_shared_write_modes_and_symlinks() {
    let directory = std::env::temp_dir().join(format!(
        "neutron-bpf-reader-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&directory).unwrap();
    let object = directory.join("object.elf");
    fs::write(&object, b"object").unwrap();
    fs::set_permissions(&object, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        read_bpf_object_path(&object),
        Err(BpfObjectError::UnsafeObject { .. })
    ));

    fs::set_permissions(&object, fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.join("object-link.elf");
    symlink(&object, &link).unwrap();
    assert!(read_bpf_object_path(&link).is_err());

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn sys_enter_filters_disallowed_syscalls_before_tracking_inflight() {
    let source = include_str!("../neutron-ebpf/src/main.rs");
    let start = source
        .find("fn try_sys_enter(ctx: &TracePointContext) -> Result<(), ()> {")
        .expect("try_sys_enter definition");
    let end = source[start..]
        .find("\n#[tracepoint]\npub fn trace_sys_exit")
        .map(|offset| start + offset)
        .expect("trace_sys_exit boundary");
    let body = &source[start..end];

    let admission = body
        .find("mark_admitted_thread_enter")
        .expect("causal admission bookkeeping");
    let syscall_number = body.find("let nr =").expect("syscall number read");
    let allow_gate = body
        .find("if !syscall_allowed(nr) {")
        .expect("sys_enter must reject disallowed syscalls");
    let argument_read = body.find("let args =").expect("syscall argument read");
    let inflight_insert = body.find("if INFLIGHT.insert").expect("INFLIGHT insertion");

    assert!(
        admission < syscall_number
            && syscall_number < allow_gate
            && allow_gate < argument_read
            && argument_read < inflight_insert,
        "sys_enter must preserve causal admission, then filter disallowed syscalls before reading arguments or inserting INFLIGHT state"
    );
}

#[test]
fn state_required_syscalls_are_wired_into_the_active_bpf_filter() {
    let source = include_str!("../src/main.rs");
    let start = source
        .find("fn populate_match_maps(")
        .expect("populate_match_maps definition");
    let end = source[start..]
        .find("\nfn populate_ioctl_refresh_maps(")
        .map(|offset| start + offset)
        .expect("populate_ioctl_refresh_maps boundary");
    let body = &source[start..end];

    assert!(
        body.contains("spec.effective_bpf_syscalls(state_events_required)"),
        "populate_match_maps must extend an active syscall whitelist with required fdgraph state syscalls"
    );
}
