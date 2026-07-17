use neutron::bpf_abi::{
    validate_bpf_abi, BpfAbiError, BpfAbiMetadata, BpfAbiRequirements, BPF_ABI_MAGIC, BPF_ABI_MAJOR,
};
use neutron::SyscallEvent;

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
