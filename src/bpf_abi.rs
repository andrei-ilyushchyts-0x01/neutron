//! Userspace validation for the ABI metadata embedded in Neutron BPF objects.
//!
//! Call [`validate_bpf_object_path`] before handing object bytes to Aya. This
//! ensures an incompatible userspace/object pair fails before map creation or
//! tracepoint attachment and also records the exact object SHA-256.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use goblin::elf::Elf;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub use neutron_common::{
    BpfAbiError, BpfAbiMetadata, BPF_ABI_ENCODED_SIZE, BPF_ABI_MAGIC, BPF_ABI_MAJOR, BPF_ABI_MINOR,
    BPF_ABI_SECTION_NAME, BPF_FEATURE_BINDER_TRACE, BPF_FEATURE_PER_CPU_HEALTH,
    BPF_FEATURE_PROCESS_EXIT, BPF_FEATURE_STACKS, BPF_FEATURE_SYSCALL_TRACE,
};

pub const MAX_BPF_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BpfAbiRequirements {
    pub abi_major: u16,
    pub syscall_event_size: u32,
    pub required_feature_bits: u64,
    pub expected_build_id: Option<[u8; 20]>,
}

impl BpfAbiRequirements {
    /// Requirements for every supported capture: syscalls, process-exit state,
    /// and per-CPU health accounting.
    pub const fn default_capture() -> Self {
        Self {
            abi_major: BPF_ABI_MAJOR,
            syscall_event_size: core::mem::size_of::<neutron_common::SyscallEvent>() as u32,
            required_feature_bits: BPF_FEATURE_SYSCALL_TRACE
                | BPF_FEATURE_PROCESS_EXIT
                | BPF_FEATURE_PER_CPU_HEALTH,
            expected_build_id: Some(neutron_common::bpf_build_id_from_git_hex(Some(env!(
                "NEUTRON_GIT_COMMIT"
            )))),
        }
    }

    /// Add feature bits required by the selected capture options.
    pub const fn with_features(mut self, feature_bits: u64) -> Self {
        self.required_feature_bits |= feature_bits;
        self
    }
}

impl Default for BpfAbiRequirements {
    fn default() -> Self {
        Self::default_capture()
    }
}

/// Validate already-decoded metadata against a userspace requirement set.
pub fn validate_bpf_abi(
    metadata: &BpfAbiMetadata,
    requirements: &BpfAbiRequirements,
) -> Result<(), BpfAbiError> {
    if metadata.magic != BPF_ABI_MAGIC {
        return Err(BpfAbiError::InvalidMagic {
            expected: BPF_ABI_MAGIC,
            actual: metadata.magic,
        });
    }
    if metadata.abi_major != requirements.abi_major {
        return Err(BpfAbiError::MajorMismatch {
            expected: requirements.abi_major,
            actual: metadata.abi_major,
        });
    }
    if metadata.syscall_event_size != requirements.syscall_event_size {
        return Err(BpfAbiError::EventSizeMismatch {
            expected: requirements.syscall_event_size,
            actual: metadata.syscall_event_size,
        });
    }
    if !metadata.build_id.iter().any(|byte| *byte != 0) {
        return Err(BpfAbiError::MissingBuildId);
    }
    if let Some(expected) = requirements.expected_build_id {
        if metadata.build_id != expected {
            return Err(BpfAbiError::BuildIdMismatch {
                expected,
                actual: metadata.build_id,
            });
        }
    }
    let missing = requirements.required_feature_bits & !metadata.feature_bits;
    if missing != 0 {
        return Err(BpfAbiError::MissingFeatures {
            required: requirements.required_feature_bits,
            available: metadata.feature_bits,
            missing,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Eq, PartialEq)]
pub struct BpfObjectIdentity {
    pub object_sha256: String,
    pub section: &'static str,
    pub magic: String,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub syscall_event_size: u32,
    pub feature_bits: u64,
    pub build_id: String,
    pub build_id_present: bool,
}

#[derive(Debug, Clone)]
pub struct ValidatedBpfObject {
    pub metadata: BpfAbiMetadata,
    pub identity: BpfObjectIdentity,
}

#[derive(Debug)]
pub enum BpfObjectError {
    Io { path: PathBuf, source: io::Error },
    UnsafeObject { path: PathBuf, reason: String },
    ObjectTooLarge { path: PathBuf, size: u64 },
    InvalidElf(String),
    UnsupportedMachine(u16),
    UnsupportedEndianness,
    MissingAbiSection,
    DuplicateAbiSection,
    InvalidAbiSectionRange,
    InvalidAbiSectionSize { expected: usize, actual: usize },
    Abi(BpfAbiError),
}

impl fmt::Display for BpfObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(formatter, "cannot read BPF object {}: {source}", path.display())
            }
            Self::UnsafeObject { path, reason } => {
                write!(formatter, "unsafe BPF object {}: {reason}", path.display())
            }
            Self::ObjectTooLarge { path, size } => write!(
                formatter,
                "BPF object {} is {size} bytes; maximum is {MAX_BPF_OBJECT_BYTES}",
                path.display()
            ),
            Self::InvalidElf(reason) => write!(formatter, "invalid BPF ELF object: {reason}"),
            Self::UnsupportedMachine(actual) => write!(
                formatter,
                "ELF machine mismatch: expected EM_BPF, found {actual}"
            ),
            Self::UnsupportedEndianness => {
                formatter.write_str("big-endian BPF objects are not supported by this ABI")
            }
            Self::MissingAbiSection => {
                write!(formatter, "BPF object has no {BPF_ABI_SECTION_NAME} section")
            }
            Self::DuplicateAbiSection => write!(
                formatter,
                "BPF object contains more than one {BPF_ABI_SECTION_NAME} section"
            ),
            Self::InvalidAbiSectionRange => {
                write!(formatter, "BPF object {BPF_ABI_SECTION_NAME} range is invalid")
            }
            Self::InvalidAbiSectionSize { expected, actual } => write!(
                formatter,
                "BPF object {BPF_ABI_SECTION_NAME} size mismatch: expected {expected}, found {actual}"
            ),
            Self::Abi(error) => write!(formatter, "incompatible BPF object: {error}"),
        }
    }
}

impl Error for BpfObjectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Inspect and validate in-memory object bytes without creating kernel state.
pub fn inspect_bpf_object(
    bytes: &[u8],
    requirements: &BpfAbiRequirements,
) -> Result<ValidatedBpfObject, BpfObjectError> {
    let object_sha256 = sha256_hex(bytes);
    let elf = Elf::parse(bytes).map_err(|error| BpfObjectError::InvalidElf(error.to_string()))?;
    if elf.header.e_machine != goblin::elf::header::EM_BPF {
        return Err(BpfObjectError::UnsupportedMachine(elf.header.e_machine));
    }
    if !elf.little_endian {
        return Err(BpfObjectError::UnsupportedEndianness);
    }

    let mut section_bytes = None;
    for section in &elf.section_headers {
        if elf.shdr_strtab.get_at(section.sh_name) != Some(BPF_ABI_SECTION_NAME) {
            continue;
        }
        if section_bytes.is_some() {
            return Err(BpfObjectError::DuplicateAbiSection);
        }
        let start = usize::try_from(section.sh_offset)
            .map_err(|_| BpfObjectError::InvalidAbiSectionRange)?;
        let size =
            usize::try_from(section.sh_size).map_err(|_| BpfObjectError::InvalidAbiSectionRange)?;
        if size != BPF_ABI_ENCODED_SIZE {
            return Err(BpfObjectError::InvalidAbiSectionSize {
                expected: BPF_ABI_ENCODED_SIZE,
                actual: size,
            });
        }
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .ok_or(BpfObjectError::InvalidAbiSectionRange)?;
        section_bytes = Some(&bytes[start..end]);
    }

    let section_bytes = section_bytes.ok_or(BpfObjectError::MissingAbiSection)?;
    let metadata = BpfAbiMetadata::decode(section_bytes).map_err(BpfObjectError::Abi)?;
    validate_bpf_abi(&metadata, requirements).map_err(BpfObjectError::Abi)?;
    let magic = metadata.magic;
    let abi_major = metadata.abi_major;
    let abi_minor = metadata.abi_minor;
    let syscall_event_size = metadata.syscall_event_size;
    let feature_bits = metadata.feature_bits;
    let build_id = metadata.build_id;
    let build_id_present = build_id.iter().any(|byte| *byte != 0);
    let identity = BpfObjectIdentity {
        object_sha256,
        section: BPF_ABI_SECTION_NAME,
        magic: format!("{magic:#018x}"),
        abi_major,
        abi_minor,
        syscall_event_size,
        feature_bits,
        build_id: hex_bytes(&build_id),
        build_id_present,
    };
    Ok(ValidatedBpfObject { metadata, identity })
}

/// Read, hash, inspect, and validate an object before Aya loads it.
pub fn validate_bpf_object_path(
    path: impl AsRef<Path>,
    requirements: &BpfAbiRequirements,
) -> Result<ValidatedBpfObject, BpfObjectError> {
    let path = path.as_ref();
    let bytes = read_bpf_object_path(path)?;
    inspect_bpf_object(&bytes, requirements)
}

/// Read an object once through a verified descriptor. Root captures refuse
/// symlinks, shared-write modes, foreign ownership, multiple links, and
/// unbounded inputs before the bytes reach the ELF parser or Aya.
pub fn read_bpf_object_path(path: impl AsRef<Path>) -> Result<Vec<u8>, BpfObjectError> {
    let path = path.as_ref();
    let path_buf = path.to_path_buf();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| BpfObjectError::Io {
            path: path_buf.clone(),
            source,
        })?;
    let metadata = file.metadata().map_err(|source| BpfObjectError::Io {
        path: path_buf.clone(),
        source,
    })?;
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file() {
        return Err(BpfObjectError::UnsafeObject {
            path: path_buf,
            reason: "not a regular file".into(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(BpfObjectError::UnsafeObject {
            path: path_buf,
            reason: "must have exactly one hard link".into(),
        });
    }
    if metadata.uid() != euid {
        return Err(BpfObjectError::UnsafeObject {
            path: path_buf,
            reason: format!(
                "owner uid {} does not match effective uid {euid}",
                metadata.uid()
            ),
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(BpfObjectError::UnsafeObject {
            path: path_buf,
            reason: "group- or other-writable mode is forbidden".into(),
        });
    }
    if metadata.len() > MAX_BPF_OBJECT_BYTES {
        return Err(BpfObjectError::ObjectTooLarge {
            path: path_buf,
            size: metadata.len(),
        });
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_BPF_OBJECT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| BpfObjectError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_BPF_OBJECT_BYTES {
        return Err(BpfObjectError::ObjectTooLarge {
            path: path.to_path_buf(),
            size: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
