use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    CharacterDevice,
    BlockDevice,
    #[default]
    Other,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PlatformMetadata {
    pub kind: FileKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub major: Option<u32>,
    pub minor: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait PlatformReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    fn metadata(&self, path: &Path) -> io::Result<PlatformMetadata>;
    fn selinux_context(&self, path: &Path) -> io::Result<Option<String>>;
    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
    fn collected_at(&self) -> String;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RealPlatformReader;

impl PlatformReader for RealPlatformReader {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort();
        Ok(entries)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        fs::canonicalize(path)
    }

    fn metadata(&self, path: &Path) -> io::Result<PlatformMetadata> {
        let metadata = fs::symlink_metadata(path)?;
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Directory
        } else if file_type.is_file() {
            FileKind::File
        } else if file_type.is_char_device() {
            FileKind::CharacterDevice
        } else if file_type.is_block_device() {
            FileKind::BlockDevice
        } else {
            FileKind::Other
        };
        let rdev = metadata.rdev();
        let (major, minor) = if matches!(kind, FileKind::CharacterDevice | FileKind::BlockDevice) {
            (
                Some(libc::major(rdev) as u32),
                Some(libc::minor(rdev) as u32),
            )
        } else {
            (None, None)
        };
        Ok(PlatformMetadata {
            kind,
            mode: metadata.mode() & 0o7777,
            uid: metadata.uid(),
            gid: metadata.gid(),
            major,
            minor,
        })
    }

    fn selinux_context(&self, path: &Path) -> io::Result<Option<String>> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let name = CString::new("security.selinux").expect("SELinux xattr name has no NUL");
        // SAFETY: both C strings live across the calls, and the second call
        // receives a buffer with exactly the size reported by the kernel.
        let size =
            unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ENODATA) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let mut value = vec![0_u8; size as usize];
        let read = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        value.truncate(read as usize);
        while value.last() == Some(&0) {
            value.pop();
        }
        String::from_utf8(value)
            .map(Some)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn command_output(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        let candidates: &[&str] = match program {
            "service" => &["/system/bin/service"],
            "dumpsys" => &["/system/bin/dumpsys"],
            "getprop" => &["/system/bin/getprop"],
            "lshal" => &["/system/bin/lshal", "/vendor/bin/lshal"],
            "vndservice" => &["/vendor/bin/vndservice", "/system/bin/vndservice"],
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported platform command: {program}"),
                ))
            }
        };
        let mut last_not_found = None;
        let mut output = None;
        for candidate in candidates {
            match Command::new(candidate).args(args).output() {
                Ok(result) => {
                    output = Some(result);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    last_not_found = Some(error)
                }
                Err(error) => return Err(error),
            }
        }
        let output = output.ok_or_else(|| {
            last_not_found.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "platform command not found")
            })
        })?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn collected_at(&self) -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        let mut utc = MaybeUninit::<libc::tm>::uninit();
        // SAFETY: `seconds` and `utc` are valid for the duration of gmtime_r.
        let result = unsafe { libc::gmtime_r(&seconds, utc.as_mut_ptr()) };
        if result.is_null() {
            return format!("{seconds}Z");
        }
        // SAFETY: a non-null gmtime_r return initialized `utc`.
        let utc = unsafe { utc.assume_init() };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            utc.tm_year + 1900,
            utc.tm_mon + 1,
            utc.tm_mday,
            utc.tm_hour,
            utc.tm_min,
            utc.tm_sec,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_reader_rejects_commands_outside_the_android_allowlist() {
        let error = RealPlatformReader
            .command_output("sh", &["-c", "exit 0"])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
