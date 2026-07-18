use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_PLATFORM_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PLATFORM_DIRECTORY_ENTRIES: usize = 4096;
const MAX_PLATFORM_COMMAND_BYTES: usize = 16 * 1024 * 1024;
const PLATFORM_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);

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
    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        let bytes = self.read(path)?;
        if bytes.len() > max_bytes {
            return Err(size_limit_error(max_bytes));
        }
        Ok(bytes)
    }
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
        read_regular_file_bounded(path, MAX_PLATFORM_FILE_BYTES)
    }

    fn read_bounded(&self, path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
        read_regular_file_bounded(path, max_bytes)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        read_directory_bounded(path, MAX_PLATFORM_DIRECTORY_ENTRIES)
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
        let output = run_platform_command_bounded(program, args)?;
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
            .as_secs() as libc::c_long;
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

fn size_limit_error(max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("input exceeds {max_bytes} byte limit"),
    )
}

pub(crate) fn read_regular_file_bounded(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input must be a single-link regular file",
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(size_limit_error(max_bytes));
    }

    let mut bytes = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(size_limit_error(max_bytes));
    }
    Ok(bytes)
}

fn read_directory_bounded(path: &Path, max_entries: usize) -> io::Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)? {
        if entries.len() == max_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("directory exceeds {max_entries} entry limit"),
            ));
        }
        entries.push(entry?.path());
    }
    entries.sort();
    Ok(entries)
}

fn platform_command_candidates(program: &str) -> io::Result<&'static [&'static str]> {
    match program {
        "cmd" => Ok(&["/system/bin/cmd"]),
        "pm" => Ok(&["/system/bin/pm"]),
        "service" => Ok(&["/system/bin/service"]),
        "dumpsys" => Ok(&["/system/bin/dumpsys"]),
        "getprop" => Ok(&["/system/bin/getprop"]),
        "lshal" => Ok(&["/system/bin/lshal", "/vendor/bin/lshal"]),
        "vndservice" => Ok(&["/vendor/bin/vndservice", "/system/bin/vndservice"]),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported Android platform command: {program}"),
        )),
    }
}

pub(crate) fn run_platform_command_bounded(program: &str, args: &[&str]) -> io::Result<Output> {
    let mut last_not_found = None;
    for candidate in platform_command_candidates(program)? {
        let mut command = Command::new(candidate);
        command.args(args);
        match run_bounded_command(
            command,
            PLATFORM_COMMAND_TIMEOUT,
            MAX_PLATFORM_COMMAND_BYTES,
        ) {
            Ok(output) => return Ok(output),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                last_not_found = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_not_found
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "platform command not found")))
}

fn drain_pipe<R>(
    mut pipe: R,
    max_bytes: usize,
    oversized: Arc<AtomicBool>,
) -> io::Result<JoinHandle<io::Result<Vec<u8>>>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name("neutron-command-output".into())
        .spawn(move || {
            let mut retained = Vec::new();
            let mut chunk = [0_u8; 8192];
            loop {
                let read = pipe.read(&mut chunk)?;
                if read == 0 {
                    break;
                }
                let available = max_bytes.saturating_sub(retained.len());
                let keep = available.min(read);
                retained.extend_from_slice(&chunk[..keep]);
                if keep != read {
                    oversized.store(true, Ordering::Release);
                }
            }
            Ok(retained)
        })
}

fn join_pipe(handle: JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other("platform command output reader panicked"))?
}

fn kill_and_wait(child: &mut Child) -> io::Result<ExitStatus> {
    let process_group = i32::try_from(child.id()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "child process id is out of range",
        )
    })?;
    // The command is placed in a dedicated process group before exec, so a
    // timeout cannot leave descendants holding the output pipes open.
    let killed = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    let kill_error = if killed != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            child.kill().err()
        } else {
            None
        }
    } else {
        None
    };
    let waited = child.wait();
    match (kill_error, waited) {
        (_, Err(error)) => Err(error),
        (Some(error), Ok(_)) => Err(error),
        (None, Ok(status)) => Ok(status),
    }
}

fn run_bounded_command(
    mut command: Command,
    timeout: Duration,
    max_bytes: usize,
) -> io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let error = io::Error::other("platform command stdout is not piped");
            return kill_and_wait(&mut child).and(Err(error));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let error = io::Error::other("platform command stderr is not piped");
            return kill_and_wait(&mut child).and(Err(error));
        }
    };
    let oversized = Arc::new(AtomicBool::new(false));
    let stdout_reader = match drain_pipe(stdout, max_bytes, Arc::clone(&oversized)) {
        Ok(reader) => reader,
        Err(error) => {
            drop(stderr);
            return kill_and_wait(&mut child).and(Err(error));
        }
    };
    let stderr_reader = match drain_pipe(stderr, max_bytes, Arc::clone(&oversized)) {
        Ok(reader) => reader,
        Err(error) => {
            let cleanup = kill_and_wait(&mut child).and(Err(error));
            let _ = join_pipe(stdout_reader);
            return cleanup;
        }
    };
    let deadline = Instant::now().checked_add(timeout);

    let mut forced_error = None;
    let mut leader_status = None;
    let status = loop {
        if oversized.load(Ordering::Acquire) {
            forced_error = Some(size_limit_error(max_bytes));
            break kill_and_wait(&mut child);
        }
        if leader_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => leader_status = Some(status),
                Ok(None) => {}
                Err(error) => {
                    let cleanup = kill_and_wait(&mut child);
                    break cleanup.and(Err(error));
                }
            }
        }
        if leader_status.is_some() && stdout_reader.is_finished() && stderr_reader.is_finished() {
            break Ok(leader_status.take().expect("leader status was checked"));
        }
        if deadline.map_or(true, |deadline| Instant::now() >= deadline) {
            forced_error = Some(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "platform command exceeded {} ms timeout",
                    timeout.as_millis()
                ),
            ));
            break kill_and_wait(&mut child);
        }
        thread::sleep(COMMAND_POLL_INTERVAL);
    };

    let stdout = join_pipe(stdout_reader);
    let stderr = join_pipe(stderr_reader);
    let status = status?;
    let stdout = stdout?;
    let stderr = stderr?;
    if forced_error.is_none() && oversized.load(Ordering::Acquire) {
        forced_error = Some(size_limit_error(max_bytes));
    }
    if let Some(error) = forced_error {
        return Err(error);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "neutron-platform-unit-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn child_fixture(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .args(["--ignored", "bounded_command_child", "--nocapture"])
            .env("NEUTRON_BOUNDED_COMMAND_CHILD", mode);
        command
    }

    // This deliberately drops the Child handle: the fixture must let its
    // leader exit while the descendant retains inherited output pipes. The
    // bounded-command supervisor owns the process group and kills it.
    #[allow(clippy::zombie_processes)]
    fn spawn_inherited_pipe_holder() {
        child_fixture("hold-pipe-descendant").spawn().unwrap();
    }

    #[test]
    #[ignore = "subprocess fixture for bounded-command tests"]
    fn bounded_command_child() {
        match std::env::var("NEUTRON_BOUNDED_COMMAND_CHILD").as_deref() {
            Ok("hang") => std::thread::sleep(Duration::from_secs(30)),
            Ok("oversize") => {
                std::io::stdout()
                    .write_all(&vec![b'o'; 128 * 1024])
                    .unwrap();
            }
            Ok("dual-pipe") => {
                std::io::stdout()
                    .write_all(&vec![b'o'; 128 * 1024])
                    .unwrap();
                std::io::stderr()
                    .write_all(&vec![b'e'; 128 * 1024])
                    .unwrap();
            }
            Ok("hold-pipe") => {
                spawn_inherited_pipe_holder();
            }
            Ok("hold-pipe-descendant") => std::thread::sleep(Duration::from_secs(2)),
            mode => panic!("unexpected child fixture mode: {mode:?}"),
        }
    }

    #[test]
    fn real_reader_rejects_commands_outside_the_android_allowlist() {
        let error = RealPlatformReader
            .command_output("sh", &["-c", "exit 0"])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn bounded_read_rejects_oversize_and_symlink_inputs() {
        let directory = temp_dir();
        fs::create_dir(&directory).unwrap();
        let input = directory.join("input");
        let link = directory.join("link");
        let fifo = directory.join("fifo");
        fs::write(&input, b"12345").unwrap();
        symlink(&input, &link).unwrap();
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

        let reader = RealPlatformReader;
        assert_eq!(reader.read_bounded(&input, 5).unwrap(), b"12345");
        assert_eq!(
            reader.read_bounded(&input, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(reader.read_bounded(&link, 5).is_err());
        assert!(reader.read_bounded(&fifo, 5).is_err());
        assert_eq!(
            read_directory_bounded(&directory, 2).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn bounded_command_times_out_and_waits_for_the_child() {
        let started = Instant::now();
        let error = run_bounded_command(child_fixture("hang"), Duration::from_millis(100), 1024)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn bounded_command_rejects_oversize_output_without_hanging() {
        let started = Instant::now();
        let error = run_bounded_command(child_fixture("oversize"), Duration::from_secs(3), 1024)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn bounded_command_drains_stdout_and_stderr_without_pipe_deadlock() {
        let output = run_bounded_command(
            child_fixture("dual-pipe"),
            Duration::from_secs(3),
            256 * 1024,
        )
        .unwrap();

        assert!(output.status.success());
        assert!(output.stdout.iter().filter(|byte| **byte == b'o').count() >= 128 * 1024);
        assert!(output.stderr.iter().filter(|byte| **byte == b'e').count() >= 128 * 1024);
    }

    #[test]
    fn bounded_command_times_out_when_a_descendant_keeps_pipes_open() {
        let started = Instant::now();
        let error = run_bounded_command(
            child_fixture("hold-pipe"),
            Duration::from_millis(100),
            256 * 1024,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(1500));
    }
}
