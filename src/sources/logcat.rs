//! Logcat tail and fatal-line parser.
//!
//! On Android, fatal app errors are reported via `logcat` in three flavours:
//!
//! 1. **Java FATAL EXCEPTION** — the runtime catches an uncaught Throwable
//!    and emits a `E AndroidRuntime: FATAL EXCEPTION: <thread>` block. The
//!    pid lives on the next line as `Process: <name>, PID: <N>`.
//!
//! 2. **Native crash via debuggerd** — a SIGSEGV/SIGABRT/etc. tombstone is
//!    additionally mirrored to logcat by `debuggerd` with tag `DEBUG`. The
//!    `pid: N, tid: N, name: ...  >>> ... <<<` line and a `signal N (SIGxxx)`
//!    line are present, identical to the on-disk tombstone.
//!
//! 3. **ANR (Application Not Responding)** — `ActivityManager` emits
//!    `ANR in <package> (...)` followed by `PID: <N>`. We surface ANRs as
//!    `signal_exit` (SIGQUIT-like semantics, no actual fatal signal).
//!
//! The reader spawns `logcat -v threadtime -b crash -b main *:F` and parses
//! line-by-line. The two production sources are abstracted behind
//! [`LogcatReader`] so tests can inject synthetic streams.
//!
//! ## Test path
//!
//! [`MockLogcatReader`] consumes a `Vec<String>` of pre-baked lines.

use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, Command, Stdio};

use neutron_common::ExitSource;

use super::ProcessExitEvent;

/// Source-of-truth trait for both production logcat tailing and unit tests.
pub trait LogcatReader {
    /// Read all lines available since the last call. Returns
    /// `ProcessExitEvent`s for any fatal patterns recognised. The reader is
    /// expected to be non-blocking — long pauses between calls are normal.
    fn drain(&mut self, now_ns: u64) -> Vec<ProcessExitEvent>;
}

/// Production reader — wraps a child `logcat` process and reads its stdout.
pub struct RealLogcatReader {
    child: Option<Child>,
    reader: Option<BufReader<std::process::ChildStdout>>,
    parser: LogcatParser,
}

pub(crate) fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor owned by the caller. F_GETFL does
    // not mutate memory; F_SETFL updates only this descriptor's status flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl RealLogcatReader {
    /// Spawn `logcat -v threadtime -b crash -b main *:F`. Returns `Err` when
    /// the binary is missing (host without `logcat`) so the caller can
    /// degrade gracefully.
    pub fn spawn() -> std::io::Result<Self> {
        let mut child = Command::new("/system/bin/logcat")
            .args(["-v", "threadtime", "-b", "crash", "-b", "main", "*:F"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("logcat stdout missing"))?;
        set_nonblocking(stdout.as_raw_fd())?;
        Ok(Self {
            child: Some(child),
            reader: Some(BufReader::new(stdout)),
            parser: LogcatParser::default(),
        })
    }
}

impl Drop for RealLogcatReader {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl LogcatReader for RealLogcatReader {
    fn drain(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        let mut out = Vec::new();
        let Some(reader) = self.reader.as_mut() else {
            return out;
        };
        // Drain until EOF or EAGAIN; the pipe is explicitly non-blocking so
        // an idle logcat cannot stall ringbuf or control-socket handling.
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if let Some(ev) = self.parser.feed_line(line.trim_end_matches('\n'), now_ns) {
                        out.push(ev);
                    }
                }
                Err(_) => break,
            }
        }
        out
    }
}

/// Stateful line parser that recognises the three fatal patterns. Holds
/// minimal across-line state because Java/native crash blocks span multiple
/// lines (PID is on a follow-up line).
#[derive(Debug, Default)]
pub struct LogcatParser {
    /// When `Some`, we just saw a `FATAL EXCEPTION` and are waiting for the
    /// follow-up `Process:` line that carries the pid.
    pending_java_fatal: Option<PendingJavaFatal>,
    /// When `Some`, we just saw the `pid: N, tid: N, name: ...` debuggerd
    /// header and are waiting for the `signal N (SIGxxx)` line.
    pending_native: Option<ProcessExitEvent>,
}

#[derive(Debug)]
struct PendingJavaFatal {
    ts_ns: u64,
}

impl LogcatParser {
    /// Feed one logcat line. Returns `Some(event)` when the line completes a
    /// fatal pattern; `None` when more lines are needed or the line is
    /// uninteresting.
    pub fn feed_line(&mut self, line: &str, now_ns: u64) -> Option<ProcessExitEvent> {
        // 1. Java FATAL EXCEPTION — split across two lines.
        if line.contains("FATAL EXCEPTION:") && line.contains("AndroidRuntime") {
            self.pending_java_fatal = Some(PendingJavaFatal { ts_ns: now_ns });
            return None;
        }
        if let Some(pending) = self.pending_java_fatal.as_ref() {
            // Look for "Process: <pkg>, PID: <N>"
            if let Some(pid_str) = line.split("PID:").nth(1) {
                let pid: u32 = pid_str
                    .trim()
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("")
                    .parse()
                    .unwrap_or(0);
                let comm = line
                    .split("Process:")
                    .nth(1)
                    .and_then(|s| s.split(',').next())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let ts = pending.ts_ns;
                self.pending_java_fatal = None;
                if pid != 0 {
                    return Some(ProcessExitEvent {
                        ts_ns: ts,
                        pid,
                        uid: 0,
                        comm,
                        exit_code: 0,
                        // Java fatal exception ≈ uncaught throwable → SIGABRT
                        // because the runtime aborts via abort(2).
                        exit_signal: neutron_common::SIGABRT,
                        source: ExitSource::Logcat,
                    });
                }
            }
        }

        // 2. Native crash via debuggerd — `pid: N, tid: N, name: ...` and the
        //    follow-up `signal N (SIGxxx)`.
        if let Some(rest) = line.split("DEBUG").nth(1) {
            // The actual content lives after the *first* tag separator ": ".
            // Use splitn so that subsequent ": " inside the message (e.g.
            // "pid: 6789, tid: 6789, ...") are NOT consumed.
            let body = rest.split_once(": ").map(|x| x.1).unwrap_or("");
            if let Some(rest) = body.trim_start().strip_prefix("pid: ") {
                let mut parts = rest.split(',').map(str::trim);
                let pid = parts
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let comm = parts
                    .find(|s| s.starts_with("name: "))
                    .map(|s| {
                        // Strip "name: " then chop off the ">>> ... <<<" package
                        // suffix that debuggerd appends. Comm field is just the
                        // bare process name.
                        let raw = s.trim_start_matches("name: ");
                        let cut = raw.find(">>>").map(|i| &raw[..i]).unwrap_or(raw);
                        cut.trim().to_string()
                    })
                    .unwrap_or_default();
                if pid != 0 {
                    self.pending_native = Some(ProcessExitEvent {
                        ts_ns: now_ns,
                        pid,
                        uid: 0,
                        comm,
                        exit_code: 0,
                        exit_signal: 0, // filled by the next line
                        source: ExitSource::Logcat,
                    });
                    return None;
                }
            }
            if let Some(rest) = body.trim_start().strip_prefix("signal ") {
                if let Some(mut pending) = self.pending_native.take() {
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    pending.exit_signal = num_str.parse().unwrap_or(0);
                    return Some(pending);
                }
            }
        }

        // 3. ANR — `ANR in <pkg>` followed (a few lines later) by `PID: N`
        //    on the same logical block. We treat the "PID: " line as the
        //    completion trigger.
        if let Some(rest) = line.split("ANR in ").nth(1) {
            let comm = rest.split(' ').next().unwrap_or("").to_string();
            // Some logcat formats put PID on the same line; others a few
            // lines below. Try the same line first.
            if let Some(pid_str) = line.split("PID:").nth(1) {
                let pid: u32 = pid_str
                    .trim()
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("")
                    .parse()
                    .unwrap_or(0);
                if pid != 0 {
                    return Some(ProcessExitEvent {
                        ts_ns: now_ns,
                        pid,
                        uid: 0,
                        comm,
                        exit_code: 0,
                        // ANR ≈ kernel SIGQUIT to dump traces; classify as
                        // SignalExit (not "crash" per R003).
                        exit_signal: 3, // SIGQUIT
                        source: ExitSource::Logcat,
                    });
                }
            }
        }

        None
    }
}

/// Mock reader for unit tests. Each line fed via `feed_line` is parsed
/// immediately; events surface on the next `drain` call.
#[cfg(test)]
#[derive(Default)]
pub struct MockLogcatReader {
    parser: LogcatParser,
    pending: Vec<ProcessExitEvent>,
}

#[cfg(test)]
impl MockLogcatReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_line(&mut self, line: &str, now_ns: u64) {
        if let Some(ev) = self.parser.feed_line(line, now_ns) {
            self.pending.push(ev);
        }
    }
}

#[cfg(test)]
impl LogcatReader for MockLogcatReader {
    fn drain(&mut self, _now_ns: u64) -> Vec<ProcessExitEvent> {
        std::mem::take(&mut self.pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use neutron_common::{SIGABRT, SIGSEGV};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn logcat_pipe_is_marked_nonblocking() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        set_nonblocking(stream.as_raw_fd()).unwrap();
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn java_fatal_exception_two_line_block_emits_event() {
        let mut p = LogcatParser::default();
        let r1 = p.feed_line(
            "05-05 12:00:00.000 12345 12345 E AndroidRuntime: FATAL EXCEPTION: main",
            100,
        );
        assert!(r1.is_none(), "first line is incomplete");
        let r2 = p.feed_line(
            "05-05 12:00:00.001 12345 12345 E AndroidRuntime: Process: com.example.app, PID: 12345",
            200,
        );
        let ev = r2.expect("two-line block must complete");
        assert_eq!(ev.pid, 12345);
        assert_eq!(ev.exit_signal, SIGABRT);
        assert_eq!(ev.comm, "com.example.app");
        assert_eq!(ev.source, ExitSource::Logcat);
        assert_eq!(ev.ts_ns, 100, "ts_ns should be the FATAL line's ts");
    }

    #[test]
    fn native_crash_two_line_block_emits_event() {
        let mut p = LogcatParser::default();
        let r1 = p.feed_line(
            "05-05 12:00:00.000   600   600 F DEBUG   : pid: 6789, tid: 6789, name: native.bin  >>> /system/bin/native.bin <<<",
            300,
        );
        assert!(r1.is_none());
        let r2 = p.feed_line(
            "05-05 12:00:00.001   600   600 F DEBUG   : signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0",
            400,
        );
        let ev = r2.expect("native two-line block must complete");
        assert_eq!(ev.pid, 6789);
        assert_eq!(ev.exit_signal, SIGSEGV);
        assert_eq!(ev.comm, "native.bin");
    }

    #[test]
    fn anr_single_line_emits_signal_exit() {
        let mut p = LogcatParser::default();
        let r = p.feed_line(
            "05-05 12:00:00.000  1000  1000 E ActivityManager: ANR in com.example.app PID: 4242 (extra context)",
            500,
        );
        let ev = r.expect("ANR line must produce an event");
        assert_eq!(ev.pid, 4242);
        assert_eq!(ev.exit_signal, 3, "ANR maps to SIGQUIT");
        assert_eq!(ev.source, ExitSource::Logcat);
    }

    #[test]
    fn unrelated_lines_produce_nothing() {
        let mut p = LogcatParser::default();
        for line in [
            "05-05 12:00:00.000 1234 1234 I MyTag: hello",
            "05-05 12:00:00.001 1234 1234 D MyTag: debug",
            "05-05 12:00:00.002 1234 1234 W MyTag: warn",
        ] {
            assert!(p.feed_line(line, 0).is_none());
        }
    }

    #[test]
    fn mock_reader_drains_pending_then_empty() {
        let mut r = MockLogcatReader::new();
        r.feed_line(
            "05-05 12:00:00.000 1 1 E AndroidRuntime: FATAL EXCEPTION: main",
            100,
        );
        r.feed_line(
            "05-05 12:00:00.001 1 1 E AndroidRuntime: Process: pkg, PID: 1",
            200,
        );
        let first = r.drain(0);
        assert_eq!(first.len(), 1);
        let second = r.drain(0);
        assert!(second.is_empty());
    }
}
