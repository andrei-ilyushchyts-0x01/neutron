//! Logcat tail and fatal-line parser.
//!
//! On Android, fatal app errors are reported via `logcat` in three flavours:
//!
//! 1. **Java FATAL EXCEPTION** — recognised and counted, but not converted
//!    into a process exit because logcat does not prove a kernel signal.
//!
//! 2. **Native crash via debuggerd** — a SIGSEGV/SIGABRT/etc. tombstone is
//!    additionally mirrored to logcat by `debuggerd` with tag `DEBUG`. The
//!    `pid: N, tid: N, name: ...  >>> ... <<<` line and a `signal N (SIGxxx)`
//!    line are present, identical to the on-disk tombstone.
//!
//! 3. **ANR (Application Not Responding)** — recognised and counted, but not
//!    converted into a process exit or fabricated signal.
//!
//! The reader spawns a current-tail stream with explicit tag priorities and
//! parses line-by-line. The two production sources are abstracted behind
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

const MAX_LOGCAT_LINE_BYTES: usize = 64 * 1024;
const MAX_CORRELATION_LINES: u8 = 8;
const MAX_LOGCAT_COMM_BYTES: usize = 256;

const LOGCAT_ARGS: &[&str] = &[
    "-v",
    "threadtime",
    "-b",
    "crash",
    "-T",
    "0",
    "AndroidRuntime:E",
    "ActivityManager:E",
    "DEBUG:F",
    "*:S",
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LogcatSourceStats {
    pub baseline_drains: u64,
    pub baseline_lines_discarded: u64,
    pub baseline_events_discarded: u64,
    pub baseline_pending_discarded: u64,
    pub baseline_errors: u64,
    pub unprimed_drains: u64,
    pub lines_read: u64,
    pub oversized_lines: u64,
    pub eof: u64,
    pub read_errors: u64,
    pub incomplete_correlations: u64,
    pub malformed_correlations: u64,
    pub unsupported_java_fatal: u64,
    pub unsupported_anr: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamTerminalState {
    EndOfStream,
    ReadError {
        kind: io::ErrorKind,
        message: String,
    },
    ChildExited {
        status: String,
    },
    ChildWaitError {
        kind: io::ErrorKind,
        message: String,
    },
}

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
    reader: Option<Box<dyn BufRead + Send>>,
    parser: LogcatParser,
    pending_line: Vec<u8>,
    pending_overflow: bool,
    stats: LogcatSourceStats,
    terminal_state: Option<StreamTerminalState>,
    primed: bool,
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
    /// Spawn a current-tail, explicit-tag logcat stream. Returns `Err` when
    /// the binary is missing (host without `logcat`) so the caller can
    /// degrade gracefully.
    pub fn spawn() -> std::io::Result<Self> {
        let mut child = Command::new("/system/bin/logcat")
            .args(LOGCAT_ARGS)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()?;
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                stop_child(&mut child);
                return Err(io::Error::other("logcat stdout missing"));
            }
        };
        if let Err(error) = set_nonblocking(stdout.as_raw_fd()) {
            stop_child(&mut child);
            return Err(error);
        }
        Ok(Self::from_reader(Some(child), BufReader::new(stdout)))
    }

    fn from_reader<R>(child: Option<Child>, reader: R) -> Self
    where
        R: BufRead + Send + 'static,
    {
        Self {
            child,
            reader: Some(Box::new(reader)),
            parser: LogcatParser::default(),
            pending_line: Vec::with_capacity(4096),
            pending_overflow: false,
            stats: LogcatSourceStats::default(),
            terminal_state: None,
            primed: false,
        }
    }

    #[cfg(test)]
    fn from_reader_for_test<R>(reader: R) -> Self
    where
        R: BufRead + Send + 'static,
    {
        let mut source = Self::from_reader(None, reader);
        source.primed = true;
        source
    }

    pub fn stats(&self) -> LogcatSourceStats {
        let mut stats = self.stats;
        stats.incomplete_correlations = self.parser.incomplete_correlations;
        stats.malformed_correlations = self.parser.malformed_correlations;
        stats.unsupported_java_fatal = self.parser.unsupported_java_fatal;
        stats.unsupported_anr = self.parser.unsupported_anr;
        stats
    }

    /// Drain everything already buffered without admitting it as evidence,
    /// then reset all cross-line parser state. Live logcat uses `-T 0`; this
    /// explicit drain closes the spawn-to-boundary pipe-buffer race.
    pub fn prime(&mut self, now_ns: u64) -> io::Result<()> {
        self.stats.baseline_drains = self.stats.baseline_drains.saturating_add(1);
        let lines_before = self.stats.lines_read;
        let oversized_before = self.stats.oversized_lines;
        let events = self.drain_impl(now_ns);
        self.stats.baseline_lines_discarded = self
            .stats
            .baseline_lines_discarded
            .saturating_add(self.stats.lines_read.saturating_sub(lines_before))
            .saturating_add(self.stats.oversized_lines.saturating_sub(oversized_before));
        self.stats.baseline_events_discarded = self
            .stats
            .baseline_events_discarded
            .saturating_add(events.len() as u64);
        self.stats.baseline_pending_discarded = self
            .stats
            .baseline_pending_discarded
            .saturating_add(self.parser.pending_count())
            .saturating_add(u64::from(
                !self.pending_line.is_empty() || self.pending_overflow,
            ));
        self.pending_line.clear();
        self.pending_overflow = false;
        self.parser = LogcatParser::default();
        if let Some(terminal) = self.terminal_state.as_ref() {
            self.stats.baseline_errors = self.stats.baseline_errors.saturating_add(1);
            return Err(io::Error::other(format!(
                "logcat terminated during baseline drain: {terminal:?}"
            )));
        }
        self.primed = true;
        Ok(())
    }

    pub fn terminal_state(&self) -> Option<&StreamTerminalState> {
        self.terminal_state.as_ref()
    }

    pub fn is_available(&mut self) -> bool {
        if self.terminal_state.is_some() || self.reader.is_none() {
            return false;
        }
        let Some(child) = self.child.as_mut() else {
            return true;
        };
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(status)) => {
                self.terminal_state = Some(StreamTerminalState::ChildExited {
                    status: status.to_string(),
                });
                false
            }
            Err(error) => {
                self.terminal_state = Some(StreamTerminalState::ChildWaitError {
                    kind: error.kind(),
                    message: error.to_string(),
                });
                false
            }
        }
    }

    fn finish_pending_line(&mut self, now_ns: u64, out: &mut Vec<ProcessExitEvent>) {
        if self.pending_overflow {
            self.stats.oversized_lines = self.stats.oversized_lines.saturating_add(1);
        } else if !self.pending_line.is_empty() {
            self.stats.lines_read = self.stats.lines_read.saturating_add(1);
            let line = String::from_utf8_lossy(&self.pending_line);
            if let Some(event) = self.parser.feed_line(line.trim_end_matches('\r'), now_ns) {
                out.push(event);
            }
        }
        self.pending_line.clear();
        self.pending_overflow = false;
    }

    fn drain_impl(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        let mut out = Vec::new();
        if self.terminal_state.is_some() {
            return out;
        }
        while let Some(reader) = self.reader.as_mut() {
            let available = match reader.fill_buf() {
                Ok([]) => {
                    self.finish_pending_line(now_ns, &mut out);
                    self.parser.discard_pending(true);
                    self.stats.eof = self.stats.eof.saturating_add(1);
                    self.terminal_state = Some(StreamTerminalState::EndOfStream);
                    break;
                }
                Ok(available) => available,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => {
                    self.parser.discard_pending(true);
                    self.stats.read_errors = self.stats.read_errors.saturating_add(1);
                    self.terminal_state = Some(StreamTerminalState::ReadError {
                        kind: error.kind(),
                        message: error.to_string(),
                    });
                    break;
                }
            };
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consume = newline.map_or(available.len(), |index| index + 1);
            let content = newline.map_or(available, |index| &available[..index]);
            if self.pending_line.len() < MAX_LOGCAT_LINE_BYTES + 1 {
                let remaining = MAX_LOGCAT_LINE_BYTES + 1 - self.pending_line.len();
                self.pending_line
                    .extend_from_slice(&content[..content.len().min(remaining)]);
            }
            self.pending_overflow |= self.pending_line.len() > MAX_LOGCAT_LINE_BYTES;
            reader.consume(consume);
            if newline.is_some() {
                self.finish_pending_line(now_ns, &mut out);
            }
        }
        out
    }
}

pub(crate) fn stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for RealLogcatReader {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            stop_child(&mut c);
        }
    }
}

impl LogcatReader for RealLogcatReader {
    fn drain(&mut self, now_ns: u64) -> Vec<ProcessExitEvent> {
        if !self.primed {
            self.stats.unprimed_drains = self.stats.unprimed_drains.saturating_add(1);
            return Vec::new();
        }
        self.drain_impl(now_ns)
    }
}

/// Stateful line parser that recognises the three fatal patterns. Holds
/// minimal across-line state because Java/native crash blocks span multiple
/// lines (PID is on a follow-up line).
#[derive(Debug, Default)]
pub struct LogcatParser {
    /// When `Some`, we just saw the `pid: N, tid: N, name: ...` debuggerd
    /// header and are waiting for the `signal N (SIGxxx)` line.
    pending_native: Option<PendingNativeFatal>,
    incomplete_correlations: u64,
    malformed_correlations: u64,
    unsupported_java_fatal: u64,
    unsupported_anr: u64,
}

#[derive(Debug)]
struct PendingNativeFatal {
    event: ProcessExitEvent,
    remaining_lines: u8,
}

impl LogcatParser {
    fn pending_count(&self) -> u64 {
        u64::from(self.pending_native.is_some())
    }

    fn discard_pending(&mut self, count_incomplete: bool) -> u64 {
        let count = self.pending_count();
        self.pending_native = None;
        if count_incomplete {
            self.incomplete_correlations = self.incomplete_correlations.saturating_add(count);
        }
        count
    }

    fn age_pending(&mut self) {
        let mut expired = 0_u64;
        if self.pending_native.as_mut().is_some_and(|pending| {
            pending.remaining_lines = pending.remaining_lines.saturating_sub(1);
            pending.remaining_lines == 0
        }) {
            self.pending_native = None;
            expired += 1;
        }
        self.incomplete_correlations = self.incomplete_correlations.saturating_add(expired);
    }

    /// Feed one logcat line. Returns `Some(event)` when the line completes a
    /// fatal pattern; `None` when more lines are needed or the line is
    /// uninteresting.
    pub fn feed_line(&mut self, line: &str, now_ns: u64) -> Option<ProcessExitEvent> {
        self.age_pending();

        // 1. Java FATAL EXCEPTION — split across two lines.
        if line.contains("FATAL EXCEPTION:") && line.contains("AndroidRuntime") {
            self.unsupported_java_fatal = self.unsupported_java_fatal.saturating_add(1);
            return None;
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
                    .filter(|pid| *pid != 0);
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
                    .and_then(|value| valid_comm(&value));
                if let (Some(pid), Some(comm)) = (pid, comm) {
                    if self.pending_native.is_some() {
                        self.incomplete_correlations =
                            self.incomplete_correlations.saturating_add(1);
                    }
                    self.pending_native = Some(PendingNativeFatal {
                        event: ProcessExitEvent {
                            ts_ns: now_ns,
                            pid,
                            uid: None,
                            comm,
                            exit_code: 0,
                            exit_signal: 0, // filled by the next line
                            source: ExitSource::Logcat,
                        },
                        remaining_lines: MAX_CORRELATION_LINES,
                    });
                    return None;
                }
                self.malformed_correlations = self.malformed_correlations.saturating_add(1);
                return None;
            }
            if let Some(rest) = body.trim_start().strip_prefix("signal ") {
                if let Some(mut pending) = self.pending_native.take() {
                    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    let signal = num_str.parse::<u32>().ok().filter(|signal| *signal != 0);
                    if let Some(signal) = signal {
                        pending.event.exit_signal = signal;
                        return Some(pending.event);
                    }
                    self.malformed_correlations = self.malformed_correlations.saturating_add(1);
                    return None;
                }
            }
        }

        // 3. ANR — `ANR in <pkg>` followed (a few lines later) by `PID: N`
        //    on the same logical block. We treat the "PID: " line as the
        //    completion trigger.
        if line.contains("ActivityManager") && line.contains("ANR in ") {
            self.unsupported_anr = self.unsupported_anr.saturating_add(1);
            return None;
        }

        None
    }
}

fn valid_comm(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= MAX_LOGCAT_COMM_BYTES).then(|| value.to_string())
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
    use neutron_common::SIGSEGV;
    use std::io::{Cursor, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    struct ErrorReader(io::ErrorKind);

    impl Read for ErrorReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "injected logcat read failure"))
        }
    }

    impl BufRead for ErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Err(io::Error::new(self.0, "injected logcat read failure"))
        }

        fn consume(&mut self, _amount: usize) {}
    }

    #[test]
    fn logcat_pipe_is_marked_nonblocking() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        set_nonblocking(stream.as_raw_fd()).unwrap();
        let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn logcat_args_tail_only_the_protected_crash_buffer() {
        assert_eq!(
            LOGCAT_ARGS,
            [
                "-v",
                "threadtime",
                "-b",
                "crash",
                "-T",
                "0",
                "AndroidRuntime:E",
                "ActivityManager:E",
                "DEBUG:F",
                "*:S",
            ]
        );
    }

    #[test]
    fn java_fatal_is_counted_without_fabricating_a_process_exit() {
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
        assert!(r2.is_none());
        assert_eq!(p.unsupported_java_fatal, 1);
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
        assert_eq!(ev.uid, None);
        assert_eq!(ev.exit_signal, SIGSEGV);
        assert_eq!(ev.comm, "native.bin");
    }

    #[test]
    fn anr_is_counted_without_fabricating_a_signal_exit() {
        let mut p = LogcatParser::default();
        let r = p.feed_line(
            "05-05 12:00:00.000  1000  1000 E ActivityManager: ANR in com.example.app PID: 4242 (extra context)",
            500,
        );
        assert!(r.is_none());
        assert_eq!(p.unsupported_anr, 1);
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
    fn native_pending_state_expires_and_malformed_signal_is_counted() {
        let header = "05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: native  >>> native <<<";
        let mut expired = LogcatParser::default();
        assert!(expired.feed_line(header, 1).is_none());
        for _ in 0..MAX_CORRELATION_LINES {
            assert!(expired.feed_line("unrelated", 2).is_none());
        }
        assert_eq!(expired.incomplete_correlations, 1);
        assert_eq!(expired.pending_count(), 0);

        let mut malformed = LogcatParser::default();
        malformed.feed_line(header, 1);
        assert!(malformed
            .feed_line("05-05 12:00:00.001 1 1 F DEBUG: signal 0", 2)
            .is_none());
        assert_eq!(malformed.malformed_correlations, 1);
        assert_eq!(malformed.pending_count(), 0);
    }

    #[test]
    fn mock_reader_drains_pending_then_empty() {
        let mut r = MockLogcatReader::new();
        r.feed_line(
            "05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: native  >>> native <<<",
            100,
        );
        r.feed_line("05-05 12:00:00.001 1 1 F DEBUG: signal 11 (SIGSEGV)", 200);
        let first = r.drain(0);
        assert_eq!(first.len(), 1);
        let second = r.drain(0);
        assert!(second.is_empty());
    }

    #[test]
    fn real_reader_records_eof_and_becomes_unavailable() {
        let input =
            b"05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: native  >>> native <<<\n\
05-05 12:00:00.001 1 1 F DEBUG: signal 11 (SIGSEGV)\n";
        let mut reader = RealLogcatReader::from_reader_for_test(Cursor::new(input));

        let events = reader.drain(10);

        assert_eq!(events.len(), 1);
        assert_eq!(reader.stats().lines_read, 2);
        assert_eq!(reader.stats().eof, 1);
        assert_eq!(
            reader.terminal_state(),
            Some(&StreamTerminalState::EndOfStream)
        );
        assert!(!reader.is_available());
        reader.drain(20);
        assert_eq!(reader.stats().eof, 1, "terminal EOF is counted once");
    }

    #[test]
    fn real_reader_keeps_would_block_non_terminal() {
        let mut reader =
            RealLogcatReader::from_reader_for_test(ErrorReader(io::ErrorKind::WouldBlock));

        assert!(reader.drain(10).is_empty());
        assert_eq!(reader.stats().read_errors, 0);
        assert!(reader.terminal_state().is_none());
        assert!(reader.is_available());
    }

    #[test]
    fn unprimed_reader_never_admits_buffered_records() {
        let input = b"05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: old  >>> old <<<\n\
05-05 12:00:00.001 1 1 F DEBUG: signal 11 (SIGSEGV)\n";
        let mut reader = RealLogcatReader::from_reader(None, Cursor::new(input));

        assert!(reader.drain(10).is_empty());
        assert_eq!(reader.stats().unprimed_drains, 1);
        assert_eq!(reader.stats().lines_read, 0);
    }

    #[test]
    fn explicit_baseline_discards_buffered_events_and_pending_state() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        set_nonblocking(stream.as_raw_fd()).unwrap();
        peer.write_all(
            b"05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: old  >>> old <<<\n\
05-05 12:00:00.001 1 1 F DEBUG: signal 11 (SIGSEGV)\n\
05-05 12:00:00.002 2 2 F DEBUG: pid: 2, tid: 2, name: pending  >>> pending <<<\n",
        )
        .unwrap();
        let mut reader = RealLogcatReader::from_reader(None, BufReader::new(stream));

        reader.prime(10).unwrap();
        let baseline = reader.stats();
        assert_eq!(baseline.baseline_lines_discarded, 3);
        assert_eq!(baseline.baseline_events_discarded, 1);
        assert_eq!(baseline.baseline_pending_discarded, 1);

        peer.write_all(
            b"05-05 12:00:00.003 3 3 F DEBUG: pid: 3, tid: 3, name: current  >>> current <<<\n\
05-05 12:00:00.004 3 3 F DEBUG: signal 6 (SIGABRT)\n",
        )
        .unwrap();
        let events = reader.drain(20);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, 3);
        assert_eq!(reader.stats().incomplete_correlations, 0);
    }

    #[test]
    fn real_reader_records_non_would_block_error_once() {
        let mut reader =
            RealLogcatReader::from_reader_for_test(ErrorReader(io::ErrorKind::BrokenPipe));

        assert!(reader.drain(10).is_empty());
        assert_eq!(reader.stats().read_errors, 1);
        assert!(matches!(
            reader.terminal_state(),
            Some(StreamTerminalState::ReadError {
                kind: io::ErrorKind::BrokenPipe,
                ..
            })
        ));
        assert!(!reader.is_available());
        reader.drain(20);
        assert_eq!(reader.stats().read_errors, 1);
    }

    #[test]
    fn real_reader_discards_oversize_line_with_bounded_storage() {
        let mut input = vec![b'x'; MAX_LOGCAT_LINE_BYTES + 128];
        input.extend_from_slice(b"\n");
        input.extend_from_slice(
            b"05-05 12:00:00.000 1 1 F DEBUG: pid: 1, tid: 1, name: native  >>> native <<<\n\
05-05 12:00:00.001 1 1 F DEBUG: signal 11 (SIGSEGV)\n",
        );
        let mut reader = RealLogcatReader::from_reader_for_test(Cursor::new(input));

        let events = reader.drain(10);

        assert_eq!(events.len(), 1);
        assert_eq!(reader.stats().oversized_lines, 1);
        assert_eq!(reader.stats().lines_read, 2);
        assert!(reader.pending_line.capacity() <= (MAX_LOGCAT_LINE_BYTES + 1).next_power_of_two());
    }
}
