//! Aya end-to-end load/attach diagnostic.
//!
//! Loads the Rust BPF ELF, attaches all three programs, sets FILTER_MAP entries
//! to trace a target PID, opens the ring buffer, and prints a compact summary
//! of each `SyscallEvent` received. Useful for verifying verifier acceptance
//! and data correctness on a new device or after BPF-program changes.
//!
//! On device:
//!   adb shell su -c '/data/local/tmp/neutron-spike \
//!     --object /data/local/tmp/neutron.bpf.elf --pid 1234 --duration 5'

use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aya::maps::{Array, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use neutron::decode;
use neutron_common::{SyscallEvent, FILTER_KEY_ACTIVE, FILTER_KEY_PID};

struct Opts {
    object: PathBuf,
    pid: u32,
    duration: Option<Duration>,
    max_events: Option<u64>,
    resolve_paths: bool,
    json: bool,
    quiet: bool,
}

fn parse_opts() -> Opts {
    let mut it = std::env::args().skip(1);
    let mut object = PathBuf::from("/data/local/tmp/neutron.bpf.elf");
    let mut pid: u32 = 0;
    let mut duration = None;
    let mut max_events = None;
    let mut resolve_paths = false;
    let mut json = false;
    let mut quiet = false;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--object" | "-o" => {
                object = it.next().map(PathBuf::from).expect("--object needs path")
            }
            "--pid" | "-p" => {
                pid = it
                    .next()
                    .expect("--pid needs value")
                    .parse()
                    .expect("pid must be u32");
            }
            "--duration" | "-d" => {
                let s: u64 = it
                    .next()
                    .expect("--duration needs seconds")
                    .parse()
                    .expect("seconds");
                duration = Some(Duration::from_secs(s));
            }
            "--max-events" | "-n" => {
                max_events = Some(
                    it.next()
                        .expect("--max-events needs value")
                        .parse()
                        .expect("u64"),
                );
            }
            "--resolve-paths" => resolve_paths = true,
            "--json" => json = true,
            "--quiet" | "-q" => quiet = true,
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(1);
            }
        }
    }
    Opts {
        object,
        pid,
        duration,
        max_events,
        resolve_paths,
        json,
        quiet,
    }
}

fn main() {
    let opts = parse_opts();
    eprintln!("neutron-spike: loading {}", opts.object.display());
    eprintln!("Kernel: {}", read_kernel_version());
    if let Err(e) = run(&opts) {
        eprintln!("[FAIL] {e:#}");
        std::process::exit(1);
    }
}

fn read_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn attach_tp(
    bpf: &mut Ebpf,
    name: &str,
    category: &str,
    event: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let prog: &mut TracePoint = bpf
        .program_mut(name)
        .ok_or_else(|| format!("program {name} not found"))?
        .try_into()
        .map_err(|e| format!("{name}: not a TracePoint: {e}"))?;
    prog.load()
        .map_err(|e| format!("{name} load failed: {e}"))?;
    prog.attach(category, event)
        .map_err(|e| format!("{name} attach failed: {e}"))?;
    eprintln!("[OK] {name} loaded + attached to {category}/{event}");
    Ok(())
}

fn run(opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    // Kernel 4.14 needs perf_event_paranoid relaxed for unprivileged-ish access.
    let _ = std::fs::write("/proc/sys/kernel/perf_event_paranoid", "-1\n");

    let bytes = std::fs::read(&opts.object)
        .map_err(|e| format!("cannot read {}: {e}", opts.object.display()))?;
    let mut bpf = Ebpf::load(&bytes).map_err(|e| format!("Ebpf::load failed: {e}"))?;
    eprintln!("[OK] Ebpf::load succeeded");

    attach_tp(&mut bpf, "trace_sys_enter", "raw_syscalls", "sys_enter")?;
    attach_tp(&mut bpf, "trace_sys_exit", "raw_syscalls", "sys_exit")?;
    attach_tp(
        &mut bpf,
        "trace_binder_transaction",
        "binder",
        "binder_transaction",
    )?;

    // Set filter: pid + active flag (0 = allow all syscalls).
    {
        let mut filter: Array<_, u32> =
            Array::try_from(bpf.map_mut("FILTER_MAP").ok_or("FILTER_MAP missing")?)?;
        filter.set(FILTER_KEY_PID, opts.pid, 0)?;
        filter.set(FILTER_KEY_ACTIVE, 0u32, 0)?;
        eprintln!("[OK] FILTER_MAP: pid={} active=0", opts.pid);
    }

    // Open the BPF ring buffer (single multi-producer ring).
    let mut ring: RingBuf<_> =
        RingBuf::try_from(bpf.take_map("EVENTS").ok_or("EVENTS map missing")?)?;
    let ring_fd = ring.as_raw_fd();
    eprintln!("[OK] RingBuf opened (single MPMC ring, kernel-side reservations)");

    let deadline = opts.duration.map(|d| Instant::now() + d);
    let max_events = opts.max_events.unwrap_or(u64::MAX);
    let mut count: u64 = 0;
    let mut emitted: u64 = 0;
    let ev_size = std::mem::size_of::<SyscallEvent>();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    eprintln!("[OK] polling… (Ctrl-C to stop)");
    'outer: loop {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        let mut saw_any = false;
        loop {
            let bytes_owned: Vec<u8> = match ring.next() {
                Some(item) => {
                    let slice: &[u8] = &item;
                    if slice.len() < ev_size {
                        continue;
                    }
                    slice.to_vec()
                }
                None => break,
            };
            saw_any = true;
            // SAFETY: SyscallEvent is #[repr(C, packed)] of plain integers;
            // any 257-byte payload is a valid instance.
            let ev: SyscallEvent =
                unsafe { std::ptr::read_unaligned(bytes_owned.as_ptr() as *const _) };
            count += 1;
            let mut wrote_output = false;
            if opts.json {
                wrote_output = write_json(&mut out, &ev, opts.resolve_paths)?;
            } else if !opts.quiet {
                write_compact(&mut out, &ev, opts.resolve_paths)?;
                wrote_output = true;
            }
            if opts.json && wrote_output {
                emitted += 1;
            }
            let limit = if opts.json { emitted } else { count };
            if limit >= max_events {
                break 'outer;
            }
        }
        if !saw_any {
            // Block on `poll(2)` for ring-buffer readability with a short
            // timeout so deadline / Ctrl-C remain responsive.
            let mut pfd = libc::pollfd {
                fd: ring_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is a POD initialised above.
            unsafe {
                libc::poll(&mut pfd, 1, 100);
            }
        }
    }

    eprintln!();
    eprintln!("[DONE] events={count}");
    Ok(())
}

fn write_compact<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    resolve_paths: bool,
) -> std::io::Result<()> {
    // Avoid packed-field borrows: copy scalars out first.
    let ts = ev.timestamp_ns;
    let pid = ev.pid;
    let tid = ev.tgid;
    let nr = ev.syscall_nr;
    let ret = ev.ret;
    let is_enter = ev.is_enter;
    let kstk = ev.kernel_stackid;
    let ustk = ev.user_stackid;
    let a = ev.args;
    let comm_len = ev
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.comm.len());
    let comm = core::str::from_utf8(&ev.comm[..comm_len]).unwrap_or("?");
    let path = decode::resolve_path(ev, resolve_paths);
    write!(
        w,
        "{ts} {comm} pid={pid} tid={tid} nr={nr} {} ret={ret} \
         a=[{:#x},{:#x},{:#x},{:#x},{:#x},{:#x}] kstk={kstk} ustk={ustk}",
        if is_enter == 1 { "ENT" } else { "EXT" },
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5],
    )?;
    if let Some(path) = path {
        write!(w, " data=\"{path}\"")?;
    }
    writeln!(w)
}

fn write_json<W: Write>(
    w: &mut W,
    ev: &SyscallEvent,
    resolve_paths: bool,
) -> std::io::Result<bool> {
    let Some(line) = format_json_line(ev, resolve_paths) else {
        return Ok(false);
    };

    writeln!(w, "{line}")?;
    Ok(true)
}

fn format_json_line(ev: &SyscallEvent, resolve_paths: bool) -> Option<String> {
    let nr = ev.syscall_nr;
    if !decode::is_path_syscall(nr) {
        return None;
    }

    let ts = ev.timestamp_ns;
    let pid = ev.pid;
    let tid = ev.tgid;
    let ret = ev.ret;
    let is_enter = ev.is_enter;
    let comm_len = ev
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.comm.len());
    let comm = core::str::from_utf8(&ev.comm[..comm_len]).unwrap_or("?");
    let comm = escape_json(comm);
    let path = match decode::resolve_path(ev, resolve_paths) {
        Some(path) => format!(r#""{}""#, escape_json(&path)),
        None => "null".to_string(),
    };

    Some(format!(
        r#"{{"ts_ns":{ts},"pid":{pid},"tid":{tid},"comm":"{comm}","syscall_nr":{nr},"is_enter":{is_enter},"ret":{ret},"path":{path}}}"#
    ))
}

fn escape_json(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ if ch.is_control() => {
                let _ =
                    std::fmt::Write::write_fmt(&mut escaped, format_args!("\\u{:04x}", ch as u32));
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::format_json_line;
    use neutron_common::SyscallEvent;

    fn path_bytes(path: &[u8]) -> [u8; 128] {
        let mut data = [0u8; 128];
        let len = path.len().min(data.len());
        data[..len].copy_from_slice(&path[..len]);
        data
    }

    #[test]
    fn format_json_line_emits_null_path_when_resolution_fails() {
        let ev = SyscallEvent {
            pid: 101,
            tgid: 202,
            syscall_nr: 56,
            is_enter: 1,
            ..SyscallEvent::default()
        };

        let line = format_json_line(&ev, true).expect("json line");
        assert!(line.contains(r#""pid":101"#), "line was {line}");
        assert!(line.contains(r#""tid":202"#), "line was {line}");
        assert!(line.contains(r#""path":null"#), "line was {line}");
    }

    #[test]
    fn format_json_line_escapes_resolved_path() {
        let ev = SyscallEvent {
            pid: 7,
            tgid: 8,
            syscall_nr: 56,
            is_enter: 0,
            ret: 3,
            comm: *b"quoted-task\0\0\0\0\0",
            data: path_bytes(b"/tmp/with\"quote\"\0"),
            ..SyscallEvent::default()
        };

        let line = format_json_line(&ev, false).expect("json line");
        assert!(line.contains(r#""tid":8"#), "line was {line}");
        assert!(
            line.contains(r#""path":"/tmp/with\"quote\"""#),
            "line was {line}"
        );
    }
}
