//! demo-target — exercises every deterministically-fireable detector in
//! neutron's default rule pack.
//!
//! Each phase is a single small set of syscalls that triggers exactly one
//! rule (or one cluster of related rules). Phases run in numeric order and
//! emit a stderr marker so an operator running this under `neutron --pid
//! <PID>` can correlate the trace with the rule it expects.
//!
//! ## Coverage
//!
//! Behavior-only rules (no `--stacks` requirement, fully deterministic):
//!
//! | Phase | Rule(s)                            | What we do                              |
//! |-------|------------------------------------|------------------------------------------|
//! | 1     | T001 `proc_self_maps_polling`     | open `/proc/self/maps` x3 over 150 ms   |
//! | 2     | T002 `mountinfo_magisk_check`     | open `/proc/self/{mountinfo,mounts}`    |
//! | 3     | T003 `proc_status_tracerpid`       | open `/proc/self/status`                |
//! | 4     | T004 `su_binary_probe`             | stat `/system/{,x}bin/su`               |
//! | 5     | T005 `magisk_path_probe`           | stat `/data/adb/magisk`, `/sbin/.magisk`|
//! | 6     | T006 `frida_artifact_probe`        | stat `/data/local/tmp/frida-server`     |
//! | 7     | T007 `xposed_artifact_probe`       | stat `/system/framework/XposedBridge.jar` |
//! | 8     | T008 `runtime_exec_root_command`   | execve("su", "-c", "true")              |
//! | 9     | T009 `ptrace_self_or_remote`       | `ptrace(PTRACE_TRACEME)`                |
//! | 10    | T010 `prctl_dumpable_check`        | `prctl(PR_GET_DUMPABLE)`                |
//! | 11    | T011 `rwx_memory_allocation`       | `mmap(PROT_RWX)` + `munmap`             |
//! | 12    | T012 `proc_net_enumeration`        | open `/proc/net/tcp`                    |
//! | 13    | T013 `selinux_status_check`        | open `/sys/fs/selinux/enforce`          |
//! | 14    | T014 `property_service_query`      | open `/dev/__properties__`              |
//! | 15    | T015 `cross_process_proc`          | open `/proc/1/cmdline`                  |
//! | 16    | T021 `frida_thread_comm_scan`      | open `/proc/self/task/<tid>/comm` x6   |
//! | 17    | T022 `unexpected_bpf_syscall`      | `bpf(BPF_PROG_LOAD, NULL, 0)` (EPERM ok)|
//! | 18    | (FD-graph MVP)                     | open `/dev/null` + `dup` + `ioctl` + `close` |
//!
//! Stack-dependent rules T016 / T017 / T018 / T019 / T020 are NOT exercised
//! here because their golden output depends on per-device library layout
//! and is not stable across builds.
//!
//! ## Running
//!
//! ```sh
//! # Build and push.
//! cargo build --example demo-target --release \
//!     --target aarch64-unknown-linux-musl
//! adb push target/aarch64-unknown-linux-musl/release/examples/demo-target \
//!     /data/local/tmp/
//!
//! # Capture findings (terminal A).
//! adb shell su -c '/data/local/tmp/neutron --pid 0 --json' > demo-trace.ndjson
//! # … then run the demo (terminal B), Ctrl-C neutron when done.
//! adb shell '/data/local/tmp/demo-target'
//! ```
//!
//! Or use the higher-level harness: `cargo xtask demo`.

use std::ffi::CString;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::thread;
use std::time::{Duration, Instant};

const PHASE_GAP: Duration = Duration::from_millis(50);

fn marker(phase: u32, rule: &str, detail: &str) {
    eprintln!("[phase {phase:02}] {rule} — {detail}");
}

fn slow() {
    thread::sleep(PHASE_GAP);
}

fn read_path(path: &str) {
    // We deliberately ignore the result. The point is the openat syscall;
    // it fires regardless of whether we then read the file.
    let _ = std::fs::read(path);
}

fn stat_path(path: &str) {
    let _ = std::fs::metadata(path);
}

/// Parse `--loop SECONDS` from argv. `0` (default) means run once and exit.
fn parse_loop_secs() -> u64 {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--loop" {
            if let Some(v) = args.next() {
                if let Ok(n) = v.parse::<u64>() {
                    return n;
                }
            }
        }
    }
    0
}

fn main() {
    let pid = std::process::id();
    let loop_secs = parse_loop_secs();
    eprintln!("demo-target: pid={pid}");
    if loop_secs > 0 {
        eprintln!(
            "demo-target: --loop {loop_secs}s — running phase set continuously for benchmarking"
        );
    } else {
        eprintln!(
            "demo-target: each phase fires one rule; correlate stderr with `neutron --pid {pid}` output"
        );
    }
    let deadline = if loop_secs > 0 {
        Some(Instant::now() + Duration::from_secs(loop_secs))
    } else {
        None
    };

    let mut iteration: u32 = 0;
    loop {
        if iteration > 0 {
            eprintln!("---- iteration {iteration} ----");
        }
        run_phases(iteration == 0);
        iteration += 1;
        match deadline {
            Some(dl) if Instant::now() < dl => continue,
            _ => break,
        }
    }
    eprintln!("demo-target: done — {iteration} iteration(s)");
    let _ = CString::new("");
}

fn run_phases(verbose: bool) {
    // Helper that suppresses phase markers when iteration > 0 (loop mode).
    let m = |phase: u32, rule: &str, detail: &str| {
        if verbose {
            marker(phase, rule, detail);
        }
    };

    // ── Phase 1: T001 — periodic /proc/self/maps polling (need ≥2 in 15 s) ─
    for _ in 0..3 {
        read_path("/proc/self/maps");
        slow();
    }
    m(1, "T001", "/proc/self/maps x3");

    // ── Phase 2: T002 — mount table inspection ────────────────────────────
    read_path("/proc/self/mountinfo");
    read_path("/proc/mounts");
    m(2, "T002", "/proc/self/mountinfo + /proc/mounts");

    // ── Phase 3: T003 — TracerPid scrape ──────────────────────────────────
    read_path("/proc/self/status");
    m(3, "T003", "/proc/self/status");

    // ── Phase 4: T004 — su binary probe ───────────────────────────────────
    stat_path("/system/bin/su");
    stat_path("/system/xbin/su");
    m(4, "T004", "/system/{,x}bin/su stat");

    // ── Phase 5: T005 — Magisk artifact probe ─────────────────────────────
    stat_path("/data/adb/magisk");
    stat_path("/sbin/.magisk");
    m(5, "T005", "/data/adb/magisk + /sbin/.magisk");

    // ── Phase 6: T006 — Frida artifact probe ──────────────────────────────
    stat_path("/data/local/tmp/frida-server");
    m(6, "T006", "/data/local/tmp/frida-server");

    // ── Phase 7: T007 — Xposed probe ──────────────────────────────────────
    stat_path("/system/framework/XposedBridge.jar");
    m(7, "T007", "/system/framework/XposedBridge.jar");

    // ── Phase 8: T008 — execve(su) ────────────────────────────────────────
    // The exec almost always fails (su not present, EACCES, ENOENT) but
    // raw_syscalls/sys_enter fires before the failure resolves.
    let _ = std::process::Command::new("su")
        .arg("-c")
        .arg("true")
        .output();
    m(8, "T008", "execve(su)");

    // ── Phase 9: T009 — ptrace(PTRACE_TRACEME) ────────────────────────────
    // SAFETY: ptrace with PTRACE_TRACEME and target=0 is the canonical
    // anti-debug self-probe. Returns -1/EPERM if a tracer is already
    // attached, success otherwise; either way the syscall fires.
    unsafe {
        let _ = libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            0,
        );
    }
    m(9, "T009", "ptrace(PTRACE_TRACEME)");

    // ── Phase 10: T010 — prctl(PR_GET_DUMPABLE) ───────────────────────────
    unsafe {
        let _ = libc::prctl(libc::PR_GET_DUMPABLE);
    }
    m(10, "T010", "prctl(PR_GET_DUMPABLE)");

    // ── Phase 11: T011 — RWX mmap ─────────────────────────────────────────
    // Allocate a page with PROT_READ|PROT_WRITE|PROT_EXEC, then unmap.
    // Almost no benign code does this; T011 fires on the data[0] RWX marker
    // set by the BPF mmap capture.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p != libc::MAP_FAILED {
            let _ = libc::munmap(p, 4096);
        }
    }
    m(11, "T011", "mmap(PROT_RWX) 4096");

    // ── Phase 12: T012 — /proc/net/tcp scan ───────────────────────────────
    read_path("/proc/net/tcp");
    m(12, "T012", "/proc/net/tcp");

    // ── Phase 13: T013 — SELinux enforce probe ────────────────────────────
    read_path("/sys/fs/selinux/enforce");
    m(13, "T013", "/sys/fs/selinux/enforce");

    // ── Phase 14: T014 — Android property service ─────────────────────────
    stat_path("/dev/__properties__");
    m(14, "T014", "/dev/__properties__");

    // ── Phase 15: T015 — cross-process /proc inspection ───────────────────
    // PID 1 (init) is always present on Android.
    read_path("/proc/1/cmdline");
    m(15, "T015", "/proc/1/cmdline");

    // ── Phase 16: T021 — frida thread-comm scan (≥5 in 30 s) ──────────────
    // We open our own task/<tid>/comm six times to guarantee threshold.
    for tid in 1..=6 {
        let path = format!("/proc/self/task/{tid}/comm");
        read_path(&path);
    }
    m(16, "T021", "/proc/self/task/<tid>/comm x6");

    // ── Phase 17: T022 — bpf(2) from app process ──────────────────────────
    // bpf is syscall 280 on aarch64 / 321 on x86_64. We pass invalid args;
    // the kernel returns -EPERM (or -EINVAL) but the tracepoint fires.
    // SAFETY: passing nullable arg buffer / zero size is the standard "no-op"
    // probe; libc::syscall is the documented portable raw-syscall path.
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::syscall(libc::SYS_bpf, 0i32, std::ptr::null::<u8>(), 0usize);
    }
    m(17, "T022", "bpf() (EPERM expected)");

    // ── Phase 18: FD-graph MVP exercise ───────────────────────────────────
    // openat → dup → ioctl → close. T011/T012/etc. don't apply; this is
    // here so the fdgraph module's enrichment can be visually verified in
    // the trace output (`fd_kind`: file/device, `fd_path`: /dev/null).
    if let Ok(f) = OpenOptions::new().read(true).open("/dev/null") {
        let fd = f.as_raw_fd();
        unsafe {
            // dup3(fd, fd+100, 0) — guarantees a distinct new fd number.
            let new_fd = libc::dup3(fd, fd + 100, 0);
            if new_fd >= 0 {
                // Dummy ioctl that will fail with ENOTTY but still fires
                // the syscall and the FD-graph enrichment. 0xc0184500 is a
                // synthetic value: dir=11 (rw), size=0x18, type=0x45, nr=0x00.
                let _ = libc::ioctl(new_fd, 0xc0184500_u32 as _);
                let _ = libc::close(new_fd);
            }
        }
        // Drop `f` closes its own fd.
    }
    m(18, "FD-graph", "/dev/null + dup3 + ioctl + close");
}
