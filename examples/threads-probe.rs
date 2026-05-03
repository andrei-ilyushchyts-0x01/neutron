//! threads-probe — TGID-filter verification target for `neutron`.
//!
//! Spawns the main thread plus four worker threads. Each thread opens a
//! distinct sentinel file under `/data/local/tmp/neutron-thread-*`. All
//! threads share the same userspace process ID (kernel TGID) but have
//! different thread IDs (kernel PIDs).
//!
//! Usage on a connected Pixel:
//!
//! ```sh
//! cargo build --example threads-probe \
//!     --release --target aarch64-unknown-linux-musl
//! adb push target/aarch64-unknown-linux-musl/release/examples/threads-probe \
//!     /data/local/tmp/
//! adb shell '/data/local/tmp/threads-probe & echo $!'   # remember the PID
//! adb shell su -c '/data/local/tmp/neutron --pid <PID> --json' \
//!     | grep neutron-thread-
//! ```
//!
//! Expected output: five `openat` events, one per sentinel:
//!   `/data/local/tmp/neutron-thread-main`
//!   `/data/local/tmp/neutron-thread-0`
//!   `/data/local/tmp/neutron-thread-1`
//!   `/data/local/tmp/neutron-thread-2`
//!   `/data/local/tmp/neutron-thread-binder-pool`
//!
//! If neutron only sees `neutron-thread-main`, the BPF filter is matching on
//! the kernel `pid` (thread ID) instead of the kernel `tgid` (process ID) —
//! see `neutron-ebpf/src/main.rs::pid_matches`.

use std::fs::OpenOptions;
use std::thread;
use std::time::Duration;

const SENTINEL_DIR: &str = "/data/local/tmp";

fn open_marker(suffix: &str) {
    let path = format!("{SENTINEL_DIR}/neutron-thread-{suffix}");
    // Best-effort: we just need the openat to fire. Actual file creation may
    // fail under SELinux or read-only mounts, but the syscall is what
    // neutron observes.
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path);
    // Small sleep so events from different threads don't all race the same
    // BPF tail and let the operator see them clearly in the trace.
    thread::sleep(Duration::from_millis(20));
}

fn main() {
    eprintln!("threads-probe: pid={}", std::process::id());

    // Main thread sentinel.
    open_marker("main");

    // Three plain pthread workers (each gets its own kernel PID; same TGID).
    let workers: Vec<_> = (0..3)
        .map(|i| {
            thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || open_marker(&i.to_string()))
                .expect("spawn worker")
        })
        .collect();

    // Simulated binder-pool-style thread: one extra thread named
    // "binder-pool" to mimic Android's libbinder thread pool. We don't need
    // a real binder transaction for the TGID test — what matters is that the
    // openat from a non-main, non-zygote-named thread reaches userspace.
    let binder_pool = thread::Builder::new()
        .name("binder-pool".to_string())
        .spawn(|| open_marker("binder-pool"))
        .expect("spawn binder-pool");

    for w in workers {
        let _ = w.join();
    }
    let _ = binder_pool.join();

    eprintln!("threads-probe: done");
}
