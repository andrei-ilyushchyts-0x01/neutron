//! threads-probe — TGID-filter verification target for `neutron`.
//!
//! Spawns the main thread plus four worker threads. Each thread opens a
//! distinct sentinel file in its private session directory. All
//! threads share the same userspace process ID (kernel TGID) but have
//! different thread IDs (kernel PIDs).
//!
//! Pass `--sentinel-dir /absolute/private/session` (required). Each run owns
//! its directory; no shared /data/local/tmp sentinel names are used.
//! For leader-first pthread_exit use native-lifecycle-probe.c, whose worker
//! writes an independent sentinel after the leader has exited.

use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::thread;
use std::time::Duration;

fn open_marker(directory: &std::path::Path, suffix: &str) {
    let path = directory.join(format!("neutron-thread-{suffix}"));
    // Require the independent filesystem oracle as well as the syscall.
    let _file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .expect("create session-owned sentinel");
    // Small sleep so events from different threads don't all race the same
    // BPF tail and let the operator see them clearly in the trace.
    thread::sleep(Duration::from_millis(20));
}

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    assert!(
        args.len() == 2 && args[0] == "--sentinel-dir",
        "usage: threads-probe --sentinel-dir PRIVATE_DIRECTORY"
    );
    let directory = std::path::PathBuf::from(&args[1]);
    let metadata = std::fs::symlink_metadata(&directory).expect("sentinel directory");
    assert!(
        directory.is_absolute()
            && metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "sentinel directory must exist, be absolute, owned and private"
    );
    eprintln!("threads-probe: pid={}", std::process::id());

    // Main thread sentinel.
    open_marker(&directory, "main");

    // Three plain pthread workers (each gets its own kernel PID; same TGID).
    let workers: Vec<_> = (0..3)
        .map(|i| {
            let directory = directory.clone();
            thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || open_marker(&directory, &i.to_string()))
                .expect("spawn worker")
        })
        .collect();

    // Simulated binder-pool-style thread: one extra thread named
    // "binder-pool" to mimic Android's libbinder thread pool. We don't need
    // a real binder transaction for the TGID test — what matters is that the
    // openat from a non-main, non-zygote-named thread reaches userspace.
    let binder_pool = thread::Builder::new()
        .name("binder-pool".to_string())
        .spawn(move || open_marker(&directory, "binder-pool"))
        .expect("spawn binder-pool");

    for w in workers {
        let _ = w.join();
    }
    let _ = binder_pool.join();

    eprintln!("threads-probe: done");
}
