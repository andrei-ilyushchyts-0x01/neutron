use neutron::{process_state::ProcessState, SyscallEvent};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    process::Command,
    thread,
    time::{Duration, Instant},
};

#[test]
fn pthread_exit_does_not_end_process_before_worker_sentinel() {
    let directory =
        std::env::temp_dir().join(format!("neutron-leader-exit-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let executable = directory.join("probe");
    assert!(Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/native-lifecycle-probe.c"
        ))
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap()
        .success());
    let mut child = Command::new(&executable).arg(&directory).spawn().unwrap();
    let pid = child.id();
    let mut state = ProcessState::default();
    state.refresh(pid, neutron::native::read_starttime(pid));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !directory.join("leader-ready").exists() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("probe did not start");
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::write(directory.join("start"), b"start").unwrap();
    loop {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        if stat
            .rsplit_once(')')
            .unwrap()
            .1
            .trim_start()
            .starts_with('Z')
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("leader did not exit");
        }
        thread::sleep(Duration::from_millis(5));
    }
    state.task_exit(SyscallEvent {
        pid,
        tgid: pid,
        ..Default::default()
    });
    assert!(
        state.confirmed_exits().is_empty(),
        "leader exit removed a live worker"
    );
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("probe did not exit within deadline");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert!(directory.join("worker-after-leader").exists());
    assert_eq!(state.confirmed_exits().len(), 1);
    assert!(state.confirmed_exits().is_empty());
    fs::remove_dir_all(directory).unwrap();
}
