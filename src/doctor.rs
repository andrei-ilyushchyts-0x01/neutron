//! `neutron doctor` — preflight environment checks.
//!
//! Verifies the prerequisites that have to hold for neutron to attach and run
//! on the current device:
//!
//!   - Sufficient privilege (euid 0 or `CAP_BPF` + `CAP_SYS_ADMIN`)
//!   - Kernel ≥ 6.1 with BTF, tracefs, bpffs
//!   - BPF ringbuf support (kernel 5.8+)
//!   - `raw_syscalls/sys_{enter,exit}` tracepoints
//!   - `binder/binder_transaction` tracepoint (warn if missing)
//!   - `/proc/kallsyms` readable (kptr_restrict)
//!   - SELinux mode (warn if enforcing for an unprivileged caller)
//!   - Architecture is `aarch64`
//!
//! Each check produces a `CheckResult` with a status and a one-line reason.
//! `run()` prints the table and returns `0` when every check is `Pass` or
//! `Warn`, and `1` if any check is `Fail`.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: Status,
    pub reason: String,
}

impl CheckResult {
    pub fn pass(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Pass,
            reason: reason.into(),
        }
    }
    pub fn warn(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            reason: reason.into(),
        }
    }
    pub fn fail(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            reason: reason.into(),
        }
    }
}

/// Filesystem reader injection point for tests. The real implementation
/// reads `/proc`, `/sys`, etc. directly.
pub trait Env {
    fn euid(&self) -> u32;
    fn read_to_string(&self, path: &str) -> std::io::Result<String>;
    fn path_exists(&self, path: &str) -> bool;
    fn arch(&self) -> &str;
}

pub struct RealEnv;

impl Env for RealEnv {
    fn euid(&self) -> u32 {
        // SAFETY: geteuid is always safe; returns the calling thread's euid.
        unsafe { libc::geteuid() }
    }
    fn read_to_string(&self, path: &str) -> std::io::Result<String> {
        fs::read_to_string(path)
    }
    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
    fn arch(&self) -> &str {
        std::env::consts::ARCH
    }
}

// ── Individual checks ────────────────────────────────────────────────────────

pub fn check_privilege<E: Env>(env: &E) -> CheckResult {
    let euid = env.euid();
    if euid == 0 {
        return CheckResult::pass("privilege", "running as root (euid=0)");
    }
    // Non-root: CAP_BPF + CAP_SYS_ADMIN may still allow loading. We can't
    // probe capabilities portably without libcap, so warn rather than fail.
    CheckResult::warn(
        "privilege",
        format!(
            "non-root (euid={euid}); need CAP_BPF + CAP_SYS_ADMIN \
             — run via `adb shell su -c …` on a rooted device"
        ),
    )
}

pub fn check_arch<E: Env>(env: &E) -> CheckResult {
    let arch = env.arch();
    if arch == "aarch64" {
        CheckResult::pass("arch", "aarch64")
    } else {
        CheckResult::fail(
            "arch",
            format!("expected aarch64, got {arch} — neutron's syscall table is aarch64-specific"),
        )
    }
}

pub fn check_kernel_version<E: Env>(env: &E) -> CheckResult {
    let v = match env.read_to_string("/proc/version") {
        Ok(s) => s,
        Err(e) => {
            return CheckResult::fail("kernel version", format!("cannot read /proc/version: {e}"))
        }
    };
    // Lines look like "Linux version 6.1.145-android14-11-... ".
    let prefix = "Linux version ";
    let trimmed = v.trim_start_matches(prefix);
    let token = trimmed.split_whitespace().next().unwrap_or("");
    let mut nums = token.split('.').take(2);
    let major: u32 = nums.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = nums
        .next()
        .and_then(|s| {
            // strip trailing non-numeric suffix in patterns like "1-android14"
            let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
            s[..end].parse().ok()
        })
        .unwrap_or(0);
    if major > 6 || (major == 6 && minor >= 1) {
        CheckResult::pass("kernel version", format!("{major}.{minor} (≥ 6.1)"))
    } else if major >= 5 {
        CheckResult::warn(
            "kernel version",
            format!("{major}.{minor} — neutron targets 6.1+; tracepoint layouts may differ"),
        )
    } else {
        CheckResult::fail(
            "kernel version",
            format!("{major}.{minor} — too old; required ≥ 6.1"),
        )
    }
}

pub fn check_btf<E: Env>(env: &E) -> CheckResult {
    let path = "/sys/kernel/btf/vmlinux";
    if env.path_exists(path) {
        CheckResult::pass("BTF", "/sys/kernel/btf/vmlinux present")
    } else {
        CheckResult::fail(
            "BTF",
            format!("{path} missing — kernel must be built with CONFIG_DEBUG_INFO_BTF=y"),
        )
    }
}

pub fn check_tracefs<E: Env>(env: &E) -> CheckResult {
    if env.path_exists("/sys/kernel/tracing") {
        CheckResult::pass("tracefs", "/sys/kernel/tracing mounted")
    } else if env.path_exists("/sys/kernel/debug/tracing") {
        CheckResult::warn(
            "tracefs",
            "only /sys/kernel/debug/tracing exists; modern path /sys/kernel/tracing missing",
        )
    } else {
        CheckResult::fail(
            "tracefs",
            "no tracefs mount found at /sys/kernel/tracing or /sys/kernel/debug/tracing",
        )
    }
}

pub fn check_bpffs<E: Env>(env: &E) -> CheckResult {
    if env.path_exists("/sys/fs/bpf") {
        CheckResult::pass("bpffs", "/sys/fs/bpf present")
    } else {
        CheckResult::warn(
            "bpffs",
            "/sys/fs/bpf missing — pinning won't work but transient programs still load",
        )
    }
}

pub fn check_raw_syscalls<E: Env>(env: &E) -> CheckResult {
    let enter = "/sys/kernel/tracing/events/raw_syscalls/sys_enter";
    let exit = "/sys/kernel/tracing/events/raw_syscalls/sys_exit";
    let have_enter = env.path_exists(enter);
    let have_exit = env.path_exists(exit);
    match (have_enter, have_exit) {
        (true, true) => CheckResult::pass(
            "raw_syscalls tracepoints",
            "both sys_enter and sys_exit present",
        ),
        (true, false) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "sys_enter present but sys_exit missing — neutron needs both",
        ),
        (false, true) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "sys_exit present but sys_enter missing — neutron needs both",
        ),
        (false, false) => CheckResult::fail(
            "raw_syscalls tracepoints",
            "neither tracepoint present — kernel CONFIG_FTRACE_SYSCALLS may be off",
        ),
    }
}

pub fn check_binder_tracepoint<E: Env>(env: &E) -> CheckResult {
    let p = "/sys/kernel/tracing/events/binder/binder_transaction";
    if env.path_exists(p) {
        CheckResult::pass("binder tracepoint", "binder/binder_transaction present")
    } else {
        CheckResult::warn(
            "binder tracepoint",
            "binder/binder_transaction missing — `--binder` mode will fail; \
             the rest of neutron still works",
        )
    }
}

pub fn check_kallsyms<E: Env>(env: &E) -> CheckResult {
    match env.read_to_string("/proc/kallsyms") {
        Err(e) => CheckResult::fail("kallsyms", format!("cannot read /proc/kallsyms: {e}")),
        Ok(s) => {
            // Heuristic: if every line shows 0x0 addresses, kptr_restrict is on.
            let masked = s.lines().take(5).all(|l| {
                let addr = l.split_whitespace().next().unwrap_or("");
                addr.chars().all(|c| c == '0')
            });
            if masked {
                CheckResult::warn(
                    "kallsyms",
                    "addresses zeroed (kptr_restrict ≥ 1) — kernel stack frames stay hex",
                )
            } else {
                CheckResult::pass(
                    "kallsyms",
                    "/proc/kallsyms readable with non-zero addresses",
                )
            }
        }
    }
}

pub fn check_selinux<E: Env>(env: &E) -> CheckResult {
    let p = "/sys/fs/selinux/enforce";
    if !env.path_exists(p) {
        return CheckResult::pass("SELinux", "no SELinux interface present");
    }
    match env.read_to_string(p) {
        Ok(s) if s.trim() == "0" => CheckResult::pass("SELinux", "permissive"),
        Ok(s) if s.trim() == "1" => CheckResult::warn(
            "SELinux",
            "enforcing — neutron load needs the calling domain to permit `bpf` capability",
        ),
        Ok(other) => CheckResult::warn("SELinux", format!("unexpected value: {}", other.trim())),
        Err(e) => CheckResult::warn("SELinux", format!("cannot read {p}: {e}")),
    }
}

/// Run all checks in display order.
pub fn run_all<E: Env>(env: &E) -> Vec<CheckResult> {
    vec![
        check_privilege(env),
        check_arch(env),
        check_kernel_version(env),
        check_btf(env),
        check_tracefs(env),
        check_bpffs(env),
        check_raw_syscalls(env),
        check_binder_tracepoint(env),
        check_kallsyms(env),
        check_selinux(env),
    ]
}

/// Print results table to stderr; return process exit code.
pub fn print_and_exit_code(results: &[CheckResult]) -> i32 {
    eprintln!("neutron doctor — preflight checks");
    eprintln!();
    let name_w = results.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for r in results {
        eprintln!(
            "  [{}] {:<width$}  {}",
            r.status.glyph(),
            r.name,
            r.reason,
            width = name_w
        );
    }
    eprintln!();
    let n_fail = results.iter().filter(|r| r.status == Status::Fail).count();
    let n_warn = results.iter().filter(|r| r.status == Status::Warn).count();
    if n_fail > 0 {
        eprintln!("doctor: {n_fail} FAIL, {n_warn} WARN — neutron will not run as-is");
        1
    } else if n_warn > 0 {
        eprintln!("doctor: {n_warn} WARN — neutron should run but check the warnings above");
        0
    } else {
        eprintln!("doctor: all checks passed");
        0
    }
}

/// Convenience entry point used by `main` when the `doctor` subcommand is
/// invoked. Runs all checks against the real environment, prints the table,
/// and returns the suggested process exit code.
pub fn run() -> i32 {
    let env = RealEnv;
    let results = run_all(&env);
    print_and_exit_code(&results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeEnv {
        euid: u32,
        files: RefCell<HashMap<String, String>>,
        existing: RefCell<Vec<String>>,
        arch: String,
    }

    impl FakeEnv {
        fn new() -> Self {
            Self {
                euid: 0,
                files: RefCell::new(HashMap::new()),
                existing: RefCell::new(vec![]),
                arch: "aarch64".to_string(),
            }
        }
        fn with_file(self, path: &str, contents: &str) -> Self {
            self.files.borrow_mut().insert(path.into(), contents.into());
            self.existing.borrow_mut().push(path.into());
            self
        }
        fn with_existing(self, path: &str) -> Self {
            self.existing.borrow_mut().push(path.into());
            self
        }
        fn with_arch(mut self, arch: &str) -> Self {
            self.arch = arch.into();
            self
        }
        fn with_euid(mut self, euid: u32) -> Self {
            self.euid = euid;
            self
        }
    }

    impl Env for FakeEnv {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn read_to_string(&self, path: &str) -> std::io::Result<String> {
            self.files
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
        fn path_exists(&self, path: &str) -> bool {
            self.existing.borrow().iter().any(|p| p == path)
        }
        fn arch(&self) -> &str {
            &self.arch
        }
    }

    #[test]
    fn privilege_pass_for_root() {
        let env = FakeEnv::new();
        assert_eq!(check_privilege(&env).status, Status::Pass);
    }

    #[test]
    fn privilege_warn_for_unprivileged() {
        let env = FakeEnv::new().with_euid(2000);
        assert_eq!(check_privilege(&env).status, Status::Warn);
    }

    #[test]
    fn arch_fails_for_x86() {
        let env = FakeEnv::new().with_arch("x86_64");
        assert_eq!(check_arch(&env).status, Status::Fail);
    }

    #[test]
    fn kernel_version_pass_for_pixel_8_pro() {
        let env = FakeEnv::new().with_file(
            "/proc/version",
            "Linux version 6.1.145-android14-11 (build@host) ...",
        );
        assert_eq!(check_kernel_version(&env).status, Status::Pass);
    }

    #[test]
    fn kernel_version_fail_for_4_14() {
        let env = FakeEnv::new().with_file("/proc/version", "Linux version 4.14.180 (legacy)");
        assert_eq!(check_kernel_version(&env).status, Status::Fail);
    }

    #[test]
    fn kernel_version_warn_for_5_15() {
        let env = FakeEnv::new().with_file("/proc/version", "Linux version 5.15.0 ...");
        assert_eq!(check_kernel_version(&env).status, Status::Warn);
    }

    #[test]
    fn btf_pass_when_present() {
        let env = FakeEnv::new().with_existing("/sys/kernel/btf/vmlinux");
        assert_eq!(check_btf(&env).status, Status::Pass);
    }

    #[test]
    fn btf_fail_when_missing() {
        let env = FakeEnv::new();
        assert_eq!(check_btf(&env).status, Status::Fail);
    }

    #[test]
    fn raw_syscalls_pass_when_both_present() {
        let env = FakeEnv::new()
            .with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_enter")
            .with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_exit");
        assert_eq!(check_raw_syscalls(&env).status, Status::Pass);
    }

    #[test]
    fn raw_syscalls_fail_when_either_missing() {
        let env = FakeEnv::new().with_existing("/sys/kernel/tracing/events/raw_syscalls/sys_enter");
        assert_eq!(check_raw_syscalls(&env).status, Status::Fail);
    }

    #[test]
    fn binder_warn_when_missing() {
        let env = FakeEnv::new();
        assert_eq!(check_binder_tracepoint(&env).status, Status::Warn);
    }

    #[test]
    fn kallsyms_warn_when_addresses_masked() {
        let env = FakeEnv::new().with_file(
            "/proc/kallsyms",
            "0000000000000000 T do_syscall_64\n0000000000000000 T do_anything\n",
        );
        assert_eq!(check_kallsyms(&env).status, Status::Warn);
    }

    #[test]
    fn kallsyms_pass_when_real_addresses() {
        let env = FakeEnv::new().with_file("/proc/kallsyms", "ffffffc01023f000 T do_syscall_64\n");
        assert_eq!(check_kallsyms(&env).status, Status::Pass);
    }

    #[test]
    fn selinux_pass_when_permissive() {
        let env = FakeEnv::new().with_file("/sys/fs/selinux/enforce", "0");
        assert_eq!(check_selinux(&env).status, Status::Pass);
    }

    #[test]
    fn selinux_warn_when_enforcing() {
        let env = FakeEnv::new().with_file("/sys/fs/selinux/enforce", "1");
        assert_eq!(check_selinux(&env).status, Status::Warn);
    }

    #[test]
    fn print_and_exit_returns_one_on_any_fail() {
        let results = vec![
            CheckResult::pass("a", "ok"),
            CheckResult::fail("b", "broken"),
        ];
        assert_eq!(print_and_exit_code(&results), 1);
    }

    #[test]
    fn print_and_exit_returns_zero_on_only_warnings() {
        let results = vec![CheckResult::pass("a", "ok"), CheckResult::warn("b", "soft")];
        assert_eq!(print_and_exit_code(&results), 0);
    }
}
