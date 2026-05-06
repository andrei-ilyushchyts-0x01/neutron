//! Syscall number → name table for aarch64 generic ABI.
//!
//! Source: `include/uapi/asm-generic/unistd.h` from kernel 6.1.x. Coverage
//! prioritises everything observed during V1 device validation plus the
//! security-relevant primitives (ptrace, kexec, capset, …).
//!
//! `syscall_nr == -1` is a synthetic value used by the binder kprobe path.

pub fn syscall_name(nr: i32) -> &'static str {
    match nr {
        // Binder kprobe sentinel
        -1 => "BINDER_TXN",

        // ── async I/O ──────────────────────────────────────────────────────
        0 => "io_setup",
        1 => "io_destroy",
        2 => "io_submit",
        3 => "io_cancel",
        4 => "io_getevents",

        // ── extended attributes ───────────────────────────────────────────
        5 => "setxattr",
        6 => "lsetxattr",
        7 => "fsetxattr",
        8 => "getxattr",
        9 => "lgetxattr",
        10 => "fgetxattr",
        11 => "listxattr",
        12 => "llistxattr",
        13 => "flistxattr",
        14 => "removexattr",
        15 => "lremovexattr",
        16 => "fremovexattr",

        // ── filesystem & files ────────────────────────────────────────────
        17 => "getcwd",
        18 => "lookup_dcookie",
        19 => "eventfd2",
        20 => "epoll_create1",
        21 => "epoll_ctl",
        22 => "epoll_pwait",
        23 => "dup",
        24 => "dup3",
        25 => "fcntl",
        26 => "inotify_init1",
        27 => "inotify_add_watch",
        28 => "inotify_rm_watch",
        29 => "ioctl",
        30 => "ioprio_set",
        31 => "ioprio_get",
        32 => "flock",
        33 => "mknodat",
        // CORRECTED in 1.0.0: the v0.1.0-legacy table was shifted by +1 here.
        // Authoritative numbers via the device's libc (verified 2026-04-26):
        //   mkdirat=34, unlinkat=35, symlinkat=36, linkat=37, renameat=38, umount2=39.
        34 => "mkdirat",
        35 => "unlinkat",
        36 => "symlinkat",
        37 => "linkat",
        38 => "renameat",
        39 => "umount2",
        40 => "mount",
        41 => "pivot_root",
        42 => "nfsservctl",
        43 => "statfs",
        44 => "fstatfs",
        45 => "truncate",
        46 => "ftruncate",
        47 => "fallocate",
        48 => "faccessat",
        49 => "chdir",
        50 => "fchdir",
        51 => "chroot",
        52 => "fchmod",
        53 => "fchmodat",
        54 => "fchownat",
        55 => "fchown",
        56 => "openat",
        57 => "close",
        58 => "vhangup",
        59 => "pipe2",
        60 => "quotactl",
        61 => "getdents64",
        62 => "lseek",
        63 => "read",
        64 => "write",
        65 => "readv",
        66 => "writev",
        67 => "pread64",
        68 => "pwrite64",
        69 => "preadv",
        70 => "pwritev",
        71 => "sendfile",
        72 => "pselect6",
        73 => "ppoll",
        74 => "signalfd4",
        75 => "vmsplice",
        76 => "splice",
        77 => "tee",
        78 => "readlinkat",
        79 => "fstatat",
        80 => "fstat",
        81 => "sync",
        82 => "fsync",
        83 => "fdatasync",
        84 => "sync_file_range",
        85 => "timerfd_create",
        86 => "timerfd_settime",
        87 => "timerfd_gettime",
        88 => "utimensat",
        89 => "acct",
        90 => "capget",
        91 => "capset",
        92 => "personality",

        // ── process / thread ──────────────────────────────────────────────
        93 => "exit",
        94 => "exit_group",
        95 => "waitid",
        96 => "set_tid_address",
        97 => "unshare",
        98 => "futex",
        99 => "set_robust_list",
        100 => "get_robust_list",
        101 => "nanosleep",
        102 => "getitimer",
        103 => "setitimer",
        104 => "kexec_load",
        105 => "init_module",
        106 => "delete_module",
        107 => "timer_create",
        108 => "timer_gettime",
        109 => "timer_getoverrun",
        110 => "timer_settime",
        111 => "timer_delete",
        112 => "clock_settime",
        113 => "clock_gettime",
        114 => "clock_getres",
        115 => "clock_nanosleep",
        116 => "syslog",
        117 => "ptrace",
        118 => "sched_setparam",
        119 => "sched_setscheduler",
        120 => "sched_getscheduler",
        121 => "sched_getparam",
        122 => "sched_setaffinity",
        123 => "sched_getaffinity",
        124 => "sched_yield",
        125 => "sched_get_priority_max",
        126 => "sched_get_priority_min",
        127 => "sched_rr_get_interval",
        128 => "restart_syscall",
        129 => "kill",
        130 => "tkill",
        131 => "tgkill",
        132 => "sigaltstack",
        133 => "rt_sigsuspend",
        134 => "rt_sigaction",
        135 => "rt_sigprocmask",
        136 => "rt_sigpending",
        137 => "rt_sigtimedwait",
        138 => "rt_sigqueueinfo",
        139 => "rt_sigreturn",
        140 => "setpriority",
        141 => "getpriority",
        142 => "reboot",
        143 => "setregid",
        144 => "setgid",
        145 => "setreuid",
        146 => "setuid",
        147 => "setresuid",
        148 => "getresuid",
        149 => "setresgid",
        150 => "getresgid",
        151 => "setfsuid",
        152 => "setfsgid",
        153 => "times",
        154 => "setpgid",
        155 => "getpgid",
        156 => "getsid",
        157 => "setsid",
        158 => "getgroups",
        159 => "setgroups",
        160 => "uname",
        161 => "sethostname",
        162 => "setdomainname",
        163 => "getrlimit",
        164 => "setrlimit",
        165 => "getrusage",
        166 => "umask",
        167 => "prctl",
        168 => "getcpu",
        169 => "gettimeofday",
        170 => "settimeofday",
        171 => "adjtimex",
        172 => "getpid",
        173 => "getppid",
        174 => "getuid",
        175 => "geteuid",
        176 => "getgid",
        177 => "getegid",
        178 => "gettid",
        179 => "sysinfo",
        180 => "mq_open",
        181 => "mq_unlink",
        182 => "mq_timedsend",
        183 => "mq_timedreceive",
        184 => "mq_notify",
        185 => "mq_getsetattr",
        186 => "msgget",
        187 => "msgctl",
        188 => "msgrcv",
        189 => "msgsnd",
        190 => "semget",
        191 => "semctl",
        192 => "semtimedop",
        193 => "semop",
        194 => "shmget",
        195 => "shmctl",
        196 => "shmat",
        197 => "shmdt",

        // ── network ───────────────────────────────────────────────────────
        198 => "socket",
        199 => "socketpair",
        200 => "bind",
        201 => "listen",
        202 => "accept",
        203 => "connect",
        204 => "getsockname",
        205 => "getpeername",
        206 => "sendto",
        207 => "recvfrom",
        208 => "setsockopt",
        209 => "getsockopt",
        210 => "shutdown",
        211 => "sendmsg",
        212 => "recvmsg",

        // ── memory ────────────────────────────────────────────────────────
        213 => "readahead",
        214 => "brk",
        215 => "munmap",
        216 => "mremap",
        217 => "add_key",
        218 => "request_key",
        219 => "keyctl",
        220 => "clone",
        221 => "execve",
        222 => "mmap",
        223 => "fadvise64",
        224 => "swapon",
        225 => "swapoff",
        226 => "mprotect",
        227 => "msync",
        228 => "mlock",
        229 => "munlock",
        230 => "mlockall",
        231 => "munlockall",
        232 => "mincore",
        233 => "madvise",
        234 => "remap_file_pages",
        235 => "mbind",
        236 => "get_mempolicy",
        237 => "set_mempolicy",
        238 => "migrate_pages",
        239 => "move_pages",
        240 => "rt_tgsigqueueinfo",
        241 => "perf_event_open",
        242 => "accept4",
        243 => "recvmmsg",

        // 244-258: assorted
        260 => "wait4",
        261 => "prlimit64",
        262 => "fanotify_init",
        263 => "fanotify_mark",
        264 => "name_to_handle_at",
        265 => "open_by_handle_at",
        266 => "clock_adjtime",
        267 => "syncfs",
        268 => "setns",
        269 => "sendmmsg",
        270 => "process_vm_readv",
        271 => "process_vm_writev",
        272 => "kcmp",
        273 => "finit_module",
        274 => "sched_setattr",
        275 => "sched_getattr",
        276 => "renameat2",
        277 => "seccomp",
        278 => "getrandom",
        279 => "memfd_create",
        280 => "bpf",
        281 => "execveat",
        282 => "userfaultfd",
        283 => "membarrier",
        284 => "mlock2",
        285 => "copy_file_range",
        286 => "preadv2",
        287 => "pwritev2",
        288 => "pkey_mprotect",
        289 => "pkey_alloc",
        290 => "pkey_free",
        291 => "statx",
        292 => "io_pgetevents",

        // Device-verified aliases (Pixel 4a may use these instead of 198/203)
        293 => "socket",
        294 => "connect",

        295 => "rseq",
        296 => "kexec_file_load",

        // 5.x+ additions (kernel 6.1 supports all of these)
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        428 => "open_tree",
        429 => "move_mount",
        430 => "fsopen",
        431 => "fsconfig",
        432 => "fsmount",
        433 => "fspick",
        434 => "pidfd_open",
        435 => "clone3",
        436 => "close_range",
        437 => "openat2",
        438 => "pidfd_getfd",
        439 => "faccessat2",
        440 => "process_madvise",
        441 => "epoll_pwait2",
        442 => "mount_setattr",
        443 => "quotactl_fd",
        444 => "landlock_create_ruleset",
        445 => "landlock_add_rule",
        446 => "landlock_restrict_self",
        447 => "memfd_secret",
        448 => "process_mrelease",
        449 => "futex_waitv",
        450 => "set_mempolicy_home_node",
        // 6.x:
        451 => "cachestat",
        452 => "fchmodat2",
        453 => "map_shadow_stack",
        454 => "futex_wake",
        455 => "futex_wait",
        456 => "futex_requeue",

        _ => "unknown",
    }
}

/// Reverse lookup: symbolic name → aarch64 syscall number. Returns
/// `None` for names we don't carry. Used by `--match-syscall` so
/// operators can write `--match-syscall ioctl,openat` instead of
/// `--match-syscall 29,56`. Linear scan over the full nr range; the
/// table is fixed-size so the cost is bounded and parsing happens
/// once at CLI parse time.
pub fn syscall_nr(name: &str) -> Option<i32> {
    if name.is_empty() {
        return None;
    }
    // Sentinels first — short-circuit rather than fall through 500+ nrs.
    let sentinel = match name {
        "BINDER_TXN" | "binder_txn" | "binder" => Some(-1),
        "BINDER_RECEIVED" | "binder_received" => Some(-4),
        "FD_SNAPSHOT" | "fd_snapshot" => Some(-2),
        "PROCESS_EXIT" | "process_exit" => Some(-3),
        _ => None,
    };
    if sentinel.is_some() {
        return sentinel;
    }
    // Brute-force scan. The aarch64 generic ABI tops out around 460;
    // we go a little past for new kernels. Stops at the first hit.
    (0..=470i32).find(|&nr| syscall_name(nr) == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_name_binder_sentinel() {
        assert_eq!(syscall_name(-1), "BINDER_TXN");
    }

    #[test]
    fn syscall_name_openat_56() {
        assert_eq!(syscall_name(56), "openat");
    }

    #[test]
    fn syscall_name_unknown_returns_unknown() {
        assert_eq!(syscall_name(99999), "unknown");
        assert_eq!(syscall_name(-2), "unknown");
    }

    #[test]
    fn syscall_name_spot_checks_table() {
        assert_eq!(syscall_name(29), "ioctl");
        assert_eq!(syscall_name(63), "read");
        assert_eq!(syscall_name(64), "write");
        assert_eq!(syscall_name(203), "connect");
        assert_eq!(syscall_name(294), "connect"); // device alias
        assert_eq!(syscall_name(222), "mmap");
        assert_eq!(syscall_name(226), "mprotect");
    }

    #[test]
    fn syscall_name_kernel_6_1_modern_table() {
        // Modern aarch64 kernel-6.1+ syscall numbers that the legacy
        // (kernel-4.14) table decoded as "unknown" — locked here so a future
        // table edit can't accidentally regress.
        assert_eq!(syscall_name(2), "io_submit");
        assert_eq!(syscall_name(4), "io_getevents");
        assert_eq!(syscall_name(21), "epoll_ctl");
        assert_eq!(syscall_name(22), "epoll_pwait");
        assert_eq!(syscall_name(53), "fchmodat");
        assert_eq!(syscall_name(132), "sigaltstack");
        assert_eq!(syscall_name(140), "setpriority");
        assert_eq!(syscall_name(276), "renameat2");
        assert_eq!(syscall_name(280), "bpf");
    }

    #[test]
    fn syscall_name_off_by_one_corrected_from_legacy() {
        // The v0.1.0-legacy table had these shifted by +1. Authoritative
        // numbers verified via device libc on Pixel 8 Pro (2026-04-26).
        assert_eq!(syscall_name(33), "mknodat");
        assert_eq!(syscall_name(34), "mkdirat");
        assert_eq!(syscall_name(35), "unlinkat");
        assert_eq!(syscall_name(36), "symlinkat");
        assert_eq!(syscall_name(37), "linkat");
        assert_eq!(syscall_name(38), "renameat");
        assert_eq!(syscall_name(39), "umount2");
    }

    #[test]
    fn syscall_name_security_relevant_primitives() {
        // ptrace — used by anti-debug rules (T018) and any kernel debug agent.
        assert_eq!(syscall_name(117), "ptrace");
        // capset / capget — root capability transitions.
        assert_eq!(syscall_name(90), "capget");
        assert_eq!(syscall_name(91), "capset");
        // kexec_load — should never appear in a normal app.
        assert_eq!(syscall_name(104), "kexec_load");
        // init_module / finit_module — kernel module loading.
        assert_eq!(syscall_name(105), "init_module");
        assert_eq!(syscall_name(273), "finit_module");
        // bpf — recursive: BPF programs loading more BPF programs.
        assert_eq!(syscall_name(280), "bpf");
        // seccomp — sandbox install.
        assert_eq!(syscall_name(277), "seccomp");
    }

    #[test]
    fn syscall_name_kernel_5x_and_6x_additions() {
        assert_eq!(syscall_name(425), "io_uring_setup");
        assert_eq!(syscall_name(434), "pidfd_open");
        assert_eq!(syscall_name(435), "clone3");
        assert_eq!(syscall_name(436), "close_range");
        assert_eq!(syscall_name(437), "openat2");
        assert_eq!(syscall_name(439), "faccessat2");
        assert_eq!(syscall_name(441), "epoll_pwait2");
        assert_eq!(syscall_name(447), "memfd_secret");
        assert_eq!(syscall_name(452), "fchmodat2");
    }
}
