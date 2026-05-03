# Pixel 8 Pro — Device Profile

This is the primary and only target device for neutron 1.0. Any Android
14+ device with kernel 6.1+, BTF, and root access should work, but the
verified baseline below is what we test against.

## Build identity

| Property | Value |
|----------|-------|
| Model | Pixel 8 Pro (`husky`) |
| Build fingerprint | `google/husky/husky:16/CP1A.260405.005/15001963:user/release-keys` |
| Build ID | `CP1A.260405.005` |
| Android version | 16 (SDK 36) |
| Security patch | 2026-04-05 |
| Root | KernelSU (`u:r:ksu:s0`) |
| Online CPUs | 9 (`0-8`) |

## Kernel

```
Linux localhost 6.1.145-android14-11-gfa1d6308d1fe-ab14691759
#1 SMP PREEMPT Fri Jan  9 16:33:46 UTC 2026 aarch64 Toybox
```

- Toolchain: Android clang 17.0.2, LLD 17.0.2, +pgo, +bolt, +lto
- ABI: GKI (Generic Kernel Image) — `android14-11`

## eBPF / tracing kernel config

```
CONFIG_BPF=y
CONFIG_BPF_EVENTS=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_KPROBES=y
CONFIG_PERF_EVENTS=y
CONFIG_CGROUP_BPF=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_TRACEPOINTS=y

# CONFIG_BPF_LSM is not set
# CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set
# CONFIG_FUNCTION_TRACER is not set
```

### Implications for neutron

- **BTF available**: `/sys/kernel/btf/vmlinux` (5.6 MB) → CO-RE enabled by default
- **JIT mandatory** (`BPF_JIT_ALWAYS_ON=y`) — interpreter is gone, all programs JIT-compile
- **No BPF LSM** → `bpf_d_path` works on tracepoints/kprobes but the LSM hook chain is unavailable. Acceptable for a syscall tracer; document the limitation.
- **No `CONFIG_FUNCTION_TRACER`** → `fentry`/`fexit` programs are NOT supported. Stick to tracepoints + kprobes.
- **Tracepoints + kprobes**: yes, both supported.

## Mountpoints

```
tracefs on /sys/kernel/tracing type tracefs (rw,seclabel,relatime,gid=3012)
bpf    on /sys/fs/bpf       type bpf    (rw,nosuid,nodev,noexec,relatime)
```

- `debugfs` is **not mounted** under `/sys/kernel/debug` (Android 14+ behavior).
  Use `/sys/kernel/tracing/...` directly — Aya's `kprobe.attach()` already handles
  this; the legacy code path that wrote to `/sys/kernel/debug/tracing/kprobe_events`
  must use `/sys/kernel/tracing/kprobe_events` instead of the legacy debugfs path.
- `bpffs` mounted at `/sys/fs/bpf` — ready for pinned programs/maps if needed.

## Sysctls (relevant)

| sysctl | Value | Note |
|--------|-------|------|
| `kernel.perf_event_paranoid` | `-1` | Permissive — no `setsysctl` workaround needed for our use case |
| `kernel.unprivileged_bpf_disabled` | _root-only readable_ | Doesn't matter — neutron runs as root |
| `kernel.kptr_restrict` | _root-only readable_ | Stack symbolization will need root anyway |

## Tooling notes

- **`bpftool` is not installed** by default on the device. The BPF feature
  inventory is read off `/proc/config.gz` plus runtime probing. For
  `bpftool feature probe`, cross-build it from the AOSP/kernel tree.
- ADB push speeds: 30 MB/s for the 20 KB BPF ELF, 492 MB/s for the 1.5 MB
  binary — deploy round-trip is sub-second.

## Helper inventory (kernel 6.1+)

| Helper | Used for |
|--------|----------|
| `bpf_probe_read_user_str_bytes` (helper 114) | NUL-terminated userspace strings |
| `bpf_probe_read_user` (helper 112) | Userspace buffers |
| `bpf_probe_read_kernel` (helper 113) | Map / kernel-side buffers |
| `RingBuf` (kernel 5.8+) | Single MPSC output ring, lossless |

**CO-RE:** Aya performs runtime BTF relocation automatically when the BPF
object contains BTF debuginfo (it does — `debug = true` in the release
profile of `neutron-ebpf`). The kernel exposes BTF at
`/sys/kernel/btf/vmlinux`; Aya reads both at load time and patches struct
field offsets. neutron's BPF programs do not currently dereference kernel
structs (all reads are from tracepoint context with stable offsets), so a
generated `vmlinux.h` is not yet needed. When kprobes or fentry programs
that read kernel structs are added, generate it via:
```bash
adb pull /sys/kernel/btf/vmlinux /tmp/vmlinux.btf
bpftool btf dump file /tmp/vmlinux.btf format c > include/vmlinux.h
```
and use `aya-tool generate` to produce Rust bindings.

## TGID filter verification

`bpf_get_current_pid_tgid()` returns `(kernel_tgid << 32) | kernel_pid`.
In neutron's BPF code (`neutron-ebpf/src/main.rs::pid_matches`) the filter
matches on the upper 32 bits — the kernel `tgid`, which is the userspace
process ID returned by `pidof <package>`. This means **all threads of the
target process** (binder pool, JIT helpers, native workers, WebView/Chromium,
SDK threads) share the same matching value and are captured by a single
`--pid <PID>` invocation.

The `examples/threads-probe.rs` binary exercises this. Build, push, and run
on a connected Pixel:

```sh
cargo build --example threads-probe --release \
    --target aarch64-unknown-linux-musl
adb push target/aarch64-unknown-linux-musl/release/examples/threads-probe \
    /data/local/tmp/

# Terminal 2 — launch the probe in the background and capture its PID.
PID=$(adb shell '/data/local/tmp/threads-probe & echo $!' | tail -1 | tr -d '\r')

# Terminal 1 — attach neutron to that PID and grep the sentinel paths.
adb shell su -c "/data/local/tmp/neutron --pid $PID --json" \
    | grep neutron-thread-
```

Expected sentinels in the captured trace:

```
neutron-thread-main          (main thread, openat fires from main TID)
neutron-thread-0             (worker-0)
neutron-thread-1             (worker-1)
neutron-thread-2             (worker-2)
neutron-thread-binder-pool   (a thread named "binder-pool")
```

If only `neutron-thread-main` appears, the BPF filter is matching the kernel
`pid` (thread ID) instead of the kernel `tgid` (process ID) — fix the
extraction in `try_sys_enter` / `try_sys_exit` / `try_binder` so the upper 32
bits drive `pid_matches`.

Local variable names in BPF have been chosen to be self-documenting:
`userspace_pid` (= kernel `tgid`) is the match key, `userspace_tid` (= kernel
`pid`) goes into `SyscallEvent.tgid` for per-thread debugging. The wire
field names (`pid`, `tgid`) are inverted relative to kernel terminology
and are not flipped without a coordinated wire-format bump.
