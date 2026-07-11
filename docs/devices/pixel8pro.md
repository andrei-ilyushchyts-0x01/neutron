# Pixel 8 Pro — Device Profile

This is the documented target profile for neutron 1.4. Any Android
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
| `RingBuf` (kernel 5.8+) | Bounded MPSC output ring; reserve failures are counted in capture health |

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

## Surface mapper smoke test (1.4.0)

The following is an operator procedure, not a claim that a particular app or
build will expose every edge. Run it on an authorized test device and replace
the example activities with deterministic probes that perform the named
operation during the 30-second window.

First verify that a static snapshot is usable:

```bash
NEUTRON=/data/local/tmp/neutron
SURFACE=/data/local/tmp/static.surface.json

adb shell "su -c '$NEUTRON surface scan --output $SURFACE'"
adb exec-out "su -c 'cat $SURFACE'" > static.surface.json
jq '{schema, neutron_version, device, health}' static.surface.json
```

`schema` must be `neutron.surface/v1`. Read `health.collectors` and
`health.warnings` before interpreting missing nodes; isolated permission or
parse failures make the snapshot `degraded`.

### KeyMint → Trusty TIPC

Run live observation in one host job and repeatedly trigger a KeyMint
operation while that job is active. The command has no external readiness
signal: static collection precedes the child trace, so a fixed sleep is only a
heuristic. This example assumes the probe performs the operation from
`.KeyMintSmokeActivity`:

```bash
KEYMINT_PACKAGE=com.example.keymintprobe
KEYMINT_SURFACE=/data/local/tmp/keymint.surface.json

adb shell "su -c '$NEUTRON surface scan --observe 30s \
  --from-package $KEYMINT_PACKAGE --output $KEYMINT_SURFACE'" &
SCAN_PID=$!
while kill -0 "$SCAN_PID" 2>/dev/null; do
  adb shell am start -W -n "$KEYMINT_PACKAGE/.KeyMintSmokeActivity"
  sleep 3
done
wait "$SCAN_PID"
adb exec-out "su -c 'cat $KEYMINT_SURFACE'" > keymint.surface.json
```

Check the expected evidence without guessing an owner from a filename:

```bash
jq -e '
  any(.services[];
    (.name | test("keymint"; "i")) and
    (.pid != null) and
    ((.selinux_domain // "") | contains("hal_keymint")) and
    ((.executable // "") | test("keymint.*trusty|trusty.*keymint"; "i")) and
    any(.libraries[]?; test("trusty"; "i")) and
    any(.observed_ioctls[]?; . == "TIPC_IOC_CONNECT"))
  and
  any(.devices[];
    .path == "/dev/trusty-ipc-dev0" and
    (.driver != null) and (.module != null))
' keymint.surface.json

jq '{surface_health:.health, captures:.captures}' keymint.surface.json
```

The service PID/process link, Trusty executable/library, `hal_keymint_*`
domain, device path, and driver/module must come from inventory/sysfs evidence.
`TIPC_IOC_CONNECT` must come from the causal capture. If capture health is
degraded, rerun with a smaller, deterministic probe before treating absence as
meaningful.

### Camera → V4L2 and DMA heap

Repeat with an app that opens the camera and queues at least one frame from its
smoke activity:

```bash
CAMERA_PACKAGE=com.example.cameraprobe
CAMERA_SURFACE=/data/local/tmp/camera.surface.json

adb shell "su -c '$NEUTRON surface scan --observe 30s \
  --from-package $CAMERA_PACKAGE --output $CAMERA_SURFACE'" &
SCAN_PID=$!
while kill -0 "$SCAN_PID" 2>/dev/null; do
  adb shell am start -W -n "$CAMERA_PACKAGE/.CameraSmokeActivity"
  sleep 3
done
wait "$SCAN_PID"
adb exec-out "su -c 'cat $CAMERA_SURFACE'" > camera.surface.json

jq -e '
  ([.devices[] |
      select(.path | startswith("/dev/dma_heap/")) | .id]) as $dma
  | ([.relations[] |
      select(.type == "binder" and .trace_id != null)] | length) >= 2
  and
  any(.relations[];
      .type == "ioctl" and .ioctl == "VIDIOC_QBUF")
  and
  any(.relations[];
      .type == "ioctl" and (.to as $to | $dma | index($to) != null))
' camera.surface.json
```

Confirm that the package query returns only the observed causal subgraph:

```bash
adb push camera.surface.json /data/local/tmp/camera.surface.json
adb shell "su -c '$NEUTRON surface reachable \
  --from-package $CAMERA_PACKAGE \
  --input /data/local/tmp/camera.surface.json \
  --output /data/local/tmp/camera.reachable.json'"
adb exec-out "su -c 'cat /data/local/tmp/camera.reachable.json'" \
  > camera.reachable.json
jq -e 'all(.relations[]; .type != "proc_fd")' camera.reachable.json
```

Successful mmap and complete DMA-heap allocation exits may also produce
`resources`. Treat `active:true` as “no matching release was observed before
capture end”; a partial `munmap` deliberately degrades health rather than
inventing split ranges.

### Baseline versus OTA snapshot

Collect the same deterministic scenario before and after an OTA, then compare
on the host:

```bash
neutron surface diff baseline.surface.json ota.surface.json \
  --output ota.surface-diff.json
jq '{schema, health, services, hals, devices, ioctls, scenarios, warnings}' \
  ota.surface-diff.json
```

The schema must be `neutron.surface-diff/v1`. Review fingerprint and collector
warnings before attributing a delta to firmware. This is an operator procedure;
the repository's host tests do not substitute for running both snapshots on
the authorized device builds being compared.

### Child-trace cleanup guard

`surface --observe` validates child exit, final capture health, and temporary
cleanup. It does not itself count BPF programs. If a cross-built `bpftool` is
available on the Pixel, add an external leak guard in an otherwise idle test:

```bash
BPFTOOL=/data/local/tmp/bpftool
adb shell "su -c '$BPFTOOL -j prog show'" > /tmp/neutron-bpf-before.json

# Run exactly one of the observe scenarios above.

adb shell "su -c '$BPFTOOL -j prog show'" > /tmp/neutron-bpf-after.json
test "$(jq length /tmp/neutron-bpf-before.json)" = \
     "$(jq length /tmp/neutron-bpf-after.json)"
```

The device does not ship `bpftool` by default. A changed total can also mean
another system component loaded/unloaded BPF during the window, so repeat on an
idle device before diagnosing a neutron leak.
