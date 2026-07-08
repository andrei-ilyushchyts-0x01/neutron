# Limitations

This page enumerates what `neutron` **cannot** observe today, what it
deliberately does **not** attempt, and where each limitation is tracked in
the roadmap.

The intent is to set realistic expectations for security researchers,
reverse engineers, and platform specialists evaluating neutron for their
workflow.

---

## When Neutron is the wrong tool

Use a different primary tool when the question is not about rooted Android
kernel-boundary behavior:

- You cannot use root, BPF, tracefs, or a supported aarch64 Android kernel.
  Neutron is not a non-root app instrumentation framework.
- You need Java/Kotlin method decisions, UI state, business logic, crypto
  branches, or in-process anti-tamper logic that does not cross the kernel
  boundary. Use static analysis, Frida, JDWP, or app instrumentation.
- You need an attestation verdict, server-side risk score, or API response
  semantics. Neutron can show local boundary handoff, not a remote decision.
- You need full Binder Parcel arguments or AIDL return values. Neutron reports
  routing metadata, service attribution when supplied, transaction code, and
  lifecycle status; it does not decode arbitrary Parcels.
- You need broad performance profiling, scheduling analysis, frame timing, or
  power attribution. Use Perfetto, simpleperf, systrace, or Android Studio
  Profiler.
- You need production monitoring, stealth, persistence, exploit delivery, or
  automated vulnerability verdicts. Those are explicit non-goals.

Neutron is strongest when the claim can be phrased as: "during this authorized
scenario, this PID/UID/package crossed these kernel surfaces, with this capture
health." It is weak when the claim requires intent, source-level control flow,
or data that never reached the kernel.

---

## What neutron cannot fully infer today

### 1. Java / Kotlin method-level behavior

neutron observes the kernel boundary. ART method dispatch, JNI bridges,
JIT-compiled code, and intra-process method calls leave no syscall trace
unless they trigger I/O, memory-permission changes, or IPC.

For Java-side instrumentation, pair neutron with Frida (`Java.perform`),
JDWP, or static analysis (jadx, JEB).

### 2. Full Binder Parcel contents

The `binder/binder_transaction` tracepoint exposes `to_proc`, `to_thread`,
transaction `code`, `flags`, `target_node`, and `reply` — the **routing
metadata**. The 1.1.0 binder correlator additionally pairs caller↔callee
by `debug_id` to emit synthesised `type:"binder_call"` events with
`caller_pid`, `callee_pid`, `code`, `latency_us`, and lifecycle `status`.

What is still **not** exposed: the serialized `Parcel` payload (the
actual AIDL arguments and return values).

Decoding payloads in `BINDER_WRITE_READ` ioctl buffers is V2 territory
(requires per-AIDL-interface unmarshalling); until then, treat binder
events as "who talked to whom about which interface code, and how long
it took" rather than as full RPC tracing.

### 3. Complete app → system service → driver causal chains

When an app calls a Camera, Location, or Keystore API, the actual driver
work happens in `system_server`, `cameraserver`, `mediaserver`, or a
vendor HAL process — none of which share the app's PID. With a single
`--pid <APP_PID>` invocation neutron sees:

```
app → openat(/dev/binder)
app → ioctl(BINDER_WRITE_READ, IServiceManager.getService)
app → ioctl(BINDER_WRITE_READ, ICameraService.connect)
                  │
                  ▼ (transaction reaches cameraserver via the kernel binder driver)
                  ▼
   cameraserver → ioctl(/dev/video0, ...)        ← NOT captured today
   vendor HAL  → mmap(/dev/dma_heap/system)     ← NOT captured today
```

Cross-process causal tracing is the v2.0 roadmap target. In the meantime,
attach a second neutron instance to the relevant service PID manually
(`pidof system_server` etc.) — the loader supports this.

### 4. Driver activity by `system_server` or HAL processes on behalf of the app

Same root cause as point 3. Driver-side ioctl, read, write, mmap, poll
events that originate from a service process are not seen by an
app-PID-only capture.

Workaround: explicit multi-PID attach (manual today; `--package` +
`--also` automation is on the v2.0 roadmap).

### 5. Runtime behavior fully inside userspace without syscalls

Pure CPU work, in-process method calls, decryption inside an `mmap`'d
page that already exists, anti-tamper checks that read process memory via
already-resolved pointers — none of these touch the kernel and none reach
neutron.

For these cases, dynamic instrumentation (Frida) or emulation (Unicorn)
are the appropriate tools.

### 6. The full set of ioctl arguments for a given device

neutron captures `ioctl(fd, cmd, arg)`'s `cmd` (4 bytes) and the first
124 bytes of the `arg` buffer. That suffices for short binder
transactions and for most Android driver command structs, but a long
DMA-heap allocation request or a driver-specific buffer deeper than 124
bytes is truncated. The truncation is recorded in the BPF `COUNTERS` map
under `path_truncated` (slot reserved; instrumentation TODO).

1.1.0 ships:
- a userspace decoder registry with typed views for known commands
  (today `DMA_HEAP_IOCTL_ALLOC`; binder / dma-buf / ashmem are
  classified to `ioctl_family` only);
- BPF post-exit re-read of `data[4..128]` for whitelisted R/RW families
  (`'H'` dma_heap, `'b'` binder/dma-buf, `'w'` ashmem) so callers see
  kernel-written fields like `dma_heap_allocation_data.fd`. Userspace
  marks these events with `"data_phase":"exit"`.

Long buffers (> 124 bytes) still truncate; broader cmd coverage and a
larger `data[]` slot are tracked separately.

### 7. BPF-side exit_code / exit_signal on `process_exit`

The `sched/sched_process_exit` BPF tracepoint payload carries `comm`,
`pid`, and scheduling priority — but **not** `exit_code` or
`exit_signal`. Reading those from `task_struct` requires BTF and is
deferred. As a result, the BPF source of `type:"process_exit"` events
emits `exit_signal: 0` (the userspace formatter omits the field).

The userspace logcat tail and tombstone watcher fill in signal info
from their respective stream formats. On hosts where neither is
available (host development, captures from devices without
`/data/tombstones/`), `R003_process_crash` only fires if logcat is
enabled and a fatal pattern (`FATAL EXCEPTION`, native `DEBUG`) is
parsed.

Adding a `task_struct->exit_code` BTF read to the BPF handler is V1.x
backlog — see [docs/ROADMAP.md](ROADMAP.md).

### 8. Pre-attach activity

neutron captures events from the moment the BPF programs are attached.
Activity that ran before `--pid <PID>` was issued (zygote initialization,
early app onCreate, splash logic) is not retroactively visible.

For early-startup capture, use `--pid 0 --exclude-comm <noisy>` then
filter by PID userspace-side, or wait for the v1.3 `--package
--attach-new` zygote-follow mode.

---

## What neutron deliberately does NOT attempt

These are non-goals — choices, not bugs. Filing an issue asking for any of
the below will receive a "see LIMITATIONS.md" response.

### Stealth / undetectability

neutron does **not** hide:

- the presence of root (KernelSU, Magisk)
- its own BPF programs (visible to `bpftool prog list`, `bpftool map list`)
- the kernel's BPF subsystem (any sufficiently invasive target can detect
  it via `/proc/sys/kernel/unprivileged_bpf_disabled`, by scanning loaded
  programs, or by timing the BPF helper overhead)
- SELinux domain anomalies on the test bench
- timing side-channels introduced by trace-point dispatch

A determined target performing full environment fingerprinting *can*
detect that something is observing it. neutron's value is that common
debugger-detection paths (`TracerPid`, loaded-library scans, mount-table
reads) do not see it; "undetectable" is not a claim we make.

### General-purpose Android profiling

neutron is **not** a replacement for Perfetto, systrace, simpleperf,
Studio Profiler, or strace. Use those tools when you want broad
performance or resource-usage data. neutron's niche is rule-driven
behavioral findings on specific syscalls.

### Frida replacement

neutron is **not** a replacement for Frida or Ghidra. It cannot rewrite,
intercept, or hook anything. Use neutron to find *what and where*, then
use Frida / Ghidra / radare2 to inspect or modify deeper.

### General Android device support

neutron explicitly targets Pixel 8 Pro / Android 14 GKI / kernel 6.1.x.
Other devices may work — the `neutron doctor` subcommand will tell you
whether the kernel exposes everything required — but only the documented
profile is verified end-to-end.

### Proactive vulnerability discovery

neutron does **not** try to find vulnerabilities. It surfaces *behaviors*
that human researchers can interpret. Whether a behavior indicates a
vulnerability, a feature, or a false positive is up to the analyst.

---

## Roadmap pointers

| Limitation | Tracking version | Notes |
|------------|------------------|-------|
| Binder service attribution | v1.2 | Exact map/template/catalog helpers; candidate catalogs are not exact attribution |
| Binder Parcel decoding | future | Full AIDL payload decoding remains out of scope for 1.2.0 |
| FD → device/socket attribution for ioctl | v1.1 | Userspace FD graph (landed) |
| FD-count rules / poller / rlimit awareness | sprint-1 PR 3 | `fd_snapshot` events + `fd_count_*` predicates |
| ioctl decoder registry | sprint-1 PR 2 | DMA_HEAP_IOCTL_ALLOC decoded; family classification for binder / dma-buf / ashmem |
| `--package` attach + zygote-follow | v1.3 | Resolves PID via UID; auto-attaches new app processes |
| Cross-process causal tracing | v2.0 | Trace `system_server` etc.; stitch binder transactions to service-side syscalls |
| `path_truncated` counter wired in BPF | v1.1 | Currently reserved in COUNTERS but not incremented |

See [docs/ROADMAP.md](ROADMAP.md) for the full multi-version plan.
