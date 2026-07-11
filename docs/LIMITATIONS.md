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

When an app calls a Camera, Location, or Keystore API, the actual driver work
often happens in `system_server`, `cameraserver`, `mediaserver`, or a vendor
HAL process. A single `--pid <APP_PID>` still cannot see those other
processes.

```
app → openat(/dev/binder)
app → ioctl(BINDER_WRITE_READ, IServiceManager.getService)
app → ioctl(BINDER_WRITE_READ, ICameraService.connect)
                  │
                  ▼ (transaction reaches cameraserver via the kernel binder driver)
                  ▼
   cameraserver → ioctl(/dev/video0, ...)        ← outside an app-PID-only trace
   vendor HAL  → mmap(/dev/dma_heap/system)     ← outside an app-PID-only trace
```

Package-rooted causal tracing (1.3) can follow Binder callees within bounded
depth/process limits, and `surface scan --observe` (1.4) uses that mechanism.
It still reports only hops that were observed while the scenario was active.
Missing tracepoints, capture drops, depth/process limits, asynchronous work
without a retained parent, or activity before attach can make a real chain
incomplete. Check `capture_health` before treating an absent edge as evidence.

### 4. Driver activity by `system_server` or HAL processes on behalf of the app

Same root cause as point 3. Driver-side ioctl, read, write, mmap, and poll
events originating from a service process are not seen by an app-PID-only
capture. Use a causal package trace with Binder/service/HAL following, a
service-specific PID trace, or `surface scan --observe`. None of those modes
infers unobserved delegated work.

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

The built-in specialized decoders still ship for stable Binder, DMA-heap and
LWIS output. `neutron ioctl generate` can add device/kernel-specific scalar
coverage at runtime, but it does not remove the capture ceiling:

- generated decoding is limited to complete scalar, enum and fixed-array
  fields inside the first 124 bytes;
- pointer values are numbers only; neutron never follows them;
- unions, bitfields, nested records and flexible arrays remain opaque;
- driver ownership is exact only when a manifest or build association proves
  it; header names and locations are candidate evidence;
- packs describe ABI/data and cannot execute code or provide trace filters.

The existing runtime also provides:
- a userspace decoder registry with typed views for known commands
  (today `DMA_HEAP_IOCTL_ALLOC`; binder / dma-buf / ashmem are
  classified to `ioctl_family` only);
- BPF post-exit re-read of `data[4..128]` for whitelisted R/RW families
  (`'H'` dma_heap, `'b'` binder/dma-buf, `'w'` ashmem) so callers see
  kernel-written fields like `dma_heap_allocation_data.fd`. Userspace
  marks these events with `"data_phase":"exit"`.

Long buffers (> 124 bytes) still truncate. Generated `ioctl_fields` reports
`expected_size`, `captured_size`, and `truncated`; a larger `data[]` slot is
tracked separately.

Version 1.4 adds verified numeric-to-name mappings for Trusty TIPC and V4L2,
including `TIPC_IOC_CONNECT` and `VIDIOC_QBUF`. An unmapped command remains
`cmd=0x...`; neutron does not search device kernel sources or invent a name.

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
Activity that ran before `--pid`, `--package`, or `--root-uid` was issued
(zygote initialization, early app `onCreate`, splash logic) is not
retroactively visible. Package roots refresh matching processes once per
second after attach and can miss a process that starts and exits between
refreshes. Explicit UID roots are admitted by eBPF on their first observed
kernel event; their refresh is only for reconciliation and limit enforcement.

---

## Surface mapper limitations (1.4.0)

The `neutron.surface/v1` snapshot is an evidence index, not an Android access
policy model.

- `surface reachable` means that a matching causal capture actually observed
  a chain. It does not solve SELinux allow rules, Android manifest permissions,
  VINTF compatibility, or theoretical Binder reachability.
- Reachable output reports capture `status` separately from attribution
  `confidence`. No matching capture is `no_evidence`, not a successful empty
  result. Candidate/inferred branches remain visible and explicitly qualified.
- Static `proc_fd` relations are point-in-time state and are deliberately
  excluded from reachability traversal. Static service/process/device fields
  only enrich a node reached through a causal trace.
- Reachability accepts only capture-sourced `root_process`, `binder`,
  `served_by`, and successful `open`, `mmap`, or `ioctl` edges. Failed or
  incomplete syscalls, exits, crashes, AVC denials, and a trace ID on any other
  relation type do not make that edge reachable.
- Captured SELinux denials are attempt evidence and are never traversed as
  successful device reachability.
- Live `--observe` requires exactly one `--from-package` or `--from-uid`.
  System-wide live observation is not supported, and `--capture` cannot be
  combined with `--observe`.
- A capture without the same boot ID as the static snapshot is retained, but
  current-PID joins are only `candidate` and surface health is degraded. PID
  identity in a static snapshot includes boot ID and `/proc/<pid>/stat`
  starttime; this does not make legacy captures PID-reuse-proof.
- An imported capture without a final `capture_health` record is retained as
  degraded evidence. Live observation requires that record and fails without
  it.
- Device collection starts from discovered `/dev` character/block nodes and
  follows their `/sys/dev/{char,block}/MAJOR:MINOR` bindings. It does not dump
  all of `/sys/devices`, search kernel source, or infer a source-code owner.
  “Driver/module” means a sysfs-proven binding.
- Service PID, executable, and library attribution are left absent when
  `service list`/exact `dumpsys --pid`, `lshal -ip`, or process evidence did
  not prove them. A similar filename is not treated as proof.
- Individual unreadable `/proc`, `/sys`, service, or VINTF inputs degrade
  collector health. Missing primary `/proc` or `/dev`, child-trace failure, or
  output failure is fatal.
- Version 1.4 has no SQLite or NDJSON surface store, full sysfs dump,
  kernel-source lookup, or Surface Mermaid renderer.

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

neutron explicitly targets the documented Pixel 8 Pro / Android 16 baseline
on an Android 14 GKI 6.1.x kernel.
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
| Binder Parcel decoding | selective/future | Catalog attribution and a bounded offline KeyMint plugin exist; generic payload decoding remains out of scope |
| FD → device/socket attribution for ioctl | v1.1 | Userspace FD graph (landed) |
| FD-count rules / poller / rlimit awareness | sprint-1 PR 3 | `fd_snapshot` events + `fd_count_*` predicates |
| ioctl decoder registry | v1.1–v1.4 | Typed/verified mappings grow additively; unknown commands remain numeric |
| `--package` / `--root-uid` process discovery | v1.3 / v1.4 | Neither is retroactive. Package roots can miss sub-second processes between refreshes; explicit UID roots use first-event kernel admission. |
| Cross-process causal tracing | v1.3–v1.4 | Observed Binder following with depth/PID/TTL/domain/special-process guardrails; incomplete branches are explicit |
| Android surface mapper | v1.4 | Static inventory plus imported/live causal evidence; explicit collector health |
| `path_truncated` counter wired in BPF | v1.1 | Currently reserved in COUNTERS but not incremented |

See [docs/ROADMAP.md](ROADMAP.md) for the full multi-version plan.
