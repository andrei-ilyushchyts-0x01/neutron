# Roadmap

## Product direction

Neutron is an Android kernel-boundary and cross-service causal tracing
platform, with the following evidence path as its product center:

```text
app action
  -> Binder transaction
  -> system/native service
  -> HAL or vendor daemon
  -> open/ioctl/mmap at a device boundary
  -> denial, allocation, state change, crash, or reboot
```

The current workspace package version is `1.5.0-rc.1`. It is a release
candidate, not a stable support claim. Command maturity is defined in
[`PRODUCT.md`](../PRODUCT.md); this ledger records capability maturity.

Status meanings:

- **Complete** — implemented, covered by host tests, and part of the supported
  contract.
- **MVP** — usable vertical slice with documented evidence or platform limits.
- **Experimental** — implemented behind a narrow workflow, but still needs
  authorized-device validation and release hardening.
- **Planned** — no supported end-to-end implementation yet.

## Capability ledger

| Direction | Status | Implemented now | Remaining boundary |
|---|---|---|---|
| Dynamic Binder follow | **MVP** | One package/UID root, global BPF programs, bounded `TRACED_PROCESSES`, Binder caller/callee stitching, depth/process caps, PID TTL, servicemanager transit cap, exact-only system_server transit, global sampling/rate limits, incomplete-branch events, and health counters. Reserved SELinux domain allow/deny flags are rejected in 1.5 because first-event BPF admission cannot enforce them. | One authorized Pixel build has evidence; broaden to a device/kernel matrix and continue exercising restart/PID-reuse edges. |
| Causal graph | **Complete** | Scenario/trace/span/parent IDs; Binder/process/syscall/ioctl/crash nodes; shared Mermaid and versioned `neutron.causal-graph/v1` JSON rendering; deterministic same-parent syscall collapse; identity/device enrichment; capture-loss and incomplete-branch warnings. | Maintain compatibility fixtures as new event types are added. |
| Android surface mapper | **MVP** | Deterministic Binder/HwBinder/VndBinder, VINTF, process, library, SELinux, device, sysfs driver/module, and causal evidence; explicit mmap/DMA resources and release lifetimes; causal-only `reachable`; semantic `surface diff` reports. | One clean Pixel snapshot exists; add authorized vendor-device coverage. Partial `munmap` intentionally remains conservative because bounded events cannot reconstruct split mappings. |
| ioctl schema generation | **Complete** | Host clang pipeline for `_IO*` macros and record layouts, data-only schema packs, selector/provenance checks, trusted runtime loading, conflict handling, and generated Rust descriptors. | Publish maintained GKI/Pixel/vendor packs; cover nested unions, flexible arrays, and driver ownership with verified source evidence. |
| Capture -> extract -> replay | **MVP** | Bounded resource capture, strict artifact validation, generated Rust ioctl replay, fixed static AArch64 build with hashed manifest, explicit physical-USB identity checks, shell-free ADB staging/execution, timeout/cleanup/recovery classification, deterministic minimization, and typed crash/reboot/timeout/nonzero/signal oracles. | Authorized-device validation and separately reviewed runners for subsystem-specific Binder/timing setup. Generic raw Binder replay is not generated. |
| Binder/AIDL intelligence | **MVP** | Exact service attribution when evidence supports it, deterministic AOSP/vendor AIDL catalog generation, method-name attribution, and a bounded offline KeyMint decoder plugin. | Broaden exact node/descriptor discovery and selective plugins. Generic version-independent Parcel decoding remains intentionally out of scope. |
| Security knowledge packs | **Experimental** | Versioned data-only pack validation, built-in subsystem packs, static preflight, bounded child trace, typed companion stimulus, artifact hash locking, bounded permission cleanup, and report generation. A dated Pixel run is clean for KeyMint/GPU/Media Codec/Bluetooth; Wi-Fi/USB/Camera are safely unsupported. | Validate across authorized devices, decide whether foreground camera coverage is needed, then make a contribution/signing governance decision before publishing a community pack registry. |
| Native code mapping | **Experimental** | Captured process maps/raw IPs, exec/mapping invalidation, bounded build-ID/load-bias aware resolution, stripped-ELF path/vaddr fallback, optional identity-checked ADB pulls, and versioned native/Ghidra JSON. | Authorized exec/mmap-churn validation and the separate Ghidra consumer/plugin. |
| SELinux-aware tracing | **MVP** | Bounded AVC ingestion from the live capture boundary, source/current domain fields, exact-vs-inferred causal attribution, secure offline explanation, and exact delegated-path evidence. Surface imports denials as non-traversable policy evidence. | Optional binary-policy indexing and rule/source attribution. Neutron must not generate allow rules or claim theoretical reachability from policy alone. |
| OTA/device differential analysis | **MVP** | `neutron.surface-diff/v1` compares services, HALs, device nodes, contexts, modules, ioctls, binaries, scenario behavior, and health while normalizing ephemeral identities. | Validate repeatable scenarios across a maintained baseline/OTA device corpus. |

## Completed P0 vertical slice

The first causal explorer slice is now implemented:

```bash
neutron trace \
  --package com.example.app \
  --follow-binder \
  --follow-depth 3 \
  --follow-max-pids 32 \
  --follow-ttl 30s \
  --json --raw \
  --output capture.ndjson

neutron graph capture.ndjson \
  --format mermaid \
  --output flow.md

neutron graph capture.ndjson \
  --collapse-syscalls \
  --format json \
  --output graph.json
```

Guardrails are evidence, not silent filtering:

- `follow_guardrail` records mark blocked or TTL-expired branches as
  incomplete;
- `capture_health.follow_policy_filtered` and
  `capture_health.follow_ttl_expired` quantify them;
- `capture_health.causal_admission_boundary_exit` records a first syscall
  exit that crossed a dynamic-admission boundary. It is a volume metric, not
  data loss; ordinary correlation misses still degrade the capture;
- a missing live control socket is fatal for phased markers;
- ring loss, correlation failure, output caps, and incomplete follow branches
  propagate to graph/surface warnings;
- process-wide post-Binder evidence is `inferred`; only thread-specific Binder
  context may be `exact`.

## Release-gate evidence and remaining external gates

### Completed execution evidence (one authorized Pixel build, 2026-07-11)

- The Android companion passed `testDebugUnitTest` and `assembleDebug` on the
  host with JDK 17, Android SDK platform 35, Build Tools 35.0.0, and Gradle
  8.10.2. The resulting `dev.neutron.probe` APK was installed and verified
  with `pm path` on the target.
- `neutron doctor` passed the required BPF/Binder checks, and a static
  `neutron.surface/v1` snapshot completed without collector warnings.
- All seven built-in packs exercised the no-authorization preflight. With
  explicit authorization, KeyMint, GPU, Media Codec, and Bluetooth completed
  with clean capture health; Wi-Fi and Camera returned safe unsupported
  outcomes with clean health; USB returned `unsupported` before stimulus when
  its typed-device preflight found no eligible USB device.

The exact identity, artifact paths, health counters, and status caveats are in
[the Pixel 8 Pro device profile](devices/pixel8pro.md#authorized-device-release-evidence-2026-07-11).
This closes the previously missing host/companion/one-device execution work;
it does not promote every pack or every device line to release-validated.

### 1. Device matrix and clean scenario evidence

1. If camera coverage beyond the safe broadcast-only `unsupported` result is
   required, add an authorized foreground stimulus rather than bypassing
   CameraService's idle-UID restriction.
2. Repeat clean KeyMint/GPU-style causal chains with matched start/end markers
   on every supported device/kernel line.
3. Exercise max depth, max PID, TTL, servicemanager, and system_server
   policies; verify domain allow/deny flags fail closed; retain an artifact for
   every deliberately truncated branch.
4. Measure ring loss and event volume with and without follow policies, then
   validate PID reuse, package UID propagation, process exit, and scenario
   restart behavior.

Exit criterion: a reproducible sanitized fixture and an operator checklist for
each supported device line. Device execution remains an explicit manual step
because it can crash or reboot the target.

### 2. Maintained device and OTA corpus

Publish reproducible AOSP/vendor AIDL catalogs and tested GKI/Pixel ioctl
schema packs only with pinned source revisions and device evidence. Add
selective camera/media/GPU decoders or replay adapters only when captures
contain every required resource; incomplete Parcel or pointer data must remain
blocked.

`surface diff` still needs a maintained baseline/OTA corpus: collect the same
sanitized scenario before and after a real update, retain both snapshots and
their capture health, and review normalized deltas. One device snapshot cannot
validate OTA-differential behavior.

### 3. External consumers and governance

The neutral `neutron.ghidra-bookmarks/v1` output is ready for a separate
Ghidra importer, but that importer and real rebasing validation remain a
separate deliverable. A public research-pack registry still needs maintainer
policy, signing/key-rotation rules, and review ownership. Those governance
decisions cannot be completed by local tests or hidden in-process plugins.

## Conditional ecosystem split

Split binaries only when independent release cadence or dependency weight
justifies it:

```text
neutron
  capture / causal / binder / syscall / ioctl / selinux / surface / graph

neutron-index
  aidl-index / ioctl-gen / kernel-index / vendor-symbols / schema-packs

neutron-lab
  extract / replay / minimize / oracle / harness-gen / device recovery

neutron-ghidra
  runtime import / rebasing / bookmarks / callsite annotations
```

Before such a split, extract a shared `neutron-schema` crate for event, graph,
surface, AIDL, ioctl, testcase, and health contracts. Today the packed kernel
ABI belongs to `neutron-common`, while versioned host schemas remain in their
feature modules; external tools should consume the JSON schemas rather than
copy private Rust structs. This is an architectural trigger, not unfinished
functionality in the current single binary.

## Deliberate non-goals

- No generic Binder Parcel decoder. Prefer exact interface/method attribution
  and selective, resource-complete plugins.
- No built-in mutation engine. Generate or export reviewed harnesses for
  libFuzzer, AFL++, honggfuzz, or a custom runner.
- No Frida replacement. Neutron owns kernel/Binder/HAL evidence; Java-only and
  purely userspace decisions require other instrumentation.
- No exploit primitives, automatic privilege changes, network ADB replay, or
  unbounded device loops.
- No claim that static SELinux/VINTF/manifest topology proves runtime
  reachability.

## Platform backlog

- Adopt `bpf_d_path` opportunistically when supported Android kernels enable
  BPF LSM.
- Add ART method-resolved JIT symbols only behind versioned ART adapters.
- Add OOM-kill attribution and BTF-backed exit signal recovery.
- Consider bpffs pinning only when a concrete multi-process consumer requires
  persistent shared maps.

## Out of scope

- Tracing production devices without the required authorization and root/BPF
  access.
- Non-Android targets.
- Defeating a specific anti-tamper product.
- Automatically turning observed behavior into an exploit.
