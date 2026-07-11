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

The current workspace package version is `1.4.0`; features listed as
Unreleased in the changelog are already implemented in this workspace but are
not claimed as a published release. Status describes capability maturity, not
just code presence.

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
| Dynamic Binder follow | **MVP** | One package/UID root, global BPF programs, bounded `TRACED_PROCESSES`, Binder caller/callee stitching, depth/process caps, PID TTL, SELinux allow/deny domains, servicemanager transit cap, exact-only system_server transit, global sampling/rate limits, incomplete-branch events, and health counters. | Authorized Pixel/device-matrix validation. A denied callee can execute briefly before userspace policy removal; this is reported rather than hidden. |
| Causal graph | **Complete** | Scenario/trace/span/parent IDs; Binder/process/syscall/ioctl/crash nodes; shared Mermaid and versioned `neutron.causal-graph/v1` JSON rendering; deterministic same-parent syscall collapse; identity/device enrichment; capture-loss and incomplete-branch warnings. | Maintain compatibility fixtures as new event types are added. |
| Android surface mapper | **MVP** | Deterministic Binder/HwBinder/VndBinder, VINTF, process, library, SELinux, device, sysfs driver/module, and causal evidence; explicit mmap/DMA resources and release lifetimes; causal-only `reachable`; semantic `surface diff` reports. | Authorized vendor-device coverage. Partial `munmap` intentionally remains conservative because bounded events cannot reconstruct split mappings. |
| ioctl schema generation | **Complete** | Host clang pipeline for `_IO*` macros and record layouts, data-only schema packs, selector/provenance checks, trusted runtime loading, conflict handling, and generated Rust descriptors. | Publish maintained GKI/Pixel/vendor packs; cover nested unions, flexible arrays, and driver ownership with verified source evidence. |
| Capture -> extract -> replay | **MVP** | Bounded resource capture, strict artifact validation, generated Rust ioctl replay, fixed static AArch64 build with hashed manifest, explicit physical-USB identity checks, shell-free ADB staging/execution, timeout/cleanup/recovery classification, deterministic minimization, and typed crash/reboot/timeout/nonzero/signal oracles. | Authorized-device validation and separately reviewed runners for subsystem-specific Binder/timing setup. Generic raw Binder replay is not generated. |
| Binder/AIDL intelligence | **MVP** | Exact service attribution when evidence supports it, deterministic AOSP/vendor AIDL catalog generation, method-name attribution, and a bounded offline KeyMint decoder plugin. | Broaden exact node/descriptor discovery and selective plugins. Generic version-independent Parcel decoding remains intentionally out of scope. |
| Security knowledge packs | **Experimental** | Versioned data-only pack validation, built-in subsystem packs, static preflight, bounded child trace, typed companion stimulus, artifact hash locking, bounded permission cleanup, and report generation. | Authorized-device validation and a contribution/signing governance decision before publishing a community pack registry. |
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
- a missing live control socket is fatal for phased markers;
- ring loss, correlation failure, output caps, and incomplete follow branches
  propagate to graph/surface warnings;
- process-wide post-Binder evidence is `inferred`; only thread-specific Binder
  context may be `exact`.

## Remaining release gates

The host-side roadmap slice is implemented. The remaining gates require
authorized hardware, maintained source inputs, or a separately governed
consumer; they cannot be proven by this repository's host tests.

### 1. Authorized-device evidence

1. Run a sanitized camera and KeyMint scenario on each supported
   device/kernel build.
2. Prove app -> service -> HAL -> device-node chains with matched start/end
   markers and final `capture_health`.
3. Exercise max depth, max PID, TTL, allow/deny domain, servicemanager, and
   system_server policies and confirm every truncated branch is reported.
4. Measure ring loss and event volume with and without follow policies.
5. Validate PID reuse, package UID propagation, process exit, and scenario
   restart behavior.

Exit criterion: one reproducible, sanitized fixture plus an operator checklist
for each supported device line. Device execution remains an explicit manual
step because it can crash or reboot the target.

### 2. Maintained knowledge corpus

Publish reproducible AOSP/vendor AIDL catalogs and tested GKI/Pixel ioctl
schema packs only with pinned source revisions and device evidence. Add
selective camera/media/GPU decoders or replay adapters only when captures
contain every required resource; incomplete Parcel or pointer data must remain
blocked.

### 3. External consumers and governance

The neutral `neutron.ghidra-bookmarks/v1` output is ready for a separate
Ghidra importer. A public research-pack registry still needs maintainer policy,
signing/key-rotation rules, and review ownership. Those are separate deliverables,
not hidden in-process plugins.

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
