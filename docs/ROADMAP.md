# Roadmap

## Product direction

Neutron is evolving from a flat Android syscall tracer into an Android
kernel-boundary and cross-service causal tracing platform:

```text
app action
  -> Binder transaction
  -> system/native service
  -> HAL or vendor daemon
  -> open/ioctl/mmap at a device boundary
  -> denial, allocation, state change, crash, or reboot
```

The current workspace is version `1.4.0`. Version numbers below describe
capability maturity, not a promise that every workspace feature has shipped in
a public release.

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
| Dynamic Binder follow | **MVP** | One package/UID root, global BPF programs, bounded `TRACED_PROCESSES`, Binder caller/callee stitching, depth/process caps, PID TTL, SELinux allow/deny domains, servicemanager transit cap, exact-only system_server transit, incomplete-branch events and health counters. | Validate on the supported Pixel matrix; add per-branch rate budgets and stronger kernel-side admission before a denied callee can run. |
| Causal graph | **MVP** | Scenario/trace/span/parent IDs, Binder/process/syscall/ioctl/crash nodes, Mermaid output, callee identity enrichment, device paths, capture-loss and incomplete-branch warnings. | Add stable JSON graph export, branch collapse policies, and explicit graph schema versioning. |
| Android surface mapper | **MVP** | Deterministic Binder/HwBinder/VndBinder, VINTF, process, library, SELinux, device, sysfs driver/module, and observed Binder/ioctl/AVC evidence. `reachable` reports capture health separately from identity confidence and never treats a denial as successful reachability. | Import open/mmap/DMA/crash relations; improve vendor sysfs coverage; add snapshot-to-snapshot semantic diff. |
| ioctl schema generation | **Complete** | Host clang pipeline for `_IO*` macros and record layouts, data-only schema packs, selector/provenance checks, trusted runtime loading, conflict handling, and generated Rust descriptors. | Publish maintained GKI/Pixel/vendor packs; cover nested unions, flexible arrays, and driver ownership with verified source evidence. |
| Capture -> extract -> replay | **MVP** | Bounded resource capture, strict artifact validation, generated Rust ioctl replay, explicit physical-USB identity checks, shell-free ADB staging/execution, remote timeout/cleanup, recovery classification, deterministic byte minimization. Metadata minimization runs only when a custom runner declares the relevant capability. | Build/deploy automation for the generated aarch64 binary; typed adapters that actually replay causal steps, Binder transactions, and delays; more crash oracles. |
| Binder/AIDL intelligence | **MVP** | Exact service attribution when evidence supports it, deterministic AOSP/vendor AIDL catalog generation, method-name attribution, and a bounded offline KeyMint decoder plugin. | Broaden exact node/descriptor discovery and selective plugins. Generic version-independent Parcel decoding remains intentionally out of scope. |
| Security knowledge packs | **Experimental** | Data-only pack validation, built-in subsystem packs, static preflight, bounded child trace, typed companion stimulus, artifact locking, and report generation are present in the workspace. | Complete authorized-device validation, stabilize the pack schema, and define contribution/signing/versioning policy before calling this a public pack ecosystem. |
| Native code mapping | **Experimental** | Captured process maps/raw IPs, build-ID/load-bias aware offline resolution, optional identity-checked ADB artifact pulls, and neutral Ghidra bookmark JSON are present in the workspace. | Validate capture invalidation across exec/mmap churn on device, stabilize schemas, and ship the separate Ghidra importer. |
| SELinux-aware tracing | **MVP** | Bounded AVC ingestion from the live capture boundary, source/current domain fields, exact-vs-inferred causal attribution, secure offline explanation, and exact delegated-path evidence. Surface imports denials as non-traversable policy evidence. | Optional binary-policy indexing and rule/source attribution. Neutron must not generate allow rules or claim theoretical reachability from policy alone. |
| OTA/device differential analysis | **Planned** | Generic capture aggregation diff and deterministic surface snapshots exist separately. | Add a schema-aware `surface diff`/`diff-device` command for services, HALs, device nodes, contexts, modules, ioctls, binaries, and scenario behavior. |

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

## Next milestones

### P0.5 — authorized-device evidence gate

No new feature should outrun validation of the causal core. Complete this gate
before broadening packs or decoders:

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

### P1 — complete the research loop

1. **Surface evidence completeness**
   - import open/openat, mmap/munmap, DMA allocation, process exit, and crash
     relations;
   - keep attempted/denied/successful relations distinct;
   - add schema-aware snapshot diff with confidence and capture-health deltas.

2. **AIDL and ioctl knowledge production**
   - generate reproducible AOSP/vendor AIDL catalogs in CI;
   - publish tested GKI and Pixel schema packs;
   - add selective camera/media/GPU decoder plugins only where complete
     captured resources make decoding sound.

3. **Native mapping stabilization**
   - finish exec/mmap generation tests and stripped-vendor fallbacks;
   - version the native-map and bookmark schemas;
   - keep the actual Ghidra plugin in a separate `neutron-ghidra` project.

4. **Harness honesty and usability**
   - add a reviewed aarch64 build/deploy command;
   - define typed runner adapters for every metadata capability;
   - never minimize a field that the selected runner does not consume.

### P2 — ecosystem split

Split binaries only after their schemas are stable:

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

Before that split, extract a shared `neutron-schema` crate for event, graph,
surface, AIDL, ioctl, testcase, and health contracts. Today the packed kernel
ABI belongs to `neutron-common`, while host schemas remain in their feature
modules; external tools should not copy those structs ad hoc.

P2 also includes signed/versioned research packs and scenario-based OTA
comparison across a maintained device corpus.

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
