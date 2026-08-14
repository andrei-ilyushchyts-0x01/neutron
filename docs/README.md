# neutron Documentation

Evidence-grade Android boundary mapping and bounded causal tracing for
authorized security assessment. Support claims are limited to the exact device,
build, and capture rows in [PRODUCT.md](../PRODUCT.md); host analysis commands
also operate on saved captures.

## Contents

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Aya loader flow, RingBuf consumer, symbolization layer, rule-engine pipeline |
| [REFERENCE.md](REFERENCE.md) | CLI flags, JSON event schema, syscall table, BPF map reference |
| [ROADMAP.md](ROADMAP.md) | Capability status, completed roadmap slices, external gates, and non-goals |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build setup, how to add maps / syscalls / rules |
| [devices/pixel8pro.md](devices/pixel8pro.md) | Reference device profile + kernel-config baseline |

## Guides

| Guide | Description |
|-------|-------------|
| [guides/quickstart.md](guides/quickstart.md) | Build, deploy, capture your first trace in minutes |
| [guides/harness.md](guides/harness.md) | Extract, minimize, and safely replay captured regression testcases |
| [guides/aidl-intelligence.md](guides/aidl-intelligence.md) | Index AIDL catalogs and selectively decode complete offline testcases |
| [guides/native-mapping.md](guides/native-mapping.md) | **Deprecated:** retained-through-1.x native mapping compatibility workflow |
| [guides/research-packs.md](guides/research-packs.md) | **Deprecated:** retained-through-1.x research-pack compatibility workflow |
| [guides/android-content-provider.md](guides/android-content-provider.md) | Low-noise Android content-provider research workflow |
| [guides/selinux.md](guides/selinux.md) | Capture AVC decisions and explain exact observed delegation |
| [guides/bpf-tracing.md](guides/bpf-tracing.md) | Tracing concepts, profiles, filtering, stack traces |
| [guides/security-assessment.md](guides/security-assessment.md) | End-to-end assessment workflow |
| [guides/output-formats.md](guides/output-formats.md) | Text and NDJSON formats with parsing examples |
| [guides/writing-rules.md](guides/writing-rules.md) | Authoring custom YAML detector rules |

## Quick Reference

```bash
# Select one physical device; build.sh refuses an implicit/default device.
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")

# Build BPF + userspace and deploy to that device.
./build.sh

# Use private run directories for authorized evidence.
NEUTRON=/data/local/share/neutron/neutron-agent
SURFACE_RUN=/data/local/share/neutron/runs/quick-surface
TRACE_RUN=/data/local/share/neutron/runs/quick-trace

# Map exact service/HAL targets, then trace one bounded package scenario.
"${ADB[@]}" shell "su -c '${NEUTRON} surface coverage \
    --targets /data/local/share/neutron/targets.txt --minimal \
    --json /data/local/share/neutron/coverage.json \
    --tsv /data/local/share/neutron/coverage.tsv --run-dir ${SURFACE_RUN}'"
"${ADB[@]}" shell "su -c 'timeout -s INT 30 ${NEUTRON} trace \
    --match-package com.example.app --json --raw \
    --attacker-capability not_tested --run-dir ${TRACE_RUN}'"

# Retrieve the fixed bundle members as described in the quickstart, then:
./neutron evidence verify quick-surface
./neutron evidence verify quick-trace
./neutron report quick-trace/capture.ndjson > report.md
```

See [guides/quickstart.md](guides/quickstart.md) for the bounded, allowlisted
bundle-transfer commands.

## Requirements

| Component | Requirement |
|-----------|-------------|
| Device | Pixel 8 Pro (`husky`) on a validated support-matrix build; other GKI devices are experimental |
| Kernel | 6.1+ aarch64 (verified: 6.1.145-android14-11) |
| Host build | rust nightly + `bpfel-unknown-none` target + `bpf-linker` + `aarch64-linux-gnu-gcc` |
| Runtime | Root shell (`adb -s SERIAL shell su`) — KernelSU or Magisk |
| BPF caps | Effective `CAP_BPF` + `CAP_SYS_ADMIN` in the `su` domain |
