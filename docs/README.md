# neutron Documentation

Aya-based eBPF syscall tracer for authorized Android security assessment.
Targets kernel 6.1+ / Pixel 8 Pro / Android 14 GKI.

## Contents

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Aya loader flow, RingBuf consumer, symbolization layer, rule-engine pipeline |
| [REFERENCE.md](REFERENCE.md) | CLI flags, JSON event schema, syscall table, BPF map reference |
| [ROADMAP.md](ROADMAP.md) | What landed in 1.0.0, V1.x backlog, V2 considerations |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build setup, how to add maps / syscalls / rules |
| [devices/pixel8pro.md](devices/pixel8pro.md) | Reference device profile + kernel-config baseline |

## Guides

| Guide | Description |
|-------|-------------|
| [guides/quickstart.md](guides/quickstart.md) | Build, deploy, capture your first trace in minutes |
| [guides/harness.md](guides/harness.md) | Extract, minimize, and safely replay captured regression testcases |
| [guides/aidl-intelligence.md](guides/aidl-intelligence.md) | Index AIDL catalogs and selectively decode complete offline testcases |
| [guides/android-content-provider.md](guides/android-content-provider.md) | Low-noise Android content-provider research workflow |
| [guides/selinux.md](guides/selinux.md) | Capture AVC decisions and explain exact observed delegation |
| [guides/bpf-tracing.md](guides/bpf-tracing.md) | Tracing concepts, profiles, filtering, stack traces |
| [guides/security-assessment.md](guides/security-assessment.md) | End-to-end assessment workflow |
| [guides/output-formats.md](guides/output-formats.md) | Text and NDJSON formats with parsing examples |
| [guides/writing-rules.md](guides/writing-rules.md) | Authoring custom YAML detector rules |
| [guides/frida-integration.md](guides/frida-integration.md) | Frida + BPF integration |

## Quick Reference

```bash
# Build BPF + userspace and adb push
./build.sh

# Default mode (rule-engine findings only)
adb shell su -c '/data/local/tmp/neutron --pid <PID>'

# Security profile + binder + stacks
adb shell su -c '/data/local/tmp/neutron \
    --pid <PID> --profile security --binder --stacks'

# Raw NDJSON capture for offline analysis
adb shell su -c '/data/local/tmp/neutron \
    --pid <PID> --raw --no-findings --json \
    --output /data/local/tmp/trace.ndjson'
```

## Requirements

| Component | Requirement |
|-----------|-------------|
| Device | Pixel 8 Pro (`husky`) or any Android 14+ GKI device with kernel 6.1+ and BTF |
| Kernel | 6.1+ aarch64 (verified: 6.1.145-android14-11) |
| Host build | rust nightly + `bpfel-unknown-none` target + `bpf-linker` + `aarch64-linux-gnu-gcc` |
| Runtime | Root shell (`adb shell su`) — KernelSU or Magisk |
| BPF caps | Effective `CAP_BPF` + `CAP_SYS_ADMIN` in the `su` domain |
