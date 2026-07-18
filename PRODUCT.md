# Neutron product contract

Neutron is an evidence-grade Android boundary mapper and bounded causal tracer
for rooted, authorized research devices.

**Map ownership. Trace delegation. Preserve the evidence.**

The stable product promise is deliberately narrow: identify which process,
SELinux domain, and executable owns an Android service or HAL; record bounded
Binder-to-syscall/ioctl/device handoffs; and preserve capture health and
provenance so absence is never silently promoted to unreachability.

## Intended users

- Android platform and OEM security engineers.
- Researchers investigating vendor HAL and kernel attack surfaces.
- Exploit-triage and OTA surface-regression teams.

## Command maturity

Maturity applies to the command contract, not every environment or device.
Supported device rows remain narrower than the CLI surface.

| Command | Maturity | Contract |
|---|---|---|
| `neutron trace` | PREVIEW | RC command/schema contract; runtime support remains unqualified until the release SHA passes the Android 16/17 device matrix. |
| `neutron doctor` | PREVIEW | RC compatibility workflow; it becomes stable only with signed smoke evidence for every supported device row. |
| `neutron self-info` | STABLE | Machine-readable source, toolchain, target, and default BPF ABI identity. |
| `neutron evidence` | STABLE | Run-bundle verification and explicitly attributed external evidence import. |
| `neutron window` | STABLE | Deterministic host-side capture windowing. |
| `neutron summarize` | STABLE | Deterministic host-side aggregation. |
| `neutron diff` | STABLE | Capture comparison without reachability claims. |
| `neutron report` | STABLE | Evidence-oriented Markdown reports. |
| `neutron binder-map` | PREVIEW | Binder attribution helpers; exactness depends on supplied evidence. |
| `neutron mark` | PREVIEW | Scenario markers for a live bounded capture. |
| `neutron graph` | STABLE | Versioned causal graph rendering. |
| `neutron surface` | PREVIEW | Static/live ownership mapping and target coverage; device support is matrix-bound. |
| `neutron recipes` | PREVIEW | Operator examples, not additional security claims. |
| `neutron ioctl` | EXPERIMENTAL | Lab schema generation from reviewed headers. |
| `neutron harness` | EXPERIMENTAL | Authorized physical-device replay and minimization. |
| `neutron aidl` | EXPERIMENTAL | Catalog generation and selective offline decoding. |
| `neutron research` | EXPERIMENTAL | Typed, bounded research packs requiring explicit authorization. |
| `neutron native-map` | EXPERIMENTAL | Offline native address mapping. |
| `neutron ghidra-export` | EXPERIMENTAL | Neutral bookmark export for a separate consumer. |
| `neutron selinux` | PREVIEW | Explanation of observed policy evidence; never policy synthesis. |

The legacy flag-only tracer invocation remains an alias for `neutron trace`
through the 1.5 release line.

## Support matrix

| Device/build line | Static ownership | Syscall BPF | Binder BPF | Causal follow |
|---|---|---|---|---|
| Pixel 8 Pro Android 16 documented baseline | fixture validated; device rerun required | validation required | validation required | validation required |
| Pixel 8 Pro Android 17 `CP2A.260705.006` | observed compatible; release-SHA rerun required | validation required | validation required | validation required |
| Other Pixel/GKI 6.1 devices | experimental | best effort | best effort | best effort |
| Vendor devices | best effort | unverified | unverified | unverified |

Neither Android build line is runtime-qualified for the eventual 1.5 release
SHA yet. Qualification requires a successful doctor smoke run, bounded
capture, health read, and clean teardown using the exact clean userspace/BPF
pair. Android 16 currently has no connected device in this release workspace;
that is an external release blocker, not a host-testable completion claim.

## Evidence classes

- Declared/live ownership evidence: VINTF, service managers, PID identity,
  domain, executable, and source excerpts.
- Observed causal evidence: transitions measured by Neutron during a bounded
  capture.
- Imported behavioral evidence: lookup, call, or proxy results produced by an
  external probe and explicitly attributed to that probe.

These classes must remain separate in schemas and reports.

## Non-goals

Neutron is not a vulnerability scanner, generic Binder Parcel decoder,
method-level authorization prover, static reachability solver, mutation engine,
Frida/Perfetto/VTS/syzkaller replacement, or proof of safety from a missing
event.
