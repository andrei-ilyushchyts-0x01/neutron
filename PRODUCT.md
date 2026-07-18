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
| Pixel 8 Pro Android 17 `CP2A.260705.006` | RC-qualified 3-target minimal smoke; original 33-target acceptance pending | layout/load/attach/event/health/cleanup qualified | positive event delivery observed; health-complete positive run pending | exact depth-1 edges observed; complete positive-chain gate pending |
| Other Pixel/GKI 6.1 devices | experimental | best effort | best effort | best effort |
| Vendor devices | best effort | unverified | unverified | unverified |

The Android 17 row is capture-compatible for target-scoped ownership and the
raw-syscall path on the exact clean RC userspace/BPF pair. Its Binder row stays
PREVIEW: one bounded run proves positive transaction/received delivery and
exact correlation, but ended with one in-flight syscall; a separate complete
run contained no Binder transaction. Neither run supports negative evidence
or a claim of a health-complete positive causal chain. The original 33-target
list was not available in this release workspace, so its 3-target smoke cannot
be promoted to the earlier 33/33 claim.

Android 16 currently has no connected device in this release workspace. Its
exact-release runtime rerun remains an external release blocker, not a
host-testable completion claim. Each published support claim must retain the
matching doctor and run manifests, artifact hashes, and clean teardown audit.

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
