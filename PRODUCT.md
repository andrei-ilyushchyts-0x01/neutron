# Neutron product contract

Neutron is an Android observability CLI designed primarily for AI agents
working on explicitly authorized rooted devices. Agents invoke bounded commands
and consume versioned JSON/NDJSON, health, scope and provenance artifacts.

The stable product promise is deliberately narrow: identify which process,
SELinux domain, and executable owns an Android service or HAL; record bounded
Binder-to-syscall/ioctl/device handoffs; and preserve capture health and
provenance so absence is never silently promoted to unreachability.

## Intended consumers

- AI agents investigating Android service ownership and kernel observations.
- Coding and security-research agents that need verifiable tool results.
- Agent orchestrators performing bounded capture and offline evidence analysis.

Human operators authorize scope and can use the same CLI. The interface is a
command-line tool with file artifacts; no MCP server or model API is implied.

## Command maturity

Maturity applies to the command contract, not every environment or device.
Supported device rows remain narrower than the CLI surface.

| Command | Maturity | Contract |
|---|---|---|
| `neutron trace` | PREVIEW | Versioned command/schema contract; runtime claims are limited to qualified device rows and matching run evidence. |
| `neutron doctor` | PREVIEW | Versioned compatibility workflow; runtime claims require signed smoke evidence for the exact published payload and device row. |
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
| `neutron recipes` | DEPRECATED (PREVIEW) | Retained through 1.x; maintained guides are canonical. |
| `neutron ioctl` | EXPERIMENTAL | Frozen lab schema generation from reviewed headers; maintenance and hardening only. |
| `neutron harness` | EXPERIMENTAL | Frozen authorized physical-device replay and minimization workflow; maintenance and hardening only. |
| `neutron aidl` | EXPERIMENTAL | Frozen catalog generation and selective offline decoding; maintenance and hardening only. |
| `neutron research` | DEPRECATED (EXPERIMENTAL) | Retained through 1.x; compose the core workflow directly. |
| `neutron native-map` | DEPRECATED (EXPERIMENTAL) | Retained through 1.x pending a qualified external consumer. |
| `neutron ghidra-export` | DEPRECATED (EXPERIMENTAL) | Retained through 1.x pending a qualified external consumer. |
| `neutron selinux` | PREVIEW | Explanation of observed policy evidence; never policy synthesis. |

The legacy flag-only tracer invocation remains an alias for `neutron trace`
through the 1.x release line and emits a deprecation notice outside
machine-readable trace mode.

## Support matrix

| Device/build line | Static ownership | Syscall BPF | Binder BPF | Causal follow |
|---|---|---|---|---|
| Pixel 8 Pro Android 16 documented baseline | historical fixture only; 1.5 unverified | 1.5 unverified | 1.5 unverified | 1.5 unverified |
| Pixel 8 Pro Android 17 `CP2A.260705.006` | 3-target minimal coverage qualified; original 33-target fixture unavailable | layout/load/attach/event/health/cleanup qualified | health-complete filtered positive path qualified | exact depth-1 app-to-servicemanager/keystore2 path; no HAL handoff claim |
| Other Pixel/GKI 6.1 devices | experimental | best effort | best effort | best effort |
| Vendor devices | best effort | unverified | unverified | unverified |

The Android 17 qualification is deliberately narrow. The release evidence
records compatible tracepoint layout and ABI, successful load/attach/sentinel
delivery, readable per-CPU health, clean teardown, 3/3 exact representative
surface rows with no drift, and one health-complete filtered run with 11
submitted/userspace/matched events. That run contains completed exact depth-1
calls to servicemanager and keystore2. Its `claim_scope_complete` is false
because BPF filters were active, so it cannot support unfiltered negative
claims. It does not demonstrate stack frames, a KeyMint HAL or driver handoff,
method-level authorization, an authorization bypass, or a vulnerability. The
original 33-target list was unavailable, so 3/3 cannot be promoted to 33/33.

Android 16 has no exact-1.5 runtime validation and is not a supported 1.5
device row. This is an accepted release limitation, not a host-testable
completion claim. Each published support claim must retain matching doctor
and run manifests, artifact hashes, and a clean teardown audit.

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

## 1.6 observability contract

The current workspace uses BPF ABI 3. Capture passports, graph v3, bounded report
timelines, verified lifecycle artifacts and reviewed Binder maps are described in
[Observability](docs/guides/observability.md). Existing support rows above describe
their original payload only. The connected Pixel 8 Pro on Android 17
`CP3A.260905.009` has development-payload smoke and positive Binder/lifecycle
evidence; see [device notes](docs/devices/pixel8pro.md#october-2026-abi-3-validation).
This is not a promotion of the historical support matrix. Other firmware, HALs,
complete asynchronous causation and performance remain unqualified.
