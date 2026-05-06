# neutron

> **Aya-based syscall tracer for authorized Android security assessment.**
> Targets kernel 6.1+ (Pixel 8 Pro / Android 14 GKI). Behavior-first observer
> using eBPF tracepoints and a rule engine that emits high-level findings —
> not a raw event firehose.

[![status: verified-v1](https://img.shields.io/badge/status-verified--v1-blue.svg)](#status)
[![kernel: 6.1+](https://img.shields.io/badge/kernel-6.1%2B_aarch64-blue.svg)](#requirements)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

> ⚠️ **Authorized testing only.** This tool is intended for security research
> on devices and applications you own or have explicit written authorization
> to test. See [SECURITY.md](SECURITY.md) for the acceptable-use policy.

## What it is

`neutron` is a behavior-first observer for Android applications. It loads a
small set of eBPF programs into the kernel via [Aya](https://aya-rs.dev/),
watches the syscalls a target process makes, and runs those events through a
**rule engine** that emits structured **findings** — "this app polled
`/proc/self/maps` every 2 seconds", "this app probed `/system/xbin/su` from a
libc-rooted call stack", "this app allocated RWX memory" — instead of dumping
multi-megabyte raw event logs.

It was built to answer one specific question: *what does a hardened Android
app actually do at runtime, when its source is obfuscated and static reverse
engineering would take days?*

`neutron` does not attach with `ptrace`, inject libraries, or modify the
target's mount namespace, so it avoids many common user-space debugger and
instrumentation checks (`TracerPid`, loaded-library scans, mount-table
inspection). It is a *low-intrusion observer* — not a stealth bypass tool.
See [Disclosure surface](#disclosure-surface) for what neutron does **not**
hide.

## Who this is for

`neutron` is for Android security researchers, reverse engineers, RASP
engineers, and mobile platform specialists who need to understand how a
protected Android application interacts with the OS at runtime. It is
**intentionally not** a general-purpose Android profiler (use Perfetto,
systrace, simpleperf, or Android Studio profiler for that), and it is
**not** a one-click vulnerability scanner.

It is also a complement to dynamic instrumentation, not a replacement: use
neutron to find *what and where*, then use Frida / Ghidra / radare2 to
inspect or modify deeper.

## What neutron can and cannot observe

neutron **can** observe, on a target Android process running under a
supported kernel:

- direct syscalls made by the target process (every thread under the same
  TGID — binder pool, JIT helpers, native workers, WebView/Chromium, SDK
  threads)
- `procfs` / `sysfs` / filesystem probes (self-inspection and cross-process)
- memory permission transitions (RWX/WX mmap, mprotect)
- selected socket activity (connect, bind, sendto, recvmsg)
- `ioctl` activity with **typed userspace decoding** for known families
  (DMA-heap allocations, binder write-read, ashmem control), including
  post-exit re-read of return-write buffers
- Binder transaction tracepoint metadata, **paired caller↔callee** by
  `debug_id` into synthesised `binder_call` events with `latency_us` and
  a lifecycle `status` (opt-in via `--binder`)
- **Process termination** observed from three independent sources — the
  `sched_process_exit` BPF tracepoint, the `logcat` tail (Java FATAL
  EXCEPTION / native debuggerd / ANR), and a `/data/tombstones/` watcher.
  Cross-correlated with binder causality to flag callee crashes
  mid-transaction
- **FD-table pressure** via a periodic `/proc/<pid>/fd` poller emitting
  `fd_snapshot` events with `fd_count`, `fd_pct_of_rlimit`, growth rate,
  and top-N path aggregation
- user + kernel stack context where available (`--stacks`)

neutron **cannot fully infer** today:

- Java / Kotlin method-level behavior (no JVMTI / instrumentation)
- full Binder Parcel contents (only tracepoint metadata + the AIDL `code`;
  serialized arguments are not decoded)
- runtime behavior that stays entirely inside userspace without making
  syscalls (pure CPU work, intra-process method calls)
- exit_code on the BPF `sched_process_exit` path — the tracepoint
  payload does not carry it; userspace logcat / tombstone sources fill
  in the signal info when available

These limitations are tracked in [docs/LIMITATIONS.md](docs/LIMITATIONS.md);
the cross-process causal-tracing roadmap lives in
[docs/ROADMAP.md](docs/ROADMAP.md).

## Status

This is the **V1 verified baseline**. It targets a single hardware/kernel
profile — Pixel 8 Pro running Android 14+ on kernel 6.1.x — and uses
Aya 0.13, BTF + CO-RE, BPF ring buffer, and modern helpers throughout.
There is no C compiler in the build pipeline.

"Verified" means: every claim in this README is backed by either a unit
test in the workspace, an integration test in `neutron-rules/tests/`, or a
documented on-device transcript in `docs/devices/pixel8pro.md`. We do
**not** claim general Android compatibility — broader device support is
deliberately deferred until the rule pack and capture-health story are
mature.

## Disclosure surface

What neutron does **not** hide:

- Presence of root (KernelSU / Magisk) on the device
- The neutron BPF programs themselves (`bpftool prog list` shows them)
- The kernel's BPF / tracing subsystem state
- Loaded BPF maps (`bpftool map list`)
- SELinux domain of the calling process
- Timing side-channels caused by BPF helper overhead
- The broader test-environment fingerprint (debug build flags, special
  device properties, test-bench network)

A target that performs full environment fingerprinting (e.g. a
hardened banking app that calls a remote attestation service) may notice
these and refuse to run. neutron is meant for authorized assessment of
applications you own or have written permission to test.

## What's new in 1.2.0

- **Predicate-based capture reduction.** New `--match-*` flags and
  `--match '<expr>'` mini-language (AND/OR/NOT/parens, `=`/`!=`/`<`/
  `<=`/`>`/`>=`/`IN`/`GLOB`) push the cheap subset
  (pid/uid/syscall/ioctl-shape/ret/latency/`arg.u32@N`) into BPF maps
  for kernel-side pre-drop, while userspace evaluates the full
  predicate exactly. Compiler is a **safe over-approximation**: any
  clause inside an `OR` or `NOT` that touches userspace-only fields
  (fd_path, comm, prot, binder, arg.u8/u16/u64) contributes no kernel
  filtering — correctness over volume reduction. State-tracking
  syscalls (open/close/dup/socket/...) bypass the predicate when fd
  fields are referenced so `FdGraph` stays consistent.
- **`--capture matched+context=<DUR>`.** Always-on userspace ring of
  recently-rejected events; on a match, flushes the previous `<DUR>`
  of context and arms a forward window for the next `<DUR>`. The
  "I don't know exactly when the bug fires" workflow.
- **`--sample <p>` and `--rate-limit <N>`.** Probabilistic and
  token-bucket volume controls; both bypass state-tracking and
  binder/process_exit sentinels so `FdGraph` and the binder
  correlator never lose pair halves.
- **`neutron summarize` + `neutron diff` host-side subcommands.**
  Streaming NDJSON aggregator (`--by syscall,fd_path,ret_class,...`)
  and a delta comparator for negative-evidence workflows ("scenario A
  vs B both ran the camera, what's different?").
- **`neutron mark <name>` + `marker:<name>` window anchor.** Append
  one `type:"marker"` NDJSON line so external scenarios bracket the
  live trace; `neutron window --anchor marker:<name>` cuts the
  bracketed window without timestamp grep'ing.
- **LWIS / GXP ioctl decoder.** `ioctl_family` now classifies
  `0x4c` ('L') as `lwis` and `0x47` / `0xee` as `gxp`.
  `LWIS_CMD_PACKET` decodes the first u32 of the arg snapshot as a
  human-readable command-packet ID name (e.g. `DEVICE_ENABLE`,
  `DMA_BUFFER_ALLOC`).
- **`--fd-snapshot-on-finding`.** Findings whose ioctl evidence
  carries a usable fd get an `fdinfo_at_event` enrichment from a
  synchronous `/proc/<pid>/fdinfo/<fd>` read at emit time.
  Catches transient fds the 1-Hz poller misses.
- **Binder service-map enrichment.** `binder_call` events now carry
  the `target_node` handle. With `--binder-services <FILE>` (a JSON
  `{callee_pid: {target_node: service_name}}` map dumped from
  `service list -p`), known pairs gain a `service` field.
- **Module-relative kernel symbols.** When `kptr_restrict` masks
  `/proc/kallsyms`, `/proc/modules` is still readable —
  kernel frames inside loaded modules render as `[<ko>]+0x<offset>`
  instead of bare hex.
- **`capture_health` JSON line on shutdown** in `--json` mode.
  Mirrors the stderr summary block in machine-readable form, with
  `degraded:bool` so consumers can gate "absence of finding is
  conclusive" on a single field.

Wire format unchanged (still 257 bytes). `FILTER_MAP` array bumps
from 2 to 16 slots; existing slot indices stay in place. See
[CHANGELOG.md](CHANGELOG.md) for the full delta.

## What's new in 1.1.0

- **Crash correlation.** Three independent sources feed a unified
  `type:"process_exit"` event: the `sched_process_exit` BPF tracepoint,
  a logcat tail (FATAL EXCEPTION / debuggerd / ANR), and a
  `/data/tombstones/` watcher. Each emitted line carries a
  `crash_context` lookback (the last N raw events neutron observed for
  the PID), making findings self-contained evidence. New rule
  `R003_process_crash` fires on fatal POSIX signals.
- **Binder causality.** A new `binder_transaction_received` tracepoint
  pairs with the existing `binder_transaction` by kernel-assigned
  `debug_id` to produce synthesised `type:"binder_call"` events with
  `caller_pid`, `callee_pid`, `code`, `latency_us`, and a lifecycle
  `status`. New rule `R004_binder_callee_crash` fires when a callee
  crashed with one of our caller's transactions in flight — the
  strongest signal that a specific AIDL method triggered a HAL crash.
- **`neutron window` host subcommand.** Cuts NDJSON event windows around
  an anchor (`finding:RULE`, `crash`, `pid:N`, `event_id:N`,
  `comm:SUBSTR`, `binder_call:STATUS`) with time-based or event-count
  bounds. See [docs/guides/window.md](docs/guides/window.md).
- **HAL-level resource observability.** A periodic FD-graph poller emits
  `type:"fd_snapshot"` events; a post-exit ioctl decoder registry
  produces typed `dma_heap` JSON nested objects. Two new rules
  (`R001_fd_table_exhaustion`, `R002_dma_heap_allocation_burst`) put
  these signals to work.
- **Finding aggregates + raw_window.** Findings carry an optional
  `aggregates` block (`events_per_sec`, peak/distinct counters per
  event kind) and an optional `raw_window` array of full NDJSON lines
  from contributing events.
- **Schema cleanup.** Every NDJSON line carries `"type"`; syscalls add
  `"phase"`, exit events add `"ok"` / `"errno"`, and a monotonic
  per-session `"event_id"` correlation token is stamped on every line.

Wire format unchanged (still 257 bytes); all schema additions are
additive. See [CHANGELOG.md](CHANGELOG.md).

## What's new in 1.0.0

- 100% Rust BPF (`neutron-ebpf` crate, no `clang -target bpf`).
- Aya 0.13 replaces ~1700 lines of hand-rolled `unsafe` (custom ELF parser,
  relocation engine, perf-buffer mmap reader, raw `bpf()` syscall wrappers).
- `RingBuf` (kernel 5.8+) instead of per-CPU `PerfEventArray` — single
  multi-producer ring with the kernel's `bpf_ringbuf_reserve` API. Drops
  occur when the ring fills up; they are counted in the `COUNTERS` BPF map
  and surfaced in the **capture summary** that prints on exit. Absence of a
  finding is only conclusive when the summary shows zero drops.
- Capture-health observability: per-cause counters (ringbuf reserve fail,
  inflight lookup miss, stack-id failures) plus a one-line warning banner
  whenever any drop or degradation occurred during capture.
- Wire format: the `args[5]` field is no longer hijacked for the enter
  timestamp on exit events. A dedicated `enter_timestamp_ns` wire field
  carries it instead, so all six syscall arguments are preserved (mmap
  offset, clone3 size, etc. now decode correctly).
- Findings schema v2: rules can declare a `behavior` slug, candidate
  `interpretation`s, baseline `confidence`, and known `false_positives`.
  Findings are framed as evidence + interpretation rather than as verdicts.
  Today four rules opt into v2 (T001, T011, T017, T019); others migrate
  incrementally.
- `neutron doctor` preflight subcommand verifies privilege, kernel version,
  BTF, tracefs, bpffs, ringbuf support, raw_syscalls + binder tracepoints,
  kallsyms, SELinux mode, and architecture before you spend time loading.
- Stack symbolization: native ELF symbols (via `goblin`), `/proc/kallsyms`
  for kernel frames, ART JIT region detection (`<JIT>+0xN`).
- Default detector pack grew from 15 to 22 rules (T001–T022 plus DexProtector
  pack `DP001`–`DP008`). Stack-aware rules cover anonymous-mapping origin
  scans and Frida thread-comm enumeration.
- Removed: ARM64 PAN workarounds, `process_vm_readv` BPF fallback, helper 45
  (`bpf_probe_read_str`), `vmlinux_4_14_aarch64.h`.

See [CHANGELOG.md](CHANGELOG.md) for the full migration notes.

## Quickstart

```bash
# 1. Build the BPF object (Rust) and the userspace loader. Pushes both to
#    /data/local/tmp/ on a connected device.
./build.sh

# 2. Find your target.
export PID=$(adb shell pidof com.example.app)

# 3. Run, get findings.
adb shell su -c "/data/local/tmp/neutron \
  --pid $PID \
  --profile security \
  --resolve-paths"
```

Default output is human-readable findings:

```
[FINDING] T001_proc_self_maps_polling root_detection MEDIUM
  rule:    Periodic /proc/self/maps inspection
  process: example.app (pid 21093)
  events:  130 over 260000.0ms, period 2033.000ms
  evidence:
    [1037686946] <- openat(/proc/self/maps) ret=79
    ...
```

For NDJSON: add `--json`. For raw per-event tracing: add `--raw`. To use a
custom ruleset: `--rules path/to/rules.yaml`. With `--stacks`, native ELF
symbols and ART JIT regions are resolved inline.

See [docs/guides/quickstart.md](docs/guides/quickstart.md) for a longer
walk-through.

### Verify your install with the demo target

A reference target binary at `examples/demo-target.rs` exercises every
deterministically-fireable detector in the default pack (T001–T015, T021,
T022) plus the FD-graph enrichment, in 18 numbered phases. To run it:

```bash
cargo xtask demo                     # builds + pushes demo-target
# then on-device, in two terminals:
adb shell su -c '/data/local/tmp/neutron --pid 0 --json' > demo-trace.ndjson
adb shell '/data/local/tmp/demo-target'
# Ctrl-C neutron when the demo prints "done", then:
cargo xtask check-findings demo-trace.ndjson
```

The expected rule list is in `examples/expected/findings.txt`. Stack-aware
rules (T016–T020) are not exercised because their golden output depends on
per-device library layout.

## Default detector pack

Twenty-six rules ship in [`neutron-rules/rules/default.yaml`](neutron-rules/rules/default.yaml),
covering the patterns that almost always show up in hardened-app assessments:

| ID    | Category             | What it catches                                           |
|-------|----------------------|-----------------------------------------------------------|
| T001  | root_detection       | Periodic `/proc/self/maps` polling                        |
| T002  | root_detection       | Mount table inspection (Magisk overlay detection)         |
| T003  | antitamper           | `/proc/self/status` (TracerPid scrape)                    |
| T004  | root_detection       | `su` binary probe                                         |
| T005  | root_detection       | Magisk artifact probe                                     |
| T006  | antitamper           | Frida artifact probe                                      |
| T007  | antitamper           | Xposed / EdXposed artifact probe                          |
| T008  | root_detection       | `Runtime.exec` of root-related binaries                   |
| T009  | antitamper           | `ptrace` syscall observed                                 |
| T010  | antitamper           | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`                |
| T011  | memory               | RWX or W^X-violating memory mapping                       |
| T012  | network_recon        | `/proc/net/tcp*` enumeration (Frida-port scan)            |
| T013  | antitamper           | SELinux enforcement state probe                           |
| T014  | antitamper           | Android property service access                           |
| T015  | recon                | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads      |
| T016  | root_detection       | `fstatat` on `su` binary with `libc` on the stack         |
| T017  | antitamper           | Syscalls from inside the ART JIT code cache               |
| T018  | antitamper           | `ptrace` resolved to `sys_ptrace` from native code        |
| T019  | recon                | `/system/lib64/*` probing excluding RenderScript / Skia   |
| T020  | antitamper           | `/proc/self/{maps,status,...}` from anonymous executable mapping |
| T021  | antitamper           | Frida thread-comm enumeration via `/proc/<pid>/task/<tid>/comm` |
| T022  | antitamper           | `bpf(2)` syscall from a non-system app process            |
| R001  | resource_exhaustion  | FD table > 90% of `RLIMIT_NOFILE` (FD-graph poller)       |
| R002  | resource_exhaustion  | DMA-heap allocation burst (50+ in 5 s)                    |
| R003  | crash                | Process killed by fatal signal (SEGV/ABRT/BUS/ILL/FPE/SYS)|
| R004  | crash                | Binder callee crashed mid-transaction                     |

A separate DexProtector RASP pack (`DP001`–`DP008`) is bundled at
`neutron-rules/rules/dexprotector-rasp.yaml`.

See [docs/guides/writing-rules.md](docs/guides/writing-rules.md) and
[docs/REFERENCE.md](docs/REFERENCE.md) for the YAML schema and the full CLI
reference.

## Architecture

```
┌────────────────────────────────────────┐               ┌──────────────────────────┐
│ neutron-ebpf (aya-ebpf, Rust)          │               │ neutron (Aya loader)     │
│ tracepoints:                           │               │ src/main.rs              │
│   raw_syscalls/sys_{enter,exit}        │               │ ┌──────────────────────┐ │
│   sched/sched_process_exit             │               │ │ Predicate eval (full)│ │
│   binder/binder_transaction            │               │ │ Capture context ring │ │
│   binder/binder_transaction_received   │  ringbuf      │ │ Sampler + rate limit │ │
│                                        │  (events  )   │ │ FD-graph + fdinfo    │ │
│ Stage 1 — BPF prefilter (Phase 1):     │──────────────▶│ │ Binder tracker       │ │
│   pid/uid/syscall/ioctl-shape/         │               │ │ Tombstone + Logcat   │ │
│   ret/latency/arg.u32@N (safe          │               │ │ Lookback ring buffer │ │
│   over-approximation; AND-only)        │               │ │ Kernel resolver      │ │
└────────────────────────────────────────┘               │ │  (kallsyms+modules)  │ │
                                                         │ └──────────┬───────────┘ │
                                                         └────────────┼─────────────┘
                                                                      │ events (JSON)
                                                                      ▼
                                                            ┌─────────────────────┐
                                                            │   neutron-rules     │
                                                            │ MatchCondition →    │
                                                            │ Finding queue +     │
                                                            │ aggregates +        │
                                                            │ raw_window +        │
                                                            │ fdinfo_at_event     │
                                                            └─────────┬───────────┘
                                                                      │ findings
                                                                      ▼
                                                                 text / NDJSON
                                                                      │
                                                                      ▼
                                                       ┌──────────────────────────────┐
                                                       │ Host-side post-processors    │
                                                       │  neutron window              │
                                                       │  neutron summarize --by …    │
                                                       │  neutron diff a b --by …     │
                                                       │  neutron mark <name>         │
                                                       └──────────────────────────────┘
```

- `neutron-ebpf/` — Aya BPF programs compiled to `bpfel-unknown-none`.
  RingBuf for output, `bpf_get_stackid` for stacks, modern user/kernel
  read helpers (112/113/114). Phase 1 added predicate-driven prefilter
  maps (`MATCH_UID_SET`, `MATCH_IOCTL_{CMD,TYPE,NR}_SET`,
  `MATCH_ARG_U32_VALS`) plus a 16-slot `FILTER_MAP` for predicate
  scalars and the `STATE_EMIT_REQUIRED` toggle.
- `src/main.rs` — userspace loader. Aya handles ELF parsing, relocation,
  map creation, program load, tracepoint attach, and BTF/CO-RE.
- `src/matcher.rs` + `src/predicate.rs` — Phase 1 capture predicate. The
  matcher is the AND-of-flags builder + evaluator; the predicate is the
  recursive-descent parser for `--match <expr>` and the safe-BPF
  lowering compiler.
- `src/capture.rs` — Phase 1c context-window ring buffer for
  `--capture matched+context=<DUR>`.
- `src/sampler.rs` — Phase 1d probability + token-bucket sampler with
  state-tracking exemption.
- `src/summarize.rs` + `src/diff.rs` — Phase 2 host-side NDJSON
  aggregator and delta comparator.
- `src/mark.rs` — Phase 5a `neutron mark` scenario-marker emitter.
- `src/fdinfo.rs` — Phase 4a synchronous `/proc/<pid>/fdinfo/<fd>`
  reader for finding enrichment.
- `src/binder_services.rs` — Phase 4b optional
  `(callee_pid, target_node) → service_name` map for `binder_call`
  enrichment.
- `src/symbolize/` — `ProcSymbolizer` (per-PID `/proc/<pid>/maps` + ELF
  symbols + ART JIT detection), `KernelSymbolizer` (`/proc/kallsyms`),
  and Phase 5b `KernelModules` (`/proc/modules` fallback when
  kallsyms is masked). The bundled `KernelResolver` chains them.
- `neutron-rules/` — declarative rule engine. Decoupled from the tracer so
  the same ruleset applies to live events or offline NDJSON captures.
- `neutron-common/` — shared `no_std` wire types (`SyscallEvent`, filter
  keys, predicate match-bits, state-tracking syscall list).

For deeper details see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Requirements

| Component | Version                                                         |
|-----------|-----------------------------------------------------------------|
| Device    | Pixel 8 Pro or any Android 14+ device with kernel 6.1+ and BTF, **rooted** |
| Kernel    | 6.1.x aarch64 GKI (verified: 6.1.145-android14-11)              |
| Root      | KernelSU or Magisk                                              |
| Host      | Rust nightly (pinned via `rust-toolchain.toml`), `bpf-linker`, `aarch64-linux-gnu-gcc`, `adb` |
| BPF caps  | `CAP_SYS_ADMIN` + `CAP_BPF` (provided by root)                  |

See [docs/devices/pixel8pro.md](docs/devices/pixel8pro.md) for the
device baseline (kernel config, mountpoints, sysctls).

## Documentation

- [man/man1/neutron.1](man/man1/neutron.1) — Unix man page (CLI reference). Preview with `man -l man/man1/neutron.1`; install with `sudo install -m 0644 man/man1/neutron.1 /usr/local/share/man/man1/ && sudo mandb`.
- [docs/guides/quickstart.md](docs/guides/quickstart.md) — first-trace tutorial
- [docs/guides/security-assessment.md](docs/guides/security-assessment.md) — assessment workflow
- [docs/guides/bpf-tracing.md](docs/guides/bpf-tracing.md) — profiles, filtering, capture, stacks
- [docs/guides/writing-rules.md](docs/guides/writing-rules.md) — author your own detectors
- [docs/guides/output-formats.md](docs/guides/output-formats.md) — text + JSON schemas
- [docs/guides/window.md](docs/guides/window.md) — host-side `neutron window` post-processor
- [docs/guides/frida-integration.md](docs/guides/frida-integration.md) — Frida + BPF workflows
- [docs/REFERENCE.md](docs/REFERENCE.md) — CLI flags, JSON schema, syscall table
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — internals
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — what neutron cannot observe and why
- [docs/FALSE-POSITIVES.md](docs/FALSE-POSITIVES.md) — known FP scenarios per default rule
- [docs/ROADMAP.md](docs/ROADMAP.md) — what's next

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md). Bug fixes, new rules, tests,
and documentation improvements are very welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
