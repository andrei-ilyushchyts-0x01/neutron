# Roadmap

## Status

`v1.1.0` is the current line. It targets Pixel 8 Pro on kernel 6.1.x via
Aya 0.13, BTF + CO-RE, and BPF ring buffer. The 1.0.0 baseline (Aya
loader, RingBuf, T001-T022 detectors, stack symbolization) is preserved;
1.1.0 adds HAL-level observability, crash + binder causality, finding
aggregates, and a host-side post-processor.

## Done in 1.0.0

- 100% Rust BPF programs (`neutron-ebpf` crate); the C BPF source and the
  custom ELF parser / relocation engine are gone.
- Aya 0.13 userspace loader replaces the hand-rolled `bpf()` syscall
  wrappers, perf-buffer mmap reader, and tracepoint attach paths.
- `RingBuf` (kernel 5.8+) replaces the per-CPU `PerfEventArray`. Lossless
  from the producer side, single multi-producer ring.
- Modern eBPF helpers throughout: 112 / 113 / 114 instead of 4 / 45.
- Stack symbolization upgraded: ELF symbol resolution via `goblin`,
  `/proc/kallsyms` for kernel frames, ART JIT region tagging
  (`<JIT>+0xN`).
- Default detector pack ships 22 rules (`T001`–`T022`), with
  T016–T021 using `stack_contains` / `stack_not_contains`.
- Stack-aware rules receive the resolved `"stack"` field before the
  rule engine runs.

## Done in 1.1.0

### Sprint 1 — HAL / binder tracing infrastructure

- Schema cleanup (`type` / `phase` / `ok` / `errno` / `event_id` /
  `data_phase` on every NDJSON line).
- Post-exit ioctl decoder registry with a userspace command table
  (DMA-heap, binder, dma-buf, ashmem). The BPF programs re-read the user
  buffer on `sys_exit` for whitelisted `_IOC_DIR ∈ {R, RW}` commands.
- FD-graph metrics: a periodic `/proc/<pid>/fd` poller emits
  `type:"fd_snapshot"` events with `fd_count`, `fd_pct_of_rlimit`,
  `high_water_mark`, growth rate, and top-N path aggregation.
- Resource-exhaustion rules `R001_fd_table_exhaustion` and
  `R002_dma_heap_allocation_burst`. New `Category::ResourceExhaustion`.
- Five new rule predicates (`fd_snapshot`, `fd_count_gt`,
  `fd_count_pct_of_rlimit_gt`, `ioctl_family_in`, `ioctl_name_in`).

### Sprint 2 — crash + binder causality + post-processor

- Crash correlation with three independent sources feeding a unified
  `type:"process_exit"` event: BPF `sched_process_exit` tracepoint,
  logcat tail (FATAL EXCEPTION / debuggerd / ANR), and a
  `/data/tombstones/` watcher.
- `crash_context` lookback ring buffer (per-PID bounded, default 100
  events × 200 PIDs) dumped into each `process_exit` line.
- `R003_process_crash` for fatal POSIX signals
  (SEGV/ABRT/BUS/ILL/FPE/SYS). New `Category::Crash`.
- Binder causality: `binder/binder_transaction_received` tracepoint
  paired with caller-side `binder_transaction` by `debug_id` (carried
  in the `ptr_hint` wire field — no struct bump). Synthesised
  `type:"binder_call"` events with `caller_pid`, `callee_pid`,
  `latency_us`, and lifecycle `status`.
- `R004_binder_callee_crash` cross-correlates in-flight transactions
  with crash events to flag callee crashes mid-transaction.
- `neutron window` host-side subcommand for cutting NDJSON event
  windows around an anchor. Supports `finding:` / `crash` / `pid:` /
  `event_id:` / `comm:` / `binder_call:` anchors with time-based or
  event-count window sizing, plus a `--summary` mode.
- Finding aggregates: `events_per_sec`, min/max interval,
  distinct-target/callee-pid/binder-code counts, and `peak_fd_*` peaks
  attached to each emitted finding when applicable.
- `raw_window` array on findings: full NDJSON lines from contributing
  events, configurable via `--finding-raw-window`.
- Seven new rule predicates (`process_exit`, `exit_signal_in`,
  `exit_classification_in`, `exit_source_in`, `binder_call`,
  `binder_status_in`, `binder_code_in`).

## V1.x backlog

Things that would be nice to have without rethinking the architecture:

- **`bpf_d_path` for fd-to-path resolution**. Requires BPF LSM hooks
  (`CONFIG_BPF_LSM`), which are not enabled on the verified husky kernel.
  Track downstream GKI configs and adopt opportunistically. Until then,
  `--resolve-paths` and `/proc/<pid>/fd/<fd>` cover the common case.
- **ART method-resolved JIT symbolization**. The current code tags JIT
  regions but does not walk ART runtime structures to recover Java
  method names. Doing this requires `art::Runtime` introspection, which
  is API-version specific. Worth doing for assessment workflows where
  Frida is not an option.
- **`bpf_loop` adoption**. The verifier on 6.1.x accepts it. The existing
  unrolled comparison loops are short enough that the rewrite is mostly
  cosmetic — defer until something actually grows.
- **More detector rules**, especially for app-class-specific patterns
  (banking apps, fintech, MDM agents). Contributions welcome — see
  [guides/writing-rules.md](guides/writing-rules.md).
- **`--rules-dir` for loading multiple YAML files** at once.
- **Better latency / period statistics on aggregated findings.** Median
  and tail percentiles in addition to the current `period_ms` mean and
  the new min/max interval / events_per_sec aggregates.
- **Findings export to Markdown report** for assessment write-ups.
- **`task_struct->exit_code` BTF read** in the BPF
  `sched_process_exit` handler. Today the exit signal is filled in by
  the userspace logcat / tombstone sources only; a BTF read would let
  the BPF path emit `exit_signal` directly even on hosts where
  logcat is unavailable.
- **Binder Parcel decoding** beyond the `code` field. Requires reading
  `binder_write_read.write_buffer` bytes and unmarshalling AIDL
  parameters per service interface. Complex; punted to V2.
- **OOM-kill correlation.** The kernel `oom_kill_process` tracepoint
  can attribute SIGKILL exits to OOM rather than user kill. Useful for
  R003 to distinguish `signal_exit` flavours.

## V2 considerations

Things that would change the shape of the project:

- **kprobe-based syscall instrumentation as an alternative to
  tracepoints.** Tracepoints are the stable ABI but lose information
  (e.g. the raw syscall context after `audit_*` rewriting). Kprobes on
  `__arm64_sys_*` give per-syscall hooks with full register access, at
  the cost of stability — symbol names change between kernel versions.
  Worth exploring once we support more devices than just husky.
- **Pinning maps and programs to bpffs (`/sys/fs/bpf/...`).** The
  filesystem is already mounted on Pixel 8 Pro. Pinning would let
  multiple processes share the same `INFLIGHT` / `STACK_TRACES` maps,
  enable cross-tool integration (e.g. a separate symbolizer daemon), and
  survive the controlling process crashing. No design yet.
- **BTF-only loader**. Currently `neutron-ebpf` is built once; CO-RE
  handles minor field-offset drift. A "skinny loader" that ships only
  CO-RE relocations and pulls program text from the running kernel BTF
  could be smaller and more portable across vendor kernels.
- **Multi-PID attach with binder transaction stitching.** The 1.1.0
  binder correlator pairs caller↔callee within the traced set. A V2
  system would attach to every process the target talks to (system
  services, HAL processes) and stitch a full causal chain across
  arbitrary PID hops.

There is no fixed timeline for V2.

## Out of scope

The following will not be addressed in this project:

- Tracing on production devices without root.
- Targets outside Android.
- Defeating any specific anti-tamper SDK. The tool reports observable
  behavior; what to do with that information is the researcher's job.
