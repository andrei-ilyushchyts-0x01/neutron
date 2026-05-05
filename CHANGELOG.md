# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-05-05

Two-sprint additive release. Wire format is unchanged (`SyscallEvent` is
still 257 bytes); JSON schema gains four new event types and several
new finding fields; rule pack grows from 22 to 26 detectors.

### Sprint 1 — HAL / binder tracing infrastructure

- **Schema cleanup.** Every NDJSON line carries `"type"` (`"syscall"` /
  `"binder"`); syscalls add `"phase":"enter"|"exit"`. Exit events add
  `"ok":bool` and `"errno":N` (when `ret < 0`). A monotonic
  per-session `"event_id":u64` correlation token is stamped on every
  emitted line. ioctl events get `"data_phase":"enter"|"exit"`.
- **Post-exit ioctl decoder registry.** The BPF programs now re-read
  the user buffer on `sys_exit` for whitelisted ioctl families
  (`_IOC_DIR ∈ {R, RW}` and `_IOC_TYPE ∈ {dma_heap, binder/dma_buf,
  ashmem}`). Userspace decodes known commands into typed nested JSON
  objects: `ioctl_family`, `ioctl_name`, `dma_heap` (with `len`,
  `returned_fd`, `fd_flags`, `heap_flags`).
- **FD-graph poller.** A dedicated thread polls
  `/proc/<pid>/fd` and `/proc/<pid>/limits` for in-scope PIDs and emits
  `type:"fd_snapshot"` events with `fd_count`, `fd_rlimit`,
  `fd_pct_of_rlimit`, `high_water_mark`, `growth_rate_per_sec`, and
  `top_paths`. Scope policies: `traced` / `active` (default) /
  `uid` (reserved) / `all`. Configurable interval (default `1s`).
- **`R001_fd_table_exhaustion`** — fires when `fd_pct_of_rlimit > 90`
  on any `fd_snapshot`. New `Category::ResourceExhaustion`.
- **`R002_dma_heap_allocation_burst`** — fires after 50
  `DMA_HEAP_IOCTL_ALLOC` calls within a 5-second window per process.
- **New rule predicates:** `fd_snapshot`, `fd_count_gt`,
  `fd_count_pct_of_rlimit_gt`, `ioctl_family_in`, `ioctl_name_in`.
- **CLI:** `--fdgraph-pids`, `--fdgraph-interval`,
  `--fdgraph-thresholds`, `--fdgraph-top-paths-n`.
- **`xtask demo-hal`** host fixture: synthesised `SyscallEvent`s
  pipe through the formatter and diff against
  `examples/expected/dma-heap.ndjson`.

### Sprint 2 — crash + binder causality + host post-processor

- **Three crash sources** feed a unified `type:"process_exit"` event:
  the `sched/sched_process_exit` BPF tracepoint, a logcat tail (Java
  `FATAL EXCEPTION` / native debuggerd / ANR), and a
  `/data/tombstones/` watcher. Per-process aggregation in the rule
  engine collapses the typical fan-out (one SIGSEGV → three events
  → one finding).
- **`crash_context` lookback ring buffer.** Every emitted JSON line is
  pushed into a per-PID bounded ring (default 100 lines × 200 PIDs).
  On `process_exit` the buffer is dumped into the `crash_context`
  array on the emitted line, making each crash record self-contained
  evidence. CLI: `--lookback-events`, `--tombstone-dir`, `--no-logcat`.
- **`R003_process_crash`** — severity `critical`, fires on fatal POSIX
  signals (SEGV / ABRT / BUS / ILL / FPE / SYS). New
  `Category::Crash`.
- **Binder causality.** A new `binder/binder_transaction_received`
  tracepoint pairs with the existing `binder_transaction` by
  `debug_id` (carried in `ptr_hint`, no wire bump). The userspace
  correlator emits synthesised `type:"binder_call"` events with
  `caller_pid`, `callee_pid`, `code`, `flags`, `latency_us`, and a
  lifecycle `status` (`completed` / `callee_crashed` / `unmatched`).
  When a callee crashes, in-flight transactions are flushed with
  `status:"callee_crashed"`. CLI: `--binder-inflight` (default 1024).
- **`R004_binder_callee_crash`** — severity `high`, fires when a
  callee crashed mid-transaction.
- **New rule predicates:** `process_exit`, `exit_signal_in`,
  `exit_classification_in`, `exit_source_in`, `binder_call`,
  `binder_status_in`, `binder_code_in`.
- **`neutron window` host-side subcommand.** Cuts NDJSON event windows
  around an anchor (`finding:RULE_ID`, `crash`, `pid:N`,
  `event_id:N`, `comm:SUBSTRING`, `binder_call:STATUS`) with either
  time-based (`--before 5s --after 1s` / `--around 2s`) or event-count
  (`--before-events 100 --after-events 50` / `--around-events 100`)
  windows. Output is NDJSON in original order, deduplicated; or
  `--summary` for a one-line-per-window roll-up. Reads `-` from stdin.
- **Finding aggregates + raw_window.** Findings now carry an optional
  `aggregates` block (`events_per_sec`, `min_interval_ms`,
  `max_interval_ms`, `distinct_targets`, `peak_fd_count`,
  `peak_fd_pct_of_rlimit`, `distinct_callee_pids`,
  `distinct_binder_codes`) and an optional `raw_window` array of full
  NDJSON lines from contributing events (default 10, configurable via
  `--finding-raw-window`). Both are additive and omitted when empty.

### Wire format

- Three new synthetic `syscall_nr` sentinels reuse the existing
  257-byte layout (no struct bump): `-2` (`fd_snapshot`), `-3`
  (`process_exit`), `-4` (`binder_transaction_received`). `-1` remains
  the legacy binder caller sentinel.
- `ptr_hint` (previously reserved) now carries the binder `debug_id`
  on `nr=-1` and `nr=-4` events.

### Tests

- Test count: 287 → **367** across the workspace.
- New host fixtures: `xtask demo-window` (windowed NDJSON
  cut against `examples/expected/window-{capture,output}.ndjson`).

### Documentation

- New: `docs/guides/window.md`.
- Updated: `docs/REFERENCE.md` (Subcommands section, all new flags,
  all new event types), `docs/guides/output-formats.md`,
  `docs/guides/writing-rules.md`, `man/man1/neutron.1`.

### Notes for downstream consumers

- All schema additions are additive — old NDJSON parsers continue to
  work; new fields are skipped when empty.
- `Category` enum gains `ResourceExhaustion` and `Crash` variants;
  rule YAML files using exhaustive Rust matches must be updated.
- The `binder_transaction_received` tracepoint requires a kernel where
  it is upstreamed (Pixel 8 Pro at 6.1+ ships it). Attach failure is
  logged and the userspace correlator silently never matches.

## [1.0.0] — 2026-04-26

First public release. Aya-based eBPF syscall tracer for authorized
Android security assessment, targeting Pixel 8 Pro / Android 14+ on
kernel 6.1.x using Aya 0.13, BTF + CO-RE, and BPF ring buffer.

### Architecture

- **`neutron-ebpf` crate** as the production BPF source. Programs are
  Rust (`aya-ebpf`), compiled to `bpfel-unknown-none` via `bpf-linker`.
  No C in the build pipeline.
- **Aya 0.13 userspace loader** in `src/main.rs`. Aya owns ELF parsing,
  BTF + CO-RE relocation, map creation, program load, tracepoint /
  kprobe attach, and verifier log capture.
- **BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`)** as the event output
  channel. Single multi-producer ring, 1 MiB, lossless from the
  producer's perspective.
- **Modern eBPF helpers** throughout: `bpf_probe_read_user_str_bytes`
  (114), `bpf_probe_read_user_buf` (112), `bpf_probe_read_kernel_buf`
  (113).

### Rule engine

- **`neutron-rules` crate.** Consumes JSON-shaped syscall events and
  emits structured findings. Sliding-window frequency rules,
  per-process and per-target aggregation modes, YAML rule loader.
- **19 default detectors** (`T001`–`T022`) covering anti-tamper,
  root-detection, recon, memory-safety, IPC, and stack-origin patterns.
  See `docs/rules/reference.md`.
- **`stack_contains` and `stack_not_contains` MatchConditions** in the
  rule DSL.
- **Findings schema v2** with additive `behavior`,
  `interpretation[]`, `confidence`, `false_positives[]`,
  `evidence_quality`, `capture_health` fields. Rules opt in via YAML.
- **`--rules <file>`** CLI flag for custom rule packs.
- **`--raw`** CLI flag preserves the per-event output stream.
- **`--no-findings`** CLI flag disables the rule engine entirely.
- Findings text and NDJSON output formats.

### Stack symbolization

- `ProcSymbolizer` — per-PID `/proc/<pid>/maps` parsing, lazy ELF
  symbol loading via `goblin`, ART JIT region detection.
- `KernelSymbolizer` — `/proc/kallsyms` reader for kernel frames.
- Renders `<file>:<symbol>+0xN` for native ELF, `<JIT>+0xN` for ART
  JIT code cache, `<kernel_symbol>+0xN` for kernel frames, and raw
  hex when symbolization fails.
- The resolved stack is emitted as a `"stack"` field in JSON output
  **before** the rule engine runs, so `stack_contains` /
  `stack_not_contains` rules see it.

### Capture health and observability

- **`neutron doctor` subcommand.** Preflight environment check that
  validates privilege, kernel version, BTF, tracefs, bpffs, ringbuf
  support, raw_syscalls + binder tracepoints, kallsyms readability,
  SELinux mode, and architecture. Returns non-zero if any check fails.
- **`COUNTERS` BPF array map (16 reserved slots).** Increments per
  degraded path: ringbuf reserve fail, inflight insert / lookup miss,
  user + kernel stack-id failures, `EVENTS_SUBMITTED`. Userspace polls
  the map on exit and prints a **capture summary** plus a hard warning
  banner whenever any drop or degradation occurred.

### Wire format

- **`SyscallEvent` is 257 bytes**, `#[repr(C, packed)]`. Compile-time
  assertions enforce the layout in both `neutron-common` and
  `neutron-ebpf`.
- **`enter_timestamp_ns: u64`** carries the enter timestamp on exit
  events in its own slot. JSON output gains an `enter_ts_ns` field.
- **`maps_generation: u16` + 6-byte reserved padding** set up for the
  v1.1 ProcSymbolizer maps-refresh feature so the bump can land
  without a second wire revision.

### Userspace FD graph

- `src/fdgraph/` tracks `(pid, fd) → resource` so events like
  `ioctl`, `read`, `write`, `mmap`, `close`, `dup3` get enriched with
  `fd_kind` (file / device / socket / pipe / anon_inode / binder /
  ashmem / memfd / unknown) and `fd_path` in the JSON output.
- State transitions wired for `openat` / `openat2` / `close` / `dup` /
  `dup3` / `socket` / `accept` / `accept4` / `memfd_create` /
  `exit_group`.
- `lookup_or_resolve` falls back to `/proc/<pid>/fd/<fd>` readlink and
  reports miss + backfill counts in the capture summary.

### Syscall coverage

- Comprehensive aarch64 syscall table covering the full kernel 6.1+
  generic ABI: async I/O (0..4), xattr (5..16), eventfd / inotify /
  epoll family (19..22, 26..28), timerfd, mq_*, semop / shm*, ptrace
  (117), kexec, capset / capget, seccomp (277), bpf (280), io_uring
  (425..427), pidfd_open (434), clone3 (435), close_range (436),
  openat2 (437), faccessat2 (439), epoll_pwait2 (441), and the kernel
  6.x additions through cachestat / fchmodat2 / map_shadow_stack /
  futex_waitv.
- Path-syscall set: mkdirat (34), unlinkat (35), symlinkat (36) at
  the correct ABI numbers; symlinkat and statfs (43) take their path
  at `args[0]` and use the args[0] capture branch alongside execve.

### Tooling

- **`examples/demo-target.rs`** — reference workload that exercises
  every deterministically-fireable rule (T001–T015, T021, T022) plus
  the FD-graph enrichment, in 18 numbered phases. `--loop SECONDS`
  flag runs the phase set continuously for benchmarking.
- **`examples/threads-probe.rs`** — TGID-filter verification target.
  Spawns main + 3 pthread workers + 1 binder-pool-style thread, each
  opening a unique sentinel under `/data/local/tmp/`. Used to confirm
  on-device that `--pid <PID>` catches every thread of the target.
- **`cargo xtask demo`** — builds + pushes neutron, BPF object, and
  demo-target to `/data/local/tmp` and prints the on-device runbook.
- **`cargo xtask check-findings <ndjson>`** — diffs a captured trace
  against `examples/expected/findings.txt` and exits non-zero if any
  expected rule failed to fire.
- **`cargo xtask bench [SECS]`** — prints the on-device snippet that
  runs neutron under each of four profiles
  (`security_no_stacks`, `security_with_stacks`, `raw`, `binder`),
  pulls the resulting stderr captures, and parses them into one
  Markdown table row per profile (events/s, drop %, stack-failure
  rates, FD-graph miss counts).
- **`neutron-spike`** (`src/bin/spike.rs`) — low-level Aya
  load/attach diagnostic.

### Documentation

- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- `docs/ARCHITECTURE.md` — Aya loader flow, RingBuf consumer,
  symbolization layer, rule-engine pipeline.
- `docs/REFERENCE.md` — CLI flags, JSON event schema, syscall table,
  BPF map reference.
- `docs/ROADMAP.md` — V1.x backlog and V2 considerations.
- `docs/devices/pixel8pro.md` — device profile (kernel config,
  mountpoints, sysctls).
- `docs/LIMITATIONS.md` — explicit list of what neutron cannot
  observe and what it deliberately does not attempt.
- `docs/FALSE-POSITIVES.md` — per-rule known-FP scenarios.
- `docs/rules/reference.md` — rule-DSL schema and authoring guide.
- Guides under `docs/guides/`: quickstart, bpf-tracing,
  security-assessment, output-formats, writing-rules,
  frida-integration.
- `man/man1/neutron.1` — Unix man page.
- GitHub issue and PR templates; Apache-2.0 license; basic CI.

### Security

- All map names are hard-coded in `neutron-ebpf` and looked up by
  exact name in the loader; no user-controlled lookup.
- BPF object path (`--object`) is read from disk only — no execution.
- Verifier log on a failed `prog.load()` may include kernel pointer
  values; emitted only with `--verbose`.

### Notes

- `--profile security` includes `recvfrom`, which on a network-active
  app produces a high raw-event volume on the order of hundreds of
  events/s of HTTPS traffic. This is by design — the rule engine
  ignores it. Use `--no-findings --raw` only when you actually want
  the full stream; otherwise default findings mode is recommended.
- The `--pages` flag is accepted for backward compatibility but
  ignored — the kernel `RingBuf` size is fixed in the BPF object.
