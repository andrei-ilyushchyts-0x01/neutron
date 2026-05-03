# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
