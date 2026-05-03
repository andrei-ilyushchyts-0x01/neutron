# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — v1.0-public verification track

Pre-public-release work landing on the `core_v1` branch. Each entry
addresses a specific item from the V1 review (see plan in commit
history). Status badge moves from "stable" to "verified-v1" once every
item below ships.

### Added

- **`neutron doctor` subcommand.** Preflight environment check that
  validates privilege, kernel version, BTF, tracefs, bpffs, ringbuf
  support, raw_syscalls + binder tracepoints, kallsyms readability,
  SELinux mode, and architecture. Returns non-zero if any FAIL.
- **`COUNTERS` BPF array map (16 reserved slots).** Increments per
  degraded path: ringbuf reserve fail, inflight insert/lookup miss, user
  + kernel stack-id failures, EVENTS_SUBMITTED. Userspace polls the map
  on exit and prints a **capture summary** plus a hard warning banner
  whenever any drop or degradation occurred. Removes the misleading
  "lossless" claim from the README.
- **Wire field `enter_timestamp_ns: u64`.** Carries the enter timestamp
  on exit events in its own slot instead of clobbering `args[5]`. JSON
  output gains an `enter_ts_ns` field on exit events.
- **Wire field `maps_generation: u16` + 6-byte reserved padding.** Set
  up for the v1.1 ProcSymbolizer maps-refresh feature so that bump can
  land without a second wire revision.
- **Findings schema v2** — additive `behavior`, `interpretation[]`,
  `confidence`, `false_positives[]`, `evidence_quality`,
  `capture_health` fields on every Finding. Rules opt in by adding the
  same fields to their YAML; today T001, T011, T017, T019 use them.
- **`docs/LIMITATIONS.md`** — explicit list of what neutron cannot
  observe today (Java method-level behavior, full Binder Parcels,
  cross-process driver IO, etc.) plus what we deliberately don't
  attempt (stealth, general profiling, vulnerability discovery).
- **`docs/FALSE-POSITIVES.md`** — per-rule known-FP scenarios for
  T001/T011/T017/T019/T020/T021. Mirrors the machine-readable
  `false_positives` field in v2-schema findings.
- **`examples/threads-probe.rs`** — TGID-filter verification target.
  Spawns main + 3 pthread workers + 1 binder-pool-style thread, each
  opening a unique sentinel under `/data/local/tmp/`. Used to confirm
  on-device that `--pid <PID>` catches every thread of the target.
  See `docs/devices/pixel8pro.md` "TGID filter verification".
- **Userspace FD graph** (`src/fdgraph/`) — tracks `(pid, fd) → resource`
  so events like `ioctl`, `read`, `write`, `mmap`, `close`, `dup3` get
  enriched with `fd_kind` (file/device/socket/pipe/anon_inode/binder/
  ashmem/memfd/unknown) and `fd_path` in the JSON output. State
  transitions wired for `openat` / `openat2` / `close` / `dup` / `dup3` /
  `socket` / `accept` / `accept4` / `memfd_create` / `exit_group`.
  `lookup_or_resolve` falls back to `/proc/<pid>/fd/<fd>` readlink and
  reports miss + backfill counts in the capture summary. 25 unit tests.
- **`examples/demo-target.rs`** — reference workload that exercises
  every deterministically-fireable rule (T001–T015, T021, T022) plus
  the FD-graph enrichment, in 18 numbered phases. `--loop SECONDS`
  flag runs the phase set continuously for benchmarking.
- **`cargo xtask demo`** — builds + pushes neutron, BPF object, and
  demo-target to `/data/local/tmp` and prints the on-device runbook.
- **`cargo xtask check-findings <ndjson>`** — diffs a captured trace
  against `examples/expected/findings.txt` and exits non-zero if any
  expected rule failed to fire.
- **`cargo xtask bench [SECS]`** — prints the on-device snippet that
  runs neutron under each of four profiles
  (`security_no_stacks`, `security_with_stacks`, `raw`, `binder`),
  pulls the resulting stderr captures, and parses them via
  `bench-parse <profile> <secs>` into one Markdown table row per
  profile (events/s, drop %, stack-failure rates, FD-graph miss counts).

### Changed

- **README status badge** from `stable` to `verified-v1`. README now
  describes the project as a *V1 verified baseline for Pixel 8 Pro*
  rather than a "production line".
- **README "lossless" wording removed.** Single-ring MPSC buffer is
  documented; drops surface in the capture summary.
- **README adds three new sections:** "Who this is for", "What neutron
  can and cannot observe", "Disclosure surface" (what neutron does
  *not* hide — root, BPF programs, SELinux domain, etc.).
- **BPF wire-format size: 241 → 257 bytes.** Compile-time assertions in
  both `neutron-common` and `neutron-ebpf/src/main.rs` updated. Both
  sides bump in lockstep.
- **`SyscallEvent::pid` / `tgid` field naming clarified in docs.** The
  fields are inverted from kernel terminology (they hold userspace PID
  / userspace TID respectively). Local variables in BPF programs now
  use self-documenting names (`userspace_pid`, `userspace_tid`); the
  wire field names are kept as-is to avoid breaking external NDJSON
  consumers — flipping them is its own future wire bump.

### Fixed

- **`args[5]` no longer clobbered on exit events.** Previously the
  exit-handler hijacked the sixth syscall arg as the enter-timestamp
  carrier, which corrupted `mmap` offset, `clone3` size, and any other
  legitimate 6-arg syscall reading from offset 5. Now stored in the
  dedicated `enter_timestamp_ns` wire field.

## [1.0.0] — 2026-04-26

First production release of the V1 line. Targets Pixel 8 Pro / Android
14+ on kernel 6.1.x using Aya 0.13, BTF + CO-RE, and BPF ring buffer.
The previous kernel-4.14 / Pixel 4a reference implementation lives on
the `legacy` branch under tag `v0.1.0-legacy` and is no longer
maintained.

### Migration from `0.1.0-legacy`

If you used the legacy line, here is what you need to know:

- **New device baseline.** Pixel 4a / kernel 4.14 is no longer
  supported on `main`. Switch to a Pixel 8 Pro (or any Android 14+
  device with kernel 6.1+ and BTF). See
  [docs/devices/pixel8pro.md](docs/devices/pixel8pro.md) for the
  verified baseline.
- **No `clang` requirement.** BPF programs are 100% Rust. The build is
  `./build.sh` (or `cargo xtask build-ebpf release && cargo build`).
- **Default `--object` changed.** From `syscall_tracer.bpf.o` to
  `/data/local/tmp/neutron.bpf.elf`. Drop the flag from your invocations
  — the new default Just Works after `./build.sh` deploys.
- **`--minimal` is gone.** The legacy two-instruction load-test mode
  has been removed. Use the `neutron-spike` diagnostic binary for
  load/attach testing.
- **`--pages` is ignored.** The kernel `RingBuf` size is fixed in the
  BPF object. The flag is accepted for backward compatibility.
- **`neutron-filter` removed.** The exploratory offline ML noise filter
  has been deleted; its responsibilities are subsumed by the rule
  engine.
- **Default ruleset grew from 15 to 19 rules.** T016..T019 use
  `stack_contains` / `stack_not_contains` and require `--stacks`.
- **Stack-aware rules now actually fire.** Pre-1.0 the rule engine ran
  before stack injection, so `stack_contains` rules never matched.
  See *Fixed* below.
- **No PAN workaround needed.** Kernel 6.1 does not block in-kernel
  user-pointer reads. The `process_vm_readv` fallback in BPF is gone.
  The userspace `--resolve-paths` flag remains (`/proc/<pid>/fd/<fd>`,
  `/proc/<pid>/net/tcp*`) for closed-fd / truncated-read corner cases.

### Added

- **`neutron-ebpf` crate** as the production BPF source. Programs are
  Rust (`aya-ebpf`), compiled to `bpfel-unknown-none` via `bpf-linker`.
- **Aya 0.13 userspace loader** in `src/main.rs`. Aya owns ELF parsing,
  BTF + CO-RE relocation, map creation, program load, tracepoint /
  kprobe attach, and verifier log capture.
- **BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`)** as the event output
  channel. Single multi-producer ring, 1 MiB, lossless from the
  producer's perspective.
- **Modern eBPF helpers** throughout: `bpf_probe_read_user_str_bytes`
  (114), `bpf_probe_read_user_buf` (112), `bpf_probe_read_kernel_buf`
  (113).
- **Stack symbolization layer** in `src/symbolize/`:
  - `ProcSymbolizer` — per-PID `/proc/<pid>/maps` parsing, lazy ELF
    symbol loading via `goblin`, ART JIT region detection.
  - `KernelSymbolizer` — `/proc/kallsyms` reader for kernel frames.
  - Renders `<file>:<symbol>+0xN` for native ELF, `<JIT>+0xN` for ART
    JIT code cache, `<kernel_symbol>+0xN` for kernel frames, and raw
    hex when symbolization fails.
  - The resolved stack is emitted as a `"stack"` field in JSON
    output.
- **Seven new detector rules** that use stack-aware conditions:
  - T016 — `fstatat` on `su` paths with `libc` on stack.
  - T017 — syscalls originating from inside the ART JIT code cache.
  - T018 — `ptrace` resolved to `sys_ptrace` from native code.
  - T019 — `/system/lib64/*` probing excluding RenderScript / Skia.
  - **T020** — process introspection (`/proc/self/{maps,status,cmdline,
    mountinfo,mounts}`) from a stack frame inside an anonymous executable
    mapping. Promoted from T001/T003 because the anonymous-mapping origin
    is the actual indicator of a packed / decrypted native anti-tamper
    module.
  - **T021** — `/proc/self/task/<TID>/comm` enumeration, the canonical
    library-name-independent Frida-thread-detection pattern. Frequency:
    5+ reads in 30 s.
  - **T022** — `bpf(2)` syscall from a non-system process. A regular
    Android app should never call `bpf(2)` directly; presence indicates
    either an unusual debug build or a sophisticated anti-tamper /
    anti-rootkit native module.
- **`stack_contains` and `stack_not_contains` MatchConditions** in the
  rule DSL.
- **Comprehensive aarch64 syscall table** in `src/decode/syscalls.rs`.
  Coverage now includes the full kernel 6.1+ generic ABI: async I/O
  (0..4), xattr (5..16), eventfd / inotify / epoll family (19..22, 26..28),
  timerfd, mq_*, semop / shm*, ptrace (117), kexec, capset / capget,
  seccomp (277), bpf (280), io_uring (425..427), pidfd_open (434),
  clone3 (435), close_range (436), openat2 (437), faccessat2 (439),
  epoll_pwait2 (441), and the kernel 6.x additions through cachestat /
  fchmodat2 / map_shadow_stack / futex_waitv.
- **Off-by-one fix in the path-syscall set.** The legacy table mistakenly
  labeled aarch64 nr 35 as `mkdirat` and 36 as `unlinkat`; the actual
  ABI is mkdirat=34, unlinkat=35, symlinkat=36. The userspace decoder,
  the BPF capture set, and `is_path_syscall` are now consistent. As a
  side effect, mkdirat (34) paths now capture; symlinkat (36) and statfs
  (43) — which take their path at args[0] — moved to a separate args[0]
  capture branch alongside execve.
- **`docs/devices/pixel8pro.md`** — device profile (kernel
  config, mountpoints, sysctls).

### Changed

- **Workspace bumped to `1.0.0`.** Crate description updated to
  "Aya-based syscall tracer for authorized Android security assessment
  (Pixel 8 Pro / kernel 6.1+)."
- **Default `--object`** is `/data/local/tmp/neutron.bpf.elf` (was
  `syscall_tracer.bpf.o`).
- **`--profile security`** auto-populates `--exclude-comm` with sensible
  kernel-worker noise filters (was a no-op augmentation in 0.1.0).
- **All documentation rewritten** to describe the V1 architecture. Files
  affected: `CLAUDE.md`, `README.md`, `docs/ARCHITECTURE.md`,
  `docs/ROADMAP.md`, `docs/CONTRIBUTING.md`, `docs/REFERENCE.md`, all
  guides under `docs/guides/`.

### Removed

- **C BPF source** (`bpf/syscall_tracer.bpf.c`).
- **`neutron-filter`** (offline ML noise filter). The rule engine
  subsumes its responsibilities.
- **`include/vmlinux_4_14_aarch64.h`** and the manually maintained
  type definitions for kernel 4.14.
- **Custom ELF64 parser** (~500 lines of `unsafe`).
- **Map-FD relocation engine** including the "nibble bug" `LD_IMM64`
  patcher.
- **Per-CPU perf ring buffer reader** (mmap-based, `data_head` /
  `data_tail` bookkeeping).
- **Raw `bpf()` syscall wrappers** (`bpf_create_map`, `bpf_prog_load`,
  manual `BpfProgLoadAttr`).
- **Manual `perf_event_open` + `PERF_EVENT_IOC_SET_BPF` attach path.**
- **`process_vm_readv` PAN fallback** in the BPF programs. (Userspace
  `/proc/<pid>/fd/<fd>` readlink and `/proc/<pid>/net/tcp*` lookups
  remain under `--resolve-paths`.)
- **Helper 45 (`bpf_probe_read_str`).** Replaced by helper 114
  (`bpf_probe_read_user_str_bytes`).
- **`--minimal` CLI flag.** Was a kernel-4.14 verifier diagnostic;
  obsolete on 6.1+.
- **`--capture-reads` content peek.** The flag still tracks fds, but
  the legacy `process_vm_readv` buffer-content readback has been
  removed. See `src/main.rs` `handle_capture_reads`.
- **`debugfs` kprobe attach path.** Aya attaches via
  `/sys/kernel/tracing/...` directly (debugfs is no longer mounted on
  Android 14+).

### Fixed

- **Stack-aware rules now receive the `"stack"` field.** Pre-1.0 the
  call to `engine.feed` happened before stack resolution and JSON
  injection, so `stack_contains` rules in custom rulesets would never
  match anything. The event-loop in `src/main.rs` was reordered so
  the resolved stack is folded into the JSON line **before** it is
  fed to the engine. This bug had no effect on 0.1.0 because no
  default rules used `stack_contains` — but it would have bitten
  anyone who shipped a custom stack-aware ruleset.

### Security

- All map names are hard-coded in `neutron-ebpf` and looked up by
  exact name in the loader; no user-controlled lookup.
- BPF object path (`--object`) is read from disk only — no execution.
- Verifier log on a failed `prog.load()` may include kernel pointer
  values; emitted only with `--verbose`.

### Notes

- `neutron-spike` (`src/bin/spike.rs`) remains as a low-level Aya
  load/attach diagnostic.
- See [docs/devices/pixel8pro.md](docs/devices/pixel8pro.md) "Helper
  inventory" for the kernel-6.1+ BPF helpers used.

## [0.1.0-legacy] — 2026-04-25

Initial public release. Reference implementation for the kernel-4.14 /
aarch64 target (Pixel 4a). Future v1 work moves to CO-RE on kernel
5.10+ (now realised as 1.0.0 on kernel 6.1+).

### Added
- **Rule engine** (`neutron-rules` crate). Replaces raw event firehose with
  structured findings. Sliding-window frequency rules, per-process and
  per-target aggregation modes, YAML rule loader.
- **15 default detectors** covering the most common anti-tamper, root-detection,
  recon, and memory-safety patterns observed in hardened Android applications.
  IDs T001 through T015. See `docs/rules/reference.md`.
- `--rules <file>` CLI flag for custom rule packs.
- `--raw` CLI flag preserves the legacy per-event output stream.
- `--no-findings` CLI flag disables the rule engine entirely.
- Findings text and NDJSON output formats.
- `neutron-rules` crate test suite (15+ unit and integration tests).
- Apache-2.0 license, `README.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue and PR templates, basic CI.

### Changed
- Project renamed from `pixel-tracer` to `neutron`. Crate names, binary names,
  and default file paths follow the new convention.
- Workspace bumped to version `0.1.0-legacy`.
- BPF object output renamed from `pixel_tracer.bpf.elf` to `neutron.bpf.elf`.
- Default tracer output is now structured findings; the previous per-event
  stream is opt-in via `--raw`.

### Removed
- Pre-publication internal notes (`TODO.md`, `TEST_RESULTS_gap_fixes.md`).
- Pre-publication research drafts containing identifiable third-party
  application data.
- Tracked build artifacts (`target/`, `*.o`, `*.elf`, `build.log`) — now in
  `.gitignore`.

### Fixed
- **T015** no longer fires on `/proc/self/...` (it duplicated T001 on the
  polling loop). Adds a new `path_not_contains` condition to the rule DSL
  and uses it to exclude `/proc/self/` and `/proc/thread-self/` from the
  cross-process rule.

### Notes
- `neutron-ebpf` (Aya BPF programs) ships as scaffolding only. The legacy C
  path in `bpf/syscall_tracer.bpf.c` remains the production loader for this
  release.
- `--profile security` includes `recvfrom`, which on a network-active app
  produces a high raw-event volume on the order of hundreds of events/s
  of HTTPS traffic. This is by design — the rule engine ignores it. Use
  `--no-findings --raw` only when you actually want the full stream;
  otherwise default findings mode is recommended.
