# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.0-rc.1] — Unreleased

- Reframed the supported core around evidence-grade Android boundary ownership
  and bounded causal tracing, with explicit STABLE/PREVIEW/EXPERIMENTAL command
  labels and a device/build support matrix.
- Added verbose source/toolchain identity, a userspace/BPF ABI and build-ID
  handshake, tracepoint-format validation, and a real syscall load/attach/event
  smoke path in versioned `doctor --json --smoke` output.
- Reworked capture health around per-CPU BPF counters, explicit read errors,
  complete/degraded/incomplete/unknown status, bounded Binder-loss accounting,
  and a versioned effective capture scope that prevents filtered or sampled
  data from supporting unqualified negative claims.
- Added target-scoped `surface coverage` collection, repeat/drift validation,
  proof-chain explanations, private content-addressed run bundles, and typed
  external behavioral-evidence import with explicit probe attribution.
- Added host and Android release payloads containing generated Bash/Zsh/Fish
  completions, man pages, both BPF variants, schemas, packs, and a
  content-identified probe APK; deployment now requires one explicit physical
  USB serial and verifies root-private candidate hashes before publication.
- Added signed-tag release automation with exact-tag tests, minisign manifests,
  GitHub build-provenance attestations, deterministic archive metadata, and a
  fixed secret-backed research-probe signing identity.
- Hardened capture/report/evidence inputs with bounded parsing, cardinality and
  file limits, non-following descriptor-relative I/O, Markdown/terminal
  escaping, and conclusive diff gates over identical pinned capture scopes.
- Added versioned `neutron.causal-graph/v1` JSON export and deterministic
  `--collapse-syscalls` grouping alongside the existing Mermaid graph.
- Added semantic `surface diff` / `surface diff-device` reports using
  `neutron.surface-diff/v1`, including service, HAL, device, module, ioctl,
  binary, SELinux, scenario, and collector-health changes.
- Added observed mmap and DMA-heap resources to `neutron.surface/v1`, with
  explicit acquisition and release relations. Partial `munmap` evidence is
  retained conservatively and degrades snapshot health.
- Added `neutron harness build` for a bounded static AArch64 replay binary,
  plus built-in crash, reboot, timeout, non-zero, and signal minimization
  oracles. Normal non-zero exits are no longer classified as crashes.
- Added bounded native symbol indexing, versioned native-map and Ghidra
  bookmark schemas, exec/mapping invalidation, and stripped-ELF fallbacks.
- Added validated data-only subsystem research packs and typed companion
  stimuli with private artifact locking and bounded permission cleanup.
- Expanded CI to verify the full host workspace, AArch64 musl build, release
  eBPF object, and Android research-probe unit tests.
- Reserved SELinux domain follow-policy flags are rejected in 1.5 because
  they cannot be enforced before first-event BPF admission.
- Added the additive `causal_admission_boundary_exit` capture-health volume
  counter, including admitted sibling-worker boundary accounting, so expected
  first exits are distinguished from ordinary correlation misses.
- Switched temporary runtime-permission inspection to `dumpsys package`, which
  supports Android 16 builds without `cmd package check-permission`.
- Fixed release-pack staging for root-owned Android directories by creating
  them as root, temporarily granting `shell` write access for `adb push`, and
  restoring root ownership afterwards.
- Fixed release provenance collection for Android tools whose version output
  is emitted on stderr, with an early completeness gate before artifact output.
- Kept machine-readable output clean over non-interactive and ADB transports;
  maturity warnings remain visible in interactive use and command help.
- Preserved the shared Binder/dma-buf ioctl magic as
  `binder_or_dma_buf` until FD evidence positively identifies Binder, instead
  of emitting contradictory concrete family labels. Dma-buf-looking path text
  alone is not treated as proof; the legacy context-free `data` view uses the
  same explicit ambiguity.
- Stopped syscall-whitelist rejects before they populate BPF `INFLIGHT` state,
  preventing long-blocking, non-emittable syscalls from falsely degrading a
  clean scenario boundary while retaining state for allowlisted exit filters.
- Fixed clean release packaging on non-x86_64 build hosts by selecting and
  validating an explicit x86_64 GNU cross-linker before host-binary and shell
  completion builds.

## [1.4.0] — 2026-07-10

- Added `neutron surface scan` and JSON query commands for deterministic
  `neutron.surface/v1` inventories of Binder/HwBinder/VndBinder services,
  VINTF HAL declarations, processes, device nodes, drivers, and modules.
- Added streaming causal-capture import. Relations retain evidence,
  `exact`/`candidate` confidence, causal attribution, and trace/scenario/span
  IDs; unknown events and additive fields remain forward-compatible.
- Added package- or UID-rooted `surface scan --observe DURATION`. It runs one
  child trace, brackets `surface-observe`, validates final capture health, and
  cleans private temporary state before returning.
- Added causal-only `surface reachable`: static `proc_fd` state can enrich an
  already-reached node but never establishes reachability. No theoretical
  SELinux, VINTF, permission, or Binder-access solver is implied.
- Added `trace --root-uid UID` for current processes and processes discovered
  by the one-second UID refresh. Very short-lived processes can finish between
  refreshes. Causal events/markers and additive capture health now carry
  `root_uid`; capture health also records boot ID and build fingerprint.
- Added verified Trusty TIPC and V4L2 ioctl labels, including
  `TIPC_IOC_CONNECT` and `VIDIOC_QBUF`. Unknown commands remain numeric
  `cmd=0x...` evidence.

## [1.3.0] — 2026-07-10

- Added explicit `trace` mode while preserving the legacy flag-only invocation.
- Added package-rooted causal Binder following with bounded depth/process maps,
  exact receiving-thread attribution, inferred process attribution, and
  causal IDs on NDJSON events.
- Added live `mark --phase start|end` scenarios over a 0600 Unix control
  socket; explicit `--output` remains append-only.
- Added `service list -p` / `lshal -ip` candidate discovery, exact Binder
  service overrides, and optional verified method maps.
- Added `neutron graph ... --format mermaid`, including legacy 1.2 fallback
  rendering and capture-health warnings.

## [1.2.0] — 2026-05-06

Additive release driven by the 2026-05-06 LWIS / GXP / Camera2 assessment.
Wire format unchanged (`SyscallEvent` still 257 bytes); the BPF
`FILTER_MAP` array grows from 2 to 16 slots (existing slots stay at
their indices). JSON schema gains two new event types (`marker`,
`capture_health`), a `target_node` field on `binder_call`, and an
optional `service` field on `binder_call`. Three new host-side
subcommands.

### Phase 1 — Predicate-based capture reduction with conservative BPF prefiltering

- **Generic capture predicates.** New `--match-pid`, `--match-uid`,
  `--match-syscall`, `--match-ioctl-cmd`, `--match-ioctl-type`,
  `--match-ioctl-nr`, `--match-ioctl-dir`, `--match-ret`,
  `--match-latency-min`, `--match-prot-rwx`, `--match-prot-wx`,
  `--match-fd`, `--match-comm`, `--match-arg-{u8,u16,u32,u64}`,
  `--match-binder-{code,flags,to_proc,to_thread,target_node,reply}`.
  All AND-conjoined. The cheap subset (pid/uid/syscall/ioctl
  shape/ret/latency/`arg.u32@N`) lowers into BPF maps so unmatched
  events drop before ringbuf reservation; the rest filters userspace
  on every surviving event.
- **`--match <expr>` mini-language.** Tiny recursive-descent parser
  for `AND` / `OR` / `NOT` / parens, `=` / `!=` / `<` / `<=` / `>`
  / `>=` / `IN` / `GLOB` over the same field vocabulary. Compiler
  produces a **safe over-approximation** for the BPF prefilter:
  top-level AND-of-atoms with BPF-evaluable fields lower into
  `MatchSpec`; anything inside an `OR` or `NOT` (or touching
  userspace-only fields) contributes no kernel-side filtering and
  evaluates strictly userspace. Mutually exclusive with the
  individual `--match-*` flags. Audit-print at startup labels each
  clause `[bpf]` or `[user]` so volume reduction is visible.
- **Enter/exit decoupling.** BPF `try_sys_enter` now updates
  `INFLIGHT` for syscall-whitelist-eligible entries after `pid_matches`;
  the ringbuf predicate decision is a separate gate. Exit-time predicates (ret class,
  latency threshold) can fire on syscalls whose enter was filtered
  from output without losing args / data / stack / enter_ts.
- **State-tracking predicate exemption.** When a predicate references
  `fd_path` (or other fdgraph-state-dependent clauses), the BPF
  prefilter lets `openat`/`openat2`/`dup`/`dup3`/`close`/`socket`/
  `socketpair`/`accept`/`accept4`/`pipe2`/`eventfd2`/`memfd_create`/
  `clone` bypass later predicates after any active syscall-whitelist
  admission. It does not expand that whitelist. Exposed via
  `FILTER_KEY_STATE_EMIT_REQUIRED` (slot 7 of `FILTER_MAP`).
- **`--capture matched+context=<DUR>` mode.** Always-on userspace
  ring of recently-rejected events; on a predicate match the ring
  flushes (the previous `<DUR>` of context) and arms a forward window
  (the next `<DUR>` of events emit unconditionally regardless of
  match). Useful for "I don't know exactly when the bug fires".
  `<DUR>` capped at 30 seconds; ring count capped at 100k entries.
- **Sampling and rate limiting.** `--sample <p>` (uniform Bernoulli
  drop, dependency-free xorshift PRNG) and `--rate-limit <N>` (leaky
  token bucket). Both bypass state-tracking syscalls so fdgraph and
  the binder correlator never lose their pair halves to a stochastic
  drop.

### Phase 2 — Host-side post-processors

- **`neutron summarize <capture> --by <fields> [--samples N] [--top K]`**.
  Streaming NDJSON aggregator. Group keys: `syscall`, `pid`, `tid`,
  `uid`, `comm`, `fd_path`, `ioctl_cmd`, `ioctl_name`, `ioctl_family`,
  `ret`, `ret_class` (`ok`/`errno`/`ok_nonzero`/`unset`), `type`,
  `is_enter`. Optional reservoir of raw exemplar lines per group.
  Prints a sorted `count + group fields` table and a one-line
  total.
- **`neutron diff <baseline> <test> --by <fields> [--top K] [--show-same]`**.
  Same aggregator on two captures; prints `added` / `removed` /
  `changed` rows sorted by `|delta|` descending. Enables the
  negative-evidence workflow: "scenario A vs B both ran the camera,
  what specifically shifted?".
- **`neutron mark <name> [--phase start|end] [--meta k=v]
  [--output FILE]`**. Append a single `type:"marker"` NDJSON line.
  Operators bracket external scenarios with two `mark` calls;
  downstream `neutron window --anchor marker:<name>` cuts a window
  around the bracketed range. With `--output` the line is appended
  with `O_APPEND` (atomic on Linux for ≤PIPE_BUF) so two concurrent
  writers don't interleave.

### Phase 3 — Pixel-camera ioctl decoder expansion

- **LWIS family.** `_IOC_TYPE = 0x4c` ('L') now classifies as
  `ioctl_family:"lwis"`. `LWIS_CMD_PACKET` (`_IOWR('L', 100,
  lwis_cmd_pkt)`) decodes the first u32 of the arg buffer as the
  LWIS command-packet ID; known IDs surface as
  `lwis.cmd_id_name` (`DEVICE_ENABLE`, `DEVICE_DISABLE`,
  `DMA_BUFFER_ALLOC`, `DMA_BUFFER_FREE`, `DMA_BUFFER_ENROLL`,
  `REG_IO`, `TRANSACTION_SUBMIT`, `TRANSACTION_CANCEL`). Unnamed
  IDs keep `cmd_id` searchable by hex without a misleading label.
- **GXP family.** `_IOC_TYPE = 0x47` ('G', upstream) and `0xee`
  (Pixel out-of-tree) classify as `ioctl_family:"gxp"`. No name
  resolution yet — header drift between upstream and Pixel makes
  static cmd-name mapping unreliable.

### Phase 4 — Per-finding enrichment

- **`--fd-snapshot-on-finding`.** When a finding fires with ioctl
  evidence, neutron reads `/proc/<pid>/fdinfo/<fd>` synchronously
  and embeds it as `fdinfo_at_event` on the JSON line. Fields:
  `pos`, `flags` (kernel hex string), `mnt_id`, `ino`. Closes the
  transient-fd gap that the 1 Hz fdgraph poller misses.
- **Binder `target_node` + service map.** `binder_call` JSON now
  includes the `target_node` handle (always available from the BPF
  tracepoint; previously dropped). New `--binder-services <FILE>`
  loads a JSON `(callee_pid, target_node) → service_name` map (typically
  populated from `service list -p`); known pairs surface a `service`
  field on the binder_call line.

### Phase 5 — Markers + symbols + capture health

- **`neutron mark` + `marker:<name>` window anchor.** See Phase 2 for
  the subcommand. `neutron window` gains a new anchor type that
  matches `type:"marker"` lines whose `name` field equals
  `<name>`.
- **Module-relative kernel symbols.** When `kptr_restrict` masks
  `/proc/kallsyms`, neutron now reads `/proc/modules` (which is
  not masked under the same restriction) and renders kernel frames
  inside loaded modules as `[<ko>]+0x<offset>`. Bare hex stays the
  fallback for IPs outside any loaded module.
- **`capture_health` JSON line on shutdown.** In `--json` mode
  neutron emits one final
  `{"type":"capture_health","events_userspace":N,...,"degraded":bool}`
  line so downstream NDJSON consumers see the same counters that go
  to the stderr summary block. The `degraded` flag mirrors the
  stderr WARNING banner predicate, making "absence of finding is
  conclusive" machine-checkable.

### Schema additions (1.2.0)

- New event types: `marker`, `capture_health`.
- `binder_call`: added `target_node`; optional `service`.
- `syscall` (ioctl): added `lwis` nested object (`cmd_id`,
  `cmd_id_name`); `ioctl_family` extended with `lwis`, `gxp`.
- Finding: optional `fdinfo_at_event` map keyed by fd.

### CLI additions (1.2.0)

`--match-pid`, `--match-uid`, `--match-syscall`, `--match-fd`,
`--match-comm`, `--match-ioctl-cmd`, `--match-ioctl-type`,
`--match-ioctl-nr`, `--match-ioctl-dir`, `--match-ret`,
`--match-latency-min`, `--match-prot-rwx`, `--match-prot-wx`,
`--match-arg-u8`, `--match-arg-u16`, `--match-arg-u32`,
`--match-arg-u64`, `--match-binder-code`, `--match-binder-flags`,
`--match-binder-to-proc`, `--match-binder-to-thread`,
`--match-binder-target-node`, `--match-binder-reply`, `--match`,
`--capture`, `--sample`, `--rate-limit`,
`--fd-snapshot-on-finding`, `--binder-services`.

New subcommands: `summarize`, `diff`, `mark`.

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
  it is available. In the current 1.5 line doctor validates both Binder
  layouts and attachment failures make capture health non-complete; older
  releases did not enforce that gate.

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
  channel. Single multi-producer ring, 1 MiB. This historical 1.0 entry
  did not account for reserve failures; current releases explicitly count
  them as dropped events and never describe the channel as lossless.
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
