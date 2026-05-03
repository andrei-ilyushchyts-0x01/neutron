# Roadmap

## Status

`v1.0.0` is the current line. It targets Pixel 8 Pro on kernel 6.1.x via
Aya 0.13, BTF + CO-RE, and BPF ring buffer. The pre-V1 kernel-4.14 line
(`v0.1.0-legacy`) lives on the `legacy` branch and is no longer
maintained.

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
- Default detector pack grew from 15 to 19 rules; T016–T019 use
  `stack_contains` / `stack_not_contains`.
- Stack-aware rules now actually receive the `"stack"` field — pre-1.0
  this never fired because resolution happened after `engine.feed`.

## V1.x backlog

Things that would be nice to have without rethinking the architecture:

- **Extend `syscall_name` table for kernel 6.1+ aarch64 numbers**. The
  Pixel-4a-era table (`src/decode/syscalls.rs`) leaves several modern
  syscalls decoded as `"unknown"`. Add at minimum: `io_setup` (0),
  `io_destroy` (1), `io_submit` (2), `io_cancel` (3), `io_getevents` (4),
  `setxattr` (5), `lgetxattr` (9), `faccessat2` (439), `openat2` (437),
  `close_range` (436), `pidfd_open` (434), `pidfd_send_signal` (424),
  `statx` (already there at 291 — verify), `epoll_pwait2` (441).
- **T020 candidate: syscall from anonymous executable memory.** Anti-tamper
  probes on hardened apps frequently issue `/proc/self/maps` and
  `/proc/self/status` reads from a `[anon:<id>]+0xN` mapping (a packed or
  decrypted native module). A rule of `stack_contains: ["[anon:"]` +
  `syscall_in: [56, 78, 79]` is a high-signal indicator of obfuscated
  anti-tamper code paths.
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
  and tail percentiles in addition to the current `period_ms` mean.
- **Findings export to Markdown report** for assessment write-ups.

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

There is no fixed timeline for V2.

## Out of scope

The following will not be addressed in this project:

- Tracing on production devices without root.
- Targets outside Android.
- Defeating any specific anti-tamper SDK. The tool reports observable
  behavior; what to do with that information is the researcher's job.
