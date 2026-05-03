# False positives

This page lists the **known false-positive scenarios** for each rule in the
default detector pack, and the tactics neutron uses to filter them out.

The intent: when a finding fires, an analyst should be able to look here,
identify whether the surrounding context matches a known FP pattern, and
either dismiss the finding or escalate it with confidence.

Findings emitted under [schema v2](rules/reference.md#schema-v2) carry a
machine-readable `false_positives: [...]` field that mirrors the bullets
below.

---

## T001 — `proc_self_maps_polling`

Rule: openat on `/proc/self/maps`, repeated within a 15-second sliding
window, threshold ≥ 2.

**Known false positives:**

- **Native crash reporters and unwinders** — Crashlytics, Bugsnag,
  Sentry-native, and bare-libunwind walk `/proc/self/maps` on first
  invocation to map IPs to library names. Usually fires once on startup,
  then once per crash. If the only T001 hits are at the start of the
  trace and immediately before a `SIGSEGV`-handled crash, treat as
  legitimate.
- **Profilers and JIT diagnostic tools** — Android Studio Profiler,
  simpleperf, and ART's own JIT compiler poll the map periodically while
  attached. If T001 fires alongside obvious profiler stack frames
  (`libsimpleperf`, `libprofiler_collector`), treat as legitimate.
- **Custom allocators** — jemalloc and tcmalloc read the map once on
  startup. A single T001 hit at process start is generally not anti-tamper
  activity.

**Tactics neutron applies:** the rule fires only after ≥ 2 hits in 15 s,
which already excludes one-shot startup reads.

**Tactics for triage:** look at the stack frame distribution. Hardened
anti-tamper code typically polls from a single hot stack frame
(`libprotect.so::check_maps`); legitimate one-shot scans show diverse
stacks.

---

## T011 — `rwx_or_wx_memory_mapping`

Rule: `mmap` or `mprotect` produced a region with `PROT_EXEC | PROT_WRITE`.

**Known false positives:**

- **Custom managed runtimes** — Hermes (React Native), V8 embedders, custom
  Lua/JS JITs, and game engines with dynamic-code generation legitimately
  need writable+executable pages.
- **Emulators / instrumentation libraries** — Unicorn, Frida-gum on its
  own gadget, and cross-platform compatibility shims that JIT-compile
  bytecode at runtime.
- **ART JIT itself** — ordinarily ART avoids RWX (it transitions W → X),
  but some debug builds keep RWX briefly. The same goes for the dexopt
  path.

**Open work (P0.4 / P1):** sub-categorize by anonymous vs file-backed vs
memfd-backed mappings. Today T011 fires on all three; the
`false_positives` rule entry contains a TODO marker pointing to this.

---

## T017 — `syscall_from_jit_code_cache`

Rule: any syscall whose user stack top frame lives inside
`[anon:dalvik-jit-code-cache]`, ≥ 5 hits in 10 s.

**Known false positives:**

- **ART's own internal callbacks during compilation** — the JIT compiler
  occasionally calls back into the runtime from generated code while
  it is mid-compile. Brief bursts at app startup are normal.
- **JNI critical-call trampolines** — ART emits inline trampolines inside
  the JIT region that call `JNI_OnLoad` and similar entry points.
- **Kernel-level profilers sampling stacks** — `simpleperf` and
  `perf_event` will incidentally land stack samples in the JIT region.

**Tactics neutron applies:** the 5/10s threshold filters out single-event
bursts. If the calling syscall is `madvise` or `mprotect`, the cause is
usually JIT compilation rather than instrumentation.

**Tactics for triage:** look at the *syscalls* that fire from the JIT
region. JIT compiler calls `mprotect` and `madvise` on its own pages.
Anti-tamper code from a packed module calls `openat`, `read`, `socket`,
`getrandom`.

---

## T019 — `system_lib_path_probing`

Rule: openat on `/system/lib64/*` with `stack_not_contains [RenderScript,
libRS, libskia]`.

**Known false positives:**

- **Dynamic linker (`linker64`)** — every Android process opens many
  `/system/lib64` libraries through the linker. The default rule's
  `stack_not_contains` list does not filter the linker's own stack.
- **WebView / Chromium startup** — loads dozens of native libraries from
  `/system/lib64` early in process lifetime.
- **Vendor / OEM components** — Vulkan ICD loaders, Skia, RenderScript,
  Adreno graphics drivers iterate the directory on first use.
- **Game engines** — Unity, Unreal, custom GLES/Vulkan loaders.

**Open work:** add an allowlist-based attribution pass that excludes the
linker and the dominant graphics-stack stacks; add a frequency floor so
single startup hits don't fire. Today the `false_positives` rule entry
contains a TODO marker pointing to this.

**Tactics for triage:** if the process is a fresh app launch and T019
fires within the first second of the trace, it is almost certainly
linker / graphics-stack init. Hardened anti-tamper probes typically fire
later, often in a periodic cadence.

---

## T020 — `native_check_from_anon_mapping`

Rule: openat on `/proc/self/{maps,status,cmdline,mountinfo}` with the
top user stack frame in an `[anon:NNNN]+0xN` mapping.

**Known false positives:**

- **Custom allocators with executable scratch pages** — jemalloc has
  occasional code-cache mappings that can shadow the same region.
- **Profilers / debuggers running their own JIT'd helpers** — rare on
  Android but possible.

**Tactics neutron applies:** this rule deliberately requires the call
origin to be anonymous executable memory (no file backing). Almost no
legitimate Android library code lives in such mappings; this is the
canonical fingerprint of packed / decrypted anti-tamper modules.

---

## T021 — `frida_thread_comm_scan`

Rule: openat on `/proc/<other_pid>/comm` or `/proc/<pid>/task/<tid>/comm`,
≥ 5 hits in 30 s.

**Known false positives:**

- **System tools** (`ps`, `top`) — but those don't run inside an app
  process, so the `comm`-based filter (`comm_in: [...]`) excludes them.
- **Unwinders** capturing thread snapshots for crash reports.

The rule excludes `netd` and other system service comms via `comm_not_in`.

---

## How to add a false-positive note to a custom rule

When authoring a YAML rule, declare known FP scenarios under the
`false_positives` field:

```yaml
- id: T999_my_rule
  name: …
  behavior: my_observable_pattern
  interpretation:
    - possible exotic anti-tamper
  confidence: 0.6
  false_positives:
    - "the dynamic linker walks /system/lib64 every process — exclude
       linker64 stacks via stack_not_contains"
    - "vendor graphics drivers do the same on first frame"
  conditions:
    - syscall_in: [56]
    - path_prefix: /system/lib64/
```

Findings emitted by this rule will carry the `false_positives` array
verbatim, so analysts triaging the result see the same list inline.

See [docs/rules/reference.md](rules/reference.md) for the full schema.
