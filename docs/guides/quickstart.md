# Quickstart

Get neutron running on a Pixel 8 Pro in under 10 minutes.

## Prerequisites

- Pixel 8 Pro (or any Android 14+ device with kernel 6.1+ and BTF), **rooted**
  via KernelSU or Magisk
- `adb` available and the device authorized (`adb devices` shows the device)
- Build environment: Rust nightly + `bpf-linker` + `aarch64-linux-gnu-gcc`

See [docs/CONTRIBUTING.md](../CONTRIBUTING.md) for the full toolchain setup.
See [docs/devices/pixel8pro.md](../devices/pixel8pro.md) for the verified
device baseline.

## Step 1: Build and Deploy

```bash
git clone <repo>
cd android_bpf
./build.sh
```

`build.sh` runs `cargo xtask build-ebpf release` (compiles the Rust BPF
programs to `neutron.bpf.elf`), `cargo build --release --target
aarch64-unknown-linux-musl --bin neutron` (cross-compiles the userspace
loader), pushes both to `/data/local/tmp/`, and stages built-in research packs
under `/data/local/share/neutron/packs/`.

For a manual deployment, keep the parent root-owned and temporarily hand only
the pack subtree to `shell` so `adb push` can create nested pack directories,
then restore root ownership and read-only modes:

```bash
adb push neutron.bpf.elf /data/local/tmp/neutron.bpf.elf
adb push target/aarch64-unknown-linux-musl/release/neutron /data/local/tmp/neutron
adb shell "su -c 'mkdir -p /data/local/share/neutron/packs && chown 0:0 /data/local/share/neutron && chmod 0755 /data/local/share/neutron && chown -R shell:shell /data/local/share/neutron/packs'"
adb push packs/. /data/local/share/neutron/packs/
adb shell "su -c 'chown -R 0:0 /data/local/share/neutron/packs && find /data/local/share/neutron/packs -type d -exec chmod 0755 {} \; && find /data/local/share/neutron/packs -type f -exec chmod 0644 {} \;'"
adb shell chmod +x /data/local/tmp/neutron
adb shell "su -c '/data/local/tmp/neutron doctor'"
```

Expected output (truncated):

```
=== [1/3] Building Aya BPF programs (Rust → bpfel-unknown-none) ===
=== [2/3] Building userspace binary (aarch64-unknown-linux-musl) ===
=== [3/3] Deploying to connected device ===
=== Done. On device: ===
  adb shell su -c '/data/local/tmp/neutron --pid <PID>'
```

## Step 2: Find Your Target PID

```bash
# Find PID of a running app
adb shell pidof com.example.app

# Or list all processes
adb shell ps -A | grep com.example
```

## Step 3: Run the Tracer

The default `--object` is `/data/local/tmp/neutron.bpf.elf` (the path
`build.sh` pushes to), so you do not need to pass it explicitly.

### Trace a Specific App (rule-engine findings only)

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid '$(adb shell pidof com.example.app)
```

### Trace All Processes

```bash
adb shell su -c '/data/local/tmp/neutron'
```

### Security Assessment Mode

Limits to security-relevant syscalls in the BPF filter. Best for root
detection, anti-tamper, and network analysis:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid <PID> \
  --profile security \
  --resolve-paths'
```

### Save Raw Events to File

```bash
# On device, save as NDJSON
adb shell su -c '/data/local/tmp/neutron \
  --pid <PID> \
  --raw --json \
  --max-output-size 250mb \
  --output /data/local/tmp/trace.ndjson'

# Pull the file
adb pull /data/local/tmp/trace.ndjson
```

`--raw` includes the per-event stream; without it, only rule-engine
findings are emitted. `--no-findings` suppresses findings (useful with
`--raw` to reproduce the legacy per-event-only behavior).

For Android app workflows, prefer package-scoped capture when possible:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --raw --json --no-findings \
  --match-package com.example.app \
  --max-output-size 250mb \
  --output /data/local/tmp/app_trace.ndjson'
```

`--match-package` resolves the installed package to its UID on-device and
uses the BPF UID prefilter. `--max-output-size` stops runaway captures
before they fill `/data/local/tmp`.

For longer sessions where stopping at the cap is not acceptable, rotate
bounded NDJSON segments instead:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --raw --json --no-findings \
  --match-package com.example.app \
  --rotate-output-size 250mb \
  --output /data/local/tmp/app_trace.ndjson'
```

This writes `/data/local/tmp/app_trace.ndjson`,
`/data/local/tmp/app_trace.ndjson.1`, and so on. `--rotate-output-size`
requires `--output` and cannot be combined with `--max-output-size`.

For content-provider research, scope the caller package and provider
authority together:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --raw --json --no-findings \
  --match-package com.example.probe \
  --match-android-provider content://com.android.contacts/contacts \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/provider_trace.ndjson'
```

`--match-android-provider` resolves the authority to the declaring
provider package UID on-device, then reuses the same BPF UID prefilter as
`--match-uid`.

### Investigate a captured trace with `neutron window`

After capturing NDJSON, cut a window of events around any anchor (a
finding, a crash, a PID, an `event_id`, a `comm` substring, or a
`binder_call` status):

```bash
# 5-second window around every R003 (process_crash) finding.
neutron window trace.ndjson \
    --anchor finding:R003_process_crash \
    --around 5s

# Last 100 events before each crash, plus 50 after — useful as a
# self-contained triage packet.
neutron window trace.ndjson \
    --anchor crash \
    --before-events 100 --after-events 50

# One summary line per merged window (no raw NDJSON):
neutron window trace.ndjson \
    --anchor crash --around 2s --summary
```

See [docs/guides/window.md](window.md) for the full anchor + window
reference and a small cookbook.

### Glob quoting over `adb shell`

`--match-fd` and `--match-comm` take glob patterns. When they're passed
through `adb shell su -c "..."`, two shells stand between your
keystrokes and neutron — the local shell that runs `adb`, and the
device shell that runs the `su -c` payload. Either one may expand `*`
or `?` against its own filesystem before neutron sees argv.

If neutron prints `WARNING: --match-fd arrived as N literal values …
looks like the outer shell expanded a wildcard`, escape the `*` so it
survives both shells:

```bash
# DOES NOT WORK in a typical adb-over-bash setup:
adb shell su -c "/data/local/tmp/neutron --pid 0 --match-fd '/dev/lwis*'"

# WORKS — the backslash survives the local bash and reaches the
# device shell where it correctly suppresses globbing:
adb shell su -c "/data/local/tmp/neutron --pid 0 --match-fd=/dev/lwis\\*"

# Equivalent — heredoc transports argv literally:
adb shell su -c <<'CMD'
/data/local/tmp/neutron --pid 0 --match-fd=/dev/lwis*
CMD
```

The same caveat applies to `--match-comm` and to fd-path globs inside
`--match '...'`.

## Step 4: Read the Output

Findings (default):

```
[FINDING] T001_proc_self_maps_polling root_detection MEDIUM
  rule:    Periodic /proc/self/maps inspection
  process: example.app (pid 21093)
  events:  130 over 260000.0ms, period 2033.000ms
  evidence:
    [1037686946] <- openat(/proc/self/maps) ret=79
    ...
```

Raw text events (with `--raw`):

```
[   1234.567] 21093/21093  e.bankapp        -> openat(AT_FDCWD, O_RDONLY|O_CLOEXEC) "/proc/self/maps"
[   1234.568] 21093/21093  e.bankapp        <- openat = 42 [+123 µs]
[   1234.569] 21093/21093  e.bankapp        -> connect(AF_INET, SOCK_STREAM) "AF_INET 1.2.3.4:443"
```

Raw JSON events (`--raw --json`):

```json
{"ts_ns":1712345678901,"pid":21093,"tid":21093,"uid":10147,"nr":56,"name":"openat","comm":"e.bankapp","enter":true,"ret":0,"args":[4294967196,140234567890,524288,438,0,0],"data":"/proc/self/maps"}
```

## Sanity check the BPF load

If the tracer fails to attach, run the diagnostic spike:

```bash
adb shell su -c '/data/local/tmp/neutron-spike \
  --object /data/local/tmp/neutron.bpf.elf'
```

This loads the BPF object, attaches the three tracepoints, and dumps a
few events. See `docs/devices/pixel8pro.md` for the expected transcript.

## Common First Run Issues

| Symptom                                | Cause                                                       | Fix                                                  |
|----------------------------------------|-------------------------------------------------------------|------------------------------------------------------|
| `EACCES` on `bpf()`                    | Not running as root                                         | Use `adb shell su -c '...'`                          |
| `Ebpf::load failed`                    | Pushed an outdated `.elf`                                   | Re-run `./build.sh`                                  |
| `program X not found`                  | `--binder` against a kernel without binder tracepoint       | Drop `--binder` or check `/sys/kernel/tracing/events/binder/` |
| Empty `data` fields on path syscalls   | Kernel returned a truncated read (rare on 6.1+)             | Add `--resolve-paths` for `/proc/<pid>/fd/` fallback |
| Stack frames are raw hex addresses     | `kptr_restrict` masking kallsyms (kernel frames)            | Expected on Android — root + BPF gets the syscall path, not the symbols |
| `--stacks` shows `<JIT>+0xN`           | Frame is inside `[anon:dalvik-jit-code-cache]`              | Expected — JIT method symbolization is V1.x backlog  |
