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
loader), and `adb push`es both to `/data/local/tmp/`.

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
  --output /data/local/tmp/trace.ndjson'

# Pull the file
adb pull /data/local/tmp/trace.ndjson
```

`--raw` includes the per-event stream; without it, only rule-engine
findings are emitted. `--no-findings` suppresses findings (useful with
`--raw` to reproduce the legacy per-event-only behavior).

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
