# neutron

Rooted Android kernel-boundary tracer and surface mapper for security research.

`neutron` runs on a rooted Android device, attaches eBPF programs to kernel
tracepoints, and records what an app or system service does at the
syscall/ioctl/Binder/FD/crash boundary. It is useful when static review is too
slow or too incomplete and you need runtime evidence without rewriting the
capture path around ptrace or userspace injection.

[![kernel: 6.1+](https://img.shields.io/badge/kernel-6.1%2B_aarch64-blue.svg)](#requirements)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Authorized testing only. Use this on devices and applications you own or have
explicit written permission to assess. See [SECURITY.md](SECURITY.md).

## When To Use It

Use neutron when you need to answer questions like:

- Which syscalls did this app make during this scenario?
- Did this package touch `/proc`, `/sys`, root artifacts, RWX memory, sockets,
  Binder, DMA heap, KGSL/Mali, LWIS/GXP, or other driver surfaces?
- Did a Binder call correlate with a callee crash?
- Which package or service changed behavior between two scenarios?
- Which Binder services, HALs, processes, device nodes, drivers, and modules are
  present on this device, and which of them were actually reached in a scenario?
- Did a package-scoped smoke test produce enough signal to justify deeper work?

Do not treat neutron as a vulnerability scanner. It does not prove that an app
is secure and it does not see Java/Kotlin method calls or full Binder Parcel
payloads. Pair it with static analysis, API probes, Frida/JDWP when needed, and
scenario-specific stimuli.

## What It Observes

neutron can observe:

- raw syscalls from a PID, UID, Android package, or content-provider package
- file/procfs/sysfs access, socket activity, mmap/mprotect RWX/WX transitions
- ioctl families including binder/dma-buf, dma-heap, ashmem, KGSL, Mali, ALSA,
  LWIS, and GXP where the decoder knows the command shape
- Binder tracepoint metadata and paired `binder_call` events with latency and
  crash status when `--binder` is enabled, plus exact descriptor/method
  attribution from an operator map and deterministic AIDL catalog
- process exits/crashes from BPF, logcat, and tombstone sources
- FD pressure through periodic `fd_snapshot` events
- optional stack IDs and symbols when using `neutron-stacks.bpf.elf`
- deterministic `neutron.surface/v1` snapshots of Android services, HALs,
  processes, device nodes, drivers, modules, and observed causal relations

neutron cannot observe:

- Java/Kotlin method-level control flow
- pure in-process logic that does not cross the kernel boundary
- full Binder Parcel argument payloads
- delegated driver work if you only trace the original app UID and the work is
  performed by `system_server`, a media service, a HAL, or a vendor daemon

The detailed limitations are in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Requirements

Device:

- rooted Android device
- aarch64 kernel 6.1+
- BTF exposed at `/sys/kernel/btf/vmlinux`
- tracefs at `/sys/kernel/tracing`
- bpffs at `/sys/fs/bpf`
- `CAP_BPF` and `CAP_SYS_ADMIN` in the domain that runs neutron

Verified baseline:

- Google Pixel 8 Pro (`husky`)
- Android 16
- kernel `6.1.145-android14-11`
- KernelSU, run with `adb shell "su -c '...'"`.

Host build tools:

- Rust nightly, pinned by [rust-toolchain.toml](rust-toolchain.toml)
- `bpf-linker`
- `aarch64-linux-gnu-gcc`
- Android platform tools (`adb`)

Install build prerequisites on Ubuntu-like hosts:

```bash
sudo apt-get update
sudo apt-get install -y gcc-aarch64-linux-gnu android-tools-adb
cargo install bpf-linker
```

## Install

### Option A: Install From A GitHub Release

Use this path when a release with Android assets has been published.

```bash
VERSION=v1.4.0
REPO=andrei-ilyushchyts-0x01/neutron

curl -LO "https://github.com/${REPO}/releases/download/${VERSION}/neutron-${VERSION}-android-aarch64.tar.gz"
curl -LO "https://github.com/${REPO}/releases/download/${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing

tar -xzf "neutron-${VERSION}-android-aarch64.tar.gz"
cd "neutron-${VERSION}-android-aarch64"

adb push neutron /data/local/tmp/neutron
adb push neutron.bpf.elf /data/local/tmp/neutron.bpf.elf
adb shell chmod +x /data/local/tmp/neutron
```

Run the preflight:

```bash
adb shell "su -c '/data/local/tmp/neutron doctor'"
```

Expected result: `doctor` should exit successfully. Warnings about SELinux
enforcing or masked kallsyms are normal on Pixel; privilege/BTF/tracefs/raw
syscall failures must be fixed before tracing.

### Option B: Build And Deploy From Source

```bash
git clone https://github.com/andrei-ilyushchyts-0x01/neutron.git
cd neutron

# Builds neutron.bpf.elf and the Android aarch64 userspace binary,
# then pushes both to /data/local/tmp if adb is connected.
./build.sh
```

Manual equivalent:

```bash
cargo xtask build-ebpf release
cargo build --release --target aarch64-unknown-linux-musl --bin neutron

adb push neutron.bpf.elf /data/local/tmp/neutron.bpf.elf
adb push target/aarch64-unknown-linux-musl/release/neutron /data/local/tmp/neutron
adb shell chmod +x /data/local/tmp/neutron
adb shell "su -c '/data/local/tmp/neutron doctor'"
```

## First Capture

Package-scoped capture is usually the best first run. It works even when the
app has many processes because Android package names resolve to UIDs.

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --no-findings --no-logcat \
  --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.app \
  --rate-limit 200 \
  --max-output-size 64mb \
  --health-output /data/local/tmp/neutron.health.ndjson \
  --output /data/local/tmp/neutron.ndjson'"

adb pull /data/local/tmp/neutron.ndjson
adb pull /data/local/tmp/neutron.health.ndjson
```

Read the health line first:

```bash
jq . neutron.health.ndjson
```

If `output_cap_hit` is `true`, the main NDJSON reached
`--max-output-size`. The health sidecar is still complete.

Important: if `--match-package` resolves to a shared/system UID such as `1000`,
neutron prints a warning. In that case the trace is UID-scoped, not
package-isolated. Add `--match-pid`, `--match-comm`, fd filters, or a
service-specific scenario before making package-specific claims.

## Common Capture Recipes

### Trace One Running PID For Findings

```bash
PID="$(adb shell pidof com.example.app | tr -d '\r')"

adb shell "su -c '/data/local/tmp/neutron \
  --pid ${PID} \
  --profile security \
  --resolve-paths'"
```

Without `--raw`, neutron emits rule-engine findings only.

### Save Raw NDJSON For One Package

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --no-findings \
  --match-package com.example.app \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/app.health.ndjson \
  --output /data/local/tmp/app.ndjson'"
```

### Rotate Long Captures Instead Of Stopping At A Cap

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --no-findings \
  --match-package com.example.app \
  --rate-limit 1000 \
  --rotate-output-size 250mb \
  --output /data/local/tmp/app.ndjson'"
```

This writes `/data/local/tmp/app.ndjson`, `/data/local/tmp/app.ndjson.1`, and
so on. `--rotate-output-size` and `--max-output-size` are mutually exclusive.

### Camera / Media HAL Scenario

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --profile driver-harness \
  --driver-pack media-hal,kgsl \
  --json --raw --no-findings \
  --capture matched+context=1s \
  --rate-limit 2000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/camera.health.ndjson \
  --output /data/local/tmp/camera.ndjson'"
```

Start the capture, exercise Camera, then stop neutron with Ctrl-C or
`timeout -s INT`.

### Binder Crash Correlation

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --profile kernel-lpe \
  --driver-pack binder \
  --binder \
  --json --raw \
  --capture matched+context=2s \
  --max-output-size 250mb \
  --health-output /data/local/tmp/binder.health.ndjson \
  --output /data/local/tmp/binder.ndjson'"
```

Review callee-crash windows:

```bash
adb shell /data/local/tmp/neutron window /data/local/tmp/binder.ndjson \
  --anchor binder_call:callee_crashed \
  --around 3s \
  --summary
```

### Content Provider Research

Trace a probing app plus the provider package UID resolved from an authority:

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --no-findings \
  --match-package com.example.probe \
  --match-android-provider content://com.android.contacts/contacts \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/provider.health.ndjson \
  --output /data/local/tmp/provider.ndjson'"
```

### System App Sweep

Print the built-in sweep recipe:

```bash
adb shell /data/local/tmp/neutron recipes system-app-sweep
```

The recipe runs one package at a time, records `monkey` status, attach status,
line/byte counts, and a per-package health sidecar. Treat low line counts as
"needs a targeted trigger", not as safe.

## Map The Android Surface

Version 1.4 adds a deterministic on-device surface snapshot. A static scan
needs no trace capture:

```bash
adb shell "su -c '/data/local/tmp/neutron surface scan \
  --output /data/local/tmp/surface.json'"
adb exec-out "su -c 'cat /data/local/tmp/surface.json'" > surface.json
```

Import an existing causal NDJSON capture, or observe one package/UID live:

```bash
neutron surface scan --capture capture.ndjson --output surface.json

adb shell "su -c '/data/local/tmp/neutron surface scan \
  --observe 30s --from-package com.example.app \
  --output /data/local/tmp/surface.json'"
```

`--capture` and `--observe` are mutually exclusive. Live observation requires
exactly one `--from-package` or `--from-uid`; it starts one child `neutron
trace`, brackets the interval with the `surface-observe` scenario, sends
SIGINT, and requires a final `capture_health` record. It needs the same root,
BPF, Binder, `/proc`, and `/dev` access as tracing. Surface output files are
created with mode `0600`. The static snapshot is collected after the live
interval so `/proc` starttime evidence can reject a recycled PID.

Every query emits JSON (`--output` is optional):

```bash
neutron surface services  --input surface.json
neutron surface hals      --input surface.json
neutron surface devices   --input surface.json
neutron surface process 1234 --input surface.json
neutron surface explain /dev/trusty-ipc-dev0 --input surface.json
neutron surface reachable --from-package com.example.app --input surface.json
neutron surface reachable --from-uid 10123 --input surface.json
```

## Run A Reproducible Research Pack

After installing the companion APK and built-in packs, preflight a pack without
stimulating hardware:

```bash
adb shell "su -c '/data/local/tmp/neutron research --pack keymint'"
```

This exits `2` and writes a private `authorization_required` report. Add
`--authorized-use` only on a device you are authorized to assess:

```bash
adb shell "su -c '/data/local/tmp/neutron research --pack camera \
  --param camera_id=0 --authorized-use'"
```

Packs are data-only and compile into allowlisted trace flags plus one of seven
typed companion actions. See [the research-pack guide](docs/guides/research-packs.md).

`reachable` means observed causal reachability through capture-sourced
`root_process`, `binder`, `served_by`, and successful `open`, `mmap`, or
`ioctl` relations. It does not solve SELinux, VINTF, manifest permissions, or
theoretical Binder access. Failed or incomplete syscalls are retained as
non-traversable `syscall_attempt` evidence; `process_exit`, `crash`, AVC, and
static `proc_fd` relations also enrich the capture without making a device
reachable.

For a UID-rooted causal trace, use `trace --root-uid UID`. The eBPF gate admits
each matching process on its first observed kernel event, including processes
created between `/proc` refreshes; the refresh reconciles exits and process
limits. The option cannot be combined with `--package` or an explicit `--pid`.

## Three Boundary Report Workflows

These built-in recipes print end-to-end commands and finish with
`neutron report`, so the final artifact is a Markdown boundary report rather
than only a table or event window.

```bash
neutron recipes launch-diff
neutron recipes action-diff
neutron recipes native-surface-audit
```

- `launch-diff`: compare idle baseline vs app launch.
- `action-diff`: compare baseline vs one marked user action.
- `native-surface-audit`: capture Binder plus native driver handoffs and use
  Binder attribution helpers for service labeling.

## Post-Process Captures

The same `neutron` binary can analyze NDJSON files offline.

Summarize syscall/ioctl activity:

```bash
adb shell /data/local/tmp/neutron summarize \
  --by comm,syscall,ret_class \
  --top 30 \
  /data/local/tmp/app.ndjson

adb shell /data/local/tmp/neutron summarize \
  --by comm,ioctl_family,ioctl_name,ret_class \
  --top 50 \
  /data/local/tmp/camera.ndjson
```

Cut a small window around crashes, findings, markers, PIDs, or comm names:

```bash
adb shell /data/local/tmp/neutron window /data/local/tmp/app.ndjson \
  --anchor crash \
  --before-events 100 \
  --after-events 50
```

Compare two scenario captures:

```bash
adb shell /data/local/tmp/neutron diff \
  /data/local/tmp/baseline.ndjson \
  /data/local/tmp/test.ndjson \
  --by comm,syscall,ret_class \
  --top 40
```

Bracket a live scenario with markers:

```bash
adb shell "su -c '/data/local/tmp/neutron trace \
  --package com.example.app \
  --follow-binder --follow-services --follow-hal \
  --max-depth 4 --max-processes 64 \
  --output /data/local/tmp/app.ndjson'" &

adb shell "su -c '/data/local/tmp/neutron mark login --phase start'"
# trigger the scenario
adb shell "su -c '/data/local/tmp/neutron mark login --phase end'"
```

The tracer assigns the marker timestamp and causal IDs. To keep the old
append-only behavior without changing a live scenario, pass `mark --output`.

Render the causal scenario as Mermaid:

```bash
neutron graph app.ndjson \
  --root-package com.example.app \
  --format mermaid \
  --output flow.md
```

Render a Markdown boundary report:

```bash
neutron report app.ndjson \
  --package com.example.app \
  --title "App Boundary Report" \
  --output app-boundary-report.md
```

Render a baseline diff report:

```bash
neutron report launch-test.ndjson \
  --baseline launch-baseline.ndjson \
  --package com.example.app \
  --title "Launch Boundary Report" \
  --output launch-boundary-report.md
```

For Binder-heavy captures, build helper files before the report:

```bash
adb shell service list -p > service-list-p.txt

neutron binder-map service-list \
  --input service-list-p.txt \
  --output binder-catalog.json

neutron binder-map template app.ndjson \
  --output binder-services.template.json

# Edit binder-services.template.json with exact service names when known.

neutron report app.ndjson \
  --binder-services binder-services.template.json \
  --binder-catalog binder-catalog.json \
  --package com.example.app \
  --output app-boundary-report.md
```

`--binder-services` is exact `(callee_pid,target_node) -> service` attribution.
`--binder-catalog` is candidate-only PID attribution from `service list -p`;
the report labels it as candidates and does not present it as exact.

Reports and Binder helper JSON can contain package names, device-local paths,
service topology, and other assessment evidence. Treat them like captures:
redact before sharing and do not commit real assessment outputs.

## Output Modes

Default mode:

- findings only
- human-readable text

Useful flags:

- `--json`: emit NDJSON
- `--raw`: include raw event lines
- `--no-findings`: suppress findings, useful for event-only captures
- `--health-output PATH`: write final `capture_health` line to a sidecar file
- `--max-output-size SIZE`: stop before filling storage
- `--rotate-output-size SIZE`: write numbered output segments
- `--rate-limit N`: cap emitted event rate
- `--sample P`: probabilistic event sampling
- `--capture matched+context=2s`: keep context around matched events

See [docs/guides/output-formats.md](docs/guides/output-formats.md) for the JSON
schema.

## Troubleshooting

### `privilege preflight failed`

You probably ran neutron as the Android `shell` user instead of through root.
Use:

```bash
adb shell "su -c '/data/local/tmp/neutron doctor'"
```

Bad quoting can make `su` run the wrong payload. The trace path performs the
same privilege check as `doctor` and exits early before BPF load.

### `another neutron capture appears active`

Only run one capture at a time. neutron holds a lock at
`/data/local/tmp/neutron.capture.lock` by default. Use `--capture-lock off`
only for advanced debugging.

### `--match-package ... resolved to shared/system UID`

The capture is UID-scoped. For UID `1000` and other platform/shared UIDs,
events can come from other processes sharing that UID. Add narrower filters or
trace the service/PID that actually handles the scenario.

### `output_cap_hit: true`

The primary output reached `--max-output-size`. Use the health sidecar to audit
the capture, then rerun with a narrower scope, lower rate, or
`--rotate-output-size`.

### `ioctl_family:"dma_buf"` but `data` starts with `binder:`

Binder and DMA-BUF share an ioctl magic value. neutron disambiguates with
FD hints when available. Without a binder fd hint, the family can fall back to
`dma_buf`; inspect `data`, `fd_kind`, and `fd_path` together.

### Stack traces do not work

The default `neutron.bpf.elf` is stackless for compatibility. Stack tracing
requires `neutron-stacks.bpf.elf` and a domain that can create
`BPF_MAP_TYPE_STACK_TRACE`.

## Build And Test

Fast host checks:

```bash
cargo test -p neutron --lib --bin neutron
cargo test --workspace --exclude neutron-ebpf
cargo clippy --workspace --exclude neutron-ebpf --all-targets -- -D warnings
```

BPF build check:

```bash
cargo xtask build-ebpf release
```

Android build:

```bash
cargo build --release --target aarch64-unknown-linux-musl --bin neutron
```

Plain `cargo test --workspace` is not the supported gate because the no_std BPF
crate is not host-testable in the normal Rust test harness.

## Release Assets

To prepare local assets for a GitHub release:

```bash
# Run from a clean committed tree. The source tarball is created from git HEAD.
scripts/package-release.sh
```

The script writes:

- `dist/neutron-v<VERSION>-android-aarch64.tar.gz`
- `dist/neutron-v<VERSION>-source.tar.gz`
- `dist/SHA256SUMS`

Suggested GitHub release contents:

- attach the Android aarch64 tarball and `SHA256SUMS`
- rely on GitHub's automatic source zip/tarball, or attach the explicit
  source tarball from `dist/`
- include the verified device profile and the `neutron doctor` result used for
  the release
- document the binary SHA-256 and BPF object SHA-256

Example maintainer flow:

```bash
VERSION="v$(awk -F '"' '/^version =/ { print $2; exit }' Cargo.toml)"

cargo test -p neutron --lib --bin neutron
cargo test --workspace --exclude neutron-ebpf
cargo clippy --workspace --exclude neutron-ebpf --all-targets -- -D warnings

scripts/package-release.sh

git tag -a "$VERSION" -m "neutron $VERSION"
git push origin "$VERSION"

gh release create "$VERSION" \
  "dist/neutron-${VERSION}-android-aarch64.tar.gz" \
  "dist/neutron-${VERSION}-source.tar.gz" \
  dist/SHA256SUMS \
  --verify-tag \
  --title "neutron ${VERSION}" \
  --notes "Android aarch64 release assets for neutron ${VERSION}."
```

Publishing a release changes GitHub state. Use `gh release create ...` only
after maintainers have approved the tag, notes, and assets.

## Documentation Map

- [docs/guides/quickstart.md](docs/guides/quickstart.md): longer first-trace walkthrough
- [docs/guides/security-assessment.md](docs/guides/security-assessment.md): assessment workflow
- [docs/guides/bpf-tracing.md](docs/guides/bpf-tracing.md): profiles, filtering, capture, stacks
- [docs/guides/native-mapping.md](docs/guides/native-mapping.md): offline ELF/APK mapping and Ghidra bookmark export
- [docs/guides/harness.md](docs/guides/harness.md): capture, minimize, and replay regression testcases
- [docs/guides/research-packs.md](docs/guides/research-packs.md): validated on-device research packs
- [docs/guides/writing-rules.md](docs/guides/writing-rules.md): custom detectors
- [docs/guides/output-formats.md](docs/guides/output-formats.md): text and JSON schemas
- [docs/REFERENCE.md](docs/REFERENCE.md): complete trace and Surface CLI/schema reference
- [docs/guides/window.md](docs/guides/window.md): `neutron window`
- [docs/guides/binder-attribution.md](docs/guides/binder-attribution.md): Binder service maps, templates, and catalogs
- [docs/guides/frida-integration.md](docs/guides/frida-integration.md): Frida plus BPF workflows
- [docs/case-studies/wallet-boundary.md](docs/case-studies/wallet-boundary.md): redacted wallet boundary report example
- [docs/devices/pixel8pro.md](docs/devices/pixel8pro.md): verified device profile
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): what neutron cannot see
- [docs/ROADMAP.md](docs/ROADMAP.md): planned work
- [CHANGELOG.md](CHANGELOG.md): version history

## License

Apache-2.0. See [LICENSE](LICENSE).
