# neutron

Evidence-grade Android boundary mapping and bounded causal tracing for rooted,
authorized research devices.

**Map ownership. Trace delegation. Preserve the evidence.** Neutron identifies
which process, SELinux domain, and executable owns a service or HAL, then
records bounded Binder-to-syscall/ioctl/device handoffs with explicit capture
health and provenance. See [PRODUCT.md](PRODUCT.md) for command maturity and
non-goals.

[![kernel: 6.1+](https://img.shields.io/badge/kernel-6.1%2B_aarch64-blue.svg)](#requirements)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Authorized testing only. Use this on devices and applications you own or have
explicit written permission to assess. See [SECURITY.md](SECURITY.md).

## Core Workflows

1. Map a target service/HAL set and create a static run bundle with
   `neutron surface coverage --run-dir ...`.
2. Trace one authorized scenario with `neutron trace --run-dir ...`, producing
   a bounded live run bundle only after clean shutdown.
3. Verify either bundle with `neutron evidence verify`, then generate a report
   from the verified capture.

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

Documented historical baseline (current 1.5 release-SHA runtime revalidation
is still required; see [PRODUCT.md](PRODUCT.md#support-matrix)):

- Google Pixel 8 Pro (`husky`)
- Android 16
- kernel `6.1.145-android14-11`
- KernelSU, run with `adb -s SERIAL shell "su -c '...'"`.

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
VERSION=1.5.0-rc.1
TAG="v${VERSION}"
REPO=andrei-ilyushchyts-0x01/neutron
ASSET="neutron-agent-v${VERSION}-android-aarch64.tar.zst"

curl -LO "https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
curl -LO "https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS.minisig"

# Obtain this public key through the separately documented trusted channel;
# never replace it with a key downloaded beside the release assets.
: "${NEUTRON_RELEASE_PUBKEY:?Set the separately verified minisign public-key path}"
gh attestation verify "$ASSET" --repo "$REPO"
gh attestation verify SHA256SUMS --repo "$REPO"
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig \
  -p "$NEUTRON_RELEASE_PUBKEY"
sha256sum -c SHA256SUMS --ignore-missing

tar --zstd -xf "$ASSET"
cd "neutron-agent-v${VERSION}-android-aarch64"
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
./install-android.sh
```

The attestation binds the archive and checksum manifest to this repository's
release workflow. Minisign authenticates that manifest with the independently
trusted Neutron release key; only then does SHA-256 bind the archive bytes to
it. Do not extract or run the root installer if any of these checks fails.

The Android archive includes `packs/`, both BPF objects, schemas, and the probe
APK. Its installer stages files in a unique temporary directory, installs the
agent under `/data/local/share/neutron`, makes all final content root-private,
verifies all SHA-256 digests before replacing an existing install, and removes
staging files on success or failure. Review the archive's `INSTALL.md` before
running it.

Run the preflight:

```bash
"${ADB[@]}" shell \
  "su -c '/data/local/share/neutron/neutron-agent doctor'"
```

Expected result: `doctor` should exit successfully. Warnings about SELinux
enforcing or masked kallsyms are normal on Pixel; privilege/BTF/tracefs/raw
syscall failures must be fixed before tracing.

### Option B: Build And Deploy From Source (Advanced)

```bash
git clone https://github.com/andrei-ilyushchyts-0x01/neutron.git
cd neutron
export ANDROID_SERIAL=USB_SERIAL

# Builds both BPF objects and the Android aarch64 userspace binary, then pushes
# them and stages the built-in packs on the explicitly selected device.
./build.sh
```

## First Capture

Package-scoped capture is usually the best first run. It works even when the
app has many processes because Android package names resolve to UIDs.

All device commands below require the explicit serial and write into a
root-owned private directory. Direct `adb pull` cannot read those files, so
retrieve them through a bounded root `cat`:

```bash
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
NEUTRON=/data/local/share/neutron/neutron-agent
REMOTE_RUN=/data/local/share/neutron/runs/first-capture

"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --raw --no-findings --no-logcat \
  --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.app \
  --rate-limit 200 \
  --max-output-size 64mb \
  --attacker-capability not_tested \
  --run-dir ${REMOTE_RUN}'"

LOCAL_RUN=first-capture
install -d -m 0700 "$LOCAL_RUN"
set -o pipefail
for artifact in capture.ndjson capture.health.json manifest.json SHA256SUMS; do
  case "$artifact" in
    capture.ndjson) limit=68157440 ;;
    *) limit=4194304 ;;
  esac
  timeout 60s "${ADB[@]}" exec-out \
    "su -c 'cat ${REMOTE_RUN}/${artifact}'" \
    | head -c "$((limit + 1))" > "$LOCAL_RUN/${artifact}.part"
  (( $(wc -c < "$LOCAL_RUN/${artifact}.part") <= limit ))
  mv -- "$LOCAL_RUN/${artifact}.part" "$LOCAL_RUN/${artifact}"
done

./neutron evidence verify "$LOCAL_RUN"
```

Read the bound health sidecar first:

```bash
jq . "$LOCAL_RUN/capture.health.json"
```

`manifest.json` binds the exact capture, health, BPF identity, tool identity,
device boot, and effective capture scope. `SHA256SUMS` detects mutation of any
bundle member. A killed or pre-final trace has neither a valid manifest nor a
checksum seal and must fail `evidence verify`.

If `output_cap_hit` is `true`, the main NDJSON reached
`--max-output-size`. The sidecar still preserves the final telemetry record,
but run health is `incomplete` and absence-of-event claims are non-conclusive.
The example also uses rate limiting, so its claim scope is intentionally
restricted even when transport health is complete.

Important: if `--match-package` resolves to a shared/system UID such as `1000`,
neutron prints a warning. In that case the trace is UID-scoped, not
package-isolated. Add `--match-pid`, `--match-comm`, fd filters, or a
service-specific scenario before making package-specific claims.

## Common Capture Recipes

These examples reuse `ADB`, `NEUTRON`, and `REMOTE_RUN` from the first-capture
setup above. Create a separate mode-`0700` remote directory for each real run.

### Trace One Running PID For Findings

```bash
PID="$("${ADB[@]}" shell pidof -s com.example.app | tr -d '\r')"
[[ "$PID" =~ ^[0-9]+$ ]] || { echo "invalid target PID" >&2; exit 1; }

"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid ${PID} \
  --profile security \
  --resolve-paths'"
```

Without `--raw`, neutron emits rule-engine findings only.

### Save Raw NDJSON For One Package

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --json --raw --no-findings \
  --match-package com.example.app \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output ${REMOTE_RUN}/app.health.json \
  --output ${REMOTE_RUN}/app.ndjson'"
```

### Rotate Long Captures Instead Of Stopping At A Cap

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --json --raw --no-findings \
  --match-package com.example.app \
  --rate-limit 1000 \
  --rotate-output-size 250mb \
  --output ${REMOTE_RUN}/app.ndjson'"
```

This writes `${REMOTE_RUN}/app.ndjson`, `${REMOTE_RUN}/app.ndjson.1`, and so
on. `--rotate-output-size` and `--max-output-size` are mutually exclusive.

### Camera / Media HAL Scenario

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --profile driver-harness \
  --driver-pack media-hal,kgsl \
  --json --raw --no-findings \
  --capture matched+context=1s \
  --rate-limit 2000 \
  --max-output-size 250mb \
  --health-output ${REMOTE_RUN}/camera.health.json \
  --output ${REMOTE_RUN}/camera.ndjson'"
```

Start the capture, exercise Camera, then stop neutron with Ctrl-C or
`timeout -s INT`.

### Binder Crash Correlation

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --profile kernel-lpe \
  --driver-pack binder \
  --binder \
  --json --raw \
  --capture matched+context=2s \
  --max-output-size 250mb \
  --health-output ${REMOTE_RUN}/binder.health.json \
  --output ${REMOTE_RUN}/binder.ndjson'"
```

Review callee-crash windows:

```bash
./neutron window binder.ndjson \
  --anchor binder_call:callee_crashed \
  --around 3s \
  --summary
```

### Content Provider Research

Trace a probing app plus the provider package UID resolved from an authority:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --json --raw --no-findings \
  --match-package com.example.probe \
  --match-android-provider content://com.android.contacts/contacts \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output ${REMOTE_RUN}/provider.health.json \
  --output ${REMOTE_RUN}/provider.ndjson'"
```

### System App Sweep

Print the built-in sweep recipe:

```bash
./neutron recipes system-app-sweep
```

The recipe runs one package at a time, records `monkey` status, attach status,
line/byte counts, and a per-package health sidecar. Treat low line counts as
"needs a targeted trigger", not as safe.

## Map The Android Surface

Version 1.5 provides a deterministic on-device surface snapshot. A static scan
needs no trace capture:

```bash
SURFACE_DIR=/data/local/share/neutron/runs/manual-surface
"${ADB[@]}" shell "su -c 'install -d -m 0700 ${SURFACE_DIR}'"
"${ADB[@]}" shell "su -c '${NEUTRON} surface scan \
  --output ${SURFACE_DIR}/surface.json'"
"${ADB[@]}" exec-out "su -c 'cat ${SURFACE_DIR}/surface.json'" > surface.json
```

Import an existing causal NDJSON capture, or observe one package/UID live:

```bash
neutron surface scan --capture capture.ndjson --output surface.json

"${ADB[@]}" shell "su -c '${NEUTRON} surface scan \
  --observe 30s --from-package com.example.app \
  --output ${SURFACE_DIR}/surface.json'"
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
neutron surface diff baseline.json ota.json --output surface-diff.json
```

## Run A Reproducible Research Pack

Install the companion probe before running a pack. It requires JDK 17, Android
SDK platform 35 with Build Tools 35.0.0, and Gradle 8.10.2. From the repository
root, point Gradle at those tools, run the probe's unit test and debug build,
then install and verify the package:

```bash
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
  "platforms;android-35" "build-tools;35.0.0"

cd probe-app
./gradlew --version # must report Gradle 8.10.2 and JVM 17
./gradlew --no-daemon testDebugUnitTest assembleDebug
"${ADB[@]}" install -r app/build/outputs/apk/debug/app-debug.apk
"${ADB[@]}" shell pm path dev.neutron.probe
cd ..
```

`pm path` must print a `package:` path before continuing. Use the probe only
through `neutron research`; its `DUMP`-protected receiver accepts exactly the
pack's typed action and parameters, not arbitrary broadcasts or shell commands.

After installing the companion APK and built-in packs, preflight a pack without
stimulating hardware:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} research --pack keymint \
  --probe-package dev.neutron.probe'"
```

This exits `2` and writes a private `authorization_required` report. Add
`--authorized-use` only on a device you are authorized to assess:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} research --pack camera \
  --param camera_id=0 --probe-package dev.neutron.probe --authorized-use'"
```

Packs are data-only and compile into allowlisted trace flags plus one of seven
typed companion actions. See [the research-pack guide](docs/guides/research-packs.md).

`reachable` means observed causal reachability through capture-sourced
`root_process`, `binder`, `served_by`, successful `open`, `mmap`, or `ioctl`,
and resource-acquisition relations (`mapping`, `mapped_from`, `allocation`,
`allocated_from`). It does not solve SELinux, VINTF, manifest permissions, or
theoretical Binder access. Failed or incomplete syscalls are retained as
non-traversable `syscall_attempt` evidence. Lifecycle evidence (`munmap` and
`release`), `process_exit`, `crash`, AVC, and static `proc_fd` relations also
enrich the capture without creating reachability.

## Build And Minimize A Regression Testcase

After an opted-in `--harness-capture`, extract one complete event and build
the generated replay with the pinned static Android target:

```bash
neutron harness extract capture.ndjson --event-id 42 --output testcase
neutron harness build testcase
```

The build writes `testcase/replay` plus a hashed `build.json`. Replay and
minimization still require an explicit physical USB serial, package, reviewed
runner, and `--authorized-use`. Built-in minimization oracles include `crash`,
`reboot`, `timeout`, `nonzero`, and `signal`; custom argv-only oracles remain
supported. See [the harness guide](docs/guides/harness.md).

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

The host `neutron` binary analyzes files after they are retrieved from the
root-private device run directory.

Summarize syscall/ioctl activity:

```bash
./neutron summarize \
  --by comm,syscall,ret_class \
  --top 30 \
  app.ndjson

./neutron summarize \
  --by comm,ioctl_family,ioctl_name,ret_class \
  --top 50 \
  camera.ndjson
```

Cut a small window around crashes, findings, markers, PIDs, or comm names:

```bash
./neutron window app.ndjson \
  --anchor crash \
  --before-events 100 \
  --after-events 50
```

Compare two scenario captures:

Each input must end in exactly one structurally valid, complete
`capture_health` record and contain the same exactly paired live scenario
name/root contract. Only events carrying that scenario's exact
`scenario_id`/`trace_id` binding participate in the delta; setup and teardown
noise outside the markers is excluded. If capture used a separate health
sidecar, first build the local input as shown in **First Capture**.

```bash
./neutron diff \
  baseline.ndjson \
  test.ndjson \
  --by comm,syscall,ret_class \
  --top 40
```

Bracket a live scenario with markers:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --package com.example.app \
  --follow-binder --follow-services --follow-hal \
  --max-depth 4 --max-processes 64 \
  --output ${REMOTE_RUN}/app.ndjson'" &

"${ADB[@]}" shell "su -c '${NEUTRON} mark login --phase start'"
# trigger the scenario
"${ADB[@]}" shell "su -c '${NEUTRON} mark login --phase end'"
```

The tracer assigns the marker timestamp and causal IDs. To keep the old
append-only behavior without changing a live scenario, pass `mark --output`.
Paired markers prove an observation interval and operator label; they do not
prove that an external stimulus actually executed or that an unobserved path
is unreachable. Preserve the stimulus harness as separate external evidence.

Render the causal scenario as Mermaid, or emit the versioned JSON graph used
by downstream tools:

```bash
neutron graph app.ndjson \
  --root-package com.example.app \
  --format mermaid \
  --output flow.md

neutron graph app.ndjson \
  --root-package com.example.app \
  --collapse-syscalls \
  --format json \
  --output graph.json
```

JSON output uses `neutron.causal-graph/v1`. Collapsing never merges syscalls
across causal parents or trace IDs.

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
"${ADB[@]}" shell service list -p > service-list-p.txt

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
"${ADB[@]}" shell "su -c '${NEUTRON} doctor'"
```

Bad quoting can make `su` run the wrong payload. The trace path performs the
same privilege check as `doctor` and exits early before BPF load.

### `another neutron capture appears active`

Only run one capture at a time. neutron holds a lock at
`/data/local/share/neutron/runtime/neutron.capture.lock` by default. Use `--capture-lock off`
only for advanced debugging.

### `--match-package ... resolved to shared/system UID`

The capture is UID-scoped. For UID `1000` and other platform/shared UIDs,
events can come from other processes sharing that UID. Add narrower filters or
trace the service/PID that actually handles the scenario.

### `output_cap_hit: true`

The primary output reached `--max-output-size`. Use the health sidecar to audit
the capture, then rerun with a narrower scope, lower rate, or
`--rotate-output-size`.

### `ioctl_family:"binder_or_dma_buf"`

Binder and DMA-BUF share an ioctl magic value. neutron disambiguates with
positive FD evidence when available. Without a conclusive Binder FD hint, the
family remains `binder_or_dma_buf`; path-like text alone does not prove either
family. Inspect `data`, `fd_kind`, and `fd_path` together.

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
cargo xtask build-ebpf --stacks release
```

Android build:

```bash
cargo build --release --target aarch64-unknown-linux-musl --bin neutron
```

Plain `cargo test --workspace` is not the supported gate because the no_std BPF
crate is not host-testable in the normal Rust test harness.

## Release Assets

To exercise packaging locally with unpublished, explicitly unauthenticated
assets, install `qemu-aarch64` (the `qemu-user` package on Debian/Ubuntu) so the
packager can execute and measure the static Android agent. A non-x86_64 build
host additionally needs `x86_64-linux-gnu-gcc`, `qemu-x86_64`, and a matching
x86_64 sysroot (Debian/Ubuntu packages: `gcc-x86-64-linux-gnu`, `qemu-user`,
and `libc6-dev-amd64-cross`). Override the defaults only with
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` and
`NEUTRON_X86_64_SYSROOT`:

```bash
# Run from a clean committed tree. Never publish this unsigned local output.
scripts/package-release.sh
```

The script writes:

- `dist/v<VERSION>/neutron-v<VERSION>-linux-x86_64.tar.zst`
- `dist/v<VERSION>/neutron-agent-v<VERSION>-android-aarch64.tar.zst`
- `dist/v<VERSION>/neutron-v<VERSION>-source.tar.gz`
- `dist/v<VERSION>/SBOM.spdx.json`
- `dist/v<VERSION>/provenance.json`
- `dist/v<VERSION>/SHA256SUMS`

The signed-tag workflow is the only supported producer for publishable assets.
It rebuilds the exact signed tag, requires a stable probe signing identity,
minisign-signs `SHA256SUMS`, emits a GitHub build-provenance attestation, and
uploads the complete `dist/v<VERSION>/` directory as a workflow artifact.
The protected release configuration must pin
`NEUTRON_APPROVED_PROBE_CERT_SHA256` and the raw
`NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY`; packaging rejects a different APK
certificate or a signature that cannot be verified by that approved key.
Supplying `SIGNING_KEY` to the local packager automatically enables the same
strict identity requirements.

Required GitHub release contents from that verified workflow artifact:

- attach both runtime archives, the source archive, `SBOM.spdx.json`,
  `provenance.json`, `SHA256SUMS`, and `signatures/SHA256SUMS.minisig`
- rely on GitHub's automatic source zip/tarball, or attach the explicit
  source tarball from `dist/v<VERSION>/`
- include the verified device profile and the `neutron doctor` result used for
  the release
- document the binary SHA-256 and BPF object SHA-256

`provenance.json` is build metadata, not a signed attestation. A signed Git tag
authenticates source, not independently built binaries. Verify both the GitHub
attestation for the workflow-built subjects and the minisign signature over
`SHA256SUMS` before using root-device artifacts.

Example maintainer flow:

```bash
VERSION="$(awk -F '"' '/^version =/ { print $2; exit }' Cargo.toml)"
TAG="v${VERSION}"

git tag -s "$TAG" -m "neutron $TAG"
git push origin "$TAG"

# Wait for `.github/workflows/release.yml`, then download its artifact without
# merging files from any local build. Verify the downloaded GitHub attestation
# and the minisign signature with the separately distributed release public key.
COMMIT="$(git rev-list -n 1 "$TAG")"
RUN_ID="$(gh run list --workflow release.yml --commit "$COMMIT" \
  --status success --limit 1 --json databaseId --jq '.[0].databaseId')"
test -n "$RUN_ID"
mkdir "release-artifact-$COMMIT"
gh run download "$RUN_ID" --name "neutron-${TAG}-${COMMIT}" \
  --dir "release-artifact-$COMMIT"
cd "release-artifact-$COMMIT"
for subject in ./*.tar.* ./SHA256SUMS ./SBOM.spdx.json ./provenance.json; do
  gh attestation verify "$subject" \
    --repo andrei-ilyushchyts-0x01/neutron
done
minisign -Vm SHA256SUMS -x signatures/SHA256SUMS.minisig \
  -p /path/to/separately-verified-neutron-release.pub
sha256sum --check --strict SHA256SUMS

# External publication still requires explicit maintainer approval.
gh release create "$TAG" \
  ./neutron-v${VERSION}-linux-x86_64.tar.zst \
  ./neutron-agent-v${VERSION}-android-aarch64.tar.zst \
  ./neutron-v${VERSION}-source.tar.gz \
  ./SBOM.spdx.json \
  ./provenance.json \
  ./SHA256SUMS \
  ./signatures/SHA256SUMS.minisig \
  --verify-tag \
  --title "neutron ${TAG}" \
  --notes "Host and Android release assets for neutron ${TAG}."
```

Publishing a tag or release changes GitHub state. Run those commands only after
maintainers have approved the tag, notes, exact workflow SHA, and assets.

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
- [docs/ROADMAP.md](docs/ROADMAP.md): capability status, external gates, and planned work
- [CHANGELOG.md](CHANGELOG.md): version history

## License

Apache-2.0. See [LICENSE](LICENSE).
