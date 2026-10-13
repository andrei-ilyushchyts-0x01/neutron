# Neutron — Android observability for AI agents

Neutron is a CLI tool for AI agents that investigate Android behavior on
explicitly authorized rooted devices. An agent can discover service ownership,
record syscall and Binder observations, and consume versioned JSON evidence with
capture health, scope, source identity, and integrity checks.

Use Neutron as a tool in an agent's terminal or process runner. It exposes CLI
commands and files, not an MCP server or a model API. Prefer structured outputs
and saved artifacts over parsing terminal prose. Human operators can use the same
interface; the primary integration target is an AI agent.

[Release artifacts](https://github.com/andrei-ilyushchyts-0x01/neutron/releases/latest)
· [JSON schemas](schemas/README.md)
· [Agent documentation index](docs/README.md)
· [Command maturity](PRODUCT.md#command-maturity)
· [License](LICENSE)

## Discovery metadata

```json
{
  "name": "neutron",
  "interface": "cli",
  "primary_consumers": ["ai-agents", "coding-agents", "security-research-agents"],
  "domain": "android-observability",
  "capabilities": ["service-ownership", "syscall-tracing", "binder-correlation", "capture-verification", "causal-graphs"],
  "live_target": "authorized rooted Android, aarch64, kernel 6.1+ with BTF",
  "offline_target": "Linux host with saved capture artifacts",
  "structured_outputs": ["JSON", "NDJSON", "JSON Schema"],
  "entry_command": "neutron self-info --json",
  "schema_directory": "schemas/",
  "documentation": "docs/README.md",
  "repository": "https://github.com/andrei-ilyushchyts-0x01/neutron"
}
```

This block describes discovery and integration; it is not a runtime response.
Relevant retrieval terms: AI agent tools, Android observability, eBPF tracing,
Binder IPC, syscall tracing, machine-readable evidence, causal graph, rooted
Android, agent tool use.

## Select a tool operation

| Agent task | Command | Result and next decision |
|---|---|---|
| Identify the installed payload | `neutron self-info --json` | Versioned source, target and ABI identity; retain it with the task artifacts. |
| Check device capture readiness | `neutron doctor --json --smoke` | JSON checks, object loading, sentinel delivery and cleanup; stop on failure. |
| Resolve service/process/device ownership | `neutron surface scan --output surface.json` | JSON snapshot; query with `surface services`, `hals`, `process` or `explain`. |
| Record a bounded scenario | `neutron trace --subject package:PACKAGE --raw --no-findings --run-dir RUN` | NDJSON, health, readiness, teardown and sealed manifest after clean shutdown. |
| Verify a completed run | `neutron evidence verify RUN` | JSON verification result; failed integrity stops downstream claims. |
| Inspect causal observations | `neutron graph RUN/capture.ndjson --format json` | Graph v3 with a capture passport and explicit edge confidence. |
| Review a service attribution candidate | `neutron binder-map template RUN/capture.ndjson` | JSON review template; it is not an exact service map. |
| Compare equivalent scenarios | `neutron diff BASELINE TEST --by type` | Table, or nonzero exit with no delta when evidence is nonconclusive. |
| Produce an explanation | `neutron report RUN/capture.ndjson --output report.md` | Markdown with limitations and input record references; retain the source capture. |

Run `neutron COMMAND --help` before constructing an unfamiliar call. Live
`trace`, `doctor`, `mark` and `surface` contracts are PREVIEW. Stable offline
commands and experimental/deprecated surfaces are listed in [PRODUCT.md](PRODUCT.md).
Do not use deprecated `research` or `recipes` as the default agent entry point.

## Agent execution contract

1. Select one explicitly authorized device using `adb -s SERIAL`; do not infer
   permission to change device state from the ability to connect.
2. Verify release signatures and hashes before running binaries or the root
   installer. Record `self-info --json` and run `doctor --json --smoke` against
   the exact selected BPF object.
3. Choose a precise subject and a new private run directory. Native subjects
   support PID/starttime, executable, UID, package and exact service ownership;
   see [system subjects](docs/guides/system-subjects.md).
4. Launch the tracer as a supervised child and retain its PID. Wait for
   `readiness.json` to report `status: "ready"` and for its control socket.
   Start a named scenario with `mark --phase start`, execute the independently
   authorized stimulus, then use the matching `mark --phase end`.
5. Send SIGINT to the tracer process you launched, wait for completion, and run
   `evidence verify`. Do not read an active capture as a completed bundle.
6. Inspect health and effective scope before interpreting events. Prefer graph
   JSON plus schemas for decisions; use Markdown reports for concise context.
7. Return artifact paths, capture SHA-256, observed facts, confidence and remaining
   uncertainty to the parent agent. Keep raw device data private.

The following commands run in an authorized root shell **on the device**. Replace
`com.example.app` with a running authorized subject and use a fresh `RUN` each time:

```sh
N=/data/local/share/neutron/neutron-agent
RUN=/data/local/share/neutron/runs/agent-scenario-001
CONTROL=/data/local/share/neutron/runtime/agent-scenario-001.sock

"$N" self-info --json
"$N" doctor --json --smoke --object /data/local/share/neutron/neutron.bpf.elf

# Launch through the agent's supervised process runner; retain the tracer PID.
"$N" trace --subject package:com.example.app --follow-binder \
  --raw --no-findings --no-logcat --tombstone-dir "" --fdgraph-interval off \
  --max-output-size 64M --run-dir "$RUN" --control-socket "$CONTROL"

# While that process runs, after readiness, use a second root command channel.
"$N" mark agent-scenario --phase start --control-socket "$CONTROL"
# Execute the authorized stimulus here and retain its independent result.
"$N" mark agent-scenario --phase end --control-socket "$CONTROL"

# After SIGINT and successful tracer shutdown:
"$N" evidence verify "$RUN"
"$N" graph "$RUN/capture.ndjson" --format json --output "$RUN.graph.json"
"$N" report "$RUN/capture.ndjson" --output "$RUN.report.md"
```

The example disables logcat, tombstones and FD polling. Those omissions are part
of its observation scope. Do not silently retry with wider capture, elevated
privileges, disabled SELinux, or a different subject. Root-private artifacts need
an explicit root transfer channel; retain every manifest-listed member, including
`readiness.json` and `teardown.json`, and verify the transferred bundle again.

## Parse results and recover

| Observation | Agent response |
|---|---|
| Nonzero command exit | Retain stderr and artifacts. Fix the named prerequisite before a bounded retry; do not interpret partial stdout as success. |
| Doctor fails ABI, load, attach or delivery | Stop tracing. Select matching artifacts or a compatible, authorized environment. |
| Missing readiness or dead subject | Inspect the tracer error and process incarnation. Start a new run after resolving the cause. |
| `evidence verify` fails | Stop evidence interpretation. Inspect missing/mutated members; never repair the original capture to make verification pass. |
| Health is `incomplete`, `degraded` or `unknown` | Report observed positives with limitations. Do not make absence or full-coverage claims. |
| Health is complete but scope is restricted | Retain restrictions. Complete transport does not establish unfiltered coverage. |
| Diff refuses comparison | Return the refusal. Do not reinterpret an empty delta as equivalent behavior. |
| A Binder map is unreviewed or unbound | Keep service names as candidates; do not assign exact AIDL methods. |
| A causal edge is inferred or unknown | Preserve that confidence. Temporal proximity and process membership are not proof of async queue ownership. |

JSON commands expose their own versioned contracts; there is no universal
`status` envelope. Capture NDJSON is a typed event stream and ends with health
only after orderly finalization. `report`, `summarize` and `diff` are textual
views. Parse JSON by schema and field name, not display ordering.

A verified bundle proves internal consistency, not authenticity of every claimed
external observation. A syscall result is not an application policy decision.
A Binder dequeue is not handler completion. Missing events never prove safety,
unreachability, or absence of a vulnerability. Java/Kotlin control flow, full
Binder Parcel arguments and complete asynchronous causation are outside the
observed contract. See [observability](docs/guides/observability.md) and
[limitations](docs/LIMITATIONS.md).

## Install a verified release

Host prerequisites: `gh`, `minisign`, `sha256sum`, `tar`, `zstd` and `adb`. Obtain
the approved Minisign public key through an independently trusted channel.
This path requires artifacts with GitHub Actions attestations; a historical
locally built prerelease does not satisfy that policy.

```bash
set -euo pipefail
VERSION=1.6.1
TAG="v${VERSION}"
REPO=andrei-ilyushchyts-0x01/neutron
ASSET="neutron-agent-v${VERSION}-android-aarch64.tar.zst"
: "${NEUTRON_RELEASE_PUBKEY:?Set the independently trusted Minisign public-key path}"
: "${ANDROID_SERIAL:?Select one authorized USB device}"

gh release download "$TAG" --repo "$REPO" \
  --pattern "$ASSET" --pattern SHA256SUMS --pattern SHA256SUMS.minisig
gh attestation verify "$ASSET" --repo "$REPO"
gh attestation verify SHA256SUMS --repo "$REPO"
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -p "$NEUTRON_RELEASE_PUBKEY"
sha256sum --check --strict --ignore-missing SHA256SUMS

tar --zstd -xf "$ASSET"
cd "neutron-agent-v${VERSION}-android-aarch64"
# Review INSTALL.md and the root installer before deployment.
./install-android.sh
```

The installer checks packaged hashes and uses an explicit device, private staging
and `/data/local/share/neutron`. The companion APK is not installed automatically.
The release also contains a Linux host CLI, source archive, SBOM, provenance and
schemas. Select the host CLI for offline analysis; the Android agent needs root
only for live device operations.

## Device and build constraints

Live tracing requires rooted aarch64 Android, kernel 6.1+, readable BTF,
tracefs/bpffs and effective `CAP_BPF` plus `CAP_SYS_ADMIN` in the execution domain.
A preflight pass alone is not a qualification of every feature or firmware.
Use the release's signed device-validation summary for exact artifact/device
coverage and [PRODUCT.md](PRODUCT.md#support-matrix) for historical support rows.
The 1.6 development line has bounded Pixel 8 Pro / Android 17 observations;
other firmware and HAL/driver paths require separate evidence.

Source builds use the pinned Rust nightly, `bpf-linker`, an aarch64 cross-linker,
JDK 17, Android SDK 35 / Build Tools 35.0.0 and Gradle 8.10.2. See
[build instructions](docs/CONTRIBUTING.md). CI checks the workspace and release
contracts; device validation exercises the actual published payload. Repository
coding-agent guidance lives in [AGENTS.md](AGENTS.md).

Apache-2.0. Authorized assessment only; security reporting is described in
[SECURITY.md](SECURITY.md).
