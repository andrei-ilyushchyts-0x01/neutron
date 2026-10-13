# Native and system subjects

Use this guide after the authenticated installation and explicit-device selection
in [Quickstart](quickstart.md). Commands below run in the already authorized
privileged device shell. Do not provision root, change SELinux, or relax private
output checks to make a capture succeed. Keep the userspace binary and BPF object
from the same build: task-exit semantics now require BPF ABI **3**, event size 257.
The historical qualification rows in [PRODUCT](../../PRODUCT.md) do not qualify
this new ABI, another firmware, or every endpoint on a device.

## Select and resolve

First run `neutron doctor --json` and `neutron doctor --smoke --json`. Missing BTF
and inaccessible BTF are different results. Stackless operation still requires
every mandatory check. A failed prerequisite is a failed capture prerequisite.

Create a new private session directory under the installation's owned runs
directory. `SESSION` below must identify that directory, not an existing run.
Keep it private when retrieving artifacts; captures can contain device data.

```sh
umask 077
SESSION=/data/local/share/neutron/runs/native-example-001
mkdir -m 700 "$SESSION"
neutron surface scan --output "$SESSION/inventory.json"
neutron surface services --input "$SESSION/inventory.json"
```

Choose one selector; quote it as a single argument:

| Selector | Meaning |
|---|---|
| `pid:123@456` | PID 123 with `/proc/123/stat` starttime 456 |
| `pid:123@456,124@789` | Explicit bounded set of process incarnations |
| `pid:123` | Resolve the current incarnation; do not follow PID reuse |
| `exe:/system/bin/keystore2` | Exact executable path; restart can resolve a new incarnation |
| `binder:android.system.keystore2.IKeystoreService/default` | Exact endpoint and Binder transport with proven process ownership |
| `vndbinder:NAME`, `hwbinder:NAME` | Exact endpoint on that transport |
| `package:com.example.probe`, `uid:1000` | Package or explicit UID selection |

UID selection deliberately includes all matching processes. Prefer an executable
or pinned PID when only one of several system-UID daemons is intended. A service
with absent, candidate, or ambiguous ownership fails narrowly. No automatic UID
fallback occurs, and service ownership alone never proves a Binder invocation.
Root identity requires boot ID, PID/starttime, UID/GID, executable and domain.
The root cap is `--max-processes` (1–1024). Existing `--pid`, `--package`, and
`--root-uid` retain their legacy scope behavior.

## Capture, then verify and explain

In this example, stimulus is a separately reviewed, bounded action against the
selected subject. A marker merely bounds observation; it does not prove that the
stimulus caused every contemporaneous event.

```sh
SUBJECT=exe:/system/bin/keystore2
neutron trace --subject "$SUBJECT" --follow-binder --max-processes 16 \
  --run-dir "$SESSION/capture" --max-output-size 32mb \
  --control-socket "$SESSION/control.sock" &
TRACER=$!
```

Wait for the tracer's ready message and socket, checking that `TRACER` is still
alive. Then use the same control socket for both boundaries:

```sh
neutron mark native-check --phase start --control-socket "$SESSION/control.sock"
# Execute the reviewed stimulus once; record its own identity and outcome.
neutron mark native-check --phase end --control-socket "$SESSION/control.sock"
kill -INT "$TRACER"
wait "$TRACER"
neutron evidence verify "$SESSION/capture"
neutron graph "$SESSION/capture/capture.ndjson" --subject "$SUBJECT" --format json
neutron report "$SESSION/capture/capture.ndjson" --subject "$SUBJECT" \
  --output "$SESSION/report.md"
neutron surface scan --capture "$SESSION/capture/capture.ndjson" \
  --output "$SESSION/surface.json"
neutron surface reachable --input "$SESSION/surface.json" --from-subject "$SUBJECT"
```

For the existing single-command observation workflow, use
`neutron surface scan --observe 10s --from-subject "$SUBJECT" --output FILE`.
It observes first and collects static identities afterward. Static collection
alone is not execution evidence. Check capture and collector health separately.

PID, executable, package and UID roots use bounded process-identity collection;
PID selectors read only the requested processes. Service roots retain the full
exact-ownership inventory. A changed
incarnation produces `subject_resolution`; a resolution gap disables admission,
emits `subject_unavailable`, and makes health incomplete. The next resolved
incarnation starts with cleared causal context. Pinned PID subjects expire rather
than selecting a reused PID. Proc reads can race events; refreshed userspace
identity is not a kernel-enforced incarnation cookie. Permission failures never
justify reusing cached FD paths or symbols. Root domains are recorded; unsafe
follower-domain admission flags remain rejected.

## Native stimulus evidence

`examples/native-stimulus.rs` is a bounded, disposable private-file create/dup/close
collector. Build with `cargo build --release --example native-stimulus --target
aarch64-unknown-linux-musl`. It prints a dry run unless `--execute` is supplied:

```sh
native-stimulus --output-dir "$SESSION/stimulus" --attempts 3
# After creating the owned mode-0700 stimulus directory:
native-stimulus --output-dir "$SESSION/stimulus" --attempts 3 --execute
```

It records identity before and after every attempt and writes a discriminated
`stimulus-identity.json` plus `stimulus-observation.json`. It does **not** call a
service or demonstrate driver reachability. For a service experiment, adapt only
the reviewed procedure and outcome; keep the same per-attempt identity checks.

Import a service experiment into a verified surface/coverage bundle containing
the exact `service:TRANSPORT:ENDPOINT` subject:

```sh
neutron evidence import --run-dir COVERAGE_RUN --id native-check \
  --input stimulus-observation.json --stimulus-identity stimulus-identity.json \
  --claim observed-edge --subject-id service:binder:ENDPOINT \
  --imported-from reviewed-native-procedure \
  --claim-scope '{"procedure":"REVIEWED_PROCEDURE","caller":"native_root","attempt_count":1}'
neutron evidence verify COVERAGE_RUN
neutron evidence report COVERAGE_RUN
```

The scope must exactly match the artifact's procedure, caller and attempt count.
Use `native_root` for UID 0, `native_shell` for UID 2000, and `native_process` for
other UIDs. The report separates stimulus identity from observer privilege and
the run's declared attacker capability. Native claims cannot be labeled
`ordinary_installed_app`. App evidence v1 remains readable; v2 supports either
`android_app` or `native_process`, never mixed fields. Boot, starttime, binary
hash, executable, UID/GID, SELinux context, capabilities and optional build ID
must remain identical across attempts. Verification proves internal integrity,
not trusted origin. A negative observation requires complete health and its
explicitly bounded procedure; it never establishes global unreachability.

## Contract changes

| Contract | Current meaning |
|---|---|
| BPF ABI 3 / `task_exit` v1 | One task exited; status unavailable; other threads may remain |
| `process_exit` v2 | Proc reconciliation confirmed death; tracepoint status remains unknown |
| `binder_call` v2 | `delivery_phase=dequeued`; `queue_latency_us` measures send to dequeue |
| Legacy `completed`, `latency_us` | Compatibility spellings of dequeue and queue latency, never handler completion |
| Graph v3 | `kind` separates process membership from causal parents; absent/invalid confidence stays unknown |
| Capture scope v2 / subject v1 | Initial resolved roots plus marker/admission records; v1 inputs remain readable |
| Finding scope fields | Scenario, trace, generation and process starttime; untagged observations stay untagged |
| `fd_binding_source`, `fd_binding_confidence` | Captured binding or proc readlink, always best effort; resource joins stay candidate |

Detached diff, report, summarize and bundle verification share the ordered
scenario validator. Events outside a paired interval, reused trace/generation,
changed roots and invalid timestamps cannot support conclusions. Legacy positive
rendering still works with warnings. Unknown causal links are not traversed as
proven reachability. State caps, identity failures and shutdown discards are
visible in final health.

## Qualification gate: partial Android evidence

The existing host suite is designed to compile and run `examples/native-lifecycle-probe.c`, using real
`pthread_exit` and a worker sentinel. This checks the userspace reconciliation
oracle; it does not qualify Android BPF loading or continued worker capture.

For each already provisioned authorized device, retain exact firmware, kernel,
boot, observer privileges, subject identities, tool/BPF/probe hashes, target list,
command lines and all raw outputs. Build the C probe with the target NDK compiler,
`-std=c11 -Wall -Wextra -Werror -pthread`. Use one fresh owned mode-0700 directory
per mode and repeat, and only the disposable probe PID for termination tests.

The October device run observed worker capture after leader exit; its unmarked
capture was not sealable. See [the device record](../devices/pixel8pro.md#october-2026-abi-3-validation).
The full repeated qualification below remains required.

The probe takes `DIRECTORY [leader-exit|worker-exit|exit0|exit7|wait-signal]`.
It writes `leader-ready` and waits at most 30 seconds for the controller to create
`start`. Attach a bounded trace by exact probe executable, open a scenario, then
create `start`. In leader-exit mode require `worker-after-leader` in both the
filesystem and trace after leader exit; worker-exit also writes
`leader-after-worker`. Require exactly one confirmed teardown and unknown
tracepoint status. For wait-signal, send SIGTERM only to the recorded probe PID
after rechecking its starttime. Close the scenario, interrupt/wait the tracer,
retrieve the bundle using the explicit device serial, and verify it on the host.

Run three repeats of lifecycle, native FD and a separately reviewed Binder
procedure with an independent request/outcome oracle. Exercise FD replacement,
exec/CLOEXEC, close_range and permission-denied identity refresh; use synthetic
PID reuse on the host instead of changing system-wide PID limits. Require no
stale path/symbol reuse. Retain untraced and traced wall/CPU/RSS measurements,
event counts and every loss counter. Check that all owned processes/sockets are
gone before removing only the newly created session directory. A failed check,
dirty build, or preflight refusal is not successful qualification. No new support
row, HAL/driver claim, reply-latency claim or performance claim is established by
this implementation.
