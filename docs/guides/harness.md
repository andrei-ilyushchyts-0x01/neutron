# Capture, minimize, and replay

The harness turns one captured ioctl or Binder event into an auditable regression
testcase. It is for authorized testing on a physical USB-connected Android device.
It does not synthesize values, addresses, boundary cases, heap sprays, or exploit
primitives.

## Capture

Capture is opt-in and must be scoped to a package or one concrete PID. A file
output is required because replay resources are stored next to it.

```sh
neutron --package com.example.app \
  --harness-capture \
  --schema-pack ./device-schema.json \
  --output capture.ndjson
```

Large values are written by SHA-256 to `capture.ndjson.blobs/`. Each relevant
NDJSON event receives an additive `harness_ref`. The limits are 64 KiB per Binder
Parcel, 1 MiB per resource, and 4 MiB per event. A short read, unknown pointer,
unknown Binder object, missing adapter, or limit violation is recorded as blocked;
Neutron never presents a partial capture as replayable.

Ioctl schema descriptors may declare pointer resources with `pointers` entries:

```json
{
  "field": "items",
  "pointee_layout": "sample.item",
  "length_field": "items_bytes",
  "direction": "in_out"
}
```

Use exactly one of `length_field` and `length_expression`. Expressions support
captured scalar field names, integer literals, parentheses, and checked `+ - * /`.

## Extract

```sh
neutron harness extract capture.ndjson --event-id 42 --output testcase
```

Extraction validates duplicate IDs, resource sizes, blob hashes, and the strict
`harness_ref` schema. It follows causal parent spans and FD provenance and writes:

- `metadata.json`, `resources.json`, and `input.bin`
- content-addressed `blobs/`
- standalone `replay.rs`
- argv-only `runner.json`
- manual `setup.sh` and safety-focused `README.md`

`setup.sh` is documentation; Neutron never executes it. Resolve every blocked
resource before replay. Then review `replay.rs` and cross-build it with the
fixed static Android target:

```sh
neutron harness build testcase
```

The command requires the pinned `aarch64-unknown-linux-musl` Rust target. It
rejects symlinked or oversized source/output artifacts, verifies that the
result is an AArch64 ELF without a dynamic interpreter, caps it at 64 MiB, and
writes `testcase/replay` mode `0700`. `build.json` uses
`neutron.harness/v1` and records the target, compiler, source/binary SHA-256,
and binary size.

Recorded Binder handles are never reused. Binder callback objects require an
explicit adapter; service handles require a reacquisition adapter in the runner.

## Replay

```sh
neutron harness replay testcase \
  --serial USB_SERIAL \
  --package com.example.app \
  --runner runner.json \
  --max-runs 1 \
  --authorized-use
```

Replay refuses network ADB transports and emulators. Before every run it checks
the explicit serial, build fingerprint, boot identity, package UID, and SELinux
domain. The generated `runner.json` uses `transport:"adb"`: Neutron validates a
fixed set of regular assets, stages them below a generated
`/data/local/tmp/neutron-harness-*` directory, applies a device-side timeout,
executes argv without `sh -c`, and removes the staging directory. ADB runners do
not retain evidence or install Neutron there; the path is disposable replay
staging only. ADB runners do not accept prepare/recover hooks; old or custom
`transport:"host"` runners keep
direct host argv semantics. Every command runs in a dedicated process group;
timeout or output overflow kills the group, including descendants. Standard
output and error are capped at 1 MiB each. The default timeout is 30 seconds and
the hard cap is 1000 runs. Every attempt overwrites `run-result.json` with a distinct
completed, crash, non-zero, reboot, transport-loss, timeout, hook-failure,
identity-drift, recovery-failure, or oracle-error result. `signal` is present
when the host can recover the terminating signal. A normal exit status such as
`1` is `nonzero`, not `crash`.

Recovery is attempted at most once: wait for the same USB serial and
`sys.boot_completed=1`, re-check identity, then run bounded recovery hooks.

## Minimize

```sh
neutron harness minimize testcase \
  --serial USB_SERIAL \
  --package com.example.app \
  --runner runner.json \
  --oracle crash \
  --max-runs 64 \
  --authorized-use
```

Built-in oracles are `crash`, `reboot`, `timeout`, `nonzero`, and `signal`.
The signal oracle additionally requires `--signal SIGSEGV` (or a number in
`1..=64`). `nonzero` accepts a normal non-zero result or a signal crash, while
`crash` accepts only an actual signal/process disappearance classified as a
crash. Infrastructure failures are never accepted as reproduction.

An argv-only external oracle remains available:

```sh
neutron harness minimize testcase \
  --serial USB_SERIAL \
  --package com.example.app \
  --runner runner.json \
  --oracle-command ./oracle \
  --oracle-arg expected-signature \
  --authorized-use
```

The external oracle receives `run-result.json` as its final argument. Exit `0`
means reproduced, `1` means not reproduced, and `2+` is an oracle error.

Deterministic ddmin always processes captured mutable regions and trailing
buffer bytes. It processes causal steps, Binder transactions, or timing delays
only when the selected runner explicitly declares the matching
`capabilities` value (`causal_steps`, `binder_transactions`, or
`timing_delays`). The generated ioctl runner declares none because it does not
consume those metadata fields. Candidates only delete existing elements,
replace captured bytes with zero, or shorten a trailing region. The source
testcase is left intact; accepted output is written under
`testcase/revisions/revision-N/` with a manifest and candidate log.

Neutron does not generate raw Binder or timing replay adapters. A custom
runner may advertise those capabilities only when it actually consumes the
corresponding fields; otherwise minimization deliberately leaves them alone.
