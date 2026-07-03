# Android Content-Provider Research Recipe

This recipe is for authorized Android security research where you need
low-noise evidence around `ContentResolver` / content-provider access:
direct reads, wrapped reads, caller-vs-provider behaviour, and negative
evidence.

The same workflow is available from the binary:

```bash
neutron recipes android-content-provider
```

## Goals

- Trace one probing app plus one provider UID without broad system noise.
- Compare direct vs wrapped provider reads with `summarize` and `diff`.
- Bracket external stimuli with markers and cut reviewable windows.
- Avoid accidental Binder/global trace floods.

## Resolve Scope

Prefer package names for the app under test and provider authorities for
the content provider:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --json --raw --no-findings \
  --no-logcat --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.probe \
  --match-android-provider content://com.android.contacts/contacts \
  --max-output-size 250mb \
  --output /data/local/tmp/provider_probe.ndjson'
```

`--match-package` runs on-device and resolves the package to its UID via
`cmd package` / `pm`, then uses the same BPF UID prefilter as
`--match-uid`. `--match-android-provider` accepts a bare authority or a
`content://authority/path` URI, resolves it through
`dumpsys package providers`, and adds the provider package UID to the
same BPF UID prefilter.

Use `--rotate-output-size 250mb` instead of `--max-output-size 250mb`
for unattended captures that should continue across bounded files. The
segments are named `provider_probe.ndjson`, `provider_probe.ndjson.1`,
`provider_probe.ndjson.2`, and so on. For marker-bracketed workflows,
prefer a single capped file: `neutron mark --output <file>` appends to
the path you name, not to whichever rotated segment is current.

For platform or shared providers where authority resolution is blocked or
ambiguous, add their UID explicitly:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 \
  --json --raw --no-findings \
  --no-logcat --fdgraph-interval off --lookback-events 0 \
  --match-package com.example.probe \
  --match-uid 10094 \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/provider_probe.ndjson'
```

Use `cmd package list packages -U | grep <name>` or
`dumpsys package providers` when you need to confirm a provider mapping
manually.

## Bracket Scenarios

Run the tracer in one shell, then add markers around each stimulus:

```bash
adb shell su -c '/data/local/tmp/neutron mark direct_avatar \
  --phase start --output /data/local/tmp/provider_probe.ndjson'

# Trigger direct provider read in the app.

adb shell su -c '/data/local/tmp/neutron mark direct_avatar \
  --phase end --output /data/local/tmp/provider_probe.ndjson'
```

Repeat with a second marker name for the wrapped or mediated path:

```bash
adb shell su -c '/data/local/tmp/neutron mark wrapped_avatar \
  --phase start --output /data/local/tmp/provider_probe.ndjson'

# Trigger wrapped provider read.

adb shell su -c '/data/local/tmp/neutron mark wrapped_avatar \
  --phase end --output /data/local/tmp/provider_probe.ndjson'
```

The tracer writes output with append-safe semantics, so marker lines are
safe to append to the live capture file.

## Review

Summarize high-level syscall shape:

```bash
adb shell /data/local/tmp/neutron summarize \
  --by comm,syscall,ret_class \
  --top 30 /data/local/tmp/provider_probe.ndjson
```

Cut windows around each scenario:

```bash
adb shell /data/local/tmp/neutron window \
  /data/local/tmp/provider_probe.ndjson \
  --anchor marker:direct_avatar --around 3s \
  > direct_avatar_windows.ndjson

adb shell /data/local/tmp/neutron window \
  /data/local/tmp/provider_probe.ndjson \
  --anchor marker:wrapped_avatar --around 3s \
  > wrapped_avatar_windows.ndjson
```

Compare direct vs wrapped windows:

```bash
adb shell /data/local/tmp/neutron diff \
  --by comm,syscall,ret_class \
  --top 40 \
  direct_avatar_windows.ndjson wrapped_avatar_windows.ndjson
```

For quick host-side review, pull the capture and run the same
post-processors locally.

## Binder Context

Binder tracing is useful when provider access crosses process boundaries,
but it is high-volume under `--pid 0`.

Use Binder only when you need transaction metadata:

```bash
adb shell su -c '/data/local/tmp/neutron \
  --pid 0 --binder \
  --json --raw --no-findings \
  --match-package com.example.probe \
  --match-android-provider com.android.contacts \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --output /data/local/tmp/provider_binder.ndjson'
```

`type:"binder_call"` lines are synthesized by the global Binder
correlator and may include caller/callee context outside a strict
`--match-*` expectation. If you only want raw filtered events, disable
correlation with:

```bash
--binder-inflight 0
```

## Interpretation Limits

Neutron gives syscall, fd, eBPF, crash, and Binder metadata evidence. It
does not prove Java/Kotlin method-level control flow, app authorization
branches, or full Binder Parcel contents. Pair traces with static review,
app logs, or instrumentation when making content-provider authorization
conclusions.
