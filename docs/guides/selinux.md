# SELinux-aware tracing

Neutron automatically tails bounded AVC records while tracing. The SELinux
source uses `logcat -T 0`, so records already buffered before capture startup
are not attributed to the new trace. It is disabled by `--no-logcat`.

Capture NDJSON on an authorized device:

```bash
adb shell su -c '/data/local/tmp/neutron trace \
  --package com.example.app --follow-hal --json --raw \
  --output /data/local/tmp/capture.ndjson'
```

Each observed decision is written as `type:"selinux_denial"`. `permissions`
is canonical; the compatibility `permission` field is present only for a
single permission. A permissive-domain AVC uses
`result:"allowed_permissive"` and does not claim that the operation was
blocked. A root process context may be exact; a process-wide context inherited
through Binder is inferred because it does not prove which Binder thread caused
the AVC. Capture health reports source availability plus parsed, malformed,
deduplicated, and out-of-scope counts.

Explain one event offline:

```bash
neutron selinux explain capture.ndjson --event-id 9182
neutron selinux explain capture.ndjson --event-id 9182 \
  --format json --output explanation.json
```

JSON output uses `neutron.selinux-explanation/v1`. Delegated paths are shown
only when the same trace contains exact Binder edges, exact service or HAL
attribution, and a successful exit-side syscall on the identical captured
path. Static topology, candidate attribution, inferred edges, failed syscalls,
and different paths are warnings rather than reachability evidence.

`--output` is opened as an owned, single-link regular file with mode `0600`.
Symlinks, hard links, public modes, and special files are rejected before the
verified descriptor is truncated.

Neutron explains the observed AVC tuple. It does not parse binary policy,
attribute source files or rules, infer `neverallow`, run `audit2allow`, or
recommend policy changes.
