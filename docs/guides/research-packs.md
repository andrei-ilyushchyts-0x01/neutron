# Security research packs

`neutron research` runs a validated, data-only pack through static
surface preflight, one scoped child trace, one typed companion stimulus,
postflight correlation, and a Markdown report.

```text
neutron research --pack NAME|PATH
  [--scenario NAME] [--param KEY=VALUE ...]
  [--duration DURATION] [--output DIR]
  [--probe-package PACKAGE] [--authorized-use]
```

Without `--authorized-use`, Neutron performs validation and read-only preflight,
writes the artifact set, skips permission changes and stimulus, and exits `2`.
Other exit codes are `0` complete, `1` validation/runtime failure, `3`
unsupported prerequisites, and `4` degraded capture health.

Built-ins are `keymint`, `gpu`, `camera`, `media-codec`, `bluetooth`, `wifi`,
and `usb`. Camera, Bluetooth, and Wi-Fi grants are limited by the compiled
registry and are revoked only when the current run granted them. Radios are
never enabled. USB selection is automatic only when the companion sees one
non-hub device; otherwise pass `--param usb_device_id=...`.

## Companion and authorized run

Install the minimal `dev.neutron.probe` companion before running a built-in
stimulus. Its build, unit-test, installation, and verification procedure is in
[probe-app/README.md](../../probe-app/README.md). The only companion selector
is `--probe-package`; there is no generic companion action or arbitrary
broadcast interface.

On hardware you are authorized to assess, a minimal KeyMint run is:

```bash
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
NEUTRON=/data/local/share/neutron/neutron-agent
RUN=/data/local/share/neutron/runs/keymint-$(date -u +%Y%m%dT%H%M%SZ)

"${ADB[@]}" shell "su -c '$NEUTRON research --pack keymint \
  --authorized-use --probe-package dev.neutron.probe --output $RUN'"
"${ADB[@]}" shell "su -c 'cat $RUN/run.json; cat $RUN/stimulus.json; \
  tail -n 1 $RUN/capture.health.ndjson'"
```

Without `--authorized-use`, that same command must end at the safe
`authorization_required` preflight. `--authorized-use` is an explicit
authorized-use acknowledgement, not a permission to enable radios, select an
ambiguous USB device, or run arbitrary code from a pack.

Before a temporary permission grant, the runner checks the package's runtime
state with `dumpsys package <package>`; it uses `pm grant` only for a compiled
action permission that was not already granted. Cleanup revokes only grants
made by that run. Android builds that do not provide `cmd package
check-permission` are therefore supported.

Research child traces use the causal follower's built-in coordinator transit
limits for `servicemanager` and `system_server`. Domain allow/deny flags are
rejected in 1.5 because they cannot be enforced at the first-event BPF
admission boundary; pack runs do not inject those rejected flags or claim an
unobserved pre-attach filter.

The new output directory is mode `0700`; files are `0600`. `pack.lock.json`
and the private `pack/` copy pin the exact bytes used by the child trace. The
remaining artifacts are `run.json`, `preflight.surface.json`, `capture.ndjson`,
`capture.health.ndjson`, `surface.json`, sanitized `stimulus.json`, and
`report.md`.

Read `run.json`, `stimulus.json`, and the final `capture.health.ndjson` line
together. `complete` with `degraded:false` is a clean capture. `unsupported`
is a safe prerequisite result; it is not proof of unreachability. `degraded`
and `failed` runs are diagnostic evidence, not release validation.
`causal_admission_boundary_exit` is an informational volume counter for an
exit that began before dynamic causal admission, including an already-active
sibling Binder thread; unlike an ordinary `inflight_lookup_missed`, it does
not set `degraded:true`.

Local packs must be owned by root or the current effective user, must not be
group/world writable, and cannot contain symlinks, nested paths, traversal,
unknown schema fields, duplicate IDs, oversized components, or a stale
SHA-256 content hash. Packs cannot contain executable code, shell commands, or
arbitrary trace argv.

The pack schema is `neutron.research-pack/v1`. Its content hash and private
copy provide run reproducibility, not publisher identity or a cryptographic
trust chain. A public/community registry therefore still requires an explicit
signing, key-rotation, review, and ownership policy.

CI validates the Rust pack engine and the Android companion probe's unit
tests. Hardware stimulus, capture completeness, permission restoration, and
reboot/crash recovery remain manual gates on an explicitly authorized device;
the repository does not claim a built-in pack is validated on every vendor
firmware merely because host CI passes.

The dated Pixel 8 Pro results, including clean KeyMint/GPU/Media Codec/
Bluetooth evidence and the Wi-Fi, USB, and Camera caveats, are recorded in
[the device profile](../devices/pixel8pro.md#authorized-device-release-evidence-2026-07-11).
