# Security research packs

`neutron research` runs a sealed, data-only pack through validation, static
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

The new output directory is mode `0700`; files are `0600`. `pack.lock.json`
and the private `pack/` copy pin the exact bytes used by the child trace. The
remaining artifacts are `run.json`, `preflight.surface.json`, `capture.ndjson`,
`capture.health.ndjson`, `surface.json`, sanitized `stimulus.json`, and
`report.md`.

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
