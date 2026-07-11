# AIDL Intelligence

Neutron maps Binder transaction codes only after an exact
`(callee_pid,target_node)` service mapping identifies one interface descriptor.
PID-only `service list`, `lshal`, and VINTF evidence remains candidate evidence
and never produces a method name.

## Build a catalog

Run indexing on the host with an AIDL compiler in `PATH`, an explicit
`--aidl-bin`, or an AOSP prebuilt:

```bash
neutron aidl index "$AOSP_ROOT" \
  --vendor-tree "$VENDOR_ROOT" \
  --output aidl-catalog.json
```

The `neutron.aidl-catalog/v1` output is deterministic: interfaces, versions,
provenance, and transaction codes are sorted; timestamps and absolute paths are
not written. The AIDL compiler validates each interface and its generated
transaction constants provide the numeric codes. Unsupported inputs are listed
in `diagnostics`; add `--strict` to make any diagnostic fatal.

## Trace and report attribution

Use the catalog with an exact service map:

```bash
neutron trace --binder \
  --binder-services binder-services.json \
  --aidl-catalog aidl-catalog.json \
  --json --raw --output capture.ndjson

neutron report capture.ndjson \
  --binder-services binder-services.json \
  --aidl-catalog aidl-catalog.json \
  --output report.md
```

Exact matches may add `interface_descriptor`, `method`, `aidl_version`, and
`catalog_source` to `binder_call`. Ambiguous matches add sorted
`service_candidates` and `interface_candidates` but no method. Unknown codes
remain numeric. `--binder-methods` remains a deprecated fallback; conflicting
catalog and legacy method names are rejected.

## Decode a complete KeyMint testcase

Parcel decoding is offline-only and accepts a complete, unblocked Binder
harness testcase:

```bash
neutron aidl decode testcase \
  --catalog aidl-catalog.json \
  --plugin keymint \
  --output decoded-aidl.json
```

The reference plugin supports the request parameters of
`IKeyMintDevice.generateKey(KeyParameter[])`. Unknown union variants are marked
unsupported instead of guessed. Byte arrays are emitted as length plus SHA-256;
`--show-sensitive-bytes` explicitly includes their hexadecimal contents.

The decoder validates blob hashes, lengths, Binder object offsets, descriptor,
transaction code, and catalog signature. It never follows captured addresses,
never rewrites the testcase, and refuses to place its output inside the
testcase directory. Ordinary Binder tracing still captures metadata only, not
Parcel bytes.
