# Binder Attribution

Neutron can observe Binder routing metadata at the kernel boundary. It can
pair caller-side and callee-side transactions into `type:"binder_call"` events
with fields such as `caller_pid`, `callee_pid`, `target_node`, `code`,
`latency_us`, and `status`.

The kernel does not provide a stable human service name for every
`(callee_pid,target_node)` pair. Neutron therefore uses two helper files:

- an exact service map for `(callee_pid,target_node) -> service`
- a candidate catalog for `callee_pid -> possible services`

In 1.6, exact labels require a reviewed map bound to capture or live process
identity. Legacy PID/node maps remain readable as candidates. Candidate catalogs
never establish a descriptor or exact method.

An optional descriptor-centric AIDL catalog maps transaction codes to methods
only after the exact service map proves the descriptor. See
[AIDL Intelligence](aidl-intelligence.md).

## Reviewed service map

Generate a review document from the actual capture:

```sh
neutron binder-map template capture.ndjson --output binder-review.json
```

The `neutron.binder-review/v1` output records the capture hash, boot/build identity,
endpoint candidates, observed codes/status counts and up to 16 input record
references per endpoint. Multiple candidate names are a conflict to investigate,
not a choice the tool makes automatically. The template is not an exact map.

After independently verifying each endpoint, export this reviewed format:

```json
{
  "schema": "neutron.binder-services/v1",
  "context": {
    "capture_sha256": "<64 lowercase hex digits from the review document>",
    "boot_id": "<captured boot ID>",
    "fingerprint": "<captured build fingerprint>",
    "process_starttimes": {"1234": 45678},
    "review_evidence": "<retained evidence establishing each PID/node/service pair>"
  },
  "services": {"1234": {"7": "android.example.IService/default"}}
}
```

```sh
neutron report capture.ndjson --binder-services reviewed-services.json --output report.md
```

Offline use requires matching capture hash, boot and build. Live use requires the
same boot/build and matching nonzero starttimes for every listed PID; starttime
is rechecked at lookup so PID reuse cannot inherit exactness. Offline review may
leave `process_starttimes` empty, in which case live use fails. Node identity can
change within a process: review evidence must cover the endpoint's actual lifetime.

Duplicate endpoint keys and conflicting normalized PID/node spellings are rejected.
A captured exact label conflicting with the supplied reviewed map is also rejected.
Existing unversioned maps are candidate annotations and cannot authorize AIDL method
resolution. Unknown/candidate labels in captures remain explicitly marked.

## Candidate Catalog

`service list -p` is useful but usually PID-only. It can say that a PID hosts
candidate services, but it normally cannot prove which service owns a specific
`target_node`.

Create a catalog:

```bash
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
"${ADB[@]}" shell service list -p > service-list-p.txt

neutron binder-map service-list \
  --input service-list-p.txt \
  --output binder-catalog.json
```

Then use it in the report:

```bash
neutron report app.ndjson \
  --binder-catalog binder-catalog.json \
  --output app-boundary-report.md
```

When no exact service map entry exists, the report falls back in this order:

1. `service` already present in the NDJSON event
2. exact `--binder-services` map
3. raw `callee_pid/target_node/code` with candidate services from catalog
4. raw `callee_pid/target_node/code`

## Limitations

- A PID catalog is not exact service attribution.
- PIDs can be reused; collect `service list -p` close to the capture window.
- `target_node` values are kernel Binder handles, not stable API names.
- Transaction `code` values need the corresponding AIDL interface to interpret.
- Neutron does not decode arbitrary Binder Parcel payloads.
- A boundary report can show that a handoff happened. It cannot prove the
  Java/Kotlin branch that caused it or a remote attestation verdict.
