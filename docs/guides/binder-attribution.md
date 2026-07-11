# Binder Attribution

Neutron can observe Binder routing metadata at the kernel boundary. It can
pair caller-side and callee-side transactions into `type:"binder_call"` events
with fields such as `caller_pid`, `callee_pid`, `target_node`, `code`,
`latency_us`, and `status`.

The kernel does not provide a stable human service name for every
`(callee_pid,target_node)` pair. Neutron therefore uses two helper files:

- an exact service map for `(callee_pid,target_node) -> service`
- a candidate catalog for `callee_pid -> possible services`

The report treats these differently. Exact service-map entries are labels.
Catalog entries are candidates and are shown as candidates.

An optional descriptor-centric AIDL catalog maps transaction codes to methods
only after the exact service map proves the descriptor. See
[AIDL Intelligence](aidl-intelligence.md).

## Exact Service Map

Pass an exact map to either capture-time enrichment or report-time rendering:

```bash
neutron report app.ndjson \
  --binder-services binder-services.json \
  --output app-boundary-report.md
```

Format:

```json
{
  "1234": {
    "1": "android.hardware.security.keymint.IKeyMintDevice/default",
    "2": "android.security.IKeystoreService/default"
  }
}
```

The outer key is `callee_pid`. The inner key is `target_node`. Values are the
service/interface labels you have verified for that exact pair.

## Template Workflow

Use a capture to generate unresolved pairs:

```bash
neutron binder-map template app.ndjson \
  --output binder-services.template.json
```

The template contains only unresolved `binder_call` pairs and includes observed
transaction codes and status counts:

```json
{
  "1234": {
    "1": {
      "service": "",
      "observed_codes": {
        "7": 3
      },
      "status_counts": {
        "completed": 3
      }
    }
  }
}
```

Edit `service` values after you have verified them, then use the edited file as
`--binder-services`.

## Candidate Catalog

`service list -p` is useful but usually PID-only. It can say that a PID hosts
candidate services, but it normally cannot prove which service owns a specific
`target_node`.

Create a catalog:

```bash
adb shell service list -p > service-list-p.txt

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
