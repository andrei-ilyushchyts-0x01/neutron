# JSON contracts for Neutron agent integrations

AI agents should select a schema using the document's declared version, validate
its shape, then evaluate health, scope and provenance separately. These are
Neutron CLI and artifact contracts, not model function definitions or an MCP API.
Additive fields remain compatible within a schema major; a new major requires an
explicit consumer update. Some artifacts use `type` rather than a `schema` field.

## Current consumer contracts

| Schema file | Agent use |
|---|---|
| [neutron.self-info-v1.schema.json](neutron.self-info-v1.schema.json) | Identify source revision, target, toolchain and default ABI. |
| [neutron.provenance-v1.schema.json](neutron.provenance-v1.schema.json) | Bind release binaries, BPF objects, approved signer identity and measured build environment. |
| [neutron.doctor-v1.schema.json](neutron.doctor-v1.schema.json) | Read prerequisites, object compatibility, smoke observations and cleanup. |
| [neutron.subject-v1.schema.json](neutron.subject-v1.schema.json) | Retain subject selection and process incarnations. |
| [neutron.run-manifest-v1.schema.json](neutron.run-manifest-v1.schema.json) | Enumerate bundle members, source identities and capture scope. |
| [neutron.capture-lifecycle-v1.schema.json](neutron.capture-lifecycle-v1.schema.json) | Inspect startup readiness and teardown; missing artifacts are not success. |
| [neutron.capture-health-v1.schema.json](neutron.capture-health-v1.schema.json) | Inspect losses, unknowns, effective scope and claim restrictions. |
| [neutron.capture-passport-v1.schema.json](neutron.capture-passport-v1.schema.json) | Bind derived views to exact capture bytes and bounded claim eligibility. |
| [neutron.causal-graph-v3.schema.json](neutron.causal-graph-v3.schema.json) | Consume nodes, edges, confidence, evidence basis and passport. |
| [neutron.binder-review-v1.schema.json](neutron.binder-review-v1.schema.json) | Review candidate endpoints and input record references. |
| [neutron.binder-services-v1.schema.json](neutron.binder-services-v1.schema.json) | Supply reviewed service labels bound to capture/boot/build identity. |
| [neutron.surface-coverage-v1.schema.json](neutron.surface-coverage-v1.schema.json) | Evaluate target-specific ownership coverage and unresolved entries. |
| [neutron.evidence-verification-v1.schema.json](neutron.evidence-verification-v1.schema.json) | Read successful internal integrity verification; do not infer authenticity. |
| [neutron.evidence-report-v1.schema.json](neutron.evidence-report-v1.schema.json) | Consume an evidence-bundle report. |
| [neutron.external-evidence-v2.schema.json](neutron.external-evidence-v2.schema.json) | Import explicitly attributed external observations. |
| [neutron.stimulus-identity-v1.schema.json](neutron.stimulus-identity-v1.schema.json) | Bind a workload to its declared identity. |
| [neutron.native-stimulus-observation-v1.schema.json](neutron.native-stimulus-observation-v1.schema.json) | Read observations produced by a native stimulus. |
| [neutron.probe-identity-v1.schema.json](neutron.probe-identity-v1.schema.json) | Identify APK, signing certificate, SDK and attacker model. |

[Graph v2](neutron.causal-graph-v2.schema.json) and
[external evidence v1](neutron.external-evidence-v1.schema.json) remain available
for historical artifacts. Do not label graph v3 as v2 to satisfy an old consumer.

The run-manifest schema embeds its canonical capture-scope resource for offline
Draft 2020-12 validation. Shape validation does not replace `neutron evidence
verify RUN_DIR`, release signature verification, or semantic restrictions.
Preserve missing, unknown, candidate and inferred states when transforming data.
NDJSON contains typed records; consult [output formats](../docs/guides/output-formats.md)
for event fields rather than applying a single document schema to the entire stream.
