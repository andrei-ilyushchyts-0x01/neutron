# Shipped schemas

This directory contains the machine-readable contracts shipped with Neutron.
Schema filenames are stable; additive fields remain backward-compatible within
the same schema major version.

- `neutron.self-info-v1.schema.json` — build and default BPF ABI identity.
- `neutron.provenance-v1.schema.json` — measured host/agent/BPF release identity, toolchain, signer approval, and artifact hashes.
- `neutron.run-manifest-v1.schema.json` — static-surface and live-trace identity, provenance, BPF/capture scope, side effects, and health.
- `neutron.surface-coverage-v1.schema.json` — target-scoped service/HAL ownership evidence.
- `neutron.external-evidence-v1.schema.json` — typed evidence imported from an external probe.
- `neutron.probe-identity-v1.schema.json` — APK, signing-certificate, SDK, and attacker-model identity.
- `neutron.evidence-verification-v1.schema.json` — successful run-bundle verification result.
- `neutron.capture-health-v1.schema.json` — final capture health record and tri-state failure details.
- `neutron.doctor-v1.schema.json` — tracepoint, object ABI, and bounded runtime-smoke evidence.
