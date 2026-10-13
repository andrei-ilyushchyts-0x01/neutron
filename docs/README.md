# Neutron documentation for AI agents

Use this index to load only the contract needed for the next tool call. Neutron
is an Android observability CLI for AI agents; it returns versioned JSON/NDJSON
and saved evidence artifacts. Start with the [agent execution contract](../README.md#agent-execution-contract)
and inspect installed command help before invoking a PREVIEW surface.

## Route by task

| Agent task | Load this document | Required outcome |
|---|---|---|
| Discover the tool and install it | [Root README](../README.md) | Verified artifact identity and explicit device selection. |
| Select an operation | [Product contract](../PRODUCT.md#command-maturity) | Command maturity and qualified scope. |
| Decode a structured result | [Schema index](../schemas/README.md) | Matching schema version; preserve unknowns and restrictions. |
| Understand evidence strength | [Observability](guides/observability.md) | Separate transport, scope, integrity and causal confidence. |
| Select a native/system process | [System subjects](guides/system-subjects.md) | PID incarnation or verified service ownership. |
| Execute the device workflow | [Quickstart](guides/quickstart.md) | Private run, orderly shutdown, complete transfer and verification. |
| Interpret Binder identities | [Binder attribution](guides/binder-attribution.md) | Reviewed capture binding; candidate labels remain candidates. |
| Inspect flags and event fields | [Reference](REFERENCE.md), [output formats](guides/output-formats.md) | Supported arguments and typed event interpretation. |
| Diagnose missing observations | [Limitations](LIMITATIONS.md), [BPF tracing](guides/bpf-tracing.md) | Explicit blind spots; no absence-as-safety inference. |
| Use independent workload evidence | [Probe contract](../probe-app/README.md) | Separate stimulus result and capture evidence. |
| Check device qualification | [Pixel 8 Pro notes](devices/pixel8pro.md), release validation summary | Matching build and payload hashes, not a model-name assumption. |
| Explain observed SELinux decisions | [SELinux](guides/selinux.md) | Attribution to observed events; no policy synthesis. |
| Maintain the implementation | [Architecture](ARCHITECTURE.md), [contributing](CONTRIBUTING.md), [AGENTS.md](../AGENTS.md) | Repository development workflow. |

## Minimal offline calls

```sh
neutron self-info --json
neutron evidence verify RUN_DIR
neutron graph RUN_DIR/capture.ndjson --format json --output graph.json
neutron report RUN_DIR/capture.ndjson --output report.md
neutron summarize RUN_DIR/capture.ndjson --by type
```

Only run analysis after successful bundle verification. Graph JSON carries a
capture passport; a detached analysis does not reverify the original run bundle.
Inspect health and scope before using a derived report. Nonzero exits are failures,
not empty successful observations. Keep stdout, stderr and return code separate.

## Specialized and compatibility documentation

Load these only when the task requires the corresponding capability:

- [Content providers](guides/android-content-provider.md), [security assessment](guides/security-assessment.md), [rule authoring](guides/writing-rules.md).
- [AIDL intelligence](guides/aidl-intelligence.md) and [harness replay](guides/harness.md): EXPERIMENTAL, with their own scope and authorization requirements.
- [Research packs](guides/research-packs.md) and [native mapping](guides/native-mapping.md): deprecated compatibility paths retained through 1.x.
- [Roadmap](ROADMAP.md): planned work is not an available tool capability.

Live capture requires an authorized rooted aarch64 Android device, kernel 6.1+
with BTF and the required BPF privileges. Host-side analysis uses saved artifacts.
Device support remains tied to the exact release qualification evidence.
