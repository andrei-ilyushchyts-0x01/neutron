# Repository Guidelines

## Project Structure & Module Organization

Neutron is a Rust 2021 workspace. The main CLI and library live in `src/`; formatters, decoders, event sources, and symbolizers are grouped in matching subdirectories. `neutron-common/` defines the packed event ABI shared by userspace and eBPF. `neutron-ebpf/` contains the `no_std` Aya programs, `neutron-rules/` owns YAML rules and their engine, and `xtask/` provides build/deploy automation. Put integration tests in `tests/`, rule-engine tests in `neutron-rules/tests/`, runnable probes in `examples/`, and user documentation in `docs/`.

## Build, Test, and Development Commands

The pinned nightly toolchain installs Rust targets; local cross-builds also need `bpf-linker`, `aarch64-linux-gnu-gcc`, and optionally `adb`.

- `cargo check --workspace --exclude neutron-ebpf` — fast host type check.
- `cargo test --workspace --exclude neutron-ebpf` — supported host test gate; plain workspace tests cannot run the BPF crate.
- `cargo fmt --all -- --check` — verify formatting.
- `cargo clippy --workspace --exclude neutron-ebpf --all-targets -- -D warnings` — reject lint warnings.
- `cargo xtask build-ebpf release` — produce `neutron.bpf.elf`.
- `./build.sh` — build release eBPF/userspace artifacts and deploy them when an ADB device is connected.

## Coding Style & Naming Conventions

Use `rustfmt` defaults and keep Clippy clean. Follow Rust conventions: `snake_case` for modules, functions, and tests; `PascalCase` for types; `SCREAMING_SNAKE_CASE` for constants and BPF map statics. Prefer small modules and existing workspace types. Changes to `SyscallEvent` must also update architecture documentation, formatters, decoders, and layout assertions; BPF map names must exactly match userspace lookups.

## Testing Guidelines

Add focused unit or integration coverage for behavior changes. Name tests after observable outcomes, such as `rejects_invalid_schema`. New rules require both positive and negative cases in `neutron-rules/tests/engine.rs`. BPF loading and attachment require manual validation on an authorized rooted Android device; document the device/kernel and command used in the PR.

## Commit & Pull Request Guidelines

Recent history uses short Conventional Commit subjects such as `feat: add causal graph tracing`, `fix: preserve candidate service attribution`, and `test: enforce surface mapper coverage`. Keep commits focused and imperative. PRs must complete the repository template: summarize what and why, select the change type, report verification, link relevant issues, and update `docs/` when interfaces or workflows change.

## Security & Responsible Use

Use Neutron only on systems you own or are authorized to assess. Do not commit credentials, private device data, or captured application output. Report project vulnerabilities through a private GitHub security advisory as described in `SECURITY.md`.
