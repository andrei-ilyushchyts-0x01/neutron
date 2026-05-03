# Contributing to neutron

Thanks for your interest. neutron is an Aya-based eBPF syscall tracer for
authorized Android security assessment. Targets kernel 6.1+ (Pixel 8 Pro /
Android 14 GKI).

For build setup, sync points, and the workflow for adding maps, syscalls,
and rules, see [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Reporting issues

Use the bug report / feature request / rule proposal templates under
[.github/ISSUE_TEMPLATE/](.github/ISSUE_TEMPLATE/).

## Pull requests

- `cargo fmt` must be clean (CI enforces).
- `cargo clippy --all-targets -- -D warnings` must pass.
- New rules need positive and negative tests in
  `neutron-rules/tests/engine.rs`.
- Userspace decoders / formatters need unit tests under `tests/`.

## Code of Conduct

This project adheres to the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache-2.0 license](LICENSE).
