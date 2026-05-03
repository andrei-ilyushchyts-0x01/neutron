# Contributing

## Build Environment

### Prerequisites

| Tool                                     | Purpose                                  | Install                                      |
|------------------------------------------|------------------------------------------|----------------------------------------------|
| `rustup` + `cargo`                       | Build everything                         | https://rustup.rs — **nightly** required (pinned via `rust-toolchain.toml`) |
| `bpf-linker`                             | Link Aya BPF programs                    | `cargo install bpf-linker`                   |
| `aarch64-linux-gnu-gcc`                  | Cross-linker for the musl userspace      | `apt install gcc-aarch64-linux-gnu` (or distro equivalent) |
| `adb`                                    | Deploy + run on device                   | Android SDK platform-tools                   |
| `rustup target add bpfel-unknown-none`   | BPF target                               | automatic via `rust-toolchain.toml`          |
| `rustup target add aarch64-unknown-linux-musl` | musl cross-compile target          | automatic via `rust-toolchain.toml`          |
| `rustup component add rust-src`          | BPF build-std                            | automatic via `rust-toolchain.toml`          |

The `rust-toolchain.toml` at the workspace root pins nightly and adds the
two required targets and `rust-src` automatically. You still need to
install `bpf-linker` manually.

There is no `clang` / `llvm-objdump` requirement — BPF programs are 100%
Rust in V1.

### Quick check (host, no cross-compile)

```bash
cargo check --workspace --exclude neutron-ebpf
```

This compiles against the host architecture to catch type errors quickly.
The resulting binary will not run on the device.

### Full build + deploy

```bash
./build.sh
```

Steps performed:

1. `cargo xtask build-ebpf release` — build Aya BPF programs to
   `neutron.bpf.elf`.
2. `cargo build --release --target aarch64-unknown-linux-musl --bin neutron`.
3. `adb push neutron.bpf.elf /data/local/tmp/`.
4. `adb push target/aarch64-unknown-linux-musl/release/neutron /data/local/tmp/`.

### Per-step builds

```bash
# BPF only (Rust → bpfel-unknown-none → neutron.bpf.elf):
cargo xtask build-ebpf           # debug
cargo xtask build-ebpf release   # release

# Userspace only:
cargo build --release --target aarch64-unknown-linux-musl --bin neutron

# Build everything via xtask:
cargo xtask build
cargo xtask deploy
```

## Critical Sync Points

### `SyscallEvent`

`neutron_common::SyscallEvent` (`#[repr(C, packed)]`, **241 bytes**) is the
single source of truth for the wire format. See
`neutron-common/src/lib.rs`. Both `neutron-ebpf` and the userspace loader
pull this type directly — there is no parallel C struct.

If you change the layout:

1. Edit `neutron-common/src/lib.rs`.
2. Update the field table in `docs/ARCHITECTURE.md`.
3. Update any new-field handling in `src/format/json.rs`,
   `src/format/text.rs`, and `src/decode/`.
4. Run `cargo test --workspace --exclude neutron-ebpf` — the
   `size_of::<SyscallEvent>()` assertion guards size invariants.

### Map names

Map names are the Rust static identifiers in `neutron-ebpf/src/main.rs`.
Aya does **not** lowercase them. The userspace loader looks them up by
exact name.

| Static (BPF side)  | Userspace lookup                              |
|--------------------|-----------------------------------------------|
| `FILTER_MAP`       | `bpf.map_mut("FILTER_MAP")`                   |
| `EVENTS`           | `bpf.take_map("EVENTS")`                      |
| `INFLIGHT`         | (read inside BPF only)                        |
| `SYSCALL_FILTER`   | `bpf.map_mut("SYSCALL_FILTER")`               |
| `PID_WHITELIST`    | `bpf.map_mut("PID_WHITELIST")`                |
| `WATCH_FDS`        | `bpf.map_mut("WATCH_FDS")`                    |
| `STACK_TRACES`     | `bpf.map("STACK_TRACES")` (read-only)         |

### `FILTER_MAP` layout

`FILTER_MAP[FILTER_KEY_PID]` (0) = target PID, `FILTER_MAP[FILTER_KEY_ACTIVE]` (1)
= syscall whitelist active flag. Constants in `neutron-common/src/lib.rs`.

## Adding a New BPF Map

1. Add `#[map] static MY_MAP: Type<K, V> = Type::with_max_entries(N, 0);`
   in `neutron-ebpf/src/main.rs`.
2. Aya creates the map automatically at load time — no manual
   `bpf_create_map()` call needed.
3. In the userspace loader, access via `bpf.map_mut("MY_MAP")` +
   `Type::try_from(...)`.
4. Document the map in the table in `docs/ARCHITECTURE.md`.

## Adding a New Syscall

1. If the syscall has meaningful arguments to capture, extend
   `capture_syscall_data()` (or the equivalent dispatch) in
   `neutron-ebpf/src/main.rs`.
2. Add the syscall number → name mapping in `syscall_name()`
   (`src/decode/`).
3. If the exit event needs userspace post-processing (e.g. fd-to-path
   readlink), add a case in the event loop in `src/main.rs`.
4. Update the syscall table in `docs/REFERENCE.md`.

## Adding a New BPF Program

1. Add a `#[tracepoint]` (or `#[kprobe]`) function in
   `neutron-ebpf/src/main.rs`.
2. In `src/main.rs`, in `main()`, call the matching attach helper
   (`attach_tracepoint(...)` or the kprobe equivalent).
3. Add any new event types or routing to `src/format/json.rs` and
   `src/format/text.rs`.

## Verifier Errors

If `prog.load()` fails with `EACCES`, run with `--verbose` and Aya will
emit the verifier log to stderr. Common causes on kernel 6.1.x:

- **Variable-size reads**: `bpf_probe_read_user_buf` length must be a
  constant or proven by the verifier.
- **Stack overflow**: BPF stack limit is still 512 bytes. `SyscallEvent`
  is 241 bytes — keep additional locals slim.
- **Pointer leaks**: pointers from `bpf_probe_read_user` cannot be passed
  back to other helpers without a bounds check.

## Testing

Userspace decoders, formatters, and the rule engine have unit and
integration tests:

```bash
cargo test --workspace --exclude neutron-ebpf
```

The BPF-load + on-device path has no automated test suite. Validation is
on-device:

```bash
# Default mode (rule-engine findings only):
adb shell su -c '/data/local/tmp/neutron --pid <PID>'

# Raw events with NDJSON:
adb shell su -c '/data/local/tmp/neutron --pid <PID> --raw --no-findings --json'

# Security profile + binder + stacks:
adb shell su -c '/data/local/tmp/neutron --pid <PID> \
    --profile security --binder --stacks'
```

The `neutron-spike` binary (`src/bin/spike.rs`) is a low-level diagnostic
that loads the BPF object, attaches the three programs, and dumps a few
raw events. Useful for debugging Aya / verifier / attach issues:

```bash
adb shell su -c '/data/local/tmp/neutron-spike \
    --object /data/local/tmp/neutron.bpf.elf'
```

Expected output:

```
[OK] Ebpf::load succeeded
[OK] trace_sys_enter loaded + attached to raw_syscalls/sys_enter
[OK] trace_sys_exit loaded + attached to raw_syscalls/sys_exit
...
[DONE] events=N lost=0
```
