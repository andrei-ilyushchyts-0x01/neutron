#!/usr/bin/env bash
set -uo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
failures=0

run_test() {
    local name=$1
    if "$name"; then
        echo "ok - $name"
    else
        echo "not ok - $name" >&2
        failures=$((failures + 1))
    fi
}

contains() {
    rg -Fq -- "$2" "$1"
}

dated_toolchain_omits_prebuilt_bpf_target() {
    local toolchain="$root/rust-toolchain.toml"
    contains "$toolchain" 'channel = "nightly-2026-07-15"' &&
        ! contains "$toolchain" 'bpfel-unknown-none'
}

build_requires_android_serial_before_cargo() {
    local script="$root/build.sh" serial_line cargo_line
    serial_line=$(rg -n --no-heading 'ANDROID_SERIAL' "$script" | head -n 1 | cut -d: -f1)
    cargo_line=$(rg -n --no-heading '^[[:space:]]*cargo[[:space:]]' "$script" | head -n 1 | cut -d: -f1)

    [[ -n "$serial_line" && -n "$cargo_line" && "$serial_line" -lt "$cargo_line" ]] &&
        rg -q -- '-s[[:space:]]+"?\$\{?ANDROID_SERIAL' "$script"
}

release_package_declares_complete_payload() {
    local script="$root/scripts/package-release.sh" required
    for required in \
        'neutron-v${VERSION}-linux-x86_64' \
        'neutron-agent-v${VERSION}-android-aarch64' \
        'neutron.bpf.elf' \
        'neutron-stacks.bpf.elf' \
        'neutron-probe.apk' \
        'man/man1/neutron.1' \
        'SBOM.spdx.json' \
        'provenance.json'; do
        contains "$script" "$required" || return 1
    done
}

ci_runs_for_release_lines_and_assembles_probe() {
    local workflow="$root/.github/workflows/ci.yml"
    rg -q '(^|[[:space:],\[])dev([[:space:],\]]|$)' "$workflow" &&
        contains "$workflow" 'release/**' &&
        rg -q '^[[:space:]]*workflow_dispatch:' "$workflow" &&
        rg -q 'assemble(Debug|Release|Research)' "$workflow" &&
        contains "$workflow" 'tests/release_contract.sh'
}

current_abi_docs_match_257_byte_contract() {
    local contributing="$root/docs/CONTRIBUTING.md"
    local architecture="$root/docs/ARCHITECTURE.md"

    contains "$contributing" 'SyscallEvent` (`#[repr(C, packed)]`, **257 bytes**)' &&
        ! rg -q 'SyscallEvent.*241|is 241 bytes' "$contributing" &&
        ! rg -q 'SyscallEvent.*\(241\)' "$architecture"
}

security_policy_has_private_only_reporting() {
    local policy="$root/SECURITY.md"
    contains "$policy" 'private security advisory' &&
        ! rg -qi 'regular issue|public issue|\[security\]' "$policy" &&
        ! contains "$policy" 'will be added in a follow-up release'
}

product_contract_labels_every_command() {
    local product="$root/PRODUCT.md" command
    [[ -f "$product" ]] || return 1
    for required in STABLE PREVIEW EXPERIMENTAL 'Non-goals'; do
        contains "$product" "$required" || return 1
    done
    for command in \
        trace doctor window summarize diff report binder-map mark graph surface \
        recipes ioctl harness aidl research native-map ghidra-export selinux; do
        contains "$product" "\`neutron $command\`" || return 1
    done
}

run_test dated_toolchain_omits_prebuilt_bpf_target
run_test build_requires_android_serial_before_cargo
run_test release_package_declares_complete_payload
run_test ci_runs_for_release_lines_and_assembles_probe
run_test current_abi_docs_match_257_byte_contract
run_test security_policy_has_private_only_reporting
run_test product_contract_labels_every_command

exit "$failures"
