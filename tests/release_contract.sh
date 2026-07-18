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
    cargo_line=$(rg -n --no-heading 'exec cargo xtask deploy --serial "\$ANDROID_SERIAL"' "$script" | head -n 1 | cut -d: -f1)

    [[ -n "$serial_line" && -n "$cargo_line" && "$serial_line" -lt "$cargo_line" ]]
}

unwrapped_builds_cannot_claim_clean_provenance() {
    local build_rs="$root/build.rs" script="$root/build.sh"
    contains "$build_rs" 'unwrap_or_else(|| "true".to_string())' &&
        contains "$script" 'git status --porcelain --untracked-files=normal' &&
        contains "$script" 'NEUTRON_BUILD_GIT_COMMIT' &&
        contains "$script" 'NEUTRON_BUILD_GIT_DIRTY=false'
}

xtask_deploy_and_demo_require_explicit_serial() {
    local xtask="$root/xtask/src/main.rs"
    contains "$xtask" 'cargo xtask deploy --serial SERIAL' &&
        contains "$xtask" 'cargo xtask demo --serial SERIAL' &&
        contains "$xtask" 'command.args(["-s", serial]);' &&
        [[ $(rg -c 'let serial = parse_serial\(args' "$xtask") -eq 2 ]] &&
        [[ $(rg -c 'Command::new\("adb"\)' "$xtask") -eq 1 ]]
}

release_package_declares_complete_payload() {
    local script="$root/scripts/package-release.sh" required
    for required in \
        'neutron-v${VERSION}-linux-x86_64' \
        'neutron-agent-v${VERSION}-android-aarch64' \
        'neutron.bpf.elf' \
        'neutron-stacks.bpf.elf' \
        'neutron-probe.apk' \
        'probe-metadata.json' \
        'man/man1/neutron.1' \
        'SBOM.spdx.json' \
        'provenance.json'; do
        contains "$script" "$required" || return 1
    done
}

release_sbom_and_provenance_include_dependency_and_build_inputs() {
    local package="$root/scripts/package-release.sh"
    local sbom="$root/scripts/generate-sbom.mjs"
    local provenance="$root/scripts/generate-provenance.mjs"
    contains "$package" 'cargo metadata --locked --format-version 1' &&
        contains "$sbom" 'metadata.resolve?.nodes' &&
        contains "$sbom" 'gradleGraph.components' &&
        contains "$sbom" 'relationshipType: "DEPENDS_ON"' &&
        contains "$sbom" 'licenseDeclared: pkg.license || "NOASSERTION"' &&
        contains "$provenance" 'bpf_linker:' &&
        contains "$provenance" 'gradle_distribution_sha256:' &&
        contains "$provenance" 'android_build_tools:' &&
        contains "$provenance" 'runner_image_version:' &&
        contains "$provenance" 'identity_sha256'
}

release_sbom_uses_resolved_gradle_graph_and_validates_spdx() {
    local package="$root/scripts/package-release.sh"
    local build_gradle="$root/probe-app/build.gradle"
    local wrapper="$root/probe-app/gradle/wrapper/gradle-wrapper.properties"
    local sbom="$root/scripts/generate-sbom.mjs"
    local validator="$root/scripts/validate-spdx.mjs"

    [[ -f "$validator" ]] &&
        rg -q '^distributionSha256Sum=[0-9a-f]{64}$' "$wrapper" &&
        contains "$build_gradle" 'tasks.register("neutronResolvedDependencies")' &&
        contains "$package" 'neutronResolvedDependencies' &&
        contains "$package" 'GRADLE_DEPENDENCIES=' &&
        contains "$package" 'node scripts/validate-spdx.mjs "$DIST/SBOM.spdx.json"' &&
        contains "$sbom" 'gradleGraph.components' &&
        ! contains "$sbom" 'const gradleComponents = [' &&
        node "$root/tests/sbom_contract.mjs"
}

release_install_docs_authenticate_before_root_execution() {
    local document attestation_line minisign_line extract_line install_line
    for document in "$root/README.md" "$root/docs/guides/quickstart.md"; do
        attestation_line=$(rg -n -m1 'gh attestation verify' "$document" | cut -d: -f1)
        minisign_line=$(rg -n -m1 'minisign -Vm SHA256SUMS' "$document" | cut -d: -f1)
        extract_line=$(rg -n -m1 'tar --zstd -xf' "$document" | cut -d: -f1)
        install_line=$(rg -n -m1 '\./install-android\.sh' "$document" | cut -d: -f1)
        [[ -n "$attestation_line" && -n "$minisign_line" &&
           -n "$extract_line" && -n "$install_line" ]] || return 1
        [[ "$attestation_line" -lt "$extract_line" &&
           "$minisign_line" -lt "$extract_line" &&
           "$extract_line" -lt "$install_line" ]] || return 1
        contains "$document" 'NEUTRON_RELEASE_PUBKEY'
    done
}

release_signing_identity_is_fail_closed() {
    local package="$root/scripts/package-release.sh"
    local identity="$root/scripts/release-identity.sh"
    local workflow="$root/.github/workflows/release.yml"
    local probe_schema="$root/schemas/neutron.probe-identity-v1.schema.json"

    [[ -f "$identity" ]] &&
        contains "$identity" '[[ "${REQUIRE_SIGNATURES:-0}" == "1" || -n "${SIGNING_KEY:-}" ]]' &&
        contains "$package" 'release_validate_strict_inputs "$STRICT_RELEASE"' &&
        contains "$package" 'release_assert_probe_certificate "$PROBE_CERT_SHA256" "$STRICT_RELEASE"' &&
        contains "$package" 'release_verify_minisign_identity' &&
        contains "$identity" 'NEUTRON_APPROVED_PROBE_CERT_SHA256' &&
        contains "$identity" 'NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY' &&
        contains "$identity" 'probe certificate does not match NEUTRON_APPROVED_PROBE_CERT_SHA256' &&
        contains "$identity" 'minisign -Vm "$manifest"' &&
        contains "$identity" '-P "$NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY"' &&
        contains "$package" 'PROBE_DEBUGGABLE=' &&
        contains "$package" 'PROBE_BUILD_TYPE=debug' &&
        contains "$package" '"build_type": "$PROBE_BUILD_TYPE"' &&
        contains "$package" '"debuggable": $PROBE_DEBUGGABLE' &&
        contains "$probe_schema" '"build_type"' &&
        contains "$probe_schema" '"debuggable"' &&
        contains "$workflow" 'NEUTRON_APPROVED_PROBE_CERT_SHA256' &&
        contains "$workflow" 'NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY'
}

release_provenance_comes_from_measured_artifacts() {
    local package="$root/scripts/package-release.sh"
    local provenance="$root/scripts/generate-provenance.mjs"
    local schema="$root/schemas/neutron.provenance-v1.schema.json"

    [[ -f "$schema" ]] &&
        contains "$package" 'qemu-aarch64' &&
        contains "$package" 'self-info --json' &&
        contains "$package" '--bpf-object "$AGENT_PAYLOAD/neutron.bpf.elf"' &&
        contains "$package" '--bpf-object "$AGENT_PAYLOAD/neutron-stacks.bpf.elf"' &&
        contains "$package" 'NEUTRON_PROV_HOST_SELF_INFO' &&
        contains "$package" 'NEUTRON_PROV_AGENT_SELF_INFO' &&
        contains "$provenance" 'readSelfInfo' &&
        contains "$provenance" 'stackless.feature_bits' &&
        contains "$provenance" 'stacked.feature_bits' &&
        contains "$provenance" 'binaries:' &&
        contains "$provenance" 'bpf_objects:' &&
        ! contains "$provenance" 'feature_set: []' &&
        ! contains "$provenance" 'bpf_abi: { major: 2, event_size: 257 }' &&
        contains "$schema" '"binaries"' &&
        contains "$schema" '"bpf_objects"' &&
        contains "$schema" '"release_authentication"' &&
        contains "$root/schemas/README.md" 'neutron.provenance-v1.schema.json'
}

shipped_release_schemas_are_valid_json() {
    jq empty "$root"/schemas/*.json
}

ci_runs_for_release_lines_and_assembles_probe() {
    local workflow="$root/.github/workflows/ci.yml"
    rg -q '(^|[[:space:],\[])dev([[:space:],\]]|$)' "$workflow" &&
        contains "$workflow" 'release/**' &&
        rg -q '^[[:space:]]*workflow_dispatch:' "$workflow" &&
        rg -q 'assemble(Debug|Release|Research)' "$workflow" &&
        contains "$workflow" 'tests/release_contract.sh'
}

signed_tag_workflow_requires_keys_and_attests_assets() {
    local workflow="$root/.github/workflows/release.yml"
    [[ -f "$workflow" ]] &&
        contains "$workflow" 'git verify-tag "$RELEASE_TAG"' &&
        contains "$workflow" 'test "$(git rev-list -n 1 "$RELEASE_TAG")" = "$(git rev-parse HEAD)"' &&
        ! contains "$workflow" 'test "$(git rev-list -n 1 "$RELEASE_TAG")" = "$GITHUB_SHA"' &&
        ! contains "$workflow" 'test "$GITHUB_EVENT_NAME" = workflow_dispatch' &&
        contains "$workflow" 'RELEASE_GPG_PUBLIC_KEY_B64' &&
        contains "$workflow" 'MINISIGN_SECRET_KEY_B64' &&
        contains "$workflow" 'PROBE_KEYSTORE_B64' &&
        contains "$workflow" 'REQUIRE_SIGNATURES=1' &&
        contains "$workflow" 'cargo test --workspace --exclude neutron-ebpf' &&
        contains "$workflow" 'cargo clippy --workspace --exclude neutron-ebpf --all-targets -- -D warnings' &&
        contains "$workflow" 'cargo xtask build-ebpf --stacks release' &&
        contains "$workflow" 'testDebugUnitTest assembleDebug' &&
        contains "$workflow" 'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be # v2' &&
        ! contains "$workflow" 'gh release create'
}

workflows_pin_actions_to_immutable_commits() {
    local workflow
    for workflow in "$root"/.github/workflows/*.yml; do
        if rg -q 'uses:[[:space:]]+[^[:space:]#]+@(v[0-9]+|nightly)([[:space:]#]|$)' "$workflow"; then
            return 1
        fi
        while IFS= read -r reference; do
            [[ "$reference" =~ @([0-9a-f]{40})$ ]] || return 1
        done < <(sed -n 's/^[[:space:]]*- uses: \([^[:space:]#]*\).*/\1/p' "$workflow")
    done
}

ci_and_release_gate_rustsec_advisories() {
    local workflow
    for workflow in "$root/.github/workflows/ci.yml" "$root/.github/workflows/release.yml"; do
        contains "$workflow" 'cargo install cargo-audit --version 0.22.2 --locked' &&
            contains "$workflow" 'cargo audit' || return 1
    done
}

release_archives_and_probe_identity_are_reproducible_inputs() {
    local script="$root/scripts/package-release.sh" gradle="$root/probe-app/app/build.gradle"
    contains "$script" '--sort=name --mtime="@$ARCHIVE_EPOCH" --owner=0 --group=0' &&
        contains "$script" 'release_validate_strict_inputs "$STRICT_RELEASE"' &&
        contains "$gradle" 'NEUTRON_PROBE_KEYSTORE' &&
        contains "$gradle" 'signingConfig signingConfigs.research'
}

current_abi_docs_match_257_byte_contract() {
    local contributing="$root/docs/CONTRIBUTING.md"
    local architecture="$root/docs/ARCHITECTURE.md"

    contains "$contributing" 'SyscallEvent` (`#[repr(C, packed)]`, **257 bytes**)' &&
        ! rg -q 'SyscallEvent.*241|is 241 bytes' "$contributing" &&
        ! rg -q 'SyscallEvent.*\(241\)' "$architecture"
}

evidence_docs_do_not_overstate_capture_or_domain_filter_support() {
    local architecture="$root/docs/ARCHITECTURE.md"
    local reference="$root/docs/REFERENCE.md"
    local cli="$root/src/cli.rs"
    local changelog="$root/CHANGELOG.md"

    ! rg -qi 'lossless from the producer|handles silently' "$architecture" &&
        contains "$reference" 'rejected in 1.5' &&
        contains "$cli" 'rejected in 1.5' &&
        ! rg -qi 'uid.*falls back to.*active' "$reference" "$cli" &&
        contains "$reference" '`uid` is rejected in 1.5' &&
        contains "$cli" '`uid` is rejected in 1.5' &&
        ! contains "$changelog" 'Seeded PIDs matching explicit `--follow-deny-domain`' &&
        contains "$changelog" 'domain follow-policy flags are rejected in 1.5'
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
        trace doctor self-info evidence window summarize diff report binder-map mark graph surface \
        recipes ioctl harness aidl research native-map ghidra-export selinux; do
        contains "$product" "\`neutron $command\`" || return 1
    done
}

run_test dated_toolchain_omits_prebuilt_bpf_target
run_test build_requires_android_serial_before_cargo
run_test unwrapped_builds_cannot_claim_clean_provenance
run_test xtask_deploy_and_demo_require_explicit_serial
run_test release_package_declares_complete_payload
run_test release_sbom_and_provenance_include_dependency_and_build_inputs
run_test release_sbom_uses_resolved_gradle_graph_and_validates_spdx
run_test release_install_docs_authenticate_before_root_execution
run_test release_signing_identity_is_fail_closed
run_test release_provenance_comes_from_measured_artifacts
run_test shipped_release_schemas_are_valid_json
run_test ci_runs_for_release_lines_and_assembles_probe
run_test signed_tag_workflow_requires_keys_and_attests_assets
run_test workflows_pin_actions_to_immutable_commits
run_test ci_and_release_gate_rustsec_advisories
run_test release_archives_and_probe_identity_are_reproducible_inputs
run_test current_abi_docs_match_257_byte_contract
run_test evidence_docs_do_not_overstate_capture_or_domain_filter_support
run_test security_policy_has_private_only_reporting
run_test product_contract_labels_every_command

exit "$failures"
