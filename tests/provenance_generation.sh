#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$root/target/tmp"
work=$(mktemp -d "${TMPDIR:-$root/target/tmp}/neutron-provenance-test.XXXXXX")
trap 'rm -rf -- "$work"' EXIT

commit=1111111111111111111111111111111111111111
host_object_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
stacks_object_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb

cat > "$work/host.json" <<EOF
{
  "schema": "neutron.self-info/v1",
  "tool": {
    "version": "1.5.0-rc.1",
    "git_commit": "$commit",
    "git_dirty": false,
    "build_timestamp": "2026-07-17T00:00:00Z",
    "rustc_version": "rustc 1.90.0-nightly",
    "target": "x86_64-unknown-linux-gnu",
    "feature_set": ["host-feature"]
  },
  "bpf": {
    "abi_major": 2,
    "event_size": 257,
    "feature_bits": ["syscall_trace", "binder_trace", "per_cpu_health", "process_exit"]
  },
  "bpf_objects": [
    {
      "path": "/stage/neutron.bpf.elf",
      "identity": {
        "object_sha256": "$host_object_sha",
        "section": ".neutron_abi",
        "magic": "0x004e4f525455454e",
        "abi_major": 2,
        "abi_minor": 0,
        "syscall_event_size": 257,
        "feature_bits": 23,
        "build_id": "$commit",
        "build_id_present": true
      }
    },
    {
      "path": "/stage/neutron-stacks.bpf.elf",
      "identity": {
        "object_sha256": "$stacks_object_sha",
        "section": ".neutron_abi",
        "magic": "0x004e4f525455454e",
        "abi_major": 2,
        "abi_minor": 0,
        "syscall_event_size": 257,
        "feature_bits": 31,
        "build_id": "$commit",
        "build_id_present": true
      }
    }
  ]
}
EOF

cat > "$work/agent.json" <<EOF
{
  "schema": "neutron.self-info/v1",
  "tool": {
    "version": "1.5.0-rc.1",
    "git_commit": "$commit",
    "git_dirty": false,
    "build_timestamp": "2026-07-17T00:00:00Z",
    "rustc_version": "rustc 1.90.0-nightly",
    "target": "aarch64-unknown-linux-musl",
    "feature_set": ["agent-feature"]
  },
  "bpf": {
    "abi_major": 2,
    "event_size": 257,
    "feature_bits": ["syscall_trace", "binder_trace", "per_cpu_health", "process_exit"]
  }
}
EOF

export NEUTRON_PROV_VERSION=1.5.0-rc.1
export NEUTRON_PROV_GIT_COMMIT=$commit
export NEUTRON_PROV_GIT_DIRTY=false
export NEUTRON_PROV_BUILD_TIMESTAMP=2026-07-17T00:00:00Z
export NEUTRON_PROV_RUSTC='rustc 1.90.0-nightly'
export NEUTRON_PROV_CARGO='cargo 1.90.0-nightly'
export NEUTRON_PROV_BPF_LINKER='bpf-linker 0.10.3'
export NEUTRON_PROV_X86_64_LINKER='x86_64-linux-gnu-gcc 14.2.0'
export NEUTRON_PROV_JAVA_RUNTIME=17.0.1
export NEUTRON_PROV_JAVA_VENDOR=Eclipse
export NEUTRON_PROV_GRADLE=8.10.2
export NEUTRON_PROV_GRADLE_SHA256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
export NEUTRON_PROV_AGP=8.8.2
export NEUTRON_PROV_COMPILE_SDK=35
export NEUTRON_PROV_BUILD_TOOLS=35.0.0
export NEUTRON_PROV_AAPT2='Android Asset Packaging Tool (aapt) 2.19'
export NEUTRON_PROV_APKSIGNER=0.9
export NEUTRON_PROV_RUNNER_OS=ubuntu24
export NEUTRON_PROV_RUNNER_IMAGE_VERSION=20260717.1
export NEUTRON_PROV_RUNNER_ARCH=X64
export NEUTRON_PROV_RUNNER_ENVIRONMENT=github-hosted
export NEUTRON_PROV_PROBE_PACKAGE=dev.neutron.probe
export NEUTRON_PROV_PROBE_VERSION_CODE=1
export NEUTRON_PROV_PROBE_VERSION_NAME=1.0
export NEUTRON_PROV_PROBE_TARGET_SDK=35
export NEUTRON_PROV_PROBE_CERT_SHA256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
export NEUTRON_PROV_APPROVED_PROBE_CERT_SHA256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
export NEUTRON_PROV_PROBE_BUILD_TYPE=debug
export NEUTRON_PROV_PROBE_DEBUGGABLE=true
export NEUTRON_PROV_STRICT_RELEASE=true
export NEUTRON_PROV_MINISIGN_PUBLIC_KEY_SHA256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
export NEUTRON_PROV_HOST_NAME=neutron-v1.5.0-rc.1-linux-x86_64.tar.zst
export NEUTRON_PROV_AGENT_NAME=neutron-agent-v1.5.0-rc.1-android-aarch64.tar.zst
export NEUTRON_PROV_SOURCE_NAME=neutron-v1.5.0-rc.1-source.tar.gz
export NEUTRON_PROV_HOST_SHA256=0101010101010101010101010101010101010101010101010101010101010101
export NEUTRON_PROV_AGENT_SHA256=0202020202020202020202020202020202020202020202020202020202020202
export NEUTRON_PROV_SOURCE_SHA256=0303030303030303030303030303030303030303030303030303030303030303
export NEUTRON_PROV_HOST_BINARY_SHA256=0404040404040404040404040404040404040404040404040404040404040404
export NEUTRON_PROV_AGENT_BINARY_SHA256=0505050505050505050505050505050505050505050505050505050505050505
export NEUTRON_PROV_BPF_SHA256=$host_object_sha
export NEUTRON_PROV_BPF_STACKS_SHA256=$stacks_object_sha
export NEUTRON_PROV_PROBE_SHA256=0606060606060606060606060606060606060606060606060606060606060606
export NEUTRON_PROV_HOST_SELF_INFO=$work/host.json
export NEUTRON_PROV_AGENT_SELF_INFO=$work/agent.json

node "$root/scripts/generate-provenance.mjs" "$work/provenance.json"

jq -e '
  .schema == "neutron.provenance/v1" and
  .binaries.host.self_info.feature_set == ["host-feature"] and
  .binaries.android_agent.self_info.feature_set == ["agent-feature"] and
  .toolchain.x86_64_linker == "x86_64-linux-gnu-gcc 14.2.0" and
  .bpf_objects["neutron.bpf.elf"].identity.feature_bits == 23 and
  .bpf_objects["neutron-stacks.bpf.elf"].identity.feature_bits == 31 and
  .bpf_abi == {major: 2, minor: 0, event_size: 257} and
  .probe.build_type == "debug" and
  .probe.debuggable == true and
  .probe.signing_certificate_approved == true and
  .probe.attacker_model == "ordinary_installed_app_target_sdk_35_debuggable_true" and
  .release_authentication.strict == true
' "$work/provenance.json" >/dev/null

unset NEUTRON_PROV_X86_64_LINKER
if node "$root/scripts/generate-provenance.mjs" "$work/missing-linker.json" \
    >"$work/missing-linker.stdout" 2>"$work/missing-linker.stderr"; then
  echo "provenance generator accepted a missing x86_64 linker identity" >&2
  exit 1
fi
rg -F 'missing provenance input NEUTRON_PROV_X86_64_LINKER' \
  "$work/missing-linker.stderr"
[[ ! -e "$work/missing-linker.json" ]]
export NEUTRON_PROV_X86_64_LINKER='x86_64-linux-gnu-gcc 14.2.0'

jq '.bpf_objects[1].identity.feature_bits = 23' "$work/host.json" \
  > "$work/host-mismatch.json"
export NEUTRON_PROV_HOST_SELF_INFO=$work/host-mismatch.json
if node "$root/scripts/generate-provenance.mjs" "$work/invalid.json" \
    >"$work/invalid.stdout" 2>"$work/invalid.stderr"; then
  echo "provenance generator accepted a stack-enabled object without the stacks bit" >&2
  exit 1
fi
rg -F 'stack-enabled BPF feature bits must equal stackless bits plus stacks' \
  "$work/invalid.stderr"
[[ ! -e "$work/invalid.json" ]]

export NEUTRON_PROV_HOST_SELF_INFO=$work/host.json
export NEUTRON_PROV_APPROVED_PROBE_CERT_SHA256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
if node "$root/scripts/generate-provenance.mjs" "$work/invalid-cert.json" \
    >"$work/invalid-cert.stdout" 2>"$work/invalid-cert.stderr"; then
  echo "provenance generator accepted the wrong approved probe certificate" >&2
  exit 1
fi
rg -F 'strict release probe certificate does not match the approved identity' \
  "$work/invalid-cert.stderr"
[[ ! -e "$work/invalid-cert.json" ]]
