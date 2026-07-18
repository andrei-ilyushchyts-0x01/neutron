#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
script="$root/scripts/package-release.sh"
identity="$root/scripts/release-identity.sh"
quickstart="$root/docs/guides/quickstart.md"

rg -F ': "${ANDROID_SERIAL:?Set ANDROID_SERIAL to the explicit authorized USB device serial}"' "$script"
rg -F 'ADB=(adb -s "$ANDROID_SERIAL")' "$script"
rg -F 'ANDROID_SERIAL must name one physical USB device' "$script"
rg -F '$i ~ /^usb:/' "$script"
rg -F 'STAGE_ROOT="/data/local/tmp/neutron-install-' "$script"
rg -F 'trap cleanup EXIT' "$script"
rg -F 'chmod 0700 $INSTALL_ROOT $INSTALL_ROOT/runtime $INSTALL_ROOT/runs' "$script"
rg -F 'chmod 0700 $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX' "$script"
rg -F 'chmod 0600 $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX' "$script"
rg -F 'chown -R 0:0 $INSTALL_ROOT/packs$NEXT_SUFFIX' "$script"
rg -F 'verify_device_hash neutron-agent "$INSTALL_ROOT/neutron-agent$NEXT_SUFFIX"' "$script"
rg -F 'verify_device_hash neutron.bpf.elf "$INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX"' "$script"
rg -F 'verify_device_hash neutron-stacks.bpf.elf "$INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX"' "$script"
rg -F 'verify_device_hash "packs/$relative" "$INSTALL_ROOT/packs$NEXT_SUFFIX/$relative"' "$script"
rg -F 'sha256sum --check --strict --quiet SHA256SUMS' "$script"
rg -F 'payload entry is absent from SHA256SUMS' "$script"
rg -F "find '\$STAGE_ROOT' ! -type d ! -type f -print -quit" "$script"
rg -F 'device staging file list differs from the packaged allowlist' "$script"
rg -F '"${ADB[@]}" push "packs/$relative" "$STAGE_ROOT/packs/$relative"' "$script"
rg -F 'cp $STAGE_ROOT/packs/$relative $INSTALL_ROOT/packs$NEXT_SUFFIX/$relative' "$script"
rg -F 'rollback_publish() {' "$script"
rg -F 'mv $BACKUP_ROOT/neutron-agent $INSTALL_ROOT/neutron-agent' "$script"
rg -F "tr -cd 'A-Za-z0-9 ._:/@,+()=_-'" "$script"
rg -F 'jq '"'"'{schema, compatible, object, smoke}'"'"' neutron.doctor.json' "$script"
rg -F 'mv "$DIST" "$FINAL_DIST"' "$script"
rg -F 'apksigner verify --print-certs' "$script"
rg -F '"schema": "neutron.probe-identity/v1"' "$script"
rg -F '"target_sdk": $PROBE_TARGET_SDK' "$script"
rg -F 'NEUTRON_PROBE_KEYSTORE' "$identity"
rg -F 'release_assert_probe_certificate "$PROBE_CERT_SHA256" "$STRICT_RELEASE"' "$script"
rg -F '"debuggable": $PROBE_DEBUGGABLE' "$script"
rg -Fx 'umask 022' "$script"
rg -F 'chmod 0755 "$DIST"' "$script"
rg -F 'find "$payload" -type d -exec chmod 0755 {} +' "$script"
rg -F 'find "$payload" -type f -exec chmod 0644 {} +' "$script"
rg -F 'chmod 0755 "$HOST_PAYLOAD/neutron"' "$script"
rg -F 'chmod 0755 "$AGENT_PAYLOAD/neutron" "$AGENT_PAYLOAD/neutron-agent" "$AGENT_PAYLOAD/install-android.sh"' "$script"
rg -F 'LC_ALL=C sort -z' "$script"
rg -F -- '--sort=name --mtime="@$ARCHIVE_EPOCH" --owner=0 --group=0' "$script"
rg -F -- '--format=gnu' "$script"
rg -F 'ZSTD_CLEVEL=19 ZSTD_NBTHREADS=1' "$script"
rg -F 'cmp -s "$output" "$check"' "$script"
rg -F 'create_archive_twice "$DIST/$HOST_NAME.tar.zst" create_payload_archive "$HOST_NAME"' "$script"
rg -F 'create_archive_twice "$DIST/$AGENT_NAME.tar.zst" create_payload_archive "$AGENT_NAME"' "$script"
rg -F 'create_archive_twice "$DIST/$SOURCE_NAME" create_source_archive' "$script"
rg -F 'rm -rf -- "$HOST_PAYLOAD" "$AGENT_PAYLOAD"' "$script"
rg -F 'git archive --format=tar --mtime="$BUILD_TIMESTAMP"' "$script"
rg -F 'gzip -n -9' "$script"
rg -F 'BUILD_ARCH=$(uname -m)' "$script"
rg -F 'if [[ "$BUILD_ARCH" != "x86_64" ]]; then' "$script"
rg -F 'X86_64_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-linux-gnu-gcc}"' "$script"
rg -F 'if ! command -v "$X86_64_LINKER" >/dev/null 2>&1; then' "$script"
rg -F 'release packaging on $BUILD_ARCH requires a usable x86_64-linux-gnu linker: $X86_64_LINKER' "$script"
rg -F 'export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$X86_64_LINKER"' "$script"
rg -F 'X86_64_SYSROOT="${NEUTRON_X86_64_SYSROOT:-/usr/x86_64-linux-gnu}"' "$script"
rg -F 'command -v qemu-x86_64' "$script"
rg -F 'HOST_RUNNER=(qemu-x86_64 -L "$X86_64_SYSROOT")' "$script"
rg -F '"${HOST_RUNNER[@]}" "$HOST_PAYLOAD/neutron" self-info --json' "$script"
rg -F 'cargo run --locked --release --example generate-completions -- "$HOST_PAYLOAD/completions"' "$script"
rg -F 'path: dist/v*/' "$root/.github/workflows/ci.yml"
rg -F 'installs only the agent, both BPF variants, and packs' "$quickstart"
rg -F "jq '{schema, compatible, object, smoke}' neutron.doctor.json" "$quickstart"

arch_line=$(rg -n -m1 -F 'BUILD_ARCH=$(uname -m)' "$script" | cut -d: -f1)
linker_line=$(rg -n -m1 -F 'export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$X86_64_LINKER"' "$script" | cut -d: -f1)
host_build_line=$(rg -n -m1 -F 'cargo build --release --target x86_64-unknown-linux-gnu --bin neutron' "$script" | cut -d: -f1)
host_runner_line=$(rg -n -m1 -F 'HOST_RUNNER=(qemu-x86_64 -L "$X86_64_SYSROOT")' "$script" | cut -d: -f1)
host_self_info_line=$(rg -n -m1 -F '"${HOST_RUNNER[@]}" "$HOST_PAYLOAD/neutron" self-info --json' "$script" | cut -d: -f1)
agent_archive_line=$(rg -n -m1 -F 'create_archive_twice "$DIST/$AGENT_NAME.tar.zst" create_payload_archive "$AGENT_NAME"' "$script" | cut -d: -f1)
payload_cleanup_line=$(rg -n -m1 -F 'rm -rf -- "$HOST_PAYLOAD" "$AGENT_PAYLOAD"' "$script" | cut -d: -f1)
outer_manifest_line=$(rg -n -m1 -F 'SBOM.spdx.json \' "$script" | cut -d: -f1)
[[ "$arch_line" -lt "$linker_line" ]]
[[ "$linker_line" -lt "$host_build_line" ]]
[[ "$host_runner_line" -lt "$host_self_info_line" ]]
[[ "$agent_archive_line" -lt "$payload_cleanup_line" ]]
[[ "$payload_cleanup_line" -lt "$outer_manifest_line" ]]

if rg -F 'cargo run --locked --release --target x86_64-unknown-linux-gnu --example generate-completions' "$script"; then
    echo "completion generation must run natively" >&2
    exit 1
fi

checksum_line=$(rg -n -m1 'sha256sum --check --strict --quiet SHA256SUMS' "$script" | cut -d: -f1)
push_line=$(rg -n -m1 -F '"${ADB[@]}" push neutron-agent' "$script" | cut -d: -f1)
[[ "$checksum_line" -lt "$push_line" ]]

if rg -F 'push neutron-agent /data/local/tmp/neutron' "$script"; then
    exit 1
fi
if rg -F '"${ADB[@]}" push packs/.' "$script"; then
    exit 1
fi
if rg -F 'cp -R $STAGE_ROOT/packs' "$script"; then
    exit 1
fi
if rg -F 'chmod 0755 $INSTALL_ROOT' "$script"; then
    exit 1
fi
if rg -F 'chown -R shell:shell $INSTALL_ROOT' "$script"; then
    exit 1
fi

mkdir -p "$root/target/tmp"
fixture=$(mktemp -d "$root/target/tmp/package-archive.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT

(
    umask 077
    mkdir -p "$fixture/first/payload/z"
    printf 'first\n' > "$fixture/first/payload/a-first"
    printf '#!/bin/sh\nexit 0\n' > "$fixture/first/payload/bin"
    printf 'last\n' > "$fixture/first/payload/z/last"
    chmod 0700 "$fixture/first/payload/z"
    chmod 0600 "$fixture/first/payload/a-first" "$fixture/first/payload/z/last"
)
(
    umask 002
    mkdir -p "$fixture/second/payload/z"
    printf 'last\n' > "$fixture/second/payload/z/last"
    printf '#!/bin/sh\nexit 0\n' > "$fixture/second/payload/bin"
    printf 'first\n' > "$fixture/second/payload/a-first"
    chmod 0777 "$fixture/second/payload/z"
    chmod 0666 "$fixture/second/payload/a-first" "$fixture/second/payload/z/last"
)

for build in first second; do
    payload="$fixture/$build/payload"
    find "$payload" -type d -exec chmod 0755 {} +
    find "$payload" -type f -exec chmod 0644 {} +
    chmod 0755 "$payload/bin"
    if [[ "$build" == first ]]; then
        source_epoch=1600000000
    else
        source_epoch=1800000000
    fi
    touch -d "@$source_epoch" "$payload" "$payload"/* "$payload/z/last"
    LC_ALL=C TAR_OPTIONS= ZSTD_CLEVEL=19 ZSTD_NBTHREADS=1 \
        tar -C "$fixture/$build" --format=gnu \
            --sort=name --mtime='@1700000000' --owner=0 --group=0 \
            --numeric-owner --zstd -cf "$fixture/$build.tar.zst" payload
done

cmp -s "$fixture/first.tar.zst" "$fixture/second.tar.zst"
expected_modes=$'drwxr-xr-x payload/\n-rw-r--r-- payload/a-first\n-rwxr-xr-x payload/bin\ndrwxr-xr-x payload/z/\n-rw-r--r-- payload/z/last'
actual_modes=$(tar --zstd --numeric-owner -tvf "$fixture/first.tar.zst" | awk '{print $1, $6}')
[[ "$actual_modes" == "$expected_modes" ]]
