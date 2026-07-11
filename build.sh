#!/usr/bin/env bash
# neutron CORE V1 — build + deploy script
#
# Targets Pixel 8 Pro (kernel 6.1.x, BTF, CO-RE). The legacy C BPF + raw-bpf()
# loader path is gone — see git history / `legacy` branch for that.
#
# Two artefacts: one userspace binary (Aya loader) + one BPF ELF (Aya programs).

set -euo pipefail
cd "$(dirname "$0")"

echo "=== [1/3] Building Aya BPF programs (Rust → bpfel-unknown-none) ==="
cargo xtask build-ebpf release

echo ""
echo "=== [2/3] Building userspace binary (aarch64-unknown-linux-musl) ==="
cargo build --release --target aarch64-unknown-linux-musl --bin neutron

echo ""
echo "=== [3/3] Deploying to connected device ==="
if adb get-state >/dev/null 2>&1; then
    adb push neutron.bpf.elf /data/local/tmp/
    adb push target/aarch64-unknown-linux-musl/release/neutron /data/local/tmp/
    adb shell mkdir -p /data/local/share/neutron/packs
    adb push packs/. /data/local/share/neutron/packs/
    adb shell "su -c 'chown -R 0:0 /data/local/share/neutron/packs && find /data/local/share/neutron/packs -type d -exec chmod 0755 {} \; && find /data/local/share/neutron/packs -type f -exec chmod 0644 {} \;'"
    adb shell chmod +x /data/local/tmp/neutron

    echo ""
    echo "=== Done. On device: ==="
    echo ""
    echo "  # Default mode (rule-engine findings only):"
    echo "  adb shell su -c '/data/local/tmp/neutron --pid <PID>'"
    echo ""
    echo "  # Raw events with NDJSON:"
    echo "  adb shell su -c '/data/local/tmp/neutron --pid <PID> --raw --no-findings --json'"
    echo ""
    echo "  # Security profile + binder + stacks:"
    echo "  adb shell su -c '/data/local/tmp/neutron --pid <PID> \\"
    echo "      --profile security --binder --stacks'"
else
    echo "No adb device found. Push manually:"
    echo "  adb push neutron.bpf.elf /data/local/tmp/"
    echo "  adb push target/aarch64-unknown-linux-musl/release/neutron /data/local/tmp/"
    echo "  adb shell mkdir -p /data/local/share/neutron/packs"
    echo "  adb push packs/. /data/local/share/neutron/packs/"
    echo "  adb shell su -c 'chown -R 0:0 /data/local/share/neutron/packs'"
    echo "  adb shell chmod +x /data/local/tmp/neutron"
fi
