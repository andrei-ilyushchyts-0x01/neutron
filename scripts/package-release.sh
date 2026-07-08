#!/usr/bin/env bash
# Build local GitHub release assets for neutron.
#
# This script does not publish anything. It creates:
#   dist/neutron-v<VERSION>-android-aarch64.tar.gz
#   dist/neutron-v<VERSION>-source.tar.gz
#   dist/SHA256SUMS
#
# A GitHub release can then attach the Android tarball. GitHub also creates
# source archives automatically from the release tag, but the explicit source
# tarball is useful for offline handoff and reproducibility checks.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="$(awk -F '"' '/^version =/ { print $2; exit }' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
  echo "could not determine workspace version from Cargo.toml" >&2
  exit 1
fi

if [[ "${ALLOW_DIRTY:-0}" != "1" ]]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "working tree has uncommitted changes; commit first or rerun with ALLOW_DIRTY=1" >&2
    echo "source archive is created from git HEAD, so uncommitted files would be omitted" >&2
    exit 1
  fi
fi

DIST="$ROOT/dist"
NAME="neutron-v${VERSION}-android-aarch64"
PAYLOAD="$DIST/$NAME"

rm -rf "$PAYLOAD"
mkdir -p "$PAYLOAD" "$DIST"

echo "==> Building stackless BPF object"
cargo xtask build-ebpf release

echo "==> Building Android aarch64 userspace binary"
cargo build --release --target aarch64-unknown-linux-musl --bin neutron

echo "==> Assembling $NAME"
install -m 0755 target/aarch64-unknown-linux-musl/release/neutron "$PAYLOAD/neutron"
install -m 0644 neutron.bpf.elf "$PAYLOAD/neutron.bpf.elf"
install -m 0644 README.md CHANGELOG.md LICENSE SECURITY.md "$PAYLOAD/"

cat > "$PAYLOAD/INSTALL.md" <<'EOF'
# Install

```bash
adb push neutron /data/local/tmp/neutron
adb push neutron.bpf.elf /data/local/tmp/neutron.bpf.elf
adb shell chmod +x /data/local/tmp/neutron
adb shell "su -c '/data/local/tmp/neutron doctor'"
```

Run a package-scoped smoke capture:

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --no-findings --no-logcat \
  --fdgraph-interval off --lookback-events 0 \
  --match-package com.android.settings \
  --rate-limit 200 \
  --max-output-size 4mb \
  --health-output /data/local/tmp/neutron.health.ndjson \
  --output /data/local/tmp/neutron.ndjson'"
```
EOF

echo "==> Creating archives"
tar -C "$DIST" -czf "$DIST/$NAME.tar.gz" "$NAME"
git archive --format=tar.gz --prefix="neutron-v${VERSION}/" -o "$DIST/neutron-v${VERSION}-source.tar.gz" HEAD

(
  cd "$DIST"
  sha256sum "$NAME.tar.gz" "neutron-v${VERSION}-source.tar.gz" > SHA256SUMS
)

echo "Release assets:"
echo "  $DIST/$NAME.tar.gz"
echo "  $DIST/neutron-v${VERSION}-source.tar.gz"
echo "  $DIST/SHA256SUMS"
