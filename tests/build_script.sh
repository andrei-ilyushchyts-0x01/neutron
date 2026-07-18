#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
script="$root/build.sh"
xtask="$root/xtask/src/main.rs"

[[ -x "$script" ]]
rg -Fq ': "${ANDROID_SERIAL:?Set ANDROID_SERIAL to the explicit authorized USB device serial}"' "$script"
rg -Fq 'exec cargo xtask deploy --serial "$ANDROID_SERIAL"' "$script"

if rg -n '(^|[[:space:]])adb([[:space:]]|$)|/data/local/tmp|/data/local/share/neutron' "$script"; then
    echo "build.sh must delegate deployment instead of maintaining a second installer" >&2
    exit 1
fi

rg -Fq 'rollback_publish' "$xtask"
rg -Fq 'restore_backup' "$xtask"
rg -Fq 'device_sha256(serial, &candidate)' "$xtask"
