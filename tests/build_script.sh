#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
script="$root/build.sh"

rg -F "adb shell \"su -c 'mkdir -p /data/local/share/neutron/packs'\"" "$script"
if rg -F "adb shell mkdir -p /data/local/share/neutron/packs" "$script"; then
    exit 1
fi
