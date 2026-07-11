#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
script="$root/scripts/package-release.sh"

rg -F "chown 0:0 /data/local/share/neutron && chmod 0755 /data/local/share/neutron && chown -R shell:shell /data/local/share/neutron/packs" "$script"
rg -F "adb push share/neutron/packs/. /data/local/share/neutron/packs/" "$script"
rg -F "chown -R 0:0 /data/local/share/neutron/packs" "$script"
if rg -F "chown shell:shell /data/local/share/neutron /data/local/share/neutron/packs" "$script"; then
    exit 1
fi
if rg -F "adb shell mkdir -p /data/local/share/neutron/packs" "$script"; then
    exit 1
fi
