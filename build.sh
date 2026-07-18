#!/usr/bin/env bash
# Build and install the matching userspace/BPF set on one authorized device.

set -euo pipefail
: "${ANDROID_SERIAL:?Set ANDROID_SERIAL to the explicit authorized USB device serial}"
cd "$(dirname "$0")"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "Evidence builds require a clean checkout; commit or stash scoped changes first" >&2
    exit 1
fi
export NEUTRON_BUILD_GIT_COMMIT="$(git rev-parse HEAD)"
export NEUTRON_BUILD_GIT_DIRTY=false
export NEUTRON_BUILD_TIMESTAMP="$(git show -s --format=%cI HEAD)"

exec cargo xtask deploy --serial "$ANDROID_SERIAL"
