#!/usr/bin/env bash
# Build local, unpublished release assets for neutron.
# Produces host and Android archives, a source archive, artifact provenance,
# an SPDX document, and one checksum manifest.

set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
# shellcheck source=release-identity.sh
source "$ROOT/scripts/release-identity.sh"

VERSION="$(awk -F '"' '/^version =/ { print $2; exit }' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
  echo "could not determine workspace version from Cargo.toml" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "working tree has uncommitted changes; release packaging requires a clean checkout" >&2
  echo "source archives and build identity must describe the same checkout" >&2
  exit 1
fi

STRICT_RELEASE=false
if [[ "${REQUIRE_SIGNATURES:-0}" == "1" || -n "${SIGNING_KEY:-}" ]]; then
  STRICT_RELEASE=true
fi
release_validate_strict_inputs "$STRICT_RELEASE"

GIT_COMMIT=$(git rev-parse HEAD)
GIT_DIRTY=false
if [[ -n "${SOURCE_DATE_EPOCH:-}" ]]; then
  ARCHIVE_EPOCH=$SOURCE_DATE_EPOCH
else
  ARCHIVE_EPOCH=$(git show -s --format=%ct HEAD)
fi
BUILD_TIMESTAMP=$(date -u -d "@$ARCHIVE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
export NEUTRON_BUILD_GIT_COMMIT="$GIT_COMMIT"
export NEUTRON_BUILD_GIT_DIRTY="$GIT_DIRTY"
export NEUTRON_BUILD_TIMESTAMP="$BUILD_TIMESTAMP"

DIST_ROOT="$ROOT/dist"
FINAL_DIST="$DIST_ROOT/v$VERSION"
mkdir -p "$DIST_ROOT"
if [[ -e "$FINAL_DIST" ]]; then
  echo "release output already exists: $FINAL_DIST" >&2
  echo "move it aside explicitly before rebuilding; stale artifacts are never overwritten" >&2
  exit 1
fi
DIST=$(mktemp -d "$DIST_ROOT/.stage-v${VERSION}.XXXXXX")
chmod 0755 "$DIST"
cleanup_stage() {
  rm -rf -- "$DIST"
}
trap cleanup_stage EXIT
HOST_NAME="neutron-v${VERSION}-linux-x86_64"
AGENT_NAME="neutron-agent-v${VERSION}-android-aarch64"
HOST_PAYLOAD="$DIST/$HOST_NAME"
AGENT_PAYLOAD="$DIST/$AGENT_NAME"
SOURCE_NAME="neutron-v${VERSION}-source.tar.gz"

mkdir -p "$HOST_PAYLOAD/man/man1" "$HOST_PAYLOAD/schemas"
mkdir -p "$AGENT_PAYLOAD/packs" "$AGENT_PAYLOAD/probe" "$AGENT_PAYLOAD/schemas"

echo "==> Building stackless BPF object"
cargo xtask build-ebpf release

echo "==> Building stack-enabled BPF object"
cargo xtask build-ebpf --stacks release

echo "==> Building Linux x86_64 host binary"
cargo build --release --target x86_64-unknown-linux-gnu --bin neutron

echo "==> Building Android aarch64 userspace binary"
cargo build --release --target aarch64-unknown-linux-musl --bin neutron

echo "==> Building research probe APK"
GRADLE_DEPENDENCIES="$DIST/gradle-dependencies.json"
(
  cd probe-app
  ./gradlew --no-daemon testDebugUnitTest assembleDebug neutronResolvedDependencies \
    -PneutronDependencyOutput="$GRADLE_DEPENDENCIES"
)

echo "==> Assembling $HOST_NAME"
install -m 0755 target/x86_64-unknown-linux-gnu/release/neutron "$HOST_PAYLOAD/neutron"
install -m 0644 man/man1/neutron.1 "$HOST_PAYLOAD/man/man1/neutron.1"
cp -R schemas/. "$HOST_PAYLOAD/schemas/"
install -m 0644 README.md PRODUCT.md CHANGELOG.md LICENSE SECURITY.md "$HOST_PAYLOAD/"

cat > "$HOST_PAYLOAD/INSTALL.md" <<'EOF'
# Host install

Run `./neutron --version --verbose` before use. Host-side analysis commands
operate on previously collected artifacts and do not require ADB.
EOF

echo "==> Assembling $AGENT_NAME"
install -m 0755 target/aarch64-unknown-linux-musl/release/neutron "$AGENT_PAYLOAD/neutron-agent"
ln "$AGENT_PAYLOAD/neutron-agent" "$AGENT_PAYLOAD/neutron"
install -m 0644 neutron.bpf.elf "$AGENT_PAYLOAD/neutron.bpf.elf"
install -m 0644 neutron-stacks.bpf.elf "$AGENT_PAYLOAD/neutron-stacks.bpf.elf"
install -m 0644 probe-app/app/build/outputs/apk/debug/app-debug.apk "$AGENT_PAYLOAD/probe/neutron-probe.apk"
cp -R schemas/. "$AGENT_PAYLOAD/schemas/"
install -m 0644 README.md PRODUCT.md CHANGELOG.md LICENSE SECURITY.md "$AGENT_PAYLOAD/"
if [[ -n "$(find packs ! -type d ! -type f -print -quit)" ]]; then
  echo "release packs may contain only directories and regular files" >&2
  exit 1
fi
while IFS= read -r -d '' path; do
  relative=${path#packs/}
  [[ "$relative" =~ ^[A-Za-z0-9._/-]+$ ]] || {
    echo "unsafe release pack path: $relative" >&2
    exit 1
  }
  if [[ -d "$path" ]]; then
    install -d -m 0755 "$AGENT_PAYLOAD/packs/$relative"
  else
    install -D -m 0644 "$path" "$AGENT_PAYLOAD/packs/$relative"
  fi
done < <(find packs -mindepth 1 -print0 | LC_ALL=C sort -z)

PROBE_APK="$AGENT_PAYLOAD/probe/neutron-probe.apk"
PROBE_SHA256=$(sha256sum "$PROBE_APK" | cut -d ' ' -f 1)
PROBE_CERT_SHA256=$(apksigner verify --print-certs "$PROBE_APK" |
  awk -F': ' '/Signer #1 certificate SHA-256 digest:/ {print tolower($2); exit}')
PROBE_BADGING=$(aapt2 dump badging "$PROBE_APK")
PROBE_PACKAGE=$(printf '%s\n' "$PROBE_BADGING" |
  sed -n "s/^package: name='\([^']*\)'.*/\1/p" | head -n 1)
PROBE_VERSION_CODE=$(printf '%s\n' "$PROBE_BADGING" |
  sed -n "s/^package:.*versionCode='\([^']*\)'.*/\1/p" | head -n 1)
PROBE_VERSION_NAME=$(printf '%s\n' "$PROBE_BADGING" |
  sed -n "s/^package:.*versionName='\([^']*\)'.*/\1/p" | head -n 1)
PROBE_TARGET_SDK=$(printf '%s\n' "$PROBE_BADGING" |
  sed -n "s/^targetSdkVersion:'\([^']*\)'.*/\1/p" | head -n 1)
PROBE_BUILD_TYPE=debug
PROBE_DEBUGGABLE=false
if printf '%s\n' "$PROBE_BADGING" | grep -qx 'application-debuggable'; then
  PROBE_DEBUGGABLE=true
fi
if [[ ! "$PROBE_CERT_SHA256" =~ ^[0-9a-f]{64}$ ||
      ! "$PROBE_PACKAGE" =~ ^[A-Za-z0-9._]+$ ||
      ! "$PROBE_VERSION_CODE" =~ ^[0-9]+$ ||
      ! "$PROBE_VERSION_NAME" =~ ^[A-Za-z0-9._+-]+$ ||
      ! "$PROBE_TARGET_SDK" =~ ^[0-9]+$ ]]; then
  echo "could not derive a safe, complete identity from the built probe APK" >&2
  exit 1
fi
release_assert_probe_certificate "$PROBE_CERT_SHA256" "$STRICT_RELEASE"
cat > "$AGENT_PAYLOAD/probe/probe-metadata.json" <<EOF
{
  "schema": "neutron.probe-identity/v1",
  "file": "neutron-probe.apk",
  "sha256": "$PROBE_SHA256",
  "signing_certificate_sha256": "$PROBE_CERT_SHA256",
  "signing_certificate_approved": $STRICT_RELEASE,
  "package": "$PROBE_PACKAGE",
  "version_code": $PROBE_VERSION_CODE,
  "version_name": "$PROBE_VERSION_NAME",
  "target_sdk": $PROBE_TARGET_SDK,
  "build_type": "$PROBE_BUILD_TYPE",
  "debuggable": $PROBE_DEBUGGABLE,
  "attacker_model": "ordinary_installed_app_target_sdk_${PROBE_TARGET_SDK}_debuggable_${PROBE_DEBUGGABLE}"
}
EOF
chmod 0644 "$AGENT_PAYLOAD/probe/probe-metadata.json"

command -v qemu-aarch64 >/dev/null || {
  echo "release packaging requires qemu-aarch64 to measure the Android binary identity" >&2
  exit 1
}
HOST_SELF_INFO="$DIST/host-self-info.json"
AGENT_SELF_INFO="$DIST/agent-self-info.json"
"$HOST_PAYLOAD/neutron" self-info --json \
  --bpf-object "$AGENT_PAYLOAD/neutron.bpf.elf" \
  --bpf-object "$AGENT_PAYLOAD/neutron-stacks.bpf.elf" \
  > "$HOST_SELF_INFO"
qemu-aarch64 "$AGENT_PAYLOAD/neutron-agent" self-info --json > "$AGENT_SELF_INFO"

cat > "$AGENT_PAYLOAD/install-android.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_SERIAL:?Set ANDROID_SERIAL to the explicit authorized USB device serial}"
ADB=(adb -s "$ANDROID_SERIAL")
INSTALL_ROOT=/data/local/share/neutron
STAGE_ROOT="/data/local/tmp/neutron-install-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM"
NEXT_SUFFIX=".new.$$.$RANDOM"
BACKUP_ROOT="$INSTALL_ROOT/previous$NEXT_SUFFIX"

cd "$(dirname "${BASH_SOURCE[0]}")"

sha256sum --check --strict --quiet SHA256SUMS

if [[ -n "$(find packs ! -type d ! -type f -print -quit)" ]]; then
  echo "packs may contain only directories and regular files" >&2
  exit 1
fi
PACK_FILES=()
while IFS= read -r -d '' path; do
  relative=${path#packs/}
  if [[ ! "$relative" =~ ^[A-Za-z0-9._/-]+$ || "/$relative/" == *"/../"* ]]; then
    echo "unsafe pack path: $relative" >&2
    exit 1
  fi
  if [[ -f "$path" ]]; then
    PACK_FILES+=("$relative")
  fi
done < <(find packs -mindepth 1 -print0 | LC_ALL=C sort -z)

STAGE_FILES=(neutron-agent neutron.bpf.elf neutron-stacks.bpf.elf)
for relative in "${PACK_FILES[@]}"; do
  STAGE_FILES+=("packs/$relative")
done
for relative in "${STAGE_FILES[@]}"; do
  if [[ ! -f "$relative" || -L "$relative" ]]; then
    echo "payload entry is not a regular file: $relative" >&2
    exit 1
  fi
  if ! awk -v path="./$relative" \
    'substr($0, 65, 2) == "  " && substr($0, 67) == path { found = 1 }
     END { exit found ? 0 : 1 }' SHA256SUMS; then
    echo "payload entry is absent from SHA256SUMS: $relative" >&2
    exit 1
  fi
done

if [[ ! "$ANDROID_SERIAL" =~ ^[A-Za-z0-9._-]+$ || "$ANDROID_SERIAL" == emulator-* ]]; then
  echo "ANDROID_SERIAL must name one physical USB device" >&2
  exit 1
fi
if ! adb devices -l | awk -v serial="$ANDROID_SERIAL" '
  $1 == serial && $2 == "device" {
    for (i = 3; i <= NF; i++) if ($i ~ /^usb:/) found = 1
  }
  END { exit found ? 0 : 1 }
'; then
  echo "ANDROID_SERIAL is not an attached authorized USB device" >&2
  exit 1
fi

if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
  echo "the selected ADB device is not connected and authorized" >&2
  exit 1
fi

cleanup() {
  "${ADB[@]}" shell "rm -rf '$STAGE_ROOT'" >/dev/null 2>&1 || true
  "${ADB[@]}" shell "su -c 'rm -f $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX; rm -rf $INSTALL_ROOT/packs$NEXT_SUFFIX'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

json_identity() {
  local value=$1
  value=$(LC_ALL=C printf '%s' "$value" | LC_ALL=C tr -cd 'A-Za-z0-9 ._:/@,+()=_-')
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

model=$("${ADB[@]}" exec-out getprop ro.product.model | head -c 512)
fingerprint=$("${ADB[@]}" exec-out getprop ro.build.fingerprint | head -c 512)
boot_id=$("${ADB[@]}" exec-out cat /proc/sys/kernel/random/boot_id | head -c 512)
printf '{"device":{"serial":%s,"model":%s,"fingerprint":%s,"boot_id":%s}}\n' \
  "$(json_identity "$ANDROID_SERIAL")" \
  "$(json_identity "$model")" \
  "$(json_identity "$fingerprint")" \
  "$(json_identity "$boot_id")"
echo "destinations=$INSTALL_ROOT/neutron-agent,$INSTALL_ROOT/neutron.bpf.elf,$INSTALL_ROOT/neutron-stacks.bpf.elf,$INSTALL_ROOT/packs"

"${ADB[@]}" shell "mkdir -p '$STAGE_ROOT/packs'"
"${ADB[@]}" push neutron-agent "$STAGE_ROOT/neutron-agent"
"${ADB[@]}" push neutron.bpf.elf "$STAGE_ROOT/neutron.bpf.elf"
"${ADB[@]}" push neutron-stacks.bpf.elf "$STAGE_ROOT/neutron-stacks.bpf.elf"
for relative in "${PACK_FILES[@]}"; do
  parent=${relative%/*}
  if [[ "$parent" == "$relative" ]]; then
    stage_parent="$STAGE_ROOT/packs"
  else
    stage_parent="$STAGE_ROOT/packs/$parent"
  fi
  "${ADB[@]}" shell "mkdir -p '$stage_parent'"
  "${ADB[@]}" push "packs/$relative" "$STAGE_ROOT/packs/$relative"
done

if IFS= read -r _ < <("${ADB[@]}" exec-out \
  "find '$STAGE_ROOT' ! -type d ! -type f -print -quit"); then
  echo "device staging contains a non-regular entry" >&2
  exit 1
fi
if ! cmp -s \
  <(printf './%s\0' "${STAGE_FILES[@]}" | LC_ALL=C sort -z) \
  <("${ADB[@]}" exec-out "cd '$STAGE_ROOT' && find . -type f -print0" | LC_ALL=C sort -z); then
  echo "device staging file list differs from the packaged allowlist" >&2
  exit 1
fi

"${ADB[@]}" shell "su -c 'set -eu
mkdir -p $INSTALL_ROOT $INSTALL_ROOT/runtime $INSTALL_ROOT/runs
chown 0:0 $INSTALL_ROOT $INSTALL_ROOT/runtime $INSTALL_ROOT/runs
chmod 0700 $INSTALL_ROOT $INSTALL_ROOT/runtime $INSTALL_ROOT/runs
[ -f $STAGE_ROOT/neutron-agent ]
[ ! -L $STAGE_ROOT/neutron-agent ]
[ -f $STAGE_ROOT/neutron.bpf.elf ]
[ ! -L $STAGE_ROOT/neutron.bpf.elf ]
[ -f $STAGE_ROOT/neutron-stacks.bpf.elf ]
[ ! -L $STAGE_ROOT/neutron-stacks.bpf.elf ]
cp $STAGE_ROOT/neutron-agent $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX
cp $STAGE_ROOT/neutron.bpf.elf $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX
cp $STAGE_ROOT/neutron-stacks.bpf.elf $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX
chown 0:0 $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX
chmod 0700 $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX
chmod 0600 $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX
rm -rf $INSTALL_ROOT/packs$NEXT_SUFFIX
mkdir -p $INSTALL_ROOT/packs$NEXT_SUFFIX
chown 0:0 $INSTALL_ROOT/packs$NEXT_SUFFIX
chmod 0700 $INSTALL_ROOT/packs$NEXT_SUFFIX'"

for relative in "${PACK_FILES[@]}"; do
  parent=${relative%/*}
  if [[ "$parent" == "$relative" ]]; then
    destination_parent="$INSTALL_ROOT/packs$NEXT_SUFFIX"
  else
    destination_parent="$INSTALL_ROOT/packs$NEXT_SUFFIX/$parent"
  fi
  "${ADB[@]}" shell "su -c 'set -eu
mkdir -p $destination_parent
[ -f $STAGE_ROOT/packs/$relative ]
[ ! -L $STAGE_ROOT/packs/$relative ]
cp $STAGE_ROOT/packs/$relative $INSTALL_ROOT/packs$NEXT_SUFFIX/$relative'"
done

"${ADB[@]}" shell "su -c 'set -eu
chown -R 0:0 $INSTALL_ROOT/packs$NEXT_SUFFIX
find $INSTALL_ROOT/packs$NEXT_SUFFIX -type d -exec chmod 0700 {} \;
find $INSTALL_ROOT/packs$NEXT_SUFFIX -type f -exec chmod 0600 {} \;'"

verify_device_hash() {
  local source=$1
  local destination=$2
  local expected actual
  expected=$(sha256sum "$source" | awk '{print $1}')
  actual=$("${ADB[@]}" shell "su -c 'sha256sum $destination'" | tr -d '\r' | awk 'NR == 1 {print $1}')
  if [[ ! "$actual" =~ ^[0-9a-f]{64}$ || "$actual" != "$expected" ]]; then
    "${ADB[@]}" shell "su -c 'rm -f $destination'" >/dev/null 2>&1 || true
    echo "device SHA-256 mismatch for $destination" >&2
    exit 1
  fi
  echo "verified_sha256=$actual path=$destination"
}

verify_device_hash neutron-agent "$INSTALL_ROOT/neutron-agent$NEXT_SUFFIX"
verify_device_hash neutron.bpf.elf "$INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX"
verify_device_hash neutron-stacks.bpf.elf "$INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX"

for relative in "${PACK_FILES[@]}"; do
  verify_device_hash "packs/$relative" "$INSTALL_ROOT/packs$NEXT_SUFFIX/$relative"
done

"${ADB[@]}" shell "su -c 'set -eu
rm -rf $BACKUP_ROOT
mkdir -p $BACKUP_ROOT
chown 0:0 $BACKUP_ROOT
chmod 0700 $BACKUP_ROOT
restore_backup() {
  [ ! -e $BACKUP_ROOT/neutron-agent ] || {
    rm -f $INSTALL_ROOT/neutron-agent
    mv $BACKUP_ROOT/neutron-agent $INSTALL_ROOT/neutron-agent
  }
  [ ! -e $BACKUP_ROOT/neutron.bpf.elf ] || {
    rm -f $INSTALL_ROOT/neutron.bpf.elf
    mv $BACKUP_ROOT/neutron.bpf.elf $INSTALL_ROOT/neutron.bpf.elf
  }
  [ ! -e $BACKUP_ROOT/neutron-stacks.bpf.elf ] || {
    rm -f $INSTALL_ROOT/neutron-stacks.bpf.elf
    mv $BACKUP_ROOT/neutron-stacks.bpf.elf $INSTALL_ROOT/neutron-stacks.bpf.elf
  }
  [ ! -e $BACKUP_ROOT/packs ] || {
    rm -rf $INSTALL_ROOT/packs
    mv $BACKUP_ROOT/packs $INSTALL_ROOT/packs
  }
  rmdir $BACKUP_ROOT 2>/dev/null || true
}
trap \"restore_backup; exit 1\" 1 2 15
if { [ ! -e $INSTALL_ROOT/neutron-agent ] || mv $INSTALL_ROOT/neutron-agent $BACKUP_ROOT/neutron-agent; } &&
   { [ ! -e $INSTALL_ROOT/neutron.bpf.elf ] || mv $INSTALL_ROOT/neutron.bpf.elf $BACKUP_ROOT/neutron.bpf.elf; } &&
   { [ ! -e $INSTALL_ROOT/neutron-stacks.bpf.elf ] || mv $INSTALL_ROOT/neutron-stacks.bpf.elf $BACKUP_ROOT/neutron-stacks.bpf.elf; } &&
   { [ ! -e $INSTALL_ROOT/packs ] || mv $INSTALL_ROOT/packs $BACKUP_ROOT/packs; }; then
  :
else
  restore_backup
  trap - 1 2 15
  exit 1
fi
rollback_publish() {
  rm -f $INSTALL_ROOT/neutron-agent $INSTALL_ROOT/neutron.bpf.elf $INSTALL_ROOT/neutron-stacks.bpf.elf
  rm -rf $INSTALL_ROOT/packs
  restore_backup
}
trap \"rollback_publish; exit 1\" 1 2 15
if mv $INSTALL_ROOT/neutron-agent$NEXT_SUFFIX $INSTALL_ROOT/neutron-agent &&
   mv $INSTALL_ROOT/neutron.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron.bpf.elf &&
   mv $INSTALL_ROOT/neutron-stacks.bpf.elf$NEXT_SUFFIX $INSTALL_ROOT/neutron-stacks.bpf.elf &&
   mv $INSTALL_ROOT/packs$NEXT_SUFFIX $INSTALL_ROOT/packs; then
  trap - 1 2 15
  rm -rf $BACKUP_ROOT
else
  rollback_publish
  trap - 1 2 15
  exit 1
fi'"

"${ADB[@]}" shell "rm -rf '$STAGE_ROOT'"
trap - EXIT
echo "installed root-private agent at $INSTALL_ROOT/neutron-agent"
EOF
chmod 0755 "$AGENT_PAYLOAD/install-android.sh"

cat > "$AGENT_PAYLOAD/INSTALL.md" <<'EOF'
# Android agent install

Install only on an authorized rooted device selected by its exact ADB serial:

```bash
export ANDROID_SERIAL=USB_SERIAL
./install-android.sh
adb -s "$ANDROID_SERIAL" exec-out \
  "su -c '/data/local/share/neutron/neutron-agent doctor --json --smoke'" \
  > neutron.doctor.json
jq '{schema, compatible, object, smoke}' neutron.doctor.json
```

The installer first verifies the archive's internal `SHA256SUMS`. It then uses
an exact file allowlist in a unique `/data/local/tmp/neutron-install-*` staging
directory and always removes it. It copies only named regular pack files into
a root-private candidate. Final directories and the agent use mode `0700`;
BPF objects and pack files use mode `0600`. Candidate hashes are verified
before replacing an existing install, and ordinary publication failures roll
back to the previous installed set.

The archive also contains `schemas/` for host-side validation and
`probe/neutron-probe.apk` for separately authorized app testing. The installer
does not copy schemas to the device or install the probe APK.
EOF

for payload in "$HOST_PAYLOAD" "$AGENT_PAYLOAD"; do
  find "$payload" -type d -exec chmod 0755 {} +
  find "$payload" -type f -exec chmod 0644 {} +
done
chmod 0755 "$HOST_PAYLOAD/neutron"
chmod 0755 "$AGENT_PAYLOAD/neutron" "$AGENT_PAYLOAD/neutron-agent" "$AGENT_PAYLOAD/install-android.sh"

for payload in "$HOST_PAYLOAD" "$AGENT_PAYLOAD"; do
  (
    cd "$payload"
    find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
    chmod 0644 SHA256SUMS
  )
done

echo "==> Creating archives"
create_payload_archive() {
  local output=$1 payload=$2
  LC_ALL=C TAR_OPTIONS= ZSTD_CLEVEL=19 ZSTD_NBTHREADS=1 \
    tar -C "$DIST" --format=gnu \
      --sort=name --mtime="@$ARCHIVE_EPOCH" --owner=0 --group=0 \
      --numeric-owner --zstd -cf "$output" "$payload"
}

create_source_archive() {
  local output=$1
  git archive --format=tar --mtime="$BUILD_TIMESTAMP" \
    --prefix="neutron-v${VERSION}/" HEAD | gzip -n -9 > "$output"
}

create_archive_twice() {
  local output=$1 creator=$2
  local check="${output}.reproducibility-check"
  shift 2
  "$creator" "$output" "$@"
  "$creator" "$check" "$@"
  if ! cmp -s "$output" "$check"; then
    echo "archive serialization is not reproducible: $(basename "$output")" >&2
    rm -f -- "$check"
    exit 1
  fi
  rm -f -- "$check"
}

create_archive_twice "$DIST/$HOST_NAME.tar.zst" create_payload_archive "$HOST_NAME"
create_archive_twice "$DIST/$AGENT_NAME.tar.zst" create_payload_archive "$AGENT_NAME"
create_archive_twice "$DIST/$SOURCE_NAME" create_source_archive

RUSTC_VERSION=$(rustc --version)
CARGO_VERSION=$(cargo --version)
BPF_LINKER_VERSION=$(bpf-linker --version | head -n 1)
GRADLE_VERSION=$(sed -n 's#.*gradle-\([0-9][0-9.]*\)-bin\.zip#\1#p' \
  probe-app/gradle/wrapper/gradle-wrapper.properties)
GRADLE_SHA256=$(sed -n 's/^distributionSha256Sum=//p' \
  probe-app/gradle/wrapper/gradle-wrapper.properties)
AGP_VERSION=$(sed -n 's/.*com\.android\.application" version "\([0-9][0-9.]*\)".*/\1/p' \
  probe-app/build.gradle)
ANDROID_COMPILE_SDK=$(sed -n 's/^ *compileSdk \([0-9][0-9]*\)$/\1/p' \
  probe-app/app/build.gradle)
ANDROID_BUILD_TOOLS=$(sed -n 's/^ *buildToolsVersion "\([0-9][0-9.]*\)"$/\1/p' \
  probe-app/app/build.gradle)
JAVA_PROPERTIES=$(java -XshowSettings:properties -version 2>&1)
JAVA_RUNTIME=$(printf '%s\n' "$JAVA_PROPERTIES" | sed -n 's/^ *java\.runtime\.version = //p' | head -n 1)
JAVA_VENDOR=$(printf '%s\n' "$JAVA_PROPERTIES" | sed -n 's/^ *java\.vendor = //p' | head -n 1)
AAPT2_VERSION=$(aapt2 version | head -n 1)
APKSIGNER_VERSION=$(apksigner --version | head -n 1)
RUNNER_IMAGE_OS=${ImageOS:-local-$(uname -s)}
RUNNER_IMAGE_VERSION=${ImageVersion:-unqualified}
BUILD_RUNNER_ARCH=${RUNNER_ARCH:-$(uname -m)}
BUILD_RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-local}
if [[ "$STRICT_RELEASE" == "true" ]]; then
  for required in ImageOS ImageVersion RUNNER_ARCH RUNNER_ENVIRONMENT; do
    if [[ -z "${!required:-}" ]]; then
      echo "signed release builds require exact GitHub runner identity in $required" >&2
      exit 1
    fi
  done
fi
for value in \
  "$GRADLE_VERSION" "$GRADLE_SHA256" "$AGP_VERSION" \
  "$ANDROID_COMPILE_SDK" "$ANDROID_BUILD_TOOLS" "$JAVA_RUNTIME" "$JAVA_VENDOR"; do
  if [[ -z "$value" ]]; then
    echo "could not derive complete release toolchain provenance" >&2
    exit 1
  fi
done
HOST_SHA256=$(sha256sum "$DIST/$HOST_NAME.tar.zst" | cut -d ' ' -f 1)
AGENT_SHA256=$(sha256sum "$DIST/$AGENT_NAME.tar.zst" | cut -d ' ' -f 1)
SOURCE_SHA256=$(sha256sum "$DIST/$SOURCE_NAME" | cut -d ' ' -f 1)
HOST_BINARY_SHA256=$(sha256sum target/x86_64-unknown-linux-gnu/release/neutron | cut -d ' ' -f 1)
AGENT_BINARY_SHA256=$(sha256sum target/aarch64-unknown-linux-musl/release/neutron | cut -d ' ' -f 1)
BPF_SHA256=$(sha256sum neutron.bpf.elf | cut -d ' ' -f 1)
BPF_STACKS_SHA256=$(sha256sum neutron-stacks.bpf.elf | cut -d ' ' -f 1)
MINISIGN_PUBLIC_KEY_SHA256=
if [[ "$STRICT_RELEASE" == "true" ]]; then
  MINISIGN_PUBLIC_KEY_SHA256=$(release_minisign_public_key_sha256)
fi

export NEUTRON_PROV_VERSION="$VERSION"
export NEUTRON_PROV_GIT_COMMIT="$GIT_COMMIT"
export NEUTRON_PROV_GIT_DIRTY="$GIT_DIRTY"
export NEUTRON_PROV_BUILD_TIMESTAMP="$BUILD_TIMESTAMP"
export NEUTRON_PROV_RUSTC="$RUSTC_VERSION"
export NEUTRON_PROV_CARGO="$CARGO_VERSION"
export NEUTRON_PROV_BPF_LINKER="$BPF_LINKER_VERSION"
export NEUTRON_PROV_JAVA_RUNTIME="$JAVA_RUNTIME"
export NEUTRON_PROV_JAVA_VENDOR="$JAVA_VENDOR"
export NEUTRON_PROV_GRADLE="$GRADLE_VERSION"
export NEUTRON_PROV_GRADLE_SHA256="$GRADLE_SHA256"
export NEUTRON_PROV_AGP="$AGP_VERSION"
export NEUTRON_PROV_COMPILE_SDK="$ANDROID_COMPILE_SDK"
export NEUTRON_PROV_BUILD_TOOLS="$ANDROID_BUILD_TOOLS"
export NEUTRON_PROV_AAPT2="$AAPT2_VERSION"
export NEUTRON_PROV_APKSIGNER="$APKSIGNER_VERSION"
export NEUTRON_PROV_RUNNER_OS="$RUNNER_IMAGE_OS"
export NEUTRON_PROV_RUNNER_IMAGE_VERSION="$RUNNER_IMAGE_VERSION"
export NEUTRON_PROV_RUNNER_ARCH="$BUILD_RUNNER_ARCH"
export NEUTRON_PROV_RUNNER_ENVIRONMENT="$BUILD_RUNNER_ENVIRONMENT"
export NEUTRON_PROV_PROBE_PACKAGE="$PROBE_PACKAGE"
export NEUTRON_PROV_PROBE_VERSION_CODE="$PROBE_VERSION_CODE"
export NEUTRON_PROV_PROBE_VERSION_NAME="$PROBE_VERSION_NAME"
export NEUTRON_PROV_PROBE_TARGET_SDK="$PROBE_TARGET_SDK"
export NEUTRON_PROV_PROBE_CERT_SHA256="$PROBE_CERT_SHA256"
export NEUTRON_PROV_PROBE_BUILD_TYPE="$PROBE_BUILD_TYPE"
export NEUTRON_PROV_PROBE_DEBUGGABLE="$PROBE_DEBUGGABLE"
export NEUTRON_PROV_STRICT_RELEASE="$STRICT_RELEASE"
export NEUTRON_PROV_APPROVED_PROBE_CERT_SHA256="${NEUTRON_APPROVED_PROBE_CERT_SHA256:-}"
export NEUTRON_PROV_MINISIGN_PUBLIC_KEY_SHA256="$MINISIGN_PUBLIC_KEY_SHA256"
export NEUTRON_PROV_HOST_SELF_INFO="$HOST_SELF_INFO"
export NEUTRON_PROV_AGENT_SELF_INFO="$AGENT_SELF_INFO"
export NEUTRON_PROV_HOST_NAME="$HOST_NAME.tar.zst"
export NEUTRON_PROV_AGENT_NAME="$AGENT_NAME.tar.zst"
export NEUTRON_PROV_SOURCE_NAME="$SOURCE_NAME"
export NEUTRON_PROV_HOST_SHA256="$HOST_SHA256"
export NEUTRON_PROV_AGENT_SHA256="$AGENT_SHA256"
export NEUTRON_PROV_SOURCE_SHA256="$SOURCE_SHA256"
export NEUTRON_PROV_HOST_BINARY_SHA256="$HOST_BINARY_SHA256"
export NEUTRON_PROV_AGENT_BINARY_SHA256="$AGENT_BINARY_SHA256"
export NEUTRON_PROV_BPF_SHA256="$BPF_SHA256"
export NEUTRON_PROV_BPF_STACKS_SHA256="$BPF_STACKS_SHA256"
export NEUTRON_PROV_PROBE_SHA256="$PROBE_SHA256"
node scripts/generate-provenance.mjs "$DIST/provenance.json"
rm -f "$HOST_SELF_INFO" "$AGENT_SELF_INFO"

CARGO_METADATA="$DIST/cargo-metadata.json"
cargo metadata --locked --format-version 1 > "$CARGO_METADATA"
node scripts/generate-sbom.mjs \
  "$CARGO_METADATA" \
  "$GRADLE_DEPENDENCIES" \
  "$DIST/SBOM.spdx.json" \
  "$VERSION" \
  "$BUILD_TIMESTAMP" \
  "https://github.com/andrei-ilyushchyts-0x01/neutron/releases/tag/v$VERSION#sbom-$GIT_COMMIT" \
  "$HOST_NAME.tar.zst" "$HOST_SHA256" \
  "$AGENT_NAME.tar.zst" "$AGENT_SHA256" \
  "$SOURCE_NAME" "$SOURCE_SHA256" \
  "$PROBE_SHA256"
node scripts/validate-spdx.mjs "$DIST/SBOM.spdx.json"
rm -f "$CARGO_METADATA" "$GRADLE_DEPENDENCIES"

(
  cd "$DIST"
  sha256sum \
    "$HOST_NAME.tar.zst" \
    "$AGENT_NAME.tar.zst" \
    "$SOURCE_NAME" \
    SBOM.spdx.json \
    provenance.json > SHA256SUMS
)

if [[ "$STRICT_RELEASE" == "true" ]]; then
  command -v minisign >/dev/null || {
    echo "strict release signing requires minisign" >&2
    exit 1
  }
  mkdir -p "$DIST/signatures"
  minisign -Sm "$DIST/SHA256SUMS" -s "$SIGNING_KEY" \
    -x "$DIST/signatures/SHA256SUMS.minisig"
  release_verify_minisign_identity \
    "$DIST/SHA256SUMS" "$DIST/signatures/SHA256SUMS.minisig" "$STRICT_RELEASE"
else
  echo "WARNING: unpublished assets are unsigned (set SIGNING_KEY for release)" >&2
fi

mv "$DIST" "$FINAL_DIST"
trap - EXIT

echo "Release assets:"
echo "  $FINAL_DIST/$HOST_NAME.tar.zst"
echo "  $FINAL_DIST/$AGENT_NAME.tar.zst"
echo "  $FINAL_DIST/$SOURCE_NAME"
echo "  $FINAL_DIST/SBOM.spdx.json"
echo "  $FINAL_DIST/provenance.json"
echo "  $FINAL_DIST/SHA256SUMS"
if [[ -d "$FINAL_DIST/signatures" ]]; then
  echo "  $FINAL_DIST/signatures/"
fi
