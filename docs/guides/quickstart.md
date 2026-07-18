# Quickstart

This quickstart uses only release artifacts and an explicitly selected rooted
Android device. It does not write evidence under `/data/local/tmp`.

## Prerequisites

- An authorized rooted device listed in [PRODUCT.md](../../PRODUCT.md).
- `adb`, `zstd`, `gh`, `minisign`, and a downloaded Neutron 1.5 release.
- One explicit physical-device serial from `adb devices -l`.
- The Neutron minisign public key obtained through its separately documented
  trusted channel, not from the release-asset download location.

Set the serial once; every networked/device-changing command below uses it:

```bash
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
"${ADB[@]}" get-state
```

## 1. Install the Android agent

```bash
REPO=andrei-ilyushchyts-0x01/neutron
ASSET=neutron-agent-v1.5.0-rc.1-android-aarch64.tar.zst
: "${NEUTRON_RELEASE_PUBKEY:?Set the separately verified minisign public-key path}"

gh attestation verify "$ASSET" --repo "$REPO"
gh attestation verify SHA256SUMS --repo "$REPO"
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig \
  -p "$NEUTRON_RELEASE_PUBKEY"
sha256sum --check --strict --ignore-missing SHA256SUMS

tar --zstd -xf neutron-agent-v1.5.0-rc.1-android-aarch64.tar.zst
cd neutron-agent-v1.5.0-rc.1-android-aarch64
./install-android.sh
```

Do not extract or execute the installer unless attestation, minisign, and
checksum verification all succeed. The reviewed installer then verifies its
packaged hashes, uses a unique temporary
staging directory, and installs only the agent, both BPF variants, and packs
under `/data/local/share/neutron`. Schemas remain in the unpacked archive for
host-side validation. The probe APK is not installed automatically; install it
separately only when the authorized test requires that attacker model. The
installer refuses to run without `ANDROID_SERIAL`. Review `INSTALL.md` before
execution.

Record the installed identity and run a real syscall smoke test:

```bash
"${ADB[@]}" exec-out \
  "su -c '/data/local/share/neutron/neutron-agent self-info --json'" \
  > neutron.self-info.json

"${ADB[@]}" exec-out \
  "su -c '/data/local/share/neutron/neutron-agent doctor --json --smoke'" \
  > neutron.doctor.json

jq '{schema, compatible, object, smoke}' neutron.doctor.json
```

Do not call the device capture-compatible unless object ABI validation, load,
syscall event delivery, health read, and cleanup all pass.

## 2. Map a HAL target set

Create an exact endpoint list on the host, one endpoint per line:

```text
vendor.google.bluetooth_ext.IBluetoothCcc/default
```

Install that list directly into a root-private run workspace and collect two
minimal passes:

```bash
RUN_BASE=/data/local/share/neutron/runs
RUN_ID=hal-$(date -u +%Y%m%dT%H%M%SZ)

"${ADB[@]}" shell \
  "su -c 'install -d -m 0700 ${RUN_BASE} ${RUN_BASE}/work'"
"${ADB[@]}" shell \
  "su -c 'umask 077; cat > ${RUN_BASE}/work/targets.txt'" \
  < vendor_hal_targets.txt

"${ADB[@]}" shell "su -c '/data/local/share/neutron/neutron-agent \
  surface coverage \
  --targets ${RUN_BASE}/work/targets.txt \
  --minimal --repeat 2 --fail-unresolved \
  --json ${RUN_BASE}/work/coverage.json \
  --tsv ${RUN_BASE}/work/coverage.tsv \
  --run-dir ${RUN_BASE}/${RUN_ID}'"

install -d -m 0700 "$RUN_ID"
set -o pipefail
pull_bundle_file() {
  local file="$1" part="$RUN_ID/.$1.part" bytes
  timeout 30s "${ADB[@]}" exec-out \
    "su -c 'cat ${RUN_BASE}/${RUN_ID}/${file}'" \
    | head -c 67108865 > "$part" || {
      rm -f -- "$part"
      return 1
    }
  bytes="$(wc -c < "$part")"
  if (( bytes > 67108864 )); then
    rm -f -- "$part"
    echo "refusing oversized bundle file: $file" >&2
    return 1
  fi
  mv -- "$part" "$RUN_ID/$file"
}

for file in manifest.json targets.json targets.sha256 \
  surface.coverage.json surface.coverage.tsv SHA256SUMS
do
  pull_bundle_file "$file"
done
unset -f pull_bundle_file
```

The pull list is deliberately fixed. Do not extract a tar archive produced by
the device: archive paths are device-controlled input and can escape the host
destination or expand beyond the intended bundle. Each allowlisted file above
is capped at 64 MiB and transferred into a temporary name before rename.

Verify the bundle on the host with the host release binary:

```bash
./neutron evidence verify "$RUN_ID"
./neutron surface explain \
  vendor.google.bluetooth_ext.IBluetoothCcc/default \
  --input "$RUN_ID/surface.coverage.json"
```

The coverage command reads service/VINTF inventories first, then accesses
`/proc` only for matched owner PIDs. It does not retain a full process,
library, FD, or device snapshot.

## 3. Trace one bounded scenario

Create a dedicated root-private directory before opening capture outputs:

```bash
TRACE_ID=trace-$(date -u +%Y%m%dT%H%M%SZ)
TRACE_DIR=/data/local/share/neutron/runs/$TRACE_ID
"${ADB[@]}" shell "su -c 'install -d -m 0700 ${TRACE_DIR}'"

"${ADB[@]}" shell "su -c 'timeout -s INT 20 \
  /data/local/share/neutron/neutron-agent trace \
  --json --raw --no-findings --no-logcat \
  --match-package com.example.app \
  --rate-limit 200 --max-output-size 64mb \
  --health-output ${TRACE_DIR}/capture.health.json \
  --output ${TRACE_DIR}/capture.ndjson'"
```

Exercise only the authorized scenario during the bounded interval. Retrieve
private files through root rather than weakening their modes:

```bash
"${ADB[@]}" exec-out \
  "su -c 'cat ${TRACE_DIR}/capture.ndjson'" > capture.ndjson
"${ADB[@]}" exec-out \
  "su -c 'cat ${TRACE_DIR}/capture.health.json'" > capture.health.json

jq . capture.health.json
cp -- capture.ndjson capture.complete.ndjson
health_count=$(jq -Rr 'fromjson? | select(.type == "capture_health") | 1' \
  capture.ndjson | wc -l)
case "$health_count" in
  0) jq -e '.type == "capture_health"' capture.health.json >/dev/null
     cat capture.health.json >> capture.complete.ndjson ;;
  1) tail -n 1 capture.ndjson | jq -e '.type == "capture_health"' >/dev/null ;;
  *) echo "primary capture has duplicate health records" >&2; exit 1 ;;
esac
./neutron report capture.complete.ndjson \
  --title "Authorized app scenario" > report.md
```

`status=degraded`, `incomplete`, or `unknown` makes absence-of-event claims
non-conclusive. A missing final health record is also incomplete evidence.
When `--health-output` is used, preserve exactly one final health record as
shown above before passing the stream to `report`, `diff`, or another consumer
that validates capture completeness. A sidecar with `output_cap_hit=true`
preserves telemetry, but its run status is `incomplete`.

## 4. Import external behavioral evidence

App lookup/call/proxy tests are not Neutron observations. Import them only as
separately attributed annotations linked to an exact coverage service ID:

The external probe must export its concrete runtime identity; this is an
assertion by that probe, not a Neutron-measured app identity:

```json
{
  "schema": "neutron.external-probe-runtime/v1",
  "apk_sha256": "<64 lowercase hex>",
  "signing_certificate_sha256": "<64 lowercase hex>",
  "package": "dev.neutron.probe",
  "version_code": 1,
  "version_name": "1.0",
  "target_sdk": 35,
  "device_boot_id": "12345678-1234-1234-1234-123456789abc",
  "uid": 10123,
  "install_state": "installed_enabled",
  "granted_permissions": ["android.permission.DUMP"]
}
```

```bash
./neutron evidence import \
  --run-dir "$RUN_ID" \
  --input external-probe-result.json \
  --id ccc-authorized-probe \
  --claim call-succeeded \
  --imported-from authorized-app-probe \
  --subject-id \
    service:binder:vendor.google.bluetooth_ext.IBluetoothCcc/default \
  --claim-scope '{"procedure":"direct_call","caller":"ordinary_installed_app","attempt_count":1}' \
  --probe-identity probe-runtime.json \
  --health-status complete

./neutron evidence verify "$RUN_ID"
```

Internal SHA-256 verification proves bundle integrity, not publisher
authenticity. The installation flow therefore authenticates the workflow
attestation and independently trusted minisign identity before extraction;
`provenance.json` alone is build metadata, not a signature.
