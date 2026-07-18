#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../scripts/release-identity.sh
source "$root/scripts/release-identity.sh"

unset REQUIRE_SIGNATURES SIGNING_KEY
if release_strict_enabled; then
    echo "strict mode unexpectedly enabled without a signing request" >&2
    exit 1
fi

SIGNING_KEY=/tmp/minisign.key
release_strict_enabled

REQUIRE_SIGNATURES=0
NEUTRON_PROBE_KEYSTORE=/tmp/probe.keystore
NEUTRON_PROBE_STORE_PASSWORD=store-password
NEUTRON_PROBE_KEY_ALIAS=probe
NEUTRON_PROBE_KEY_PASSWORD=key-password
NEUTRON_APPROVED_PROBE_CERT_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY=RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
release_validate_strict_inputs true

saved_cert=$NEUTRON_APPROVED_PROBE_CERT_SHA256
NEUTRON_APPROVED_PROBE_CERT_SHA256=not-a-digest
if release_validate_strict_inputs true >/dev/null 2>&1; then
    echo "strict input validation accepted a malformed probe certificate digest" >&2
    exit 1
fi
NEUTRON_APPROVED_PROBE_CERT_SHA256=$saved_cert

release_assert_probe_certificate \
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa true
if release_assert_probe_certificate \
    bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb true \
    >/dev/null 2>&1; then
    echo "strict certificate validation accepted the wrong APK signer" >&2
    exit 1
fi

mkdir -p "$root/target/tmp"
work=$(mktemp -d "${TMPDIR:-$root/target/tmp}/neutron-release-identity-test.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf 'manifest\n' > "$work/SHA256SUMS"
printf 'signature\n' > "$work/SHA256SUMS.minisig"
mkdir "$work/bin"
cat > "$work/bin/minisign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" > "$MINISIGN_TEST_LOG"
[[ "$*" == *'-P RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'* ]]
EOF
chmod 0755 "$work/bin/minisign"

export MINISIGN_TEST_LOG=$work/minisign.log
PATH="$work/bin:$PATH" release_verify_minisign_identity \
    "$work/SHA256SUMS" "$work/SHA256SUMS.minisig" true
rg -F -- '-Vm' "$work/minisign.log" >/dev/null
rg -F -- '-P RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
    "$work/minisign.log" >/dev/null

NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY=RWQBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
if PATH="$work/bin:$PATH" release_verify_minisign_identity \
    "$work/SHA256SUMS" "$work/SHA256SUMS.minisig" true \
    >/dev/null 2>&1; then
    echo "minisign identity verification accepted the wrong approved key" >&2
    exit 1
fi
