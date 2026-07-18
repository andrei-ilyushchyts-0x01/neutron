#!/usr/bin/env bash
# Shared fail-closed identity checks for release packaging. This file defines
# functions only so the negative paths can be exercised without building or
# signing release artifacts.

release_strict_enabled() {
    [[ "${REQUIRE_SIGNATURES:-0}" == "1" || -n "${SIGNING_KEY:-}" ]]
}

release_validate_strict_inputs() {
    local strict=$1 required
    [[ "$strict" == "true" ]] || return 0

    for required in \
        SIGNING_KEY \
        NEUTRON_PROBE_KEYSTORE \
        NEUTRON_PROBE_STORE_PASSWORD \
        NEUTRON_PROBE_KEY_ALIAS \
        NEUTRON_PROBE_KEY_PASSWORD \
        NEUTRON_APPROVED_PROBE_CERT_SHA256 \
        NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY; do
        if [[ -z "${!required:-}" ]]; then
            echo "signed release builds require $required for an approved release identity" >&2
            return 1
        fi
    done

    if [[ ! "$NEUTRON_APPROVED_PROBE_CERT_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
        echo "NEUTRON_APPROVED_PROBE_CERT_SHA256 must be 64 lowercase hex characters" >&2
        return 1
    fi
    if [[ ! "$NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{40,128}={0,2}$ ]]; then
        echo "NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY must be one raw minisign public key" >&2
        return 1
    fi
}

release_assert_probe_certificate() {
    local actual=$1 strict=$2
    [[ "$strict" == "true" ]] || return 0
    if [[ "$actual" != "$NEUTRON_APPROVED_PROBE_CERT_SHA256" ]]; then
        echo "probe certificate does not match NEUTRON_APPROVED_PROBE_CERT_SHA256" >&2
        return 1
    fi
}

release_verify_minisign_identity() {
    local manifest=$1 signature=$2 strict=$3
    [[ "$strict" == "true" ]] || return 0
    command -v minisign >/dev/null || {
        echo "strict release signing requires minisign" >&2
        return 1
    }
    minisign -Vm "$manifest" -x "$signature" \
        -P "$NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY"
}

release_minisign_public_key_sha256() {
    printf '%s' "$NEUTRON_APPROVED_MINISIGN_PUBLIC_KEY" | sha256sum | cut -d ' ' -f 1
}
