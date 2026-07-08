# Wallet Boundary Case Study

This is a redacted-style example for a wallet app assessment. Names, package
IDs, service names, and counts are illustrative. The point is the evidence
boundary: Neutron shows kernel-boundary handoffs. It does not prove an
attestation verdict, server decision, or Java/Kotlin control-flow branch.

## Scenario

Question:

During wallet launch and the first sensitive action, does the app cross
security-relevant Android boundaries such as `/proc`, Binder security services,
native driver surfaces, sockets, or RWX memory?

Scope:

- rooted Pixel-class Android device
- package-scoped capture for `com.example.wallet`
- Binder tracing enabled
- baseline capture before app launch
- test capture during launch and the sensitive action
- health sidecar collected for each capture

## Capture

```bash
adb shell "su -c '/data/local/tmp/neutron \
  --json --raw --binder --driver-pack binder \
  --match-package com.example.wallet \
  --capture matched+context=2s \
  --rate-limit 1000 \
  --max-output-size 250mb \
  --health-output /data/local/tmp/wallet-test.health.ndjson \
  --output /data/local/tmp/wallet-test.ndjson'"
```

Binder helper files:

```bash
adb shell service list -p > service-list-p.txt

neutron binder-map service-list \
  --input service-list-p.txt \
  --output binder-catalog.json

neutron binder-map template wallet-test.ndjson \
  --output binder-services.template.json
```

After analyst review, the exact service map contained only pairs that were
verified for the observed `(callee_pid,target_node)` values.

Report:

```bash
neutron report wallet-test.ndjson \
  --baseline wallet-baseline.ndjson \
  --package com.example.wallet \
  --binder-services binder-services.json \
  --binder-catalog binder-catalog.json \
  --title "Wallet Boundary Report" \
  --output wallet-boundary-report.md
```

## Evidence Observed

The report highlighted:

- `/proc/self/maps` and `/proc/self/status` reads during startup
- Binder calls attributed to candidate or exact security-related services
- ioctl activity on `/dev/binder`
- network socket setup during the action window
- no RWX/WX memory transition in the captured window
- no `callee_crashed` Binder status in the captured window

The capture health was clean in this example: no output cap and no degraded
counter. That means the negative observations above are stronger for this
specific window, but they are still not a global claim about all app behavior.

## Interpretation

Supported by the Neutron evidence:

- The wallet crossed kernel boundaries associated with process inspection,
  Binder IPC, and sockets during the tested scenario.
- Binder handoff happened at the kernel boundary for the listed
  `callee_pid/target_node/code` combinations.
- Exact Binder service labels were used only where the service map supplied
  verified `(callee_pid,target_node)` mappings.
- PID catalog labels were treated as candidate services, not exact targets.

Not supported by the Neutron evidence alone:

- Whether a remote attestation verdict passed or failed.
- Whether Java/Kotlin code made a specific security decision.
- The full AIDL argument payload for each Binder transaction.
- Whether any observed root-detection behavior is malicious, benign, or
  required by product policy.
- Whether the app is secure.

## Follow-Up

The next step was static or dynamic userspace analysis focused on the exact
startup and action windows:

- inspect call sites that read `/proc/self/maps` and `/proc/self/status`
- map Binder transaction `code` values to AIDL interfaces where available
- compare the network request timing with app logs or proxy evidence
- repeat the capture with a narrower trigger if health becomes degraded or the
  output cap is hit
