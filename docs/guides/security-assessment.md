# Security Assessment Guide

End-to-end workflow for authorized security assessment of Android
applications using neutron. This guide covers root detection analysis,
network traffic enumeration, file probing, and IPC analysis on Pixel 8
Pro on the explicitly validated build lines in the support matrix. Other
Android/GKI combinations remain experimental even when they expose kernel 6.1+.

> **Authorization required.** Only use this tool on devices and
> applications you own or have explicit written authorization to test.

## Environment Setup

```bash
# 1. Select exactly one physical device, then build and deploy.
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
./build.sh

# 2. Find one target PID (launch the app first) and reject unexpected output.
TARGET_PID="$("${ADB[@]}" shell pidof -s com.target.app | tr -d '\r')"
[[ "$TARGET_PID" =~ ^[0-9]+$ ]] || { echo "invalid target PID" >&2; exit 1; }

# 3. Create one root-private run directory.
NEUTRON=/data/local/share/neutron/neutron-agent
RUN=/data/local/share/neutron/runs/security-$(date -u +%Y%m%dT%H%M%SZ)
"${ADB[@]}" shell "su -c 'install -d -m 0700 ${RUN}'"
```

The installed default object is
`/data/local/share/neutron/neutron.bpf.elf`; no explicit `--object` is needed.
Retrieve private output with `adb -s "$ANDROID_SERIAL" exec-out "su -c
'cat ...'"`; do not make evidence world-readable for `adb pull`.

## Default workflow: rule-engine findings

For most assessments, start with the bundled detector pack:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --resolve-paths \
  --stacks'"
```

Findings emit to stdout. Rules T001..T015 are path/syscall-pattern based;
T016..T019 use stack-aware conditions and require `--stacks` to fire.
Examples:

- T001 fires when the app polls `/proc/self/maps` ≥ 2 times in a 10s
  window.
- T016 fires on `fstatat` for `/system/xbin/su` with `libc` on the user
  stack.
- T017 fires when ≥ 5 syscalls in 10s originate from inside the ART JIT
  code cache (`<JIT>` frame).
- T018 fires on `ptrace` resolved to `sys_ptrace` from native code.

To export findings as NDJSON for tooling:

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --resolve-paths --stacks \
  --json --output ${RUN}/findings.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/findings.ndjson'" > findings.ndjson
```

For raw events alongside findings, add `--raw`. To suppress findings
(legacy per-event-only behaviour), add `--no-findings --raw`.

## Root Detection Analysis

Root detection typically involves:

- Reading `/proc/` entries (`maps`, `mounts`, `self/status`).
- Executing `which su`, `ls /system/xbin/su`, `ls /sbin/su`.
- Checking system properties (`ro.build.tags`, `ro.debuggable`).
- Calling `stat()` / `access()` on known root artifacts.

### Capture command (raw events for ad-hoc analysis)

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --resolve-paths \
  --raw --no-findings --json \
  --output ${RUN}/raw.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/raw.ndjson'" > raw.ndjson
```

### What to Look For

| Pattern                                              | Indicator                                     |
|------------------------------------------------------|-----------------------------------------------|
| `openat` on `/proc/self/maps`                        | Reading own memory map (Frida / Xposed / Magisk module checks) |
| `faccessat` on `/sbin/su`, `/system/xbin/su`, `/system/bin/su` | Checking for su binary                |
| `openat` on `/proc/mounts`                           | Checking for unusual mounts                   |
| `faccessat` on `/data/local/tmp/frida-*`             | Frida presence check                          |
| `execve` with `which` or `ls` arguments              | Probing PATH for root tools                   |
| `prctl(PR_GET_DUMPABLE)`                             | Checking if process is debuggable             |
| `openat` on `/proc/net/tcp*`                         | Network socket enumeration (Frida-port scan)  |
| `fstatat` on `su` paths with `libc` on stack         | Native root check (T016)                      |

### Example: filter the raw stream for `/proc` reads

```bash
jq -c 'select(.nr == 56 and (.data // "") | startswith("/proc"))' raw.ndjson
```

## Network Traffic Enumeration

Capture all outbound connections and DNS-like activity.

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --raw --no-findings --json \
  --output ${RUN}/net_trace.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/net_trace.ndjson'" > net_trace.ndjson

# All connect() calls with destination
jq -r 'select(.nr == 203 and .enter == false) | "\(.comm) connect -> \(.data) ret=\(.ret)"' net_trace.ndjson

# DNS-like (port 53)
jq -r 'select(.nr == 203 and (.data // "") | contains(":53")) | .data' net_trace.ndjson

# TLS (port 443)
jq -r 'select(.nr == 203 and (.data // "") | contains(":443")) | .data' net_trace.ndjson
```

## File System Probing Analysis

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --resolve-paths \
  --raw --no-findings --json \
  --output ${RUN}/fs_trace.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/fs_trace.ndjson'" > fs_trace.ndjson

# All opened files (successful)
jq -r 'select(.nr == 56 and .enter == false and .ret > 0) | .data' fs_trace.ndjson \
  | sort | uniq -c | sort -rn | head -50

# Suspicious paths
jq -r 'select(.nr == 56 or .nr == 48) | .data' fs_trace.ndjson \
  | grep -E '(su|root|magisk|xposed|frida|supersu)' | sort | uniq
```

## IPC and Binder Analysis

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --binder \
  --raw --no-findings --json \
  --output ${RUN}/binder_trace.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/binder_trace.ndjson'" > binder_trace.ndjson

# Summary of destination processes
jq -r 'select(.type == "binder") | .to_proc' binder_trace.ndjson \
  | sort | uniq -c | sort -rn

# AIDL method codes per destination
jq -r 'select(.type == "binder") | "\(.to_proc) code=\(.code)"' binder_trace.ndjson \
  | sort | uniq -c | sort -rn

# Synthesised binder_call pairs (caller↔callee matched by debug_id) with
# completion latency. Sprint-2 PR 2.
jq -r 'select(.type == "binder_call") |
  "\(.caller_pid)→\(.callee_pid) code=\(.code) status=\(.status) lat=\(.latency_us // "-")us"' \
  binder_trace.ndjson | sort | uniq -c | sort -rn

# Calls in flight when the callee crashed (R004 evidence).
jq -c 'select(.type == "binder_call" and .status == "callee_crashed")' \
  binder_trace.ndjson
```

## Crash Investigation

Sprint-2 PR 1 introduced `process_exit` events from three independent
sources (BPF tracepoint, logcat, tombstones) and a `crash_context`
lookback ring buffer. Combined with sprint-2 PR 2 binder causality and
sprint-2 PR 3 `neutron window`, this gives a self-contained triage
workflow:

```bash
# Capture with all sources enabled (binder + crash + fdgraph all on by
# default in 1.1.0).
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid 0 \
  --binder \
  --json \
  --output ${RUN}/full_trace.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/full_trace.ndjson'" > full_trace.ndjson

# Every crash with its in-flight binder context (R004 finding).
jq -c 'select(.type == "finding" and .rule_id == "R004_binder_callee_crash")' \
  full_trace.ndjson

# All process_exit lines + their crash_context (last N events before exit).
jq -c 'select(.type == "process_exit" and .classification == "crash") |
  {pid, comm, signal_name, ctx_count: (.crash_context | length)}' \
  full_trace.ndjson

# Cut a 5-second window around every crash for triage as a standalone
# NDJSON file that can be re-fed to the rule engine.
neutron window full_trace.ndjson \
  --anchor crash --around 5s \
  > crash_windows.ndjson

# The same windows in summary form (one line per merged window):
neutron window full_trace.ndjson \
  --anchor crash --around 5s --summary
```

For the full anchor + window reference see
[docs/guides/window.md](window.md).

## Memory Integrity Analysis

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --alert-rwx \
  --raw --no-findings --json'" \
  | jq -r 'select(.rwx_alert != null) |
    "\(.comm) \(.rwx_alert): mmap addr=\(.args[0]) size=\(.args[1]) prot=\(.args[2])"'
```

T011 in the default ruleset already fires on RWX / W^X events; raw mode
is useful when you need every occurrence rather than a summary finding.

## Stack Trace Correlation

When the call origin matters (which native function or JIT region
triggered a syscall):

```bash
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid $TARGET_PID \
  --profile security \
  --stacks \
  --raw --no-findings --json'" \
  | jq -r 'select(.stack and (.stack | contains("su"))) | "\(.name) \(.data) | \(.stack)"'
```

Stack-aware rules (T016..T019) automate the most common patterns. See
[writing-rules.md](writing-rules.md) for authoring custom ones.

## Example: end-to-end fintech app assessment

A typical 10-minute session against a hardened banking app on Pixel 8 Pro:

```bash
# Terminal 1: rule-engine findings live + capture full raw stream
"${ADB[@]}" shell "su -c '${NEUTRON} trace \
  --pid ${TARGET_PID} \
  --profile security \
  --resolve-paths \
  --follow-children \
  --binder \
  --stacks \
  --raw --json \
  --output ${RUN}/full_trace.ndjson'"

# Terminal 2: drive the app — login, biometric prompt, payment flow.
# Watch findings stream in Terminal 1. Each [FINDING] block is one
# triggered detector with evidence and process context.

# After session: retrieve the private file through the selected device.
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/full_trace.ndjson'" > full_trace.ndjson

echo "Total raw events:"
wc -l full_trace.ndjson

echo "Syscall distribution:"
jq -r 'select(.name) | .name' full_trace.ndjson \
  | sort | uniq -c | sort -rn | head -20

echo "Findings emitted:"
jq -r 'select(.type == "finding") | .rule_id' full_trace.ndjson \
  | sort | uniq -c | sort -rn

echo "Outbound connections:"
jq -r 'select(.nr == 203 and .enter == false and .ret == 0) | .data' full_trace.ndjson \
  | sort | uniq
```

Depending on the behavior actually observed, relevant rules may include T001
(proc/self/maps polling), T003 (TracerPid scrape), T004 or T016 (su binary
checks), T013 (SELinux status), T014 (property service), T017 (JIT-cache
syscalls), and T011 (RWX/W^X events). A rule firing is a review lead, not a
vulnerability finding or proof of intent.

## Output Enrichment with Python

```python
#!/usr/bin/env python3
"""Enrich trace with process names and flag suspicious patterns."""
import json, os, subprocess

# Build PID → app name map
pid_map = {}
serial = os.environ['ANDROID_SERIAL']
result = subprocess.run(['adb', '-s', serial, 'shell', 'ps', '-A'],
                        capture_output=True, text=True, check=True)
for line in result.stdout.splitlines()[1:]:
    parts = line.split()
    if len(parts) >= 9:
        pid_map[parts[1]] = parts[-1]

SUSPICIOUS = [
    '/su', 'xbin/su', '/magisk', 'frida', 'xposed',
    '/proc/mounts', '/proc/self/maps', 'which su',
]

with open('full_trace.ndjson') as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue

        data = e.get('data', '')
        flags = [s for s in SUSPICIOUS if s in data]
        if flags:
            name = pid_map.get(str(e.get('pid')), 'unknown')
            print(f"[SUSPICIOUS] {e.get('name')} by {e.get('comm')} "
                  f"({name}): {data!r}")
            print(f"  flags: {flags}")
```
