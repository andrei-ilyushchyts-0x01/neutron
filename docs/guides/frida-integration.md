# Frida + BPF Integration Guide

This guide describes the planned bidirectional integration between neutron and Frida — combining kernel-level BPF syscall visibility with Frida's in-process JavaScript instrumentation. Each covers a blind spot of the other.

## Why Combine BPF and Frida

| Capability | BPF (neutron) | Frida |
|------------|-------------------|-------|
| Syscall arguments | Supported syscall set with bounded payload snippets | Via Interceptor on libc wrappers |
| Java method calls | No | Yes (Java.use) |
| Return values at Java layer | No | Yes |
| Java stack traces | No | Yes |
| SSL/TLS plaintext | No | Yes (hook SSL_read/SSL_write or Java SSLSocket) |
| Root detection Java checks | No (only at syscall level) | Yes |
| Memory read without root | Root required | Yes (in-process) |
| Low overhead | Very low (BPF kernel filter) | Medium (JavaScript bridge) |
| Works without source code | Yes | Yes |
| Works without repackaging | Yes | Yes (with frida-server) |

The combination: Neutron records its configured kernel-boundary event set;
Frida hooks the Java/native layer and can recover context that lives only
inside the process. Neither source proves method authorization merely because
an event was observed.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Android process (app)                   │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              Frida agent (JavaScript)            │    │
│  │                                                  │    │
│  │  Java.use hooks → SSL, File, Runtime.exec       │    │
│  │  Interceptor.attach → open, connect, SSL_write  │    │
│  │  ptr_hint resolver → Memory.readUtf8String      │    │
│  │                                                  │    │
│  │  UnixSocket client → reads BPF events           │    │
│  │                    → sends synthetic events      │    │
│  └─────────────────────────────────────────────────┘    │
│                        │  ▲                              │
└────────────────────────│──│──────────────────────────────┘
                         │  │  Unix domain socket
                         │  │  NDJSON, bidirectional
┌────────────────────────▼──│──────────────────────────────┐
│             neutron (root process)                   │
│                                                          │
│  BPF event loop → JSON serialize → broadcast to agents  │
│  Receive synthetic events → emit to output stream        │
│  ptr_hint != 0 → send resolve_request to agents         │
│  Receive resolve_response → annotate and re-emit event   │
└──────────────────────────────────────────────────────────┘
```

## Current Status

The Frida integration is **planned but not yet implemented** in neutron. This document describes the intended design.

The following sections cover:
1. The designed IPC protocol
2. The Frida agent structure
3. Workflows you can implement today using Frida standalone + neutron JSON output

---

## Designed: neutron Frida Bridge

When `--frida` is passed, neutron will:

1. Bind a Unix domain socket at `--frida-socket PATH` (planned default:
   `/data/local/share/neutron/runtime/neutron.frida.sock`)
2. Accept multiple Frida agent connections
3. Broadcast every BPF event as JSON to all connected agents
4. Accept JSON lines from agents (synthetic events and resolve responses)

### New CLI Flags (planned)

| Flag | Default | Description |
|------|---------|-------------|
| `--frida` | off | Enable Frida bidirectional bridge |
| `--frida-socket PATH` | `/data/local/share/neutron/runtime/neutron.frida.sock` | Unix socket path |

### Protocol

All messages are NDJSON (one JSON object per line, `\n` terminated). The socket is bidirectional.

**neutron → agent (BPF events)**:
```json
{"source":"bpf","ts_ns":1712345678901,"pid":21093,"tid":21093,"nr":56,"name":"openat","comm":"e.bankapp","enter":true,"args":[4294967196,140234567890,524288,0,0,0],"data":"","ptr_hint":140234567890}
```

When `data` is empty and `ptr_hint != 0`, the agent should resolve the pointer. (On kernel 6.1+ this is rare — `bpf_probe_read_user_str_bytes` reads userspace memory directly. The hook stays useful when the user pointer was already invalid by the time the BPF program ran, e.g. after a `close()` race.)

**neutron → agent (resolve request)**:
```json
{"type":"resolve_request","id":"abc123","pid":21093,"ptr":140234567890,"size":128}
```

**agent → neutron (synthetic event)**:
```json
{"type":"event","source":"frida","ts_ns":1712345678901,"pid":21093,"tid":21093,"comm":"e.bankapp","name":"ssl_write","data":"GET /api/v1/auth HTTP/1.1\r\nHost: api.example.com\r\n","java_stack":"com.example.net.ApiClient.request(ApiClient.java:147)\n  ...","ret":0}
```

**agent → neutron (resolve response)**:
```json
{"type":"resolve_response","id":"abc123","data":"/data/app/com.example/.../lib/arm64/libssl.so"}
```

---

## Designed: Frida Agent Structure

`frida/agent.js` — to be injected with `frida -U -f com.target.app -l agent.js --no-pause`

### Connection

```javascript
// Connect to neutron Unix socket
const sock = new Socket('unix');
sock.connect({ path: '/data/local/share/neutron/runtime/neutron.frida.sock' });

function sendEvent(obj) {
    sock.write(JSON.stringify(obj) + '\n');
}
```

### ptr_hint Resolution

When neutron cannot read a syscall argument (e.g. the user pointer is no longer valid by the time the BPF read runs), it sends a `resolve_request`. The Frida agent, running inside the process, can read memory directly:

```javascript
sock.onMessage = function(data) {
    const msg = JSON.parse(data);
    if (msg.type === 'resolve_request') {
        try {
            const str = Memory.readUtf8String(ptr(msg.ptr), msg.size);
            sendEvent({ type: 'resolve_response', id: msg.id, data: str });
        } catch (e) {
            sendEvent({ type: 'resolve_response', id: msg.id, data: null });
        }
    }
};
```

This complements `--resolve-paths` (which uses `/proc/<pid>/fd/<fd>` readlink and `/proc/<pid>/net/tcp*` lookups) by reading raw bytes from arbitrary userspace pointers — useful for non-string buffers that the BPF program does not capture.

### Root Detection Hooks

```javascript
// Hook java.io.File.exists() — the most common root check pattern
Java.perform(function() {
    const File = Java.use('java.io.File');
    File.exists.implementation = function() {
        const path = this.getAbsolutePath();
        const result = this.exists.call(this);
        const suspicious = ['/sbin/su', '/system/xbin/su', '/system/bin/su',
                            '/data/local/tmp/su', '/system/app/Superuser.apk',
                            '/sbin/magisk', '/data/adb/magisk', '/cache/magisk.log'];
        if (suspicious.some(p => path.includes(p))) {
            sendEvent({
                type: 'event', source: 'frida',
                ts_ns: Date.now() * 1e6,
                pid: Process.id, comm: Java.androidVersion,
                name: 'root_check_file_exists',
                data: path,
                java_stack: Java.vm.getEnv().getStackTrace().join('\n'),
                ret: result ? 1 : 0
            });
        }
        return result;
    };
});
```

### SSL/TLS Plaintext Capture

```javascript
// Hook native SSL_write to capture plaintext before encryption
const libssl = Module.findExportByName(null, 'SSL_write');
if (libssl) {
    Interceptor.attach(libssl, {
        onEnter: function(args) {
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function(retval) {
            if (retval.toInt32() > 0 && this.len > 0) {
                const data = Memory.readByteArray(this.buf, Math.min(this.len, 512));
                sendEvent({
                    type: 'event', source: 'frida',
                    ts_ns: Date.now() * 1e6,
                    pid: Process.id, comm: 'SSL_write',
                    name: 'ssl_write',
                    data: hexdump(data, { length: Math.min(this.len, 512) }),
                    ret: retval.toInt32()
                });
            }
        }
    });
}
```

### Java File I/O Context

```javascript
Java.perform(function() {
    const FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.io.File').implementation = function(file) {
        const path = file.getAbsolutePath();
        sendEvent({
            type: 'event', source: 'frida',
            ts_ns: Date.now() * 1e6,
            pid: Process.id, comm: 'FileInputStream',
            name: 'java_file_open',
            data: path,
            java_stack: Java.vm.getEnv().getStackTrace().toString()
        });
        return this.$init.overload('java.io.File').call(this, file);
    };
});
```

---

## Workflows Available Today

Even before the socket bridge is implemented, you can combine neutron and Frida manually.

### Workflow 1: Parallel JSON Streams

Run neutron in one terminal, Frida in another. Merge and sort by timestamp in post-processing.

```bash
export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
NEUTRON=/data/local/share/neutron/neutron-agent
RUN=/data/local/share/neutron/runs/frida-$(date -u +%Y%m%dT%H%M%SZ)
"${ADB[@]}" shell "su -c 'install -d -m 0700 ${RUN}'"

# Terminal 1: BPF trace
"${ADB[@]}" shell "su -c '${NEUTRON} trace --pid <PID> --profile security \
  --json --output ${RUN}/bpf.ndjson'"
"${ADB[@]}" exec-out "su -c 'cat ${RUN}/bpf.ndjson'" > bpf.ndjson

# Terminal 2: Frida trace (stdout)
frida -U -f com.target.app -l frida_standalone.js --no-pause > frida.ndjson

# Merge and sort by timestamp
cat bpf.ndjson frida.ndjson | jq -s 'sort_by(.ts_ns)[]' | jq -c .
```

`frida_standalone.js` should emit JSON lines with a `ts_ns` field using `Date.now() * 1e6` for millisecond-resolution timestamps.

### Workflow 2: ptr_hint Resolution with Frida Script

When BPF data is empty (e.g. due to a closed-fd race or a non-string buffer the BPF program does not capture), use a Frida script to read the argument before the syscall returns. This requires hooking the libc wrapper, not the BPF tracepoint.

```javascript
// frida_path_resolver.js
// Intercept openat to log the path from inside the process
const openat = Module.findExportByName('libc.so', 'openat');
Interceptor.attach(openat, {
    onEnter: function(args) {
        const path = args[1].readUtf8String();
        if (path) {
            console.log(JSON.stringify({
                ts_ns: Date.now() * 1e6,
                pid: Process.id,
                source: 'frida',
                name: 'openat',
                data: path
            }));
        }
    }
});
```

Cross-reference with neutron output by pid + approximate timestamp.

### Workflow 3: SSL Pinning + BPF Correlation

1. Use Frida to bypass certificate pinning and hook `SSL_write`/`SSL_read`.
2. Use neutron to observe the `connect()` syscall that established the socket.
3. Correlate: the `connect()` fd returned by BPF matches the fd used in SSL operations.

```bash
# Find TLS connections by IP
jq -r 'select(.nr == 203 and .ret == 0) | "\(.ts_ns) fd=\(.ret) -> \(.data)"' bpf.ndjson

# In Frida, log SSL operations with the SSL* pointer (which maps to a fd)
```

### Workflow 4: Root Detection Fingerprinting

1. Run neutron with `--profile security --capture-reads`.
2. Run Frida to hook `java.io.File.exists()`, `Runtime.exec()`, system property reads.
3. BPF catches the syscall-level evidence; Frida catches the Java-level caller.
4. Together: full call stack from Java down to kernel.

```bash
# BPF: see which files are stat'd / access-checked
jq -r 'select(.nr == 48 or .nr == 79) | .data' bpf.ndjson | sort | uniq -c | sort -rn

# Frida: see which Java method triggers each check
# (java_stack field in frida output)
```

---

## Frida Setup

### Install Frida Server on Device

```bash
# Download frida-server for arm64 (match your Frida version)
# https://github.com/frida/frida/releases

export ANDROID_SERIAL=USB_SERIAL
ADB=(adb -s "$ANDROID_SERIAL")
FRIDA_DIR=/data/local/share/frida
"${ADB[@]}" shell "su -c 'install -d -m 0700 ${FRIDA_DIR}'"
"${ADB[@]}" exec-in "su -c 'umask 077; \
  cat > ${FRIDA_DIR}/frida-server'" \
  < frida-server-XX.X.X-android-arm64
"${ADB[@]}" shell "su -c 'chmod 0700 ${FRIDA_DIR}/frida-server; \
  ${FRIDA_DIR}/frida-server >/dev/null 2>&1 &'"
```

### Connect from Host

```bash
pip install frida-tools

# List running apps
frida-ps -U

# Attach to running app
frida -U -p <PID> -l agent.js

# Spawn app fresh (useful for capturing startup)
frida -U -f com.target.app -l agent.js --no-pause
```

### Verify Frida Can Read Process Memory

```bash
MAP_BASE="$("${ADB[@]}" shell \
  "su -c 'sed -n \"1s/-.*//p\" /proc/<PID>/maps'" | tr -d '\r')"
[[ "$MAP_BASE" =~ ^[0-9a-fA-F]+$ ]] || { echo "invalid map base" >&2; exit 1; }
frida -U -p <PID> -e "Memory.readUtf8String(ptr(0x${MAP_BASE}))"
```

If this fails, check for anti-Frida protections (the app is likely the one you are assessing — neutron can help identify the exact syscalls used for the check).

---

## Anti-Detection Notes

Some apps detect Frida's presence by:
- Reading `/proc/self/maps` for `frida-agent` library segments
- Scanning `/proc/self/fd` for frida-server sockets
- Checking for the frida-helper process name in `/proc`

neutron will capture these checks:
```bash
# Watch for Frida self-detection attempts
jq -r 'select((.nr == 56 or .nr == 48) and (.data | contains("frida")))' trace.ndjson
```

When the app tries to detect Frida, the BPF trace shows the exact path being probed before the Java-level result is returned — allowing you to understand and counter the detection logic.
