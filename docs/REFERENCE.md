# Reference

## Subcommands

| Command       | Purpose                                                                                |
|---------------|----------------------------------------------------------------------------------------|
| (default)     | Tracer mode: load BPF, attach tracepoints, emit NDJSON / findings.                     |
| `trace`       | Explicit tracer mode; accepts the same flags as the legacy default invocation. (1.3.0) |
| `doctor`      | Preflight environment checks (kernel, privileges, BPF subsystem). Exits non-zero on FAIL. |
| `window`      | Cut event windows around an anchor from a captured NDJSON.                             |
| `summarize`   | Aggregate an NDJSON capture by `--by <fields>` and print a sorted count table. (1.2.0) |
| `diff`        | Compare two captures aggregated on the same key; print added/removed/Δ rows. (1.2.0)  |
| `mark`        | Switch a live start/end scenario over the control socket, or append with explicit `--output`. (1.3.0) |
| `graph`       | Render causal NDJSON as a Mermaid `flowchart TD`. (1.3.0) |
| `surface`     | Collect or query a deterministic Android service/HAL/process/device snapshot. (1.4.0) |
| `recipes`     | Print built-in workflow recipes, e.g. `neutron recipes android-content-provider`. |

For `window`, see [docs/guides/window.md](guides/window.md). For
`summarize` / `diff`, see the per-subcommand `--help`. For `mark`, see
the **Marker workflow** section below. For Android provider work, use
`neutron recipes android-content-provider` or
[guides/android-content-provider.md](guides/android-content-provider.md).

## CLI Flags

<!-- AUTO-GENERATED from src/cli.rs Args struct -->

| Flag                              | Type             | Default                                  | Description |
|-----------------------------------|------------------|------------------------------------------|-------------|
| `--package NAME`                  | String           | unset                                    | Root package for causal tracing; resolves UID, then matches `/proc/PID/cmdline` as `package` or `package:*`. Separate from `--match-package`. |
| `--root-uid UID`                  | u32              | unset                                    | Root current processes of one Android UID and add matches found by a one-second refresh. A process that starts and exits between refreshes can be missed. Mutually exclusive with `--package` and an explicit `--pid`. (1.4.0) |
| `--follow-binder`                 | flag             | off                                      | Add Binder callees to the bounded dynamic trace set before publishing the caller event. |
| `--follow-services`               | flag             | off                                      | Enable `service list -p` candidate discovery; implies `--follow-binder`. |
| `--follow-hal`                    | flag             | off                                      | Enable `service list -p` and `lshal -ip` HAL candidate discovery; implies `--follow-binder`. |
| `--max-depth N`                   | u8               | `4`                                      | Maximum causal Binder expansion depth. |
| `--max-processes N`               | 1..=1024         | `64`                                     | Dynamic `TRACED_PROCESSES` map capacity. A package/UID root exceeding the limit fails the trace. |
| `--control-socket PATH|off`       | String           | `/data/local/tmp/neutron.control.sock`   | Live scenario marker socket; `off` disables it. |
| `--pid N`                         | u32              | `0`                                      | Target process ID. `0` traces all processes. |
| `--object PATH`                   | String           | `/data/local/tmp/neutron.bpf.elf`        | Path to the compiled Aya BPF ELF object on the device. |
| `--pages N`                       | usize            | `64`                                     | **Deprecated.** Accepted for backward compatibility; ignored. The kernel `RingBuf` size is fixed in the BPF object. |
| `-v, --verbose`                   | flag             | off                                      | Print diagnostic information to stderr: attached programs, kallsyms status, follow-children / capture-reads decisions, Aya verifier log on a failed `prog.load()`. |
| `--exclude-comm LIST`             | comma-separated  | empty                                    | Exclude events whose `comm` field contains any of the listed substrings. Applied in userspace after reading from the ring buffer. |
| `--output PATH`                   | String           | stdout                                   | Write event output to a file instead of stdout. |
| `--max-output-size SIZE`          | String           | unset                                    | Stop capture after the output stream reaches SIZE. Accepts bytes or binary suffixes (`kb`, `mb`, `gb`). |
| `--rotate-output-size SIZE`       | String           | unset                                    | Rotate file output after SIZE bytes per segment. Requires `--output`; writes `PATH`, `PATH.1`, `PATH.2`, ... Mutually exclusive with `--max-output-size`. |
| `--json`                          | flag             | off                                      | Emit events and findings as NDJSON (one JSON object per line). |
| `--profile security`              | String           | off                                      | Enable BPF-side syscall whitelisting: only security-relevant syscalls are captured. Also captures file paths via `bpf_probe_read_user_str_bytes` and auto-populates `--exclude-comm` with kernel-worker noise. |
| `--binder`                        | flag             | off                                      | Enable binder transaction tracing via the `binder/binder_transaction` tracepoint. Emits events with `syscall_nr = -1`. |
| `--stacks`                        | flag             | off                                      | Collect kernel and userspace stack traces via `bpf_get_stackid`. Resolve native ELF symbols, ART JIT regions, and (when not masked) kernel symbols via `/proc/kallsyms`. |
| `--alert-rwx`                     | flag             | off                                      | Only show `mmap`/`mprotect` events with `PROT_READ\|PROT_WRITE\|PROT_EXEC`. Adds `"rwx_alert"` field in JSON mode. |
| `--resolve-paths`                 | flag             | off                                      | When `data[128]` is empty (truncated read or closed fd), fall back to `/proc/<pid>/fd/<fd>` readlink for paths and `/proc/<pid>/net/tcp*` for socket addresses. |
| `--follow-children`               | flag             | off                                      | On `clone()` exit, write the child PID into the `PID_WHITELIST` BPF map so child events are also captured. |
| `--capture-reads`                 | flag             | off                                      | On `openat()` exit for `/proc/*` or `/sys/*` paths, register the fd in `WATCH_FDS`. (Buffer-content peek removed in V1; fd-tracking only.) |
| `--rules PATH`                    | String           | bundled                                  | Path to a custom YAML rule file. Defaults to the bundled detector pack (19 rules — see below). |
| `--raw`                           | flag             | off                                      | Output raw syscall events in addition to (or instead of, with `--no-findings`) findings. Without this flag, neutron emits only rule-engine findings. |
| `--no-findings`                   | flag             | off                                      | Suppress findings output. Useful with `--raw` for the legacy per-event-only behavior of pre-rule-engine versions. |
| `--findings-drain-interval N`     | u64              | `256`                                    | Drain pending findings every N events. |
| `--fdgraph-pids POLICY`           | String           | `active`                                 | Periodic FD-poller scope: `traced` (target + followed children), `active` (PIDs with at least one traced event), `uid` (sprint-2 stub → falls back to `active`), `all` (every `/proc/<NUM>` — heavy). |
| `--fdgraph-interval DURATION`     | String           | `1s`                                     | Poller interval. Accepts `1s`, `500ms`, or `off` to disable polling. |
| `--fdgraph-thresholds TIERS`      | String           | `1024,8192,90%`                          | Comma-separated FD-count alert tiers. Parsed for forward-compat; rules carry their own thresholds today. |
| `--fdgraph-top-paths-n N`         | usize            | `0`                                      | Top-N `/proc/<pid>/fd/<fd>` readlink aggregation per snapshot. `0` disables. |
| `--lookback-events N`             | usize            | `100`                                    | Per-PID ring-buffer depth dumped into `crash_context` on `process_exit`. `0` disables. |
| `--tombstone-dir PATH`            | String           | `/data/tombstones`                       | Directory the tombstone watcher polls at 1 Hz. Empty string disables. |
| `--no-logcat`                     | flag             | off                                      | Skip spawning the `logcat` tail. Useful on hosts without `logcat` in PATH. |
| `--binder-inflight N`             | usize            | `1024`                                   | Max in-flight binder transactions tracked by the userspace correlator. `0` disables (raw events still flow). |
| `--finding-raw-window N`          | usize            | `10`                                     | Per-finding `raw_window` length — full NDJSON lines from contributing events. `0` disables. |

### Phase 1 — predicate-based capture reduction (1.2.0)

| Flag                              | Type             | Default                                  | Description |
|-----------------------------------|------------------|------------------------------------------|-------------|
| `--match-pid LIST`                | comma-separated  | empty                                    | Multi-PID match. Pushed into BPF (`PID_WHITELIST` map). Combine with `--pid` for the kernel-side fast path. |
| `--match-uid LIST`                | comma-separated, accepts `LO..HI` | empty               | UID match. Range expansion capped at 1024 entries. BPF-evaluable (`MATCH_UID_SET`). |
| `--match-package LIST`            | comma-separated  | empty                                    | Android package-name match. Resolved on-device to UID(s) through `cmd package` / `pm`, then applied through the BPF UID prefilter. |
| `--match-android-provider LIST`   | comma-separated  | empty                                    | Android content-provider authority match. Accepts `authority` or `content://authority/path`, resolves through `dumpsys package providers` to the provider package, then applies the package UID through the BPF UID prefilter. |
| `--match-syscall LIST`            | comma-separated  | empty                                    | Syscall whitelist by aarch64 nr. Reuses `SYSCALL_FILTER`. BPF-evaluable. |
| `--match-fd LIST`                 | comma-separated  | empty                                    | Glob-matched fd path (e.g. `'/dev/lwis*,/dev/gxp'`). Userspace-only — needs `--resolve-paths` or an established fdgraph entry. Toggles `STATE_EMIT_REQUIRED` so kernel-side state syscalls bypass the predicate. |
| `--match-comm LIST`               | comma-separated  | empty                                    | Glob-matched `comm`. Userspace-only. |
| `--match-ioctl-cmd LIST`          | comma-separated  | empty                                    | ioctl `cmd` 32-bit word. BPF-evaluable. |
| `--match-ioctl-type LIST`         | comma-separated  | empty                                    | `_IOC_TYPE` byte (e.g. `0x4c` for LWIS). BPF-evaluable. |
| `--match-ioctl-nr LIST`           | comma-separated  | empty                                    | `_IOC_NR` byte. BPF-evaluable. |
| `--match-ioctl-dir VALUE`         | one of `none\|r\|w\|rw` | unset                              | `_IOC_DIR`. BPF-evaluable. |
| `--match-ret VALUE`               | one of `any\|nonzero\|negative\|zero` | `any`                  | Discrete ret-class on exit events. BPF-evaluable. |
| `--match-latency-min DUR`         | `100us\|5ms\|2s\|<int µs>` | unset                          | Minimum exit-side latency. BPF-evaluable. |
| `--match-prot-rwx`                | flag             | off                                      | Match `mmap`/`mprotect` events with `PROT_READ\|PROT_WRITE\|PROT_EXEC`. Userspace-only. |
| `--match-prot-wx`                 | flag             | off                                      | Match `mmap`/`mprotect` with `PROT_WRITE\|PROT_EXEC`. Userspace-only. |
| `--match-arg-u32 'OFF=V[,V...]'`  | repeatable       | empty                                    | Typed accessor over the captured ioctl arg snapshot. Single-offset BPF-evaluable (`MATCH_ARG_U32_VALS`); multiple offsets degrade to userspace-only. |
| `--match-arg-u8 / -u16 / -u64`    | repeatable       | empty                                    | Same shape, narrower / wider widths. Userspace-only. |
| `--match-binder-code LIST`        | comma-separated  | empty                                    | Match `code` field on `binder` and `binder_call` events. Userspace-only. |
| `--match-binder-flags LIST`       | comma-separated  | empty                                    | Match `flags`. Userspace-only. |
| `--match-binder-to-proc LIST`     | comma-separated  | empty                                    | Match `to_proc`. Userspace-only. |
| `--match-binder-to-thread LIST`   | comma-separated  | empty                                    | Match `to_thread`. Userspace-only. |
| `--match-binder-target-node LIST` | comma-separated, signed | empty                              | Match `target_node` handle. Userspace-only. |
| `--match-binder-reply true\|false`| bool             | unset                                    | Match the reply flag. Userspace-only. |
| `--match EXPR`                    | string           | unset                                    | Recursive-descent boolean expression: `AND`/`OR`/`NOT`/parens, `=`/`!=`/`<`/`<=`/`>`/`>=`/`IN`/`GLOB` over the same field vocabulary. Mutually exclusive with the individual `--match-*` flags. Compiler labels each clause `[bpf]` or `[user]` at startup. |
| `--capture MODE`                  | string           | unset                                    | Capture mode. `matched+context=<DUR>` arms a backward+forward window of `<DUR>` (cap 30s) around every match. Anything else (including `default` / `matched`) preserves Phase 1a/1b emit-on-match-only behaviour. |
| `--sample P`                      | f64 in [0.0, 1.0] | unset                                  | Uniform Bernoulli drop with probability `1-P`. State-tracking syscalls bypass. |
| `--rate-limit N`                  | u64              | unset                                    | Token-bucket cap on emitted events per second. State-tracking syscalls bypass. |

### Phase 4 — finding enrichment (1.2.0)

| Flag                              | Type             | Default                                  | Description |
|-----------------------------------|------------------|------------------------------------------|-------------|
| `--fd-snapshot-on-finding`        | flag             | off                                      | When a finding fires with ioctl evidence, read `/proc/<pid>/fdinfo/<fd>` synchronously and embed as `fdinfo_at_event` on the JSON line. |
| `--binder-services FILE`          | String           | unset                                    | Path to a JSON `{callee_pid: {target_node: service_name}}` map. Known pairs surface a `service` field on `binder_call` events. |
| `--binder-methods FILE`           | String           | unset                                    | Verified JSON `{service: {code: method}}` map. Unknown codes remain `code=N`. |

<!-- END AUTO-GENERATED -->

## Surface mapper (1.4.0)

`surface scan` emits one deterministic JSON document. Static collection works
without a capture; the other two forms add observed causal evidence:

```bash
neutron surface scan --output surface.json
neutron surface scan --capture capture.ndjson --output surface.json
neutron surface scan --observe 30s --from-package com.example.app \
  --output surface.json
neutron surface scan --observe 30s --from-uid 10123 --output surface.json
```

`--capture FILE` accepts `-` for stdin. `--capture` and `--observe` are
mutually exclusive. Live observation requires exactly one root selector and
does not support a system-wide root. Durations accept `ms`, `s`, `m`, or `h`
and must be non-zero.

Static service inventory uses `service list` plus exact
`dumpsys --pid SERVICE`, `lshal -ip`, and `vndservice list`. AIDL/HIDL
declarations come from VINTF manifests under `system`, `vendor`, `product`,
`system_ext`, and `odm`. Process evidence comes from `/proc`; device and module
evidence starts at `/dev`, `/proc/modules`, `/sys/module`, and the sysfs links
anchored by each discovered major/minor pair.

Live mode starts the current `neutron` executable directly as one child trace,
waits for its control socket, opens and closes a `surface-observe` scenario,
sends SIGINT, waits for successful shutdown and a final `capture_health`, then
removes its private temporary directory. Static collection follows the live
interval so current `/proc` starttimes can reject PID reuse. Child failure,
timeout, missing health, or incomplete cleanup fails the scan.

All query commands read `neutron.surface/v1` and emit
`neutron.surface/query/v1` JSON:

```bash
neutron surface services  --input surface.json --output services.json
neutron surface hals      --input surface.json
neutron surface devices   --input surface.json
neutron surface process 1234 --input surface.json --output process.json
neutron surface explain SERVICE_OR_DEVICE --input surface.json
neutron surface reachable --from-package com.example.app --input surface.json
neutron surface reachable --from-uid 10123 --input surface.json
```

`--input -` reads stdin. `process` rejects a PID absent from the snapshot and a
PID shared by multiple stored identities. `explain` accepts a service ID/name
or device ID/path/alias and rejects zero or ambiguous matches. Every command
writes JSON to stdout unless `--output` is set; a final-component symlink is
rejected, while a selected file is truncated and forced to mode `0600`.

`reachable` traverses only capture-sourced `root_process`, `binder`,
`served_by`, and `ioctl` relations from matching trace IDs. Other relation
types remain enrichment evidence even if an input document attaches a trace
ID to them.

The snapshot envelope is:

```json
{
  "schema": "neutron.surface/v1",
  "neutron_version": "1.4.0",
  "collected_at": "2026-07-10T00:00:00Z",
  "device": { "fingerprint": "...", "boot_id": "..." },
  "health": { "status": "complete", "collectors": [], "warnings": [] },
  "services": [],
  "processes": [],
  "devices": [],
  "modules": [],
  "relations": [],
  "captures": []
}
```

Top-level collections are sorted by stable entity ID and deduplicated. IDs are
derived from collected identity rather than array position:

| Entity | Natural ID |
|--------|------------|
| service | `service:<transport>:<name>` |
| process | `process:<boot_id>:<pid>:<starttime>` |
| device | `device:<char\|block>:<major>:<minor>` |
| module | `module:<name>` |
| capture | `capture:<trace_id>:<scenario_id>` |
| relation | type + endpoints + trace/span identity |

Services include transport, declaration/runtime sources, proven PID/process,
SELinux domain, executable, mapped libraries, current device FDs, and observed
devices/ioctls. Processes include UID/GID, argv, executable, starttime, boot
ID, SELinux domain, unique file-backed shared libraries, and FDs. Devices
include canonical path and aliases, kind, major/minor, mode, UID/GID, SELinux
label, and any sysfs-proven subsystem/driver/module. A binary or PID is left
unknown when the collector did not prove it.

Relations carry `id`, `type`, `from`, `to`, `evidence`, and
`confidence:"exact"|"candidate"`. Capture relations may also carry
`causal_relation:"exact"|"inferred"`, `trace_id`, `scenario_id`, `span_id`,
and `ioctl`. Known Trusty TIPC and V4L2 commands include
`TIPC_IOC_CONNECT` and `VIDIOC_QBUF`; an unknown command remains numeric as
`cmd=0x...`.

`reachable` selects captures matching the requested package/UID and traverses
only capture-sourced `root_process`, `binder`, `served_by`, and `ioctl`
relations. Static `proc_fd` relations describe current scan state but are
excluded from traversal; static fields only enrich nodes already reached.
Therefore “reachable” never means a SELinux/VINTF/manifest permission or
theoretical Binder allow decision.

Capture import is streaming and ignores unknown NDJSON event types and fields.
Capture health degradation is copied into surface health. A capture without a
final `capture_health` record is retained as degraded evidence. A capture whose
boot ID is absent or differs from the static snapshot is retained, but joins
to current PIDs are `candidate` and health contains a warning. Individual read or
service-command failures, and malformed process/VINTF inputs, degrade their
collector; missing primary `/proc` or `/dev`, live trace failure, or output
failure is fatal. Device sysfs enrichment is limited to paths anchored by
discovered device nodes rather than a recursive `/sys/devices` dump.

## Text Output Format

```
[timestamp_ms] pid/tid  comm             -> syscall(args) "data"
[timestamp_ms] pid/tid  comm             <- syscall = ret [+latency_us µs] "data"
[timestamp_ms] pid/tid  comm             [!RWX] -> mmap(args)
[timestamp_ms] pid/tid  comm             -> BINDER_TXN to_proc=N code=N flags=0xN
```

With `--stacks`, ` stack=<…>` is appended to the same line. See
[guides/output-formats.md](guides/output-formats.md).

## JSON Event Schema

Emitted with `--json` (and `--raw`). One object per line (NDJSON).

### Syscall Event

```json
{
  "type":           "syscall",
  "ts_ns":          1712345678901234,
  "pid":            21093,
  "tid":            21093,
  "uid":            10147,
  "nr":             56,
  "name":           "openat",
  "comm":           "e.bankapp",
  "enter":          false,
  "phase":          "exit",
  "ret":            42,
  "ok":             true,
  "args":           [4294967196, 140234567890, 524288, 438, 0, 0],
  "data":           "/proc/self/maps",
  "data_phase":     "enter",
  "kernel_stackid": 17,
  "user_stackid":   42,
  "latency_us":     123,
  "stack":          "libc.so:__openat+0x4 <- libnative.so:check_root+0x40 ;; vfs_open+0x12",
  "event_id":       18437
}
```

| Field             | Type                | Description                                                  |
|-------------------|---------------------|--------------------------------------------------------------|
| `type`            | String              | Always `"syscall"` for syscall events. Stable event-class identifier. |
| `ts_ns`           | u64                 | Kernel monotonic timestamp (ns since boot)                   |
| `pid`             | u32                 | Linux PID (= POSIX `tgid`)                                   |
| `tid`             | u32                 | Linux TID (= kernel `pid`)                                   |
| `uid`             | u32                 | UID of the calling thread                                    |
| `nr`              | i32                 | Syscall number; `-1` for binder synthetic events             |
| `name`            | String              | Human-readable syscall name (from internal table)            |
| `comm`            | String              | Task comm (up to 15 chars, kernel-set)                       |
| `enter`           | bool                | **Deprecated.** Use `phase` instead. Both fields are still emitted for one release. |
| `phase`           | String              | `"enter"` or `"exit"`.                                       |
| `ret`             | i64                 | Return value (exit only; 0 on enter)                         |
| `ok`              | bool (optional)     | `true` if `ret >= 0` on an exit event; omitted on enter events. |
| `errno`           | u32 (optional)      | `-ret` for failed exit events (when `ok:false`); omitted otherwise. |
| `args`            | u64[6]              | Syscall arguments. All six positions reflect the actual ABI args. |
| `data`            | String (optional)   | Decoded `data[128]`: path, sockaddr, hex; omitted if empty   |
| `data_phase`      | String              | `"enter"` when `data[]` is the pre-call buffer; `"exit"` when the BPF program refreshed it post-call. Built-in refresh covers dma-heap/binder/dma-buf/ashmem; `--driver-pack` can enable runtime refresh for KGSL, Mali, ALSA, LWIS, and GXP families. |
| `ioctl_family`    | String (optional)   | `"dma_heap"`, `"binder"`, `"dma_buf"`, `"ashmem"`, `"kgsl"`, `"mali"`, `"alsa"`, `"lwis"` (1.2.0), `"gxp"` (1.2.0), or `"unknown"`. Emitted for `ioctl(2)` events. |
| `ioctl_name`      | String (optional)   | Human cmd name (e.g. `"DMA_HEAP_IOCTL_ALLOC"`, `"BINDER_WRITE_READ"`, `"LWIS_CMD_PACKET"`) when the decoder registry recognises it. |
| `dma_heap`        | Object (optional)   | Decoded `struct dma_heap_allocation_data`. Fields: `len`, `returned_fd`, `fd_flags`, `fd_flags_str`, `heap_flags`. |
| `binder_write_read` | Object (optional) | Scalar `BINDER_WRITE_READ` header: `write_size`, `write_consumed`, `read_size`, `read_consumed`. |
| `kgsl` / `mali`   | Object (optional)   | First four captured scalar words as `arg0..arg3`; nested pointers are not followed. |
| `alsa`            | Object (optional)   | ALSA scalar marker with `compat_candidate`, `arg0`, and `arg1`. |
| `unix_msg_control` | Object (optional)  | Bounded sendmsg/recvmsg control metadata: `flags`, `controllen`, first `cmsg_len`/`cmsg_level`/`cmsg_type`, bounded `scm_rights_fds`, and `msg_peek`. |
| `lwis`            | Object (optional)   | LWIS command-packet payload (1.2.0). Fields: `cmd_id` (u32 from `data[4..8]`); `cmd_id_name` is set for documented IDs (`DEVICE_ENABLE`, `DMA_BUFFER_ALLOC`, `TRANSACTION_SUBMIT`, …) and omitted for unnamed IDs so they stay searchable by hex. |
| `rwx_alert`       | `"RWX" \| "WX" \| null` | Set on mmap/mprotect with PROT_EXEC                      |
| `kernel_stackid`  | i32 (optional)      | Key into `STACK_TRACES` map; omitted if both ids are negative |
| `user_stackid`    | i32 (optional)      | Key into `STACK_TRACES` map; omitted if both ids are negative |
| `latency_us`      | u64 (optional)      | Syscall latency (exit only; omitted if `INFLIGHT` evicted)   |
| `stack`           | String (optional)   | Resolved stack trace; only present with `--stacks`           |
| `event_id`        | u64 (optional)      | Session-scoped monotonic correlation token. Resets on neutron restart. |

### Binder Event (`syscall_nr == -1`)

```json
{
  "type":        "binder",
  "ts_ns":       1712345678901234,
  "pid":         21093,
  "tgid":        21093,
  "uid":         10147,
  "phase":       "enter",
  "comm":        "e.bankapp",
  "reply":       false,
  "to_proc":     1234,
  "to_thread":   0,
  "target_node": 7,
  "code":        2,
  "flags":       16,
  "stack":       "...",
  "event_id":    18438
}
```

Binder transactions are point-in-time so `phase` is always `"enter"`. Binder
events have no `ret`/`ok`/`errno` (the binder tracepoint does not expose a
return code) and no `data`/`data_phase` (the routing fields are first-class
columns on the event itself).

### FD Snapshot Event (`type == "fd_snapshot"`)

```json
{
  "type":              "fd_snapshot",
  "ts_ns":             1234567890,
  "pid":               540,
  "uid":               1000,
  "comm":              "vendor.qti.cam",
  "fd_count":          16380,
  "fd_rlimit":         32768,
  "fd_pct_of_rlimit":  49,
  "high_water_mark":   16380,
  "growth_rate_per_sec": 124.5,
  "top_paths":         [{"path":"/dev/dma_heap/system","count":8190}],
  "event_id":          18234
}
```

| Field                  | Type   | Description                                                                 |
|------------------------|--------|-----------------------------------------------------------------------------|
| `fd_count`             | u32    | Authoritative count from `/proc/<pid>/fd` at sample time.                   |
| `fd_rlimit`            | u32    | Soft `RLIMIT_NOFILE` from `/proc/<pid>/limits`. `0` = unknown.              |
| `fd_pct_of_rlimit`     | u8     | `0..=100`, omitted when `fd_rlimit == 0`.                                   |
| `high_water_mark`      | u32    | Maximum `fd_count` ever observed for this PID this session.                 |
| `growth_rate_per_sec`  | f32    | (fds gained since last sample) / interval. `0.0` for the first sample.      |
| `top_paths`            | array  | `[{"path","count"}]` from readlinks. Empty unless `--fdgraph-top-paths-n > 0`. |

### Binder Call Event (`type == "binder_call"`)

Synthesised by the userspace correlator (sprint-2 PR 2). Pairs caller-side
`binder_transaction` (BPF nr=-1, raw `type:"binder"`) with callee-side
`binder_transaction_received` (BPF nr=-4, raw `type:"binder_received"`) by
`debug_id` carried in `ptr_hint`. On callee crash, in-flight transactions
are flushed with `status:"callee_crashed"`.

```json
{
  "type":           "binder_call",
  "ts_ns":          1234567890,
  "debug_id":       8421,
  "caller_pid":     12345,
  "caller_uid":     10001,
  "caller_comm":    "com.example.app",
  "callee_pid":     1000,
  "code":           7,
  "flags":          16,
  "reply":          false,
  "target_node":    1,
  "sent_ts_ns":     1234567890,
  "received_ts_ns": 1234568390,
  "latency_us":     500,
  "status":         "completed",
  "service":        "android.hardware.camera2",
  "event_id":       18234
}
```

| Field            | Type    | Description                                                                |
|------------------|---------|----------------------------------------------------------------------------|
| `debug_id`       | i32     | Kernel-assigned binder transaction id; matching key.                        |
| `caller_pid`     | u32     | Sending process (TGID).                                                    |
| `callee_pid`     | u32     | Receiving process — taken from caller-side `to_proc` field.                |
| `code`           | u32     | AIDL transaction code on the binder interface.                              |
| `flags`          | u32     | TF_* flags (e.g. `0x01` = TF_ONE_WAY async).                               |
| `reply`          | bool    | `true` when this is a reply transaction; `false` for a request.             |
| `target_node`    | i32     | Binder handle. Combined with `callee_pid`, identifies a specific service. (1.2.0) |
| `received_ts_ns` | u64     | When the callee dequeued. **Omitted** for `callee_crashed` pairs.           |
| `latency_us`     | u64     | `(received - sent) / 1000`. **Omitted** when `received_ts_ns` is absent.    |
| `status`         | string  | `"completed"`, `"callee_crashed"`, or `"unmatched"`.                       |
| `service`        | string  | Optional. Set when `--binder-services <FILE>` was provided and the `(callee_pid, target_node)` pair is in the map. (1.2.0) |

The rule engine maps `caller_pid` → the standard `pid` field for
`per_process` aggregation. `R004_binder_callee_crash` matches
`status: "callee_crashed"` and surfaces one finding per caller.

### Process Exit Event (`type == "process_exit"`)

```json
{
  "type":           "process_exit",
  "ts_ns":          1234567890,
  "pid":            12345,
  "uid":            10123,
  "comm":           "vendor.qti.cam",
  "source":         "tombstone",
  "classification": "crash",
  "exit_signal":    11,
  "signal_name":    "SIGSEGV",
  "crash_context":  ["{\"type\":\"syscall\",...}", "..."],
  "event_id":       18234
}
```

| Field            | Type   | Description                                                                  |
|------------------|--------|------------------------------------------------------------------------------|
| `source`         | string | `"tracepoint"` (BPF), `"logcat"`, or `"tombstone"`.                          |
| `classification` | string | `"crash"`, `"signal_exit"`, `"abnormal_exit"`, or `"normal_exit"`.           |
| `exit_signal`    | u32    | POSIX signal number (omitted when 0). `11` = SIGSEGV, `6` = SIGABRT, etc.    |
| `signal_name`    | string | Symbolic name when known (omitted otherwise).                                |
| `exit_code`      | u8     | exit(2) status (omitted when 0).                                             |
| `crash_context`  | array  | Last N raw NDJSON lines for this PID (lookback ring buffer). Empty when off. |

Sources are independent: a single SIGSEGV typically produces all three
events within milliseconds. `R003_process_crash` uses `aggregate: per_process`
so the rule fires once per PID. The `exit_source_in` predicate lets rules
require a specific source (e.g. only act on tombstone-backed evidence).

### Marker Event (`type == "marker"`, 1.2.0)

Emitted by append-only `neutron mark --output` or by the live tracer after a
validated control-socket request. `surface scan --observe` uses the latter to
bracket its `surface-observe` scenario.

```json
{
  "type":  "marker",
  "ts_ns": 1712345678901234,
  "name":  "scenario",
  "phase": "start",
  "scenario_id": "scenario",
  "trace_id": "0000000000001234",
  "root_uid": 10123,
  "meta":  { "build": "v1", "device": "oriole" }
}
```

| Field   | Type             | Description                                            |
|---------|------------------|--------------------------------------------------------|
| `name`  | string           | Operator-supplied scenario or stage identifier.         |
| `phase` | string, optional | One of `"start"` / `"end"`. Omitted for one-shot marks. |
| `meta`  | object, optional | `--meta k=v` key/value strings. Omitted when empty.     |
| `scenario_id` / `trace_id` | string, live only | IDs assigned by a live causal tracer. |
| `root_package` / `root_uid` | string / u32, optional | Causal root identity. |

`neutron window --anchor marker:<name>` cuts a window around every
matching marker. See **Marker workflow** below.

### Capture Health Event (`type == "capture_health"`, 1.2.0)

Emitted once on shutdown in `--json` mode as the last NDJSON line of
the trace. Mirrors the stderr capture-summary block in
machine-readable form so downstream pipelines can gate "absence of
finding is conclusive" on a single field instead of grepping prose.

```json
{
  "type":                    "capture_health",
  "events_userspace":        99999,
  "events_submitted":        99999,
  "ringbuf_reserve_failed":  0,
  "inflight_update_failed":  0,
  "inflight_lookup_missed":  0,
  "user_stack_failed":       0,
  "kernel_stack_failed":     0,
  "path_read_failed":        0,
  "path_truncated":          0,
  "fd_lookup_missed":        0,
  "symbolization_failed":    0,
  "ioctl_refresh_missed":    0,
  "unix_msg_control_truncated": 0,
  "unix_msg_control_nested": 0,
  "fd_graph_miss":           0,
  "fd_graph_backfilled":     0,
  "degraded":                false,
  "driver_packs":            ["kgsl"],
  "kprobe_packs":            [],
  "attached_programs":       ["trace_sys_enter","trace_sys_exit"],
  "ioctl_refresh_cmds":      [],
  "ioctl_refresh_types":     ["0x9"],
  "root_uid":                10123,
  "boot_id":                 "8b2d6c98-20a1-4e7e-944f-53f61b52d5ef",
  "fingerprint":             "google/husky/husky:16/..."
}
```

| Field              | Type | Description                                                                |
|--------------------|------|----------------------------------------------------------------------------|
| `events_userspace` | u64  | Events the userspace loop processed.                                       |
| `events_submitted` | u64  | Events the BPF programs reserved+submitted to the ringbuf.                 |
| `ringbuf_reserve_failed` | u64 | Hard data loss: `EVENTS.reserve()` returned `None`.                  |
| `*_failed` / `*_missed` / `*_truncated` | u64 | Per-cause degradation counters (see CAPTURE SUMMARY in the man page). |
| `fd_graph_miss`    | u64  | `(pid, fd)` pairs the userspace FD-graph couldn't resolve.                 |
| `fd_graph_backfilled` | u64 | Misses that `--resolve-paths` recovered via `/proc/<pid>/fd/<fd>`.         |
| `degraded`         | bool | `true` when any drop or degradation counter is non-zero. Mirrors the stderr WARNING banner predicate. |
| `driver_packs` / `kprobe_packs` | string[] | Active BPF-oriented decoder/kprobe packs requested for the capture. |
| `attached_programs` | string[] | BPF programs successfully attached in this session. |
| `ioctl_refresh_cmds` / `ioctl_refresh_types` | string[] | Runtime ioctl post-exit refresh coverage, rendered as hex strings. |
| `root_package` / `root_uid` | string / u32, optional | Causal trace root. |
| `boot_id` / `fingerprint` | string, optional | Device identity used to evaluate later attribution. |

Field set is stable; new counters extend the tail without renaming
existing fields.

### Finding Event

```json
{
  "type":          "finding",
  "rule_id":       "T001_proc_self_maps_polling",
  "rule_name":     "Periodic /proc/self/maps inspection",
  "category":      "root_detection",
  "severity":      "medium",
  "process":       {"comm": "example.app", "pid": 21093},
  "event_count":   130,
  "first_seen_ms": 1037686.946,
  "last_seen_ms":  1037946.946,
  "period_ms":     2033.0,
  "evidence":      [...],
  "aggregates": {
    "events_per_sec":          0.49,
    "min_interval_ms":         1850.0,
    "max_interval_ms":         2200.0,
    "distinct_targets":        1,
    "peak_fd_count":           31130,
    "peak_fd_pct_of_rlimit":   95,
    "distinct_callee_pids":    3,
    "distinct_binder_codes":   2
  },
  "raw_window": ["{\"type\":\"syscall\",\"nr\":56,...}", "..."]
}
```

Sprint-2 PR 4 adds two optional blocks to every finding:

| Field              | Type   | Description                                                                                      |
|--------------------|--------|--------------------------------------------------------------------------------------------------|
| `aggregates`       | object | Numerical / counting aggregates over contributing events. Whole block omitted when nothing fills.|
| `raw_window`       | array  | Up to `--finding-raw-window` (default 10) full NDJSON lines from contributing events.            |
| `fdinfo_at_event`  | object, optional (1.2.0) | Map keyed by fd (string) to `{pos, flags, mnt_id, ino}` from `/proc/<pid>/fdinfo/<fd>`. Populated when `--fd-snapshot-on-finding` is set and the finding's evidence includes ioctl events. |

Aggregate fields populate selectively by event kind:

| Field                       | Filled when…                                                            |
|-----------------------------|-------------------------------------------------------------------------|
| `events_per_sec`            | ≥2 events matched within a non-zero span                                |
| `min_interval_ms` / `max_interval_ms` | ≥2 events matched (computed from consecutive ts_ns gaps)      |
| `distinct_targets`          | any matched event carried a usable `data` / fallback comm string         |
| `peak_fd_count` / `peak_fd_pct_of_rlimit` | matched events were `type:"fd_snapshot"`                  |
| `distinct_callee_pids` / `distinct_binder_codes` | matched events were `type:"binder_call"`           |

Distinct-set trackers cap at 1024 entries per finding to prevent unbounded
memory growth on long-running rules; the count saturates at the cap.

## Default Detector Pack (26 rules)

| ID    | Category             | What it catches                                           |
|-------|----------------------|-----------------------------------------------------------|
| T001  | root_detection       | Periodic `/proc/self/maps` polling                        |
| T002  | root_detection       | Mount table inspection (Magisk overlay detection)         |
| T003  | antitamper           | `/proc/self/status` (TracerPid scrape)                    |
| T004  | root_detection       | `su` binary probe                                         |
| T005  | root_detection       | Magisk artifact probe                                     |
| T006  | antitamper           | Frida artifact probe                                      |
| T007  | antitamper           | Xposed / EdXposed artifact probe                          |
| T008  | root_detection       | `Runtime.exec` of root-related binaries                   |
| T009  | antitamper           | `ptrace` syscall observed                                 |
| T010  | antitamper           | `prctl(PR_GET_DUMPABLE / PR_SET_DUMPABLE)`                |
| T011  | memory               | RWX or W^X-violating memory mapping                       |
| T012  | network_recon        | `/proc/net/tcp*` enumeration                              |
| T013  | antitamper           | SELinux enforcement state probe                           |
| T014  | antitamper           | Android property service access                           |
| T015  | recon                | Cross-process `/proc/<pid>/{maps,cmdline,exe}` reads      |
| T016  | root_detection       | `fstatat` on `su` binary with `libc` on the stack         |
| T017  | antitamper           | Syscalls from inside the ART JIT code cache               |
| T018  | antitamper           | `ptrace` resolved to `sys_ptrace` from native code        |
| T019  | recon                | `/system/lib64/*` probing excluding RenderScript / Skia   |
| T020  | antitamper           | `/proc/self/*` introspection from anonymous r-x mapping   |
| T021  | antitamper           | Thread-comm enumeration (`/proc/self/task/<TID>/comm`)    |
| T022  | antitamper           | `bpf(2)` from a non-system process                        |
| R001  | resource_exhaustion  | FD table > 90% of `RLIMIT_NOFILE` (FD-graph poller)       |
| R002  | resource_exhaustion  | DMA-heap allocation burst (50+ in 5 s)                    |
| R003  | crash                | Process killed by fatal signal (SEGV/ABRT/BUS/ILL/FPE/SYS)|
| R004  | crash                | Binder callee crashed mid-transaction                     |

Source: [`neutron-rules/rules/default.yaml`](../neutron-rules/rules/default.yaml).
T016..T021 require `--stacks`. R001 requires the FD-graph poller
(`--fdgraph-pids active --fdgraph-interval 1s`, on by default). R002
requires post-exit ioctl decoding (always on for whitelisted commands).
R003 requires the `sched_process_exit` BPF tracepoint (always attached);
the lookback ring buffer (`--lookback-events 100` default) and at least
one of the three crash sources (`--lookback-events`, `--tombstone-dir`,
`logcat` available in PATH) populate `crash_context` and the signal field.
R004 requires `--binder` plus `--binder-inflight > 0` (default 1024) for
the userspace correlator to track in-flight transactions.

## Syscall Table (aarch64)

The following syscall numbers are recognized and named. Events with
unlisted numbers display as `syscall_<NR>`.

### File Operations

| Nr  | Name        | `data[128]` content                  |
|-----|-------------|--------------------------------------|
| 35  | mkdirat     | path string                          |
| 36  | unlinkat    | path string                          |
| 43  | statfs      | path string                          |
| 48  | faccessat   | path string                          |
| 56  | openat      | path string                          |
| 63  | read        | (currently unused — see `--capture-reads` notes) |
| 64  | write       | (currently unused)                   |
| 78  | readlinkat  | path string                          |
| 79  | fstatat     | path string                          |
| 221 | execve      | filename string                      |
| 281 | execveat    | filename string                      |

### Network

| Nr  | Name         | `data[128]` content                                |
|-----|--------------|----------------------------------------------------|
| 198 | socket       | —                                                  |
| 200 | bind         | sockaddr struct                                    |
| 203 | connect      | sockaddr struct                                    |
| 206 | sendto       | destination sockaddr                               |
| 207 | recvfrom     | —                                                  |
| 208 | shutdown     | —                                                  |
| 209 | setsockopt   | —                                                  |
| 210 | getsockopt   | —                                                  |
| 211 | sendmsg      | msg_name sockaddr + msg_controllen                 |
| 212 | recvmsg      | msg_name sockaddr + msg_controllen                 |
| 240 | accept4      | —                                                  |
| 241 | recvmmsg     | —                                                  |
| 269 | sendmmsg     | —                                                  |
| 288 | accept       | —                                                  |
| 293 | socket (alt) | device-specific number observed on some kernels    |
| 294 | connect (alt)| device-specific number observed on some kernels    |

### Memory

| Nr  | Name      | `data[128]` content    |
|-----|-----------|------------------------|
| 222 | mmap      | `[0]` = RWX marker     |
| 226 | mprotect  | `[0]` = RWX marker     |
| 233 | madvise   | —                      |

### Process / Thread

| Nr  | Name       |
|-----|------------|
| 93  | exit       |
| 94  | exit_group |
| 117 | ptrace     |
| 129 | kill       |
| 167 | prctl      |
| 172 | getpid     |
| 173 | getppid    |
| 220 | clone      |

### IPC

| Nr  | Name         | `data[128]` content                                |
|-----|--------------|----------------------------------------------------|
| 29  | ioctl        | `[0..4]` = cmd u32, `[4..128]` = payload           |
| -1  | BINDER_TXN   | (binder fields in `args[0..5]`)                    |

## Security Profile Syscall Whitelist

When `--profile security` is active, the BPF filter passes only these
syscall numbers:

```
56 (openat)   48 (faccessat)   221 (execve)   281 (execveat)
79 (fstatat)  78 (readlinkat)  203 (connect)  200 (bind)
206 (sendto)  207 (recvfrom)   29 (ioctl)     222 (mmap)
226 (mprotect) 167 (prctl)     129 (kill)     220 (clone)
```

All other syscall numbers are silently discarded in BPF before any
RingBuf reservation.

## Binder Transaction Fields (`args[0..5]`)

When `syscall_nr == -1`:

| `args` index | Field          | Description                  |
|--------------|----------------|------------------------------|
| 0            | `to_proc`      | Destination process PID      |
| 1            | `code`         | AIDL method code             |
| 2            | `flags`        | Transaction flags            |
| 3            | `to_thread`    | Target thread (0 = any)      |
| 4            | `reply`        | 0 = call, 1 = reply          |
| 5            | `target_node`  | Binder node handle           |

## Marker workflow (1.3.0)

Use `neutron mark` to bracket causal scenarios. The live tracer validates the
lifecycle, chooses the monotonic timestamp/generation/trace ID, and writes the
marker into its own NDJSON stream:

```bash
# In one shell: tracer.
neutron trace --package com.example.app --follow-hal \
  --output trace.ndjson &

# In another shell: bracket the stimulus.
neutron mark scenario --phase start
./trigger-camera-extension-night
neutron mark scenario --phase end

kill %1
wait %1
neutron graph trace.ndjson --root-package com.example.app \
  --format mermaid --output flow.md
```

Pass an explicit `mark --output trace.ndjson` to retain the 1.2 append-only
behavior without switching the live scenario. That path uses `O_APPEND`,
atomic on Linux for ≤PIPE_BUF writes. See [docs/guides/window.md](guides/window.md)
for the full anchor list.

## Binder service-map file (1.2.0)

`--binder-services <FILE>` accepts a flat JSON document keyed by
`callee_pid` and `target_node` (both strings, parsed back to
integers):

```json
{
  "1234": {
    "1": "android.hardware.camera2",
    "2": "android.hardware.audio"
  },
  "5678": {
    "1": "system_server.activity"
  }
}
```

This map is the exact `(callee_pid, target_node)` override. Without an exact
entry, `--follow-services` / `--follow-hal` can add PID-level candidates with
`attribution_confidence:"candidate"`; ambiguous candidates are listed without
claiming a service.

`--binder-methods <FILE>` accepts verified service/code mappings:

```json
{
  "android.hardware.camera.provider.ICameraProvider/default": {
    "1": "getCameraIdList"
  }
}
```

Without a verified entry, the numeric `code` remains the honest method label.

## LWIS command-packet IDs (1.2.0)

The `LWIS_CMD_PACKET` ioctl (`_IOWR('L', 100, lwis_cmd_pkt)`) carries
a u32 cmd_id at `data[4..8]`. Documented IDs that surface as
`lwis.cmd_id_name`:

| `cmd_id`  | `cmd_id_name`         |
|-----------|------------------------|
| `0x10100` | `DEVICE_ENABLE`        |
| `0x10200` | `DEVICE_DISABLE`       |
| `0x20100` | `DMA_BUFFER_ENROLL`    |
| `0x20300` | `DMA_BUFFER_ALLOC`     |
| `0x20400` | `DMA_BUFFER_FREE`      |
| `0x30100` | `REG_IO`               |
| `0x40100` | `TRANSACTION_SUBMIT`   |
| `0x40300` | `TRANSACTION_CANCEL`   |

Unnamed IDs keep `cmd_id` searchable by hex value with no
`cmd_id_name` field.
