# Native code mapping

Captures made with `--stacks --json` include additive `process_maps` and
`stack_trace` records. They preserve process start time, executable mappings,
raw instruction pointers, rendered frames, ELF build IDs, and load bias. Event
records keep their existing `stack` and stack-ID fields and add
`stack_trace_refs`.

Resolve a capture offline:

```sh
neutron native-map capture.ndjson \
  --symbols out/symbols \
  --json-output native-map.json
```

The JSON schema is `neutron.native-map/v1`. Resolution prefers recursive GNU
build-ID matches, then verified pulled/APK artifacts, then captured labels and
`path + ELF-vaddr` fallbacks. Legacy captures remain readable, but their text
stacks are reported as unresolved because runtime addresses cannot be safely
reconstructed.

Artifacts may be pulled only from an explicitly selected, unchanged device:

```sh
neutron native-map capture.ndjson \
  --pull-apk --pull-libs --adb-serial SERIAL
```

Neutron compares the capture fingerprint and boot ID before pulling. It never
selects a device automatically, invokes `adb root`, pushes files, or changes
device state. The default cache is `<capture-stem>.native-artifacts/` with
private directory and file permissions. Library pulls are restricted to the
system/APEX/app paths recorded in executable maps.

Export stable ELF virtual addresses for later Ghidra tooling:

```sh
neutron ghidra-export capture.ndjson \
  --symbols out/symbols \
  --crash-window 5s \
  --output ghidra-bookmarks.json
```

The neutral schema is `neutron.ghidra-bookmarks/v1`. Bookmarks are grouped by
program identity and ELF virtual address, with bounded event/crash exemplars.
The Ghidra plugin itself is intentionally separate.
