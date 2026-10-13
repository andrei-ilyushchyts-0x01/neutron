# Neutron probe APK — workload interface for AI agents

`dev.neutron.probe` is a companion Android workload generator. An agent can invoke
its explicit, `DUMP`-permission-protected receiver through an authorized shell to
produce independent workload results while Neutron records kernel observations.
It has no UI and is not a general-purpose shell or model endpoint.

## Invocation and result contract

Select an authorized device and install the approved, signature-verified release
APK only when the task needs this attacker model. The APK is debuggable and targets
SDK 35. Preserve its SHA-256, signing certificate and version alongside the run.

```sh
adb -s SERIAL install -r neutron-probe.apk
adb -s SERIAL shell pm path dev.neutron.probe
adb -s SERIAL shell am broadcast \
  -n dev.neutron.probe/.ResearchReceiver \
  --es action keymint --es operation lookup
```

Continue only if installation succeeds and `pm path` returns a package path.
The receiver accepts string extras only. Retain both the shell exit status and
the final `Broadcast completed: result=N` response; shell success alone does not
establish workload success.

| Result code | Meaning | Agent response |
|---|---|---|
| `0` | Workload completed | Retain this as an external result, separate from observed Binder/syscall evidence. |
| `1` | Invalid input or workload failure | Retain diagnostics; correct input or prerequisite before retrying. |
| `3` | Unsupported hardware/platform prerequisite | Report unsupported; do not turn it into a successful empty observation. |

## Action selection

| `action` | Optional string parameters | Scope |
|---|---|---|
| `keymint` | `operation=lookup`, `delay_ms`, `finish_delay_ms` | Prefer explicit read-only lookup for capture smoke. Omitting `operation` requests ephemeral key generation. |
| `gpu` | none | GPU workload; hardware-dependent. |
| `camera` | `camera_id` | Camera workload; access and foreground/platform constraints apply. |
| `media-codec` | `mime` | Codec workload; codec availability applies. |
| `bluetooth` | none | Bluetooth workload; radio and permission prerequisites apply. |
| `wifi` | none | Wi-Fi workload; radio and permission prerequisites apply. |
| `usb` | `usb_device_id` | USB workload; explicit selection and device permission apply. |

Do not infer authorization for camera, radio, USB or key-generation actions from
a read-only tracing request. Frames, pixels, identifiers, descriptors, keys and
codec buffers are discarded in memory; the workload can still have device side
effects. Record the selected action and parameters.

For `keymint` lookup only, each delay is 0–5000 ms and their sum is at most 5000 ms.
`delay_ms` delays the lookup. `finish_delay_ms` holds the pending broadcast after
the lookup and renames the worker to `neutron-finish`, allowing a marker window to
end before receiver completion. The queried nonce-derived alias is expected to be
absent; lookup does not create keys. A successful lookup proves neither a KeyMint
HAL handoff nor authorization bypass. Concurrent/delayed completion does not
prove exact async parentage in the trace.

On Android 16, CameraService can reject a broadcast-only probe as an idle UID.
That prerequisite is reported as unsupported; a foreground stimulus requires
separate authorization. Validate every required action on the exact hardware.

## Source build

Use JDK 17, SDK platform 35, Build Tools 35.0.0 and the pinned Gradle 8.10.2 wrapper:

```bash
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
  "platform-tools" "platforms;android-35" "build-tools;35.0.0"
cd probe-app
./gradlew --no-daemon assembleDebug
```

Development output is not an approved release identity. Signed packaging validates
the configured certificate before publication. CI runs the existing probe unit
checks separately; device qualification requires the exact APK and firmware.
Deprecated `neutron research` remains a compatibility wrapper through 1.x;
new agent integrations should compose the core capture and evidence commands.
See the [agent workflow](../README.md#agent-execution-contract).
