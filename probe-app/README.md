# Neutron research probe

Install this minimal companion APK before `neutron research`. Its explicit receiver is restricted to callers holding Android's platform `DUMP` permission (shell/root), dispatches exactly seven typed actions, and returns only a result code. Camera frames, GPU pixels, Bluetooth/Wi-Fi identifiers, USB descriptors, keys, and codec buffers are discarded in memory.

The `keymint` action defaults to ephemeral key generation. For a deterministic,
read-only capture smoke test it also accepts `operation=lookup` and a bounded
`delay_ms` from 0 through 5000. The delay is accepted only with the read-only
lookup and lets the incoming protected broadcast finish admission before a
marker-bounded trace begins. The lookup checks a nonce-derived alias expected
to be absent and does not create or retain key material. It proves only the
Android Keystore query path, not a KeyMint HAL handoff.

Device instrumentation should cover each action on the authorized hardware matrix; radio-off, absent hardware, ambiguous USB selection, and missing USB permission must return `unsupported`.

On Android 16, CameraService may reject this broadcast-only probe as an idle
UID. The probe reports that platform prerequisite as `unsupported`, not a
generic failure; actual camera coverage needs a separately authorized
foreground stimulus.

## Build, test, install, and verify

The probe requires JDK 17, Android SDK platform 35 with Build Tools 35.0.0,
and Gradle 8.10.2. From the repository root:

```bash
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
  "platforms;android-35" "build-tools;35.0.0"

cd probe-app
gradle --version # must report Gradle 8.10.2 and JVM 17
gradle --no-daemon testDebugUnitTest assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell pm path dev.neutron.probe
```

Continue only when `pm path` prints a `package:` path. There is no UI and the
receiver is not a general-purpose test endpoint. Invoke it through an
authorized research pack, which passes only the action and typed parameters
compiled into the probe:

```bash
adb shell "su -c '/data/local/tmp/neutron research --pack keymint \
  --probe-package dev.neutron.probe --authorized-use'"

# Add this only on hardware you are authorized to assess.
adb shell "su -c '/data/local/tmp/neutron research --pack camera \
  --param camera_id=0 --probe-package dev.neutron.probe --authorized-use'"
```
