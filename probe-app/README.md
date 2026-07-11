# Neutron research probe

Install this minimal companion APK before `neutron research`. Its explicit receiver is restricted to callers holding Android's platform `DUMP` permission (shell/root), dispatches exactly seven typed actions, and returns only a result code. Camera frames, GPU pixels, Bluetooth/Wi-Fi identifiers, USB descriptors, keys, and codec buffers are discarded in memory.

Device instrumentation should cover each action on the authorized hardware matrix; radio-off, absent hardware, ambiguous USB selection, and missing USB permission must return `unsupported`.
