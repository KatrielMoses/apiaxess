# Phase 3.1.2 — HQarroum AVD tier and APKMirror intake

The `sandbox.avd` backend now starts `halimqarroum/docker-android:api-33` as a
digest-pinned, headless `google_apis` userdebug emulator. The approved API 33
pin is:

```text
sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95
```

The image is acquired on demand and is not redistributed by APIaxess. The
wrapper code remains MIT-licensed; QEMU remains the image's GPL-2.0 in-container
process and is not linked into APIaxess.

## Lease contract

Each lease:

1. creates a session-scoped ADB key;
2. starts the image with `--device /dev/kvm`,
   `EXTRA_FLAGS=-writable-system`, and `SKIP_AUTH=false`;
3. publishes container port 5555 to an ephemeral host port bound only to
   `127.0.0.1`;
4. connects host-side ADB through that authenticated loopback endpoint;
5. verifies `ro.build.type=userdebug`, `ro.debuggable=1`, `adb root`, the first
   `adb remount`, reboot, the second remount, and a write/remove probe in
   `/system/etc/security/cacerts/`;
6. verifies that the container has an active KVM VM/vCPU descriptor, rejecting
   an unproven TCG fallback; and
7. disconnects ADB, removes the container, and removes the session key at
   teardown. No snapshot or persistent writable volume is used.

The existing sandbox control and traffic-routing seams therefore operate over
the same host-side `AdbControl` used by the other container path. The AVD tier
does not expose Docker objects or a raw ADB listener to callers.

## API level and rebuilds

API 33 uses the approved digest above. For API 34 or later, build a local image
from the HQarroum source with the documented build argument:

```bash
docker build --build-arg API_LEVEL=34 -t local/docker-android:api-34 .
```

Configure the resulting local tag and its recorded image digest explicitly;
the default remains the approved API 33 pin. A local rebuild is an input asset,
not a silently substituted image.

## Windows 11 / WSL2 routing

Capability detection probes WSL2 for a readable/writable `/dev/kvm`. The local
path is offered only when Docker is reachable, host ADB is available, WSL2
nested KVM is usable (or native acceleration is confirmed), and the runtime
itself demonstrates KVM. Win10, missing BIOS virtualization, inaccessible
`/dev/kvm`, and TCG fallback are diagnostic conditions with remote-offload as
the explicit fallback; APIaxess does not silently accept TCG.

The validated machine-level spike evidence is recorded in
`docs/sandbox/hqarroum-windows-wsl2-spike.md`. Live Phase 3.6 pipeline capture
remains a separate validation claim and is not implied by this backend wiring.

## `.apkm` intake

APKMirror ZIP-family inputs are recognized from their members rather than by
trusting the filename extension. A base APK plus `split_config_*` APK members
(or APKMirror metadata) is normalized through the existing multi-APK install
path, preserving the raw archive and deterministic split records.
