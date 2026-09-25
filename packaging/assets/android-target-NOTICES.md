# APIaxess GUI Android target notices

The APIaxess GUI Android target is the optional, separately-versioned add-on that
gives a user a slim, no-GApps, root-capable AOSP x86_64 emulator to install their
own APK into and drive by hand, with traffic flowing to the workbench (Phase D1).
It is not part of the base install. This is its licensing/provenance inventory;
exact versions and the file inventory are in `android-target-provenance.json` and
`android-target-sbom.json` beside the installed payload.

## Component inventory and licenses (all redistributable)

- **AOSP userspace** (the Android framework, system apps, and libraries in the
  system image): **Apache License 2.0**. Redistributable.
- **Linux kernel** (the guest kernel in the image): **GPL-2.0**. Redistributable;
  the corresponding source is the AOSP common kernel for the pinned image.
- **QEMU** (the Android emulator engine): **GPL-2.0**. APIaxess ships the
  emulator engine **unmodified** as acquired from the Android SDK; if a future
  build ships a modified QEMU, the GPL-2.0 source obligations must be met
  (prefer unmodified).
- **Android SDK platform-tools** (`adb`): Android SDK Terms / Apache-2.0
  components. Acquired via the Google `sdkmanager`, which verifies each package
  against Google's signed repository manifest.
- **Device-side frida-server**: wxWindows Licence 3.1 — see `frida-NOTICES.md`.
- **APIaxess client APK** (`com.apiaxess.client`): first-party APIaxess software,
  staged from this repository's own build. Not third-party.
- **ws-scrcpy** (screen streaming, Phase D2): **MIT License**, © the ws-scrcpy
  authors (NetrisTV and contributors). APIaxess ships unmodified upstream
  ws-scrcpy, pinned by commit SHA, and runs it under the reverse-proxy base path
  via its own `WS_SCRCPY_PATHNAME` setting (no source patch); the MIT licence text
  and the copyright notice are preserved in `ws-scrcpy/LICENSE` beside the staged
  payload. ws-scrcpy bundles scrcpy-server (Apache-2.0) which it pushes to the guest.
- **Node.js runtime** (streaming host, Phase D2): the OpenJS Foundation Node.js
  distribution, shipped **unmodified** from nodejs.org. Node.js is under the MIT
  License; its bundled components (V8, libuv, OpenSSL, etc.) carry their own
  licences, preserved in the runtime's `LICENSE` file. No host Node is required.

## No Google Play / GMS

The image is the **pure AOSP `default` variant** (API 33,
`system-images;android-33;default;x86_64`) — it contains **no** Google Mobile
Services, **no** Google Play, and **no** Widevine. GMS/Play/Widevine are
proprietary and not APIaxess's to redistribute. The `default` variant is also
`userdebug`, so `adb root` works — the property this add-on needs to install the
session CA into the system trust store and start the device-side frida-server.

## Provisioning is not baked

Unlike the analysis runtime, this add-on does not bake trust into a snapshot. The
session CA, frida-server, and client APK are installed on **first boot** by the
existing C2/C5 provisioning flow, and the CA installed is the **live per-session
CA** (fetched and fingerprint-pinned through pairing), never a shipped static
certificate.

## Provenance

The image and engine are acquired at build time via the Android `sdkmanager` from
Google's signed repository; the client APK and device-side frida-server are staged
from this repository's own artifacts. The payload carries its own version
(`android-target-version.txt`), provenance record, and SBOM, independent of the
base application's and the analysis runtime's versioning.
