# APIaxess analysis runtime notices

The APIaxess analysis runtime is the optional, separately-versioned dynamic-
analysis payload: a bundled QEMU-based emulator engine plus an APIaxess-owned,
pure-AOSP Android-10 (API 29) system image. This is its licensing/provenance
inventory (item 10 — done as its own workstream). Exact versions and the file
inventory are in `analysis-runtime-provenance.json` and
`analysis-runtime-sbom.json` beside the installed payload.

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

## No Google Play / GMS

The owned image is the **pure AOSP `default` variant** (API 29,
`system-images;android-29;default;x86_64`) — it contains **no** Google Mobile
Services and **no** Google Play. GMS/Play images are not APIaxess's to
redistribute. The advanced path lets a user acquire a different **public** image
(AOSP or Android-x86) for their own use, at their discretion; APIaxess ships only
the clean AOSP default.

## Provenance

The image and engine are acquired at build time via the Android `sdkmanager`
from Google's signed repository. The payload carries its own version
(`analysis-runtime-version.txt`), provenance record, and SBOM, independent of the
base application's versioning.
