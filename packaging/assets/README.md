# Heavy asset delivery

Android images and other heavyweight payloads are downloaded on demand and never
committed or baked into a native installer.

## Delivery from apiaxess.dev (in-app Download)

The two optional add-ons — `analysis-runtime` and `android-target` — are what a
user downloads from Settings → Add-ons (or the inline "not installed → Download"
on the APK and Android surfaces). The app never pulls their parts from a third
party at runtime: the release pipeline assembles each one here, from the pins in
`<slug>.toml`, into a single artifact per platform, and the app downloads only
that finished file from apiaxess.dev.

1. `pwsh packaging/assets/build-addon-artifact.ps1 -Slug <slug> -Platform <windows_x64|linux_x64> -SiteRoot <site>`
   runs `fetch-<slug>.ps1` (or packs an already-assembled `-PayloadDirectory`)
   and writes `<site>/assets/<slug>/<version>/<slug>-<windows-x64|linux-amd64>.tar.zst`
   plus `.sha256` and `.json` (sizes). The archive holds the payload root; state a
   booted emulator leaves behind (userdata, snapshots, locks, adb keys) is left
   out, so even a used payload packs clean. zstd level 19 by default (the zstd
   CLI, or Windows' own `tar.exe` when zstd is not installed). Build each
   platform on that platform (the Android SDK packages are per-OS).
2. `pwsh packaging/assets/update-asset-catalog.ps1 -SiteRoot <site>` re-hashes the
   artifacts and writes `<site>/assets/index.json` (name, purpose, version, and per
   platform: URL, SHA-256, size, installed size). Pin a version with
   `-Version analysis-runtime=<v>`.
3. Once the release key exists: `cargo xtask sign-manifest <key.pk8> <site>/assets/index.json`
   (writes `index.json.sig`; never re-save the JSON afterwards).
4. Upload `<site>/assets/` to the website: artifacts first, `index.json` (and
   `.sig`) last. Hosting: each artifact is ~1.2–1.4 GB (4.5–6 GB installed); the
   host must serve HTTP range requests so interrupted downloads resume.

In the app (`crates/updater/src/assets.rs`): the catalog is fetched only when the
operator clicks Download, the artifact is kept only if its SHA-256 matches, it is
unpacked beside its destination (entries escaping the root are refused), the
AVD's absolute `path=` is rewritten for the new home, and it is swapped into
place in one rename. It installs to the per-user data directory
(`%LOCALAPPDATA%\apiaxess\<slug>`, `~/.local/share/apiaxess/<slug>`), which the
engine resolves after an explicit `APIAXESS_ANALYSIS_RUNTIME` /
`APIAXESS_ANDROID_TARGET` override and before a copy beside the install
(`install_layout::addon_root`). With an override set the app never downloads.

`chromium.toml` is the release gate for the owned APIaxess Browser runtime. It
names an official Chromium snapshot and its SHA-256. `fetch-chromium.ps1`
verifies the archive, records the runtime `about:credits` entry point, ships
the APIaxess notice, and emits `chromium-sbom.json` beside the payload before
an installer can stage it.

## Bundled Java toolchain (Phase 11.1)

`java-runtime.toml` is the release gate for the shared, trimmed OpenJDK runtime.
It pins an unmodified Eclipse Temurin JDK per platform (URL + SHA-256), the
`jlink` module set, and the trim flags. `fetch-java-runtime.ps1` downloads and
verifies the JDK, runs that JDK's own `jlink` to build the trimmed image
(preserving the emitted `legal/` notices), ships the APIaxess notice, and emits
`java-runtime-sbom.json`. `jlink` cannot cross-compile, so run it per platform
(`-Platform windows_x64` on Windows, `-Platform linux_x64` on Linux).

`apk-tools.toml` is the release gate for the bundled apktool jar and jadx
distribution (both pinned by URL + SHA-256). `fetch-apk-tools.ps1` verifies and
lays them out under `tools/apktool/` and `tools/jadx/`, preserves the upstream
NOTICE/LICENSE files (jadx carries mixed LGPL/EPL dependency notices — the
payload is not merely "Apache"), and emits `apk-tools-sbom.json`.

Both Java tools run through the one shared runtime by absolute path
(`<runtime>/bin/java -jar apktool.jar …` and `<runtime>/bin/java … -cp
jadx-*-all.jar jadx.cli.JadxCLI …`), so APK static analysis needs nothing on the
host. The module set is validated by the clean-host integration test
(`plugins/targets/apk/tests/bundled_clean_host.rs`) against the pinned tool
versions.

## Bundled ffuf (Phase 11.2)

`ffuf.toml` is the release gate for the bundled ffuf discovery binary. It pins
the official ffuf release archive per platform (URL + SHA-256, matching the
release `checksums.txt`). `fetch-ffuf.ps1` verifies the archive, extracts the
static binary into `tools/ffuf/`, copies the upstream MIT `LICENSE`, and emits
`ffuf-sbom.json`. For Linux it also verifies the binary is statically linked
(no program interpreter / dynamic dependencies — a CGO-disabled Go build).

ffuf is invoked by absolute path from `tools/ffuf/` with a controlled
environment that confines its config/history to an APIaxess-owned directory, so
discovery needs nothing on the host. Resolution and a real directory-discovery
sweep are covered by `crates/workbench-proxy/src/bundled.rs` tests.

## Bundled Frida (Phase 11.4)

`frida.toml` pins the Frida artifacts: the host `frida-core` devkit per platform
(linked into the Rust backend when the `frida-embedded` cargo feature is on) and
the device-side `frida-server` per Android ABI (baked into / pushed to the owned
image). `fetch-frida.ps1` downloads and SHA-256-verifies each, extracts them into
`frida/`, ships the wxWindows license notice, and emits `frida-sbom.json`. Frida
is embedded as a **linked library**, not the Python CLI — no host Python, no host
Frida install. Host `frida-core`, the `frida` Rust crate, and device
`frida-server` are pinned to the same release (17.x).

## Analysis runtime (Phase 11.5 — separate optional payload)

`analysis-runtime.toml` pins the dynamic-analysis payload: the Android
`sdkmanager` bootstrap plus the emulator engine, platform-tools, and the
pure-AOSP `default` (**no GMS**) API-29 system image, and the owned
`apiaxess-android-10` AVD. `fetch-analysis-runtime.ps1` uses `sdkmanager` (which
verifies packages against Google's signed repository) to assemble the runtime,
creates the owned AVD, stages the device-side frida-server, and emits the
payload's own SBOM, provenance (`analysis-runtime-provenance.json`), notices, and
version. This is the separate ~2 GB payload — not the base installer.

The engine's `sandbox.bundled-emulator` tier resolves this runtime by absolute
path, detects host virtualization, and boots the owned image accelerated (KVM/
WHPX) or in QEMU software mode otherwise, with an honest fallback message. See
`crates/sandbox/src/lib.rs` (`AccelerationMode`, `BundledEmulatorBackend`, and
the planner tests).

## GUI Android target (Phase D1 — separate optional add-on)

`android-target.toml` pins the GUI-drivable Android target add-on: the same
`sdkmanager` bootstrap plus the emulator engine, platform-tools, and a slim
pure-AOSP `default` (**no GMS**, **userdebug** so `adb root` works) API-33 system
image, and the owned `apiaxess-android-target` AVD. Unlike the analysis runtime,
this is a target the user drives by hand — installing their own APK and completing
logins the autonomous crawler cannot — so provisioning is **not** baked into a
snapshot. `fetch-android-target.ps1` assembles the payload, stages this repo's
client APK + the device-side frida-server as first-boot artifacts, and emits the
**engine-read** `android-target-manifest.json` (id, version, AVD, emulator args,
provisioning hook, and the ws-scrcpy port D2 streams over) alongside the payload's
own SBOM, provenance, notices, and version. `install-android-target.{ps1,sh}` stage
it into the engine-resolved location. This is a separate download — not the base
installer, and independent of the analysis runtime.

The engine's add-on resolver (`crates/sandbox/src/android_target.rs`,
`AndroidTargetAddon`) reads the manifest by absolute path
(`APIAXESS_ANDROID_TARGET` override, else beside the install), boots the AVD
headless and **persistent** (no `-wipe-data`, so a completed login survives),
detects host acceleration (WHPX/KVM, honest software-mode fallback), installs the
client APK on first boot, and then runs the existing C2/C5 provisioning (live
session CA + frida-server + adb-reverse tunnel) verbatim over this target's bundled
`adb`. `Engine::launch_android_target` orchestrates it; a missing payload reports
the honest `sandbox.android-target-missing` diagnostic. The CA installed on first
boot is the live per-session CA, not a shipped static cert.

Screen streaming (Phase D2) is bundled into the same add-on: a pinned **ws-scrcpy**
fork (MIT) on a bundled **Node** runtime, staged by `fetch-android-target.ps1`
(`[streaming]` in the manifest) and built with `npm run dist`. ws-scrcpy has no
built-in auth and is bound to **127.0.0.1 only** — it is never directly reachable.
The engine is the sole listener and reverse-proxies the Android view
(`crates/local-api/src/stream_proxy.rs`, mounted at `/android-stream`) — both HTTP
and the WebSocket upgrade — only after enforcing the workbench gate: the loopback
`Origin` plus a valid workbench session or C1 device pairing token, checked on the
WebSocket upgrade as well as the initial GET. Because it rides the one engine port,
the view inherits the workbench's three access modes (loopback / SSH-tunnel /
exposure-with-warning) unchanged. The fork is preconfigured for ws-scrcpy's "proxy
over adb" interface mode (the emulator quirk: scrcpy-server listens on the AVD's
internal interface). Streaming assembly runs in the release pipeline; a payload
without it still boots and captures traffic (`sandbox.android-stream-unavailable`).
The advanced `APIAXESS_ANDROID_STREAM_PORT` override points the reverse-proxy at an
externally-run ws-scrcpy.
