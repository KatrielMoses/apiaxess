# Heavy asset delivery

Reserved for signed manifests and download/verification metadata. Android images
and other heavyweight payloads are downloaded on demand and never committed or
baked into a native installer.

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
