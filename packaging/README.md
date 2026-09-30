# Packaging

Native packaging inputs live here, separate from runtime code and downloaded
state. Windows MSI packaging is implemented in `windows/`; the Debian `.deb`
build is implemented in `debian/`. Both produce a **native desktop application**:
the branded GUI runs in its own window (a Tauri shell, `apps/desktop`) that starts
the local engine and points a native webview at it. The Start Menu shortcut
(Windows) and `.desktop` launcher (Linux) target the shell, so the product opens
as an app — not "run a server and open a browser."

Native packages use the same conceptual payload map:

- `bin/` contains native APIaxess executables: the `apiaxess` engine and the
  `apiaxess-desktop` native shell (the double-click entry point). On Windows the
  `bin/` also carries `MicrosoftEdgeWebview2Setup.exe`, the WebView2 Evergreen
  Bootstrapper the shell runs install-if-missing; on Linux the webview dependency
  is WebKitGTK, declared in the `.deb` `Depends`.
- `share/apiaxess/gui/` contains immutable, pre-built GUI assets.
- `runtime/` contains private product runtimes when a platform needs them.
- `runtime/java/<platform>/` is the shared, trimmed OpenJDK runtime.
- `tools/apktool/` and `tools/jadx/` are the bundled Android analysis tools.
- `tools/ffuf/` is the bundled static ffuf discovery binary.
- `frida/` is the bundled Frida (host frida-core devkit + device-side
  frida-server), linked via the `frida-embedded` feature.
- `analysis-runtime/` is the **separate, optional ~2 GB dynamic-analysis
  payload** (bundled emulator engine + owned Android-10 AOSP image). It is NOT
  part of the base installer; it is separately versioned and downloaded only
  when a user wants dynamic analysis.

On the Unix prefix layout these bundled resources live under
`share/apiaxess/` (matching the bundled Chromium convention); on Windows they
sit beside `bin/` under the install folder. The staging trees produced by
`assets/fetch-java-runtime.ps1` and `assets/fetch-apk-tools.ps1` use exactly the
install-relative layout above.

## Owned, bundled components vs. runtime-managed state

APIaxess owns and ships everything its **core** analysis needs, so a correct
install requires nothing on the host — no host `java`, apktool, jadx, or
browser. Bundled owned components (private Chromium, the shared Java runtime,
apktool, jadx, ffuf, Frida) are first-class installer payload, discovered by
absolute path relative to the installed executable and pinned/verified at build
time.

The **analysis runtime** (bundled emulator + owned Android-10 image) is the one
deliberately-separate payload: it is large (~2 GB), optional, and separately
versioned, so it is a distinct download pulled only for dynamic analysis — not
part of the ~400 MB base installer. It carries its own version, SBOM, notices,
and provenance. The engine resolves it from `analysis-runtime/` (or the
`APIAXESS_ANALYSIS_RUNTIME` override) and reports `sandbox.analysis-runtime-
missing` if a dynamic run is requested without it.

Note: the emulator's *accelerated* performance depends on host virtualization
(KVM/WHPX), a CPU/firmware capability that cannot be bundled; the bundled
software (QEMU + image) runs everywhere, in software mode when no virtualization
is present (see `sandbox.software-mode-active`).

## Releasing

Release assets are unsigned; integrity comes from the published `SHA256SUMS`.
Each package also carries an `install-channel` marker (`msi`, `portable`,
`scoop`, `chocolatey`, `deb`) that tells the in-app updater how that copy is
updated (see `crates/updater/src/channel.rs`).

1. Build from the commit being tagged, so the engine's About page carries a clean
   commit stamp:
   - Windows: `pwsh packaging/windows/build-msi.ps1` → `artifacts/windows/`
     `APIaxess-<v>-windows-x64.msi` and `APIaxess-<v>-windows-x64-portable.zip`
     (the same staged tree, zipped, for Scoop).
   - Linux: `bash packaging/debian/build-deb.sh` → `artifacts/linux/apiaxess_<v>_amd64.deb`.
2. Collect the three assets in one directory and write `SHA256SUMS` with
   `pwsh packaging/gen-checksums.ps1 -Directory <dir>` or
   `bash packaging/gen-checksums.sh <dir>` (identical output).
3. `pwsh packaging/update-manifests.ps1 -Sums <dir>/SHA256SUMS -LatestJson <dir>/latest.json -Artifacts <dir> -Summary "<one line>"`
   points the Scoop manifest and Chocolatey package at the release's URLs and
   hashes, and writes the in-app updater's `latest.json` from the same
   SHA256SUMS (version, `https://apiaxess.dev/dl/<v>/<file>` URLs, SHA-256,
   sizes, `min_supported`), so the Download page, the package managers and the
   app can never disagree. Once the release key exists, sign the exact file:
   `cargo xtask sign-manifest <key.pk8> <dir>/latest.json` writes
   `latest.json.sig` (ed25519 over the raw bytes; never re-save the JSON after
   signing). The key is created once, offline, with
   `cargo xtask update-keygen <key.pk8>`; its public half goes into
   `crates/updater/src/verify.rs` (`EMBEDDED_PUBLIC_KEY`), after which the app
   refuses any unsigned or badly signed manifest.
4. Create the GitHub Release `v<v>` with the MSI, zip, `.deb`, and `SHA256SUMS`.
   Publish the same files to the website as `/dl/<v>/<file>`, then
   `latest.json` (and `latest.json.sig`, once signing is on) to
   `/releases/` — assets first, manifest last, so no app is ever pointed at a
   file that is not there yet.
5. When an add-on changed (or for the first release), build and publish the
   on-demand add-ons: `assets/build-addon-artifact.ps1` per add-on and platform,
   then `assets/update-asset-catalog.ps1`, then sign `assets/index.json` once the
   key exists (see `assets/README.md`, "Delivery from apiaxess.dev"). Add-ons are
   versioned on their own; an app release does not need new ones.
6. Copy `scoop/apiaxess.json` to `bucket/apiaxess.json` in the
   `KatrielMoses/scoop-apiaxess` bucket repo. Later versions can be bumped there by
   Scoop's `checkver`/`autoupdate`, which reads the hash from `SHA256SUMS`.
7. `choco pack chocolatey/apiaxess.nuspec` and `choco push` to the community
   repository (moderation takes days; the package downloads the release MSI and
   verifies its SHA-256).
