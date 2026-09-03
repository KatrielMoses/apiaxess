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
