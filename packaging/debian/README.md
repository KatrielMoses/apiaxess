# Debian/APT packaging

`.deb` packaging for the service-free native Linux install. It mirrors the
Windows MSI payload but uses Debian FHS locations, so the Unix bundled-tool
resolvers (`bin/../share/apiaxess/...`) find every tool in the installed product.

## Build and verify

```bash
# On a Debian/Ubuntu host, with pnpm deps installed (pnpm install --frozen-lockfile):
bash packaging/debian/build-deb.sh                 # -> artifacts/linux/apiaxess_<version>_amd64.deb
bash packaging/debian/test-installed.sh artifacts/linux/apiaxess_*.deb
```

`build-deb.sh` builds the GUI + release engine, then fetches and SHA-256-verifies
each bundled tool through the shared pinned manifests and stages them into the
package tree. `jlink` cannot cross-compile, so the Linux Java image is built on
Linux. Requires `cargo`, `node`, `dpkg-deb`, `tar`, and `pwsh` (the fetch
manifests are PowerShell). CI builds and installs it in the `debian-installer`
job.

## Installed layout (relative to `/`)

```
usr/bin/apiaxess                                   engine executable
usr/bin/apiaxess-desktop                           native shell (double-click entry point)
usr/share/applications/apiaxess.desktop            application-menu launcher
usr/share/icons/hicolor/512x512/apps/apiaxess.png  app icon (brand mark)
usr/share/apiaxess/gui/                            pre-built GUI
usr/share/apiaxess/runtime/java/linux/             shared, trimmed OpenJDK (jlink)
usr/share/apiaxess/tools/apktool/apktool.jar       bundled apktool
usr/share/apiaxess/tools/jadx/lib/*-all.jar        bundled jadx
usr/share/apiaxess/tools/ffuf/ffuf                 bundled static ffuf discovery binary
usr/share/apiaxess/chromium/chrome                 verified Chromium snapshot
usr/share/doc/apiaxess/                            per-tool NOTICES + README
```

The `apiaxess-desktop` shell (Tauri) is the app: it starts the engine and renders
the branded GUI in a WebKitGTK webview. `libwebkit2gtk-4.1-0` (that webview) is
the first `Depends` entry.

## Headless servers (no desktop)

On a server or VM with no display, skip the desktop shell and run the engine
directly:

```bash
apiaxess serve --port 7777
```

This serves the GUI + API on the port until `Ctrl-C` — no window, no browser.
Reach it from your workstation over an SSH tunnel
(`ssh -L 7777:127.0.0.1:7777 host`), which keeps the loopback origin the live
WebSocket features require. `--host 0.0.0.0` binds a routable address as a
deliberate, self-secured exposure. WebKitGTK is not needed for `serve`, only for
the `apiaxess-desktop` window — a pure headless deployment could omit it.

The Linux runtime resolvers expect these under `share/apiaxess/` relative to
`bin/` (matching bundled Chromium), which `/usr/bin/apiaxess` satisfies via
`bin/../share/apiaxess`.

## Dependencies

Static/APK analysis is genuinely self-contained (the trimmed OpenJDK, apktool,
jadx, and the static ffuf binary need nothing from the host). The `Depends:`
line in `DEBIAN/control` declares only the shared libraries the **bundled
Chromium** needs at runtime (`libnss3`, `libgtk-3-0`, `libgbm1`, …) — these are
genuine system libraries a browser links, not an alternative to the bundled
tools. Installing with `apt-get install ./apiaxess_*.deb` resolves them.

## Excluded on purpose

The optional dynamic-analysis emulator runtime (bundled QEMU + owned Android-10
image + device-side frida-server, ~2 GB) is **not** in this package. Install it
after the fact with `packaging/assets/install-analysis-runtime.sh` (defaults to a
user-writable directory + prints the `APIAXESS_ANALYSIS_RUNTIME` export; pass
`--system` to install into `/usr/share/apiaxess/analysis-runtime`, which the
engine resolves automatically). Until it is present, dynamic runs report the
honest `sandbox.analysis-runtime-missing` diagnostic.
