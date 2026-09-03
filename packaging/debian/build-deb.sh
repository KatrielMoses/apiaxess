#!/usr/bin/env bash
#
# Builds the APIaxess Debian package (.deb) with every Phase-11 bundled tool
# staged into the FHS layout the Unix resolvers expect.
#
# Mirrors packaging/windows/build-msi.ps1: it builds the GUI + release engine,
# fetches and verifies each bundled tool (shared trimmed OpenJDK, apktool, jadx,
# ffuf, Chromium) via the same pinned fetch-*.ps1 manifests, stages them under
# /usr/share/apiaxess/, ships their notices/SBOMs, and produces a .deb plus its
# SHA-256 and a build manifest.
#
# The Unix resolvers (plugins/targets/apk/src/bundled.rs,
# crates/workbench-proxy/src/bundled.rs, crates/engine-shell/src/lib.rs) resolve
# bundled resources at bin/../share/apiaxess relative to the installed binary, so
# /usr/bin/apiaxess resolves /usr/share/apiaxess/... — a standard FHS install.
#
# The emulator "analysis-runtime" is the separate, optional ~2 GB payload and is
# deliberately NOT part of this package (see packaging/README.md); it is fetched
# post-install via packaging/assets/install-analysis-runtime.sh.
#
# Requirements on the Linux build host: bash, cargo (rust-toolchain), node + the
# installed GUI deps (pnpm install), dpkg-deb, tar, and PowerShell (pwsh) to run
# the shared, hash-pinned fetch-*.ps1 manifests. jlink cannot cross-compile, so
# this must run on Linux to build the Linux Java image.

set -euo pipefail

architecture="amd64"
output_directory=""
skip_application_build="false"
bundle_frida="false"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --architecture) architecture="$2"; shift 2 ;;
        --output-directory) output_directory="$2"; shift 2 ;;
        --skip-application-build) skip_application_build="true"; shift ;;
        --bundle-frida) bundle_frida="true"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [ "$architecture" != "amd64" ]; then
    echo "Only amd64 is supported today (got '$architecture')." >&2
    exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$script_dir/../.." && pwd)"
assets="$repository_root/packaging/assets"
target_root="$repository_root/target/packaging/linux-$architecture"
cache_root="$repository_root/target/packaging-cache"
pkg_root="$target_root/pkg"
share="$pkg_root/usr/share/apiaxess"
doc="$pkg_root/usr/share/doc/apiaxess"
if [ -z "$output_directory" ]; then
    output_directory="$repository_root/artifacts/linux"
fi

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "Required tool '$1' is not on PATH." >&2; exit 1; }
}
require cargo
require dpkg-deb
require tar
require pwsh

product_version="$(grep -A6 '^\[workspace\.package\]' "$repository_root/Cargo.toml" | grep -m1 '^version' | sed -E 's/^version[[:space:]]*=[[:space:]]*"([0-9.]+)".*/\1/')"
if ! printf '%s' "$product_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Could not read the workspace package version from Cargo.toml." >&2
    exit 1
fi

# --- Bundled Frida host devkit (only the frida-embedded variant) ---
# Mirrors build-msi.ps1's -BundleFrida: fetch and verify the pinned Linux
# frida-core devkit, then point frida-sys's bindgen (BINDGEN_EXTRA_CLANG_ARGS +
# LIBCLANG_PATH) and crates/sandbox/build.rs (APIAXESS_FRIDA_DEVKIT) at it so the
# release build links the pinned static frida-core. The device-side frida-server
# ships inside the analysis-runtime image; the devkit is a build/link input.
frida_runtime_dir="$target_root/frida"
if [ "$bundle_frida" = "true" ]; then
    pwsh -File "$assets/fetch-frida.ps1" -Platform linux_x64 -OutputDirectory "$frida_runtime_dir" -CacheDirectory "$cache_root"
    frida_devkit="$frida_runtime_dir/devkit/linux-x86_64"
    if [ ! -f "$frida_devkit/libfrida-core.a" ]; then
        echo "The bundled Frida devkit is missing libfrida-core.a at $frida_devkit." >&2
        exit 1
    fi
    if [ -z "${LIBCLANG_PATH:-}" ]; then
        # frida-sys runs bindgen, which needs libclang. Auto-detect the apt
        # llvm libclang directory if the operator has not pinned one.
        detected_libclang="$(dirname "$(ls /usr/lib/llvm-*/lib/libclang.so* /usr/lib/x86_64-linux-gnu/libclang-*.so* 2>/dev/null | head -n1)")"
        if [ -z "$detected_libclang" ] || [ ! -d "$detected_libclang" ]; then
            echo "Building the frida-embedded variant requires libclang: set LIBCLANG_PATH (install libclang-dev)." >&2
            exit 1
        fi
        export LIBCLANG_PATH="$detected_libclang"
    fi
    export APIAXESS_FRIDA_DEVKIT="$frida_devkit"
    export BINDGEN_EXTRA_CLANG_ARGS="-I$frida_devkit"
fi

# --- Build the GUI + release engine ---
if [ "$skip_application_build" != "true" ]; then
    require node
    vite="$repository_root/apps/gui/node_modules/vite/bin/vite.js"
    if [ ! -f "$vite" ]; then
        echo "GUI dependencies are missing. Run 'pnpm install --frozen-lockfile' first." >&2
        exit 1
    fi
    ( cd "$repository_root/apps/gui" && node "$vite" build )
    if [ "$bundle_frida" = "true" ]; then
        ( cd "$repository_root" && cargo build --release -p apiaxess --features frida-embedded )
    else
        ( cd "$repository_root" && cargo build --release -p apiaxess )
    fi
    # The native desktop shell links no Frida; build it separately (mirrors the MSI).
    ( cd "$repository_root" && cargo build --release -p apiaxess-desktop )
fi

engine="$repository_root/target/release/apiaxess"
desktop="$repository_root/target/release/apiaxess-desktop"
gui_dist="$repository_root/apps/gui/dist"
[ -x "$engine" ] || { echo "Release engine is missing at $engine." >&2; exit 1; }
[ -x "$desktop" ] || { echo "Release desktop shell is missing at $desktop." >&2; exit 1; }
[ -f "$gui_dist/index.html" ] || { echo "Built GUI is missing at $gui_dist." >&2; exit 1; }

# --- Reset the package staging tree ---
rm -rf "$pkg_root"
mkdir -p "$pkg_root/usr/bin" "$share/gui" "$share/runtime/java" "$share/tools" "$doc" "$pkg_root/DEBIAN"
mkdir -p "$pkg_root/usr/share/applications" "$pkg_root/usr/share/icons/hicolor/512x512/apps"
mkdir -p "$cache_root" "$output_directory"

install -m 0755 "$engine" "$pkg_root/usr/bin/apiaxess"
# The native desktop shell is the double-click entry point; it spawns the engine.
install -m 0755 "$desktop" "$pkg_root/usr/bin/apiaxess-desktop"
cp -r "$gui_dist/." "$share/gui/"
cp "$repository_root/README.md" "$doc/README.md"

# Desktop launcher + icon so the app appears in the applications menu.
install -m 0644 "$repository_root/apps/desktop/icons/icon.png" "$pkg_root/usr/share/icons/hicolor/512x512/apps/apiaxess.png"
cat > "$pkg_root/usr/share/applications/apiaxess.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=APIaxess
Comment=Local API-recovery workbench
Exec=/usr/bin/apiaxess-desktop
Icon=apiaxess
Terminal=false
Categories=Development;Security;
DESKTOP

# --- Bundled shared trimmed OpenJDK (jlink; cannot cross-compile) ---
java_dir="$target_root/java-runtime"
pwsh -File "$assets/fetch-java-runtime.ps1" -Platform linux_x64 -OutputDirectory "$java_dir" -CacheDirectory "$cache_root"
[ -x "$java_dir/bin/java" ] || { echo "Bundled Java runtime is missing bin/java." >&2; exit 1; }
mkdir -p "$share/runtime/java/linux"
cp -r "$java_dir/." "$share/runtime/java/linux/"

# --- Bundled apktool + jadx (platform-independent) ---
apk_dir="$target_root/apk-tools"
pwsh -File "$assets/fetch-apk-tools.ps1" -OutputDirectory "$apk_dir" -CacheDirectory "$cache_root"
[ -f "$apk_dir/apktool/apktool.jar" ] || { echo "Bundled apktool is missing apktool.jar." >&2; exit 1; }
cp -r "$apk_dir/." "$share/tools/"
if ! ls "$share/tools/jadx/lib/"*-all.jar >/dev/null 2>&1; then
    echo "Bundled jadx is missing a *-all.jar under tools/jadx/lib." >&2
    exit 1
fi

# --- Bundled static ffuf ---
ffuf_dir="$target_root/ffuf-runtime"
pwsh -File "$assets/fetch-ffuf.ps1" -Platform linux_x64 -OutputDirectory "$ffuf_dir" -CacheDirectory "$cache_root"
[ -f "$ffuf_dir/ffuf" ] || { echo "Bundled ffuf is missing the static binary." >&2; exit 1; }
mkdir -p "$share/tools/ffuf"
cp -r "$ffuf_dir/." "$share/tools/ffuf/"
chmod 0755 "$share/tools/ffuf/ffuf"

# --- Bundled Chromium (verified official snapshot) ---
chromium_dir="$target_root/chromium-runtime"
pwsh -File "$assets/fetch-chromium.ps1" -Platform linux_x64 -OutputDirectory "$chromium_dir" -CacheDirectory "$cache_root"
[ -x "$chromium_dir/chrome" ] || { echo "Bundled Chromium is missing the chrome binary." >&2; exit 1; }
mkdir -p "$share/chromium"
cp -r "$chromium_dir/." "$share/chromium/"

# --- Notices / SBOMs travel with the product (per-tool records already staged) ---
cp "$assets/java-runtime-NOTICES.md" "$doc/java-runtime-NOTICES.md"
cp "$assets/apk-tools-NOTICES.md" "$doc/apk-tools-NOTICES.md"
cp "$assets/ffuf-NOTICES.md" "$doc/ffuf-NOTICES.md"
cp "$assets/chromium-NOTICES.md" "$doc/chromium-NOTICES.md"
if [ "$bundle_frida" = "true" ]; then
    cp "$assets/frida-NOTICES.md" "$doc/frida-NOTICES.md"
    [ -f "$frida_runtime_dir/frida-sbom.json" ] && cp "$frida_runtime_dir/frida-sbom.json" "$doc/frida-sbom.json"
fi

# --- Debian control metadata ---
installed_size_kb="$(du -sk "$pkg_root" | cut -f1)"
cat > "$pkg_root/DEBIAN/control" <<EOF
Package: apiaxess
Version: $product_version
Section: utils
Priority: optional
Architecture: $architecture
Maintainer: APIaxess <packaging@apiaxess.invalid>
Installed-Size: $installed_size_kb
Depends: libwebkit2gtk-4.1-0, libnss3, libnspr4, libatk1.0-0, libatk-bridge2.0-0, libcups2, libdrm2, libgbm1, libgtk-3-0, libasound2, libxkbcommon0, libxcomposite1, libxdamage1, libxfixes3, libxrandr2, libxext6, libxi6, libxtst6, libx11-6, libxcb1, libpango-1.0-0, libcairo2, libatspi2.0-0, ca-certificates, fonts-liberation
Description: APIaxess local API-recovery workbench
 A native desktop app: the branded GUI runs in its own window (a Tauri/WebKitGTK
 shell) against the local engine. Self-contained static and web analysis — the
 shared trimmed OpenJDK, apktool, jadx, the static ffuf discovery binary, and a
 verified Chromium snapshot are bundled under /usr/share/apiaxess and run by
 absolute path (no host toolchain). libwebkit2gtk provides the app's webview;
 the remaining dependencies are the shared libraries the bundled Chromium needs.
 Static/APK analysis itself requires none of the host toolchain. The optional
 dynamic-analysis emulator runtime is a separate ~2 GB download, not this package.
EOF

# --- Build the .deb (reproducible ownership) ---
deb_name="apiaxess_${product_version}_${architecture}.deb"
deb_path="$output_directory/$deb_name"
rm -f "$deb_path"
dpkg-deb --build --root-owner-group "$pkg_root" "$deb_path"

sha256="$(sha256sum "$deb_path" | cut -d' ' -f1)"
printf '%s  %s\n' "$sha256" "$deb_name" > "$deb_path.sha256"
cat > "$output_directory/apiaxess-${product_version}-linux-${architecture}.build.json" <<EOF
{
  "schemaVersion": 1,
  "product": "APIaxess",
  "productVersion": "$product_version",
  "architecture": "$architecture",
  "deb": "$deb_name",
  "debSha256": "$sha256",
  "fridaBundled": $bundle_frida,
  "analysisRuntimeBundled": false
}
EOF

echo "Built $deb_path"
