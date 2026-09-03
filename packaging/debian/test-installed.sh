#!/usr/bin/env bash
#
# Installs the built APIaxess .deb, verifies every Phase-11 bundled tool lands at
# the exact FHS path its resolver expects and runs from the install tree, checks
# that the optional analysis-runtime payload is absent from the base package, then
# purges the package and verifies a clean removal.
#
# Mirrors packaging/windows/test-installed.ps1. Runs on a Debian/Ubuntu host with
# apt (to resolve the bundled Chromium's shared-library dependencies). Needs root
# (or sudo) for install/removal.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: test-installed.sh <path-to-.deb>" >&2
    exit 2
fi
deb_path="$(readlink -f "$1")"
[ -f "$deb_path" ] || { echo ".deb does not exist: $deb_path" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi

installed="false"
cleanup() {
    if [ "$installed" = "true" ]; then
        $SUDO apt-get remove -y apiaxess >/dev/null 2>&1 || $SUDO dpkg -r apiaxess >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# Install with apt so the declared Chromium runtime dependencies resolve.
$SUDO apt-get update -y >/dev/null 2>&1 || true
$SUDO apt-get install -y "$deb_path"
installed="true"

root="/usr/share/apiaxess"
engine="/usr/bin/apiaxess"
desktop="/usr/bin/apiaxess-desktop"
launcher="/usr/share/applications/apiaxess.desktop"
java="$root/runtime/java/linux/bin/java"
apktool="$root/tools/apktool/apktool.jar"
ffuf="$root/tools/ffuf/ffuf"
chromium="$root/chromium/chrome"
gui="$root/gui/index.html"

jadx_jar="$(ls "$root"/tools/jadx/lib/*-all.jar 2>/dev/null | head -n1 || true)"

for required in "$engine" "$desktop" "$launcher" "$java" "$apktool" "$ffuf" "$chromium" "$gui" "$jadx_jar"; do
    if [ -z "$required" ] || [ ! -e "$required" ]; then
        echo "Installed bundled component is missing at its resolver path: '$required'" >&2
        exit 1
    fi
done

# The emulator analysis-runtime is a separate optional download and must NOT be
# baked into the base package.
if [ -e "$root/analysis-runtime" ]; then
    echo "The base package must not contain analysis-runtime/; it is a separate optional payload." >&2
    exit 1
fi

# The launcher must target the native desktop shell (double-click entry point).
grep -q '^Exec=/usr/bin/apiaxess-desktop$' "$launcher" || { echo "Desktop launcher does not target the native shell." >&2; exit 1; }

# Exercise each bundled tool through its bundled runtime (not host tools).
"$java" -version >/dev/null 2>&1 || { echo "Bundled Java runtime failed to run." >&2; exit 1; }
apktool_version="$("$java" -jar "$apktool" --version 2>&1 | tr -d '\r' | tail -n1)"
[ -n "$apktool_version" ] || { echo "Bundled apktool failed through the bundled Java runtime." >&2; exit 1; }
jadx_version="$("$java" -cp "$jadx_jar" jadx.cli.JadxCLI --version 2>&1 | tr -d '\r' | tail -n1)"
[ -n "$jadx_version" ] || { echo "Bundled jadx failed through the bundled Java runtime." >&2; exit 1; }
ffuf_version="$("$ffuf" -V 2>&1 | tr -d '\r' | tail -n1)"
[ -n "$ffuf_version" ] || { echo "Bundled ffuf failed to run." >&2; exit 1; }

echo "Bundled: java, apktool ($apktool_version), jadx ($jadx_version), ffuf ($ffuf_version) run from the install tree"

# Purge and verify clean removal of the bundled tree.
$SUDO apt-get remove -y apiaxess >/dev/null 2>&1 || $SUDO dpkg -r apiaxess
installed="false"
if [ -e "$root" ] || [ -e "$engine" ]; then
    echo "Removal left package files behind under $root or $engine." >&2
    exit 1
fi

echo "Installed-package verification passed (bundled tools placed, runnable, and cleanly removed)."
