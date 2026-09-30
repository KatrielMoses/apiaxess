#!/usr/bin/env bash
#
# Fetches and installs the optional dynamic-analysis "analysis-runtime" payload
# into the location the installed product resolves on Linux.
#
# The analysis runtime (bundled QEMU/SDK emulator + owned Android-10 AOSP image +
# owned AVD + device-side frida-server) is the separate, optional ~2 GB payload
# that is deliberately NOT part of the base .deb. The engine resolves it from
# /usr/share/apiaxess/analysis-runtime, or from APIAXESS_ANALYSIS_RUNTIME when
# set; a dynamic run without it reports the honest sandbox.analysis-runtime-missing
# diagnostic (Phase 12.1).
#
# By default this installs into the per-user data directory
# ($XDG_DATA_HOME/apiaxess/analysis-runtime), the same place the app's
# Settings → Add-ons download puts it, which the engine resolves automatically
# (no root, no export). Pass --system to install into
# /usr/share/apiaxess/analysis-runtime (needs sudo) instead. It drives sdkmanager with the product's own
# bundled Java runtime (/usr/share/apiaxess/runtime/java/linux) so no host JDK is
# required. Needs pwsh (the shared fetch manifests are PowerShell).

set -euo pipefail

destination=""
system="false"
system_image=""
cache_directory=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --destination) destination="$2"; shift 2 ;;
        --system) system="true"; shift ;;
        --system-image) system_image="$2"; shift 2 ;;
        --cache-directory) cache_directory="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v pwsh >/dev/null 2>&1 || { echo "pwsh (PowerShell) is required to run the fetch manifest." >&2; exit 1; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
system_root="/usr/share/apiaxess/analysis-runtime"

if [ -z "$destination" ]; then
    if [ "$system" = "true" ]; then
        destination="$system_root"
    else
        destination="${XDG_DATA_HOME:-$HOME/.local/share}/apiaxess/analysis-runtime"
    fi
fi

SUDO=""
case "$destination" in
    /usr/*|/opt/*) if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; fi ;;
esac

# Prefer the product's own bundled Java runtime for sdkmanager.
java_args=()
if [ -x "/usr/share/apiaxess/runtime/java/linux/bin/java" ]; then
    java_args=(-JavaHome "/usr/share/apiaxess/runtime/java/linux")
fi
extra_args=()
[ -n "$system_image" ] && extra_args+=(-SystemImage "$system_image")
[ -n "$cache_directory" ] && extra_args+=(-CacheDirectory "$cache_directory")

echo "Assembling the analysis runtime into $destination (large, one-time ~2 GB download)..."
$SUDO pwsh -File "$script_dir/fetch-analysis-runtime.ps1" \
    -Platform linux_x64 \
    -OutputDirectory "$destination" \
    "${java_args[@]}" "${extra_args[@]}"

if [ ! -x "$destination/emulator/emulator" ]; then
    echo "The analysis runtime did not assemble an emulator engine at $destination/emulator/emulator." >&2
    exit 1
fi

echo "Analysis runtime installed at $destination."
user_root="${XDG_DATA_HOME:-$HOME/.local/share}/apiaxess/analysis-runtime"
if [ "$destination" = "$system_root" ] || [ "$destination" = "$user_root" ]; then
    echo "The installed engine resolves it automatically (no export needed)."
else
    echo "Activate it by exporting (add to your shell profile to persist):"
    echo "  export APIAXESS_ANALYSIS_RUNTIME=\"$destination\""
fi
