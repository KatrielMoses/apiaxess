#!/usr/bin/env bash
# Builds the reference target's DEBUG APK. Intended for Linux or WSL2 — on the
# Windows dev box the Windows JVM's Selector.open() fails under VPN/WFP filters.
#
# Requires: JDK 17, an Android SDK (platform 34 + build-tools 34), Gradle 8.9.
#   ANDROID_HOME  default ~/android-sdk
#   GRADLE        default ~/tools/gradle-8.9/bin/gradle
#   JAVA_HOME     default ~/tools/jdk17 when present (needs jlink, i.e. a full JDK)
# Output: artifacts/mailaccess-reference-debug.apk (gitignored).
set -euo pipefail

src="$(cd "$(dirname "$0")" && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
if [ -z "${JAVA_HOME:-}" ] && [ -x "$HOME/tools/jdk17/bin/jlink" ]; then export JAVA_HOME="$HOME/tools/jdk17"; fi
gradle="${GRADLE:-$HOME/tools/gradle-8.9/bin/gradle}"
work="${WORK_DIR:-$HOME/.cache/mailaccess-reference-build}"

# Build outside /mnt/c: Gradle on a 9p/drvfs mount is slow and flaky.
mkdir -p "$work"
rsync -a --delete --exclude .gradle --exclude build --exclude app/build --exclude artifacts "$src/" "$work/"
echo "sdk.dir=$ANDROID_HOME" > "$work/local.properties"

(cd "$work" && "$gradle" --no-daemon -q :app:assembleDebug)

mkdir -p "$src/artifacts"
cp "$work/app/build/outputs/apk/debug/app-debug.apk" "$src/artifacts/mailaccess-reference-debug.apk"
echo "built $src/artifacts/mailaccess-reference-debug.apk"
