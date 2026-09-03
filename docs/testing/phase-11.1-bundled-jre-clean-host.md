# Phase 11.1 — bundled JRE + apktool + jadx, clean-host verification

Date: 2026-08-29

Phase 11.1 bundles one shared, trimmed OpenJDK runtime plus apktool and jadx,
and drives both tools through the bundled runtime by absolute path so APK
static analysis needs nothing on the host. This is the record of the
verification that the gap is closed on a host with no host Java and no
host-installed apktool/jadx.

## What ships

- **Shared runtime:** one `jlink`-trimmed OpenJDK image per platform under
  `runtime/java/<platform>/`. Pinned Eclipse Temurin 21 LTS
  (`java-runtime.toml`), stripped (`--strip-debug`, no man pages/headers,
  `--compress=zip-6`). Trimmed size on this host: **~61 MB** (budget 50–70 MB).
  The image keeps the `legal/` notices `jlink` emits (unmodified-upstream
  GPLv2+CE posture).
- **apktool:** pinned `apktool_3.0.3.jar` (`apk-tools.toml`) under
  `tools/apktool/apktool.jar`. apktool extracts its own native `aapt2` at
  runtime; it ran on a clean Windows host using only the OS C runtime in
  `System32`.
- **jadx:** pinned jadx 1.5.5 distribution under `tools/jadx/`.

Module set (validated against the pinned tools): `java.base`, `java.desktop`,
`java.xml`, `java.naming`, `java.management`, `java.sql`, `java.logging`,
`java.security.jgss`, `java.security.sasl`, `jdk.unsupported`, `jdk.zipfs`,
`jdk.crypto.ec`, `jdk.crypto.cryptoki`, `jdk.charsets`, `jdk.localedata`.
`jlink` resolves transitive modules automatically.

## Invocation model

Both Java tools run through the one bundled runtime, by absolute path, never the
host:

- apktool — `<runtime>/bin/java -jar tools/apktool/apktool.jar d --force …`
- jadx — `<runtime>/bin/java -XX:+IgnoreUnrecognizedVMOptions
  -Djdk.util.zip.disableZip64ExtraFieldValidation=true
  --enable-native-access=ALL-UNNAMED -XX:MaxRAMPercentage=70.0
  -cp tools/jadx/lib/jadx-*-all.jar jadx.cli.JadxCLI -d <out> <apk>`

The jadx path mirrors the vendored `bin/jadx` launcher (same entrypoint, same
correctness-relevant JVM flags) rather than reimplementing it, and binds it to
the bundled runtime instead of a host JVM. Resolution is by absolute path from
the installed executable (`resolve_default_toolchain`), exactly as bundled
Chromium resolves. `APIAXESS_JAVA`/`APIAXESS_APKTOOL`/`APIAXESS_JADX` remain
advanced overrides; the default requires nothing on the host.

## Verification

Fixture: `fixtures/capstone/feeder-2.22.0-4050.apk` (a real APK: 11,736
classes, 2 DEX).

### 1. Automated integration test (product resolution path)

`plugins/targets/apk/tests/bundled_clean_host.rs` resolves the toolchain from a
staged install tree via `resolve_from_resource_base` and runs a real intake:

```bash
APIAXESS_BUNDLED_VERIFY=1 cargo test -p apiaxess-target-apk --test bundled_clean_host -- --nocapture
```

Result: **passed** — `format=Apk smali_roots=2 java_files=8547 dex_files=2`.
apktool produced authoritative smali + manifest; jadx produced 8,547 decompiled
`.java` files; DEX access established.

### 2. Real engine binary, fully sanitized host environment

The built `apiaxess.exe` was staged into an install-shaped directory
(`bin/apiaxess.exe` + `runtime/java/windows/` + `tools/apktool/` +
`tools/jadx/`) and run with a scrubbed process environment — **no JDK on
`PATH`, no `JAVA_HOME`, no `APIAXESS_*` overrides** — using only the default
`current_exe`-relative bundled resolution:

```bash
env -i PATH="/c/Windows/System32:/c/Windows" SystemRoot=... TEMP=... \
  <install>/bin/apiaxess.exe analyze <apk> --static-only --intake-output <dir>
```

Result: **exit 0**. Pipeline stages observed: `intake status=running … Artifact
normalized` → `static … Running static routing and extraction` → completion
(`coverage: 12 endpoints, … 12 static-only`). The jadx `artifact.decompilation-
failed / Warning` (exit code 3, 51 of 11,736 classes with per-class errors) is
jadx's normal partial-decompile path and is handled as a Warning because the
convenience source tree was still produced — designed behavior, not a failure.

Together these prove intake + unpack + decompile work with only the bundled JRE
+ bundled tools, with nothing on the host. This also finally exercises the
APK-intake path the Aug-2026 hardening host could not run (no apktool there).

## Diagnostics

With bundling, "apktool not found" / "no Java" is impossible on a correct
install. If a bundled component is missing or corrupt, intake fails fast with
`install.component-missing` (what/why/fix naming the component and the checked
path) before any tool is probed — an install-integrity error, not a silent
intake death.

## Licensing / SBOM

- OpenJDK: GPLv2 + Classpath Exception; unmodified Temurin, `legal/` notices
  preserved in the image; `java-runtime-sbom.json` emitted per platform.
- apktool: Apache-2.0. jadx: Apache-2.0 **plus** mixed distributed-dependency
  notices (LGPL/EPL logback) — payload is not labeled merely "Apache"; upstream
  NOTICE/LICENSE files preserved; `apk-tools-sbom.json` emitted.

See `packaging/assets/java-runtime-NOTICES.md` and
`packaging/assets/apk-tools-NOTICES.md`.

## Out of scope (per Phase 11.1)

ffuf (11.2), the proxy backend (11.3 — dropped mitmdump for hudsucker), Frida
(11.4), emulator (11.5); the native
installers (Phase 12 packages the layout produced here); the AAB/bundletool
branch (bundletool keeps its override-or-`PATH` behavior; not bundled here).
Linux verification is **done** — see
[phase-11-linux-verification.md](phase-11-linux-verification.md): the Linux
`jlink` image was built on Linux and a real APK analyzed on a scrubbed host
(12 endpoints, exit 0, poison-java never used).
