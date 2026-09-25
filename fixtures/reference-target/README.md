# MailAccess reference target

A small Android app whose complete API surface we know exactly, used to measure how completely and
correctly APIaxess recovers an APK's API through static decompilation, dynamic capture, and fusion.
Because we wrote it, every recovered or missed endpoint is unambiguous.

- **Ground truth:** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) (table) and [`ground-truth.json`](ground-truth.json)
  (machine-readable). Update both whenever a request is added or changed.
- **Package:** `pro.mailaccess.reference`, DEBUG build, un-minified, `minSdk 21`, `targetSdk 34`,
  pure Kotlin/JVM (no native code, so it runs on the x86_64 Android-10 analysis emulator).
- **Deliberately absent:** Google Play Services / Firebase (they crash the no-GApps AOSP image),
  certificate pinning (a system-installed CA is trusted, so this tests base capture and decrypt), and
  any login gate (every screen is reachable straight away).

## What it exercises

Requests go to `https://mailaccess.pro` plus one third-party host. They use four construction styles
chosen to probe different static-extraction paths:

| Style | Where | Why |
|-------|-------|-----|
| Retrofit annotations (`suspend` and `Call<T>`, two Retrofit instances) | `net/MailAccessApi.kt`, `net/TodoApi.kt`, `net/Network.kt` | The declared-route path, including per-instance base URLs |
| Raw OkHttp: const concatenation, string templates, runtime concatenation, `HttpUrl.Builder` | `net/RawApiClient.kt` | URLs assembled in code rather than declared |
| `HttpURLConnection` | `net/LegacyHttpClient.kt` | The platform stack, with the method set by `setRequestMethod` |
| Hand-written GraphQL over OkHttp | `RawApiClient.loadProfile` | A GraphQL operation without Apollo codegen |

The calls are split between app launch, taps on the home screen, and a second screen (`Settings`)
reached by a tap, so dynamic analysis can be judged on how far the crawler gets.

## Build

The build runs on Linux or WSL2. On the Windows dev box the Windows JVM's `Selector.open()` fails under
the VPN/WFP filters, so Gradle has to run in WSL2.

```bash
./build.sh
```

It needs JDK 17 (a full JDK with `jlink`), an Android SDK with platform 34 and build-tools 34, and
Gradle 8.9. The defaults are `~/tools/jdk17`, `~/android-sdk` and `~/tools/gradle-8.9`; override them with
`JAVA_HOME`, `ANDROID_HOME` and `GRADLE`. The APK is written to
`artifacts/mailaccess-reference-debug.apk`, which is gitignored.

## Score a run

```bash
apiaxess analyze artifacts/mailaccess-reference-debug.apk --dynamic --json > surface.json
```

```bash
python score.py ground-truth.json surface.json score.json
```

Each manifest endpoint gets one line: the match kind (`template`, `concrete` for under-templated,
`wrong-method`, or `MISS`), its evidence sources, and whether the host, query, headers and body are
correct. Recall and every phantom endpoint follow at the end.

## Confirm what fired

Each call logs its manifest ID and HTTP status when it completes:

```bash
adb logcat -s MailAccessRef
```

Example output: `E09 -> 404`. The paths don't exist on the live host, so 404s are expected. The request
still went out and was answered, and that's what capture needs.
