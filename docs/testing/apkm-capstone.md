# Live APKM capstone

`real_apkm_capstone_evidence` is an environment-gated integration test. It is
listed in the normal workspace test suite, but it prints a `skipped:` reason
and exits successfully when the live prerequisites are not available. It is
not an ignored test. A normal CI runner therefore reports why the live
environment was not exercised, while a prepared Hermes or self-hosted lane
can run the same test without changing the harness.

## Prerequisites

The live run requires all of the following:

- `jadx`, `apktool`, and host-side `adb` available on `PATH` (or use
  `APIAXESS_JADX`, `APIAXESS_APKTOOL`, and `APIAXESS_ADB` for explicit
  executable paths).
- Docker with the Linux engine available on `PATH` (or
  `APIAXESS_DOCKER`).
- The digest-pinned HQarroum API-33 image:
  `halimqarroum/docker-android:api-33@sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`.
  Pull it before the run if it is not already local:

  ```sh
  docker pull halimqarroum/docker-android:api-33@sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95
  ```

- Hardware acceleration: native Linux with usable AVD KVM, or Windows 11
  with the WSL2/Docker Desktop path and a readable/writable `/dev/kvm`.
  The backend preflight rejects TCG fallback and reports the acceleration
  diagnostic as the skip reason.
- The repository's designated, authorization-clean Feeder F-Droid fixture:
  `fixtures/capstone/feeder-2.22.0-4050.apk` (package
  `com.nononsenseapps.feeder`, version `2.22.0`, SHA-256
  `1066f08e9e773fe0a5a4cd35d8e308634d8c4fbe9d3390be0095cbdaf0a39c`). The
  path is stable because it is resolved from the workspace root, never from
  `target`.

The fixture is already stored in this checkout. If a deployment omits large
binary fixtures, obtain the same authorized F-Droid artifact, verify the
listed SHA-256, and place it at that path. A deliberately selected replacement
APK/APKM may be supplied with `APIAXESS_CAPSTONE_APK` (or
`APIAXESS_CAPSTONE_APKM`); relative override paths are resolved from the
workspace root and absolute paths are also accepted.

## Deliberate invocation

From PowerShell:

```powershell
$env:APIAXESS_CAPSTONE_LIVE = "1"
cargo test -p apiaxess-target-apk --test capstone_apkm real_apkm_capstone_evidence -- --nocapture
```

From native Linux or WSL2:

```sh
APIAXESS_CAPSTONE_LIVE=1 \
  cargo test -p apiaxess-target-apk --test capstone_apkm real_apkm_capstone_evidence -- --nocapture
```

The test performs intake, static routing, HQarroum installation, guest
traffic capture, dynamic modelling, and teardown. It writes disposable intake
data below `tmp/` and leaves the stage report beside that disposable output.
Use `APIAXESS_CAPSTONE_OUTPUT_ROOT` to select another workspace-local or
explicit output location. The Feeder feed defaults to
`https://planet.gnome.org/atom.xml`; `APIAXESS_CAPSTONE_FEED_URL` and
`APIAXESS_CAPSTONE_ALLOWED_DOMAIN` override those values for an authorized
fixture.

For an intake/static-only measurement that does not require an emulator:

```sh
APIAXESS_CAPSTONE_LIVE=1 APIAXESS_CAPSTONE_STOP_AFTER_STATIC=1 \
  cargo test -p apiaxess-target-apk --test capstone_apkm real_apkm_capstone_evidence -- --nocapture
```

The flag is intentionally explicit: without `APIAXESS_CAPSTONE_LIVE=1`, the
test reports a visible reason such as
`skipped: APKM capstone — set APIAXESS_CAPSTONE_LIVE=1 ...`. With the flag set,
missing fixtures, tools, the HQarroum image, Docker/ADB, or KVM produce a
specific prerequisite skip. Once all checks pass, failures in the live
harness are real test failures.

## CI and Hermes

The default CI job runs a dedicated `--nocapture` invocation in addition to
the workspace suite so the prerequisite result is visible in CI logs. It
does not set the live flag, so hosted runners remain green with a reasoned
skip. A self-hosted KVM lane can set `APIAXESS_CAPSTONE_LIVE=1`, provision the
listed image and fixture, and invoke the same command above; that is the
Hermes release-ready entry point for the capstone and its later breadth
extensions.
