# Phase 3.6.2 Tusky capstone rerun — 2026-08-20

## Headline

The WSL2/ext4 rerun closed the filesystem/static stall, but did not close the
dynamic-tier thesis. Tusky completed intake and static discovery. Sandbox
startup was then rejected by the runtime security-patch floor before install,
so stages 4–6 were not reached.

## Environment

- WSL2 Ubuntu: Linux `6.18.33.2-microsoft-standard-WSL2`
- Rust: `1.88.0`; Docker Desktop Linux engine: `29.0.1`
- `/dev/kvm`: present and accessible as `root:kvm`, mode `660`
- Java: OpenJDK 17; apktool `2.9.3`; jadx `1.5.5`; ADB `34.0.4`
- APK: `fixtures/capstone/tusky-142.apk` in the WSL-native workspace
- SHA-256: `3E8FCC49A80D4C30AB6F6037E51402C77E2694D27EC19AE5B8A93CD08B6CAFFA`

## Stage evidence

| Stage | Result | Evidence |
|---|---|---|
| 1. Intake/resolution | **Pass** | One Tusky APK resolved on ext4; protection metadata completed with Tier 1 / R8 marker output. |
| 2. Static discovery | **Completed, but low-yield** | Routing returned `networking_present=true`, libraries `OkHttp`, `HttpURLConnection`, `Raw sockets`, and `WebView/JS bridge networking`, with 0 routing diagnostics. Static report returned `endpoints=0`, `loose_findings=7163`, `handoffs=4`, `static_diagnostics=7178`, protection Tier 1. It did not stall or fail to link. |
| 3. Sandbox/install | **Blocked before install** | Preflight was runnable, but startup rejected the runtime with `sandbox.adb-cve-mitigation-unsatisfiable`: reported security patch `2024-03-01`, below the enforced `2026-05-01` floor. No package collision was reached. |
| 4. Traffic/CA | **Not run** | No accepted sandbox lease or installed app. |
| 5. Pinning bypass | **Not run** | No app process reached an instrumentation lane. |
| 6. Dynamic model facts | **Not run** | No dynamic observations or scope-gate facts were produced. |
| 7. Teardown | **Partial pass** | Failed backend startup cleaned its disposable state; the direct HQarroum probe container and ADB connection were removed, and `adb devices` was empty. The intake workspace was removed. The unclean kill-mid-session check was not run because no lease started. |

## Direct HQarroum probe

The pinned image was boot-tested separately with `/dev/kvm` and
`EXTRA_FLAGS=-writable-system`:

- ADB loopback reached `127.0.0.1:5555` and boot completed in roughly 15
  seconds.
- `ro.build.type=userdebug`; `ro.debuggable=1`.
- `adb root` succeeded.
- `adb remount` succeeded after the required reboot.
- A write probe under `/system/etc/security/cacerts/` succeeded.
- The same image reported security patch `2024-03-01`, which is why the
  APIaxess security gate correctly refused to use it for the capstone.

The pinned image is therefore bootable/rootable/CA-writable on this WSL2 host,
but stale against the current security policy. A patched HQarroum image (or an
explicitly approved updated security-floor policy) is required before stages
3–6 can be honestly rerun.
