# Phase 3.6.3 capstone — stages 4–6 orchestration

## Headline

The harness now drives the live dynamic path through app launch, capture-store
inspection, pinning-bypass planning/application, dynamic capture into the
session model, scope-gate accounting, and normal teardown. The WSL2/ext4 Tusky
run exercised that orchestration successfully, but it did **not** produce a
dynamic fact: the fresh Tusky install had no configured Mastodon instance or
credentials, and the emulator reported no network connection. This is an
honest capstone finding, not a dynamic-capture pass.

## Environment and invocation

- Checkout: `/home/katriel/APIaxess-tusky-linux` on WSL2 Ubuntu native ext4.
- APK: `fixtures/capstone/tusky-142.apk`, package `com.keylesspalace.tusky`.
- HQarroum image: `halimqarroum/docker-android:api-33` at
  `sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`.
- Static tools: the Linux-native checkout's `tools/apktool` and
  `tools/jadx-linux/bin/jadx`.
- Capture window: 15 seconds after `adb shell monkey -p
  com.keylesspalace.tusky 1`.
- The harness used the in-process Hudsucker backend because `mitmdump` was not
  installed. `APIAXESS_CAPSTONE_USE_MITMDUMP=1` remains available for the
  external routed-proxy lane.

## Stage evidence

| Stage | Result | Evidence |
|---|---|---|
| 1. Intake/resolution | **Pass** | One Tusky APK resolved on ext4. |
| 2. Static discovery | **Pass** | `endpoints=0`, `loose_findings=7163`, `handoffs=4`, `static_diagnostics=7178`, networking libraries detected: OkHttp, HttpURLConnection, raw sockets, and WebView/JS bridge networking. No filesystem stall. |
| 3. Sandbox/install | **Pass** | HQarroum AVD started, CA trust setup completed, and `base` installed. JADX emitted its existing partial-decompilation warning, while apktool/static inputs remained authoritative. |
| 4. Traffic capture | **Setup pass; traffic finding** | Proxy started at `0.0.0.0:41435`; `adb shell monkey` returned exit 0. The workbench store contained `0` flow summaries and `0` completed decryptable HTTP flows. Tusky reported `not connected`. |
| 5. Pinning bypass | **Finding** | Planner selected `PrimaryFrida` because the runtime is rooted. Application could not deploy `frida-server`: `sandbox.bypass.frida-server-deploy-failed`, `frida-server: No such file or directory`. No pinning claim was made. |
| 6. Dynamic model facts | **Finding, not closed** | `flows=0`, `structured_flows=0`, `observed_endpoints=0`, `inferred_endpoints=0`, `resolved_handoffs=0`, `open_handoffs=4`, `diagnostics=1`, `scope_warnings=0`. Static findings remained in the same session; no dynamic facts were fabricated. |
| 7. Normal teardown | **Pass** | Traffic teardown returned `Ok(())`; the exact store parent was removed; intake teardown returned `Ok(())`. The unclean SIGKILL check was not run. |

## What is required to close the dynamic thesis

The harness needs a configured Mastodon instance and authorized login/timeline
interaction for Tusky, plus a compatible session-scoped `frida-server` artifact
if the target actually pins. A run with those prerequisites must show at least
one captured/decryptable flow, a dynamic model observation, and the expected
static-to-dynamic handoff accounting. A no-traffic run cannot prove stages 4–6.

## Unclean-kill boundary

The harness reports normal RAII/explicit teardown separately from the unclean
kill check. A SIGKILL bypasses Rust destructors, so it requires a supervised
child-process test that owns and externally verifies the disposable emulator,
proxy, CA, and intake paths. This remains an explicit follow-up rather than a
false green result.

## Hermes carry-forward

This single Tusky/HQarroum/WSL2 environment does not cover Flutter, Xamarin,
hardened/RASP targets, native-Linux-KVM, redroid, remote offload, or multiple
pinning implementations. Those remain environment-gated validation for the
Hermes native-Linux pass.
