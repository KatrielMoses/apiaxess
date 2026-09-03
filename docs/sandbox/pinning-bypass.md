# Phase 3.3 pinning bypass

Phase 3.3 exposes `apiaxess-sandbox::pinning` as the runtime implementation of
the versioned `apiaxess.pinning-bypass` plugin seam. The host plans one
implementation lane automatically from the target inventory:

- rooted AVD/runtime: spawn-gated Frida with the built-in OkHttp,
  `X509TrustManager`, `HostnameVerifier`, Network Security Config, and
  Conscrypt declarative specs;
- no root: decode, rewrite trust configuration, inject Frida Gadget, rebuild,
  zip-align, re-sign every APK split, and install as one session artifact;
- Flutter: reviewed native `libflutter.so` offset mappings, using Frida when
  rooted and the configured native patcher otherwise;
- Xamarin/.NET: Mono callback instrumentation in the rooted lane, or the
  automated Gadget patch lane when root is unavailable.

The registry is data-driven: a plugin registers a `BypassSpec` containing the
package/class/method/signature and return strategy. Adding a technique does not
change lane selection or the Phase 3.4 stealth substrate.

Known boundaries are surfaced as distinct diagnostics for hardware-backed
attestation, stripped/obfuscated native pinning, client mTLS, and anti-Frida
RASP. No lane claims success after one of those boundaries is detected.

All Frida processes, device server files, patched packages, and host workspaces
are attached to the sandbox lease and removed during teardown. Real pinned-app,
split-bundle, Flutter, Xamarin, and hardened-target behavior remains a Phase
3.6 live-validation item.
