# Phase 3.6 live validation report

**Status: incomplete; corrected dev-environment pass completed, with live-validation debt remaining open.**

This report records the evidence gathered on 2026-08-19. It does not promote
unit-tested substrate behavior to real-app coverage. The Phase 3.1–3.5 Rust
workspace suite is green, but the real-APK and all-three-tier acceptance
criteria below are not yet closed.

The corrected pass was run on 2026-08-19 against the user-provided
`target/PlayRoom.apk` fixture. The user identified this APK as the in-scope
validation target; no external target was selected, and no licensing or
anti-tamper bypass was attempted merely to force the fixture past its runtime
boundary.

## Evidence environment

| Area | Evidence | Result |
|---|---|---|
| WSL Linux | WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`; `/dev/kvm` exists | KVM device is present, but this distro has no Linux `adb` or `emulator` binary and no Android image installed in WSL |
| Windows Android SDK | SDK emulator and platform-tools are installed; AVDs `Pixel_4` and `Pixel_5` exist | WHPX-backed native Windows AVD is usable; this is not proof of the required Linux-KVM tier |
| Windows-host AVD probe | `Pixel_4` booted to Android 10/x86 with `sys.boot_completed=1`; `adb emu kill` completed and no `emulator-5554` remained | Partial lifecycle pass; this was a direct emulator probe, not a full APIaxess lease/snapshot test |
| Docker | Docker Desktop Linux daemon is reachable from WSL; server version `29.0.1` | WSL redroid preflight still stops at missing binder/ashmem prerequisites |
| redroid | WSL APIaxess preflight exercised | `sandbox.redroid-kernel-unavailable` returned before container start; no live redroid runtime was claimed |
| Remote offload | SSH client exists, but no remote host, identity key, or pinned known-hosts file is configured | Not runnable |
| App corpus | `target/PlayRoom.apk` is present and user-designated for this validation | Identity/install were validated; launch is blocked by PairIP licensing and no emulator network |

The redroid container and its named data volume were removed after each probe.
No unrelated Docker containers were removed.

## Corrected dev-environment pass

| Stage | Result | Evidence and boundary |
|---|---|---|
| APK identity | **Confirmed** | `C:\APIaxess\target\PlayRoom.apk`, 48,569,126 bytes, SHA-256 `0F782A5DEC67330EF43EB4BA3B3E661E43C8224B78F02B5A0108F078EE5C514C`; package `com.tamasha.live`, version `3.1.6`/code `316`, launch activity `com.tamasha.live.splash.ui.SplashActivity`. |
| Native Windows capability/planner | **Pass** | WHPX functional probe reported usable; SDK emulator discovery now finds `%LOCALAPPDATA%\Android\Sdk\emulator\emulator.exe`; Windows-specific `-version` probing reports emulator `36.2.12`; planner selected `NativeWindows`, default `Avd`, fallback `RemoteOffload`, with no redroid offer. |
| Native Windows AVD lifecycle | **Partial pass** | `Pixel_4` booted headlessly to Android 10/x86, `sys.boot_completed=1`; the emulator reported security patch `2019-09-05`; ADB installation and later `emu kill` completed, with no device remaining after teardown. |
| Real APK installation | **Pass** | `com.tamasha.live` installed and `pm path` resolved its base APK. |
| Real APK launch | **Blocked by fixture/runtime licensing** | The process exited with `com.pairip.licensecheck.LicenseCheckException: Licensing service could not process request`; no FATAL EXCEPTION stack was observed. The emulator also reported no connected network. This is not claimed as a sandbox, routing, or pinning failure. |
| Static APK intake | **Blocked by dev toolchain** | `apktool 2.9.3` and Android build tools are present, but `jadx` is not installed/on PATH; the APIaxess APK target returned `external-tool.missing` during required tool preflight. No static handoff was produced. |
| WSL capability/planner | **Pass** | WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`; `/dev/kvm` exists but cannot be opened read/write; Linux `adb` and `emulator` are absent; VM posture is `Degraded`; planner selected `InsideVm`, default `RemoteOffload`, with no redroid offer. |
| WSL redroid preflight | **Pass — clean fallback** | Docker `29.0.1` is reachable, but binder/binderfs and ashmem are absent. APIaxess `RedroidBackend` returned `sandbox.redroid-kernel-unavailable` before container start; no raw ADB listener or `0.0.0.0` bind was created. |

The Windows-specific emulator probe fix made during this pass is recorded in
`crates/host-capabilities` and `crates/sandbox`: the default detector discovers
the standard Windows SDK location and uses the Windows emulator's `-version`
flag. This changed the native Windows AVD capability result from a false
missing-tool report to supported.

## Checklist results

| Checklist | Tested target/tier | Result | Diagnosis / evidence |
|---|---|---|---|
| 1. Sandbox lifecycle and unclean teardown | Windows-host `Pixel_4` AVD | **Partial** | Direct boot and kill passed. Linux-KVM AVD, APIaxess lease ownership, snapshot restore, and kill-mid-session verification remain untested. |
| 1. Host capability honesty | WSL2 and Windows host | **Pass for tested posture** | WSL is identified as VM/nested guidance and routed to remote-offload; native Windows is not false-flagged and selects AVD when WHPX and the emulator are usable. |
| 1. redroid lifecycle | WSL2 redroid preflight | **Pass for fallback path; live runtime gated** | The corrected backend rejected the WSL kernel prerequisites before container start with a legible diagnostic. Native-Linux image boot and host-ADB contract remain environment-gated. |
| 1. Remote lifecycle | Remote-offload | **Blocked** | No configured remote Linux host or strict SSH key/known-host material. |
| 2. Routing, CA trust, non-proxy app, and QUIC downgrade | Real Android app | **Not run** | No APK and no ready Linux/redroid/remote target. Existing coverage is unit-level only. |
| 3. Frida pinning bypass | OkHttp/Conscrypt/NSC-pinned app | **Not run** | Host Frida CLI is installed, but no connected target app/device was available. |
| 3. Split-bundle patch-and-resign | Real split APK | **Not run** | No split APK fixture; signing-recovery work is also explicitly outside Phase 3.6. |
| 3. Flutter lane | Real Flutter app | **Not run** | No Flutter APK and no ready target runtime. |
| 3. Xamarin lane | Real .NET app | **Not run** | No Xamarin APK was obtained. This remains an explicit fixture gap. |
| 3. Hardened-app escalation | Attestation/RASP target | **Not run** | No authorized hardened target was available; no success or boundary claim is made. |
| 4. Early Frida hooks/watchdog | Real instrumented app | **Not run** | No device/app pair. The substrate remains unit-tested, not live-proven. |
| 4. Stealth effectiveness | Detection-employing apps | **Not run** | The 97% planning target is not a measured real-app result. |
| 5. Dynamic capture into model | Real APK through static → dynamic pipeline | **Not run** | No APK, no live traffic, and therefore no real schema, handoff-resolution, or dynamic-silence evidence. |
| QA user-seat validation | Point-and-run app workflow | **Not run** | QA could not assess the live workflow, diagnostics, tier choice, or teardown without a usable app/runtime fixture. |

## Findings and carry-forward fixes

### F36-REDROID-001 — official redroid control contract is incompatible

The original redroid implementation assumed ADB through `docker exec`, but
the official `redroid/redroid:14.0.0-latest` image has no ADB client inside the
container. The image also remained ADB-offline on the Docker Desktop Linux VM
during the probe. Phase 3.1.1 changes the backend to a host ADB client over a
per-lease authenticated loopback-only ephemeral port, with explicit readiness,
security-patch, and teardown checks. This resolves the code-level contract
finding; it does not claim live official-image compatibility until the Linux
native validation is rerun.

This is a blocking **3.6.x** fix, not a silent pass. The owner must choose and
validate one explicit contract:

1. maintain a versioned helper image that contains a compatible ADB client and
   prove its Android boot/device lifecycle; or
2. change the backend to use a host ADB client over a per-lease loopback-only,
   authenticated/isolated port, with strict port allocation and teardown.

The second option is now the implemented contract. Live validation remains
open and must verify the port binding, host-key authorization, Android boot,
security-patch floor, and complete teardown on a native Linux host.

### F36-ENV-001 — Linux AVD prerequisites are not installed in WSL

The Linux kernel exposes `/dev/kvm`, but Ubuntu has no Linux `adb`, emulator,
system image, or configured AVD. Install a Linux-native Android SDK/emulator
and image, then repeat the APIaxess `AvdBackend` lease, snapshot, unclean-kill,
traffic, and teardown tests. The Windows-host AVD result must not be substituted
for this evidence.

### F36-REMOTE-001 — remote-offload fixture is absent

Provide a reachable Linux test host, a dedicated test account, a pinned
known-hosts file, an identity key, and the remote helper at the configured
path. The full remote lease and encrypted traffic-stream teardown must then be
run. A WSL distro on the same workstation is not a substitute for a separately
reachable remote host.

### F36-APP-001 — authorized real-app corpus is absent

QA/dev must provide or approve fixtures for at least: an OkHttp/Conscrypt/NSC
pinning target, a split bundle, Flutter, Xamarin/.NET if obtainable, and a
hardened/RASP boundary target. Each fixture needs provenance, package name,
version/hash, permitted test scope, and expected traffic assertions. Until
then, all app-specific rows above remain **Not run**, not pass.

The corrected pass now has one authorized user-provided APK, but it cannot
serve as a live capture fixture in this environment because its PairIP
licensing service rejected the emulator launch and the emulator had no network.
The fixture remains useful for identity, install, and static-toolchain checks;
it does not close the real-app capstone.

## Part-B handoff checklist for Hermes

These items are explicitly environment-gated and were not substituted by the
Windows/WSL results above:

1. Native-Linux-KVM AVD: clean boot, snapshot restore, kill-mid-session,
   routing, CA trust, and complete teardown on a native Linux host with a
   readable/writable `/dev/kvm` and Linux Android SDK/image.
2. Native-Linux redroid: real binder/binderfs plus ashmem-or-memfd kernel,
   official redroid image boot, host-side authenticated ADB over the
   per-lease loopback ephemeral port, `2026-05-01` security-patch enforcement,
   traffic/CA teardown, and no residual listener/container/volume/key.
3. Remote-offload: separate reachable Linux host, dedicated account, pinned
   known-hosts file, identity key, encrypted lease/control path, traffic
   stream, and teardown.
4. Corpus breadth: authorized Flutter, Xamarin/.NET, split-bundle, and
   hardened/RASP fixtures, each with provenance, package/version/hash, scope,
   and expected traffic/model assertions.

## Honest dynamic-tier boundary

What is currently reliable is the code-level contract: sandbox descriptors,
capability diagnostics, cleanup objects, traffic/trust plans, pinning lanes,
Frida health state, stealth boundaries, and dynamic-capture model writes are
implemented and workspace-tested. A Windows-host AVD can also boot and be
cleanly stopped outside the APIaxess lease.

What is environment-gated is the real dynamic tier: Linux AVD requires a
Linux-native Android toolchain and image; redroid requires a compatible Linux
kernel/image/control contract; remote-offload requires a configured remote
host; and all app-specific claims require authorized real APK fixtures.

What is not established is equally important: no real pinned, Flutter,
Xamarin, or hardened-app success rate; no measured stealth percentage; no
real QUIC downgrade or CA-decryption result; and no end-to-end static-to-live
model capture has been demonstrated. The hardened ~3% boundary remains an
honest design target/diagnostic boundary, not a measured validation result.

## Baseline verification

Before this report, the Linux-native workspace suite completed in default
parallel mode with 85 tests passed and 0 failed, and the separate workspace
doc-test command completed with 18 targets reporting 0 passed and 0 failed.
After the corrected-pass fixes, the Windows workspace suite again completed
in default parallel mode with 85 tests passed and 0 failed; `cargo check
--workspace --all-targets` also completed successfully. The one transient
parallel `network-routing` assertion was green when rerun alone and green on
the subsequent full workspace run. These results establish code/build
coverage only; they do not close this live-validation phase.
