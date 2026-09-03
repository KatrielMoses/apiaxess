# Phase 3.6 capstone — APKM execution report

**Run date:** 2026-08-19  
**Artifact:** `fixtures/capstone/play-store.apkm` (copied from the user-supplied `target` artifact for stability)  
**Artifact SHA-256:** `C887883291FDAB8722014CE506E5A20D2CC153FB78391D62F0D3CE524298525B`  
**Environment:** Windows 11 / WSL2-backed Docker Desktop, HQarroum API 33 image digest `sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`

## Verdict

The capstone did not close the full dynamic-tier claim. The substrate passed
the live boot, KVM, root, writable-system, and CA-write checks. APKM intake was
fixed during the run and successfully normalized 29 APK members. Installation
was then blocked by the emulator image's preinstalled `com.android.vending`
package, whose `/product/app/LicenseChecker` identity has a different signing
key. Static model generation did not complete because the current corpus
materializer grew to approximately 1.1 GB while scanning the 44,202-class base
and was stopped before memory pressure became unsafe. No traffic, pinning, or
dynamic-model success is claimed.

## Stage evidence

| Stage | Result | Evidence |
|---|---|---|
| 1. Intake and resolution | **Pass after fixes** | Content-based APKM recognition reached normalized intake; the stable output contained `base.apk` plus 28 split members. The archive includes ABI and language splits. |
| 2. Static discovery | **Finding / incomplete** | `jadx 1.5.5` was installed and produced source output but returned exit 1 with `ERROR - finished with errors, count: 110`; intake now retains that as a warning when output exists. The subsequent routing/extraction corpus scan did not finish before reaching ~1.1 GB resident memory, so no API map, library list, protection roll-up, or handoff summary is claimed. |
| 3. Sandbox install | **Finding** | HQarroum booted and the 29-member `install-multiple` attempt reached Android. It failed with `INSTALL_FAILED_UPDATE_INCOMPATIBLE` because the image already owns `com.android.vending` with a different signature. `pm uninstall --user 0` and moving `/product/app/LicenseChecker` aside in the writable overlay did not remove the package identity. |
| 4. Routing and CA trust | **Partial substrate only** | `EXTRA_FLAGS=-writable-system`, reboot, and second remount succeeded. A marker write to `/system/etc/security/cacerts/` succeeded. No app traffic was available because installation/launch did not succeed; L3 redirect, QUIC downgrade, and decryptability were not run. |
| 5. Pinning bypass | **Not run** | No installable/launchable app process reached Frida or a bypass lane. |
| 6. Dynamic capture/model | **Not run** | No real flow reached the workbench store, so no schema, template match, handoff resolution, or scope-gate event can be claimed. |
| 7. Teardown | **Pass for this clean path** | The disposable container was removed, ADB disconnected, generated host ADB keys deleted, and `adb devices` was empty. An unclean kill-mid-session run was not performed after the install blocker. |

## Fixes made during the run

- Split APK validation now accepts native-library-only and resource-only
  members rather than requiring every split to contain DEX/resources.
- Partial `jadx` output is retained as an explicit warning when the source
  tree exists; empty-output failures remain blocking. The diagnostic now
  includes stdout when stderr is empty.
- Resource and asset roots are materialized as empty normalized directories
  for legitimate native-only splits; empty `smali_roots` remains honest.
- Added a regression test for a native-only installable split member.

## Required follow-up

1. Use an Android image without the conflicting Play Store system package, or
   supply a fixture whose package/signature does not collide with the image.
2. Optimize `SignatureCorpus::from_artifact` for very large APKs so static
   routing does not retain every decompiled file in memory at once. This is a
   separate 3.6.x performance item.
3. Rerun stages 2–7 with an installable app before claiming end-to-end dynamic
   facts. The native-Linux Hermes breadth, Flutter/Xamarin/hardened targets,
   remote offload, and unclean teardown remain environment-gated.
