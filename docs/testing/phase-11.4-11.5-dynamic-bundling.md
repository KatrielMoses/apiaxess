# Phase 11.4 + 11.5 — dynamic-path bundling (Frida + Android emulator)

Date: 2026-08-29

Closes Phase 11's dynamic tier: embed Frida as a linked library (no host Python)
and bundle a QEMU + owned Android-10 AOSP image as the optional zero-config
dynamic runtime, with honest capability detection and a graceful software-mode
fallback. Per the phase brief, this session **writes it all up** — code, bundling
tooling, manifests, SBOM/licensing, and layout for Phase 12 — and **defers the
live droplet e2e** (emulator boot → APK → Frida → capture) to the dedicated
no-KVM droplet run.

## 11.4 — Frida embedded as a linked library

- **`frida` crate (frida-rust) 0.17.2**, optional + behind the `frida-embedded`
  cargo feature on `apiaxess-sandbox`, links `frida-core` (17.x devkit). Off by
  default so the standard build needs no devkit; Phase-12 packaging enables it.
- New module `crates/sandbox/src/frida_embedded.rs` (`FridaCoreInstrumentation`)
  drives spawn/attach/script-load through the bindings, replacing the host
  Python/CLI path in `instrumentation.rs`. The device-side `frida-server` is
  retained (baked into / pushed to the owned image).
- Bundling: `packaging/assets/frida.toml` pins host devkits (per platform) and
  `frida-server` (per Android ABI) with real SHA-256s; `fetch-frida.ps1` acquires
  and verifies them; `frida-NOTICES.md` records the wxWindows 3.1 static-link
  posture. Host frida-core, the `frida` crate, and device frida-server are
  version-locked.
- License: wxWindows Licence 3.1 — LGPL-2.1 + static-link exception; unmodified
  upstream, notice shipped, source access not obstructed.

## 11.5 — bundled Android emulator (owned, optional payload)

- **New tier `SandboxTier::BundledEmulator`** — the zero-config default dynamic
  runtime. `BundledEmulatorBackend` (`crates/sandbox/src/lib.rs`) launches the
  bundled SDK emulator engine + owned Android-10 AOSP image directly (no Docker),
  resolving the runtime by absolute path (`analysis-runtime/`, or
  `APIAXESS_ANALYSIS_RUNTIME`).
- **Capability detection + honest fallback (the primary verifiable target).**
  `AccelerationMode::detect` maps host virtualization evidence (KVM on Linux,
  WHPX/Hyper-V/AEHD on Windows, WSL2 nested KVM) → `Accelerated` or `Software`,
  and emits the honest diagnostic. The planner makes the bundled emulator the
  default **everywhere** and, when no virtualization is present, keeps it
  **local in software mode** (`sandbox.software-mode-active`, Warning) rather
  than silently routing to remote-offload. New diagnostics:
  `sandbox.accelerated-mode-active`, `sandbox.software-mode-active`,
  `sandbox.analysis-runtime-missing`.
- **Separate optional payload.** The runtime is the ~2 GB `analysis-runtime/`
  payload — not in the base installer, separately versioned, with its own SBOM,
  provenance, and notices. `analysis-runtime.toml` + `fetch-analysis-runtime.ps1`
  assemble it via `sdkmanager` from the pure-AOSP `default` (no GMS) API-29
  image, create the owned `apiaxess-android-10` AVD, and stage the device
  frida-server. `sandbox.analysis-runtime-missing` prompts a download when a
  dynamic run is requested without it.
- **Advanced-image path.** `fetch-analysis-runtime.ps1 -SystemImage
  "system-images;android-<N>;default;x86_64"` (or an Android-x86 image) lets a
  user acquire a different public image for their own use; the owned Android-10
  `default` image is the verified default.
- **Licensing/provenance (item 10, its own inventory).** AOSP userspace
  Apache-2.0, Linux kernel GPL-2.0, QEMU GPL-2.0 (shipped unmodified), no
  GMS/Play — all redistributable. See `analysis-runtime-NOTICES.md`.

## Verified in this session (no droplet needed)

- **Capability detection + graceful software-mode fallback + honest messaging** —
  unit-verified: `crates/sandbox/src/lib.rs` planner tests
  (`no_virtualization_falls_back_to_local_software_mode_not_remote`,
  `inside_vm_and_windows_arm_still_offer_the_bundled_emulator_in_software_mode`,
  and the accelerated/AEHD cases) assert the tier default, the resolved
  `AccelerationMode`, the honest `sandbox.software-mode-active` diagnostic, and
  that no-virt stays local. All 27 sandbox lib tests pass.
- Diagnostics conformance (the three new definitions) passes.
- The default workspace build compiles with the optional `frida` dependency
  resolved but unbuilt; the sandbox crate is clippy-clean and rustfmt-clean.

## Deferred to the no-KVM droplet run (live e2e)

The full software-mode dynamic proof — bundled emulator boots the owned image,
a real APK installs/runs, traffic is captured through the proxy into the model,
Frida attaches and the pinning/signing hooks fire, dynamic facts feed fusion —
runs on the fresh Ubuntu droplet (software mode, slow-but-correct). The
accelerated-performance verification is the later Proxmox nested-virt test.
The boot-time image provisioning (CA install, agent, baseline snapshot) is part
of that run.

> **Phase 12.1 update (2026-08-29):** the two wiring gaps this section flagged
> are now closed at the build/API level (see
> `phase-12.1-engine-dynamic-wiring.md`). The engine's `run_pipeline` selects and
> invokes the bundled emulator backend through the new `DynamicBackendFactory`
> (capability-aware, with the honest software-mode fallback), and the
> `frida-embedded` feature now **compiles and links** against the real pinned
> 17.17.0 devkit (frida-rust 0.17.2 API drift fixed). The live emulator-boot →
> APK → Frida-attach → capture end-to-end run remains the deferred droplet stage.

## Out of scope

Accelerated-performance verification (Proxmox nested-virt); the native
installers (Phase 12 packages the `analysis-runtime/` + `frida/` layout produced
here); the advanced path's every-possible-image (the mechanism is built; the
Android-10 default is the verified one).
