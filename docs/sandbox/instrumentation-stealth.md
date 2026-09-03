# Phase 3.4 instrumentation substrate and stealth

`crates/sandbox/src/instrumentation.rs` is the reusable Frida substrate for
Phase 3.3 and Phase 4. It owns server deployment, spawn-gated versus attach
mode, early `Application.onCreate` and native crypto-initialization markers,
class-loader/DEX readiness, host IPC checks, crash/logcat correlation, payload
loading, and a session watchdog.

`crates/sandbox/src/stealth.rs` is intentionally independent infrastructure.
It carries versioned bundle metadata and provenance for root hiding,
integrity/attestation fixes, Frida concealment, and emulator-fingerprint
mitigation. Components are described as session artifacts with explicit
activation and cleanup commands. The plan reports the standard 9,700-basis-
point coverage target, but blocks automation and emits a boundary diagnostic
for hardened RASP, hardware attestation, or custom anti-Frida signals.

The substrate and stealth layers attach cleanup to the existing sandbox lease.
Frida processes, runtime artifacts, stealth helpers, and host workspaces are
therefore ephemeral and removed on normal teardown, explicit teardown, or
lease drop. No signing-recovery hooks are included here; Phase 4 consumes the
substrate handle.

Real stability, stealth effectiveness, watchdog crash correlation, and hardened
target behavior remain live-validation items for Phase 3.6.
