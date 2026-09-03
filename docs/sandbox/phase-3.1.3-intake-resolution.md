# Phase 3.1.3 — Intake resolution brain

Phase 3.1.3 adds the resolve-or-diagnose boundary between normalized Android
intake and sandbox installation. It is deterministic code-based reasoning; it
does not use an AI model or fetch missing package members from the network.

## Recognition and resolution

APK target intake now classifies archive bytes before using the filename as a
hint. It distinguishes standalone/universal APKs, AABs, bundletool APKS,
APKMirror APKM, XAPK, and bare ZIP split sets. A renamed `.apk` containing a
split archive is routed as a split archive, and a renamed ZIP containing an APK
and XAPK metadata is routed as XAPK.

The sandbox `IntakeResolutionBrain` consumes the normalized artifact and picks
an extensible sibling strategy:

- one APK uses the direct single-APK install operation;
- two or more APKs use `install-multiple` as one complete split set;
- new artifact-to-install plans can be added through
  `IntakeResolutionStrategy` without changing the sandbox control interface.

`SandboxLease::resolve_and_install` is the integration point for callers. A
successful result includes the recognized format, strategy, installed APK IDs,
and a human-readable summary such as “detected apkm, installed 3 APK splits”.

## Installer signal reasoning

Nonzero installer results are reduced to stable signals and passed through
sibling `InstallerErrorStrategy` implementations. The built-in mappings cover
missing splits, ABI mismatch, Android API mismatch, signature/verification
failures, insufficient storage, and a generic translated installer failure.
Missing-split handling is honest: a lone base APK produces a precise request for
the full split set or universal APK; a supplied multi-APK set produces a
different incomplete-set diagnostic rather than being misreported as base-only.

No raw `INSTALL_FAILED_*` string is surfaced as the user-facing explanation.
Unrecognized or corrupt input remains an explicit artifact diagnostic, and
missing splits are never sourced automatically from external networks.

The real-artifact capstone remains live-untested for the later Phase 3.6 rerun:
the code path is covered by deterministic fixture tests, while an actual APKM
multi-install and base-only emulator failure still require a live rooted
HQarroum lease.
