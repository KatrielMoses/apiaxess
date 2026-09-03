# APK target

This crate is the first implementation of the TargetType seam from
apiaxess-artifact-intake. It handles APK, AAB, and APKS intake only; jadx,
apktool, and bundletool are external adapters invoked through
crates/external-tools. Protection detection is performed in-house from the
normalized artifact and is not delegated to an external scanner.

The public handoff is NormalizedUnpackedArtifact. Later Phase 1 sub-phases
consume that representation rather than rerunning unpacking or reading raw
tool output. A future web, executable, or Debian target is a sibling crate that
implements the same target seam.

Licensing: apktool, jadx, and bundletool are only invoked as separately
installed tools. The protection detector is clean-room, Apache-2.0-compatible,
and gated by the audited provenance ledger in `docs/protection`. MobSF is
intentionally not used.
