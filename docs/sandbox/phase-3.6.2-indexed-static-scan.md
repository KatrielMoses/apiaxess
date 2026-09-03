# Phase 3.6.2 — Indexed In-Place Static Scan

Phase 3.6.2 moves the static corpus handoff from an exploded-file-tree
assumption to an indexed APK-member path.

## Implementation

- `apiaxess-artifact-intake` records a `StaticArchiveIndex` for each resolved
  installable APK by reading only its ZIP central directory. Member contents
  remain in the APK; the index retains names and uncompressed sizes only.
- `ApkTarget::intake` builds those indexes before static detection and records
  their provenance as `StaticArchiveIndex`.
- `SignatureCorpus` prefers indexed archives whenever they are present. Each
  member is a virtual document (`archive.apk!/classes.dex`), and archive-wide
  marker and string-pool passes open each archive once. The file-tree corpus is
  retained as a compatibility fallback for older handoffs without indexes.
- The protection detector uses the same virtual-member path and performs its
  marker, feature-vector, and manifest-gap passes archive-by-archive, retaining
  only one bounded member at a time.
- Archive members over the existing 16 MiB bounded document window, corrupt
  ZIP reads, missing members, and unreadable files become retained diagnostics;
  they are not silently skipped or materialized without a limit.
- `ApkTarget::cleanup` removes an intake workspace only when it is a direct
  child of the configured intake output root, then verifies that it is gone.

## Regression evidence

`network-routing` includes:

- a 44,202-member indexed archive regression; it scans successfully without an
  exploded `smali` directory and keeps corpus metadata bounded to the index;
- an indexed-text/file-tree detection-equivalence test for the same smali
  content; and
- the existing large file-tree and oversized-document boundary tests.

The indexed path is now the default for target-produced artifacts. The legacy
tree path remains only for synthetic/older normalized artifacts that do not
carry an index.
