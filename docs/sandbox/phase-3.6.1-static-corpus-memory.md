# Phase 3.6.1 — bounded static corpus scanning

Phase 3.6.1 removes corpus-wide decompiled-text retention from Phase 1.2 and
Phase 1.3.

`SignatureCorpus` now retains only normalized file metadata (`path` and
`source_kind`). Routing scans each member through a reusable 64 KiB byte
buffer, preserving the former case-insensitive line/marker hit order and line
hints. Extraction loads only the current evidence document, then releases it
before the next member. A single document is capped at 16 MiB for the existing
whole-document method/block parsers; exceeding that limit produces the
structured `networking.artifact-location-unavailable` diagnostic instead of
unbounded allocation.

The protection detector now follows the same metadata-only discipline. Its
feature counters and built-in marker signatures stream one document at a time;
marker results share one pass, and manifest-gap evaluation does not reread the
whole corpus once per manifest name. Routing marker hits are cached as bounded
evidence vectors so detector-specific searches do not amplify filesystem I/O.

The bounded path is the default for all artifact sizes; there is no large-app
mode or threshold switch. The corpus exposes metadata-retention accounting for
regression tests, not as a production memory oracle.

## Regression evidence

- `streaming_hits_match_the_previous_whole_file_reference` compares streamed
  hits against the previous `fs::read` + lossy UTF-8 + `str::lines` behavior,
  including marker ordering, line hints, and a marker crossing the 64 KiB
  scanner chunk boundary.
- `large_corpus_scans_with_bounded_retained_memory` scans 4,096 synthetic
  members of 128 KiB each (512 MiB of normalized input). It finds the expected
  marker and asserts retained corpus metadata remains below 2 MiB.
- `oversized_extraction_document_is_a_legible_diagnostic` locks the per-file
  resource boundary and diagnostic identity.

The live Play Room capstone remains a separate rerun after a non-colliding
fixture is available; this phase changes only corpus materialization and does
not claim dynamic-tier validation.
