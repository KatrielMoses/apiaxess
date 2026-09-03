# Phase 8.7 — Loose-finding volume reduction

## Measure-first characterization

The persisted Windows Feeder run was used as the probe before changing
extraction. It contained 27,473 unbound candidates and 12 structured
endpoints:

| Candidate kind | Count |
| --- | ---: |
| URL | 24,928 |
| Domain | 1,273 |
| Path | 648 |
| Query key | 562 |
| Header | 56 |
| Base URL | 6 |

The source-location breakdown identified the pathological volume rather than
a fusion or endpoint-promotion problem:

| Source category | Count | Main observation |
| --- | ---: | --- |
| Packaged resource data | 25,079 | One `res/bz.json` catalog supplied feed/article data. |
| Binary support data | 778 | `resources.arsc`, ICU tables, and binary support members supplied printable fragments. |
| Packaged metadata | 56 | `META-INF`, Kotlin metadata, and version records supplied build/version strings. |
| Code/DEX/ambiguous sources | 1,560 | Retained as evidence because these locations may carry real API signals. |

The same classification replayed against the persisted PlayRoom run found 470
metadata/resource/binary candidates and 3,826 retained candidates out of the
original 4,296.

## Source-level fix

`crates/network-extraction/src/lib.rs` now classifies only unambiguous packaged
noise before allocating canonical loose-finding facts:

- `res/*.json`, `*.csv`, and `*.tsv` are classified as packaged resource data;
- archive metadata, Kotlin/version records, native libraries, and binary/ICU
  tables are classified as support noise;
- DEX, code, JavaScript, HTML, and ordinary XML/resource candidates remain
  loose evidence.

The filter does not alter endpoint extraction, promotion, candidate values, or
provenance for retained findings. It emits one durable
`extraction.loose-findings-filtered` diagnostic containing the filtered count,
reason counts, retained count, and bounded value/path examples, so a
classification is reviewable rather than silently discarded.

## Windows real-app verification

The gated real probes run the existing Windows-normalized corpora through the
real router and extractor:

| App | Endpoints | Before | After | Filtered | Filter timing |
| --- | ---: | ---: | ---: | ---: | ---: |
| Feeder | 12 | 27,473 | 1,560 | 25,913 | 34 ms |
| PlayRoom | 4 | 4,296 | 3,826 | 470 | 5 ms |

Feeder's structured endpoint result remained exactly 12. PlayRoom's remained
exactly 4. The Feeder filtered diagnostic reported
`binary-support-data=778`, `packaged-metadata=56`, and
`packaged-resource-data=25079`, with 1,563 candidates retained before the
existing final coalescing pass produced 1,560 findings.

The existing downstream Windows profile was also rerun against the larger,
pre-reduction 27,473-finding Feeder session: fusion 7.9 s, confidence 8.0 s,
and surface assembly 14.6 s. The post-filter document is 94% smaller while
preserving the same endpoint facts, so downstream processing remains within
that already-bounded envelope; the reduced static result is the one persisted
by a new analysis run.

## Regression coverage

- `packaged_noise_is_filtered_with_auditable_reason_and_code_signal_retained`
  verifies classification, diagnostic context, and retention of a code signal.
- `packaged_catalogue_volume_does_not_become_loose_finding_volume` feeds 5,000
  packaged URLs and asserts one retained code finding and sub-two-second
  filtering.
- The gated real probes are
  `real_feeder_probe_preserves_endpoints_and_reduces_packaged_noise` and
  `real_playroom_probe_keeps_signal_while_reducing_packaged_metadata`; run
  them with `APIAXESS_PHASE_8_7_REAL=1` when the existing normalized workspaces
  are present.

Validation completed on Windows with `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings`.
