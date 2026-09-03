# Phase 3.6.4 — Static extraction performance evidence

## Measurement

The first measurement was run from the Linux-native WSL2 checkout at
`/home/katriel/APIaxess-tusky-linux` with Feeder 2.22.0. The profiler was
enabled with `APIAXESS_PROFILE_STATIC=1` and did not change extraction logic.

The pre-fix run identified two quadratic costs:

| Subphase | Pre-fix result |
| --- | ---: |
| String-pool scan | 17,988 ms; 5,678 documents, 42,690 classified literals, 41,600 candidates |
| Protocol extractors | 8,850 ms combined |
| Loose-finding materialization | 132 ms |
| Loose-finding coalescing | 94,897 ms for 41,599 findings |
| Model validation | Did not return within the bounded observation window |

## Fix

`ModelBuilder` now indexes `(LooseFindingKind, value)` while collecting
string candidates and coalesces findings through a `BTreeMap`, preserving the
first evidence path and the existing merge behavior. Provenance validation
now reuses one graph index and performs one shared graph traversal; fact
validation checks entity references after the graph has been validated rather
than rebuilding the graph index for every finding.

## Post-fix Feeder result on ext4

The completed ext4 run reached:

```text
STAGE 2 PASS: endpoints=1, loose_findings=41599, handoffs=6,
static_diagnostics=41611, protection_tier=Some(Tier1StockR8)
```

The instrumented extraction timing was:

| Subphase | Post-fix result |
| --- | ---: |
| Corpus metadata | 3 ms |
| String-pool scan | 4,355 ms |
| Protocol extractors | 8,418 ms combined |
| Loose-finding materialization | 135 ms |
| Loose-finding coalescing | 123 ms |
| Extraction finalization/model validation | 44,449 ms |
| Static-pass normalization | 90,876 ms |

The output counts and static diagnostics remained consistent with the
pre-fix Feeder result. The run was stopped after Stage 2 so it did not start
another emulator capstone.

After this completed measurement, one further refinement replaced the
remaining per-finding provenance lookup with a shared entity-ID index. Its
focused tests and the full workspace suite pass. A refresh real-app run was
interrupted during intake when WSL became unresponsive, before producing any
new static result; the timings above are therefore reported conservatively
from the completed run immediately before that refinement.

## Regression coverage

`large_string_pool_stays_bounded_during_coalescing_and_validation` creates
20,000 unique URL literals and asserts that extraction produces 20,000 loose
findings, coalescing remains below the bounded timing envelope, and final
model validation remains below its envelope. The focused test passed in
15.26 seconds.

The test preserves the existing small-fixture output tests, which cover
endpoint, operation, partial-recovery, provenance, and model validity
equivalence.
