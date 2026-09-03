# Phase 8.3.1 — Static pipeline performance

## Measure-first finding

The Feeder 2.22.0 APK was used as the pathological probe:
`fixtures/capstone/feeder-2.22.0-4050.apk`.

The completed ext4 baseline was 377.4 seconds. Its static extraction timing
was string-pool scan 2.8 seconds, protocol extractors 49.1 seconds, loose
collection/coalescing 0.2 seconds, model finalization 0.4 seconds, and static
normalization 0.9 seconds. The earlier 40-minute Windows failure was therefore
not the known loose-finding coalescing hotspot.

The new Windows-first profile measured the intake boundary at 81.3 seconds:
external tools took 54.1 seconds and protection detection took 27.0 seconds.
The tool outputs contained 18,250 apktool files (207 MiB) and 14,316 jadx
files (115 MiB). Routing built 8,818 searchable documents. Before the fix,
routing reopened the corpus for each detector marker group; the one-pass
profile still took 279.3 seconds because the scanner compared every byte with
64 markers and maintained a sliding tail with per-byte drains.

## Fix

- Detector marker sets are exposed as priming hints and all built-in/generic
  markers are scanned in one corpus pass.
- The scanner uses a bounded 16 MiB document buffer and an Aho–Corasick
  multi-pattern matcher, with overlapping matches enabled so marker sets such
  as `retrofit` and `retrofit2/` retain their prior evidence.
- Profile output reports intake/tool materialization, protection stages,
  routing stages, marker-scan progress, extraction stages, and normalization.
  Long runs now identify the active stage and document progress.

## Windows verification

The assembled Windows Feeder static run completed in 248.36 seconds:

| Stage | Time |
| --- | ---: |
| Intake and protection | 81.3 s |
| Routing marker prime | 129.9 s |
| String-pool scan | 2.9 s |
| Protocol extraction | 24.3 s |
| Normalization | 0.7 s |

The result remained equivalent: 12 structured endpoints, 27,473 loose
findings, 26 dynamic handoffs, 27,527 diagnostics, and `Tier1StockR8`.

## Regression coverage

`indexed_large_archive_scans_without_exploding_members` now primes a
multi-marker corpus containing 44,202 archive members and asserts completion
within the 90-second bounded envelope, while retaining the existing hit and
metadata assertions. The measured Windows run was 39.5 seconds.

Focused routing, extraction, protection, and assembled static tests pass.
