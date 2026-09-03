# Phase 3.6.5 — Static Endpoint-Yield Investigation

## Result

The real-app investigation found two separate causes:

1. Feeder had a genuine under-yield bug. Indexed intake returned only APK archive members, so the structured extractor never saw the materialized `FeederSync.smali` Retrofit annotation table. Feeder's ten declared Retrofit routes were therefore absent from the structured model.
2. Both apps also produced substantial loose-string over-harvest. Binary DEX renderings and resource/data content were being classified as domains, paths, and query keys even when they were code fragments or prose.

Tusky is different from Feeder: its final run has no Retrofit route table and only DEX-level OkHttp/`HttpURLConnection`/socket evidence. Its zero structured endpoints are therefore an honest low-static-surface/ runtime-composition result, with partial recoveries retained for dynamic handoff rather than evidence of a universal parser failure.

## Measurement evidence

All measurements below ran from the Linux-native ext4 checkout at `/home/katriel/APIaxess-tusky-linux`, with the APK fixtures under `fixtures/capstone/`. The capstone harness stopped after Stage 2 and cleaned each intake workspace.

| App / pass | Structured endpoints | Loose findings | Key observation |
| --- | ---: | ---: | --- |
| Feeder, pre-change | 1 | 41,599 | 24,931 URL candidates; 25,491 candidates came from resources; giant control-byte/binary literals were present |
| Feeder, binary-safe scan | 1 | 33,534 | Removing quote parsing from binary DEX/control-byte resources removed malformed blobs, but grammar noise remained |
| Feeder, final scoped path | 12 | 27,473 | Retrofit record: 10 endpoints; OkHttp: 1; `HttpURLConnection`: 1 |
| Tusky, pre-change reference | 0 | 7,163 | Previous capstone measurement |
| Tusky, binary-safe scan | 0 | 5,865 | Binary false positives reduced |
| Tusky, final scoped path | 0 | 2,092 | Four partial-recovery groups; no Retrofit route table in the app evidence |

Feeder's final loose breakdown was 24,928 URLs, 1,273 domains, 648 paths, 562 query keys, and 58 headers. The URL sample contains bundled feed/data and documentation links (Substack feeds, W3C/Adobe examples, GitHub, and the app's sync host), so not every loose URL is an API endpoint. The remaining domain/path/query samples include recognizable DEX/code noise; these remain loose evidence rather than being promoted to structured routes.

The decisive Feeder evidence was the final extraction record:

```text
retrofit endpoint_count=10 partial_count=0
okhttp endpoint_count=1 partial_count=23
httpurlconnection endpoint_count=1 partial_count=0
raw-sockets endpoint_count=0 partial_count=1
```

The ten routes correspond to the `FeederSync` Retrofit interface (`create`, `join`, `devices`, `feeds`, `readmark`, and related routes) in the app-package smali source.

## Changes

- Indexed corpora now combine archive members with existing typed smali/jadx views instead of returning early and discarding those views.
- In indexed mode, DEX/resources/assets remain authoritative for the global string pool; materialized resource trees and extracted DEX are not rescanned redundantly.
- Materialized smali/jadx traversal is scoped directly to the manifest package path. It no longer walks every dependency file merely to discover the target package.
- Retrofit extraction first selects documents containing actual Retrofit route annotations, avoiding broad scans of every file that merely references the Retrofit library.
- Binary DEX uses printable-string extraction rather than quote parsing over a lossy binary rendering. Resource documents containing binary control bytes are not quote-scanned.
- Loose classification now requires URI-like shapes: valid HTTP authority, URI-safe path characters, identifier-shaped query keys, DNS-like domain labels, and valid header-name tokens. Control-byte and oversized candidates are rejected before model materialization.
- Measurement output is bounded to escaped 160-character samples, and the capstone harness has an opt-in `APIAXESS_CAPSTONE_STOP_AFTER_STATIC` measurement exit.

The changes preserve provenance and confidence for retained candidates. Structured Feeder routes retain their smali evidence and declared route origin; unresolved Tusky findings remain partial/loose with their existing dynamic recommendation.

## Verification

From the ext4 checkout:

```text
cargo fmt --all -- --check                         PASS
cargo test -p apiaxess-network-routing             10 passed, 0 failed
cargo test -p apiaxess-network-extraction          5 passed, 0 failed
```

The routing suite's indexed large-archive and bounded-corpus tests passed. The extraction suite's Retrofit-equivalence, loose-shape, partial-recovery, and large-string-pool tests passed. The real Feeder and Tusky Stage-2 measurement runs both passed and cleaned their intake workspaces.

## Boundary

The final loose pool is intentionally not presented as an API map. Bundled feed/resource URLs can be useful static evidence but cannot be promoted without a request call-site or declared route. Dynamic capture remains the correct path for runtime-assembled endpoints; the static pass now reports that boundary honestly while recovering declarations that are actually present in typed source.
