# Phase 5.3 — signer integration and unified API surface

Phase 5.3 assembles the durable `UnifiedApiSurface` from an already-fused
`ApiDocument`. It performs no capture and no additional merging.

The artifact contains the complete fused `ApiSurface`, the Phase 5.2
`ConfidenceSummary`, an endpoint-centric projection retaining every endpoint
fact-confidence record, explicit API-wide or endpoint-specific signer
bindings, and actionable diagnostics. The complete endpoint is copied into
each projection, so method, path template, parameters, headers, schemas, and
authentication remain available to Phase 6 without a lossy flattened view.

Signer scope is explicit through `SignerTarget`. Every signer artifact must be
bound either API-wide or to a canonical endpoint. Endpoint projections include
both applicable API-wide signers and endpoint-specific signers. The artifact's
original `signer_mode`, confidence, credential reference, and provenance are
preserved; only `reproducible` is suitable for clean generated signing logic.
Partial hypotheses and observed-only artifacts remain review signals, while
device-oracle artifacts retain the original-runtime requirement.

Assembly validates that endpoint projections exactly preserve the fused model,
that every confidence record is retained and attributed, that every signer is
attached, and that authentication fact links point into the Phase 5.2 summary.
The result round-trips through the versioned `ApiDocument` envelope and is
returned as both a standalone Phase 6 input and a document with the unified
surface attached.
