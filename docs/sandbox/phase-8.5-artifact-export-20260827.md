# Phase 8.5 — Artifact export

## Product path

Completed session analyses can now be exported with:

    apiaxess export <session.json> --format openapi|sdk|postman|har|all --out <dir>

The local API exposes the same operation at POST /api/v1/export. The request
accepts outputDir and either format or formats; omitted formats mean all.
Export requires a completed UnifiedApiSurface, writes the selected files below
the requested directory, and records artifact.export in the canonical session
audit trail.

## Bloat boundary

The primary artifacts do not inline Feeder's 27,473 loose findings or 27,597
diagnostics. openapi.json carries compact counts and an
apiaxess-evidence.json sidecar reference under the x-apiaxess-* extensions. The
sidecar retains the full provenance, facts, loose findings, handoffs, signers,
coverage, and diagnostics for audit/review use.

The export service uses the Phase 6 OpenAPI, Python SDK, and Postman emitters
directly. HAR uses the durable captured-traffic store when flows exist and
falls back to the Phase 6 HAR emitter when the session has no captured flows,
preserving its explicit no-capture warning.

## Windows Feeder verification

Export was driven through the product CLI from the completed Windows Feeder
session:

    openapi.json: 123,960 bytes
    python SDK: 13,872 bytes
    postman.collection.json: 17,967 bytes
    traffic.har.json: 132 bytes
    apiaxess-evidence.json: approximately 81.5 MiB

Validation results:

- swagger-cli validate openapi.json: valid;
- Python package installed with pip and imported apiaxess_client.ApiClient;
- Postman collection parsed as Collection v2.1 JSON;
- HAR parsed as HAR 1.2 JSON;
- secret scan over primary artifacts: clean.

The export emitted honest warnings for incomplete response evidence, low
confidence schemas, missing recovered authentication, and no captured HAR
traffic. No secrets or invented signer implementations were added.

## Regression coverage

- ExportConfig expands all and rejects unsupported format names;
- engine-shell owns the session export, output writes, sidecar, and audit
  record;
- local API exposes structured export errors for missing surfaces, invalid
  requests, emitter failures, and write failures;
- the existing emitter test suites remain green.
