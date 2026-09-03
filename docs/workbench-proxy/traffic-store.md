# Durable traffic store

Phase 2.3 uses two layers with a deliberate authority boundary:

- SQLite in WAL mode with `synchronous=FULL` is the session runtime cache. Flow
  metadata is stored in structured rows and request/response bodies are stored
  once under their SHA-256 hash in the session blob directory.
- Repeater contexts and their append-only revisions use a dedicated SQLite
  table and the same content-addressed body directory.
- Intruder jobs, bounded results, and their attack configurations use a
  dedicated SQLite table and the same content-addressed body directory.
- The JSON session document is the only canonical portable artifact. Its
  `workbench.traffic` slot contains a normalized snapshot with headers,
  metadata, scope classification, provenance, body SHA-256 values, and portable
  base64 body content. The SQLite file is never the user-facing backbone.
  The same slot includes repeater current edits, revision histories, and
  intruder jobs/results.

`TrafficStore::serialize_session` commits the normalized snapshot through
`Session::set_workbench_state` and then uses the invariant-checked
`SessionDocument` serializer. `resume_from_session` treats that JSON payload as
authoritative and rebuilds a fresh SQLite/blob runtime. SQLite is therefore a
rebuildable cache, not a second source of truth.

For same-host crash recovery, the assembled product retains a non-empty newer
SQLite runtime instead of overwriting it with the older portable snapshot. A
compact versioned session-metadata checkpoint restores scope, audit, sandbox,
and pipeline state between full portable saves; the portable workbench snapshot
still hydrates a new or empty store. See
[incremental session checkpointing](../architecture/session-checkpointing.md).

The local API exposes HAR only as an interchange adapter:

- `GET /api/v1/workbench/har` exports stored flows.
- `POST /api/v1/workbench/har` imports a HAR log with explicit
  `har.import` provenance.

Storage open, integrity, write, canonical commit, resume, and HAR failures use
stable diagnostics. A referenced blob is hash-verified on read; a missing or
modified blob is reported as store corruption instead of being returned as an
empty body.
