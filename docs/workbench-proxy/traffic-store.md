# Durable traffic store

Phase 2.3 uses two layers with a deliberate authority boundary:

- SQLite in WAL mode with `synchronous=FULL` is the session runtime cache. Flow
  metadata is stored in structured rows and request/response bodies are stored
  once under their SHA-256 hash in the session blob directory.
- Resend contexts and their append-only revisions use a dedicated SQLite
  table and the same content-addressed body directory.
- Fuzzer jobs, bounded results, and their attack configurations use a
  dedicated SQLite table and the same content-addressed body directory.
- The JSON session document is the only canonical portable artifact. Its
  `workbench.traffic` slot contains a normalized snapshot with headers,
  metadata, scope classification, provenance, body SHA-256 values, and portable
  base64 body content. The SQLite file is never the user-facing backbone.
  The same slot includes resend current edits, revision histories, and
  fuzzer jobs/results.

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

- `GET /api/v1/workbench/har` exports the captured flows as HAR 1.2: every
  entry keeps its recorded URL (scheme and port included) and carries every
  field the format requires. Sizes the capture did not measure are `-1`, the
  single recorded duration is `timings.wait`, and entries note what HAR cannot
  hold (an event stream's events, a WebSocket's messages). Resend/Fuzz traffic
  and CONNECT tunnels are not exported: re-imported as captures they would
  fuse into endpoints nobody observed.
- `POST /api/v1/workbench/har` imports a HAR log (up to 512 MiB) with explicit
  `har.import` provenance and returns `{ imported, inScope, outsideScope,
  derivedScope? }`. `outsideScope` counts, by host, the imported flows that
  are outside the declared scope and so will not fuse; the GUI says so instead
  of reporting bare success. A failed import names its reason:
  `proxy.har-import-too-large` (413), `proxy.har-import-unreadable`, or
  `proxy.har-import-malformed` (422, with the parse error). Entries saved
  without bodies (as browsers often do) import without them. When the
  session has no declared scope, one is derived first from the HAR's own
  hosts (exact-host rules for the first-party hosts, or every HAR host when
  none dominates), audited as `session.scope.derive-from-har`, so the
  imported traffic is in scope and fuses. `derivedScope` lists the hosts put
  in scope and the ones left out; the GUI shows both and lets the operator
  narrow or widen the scope.
- `GET /api/v1/workbench/flows/{id}/sse-events?after=&limit=` pages the
  Server-Sent Events captured on a `text/event-stream` flow (stored in
  `sse_events`, redacted like bodies). The flow summary's `sse` field carries
  `{ eventCount, closed }`.

Storage open, integrity, write, canonical commit, resume, and HAR failures use
stable diagnostics. A referenced blob is hash-verified on read; a missing or
modified blob is reported as store corruption instead of being returned as an
empty body.
