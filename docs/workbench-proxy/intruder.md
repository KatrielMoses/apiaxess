# Intruder

Phase 2.5 provides bounded, session-scoped payload iteration over a captured
request. Positions may be marked in the URL, a named header value, or a UTF-8
body. Sniper, clusterbomb, and pitchfork expansion is represented explicitly
in the persisted `IntruderConfig`.

The execution tier is selected when a job is created:

- Stateless jobs use the hidden `ffuf` process through `external-tools`. The
  invocation is noninteractive, proxied through the active workbench listener,
  version-checked, time-bounded, and parsed from ffuf JSON output.
- Jobs with an authentication pre-flight or multi-step token sequence use the
  native Rust sender. It performs each request through the same routed proxy
  path as repeater sends, extracts JSON-path, header, or regex tokens, and
  injects them into later steps.

Every result records the exact substituted request, response metadata when
available, status/size/content matching, response differences, scope
classification, and any diagnostic. Jobs are bounded by `maxResults`, with
rate and concurrency controls in the configuration. Out-of-scope work is
warned and recorded under the session's honor-system scope policy.

The host session can append each completed result to the canonical audit trail
through `IntruderWorkbench::record_result_in_session`; the record carries the
network target, completion/failure outcome, and the same structured
diagnostics retained on the result.

Jobs and results are stored in SQLite for the active session and included in
the canonical `workbench.traffic` JSON snapshot. Request and response bodies
use the store's SHA-256 blob directory, so repeated payload iterations are
deduplicated and a resumed session can reconstruct the same job state.

The local API exposes:

- `POST /api/v1/workbench/intruder` to create a job from an `IntruderConfig`.
- `GET /api/v1/workbench/intruder` and
  `GET /api/v1/workbench/intruder/<id>` to inspect jobs and results.
- `POST /api/v1/workbench/intruder/<id>/start` to launch work.
- `POST /api/v1/workbench/intruder/<id>/pause`, `/resume`, and `/stop` for
  lifecycle control.

Missing ffuf, malformed positions, transport or sequence failures, cancelled
jobs, persistence failures, and outside-scope sends use stable diagnostics in
the catalogue. RESTler, Schemathesis, fuzzing automation beyond explicit
payload sets, and AI reasoning remain outside this phase.
