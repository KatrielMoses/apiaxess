# Phase 3.5 dynamic capture

`apiaxess-dynamic-capture` consumes the durable Phase-2 `TrafficStore` and
commits observed HTTP behavior into the same `ApiDocument` used by the static
pass.

The extractor matches method plus path against existing templates first. If no
static identity matches, ID-shaped path segments are collapsed into an
`{id}`-style inferred template and retained as dynamically inferred. Request
and response JSON samples become provenance-linked `SchemaObservation` values;
object properties use observed presence tallies, so requiredness remains
inconclusive until the caller's configured sample threshold is met. Types are
retained as widened candidates, with no Phase-5 fusion or conflict deletion.

Dynamic candidates are appended to existing facts. Static candidates and
unexercised endpoints are never removed. Observed authentication selects the
dynamic candidate as required by the model policy. Query/header/path metadata,
status selectors, and observable pagination conventions (`page`, `limit`,
`offset`, cursor names, and `Link`) are represented in the canonical model.

Each run adds a dynamic agent/activity and flow/sample entities to the
provenance registry. `ApiDocument.dynamic_capture` records flow counts,
observed versus static-only identities, resolved/open static handoffs, the
sample threshold, and all recoverable diagnostics. A real APK run through the
3.1–3.4 substrate remains required to validate live capture fidelity; this
phase does not claim live validation or fusion.
