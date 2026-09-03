# APIaxess Phase 5.2: Confidence Recomputation and Handoff Resolution

Phase 5.2 is the scoring and feedback pass over the Phase 5.1 fused model. It
does not merge facts and it does not treat dynamic silence as evidence. The
`apiaxess-confidence` crate consumes a validated `ApiDocument`, recomputes
confidence from the retained candidates, merge records, and provenance leaves,
then attaches an auditable `ConfidenceSummary`.

## Recomputable confidence

Every scored fact retains:

- the selected candidate and model path;
- static and dynamic leaf sample counts and source categories;
- the exact leaf entity IDs used by the computation;
- source-agreement state;
- counts of agreement, refinement, gap-fill, and true-conflict merge records;
- the scalar score, checked against `FactConfidence::recompute_score()` during
  model validation.

The bounded policy is intentionally transparent:

1. sample strength is `samples / (samples + 4)`;
2. source support contributes more when static and dynamic agree or a dynamic
   refinement is retained;
3. gap-fill uses only the asserting source, so silence does not inflate it;
4. true conflict lowers the case strength and applies a conflict penalty even
   when both sources have spoken.

The formula is a provisional, deterministic policy rather than a claim of
probability calibration. It is regenerated whenever the evidence changes.

## Handoff closure

Each `StaticPassSummary.dynamic_handoffs` marker becomes a
`HandoffResolution`. A marker is resolved only when:

- its location matches a canonical endpoint identity; and
- that endpoint has dynamic leaf evidence in the fused facts.

Otherwise it remains open. In particular, a capture run with no observations
cannot resolve a marker. Matching endpoint identities and dynamic evidence IDs
are retained for audit and presentation.

The existing `DynamicCaptureSummary` handoff lists are refreshed when a dynamic
summary is present, while the full resolution records live in the Phase 5.2
confidence summary.

## Coverage

`CoveragePicture` partitions the endpoint surface into:

- confirmed: both static and dynamic evidence;
- inferred: dynamic evidence without static evidence;
- static-only: static evidence without dynamic evidence.

It also reports dynamic-ground-truth count, basis-point proportions, resolved
and open handoffs, low-confidence fact count, and true-conflict fact count.
This is an honest coverage signal, not an endpoint confidence score.

## Diagnostics and tests

The scorer emits structured diagnostics for resolved handoffs, open handoffs,
low-confidence facts, and unresolved source conflicts. Invalid input and failed
summary commits are errors; open handoffs and conflicts remain actionable
information rather than being silently discarded.

Fixtures cover agreement, refinement, gap-fill, conflict, dynamic-only and
static-only endpoints, resolved/open handoffs, diagnostics, and durable JSON
round-tripping. Live capture is outside this phase.
