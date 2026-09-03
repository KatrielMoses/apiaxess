# Phase 8.4.1 — Fusion/surface performance

## Measure-first finding

The Feeder 2.22.0 APK was used as the high-volume probe. Its persisted
static-stage document contained 12 endpoints, 27,473 loose findings, and 26
handoffs.

The first downstream profile identified repeated provenance-index construction
inside fusion and confidence evidence walks. Fusion remained in its loose-
finding pass for more than the 60-second test observation window. After that
was measured, the same Feeder document profiled as follows on Windows:

| Stage | Time |
| --- | ---: |
| Fusion, including validation | 8.1 s |
| Confidence scoring and handoff resolution | 8.5 s |
| Unified surface assembly and validation | 15.5 s |
| Downstream total | 32.1 s |

The surface profile also showed that the assembled product validated the
high-volume document multiple times. The final document contains the already
validated source plus the already validated unified projection, so the last
full-document validation was redundant and was removed. The profile now marks
that point as `surface.document-attached` rather than claiming another
validation pass.

## Fix

- Build one immutable provenance entity index per fusion operation and reuse it
  for every candidate source-mask lookup.
- Build one immutable provenance entity index per confidence recomputation and
  reuse it for every fact evidence walk.
- Keep the public validation boundaries intact, while avoiding a duplicate
  full-document validation after unified assembly.
- Preserve Feeder's complete finding inventory; no upstream findings were
  filtered or discarded to obtain the speedup.
- Keep opt-in `[pipeline-profile]` timing marks for fusion, confidence,
  handoff resolution, surface assembly, and validation/attachment boundaries.

## Windows end-to-end verification

The assembled Windows CLI run completed from APK intake through the unified
surface and persisted:

```text
session artifact: tmp/phase-8.4.1-feeder-session.json
endpoints: 12
protocol operations: 0
loose findings: 27473
signers: 0
handoffs: 26 open / 26 total
diagnostics: 27597
pipeline status: completed
```

The run took approximately 6 minutes 5 seconds wall-clock on the development
Windows/NTFS environment, including intake and static analysis. The downstream
stages were bounded as shown above; the known partial-jadx warning and
static-only/open-handoff diagnostics remained legible, and the run did not
stall in fusion or surface assembly.

## Correctness and regression coverage

The Feeder result retained the same 12-endpoint surface and 27,473 loose
findings as the prior static output. The persisted artifact can be resumed and
inspected as a normal session document.

The following regular tests lock the high-volume behavior with 27,473
representative findings:

- `high_volume_loose_findings_have_bounded_fusion_cost` in `crates/fusion`;
- `high_volume_surface_assembly_has_bounded_validation_cost` in
  `crates/unified-surface`.

The real-artifact probe remains available as the ignored
`profile_downstream_pipeline_from_session_artifact` test in
`crates/engine-shell`; set `APIAXESS_PROFILE_SESSION_ARTIFACT` and
`APIAXESS_PROFILE_PIPELINE=1` to reproduce the stage breakdown without
rerunning intake.

## Finding-volume coordination note

27,473 loose findings is a substantial but valid retained evidence volume.
This phase leaves the inventory intact because the measured defect was
superlinear downstream processing, not proof that the findings were junk.
Phase 1 may separately review the yield/noise mix, but fusion and surface now
scale with the retained volume without requiring upstream suppression.
