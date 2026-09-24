//! One source of truth for the API surface's evidence vocabulary, shared by the
//! per-endpoint badge and the header counts so the two can never disagree.
//!
//! GUI vocabulary (what an operator reads):
//! - **confirmed** — the endpoint was observed in dynamic capture (live
//!   traffic); it may *also* be backed by code (`alsoInCode`).
//! - **inferred** — recovered from code only, never observed being hit: a lead.
//!
//! The engine's `CoveragePicture` uses different words for a finer split
//! (its "confirmed" = static AND dynamic, "inferred" = dynamic only, "static
//! only" = static only). Those counts stay in the evidence export; the GUI
//! derives its own from each endpoint's evidence rather than relabeling them.

/** The evidence behind one endpoint, as the surface summary reports it. */
export interface EndpointEvidence {
  /** `confirmed` when any fact traces to dynamic capture, else `static_inferred`. */
  readonly evidenceSource?: string | null;
  /** Whether any fact also traces to static analysis (code). */
  readonly staticEvidence?: boolean | null;
}

export interface SurfaceTally {
  readonly endpoints: number;
  /** Observed in live traffic. */
  readonly confirmed: number;
  /** Observed in live traffic and also found in code. */
  readonly alsoInCode: number;
  /** Code only; not observed. */
  readonly inferred: number;
}

/** Whether an endpoint reads as confirmed (observed in dynamic capture). */
export function isConfirmed(endpoint: EndpointEvidence): boolean {
  return endpoint.evidenceSource === "confirmed";
}

/** Counts a surface's endpoints by the same rule the badges use. */
export function tallySurface(endpoints: readonly EndpointEvidence[]): SurfaceTally {
  let confirmed = 0;
  let alsoInCode = 0;
  for (const endpoint of endpoints) {
    if (!isConfirmed(endpoint)) continue;
    confirmed += 1;
    if (endpoint.staticEvidence === true) alsoInCode += 1;
  }
  return { endpoints: endpoints.length, confirmed, alsoInCode, inferred: endpoints.length - confirmed };
}
