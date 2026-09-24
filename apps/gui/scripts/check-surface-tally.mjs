// Executable check: the API surface header counts come from the same rule as
// the per-endpoint badges (src/surface/tally.ts), for a capture-only surface
// and a mixed static + dynamic one.
import assert from "node:assert/strict";
import { isConfirmed, tallySurface } from "../src/surface/tally.ts";

// A web capture: every endpoint observed, none in code.
const capture = [
  { evidenceSource: "confirmed", staticEvidence: false },
  { evidenceSource: "confirmed", staticEvidence: false },
  { evidenceSource: "confirmed" },
  { evidenceSource: "confirmed" },
];
assert.deepEqual(tallySurface(capture), { endpoints: 4, confirmed: 4, alsoInCode: 0, inferred: 0 });

// An APK run with dynamic capture: observed + in code, observed only, code only.
const mixed = [
  { evidenceSource: "confirmed", staticEvidence: true },
  { evidenceSource: "confirmed", staticEvidence: false },
  { evidenceSource: "static_inferred", staticEvidence: true },
  { evidenceSource: "static_inferred", staticEvidence: true },
  { evidenceSource: null },
];
const tally = tallySurface(mixed);
assert.deepEqual(tally, { endpoints: 5, confirmed: 2, alsoInCode: 1, inferred: 3 });
// The header's confirmed count equals the number of rows the badge marks confirmed.
assert.equal(tally.confirmed, mixed.filter(isConfirmed).length);
assert.equal(tally.inferred, mixed.filter((endpoint) => !isConfirmed(endpoint)).length);
assert.deepEqual(tallySurface([]), { endpoints: 0, confirmed: 0, alsoInCode: 0, inferred: 0 });

console.log("Surface tally OK: header counts match the per-endpoint badges (capture-only and mixed static+dynamic).");
