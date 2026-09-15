/*
 * Guards brand-mark integrity.
 *
 * The APIaxess mark ends in an "x": two arrowheads that share a tip, an accent
 * "<" (wings LEFT of the tip) crossed with an ink ">" (wings RIGHT of the tip).
 * Every hand-authored copy of the mark (favicon, splash, desktop control UI,
 * app icons) must draw BOTH — the canonical source is apps/gui/src/brand/logo.ts.
 * A copy that has one arrowhead direction but not its mirror is a half-drawn x;
 * that shipped once in the favicon, so this check fails the build if it recurs.
 *
 * Run: node scripts/check-marks.mjs  (wired as `pnpm --filter … lint:marks`)
 */

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

// Where hand-authored marks live. logo.ts is the canonical generator; the rest
// are static copies that must stay faithful to it.
const TARGETS = [
  "apps/gui/index.html",
  "apps/gui/public/favicon.svg",
  "apps/gui/src/brand/logo.ts",
  "apps/desktop/ui/control.html",
  "apps/desktop/icons/icon.svg",
];

// An arrowhead is `L<x> 100 L<wing>`: the tip sits on the y=100 centre line, the
// wing is left (~11x, accent) or right (~16x–17x, ink).
const LEFT_ARROW = /L\d{2,3}\s+100\s+L11\d\b/;
const RIGHT_ARROW = /L\d{2,3}\s+100\s+L1[67]\d\b/;

function filesUnder(rel) {
  const abs = join(repoRoot, rel);
  if (!existsSync(abs)) return [];
  if (statSync(abs).isFile()) return [rel];
  const out = [];
  for (const entry of readdirSync(abs)) {
    if (/\.(svg|html|ts)$/.test(entry)) out.push(join(rel, entry));
  }
  return out;
}

const violations = [];
for (const rel of TARGETS.flatMap(filesUnder)) {
  const text = readFileSync(join(repoRoot, rel), "utf8");
  const hasLeft = LEFT_ARROW.test(text);
  const hasRight = RIGHT_ARROW.test(text);
  if (hasLeft !== hasRight) {
    violations.push({
      rel,
      missing: hasLeft ? "ink arrowhead (the > that completes the x)" : "accent arrowhead (the < half of the x)",
    });
  }
}

if (violations.length > 0) {
  console.error(
    "Half-drawn brand mark(s): an arrowhead is missing its mirror.\n" +
      "The mark must draw both the accent < and the ink > (see apps/gui/src/brand/logo.ts).\n",
  );
  for (const v of violations) console.error(`  ${v.rel}  —  missing the ${v.missing}`);
  process.exit(1);
}

console.log("Brand marks OK: every mark draws a complete arrowhead pair.");
