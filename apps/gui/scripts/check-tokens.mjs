/*
 * Guards the design-token boundary.
 *
 * The desktop shell is coded against the production-spec `--s-*` tokens
 * (`src/styles/shell-tokens.css`). No component stylesheet may hard-code a
 * colour: every hex literal must live in a designated token file so the brand
 * can be retuned in one place. This check fails the build on any hex colour
 * found in a stylesheet outside that allowlist.
 *
 * `tokens.css` is allowlisted during the transition — it is the legacy
 * `--color-*` token file the not-yet-rebuilt surfaces still consume. It is
 * removed from the allowlist once the last surface is migrated.
 *
 * Run: node scripts/check-tokens.mjs  (wired as `pnpm --filter … lint:tokens`)
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, relative } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const stylesDir = join(here, "..", "src", "styles");

// Files permitted to hold raw hex colours. Both are token definitions, not
// components. `tokens.css` leaves this list when the legacy vocabulary is gone.
const ALLOWLIST = new Set(["shell-tokens.css", "tokens.css"]);

// #rgb, #rgba, #rrggbb, #rrggbbaa — the shapes a CSS hex colour can take.
const HEX = /#[0-9a-fA-F]{3,8}\b/g;

/** Every `.css` file under the styles directory, recursively. */
function cssFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...cssFiles(full));
    else if (entry.endsWith(".css")) out.push(full);
  }
  return out;
}

const violations = [];
for (const file of cssFiles(stylesDir)) {
  const name = relative(stylesDir, file);
  if (ALLOWLIST.has(name)) continue;
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    const matches = line.match(HEX);
    if (matches !== null) {
      violations.push({ file: name, line: index + 1, matches, text: line.trim() });
    }
  });
}

if (violations.length > 0) {
  console.error(
    "Hard-coded hex colour(s) found outside the token files.\n" +
      "Use an --s-* token from shell-tokens.css instead.\n",
  );
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  ${v.matches.join(", ")}  ->  ${v.text}`);
  }
  process.exit(1);
}

console.log("Token boundary OK: no hard-coded hex colours outside the token files.");
