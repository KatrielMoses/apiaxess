/**
 * Continuous-width overflow sweep.
 *
 * `ui-shots.mjs` samples seven viewports. A breakpoint that is a few pixels too
 * tight breaks only in the gaps between those samples — which is exactly the
 * failure the native shell surfaced, because a classic scrollbar shifts the
 * layout width ~15px away from the width the media query sees. This walks every
 * width in the supported range in small steps, on every surface, and reports
 * anything that overflows horizontally. No screenshots: it is a tripwire, not
 * evidence.
 *
 * It runs headed on purpose. A headless browser uses overlay scrollbars, so the
 * layout width equals the viewport width and the whole class of bug this sweep
 * exists to catch cannot reproduce. A headed window on Windows draws a classic
 * scrollbar — the layout gets ~11px less than the media queries see, which is
 * the same geometry as the desktop shell's WebView2.
 *
 * Usage:
 *   node tools/brand/ui-widths.mjs --base http://127.0.0.1:7777
 *   node tools/brand/ui-widths.mjs --from 360 --to 1920 --step 10
 */

import { createRequire } from "node:module";
import path from "node:path";
import process from "node:process";

const require = createRequire(import.meta.url);
const { chromium } = require(
  path.join(
    process.env.USERPROFILE ?? process.env.HOME ?? "",
    ".claude/skills/gstack/node_modules/playwright",
  ),
);

const VIEWS = [
  "start",
  "apk",
  "web",
  "workbench",
  "surface",
  "export",
  "session",
  "settings",
  "about",
];

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

async function main() {
  const base = arg("base", "http://127.0.0.1:7777").replace(/\/$/, "");
  const from = Number(arg("from", "360"));
  const to = Number(arg("to", "1920"));
  const step = Number(arg("step", "10"));
  const height = Number(arg("height", "820"));
  const themes = (arg("themes", "dark,light")).split(",");

  const browser = await chromium.launch({
    executablePath: arg("chromium", process.env.APIAXESS_CHROMIUM ?? undefined),
    // See the header: headless would hide the very geometry under test.
    headless: false,
  });

  const problems = [];
  let checked = 0;

  for (const theme of themes) {
    const context = await browser.newContext({
      viewport: { width: to, height },
      deviceScaleFactor: 1,
    });
    await context.addInitScript(
      (value) => window.localStorage.setItem("apiaxess.theme", value),
      theme,
    );
    const page = await context.newPage();
    await page.goto(`${base}/#start`, { waitUntil: "networkidle" });
    await page.waitForFunction(
      () => document.querySelector("#splash")?.hidden === true,
      undefined,
      { timeout: 15000 },
    );

    for (let width = from; width <= to; width += step) {
      await page.setViewportSize({ width, height });
      for (const view of VIEWS) {
        await page.evaluate((name) => {
          window.location.hash = `#${name}`;
        }, view);
        // One frame is enough: nothing here animates its width.
        await page.evaluate(
          () => new Promise((resolve) => requestAnimationFrame(() => resolve())),
        );
        const measured = await page.evaluate(() => {
          const doc = document.documentElement;
          const offenders = [];
          if (doc.scrollWidth > doc.clientWidth + 1) {
            document.querySelectorAll("*").forEach((node) => {
              const box = node.getBoundingClientRect();
              if (box.width === 0) return;
              if (box.right > doc.clientWidth + 1 || box.left < -1) {
                const cls = String(node.className || "").split(" ")[0];
                offenders.push(`${node.tagName.toLowerCase()}${cls ? "." + cls : ""}`);
              }
            });
          }
          return {
            over: doc.scrollWidth - doc.clientWidth,
            client: doc.clientWidth,
            offenders: [...new Set(offenders)].slice(0, 5),
          };
        });
        checked += 1;
        if (measured.over > 1) {
          problems.push(
            `${theme} viewport ${width} (client ${measured.client}) #${view}: ` +
              `over by ${measured.over}px — ${measured.offenders.join(", ")}`,
          );
        }
      }
    }

    await context.close();
    process.stdout.write(`swept ${theme} ${from}..${to} step ${step}\n`);
  }

  await browser.close();

  console.log(`\n${checked} width/surface combinations checked`);
  if (problems.length === 0) {
    console.log("no horizontal overflow at any width");
  } else {
    // Collapse runs of consecutive failing widths so the report stays readable.
    console.log(`\n${problems.length} problem(s):`);
    problems.slice(0, 60).forEach((problem) => console.log(`  - ${problem}`));
    if (problems.length > 60) console.log(`  … and ${problems.length - 60} more`);
    process.exitCode = 1;
  }
}

await main();
