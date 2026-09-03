/**
 * Responsive screenshot harness for the APIaxess web UI.
 *
 * Walks every surface at every viewport in the matrix below, in both themes,
 * and writes the frames into `testers/assets/<stamp>/`. It exists so the
 * responsive claims in a run doc are backed by frames anyone can regenerate,
 * rather than by "it looked fine".
 *
 * Usage (from the repository root, with the GUI served somewhere):
 *
 *   node tools/brand/ui-shots.mjs --base http://127.0.0.1:5173 --stamp 2026-09-02_1500
 *
 * Options:
 *   --base    origin serving the GUI (default http://127.0.0.1:5173)
 *   --stamp   output folder name under testers/assets (default: now)
 *   --themes  comma-separated subset of dark,light (default both)
 *   --sizes   comma-separated subset of the size keys below
 *   --views   comma-separated subset of the view names below
 *   --full    capture full-page frames instead of viewport frames
 */

import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const require = createRequire(import.meta.url);
const { chromium } = require(
  path.join(
    process.env.USERPROFILE ?? process.env.HOME ?? "",
    ".claude/skills/gstack/node_modules/playwright",
  ),
);

/** The viewport matrix: large desktop down to the smallest supported window. */
const SIZES = {
  "1920x1080": { width: 1920, height: 1080 },
  "1440x900": { width: 1440, height: 900 },
  "1280x800": { width: 1280, height: 800 },
  "1024x768": { width: 1024, height: 768 },
  "820x900": { width: 820, height: 900 },
  "640x900": { width: 640, height: 900 },
  "400x860": { width: 400, height: 860 },
};

/** Every routed surface in the shell. */
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

function list(name, fallback) {
  const raw = arg(name, null);
  return raw === null ? fallback : raw.split(",").map((item) => item.trim());
}

function stamp() {
  const now = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return (
    `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}` +
    `_${pad(now.getHours())}${pad(now.getMinutes())}`
  );
}

/**
 * A stitched full-page capture paints `position: sticky` elements where they
 * would sit after scrolling, so the app header appears twice in the frame.
 * Pinning them static for the capture only removes the artefact — the
 * responsive layout under test is unchanged.
 */
async function unstick(page) {
  await page.addStyleTag({
    content:
      ".app-header, .data-table th { position: static !important; }",
  });
}

async function main() {
  const base = arg("base", "http://127.0.0.1:5173").replace(/\/$/, "");
  const outDir = path.resolve("testers/assets", arg("stamp", stamp()));
  const themes = list("themes", ["dark", "light"]);
  const sizes = list("sizes", Object.keys(SIZES));
  const views = list("views", VIEWS);
  const fullPage = process.argv.includes("--full");

  await mkdir(outDir, { recursive: true });

  // The bundled Playwright build and the installed browser revisions can
  // drift; an explicit executable keeps the harness runnable either way.
  const executablePath = arg("chromium", process.env.APIAXESS_CHROMIUM ?? null);
  const browser = await chromium.launch(
    executablePath === null ? {} : { executablePath },
  );
  const problems = [];

  for (const theme of themes) {
    for (const key of sizes) {
      const viewport = SIZES[key];
      if (viewport === undefined) throw new Error(`unknown size: ${key}`);
      const context = await browser.newContext({
        viewport,
        deviceScaleFactor: 1,
      });
      // Seeded before any document script runs, so the shell's pre-paint theme
      // resolution picks it up and no frame is captured mid-switch.
      await context.addInitScript(
        (value) => window.localStorage.setItem("apiaxess.theme", value),
        theme,
      );
      const page = await context.newPage();
      page.on("pageerror", (error) =>
        problems.push(`${theme} ${key}: page error: ${error.message}`),
      );

      for (const view of views) {
        await page.goto(`${base}/#${view}`, { waitUntil: "networkidle" });
        // The splash fades out on its own timer; wait it out so no frame
        // captures the overlay.
        await page.waitForFunction(
          () => document.querySelector("#splash")?.hidden === true,
          undefined,
          { timeout: 15000 },
        );
        await page.waitForTimeout(180);

        // Horizontal overflow is the failure this harness exists to catch, so
        // it is measured on every frame rather than left to the eye.
        const overflow = await page.evaluate(() => {
          const doc = document.documentElement;
          const offenders = [];
          if (doc.scrollWidth > doc.clientWidth + 1) {
            document.querySelectorAll("*").forEach((node) => {
              const box = node.getBoundingClientRect();
              if (box.width === 0) return;
              if (box.right > doc.clientWidth + 1 || box.left < -1) {
                offenders.push(
                  `${node.tagName.toLowerCase()}.${String(node.className || "").split(" ")[0]}` +
                    ` [${Math.round(box.left)}..${Math.round(box.right)}]`,
                );
              }
            });
          }
          return {
            scrollWidth: doc.scrollWidth,
            clientWidth: doc.clientWidth,
            offenders: [...new Set(offenders)].slice(0, 8),
          };
        });
        if (overflow.scrollWidth > overflow.clientWidth + 1) {
          problems.push(
            `${theme} ${key} #${view}: overflows ` +
              `${overflow.scrollWidth} > ${overflow.clientWidth} — ` +
              overflow.offenders.join(", "),
          );
        }

        if (fullPage) await unstick(page);
        await page.screenshot({
          path: path.join(outDir, `${theme}_${key}_${view}.png`),
          fullPage,
        });
      }

      await context.close();
      process.stdout.write(`captured ${theme} @ ${key}\n`);
    }
  }

  await browser.close();

  console.log(`\nframes in ${outDir}`);
  if (problems.length === 0) {
    console.log("no horizontal overflow and no page errors at any size");
  } else {
    console.log(`\n${problems.length} problem(s):`);
    problems.forEach((problem) => console.log(`  - ${problem}`));
    process.exitCode = 1;
  }
}

await main();
