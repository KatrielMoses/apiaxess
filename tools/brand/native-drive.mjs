/**
 * Walks every surface of the running APIaxess desktop app, at a range of real
 * window sizes, and captures the actual OS window at each combination.
 *
 * Why this rather than the browser sweep: in the native shell the viewport is
 * the window's client area, the operator changes it by dragging an edge, and
 * the host is WebView2 rather than Chromium-with-an-emulated-viewport. This
 * checks the layout survives all three differences.
 *
 * The window is resized and captured through `native-window.ps1` (Win32
 * MoveWindow / GDI capture); the view is switched over WebView2's CDP endpoint,
 * which `native-shots.ps1 -KeepRunning` leaves open.
 *
 * Usage — start the shell first:
 *   pwsh -File tools/brand/native-shots.ps1 -Stamp <folder> -KeepRunning
 *   node tools/brand/native-drive.mjs --stamp <folder> --pid <pid>
 */

import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
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

const SIZES = ["1920x1080", "1440x900", "1280x800", "1024x768", "820x900", "640x900", "480x860"];

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

function powershell(args) {
  return execFileSync(
    "pwsh",
    ["-NoProfile", "-File", path.resolve("tools/brand/native-window.ps1"), ...args],
    { encoding: "utf-8" },
  ).trim();
}

async function main() {
  const stamp = arg("stamp", "native");
  const pid = arg("pid", null);
  if (pid === null) throw new Error("--pid is required (printed by native-shots.ps1 -KeepRunning)");
  const port = arg("port", "9222");
  const outDir = path.resolve("testers/assets", stamp);
  const sizes = list("sizes", SIZES);
  const views = list("views", VIEWS);
  const themes = list("themes", ["dark"]);

  await mkdir(outDir, { recursive: true });

  const browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
  const page = browser.contexts()[0].pages()[0];
  const problems = [];

  for (const theme of themes) {
    await page.evaluate((value) => {
      window.localStorage.setItem("apiaxess.theme", value);
      document.documentElement.dataset.theme = value;
    }, theme);
    await page.reload({ waitUntil: "networkidle" });
    await page.waitForTimeout(600);

    for (const size of sizes) {
      const [width, height] = size.split("x");
      powershell(["-Action", "resize", "-ProcessId", pid, "-Width", width, "-Height", height]);
      await page.waitForTimeout(700);

      for (const view of views) {
        await page.evaluate((name) => {
          window.location.hash = `#${name}`;
        }, view);
        await page.waitForTimeout(450);

        const measured = await page.evaluate(() => ({
          scrollWidth: document.documentElement.scrollWidth,
          clientWidth: document.documentElement.clientWidth,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
        }));
        if (measured.scrollWidth > measured.clientWidth + 1) {
          problems.push(
            `${theme} ${size} #${view}: overflows ${measured.scrollWidth} > ${measured.clientWidth}`,
          );
        }

        powershell([
          "-Action",
          "capture",
          "-ProcessId",
          pid,
          "-Path",
          path.join(outDir, `native-${theme}_${size}_${view}.png`),
        ]);
      }

      process.stdout.write(`native ${theme} @ ${size}: ${views.length} views\n`);
    }
  }

  await browser.close();

  if (problems.length === 0) {
    console.log("\nno overflow in the native window at any size, on any surface");
  } else {
    console.log(`\n${problems.length} problem(s):`);
    problems.forEach((problem) => console.log(`  - ${problem}`));
    process.exitCode = 1;
  }
}

await main();
