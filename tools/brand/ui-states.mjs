/**
 * Component-state screenshot harness.
 *
 * `ui-shots.mjs` walks the routed surfaces; this walks the states inside them
 * that only exist once there is data or once something is open — a selected
 * flow, the resend and fuzzer drawers, the diagnostics drawer, a confirm
 * dialog, a toast. Those are the states most likely to break responsively and
 * the ones a route-level sweep never reaches.
 *
 * Requires a session with traffic in it. Seed one first, e.g.
 *
 *   curl -X POST http://127.0.0.1:7777/api/v1/workbench/har --data-binary @seed.har
 *   curl -X POST http://127.0.0.1:7777/api/v1/web/fuse
 *
 * Usage:
 *   node tools/brand/ui-states.mjs --base http://127.0.0.1:5173 --stamp <folder>
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

const SIZES = {
  "1920x1080": { width: 1920, height: 1080 },
  "1440x900": { width: 1440, height: 900 },
  "1280x800": { width: 1280, height: 800 },
  "1024x768": { width: 1024, height: 768 },
  "820x900": { width: 820, height: 900 },
  "640x900": { width: 640, height: 900 },
  "400x860": { width: 400, height: 860 },
};

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function list(name, fallback) {
  const raw = arg(name, null);
  return raw === null ? fallback : raw.split(",").map((item) => item.trim());
}

/**
 * Each state names the view it lives in and the interaction that opens it.
 * `settle` is how long the state needs after the click before it is stable.
 */
const STATES = [
  {
    name: "workbench-flows",
    view: "workbench",
    async open() {},
  },
  {
    name: "workbench-detail",
    view: "workbench",
    async open(page) {
      await page.locator("#flow-list .list-row").nth(1).click();
      await page.waitForSelector("#detail-actions .btn");
    },
  },
  {
    name: "workbench-resend",
    view: "workbench",
    async open(page) {
      await page.locator("#flow-list .list-row").nth(1).click();
      await page.waitForSelector("#detail-actions .btn");
      await page.getByRole("button", { name: "Resend", exact: true }).click();
      await page.waitForSelector("#resend-panel:not([hidden])");
    },
  },
  {
    name: "workbench-fuzzer",
    view: "workbench",
    async open(page) {
      await page.locator("#flow-list .list-row").nth(1).click();
      await page.waitForSelector("#detail-actions .btn");
      await page.getByRole("button", { name: "Fuzzer", exact: true }).click();
      await page.waitForSelector("#fuzzer-panel:not([hidden])");
    },
  },
  {
    name: "surface-endpoints",
    view: "surface",
    async open() {},
  },
  {
    /*
     * A populated surface. Assembling a real one needs a full APK pipeline or a
     * live capture; the endpoint row is a layout under test either way, so the
     * response is stubbed and the app's own renderer draws it. The shape is
     * `SurfaceSummary` exactly as `renderSurface` consumes it.
     */
    name: "surface-populated",
    view: "surface",
    async route(page) {
      await page.route("**/api/v1/surface", (route) =>
        route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({
            schemaVersion: 1,
            assemblyRunId: "web:capture:4d43d29c0be85bcc1f4e74c61722da24:surface",
            signerCount: 2,
            coverage: {
              endpointCount: 7,
              confirmedEndpointCount: 4,
              inferredEndpointCount: 2,
              staticOnlyEndpointCount: 1,
              resolvedHandoffCount: 3,
              openHandoffCount: 1,
            },
            endpoints: [
              { method: "get", pathTemplate: "/v1/accounts", minimumFactConfidence: 0.94, signerCount: 1 },
              { method: "post", pathTemplate: "/v1/accounts/{accountId}/transfers", minimumFactConfidence: 0.88, signerCount: 2 },
              { method: "patch", pathTemplate: "/v1/accounts/{accountId}/settings/notifications", minimumFactConfidence: 0.61, signerCount: 0 },
              { method: "delete", pathTemplate: "/v1/sessions/current", minimumFactConfidence: 0.42, signerCount: 0 },
              { method: "put", pathTemplate: "/uploads/{year}/{month}/statement-september-consolidated-report.pdf", minimumFactConfidence: 0.31, signerCount: 0 },
              { method: "get", pathTemplate: "/v1/accounts/{accountId}/statements", minimumFactConfidence: null, signerCount: 0 },
              { method: "options", pathTemplate: "/v1/accounts", minimumFactConfidence: 0.8, signerCount: 1 },
            ],
            diagnostics: [],
          }),
        }),
      );
    },
    async open() {},
  },
  {
    name: "diagnostics-drawer",
    view: "start",
    async open(page) {
      await page.locator("#diagnostics-toggle").click();
      await page.waitForSelector("#diagnostics-drawer:not([hidden])");
    },
  },
  {
    name: "confirm-dialog",
    view: "session",
    async open(page) {
      await page.locator("#session-new").click();
      await page.waitForSelector(".modal");
    },
  },
  {
    /*
     * A pipeline mid-run. Reaching this for real needs an APK and several
     * minutes of analysis; the progress bar, the stage rail and the run
     * key/value block are layouts under test regardless, so the status
     * response is stubbed and the app's own renderer draws them.
     */
    name: "apk-running",
    view: "apk",
    async route(page) {
      await page.route("**/api/v1/pipeline", (route) =>
        route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({
            runId: "apk:2026-09-02:9f31c0",
            artifactPath: "C:\\targets\\com.example.banking_8.14.2-release.apk",
            status: "running",
            stage: "dynamic",
            message: "Exercising the app in the sandbox — 41 screens visited, 128 requests observed",
            progressBasisPoints: 4820,
            dynamicRan: true,
            surfaceAvailable: false,
            updatedAt: new Date().toISOString(),
            diagnostics: [
              {
                id: "sandbox.pinning-bypass-partial",
                what: "Certificate pinning was bypassed for two of three clients.",
                why: "One client pins inside native code the injected hooks did not reach.",
                fix: "Re-run with the native hook set enabled, or treat that client's endpoints as unconfirmed.",
                severity: "warning",
              },
            ],
          }),
        }),
      );
    },
    async open(page) {
      await page.waitForSelector(".progress");
    },
  },
  {
    /* Keyboard focus, on a control and on a text input, in both grounds. */
    name: "focus-ring",
    view: "apk",
    async open(page) {
      await page.locator("#apk-path").focus();
      await page.keyboard.press("Tab");
      await page.keyboard.press("Tab");
    },
  },
  {
    /* Saving with nothing changed is the one toast that needs no side effect. */
    name: "toast",
    view: "settings",
    async open(page) {
      await page.waitForSelector("#settings-body .panel");
      await page.locator("#settings-save").click();
      await page.waitForSelector(".toast");
    },
  },
];

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
  const outDir = path.resolve("testers/assets", arg("stamp", "states"));
  const themes = list("themes", ["dark", "light"]);
  const sizes = list("sizes", Object.keys(SIZES));
  const names = list("states", STATES.map((state) => state.name));

  await mkdir(outDir, { recursive: true });

  const browser = await chromium.launch({
    executablePath: arg("chromium", process.env.APIAXESS_CHROMIUM ?? undefined),
  });
  const problems = [];

  for (const theme of themes) {
    for (const key of sizes) {
      const context = await browser.newContext({
        viewport: SIZES[key],
        deviceScaleFactor: 1,
      });
      await context.addInitScript(
        (value) => window.localStorage.setItem("apiaxess.theme", value),
        theme,
      );
      const page = await context.newPage();
      page.on("pageerror", (error) =>
        problems.push(`${theme} ${key}: page error: ${error.message}`),
      );

      let visit = 0;
      for (const state of STATES.filter((item) => names.includes(item.name))) {
        // A goto that only changes the hash is a same-document navigation, so
        // the previous state's open drawers would survive into the next frame.
        // The counter forces a real load every time.
        visit += 1;
        await page.goto(`${base}/?state=${visit}#${state.view}`, {
          waitUntil: "networkidle",
        });
        await page.waitForFunction(
          () => document.querySelector("#splash")?.hidden === true,
          undefined,
          { timeout: 15000 },
        );
        await page.waitForTimeout(250);
        try {
          if (state.route !== undefined) {
            await state.route(page);
            await page.reload({ waitUntil: "networkidle" });
            await page.waitForTimeout(250);
          }
          await state.open(page);
        } catch (error) {
          problems.push(`${theme} ${key} ${state.name}: could not open — ${error.message}`);
          continue;
        }
        await page.waitForTimeout(320);

        const overflow = await page.evaluate(() => {
          const doc = document.documentElement;
          return { scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth };
        });
        if (overflow.scrollWidth > overflow.clientWidth + 1) {
          problems.push(
            `${theme} ${key} ${state.name}: overflows ` +
              `${overflow.scrollWidth} > ${overflow.clientWidth}`,
          );
        }

        await unstick(page);
        await page.screenshot({
          path: path.join(outDir, `${theme}_${key}_state-${state.name}.png`),
          fullPage: true,
        });
      }

      await context.close();
      process.stdout.write(`captured states ${theme} @ ${key}\n`);
    }
  }

  await browser.close();

  console.log(`\nframes in ${outDir}`);
  if (problems.length === 0) {
    console.log("every state opened, with no overflow and no page errors");
  } else {
    console.log(`\n${problems.length} problem(s):`);
    problems.forEach((problem) => console.log(`  - ${problem}`));
    process.exitCode = 1;
  }
}

await main();
