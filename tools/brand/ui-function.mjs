/**
 * Functional confirmation for the UI work.
 *
 * The dark-default / responsive pass touched styling, markup and two small
 * pieces of shell wiring. Nothing in it should change behaviour, and this
 * asserts that: it drives the real app against the real engine and checks that
 * each wired interaction still reaches the API and still updates the DOM.
 *
 * It is a regression tripwire, not a product test — it does not assert what the
 * engine returns, only that the UI still asks and still renders the answer.
 *
 * Requires an engine with a session that has traffic and an assembled surface.
 *
 * Usage:
 *   node tools/brand/ui-function.mjs --base http://127.0.0.1:7777
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

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

const results = [];

async function check(name, run) {
  try {
    const detail = await run();
    results.push({ name, ok: true, detail: detail ?? "" });
  } catch (error) {
    results.push({ name, ok: false, detail: error.message });
  }
}

function expect(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  const base = arg("base", "http://127.0.0.1:7777").replace(/\/$/, "");
  const browser = await chromium.launch({
    executablePath: arg("chromium", process.env.APIAXESS_CHROMIUM ?? undefined),
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const pageErrors = [];
  const failedRequests = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("requestfailed", (request) => {
    // A reload or a view change cancels whatever poll was in flight; the browser
    // reports that as ERR_ABORTED and the shell's own catch handles it. Only a
    // request that genuinely could not complete is a regression signal.
    const reason = request.failure()?.errorText ?? "unknown";
    if (reason.includes("ERR_ABORTED")) return;
    failedRequests.push(`${request.url()} (${reason})`);
  });

  await page.goto(`${base}/#start`, { waitUntil: "networkidle" });
  await page.waitForFunction(
    () => document.querySelector("#splash")?.hidden === true,
    undefined,
    { timeout: 15000 },
  );

  await check("engine connects and the shell reports ready", async () => {
    const text = await page.locator("#status-text").textContent();
    expect(/ready|connected/i.test(text ?? ""), `status reads "${text}"`);
    return text?.trim();
  });

  await check("dark is the default theme", async () => {
    const theme = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(theme === "dark", `data-theme is "${theme}"`);
    return theme;
  });

  await check("theme toggle switches and persists across a reload", async () => {
    await page.locator("[data-theme-toggle]").click();
    const after = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(after === "light", `toggle produced "${after}"`);
    await page.reload({ waitUntil: "networkidle" });
    const restored = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(restored === "light", `reload produced "${restored}"`);
    await page.locator("[data-theme-toggle]").click();
    const back = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(back === "dark", `toggle back produced "${back}"`);
    return "dark → light → reload → light → dark";
  });

  await check("every nav target routes and marks itself current", async () => {
    const views = ["apk", "web", "workbench", "surface", "export", "session", "start"];
    for (const view of views) {
      await page.locator(`.app-nav__item[data-nav="${view}"]`).click();
      await page.waitForTimeout(120);
      const state = await page.evaluate((name) => {
        const section = document.querySelector(`[data-view="${name}"]`);
        const item = document.querySelector(`.app-nav__item[data-nav="${name}"]`);
        return {
          visible: section !== null && !section.hidden,
          current: item?.getAttribute("aria-current") === "page",
          hash: window.location.hash,
        };
      }, view);
      expect(state.visible, `#${view} did not become visible`);
      expect(state.current, `#${view} is not marked current`);
      expect(state.hash === `#${view}`, `hash is ${state.hash} for #${view}`);
    }
    return `${views.length} routes`;
  });

  await check("settings load from the engine", async () => {
    await page.locator('[data-nav="settings"]').click();
    await page.waitForSelector("#settings-body .panel", { timeout: 10000 });
    const panels = await page.locator("#settings-body .panel").count();
    const tools = await page.locator(".tool-row").count();
    expect(panels > 0 && tools > 0, `panels=${panels} tools=${tools}`);
    return `${panels} panels, ${tools} bundled tools`;
  });

  await check("settings save posts and reports back", async () => {
    const [response] = await Promise.all([
      page
        .waitForResponse((r) => r.url().includes("/api/v1/settings") && r.request().method() === "PUT", {
          timeout: 4000,
        })
        .catch(() => null),
      page.locator("#settings-save").click(),
    ]);
    // With nothing edited the shell short-circuits to a toast rather than
    // posting; either outcome proves the handler is wired.
    if (response === null) {
      await page.waitForSelector(".toast", { timeout: 4000 });
      return "no changes → toast (no request, as designed)";
    }
    return `PUT /api/v1/settings → ${response.status()}`;
  });

  await check("workbench lists captured flows", async () => {
    await page.locator('.app-nav__item[data-nav="workbench"]').click();
    await page.waitForSelector("#flow-list .list-row", { timeout: 10000 });
    const rows = await page.locator("#flow-list .list-row").count();
    expect(rows > 0, "no flow rows");
    return `${rows} flows`;
  });

  await check("selecting a flow loads its detail from the engine", async () => {
    const [response] = await Promise.all([
      page.waitForResponse((r) => /\/api\/v1\/workbench\/flows\/\d+/.test(r.url()), { timeout: 8000 }),
      page.locator("#flow-list .list-row").first().click(),
    ]);
    await page.waitForSelector("#detail-actions .btn");
    const label = await page.locator("#selected-label").textContent();
    expect(response.status() === 200, `detail responded ${response.status()}`);
    expect((label ?? "").includes("Flow #"), `label reads "${label}"`);
    return `${label?.trim()} (${response.status()})`;
  });

  await check("send-to-resend creates a durable context", async () => {
    const [response] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes("/api/v1/workbench/resend") && r.request().method() === "POST",
        { timeout: 8000 },
      ),
      page.getByRole("button", { name: "Resend", exact: true }).click(),
    ]);
    await page.waitForSelector("#resend-panel:not([hidden])");
    expect(response.status() === 200, `resend create responded ${response.status()}`);
    const heading = await page.locator("#resend-panel h2").textContent();
    return `${heading?.trim()} (${response.status()})`;
  });

  await check("send-to-fuzzer opens a configurable draft", async () => {
    await page.getByRole("button", { name: "Fuzzer", exact: true }).click();
    await page.waitForSelector("#fuzzer-panel:not([hidden])");
    const fields = await page.locator("#fuzzer-panel .field").count();
    expect(fields > 4, `only ${fields} fields in the fuzzer draft`);
    return `${fields} configurable fields`;
  });

  await check("the fused surface renders its endpoints", async () => {
    await page.locator('.app-nav__item[data-nav="surface"]').click();
    await page.waitForSelector(".endpoint-row", { timeout: 10000 });
    const rows = await page.locator(".endpoint-row").count();
    const metrics = await page.locator(".metric__value").allTextContents();
    expect(rows > 0, "no endpoint rows");
    return `${rows} endpoints, coverage ${metrics.join("/")}`;
  });

  await check("export posts and reports written artifacts", async () => {
    await page.locator('.app-nav__item[data-nav="export"]').click();
    await page.locator("#export-dir").fill("tmp/ui-function-export");
    const [response] = await Promise.all([
      page.waitForResponse((r) => r.url().includes("/api/v1/export"), { timeout: 60000 }),
      page.locator("#export-run").click(),
    ]);
    expect(response.status() === 200, `export responded ${response.status()}`);
    await page.waitForSelector("#export-result .kv, #export-result .data-table, #export-result .stack", {
      timeout: 10000,
    });
    const badge = await page.locator("#export-badge").textContent();
    return `POST /api/v1/export → ${response.status()}, badge "${badge?.trim()}"`;
  });

  await check("session view loads status and the audit trail", async () => {
    await page.locator('.app-nav__item[data-nav="session"]').click();
    await page.waitForSelector("#session-detail .kv", { timeout: 10000 });
    const audit = await page.locator(".audit-row").count();
    expect(audit > 0, "no audit rows");
    return `${audit} audit records`;
  });

  await check("new-session asks before replacing the active one", async () => {
    await page.locator("#session-new").click();
    await page.waitForSelector(".modal", { timeout: 5000 });
    const title = await page.locator(".modal__title").textContent();
    await page.getByRole("button", { name: "Cancel" }).click();
    await page.waitForSelector(".modal", { state: "detached", timeout: 5000 });
    return `confirm "${title?.trim()}" → cancelled`;
  });

  await check("diagnostics drawer opens and closes", async () => {
    await page.locator("#diagnostics-toggle").click();
    await page.waitForSelector("#diagnostics-drawer:not([hidden])");
    await page.locator("#diagnostics-close").click();
    // The drawer stays in the document and toggles `hidden`, so wait on the
    // hidden state rather than on a selector that can never be "visible".
    await page.waitForSelector("#diagnostics-drawer", { state: "hidden" });
    return "open → close";
  });

  await check("no uncaught page errors or failed requests", async () => {
    expect(pageErrors.length === 0, `page errors: ${pageErrors.join("; ")}`);
    expect(failedRequests.length === 0, `failed requests: ${failedRequests.join("; ")}`);
    return "clean";
  });

  await browser.close();

  const failed = results.filter((result) => !result.ok);
  results.forEach((result) => {
    console.log(`${result.ok ? "PASS" : "FAIL"}  ${result.name}${result.detail ? " — " + result.detail : ""}`);
  });
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length > 0) process.exitCode = 1;
}

await main();
