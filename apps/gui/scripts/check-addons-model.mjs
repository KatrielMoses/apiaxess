// Executable check: every add-on state the engine reports maps to the right
// card (src/addons/model.ts) — overrides are never downloaded over, failures
// say why, and a kept partial download offers "Resume".
import assert from "node:assert/strict";
import { addonCard, anyActive, downloadConfirmation, formatSize } from "../src/addons/model.ts";

const offer = { version: "1.0.0-android10", size: 2_254_857_830, installedSize: 6_442_450_944, url: "https://apiaxess.dev/assets/analysis-runtime/1.0.0-android10/analysis-runtime-windows-x64.tar.zst", sha256: "ab".repeat(32) };
const base = {
  slug: "analysis-runtime", name: "Android analysis runtime", purpose: "Dynamic APK analysis.",
  installed: false, installedVersion: null, outdated: false,
  path: "C:\\Users\\op\\AppData\\Local\\apiaxess\\analysis-runtime", installDir: "C:\\Users\\op\\AppData\\Local\\apiaxess\\analysis-runtime",
  overriddenBy: null, available: null, job: { phase: "idle" },
};
const kinds = (card) => card.actions.map((action) => action.kind);
const platform = "windows-x64";

// Missing, before the catalog is fetched: Download, no size yet.
let card = addonCard(base, platform);
assert.equal(card.badge, "not installed");
assert.deepEqual(kinds(card), ["download"]);
assert.equal(card.actions[0].label, "Download");
// With the catalog: the size is on the button.
assert.equal(addonCard({ ...base, available: offer }, platform).actions[0].label, "Download (2.1 GB)");

// Downloading / unpacking: progress and Cancel.
card = addonCard({ ...base, available: offer, job: { phase: "downloading", received: offer.size / 4, total: offer.size } }, platform);
assert.equal(card.progress, 25);
assert.match(card.lines[0], /25% · 538 MB of 2\.1 GB from apiaxess\.dev/);
assert.deepEqual(kinds(card), ["cancel"]);
assert.ok(anyActive({ addons: [{ ...base, job: { phase: "extracting", read: 1, total: 2 } }] }));
assert.ok(!anyActive({ addons: [base] }));

// A tampered artifact: the reason, and a fresh Download (nothing to resume).
card = addonCard({ ...base, available: offer, job: { phase: "failed", message: "the download does not match its published SHA-256", resumable: false } }, platform);
assert.equal(card.tone, "danger");
assert.ok(card.lines.some((line) => /SHA-256/.test(line)));
assert.equal(card.actions[0].label, "Download (2.1 GB)");
// A dropped connection or cancel: Resume.
card = addonCard({ ...base, available: offer, job: { phase: "failed", message: "Cancelled.", resumable: true } }, platform);
assert.equal(card.actions[0].label, "Resume download (2.1 GB)");

// Installed: nothing to do, unless the catalog offers a different version.
card = addonCard({ ...base, installed: true, installedVersion: "1.0.0-android10", available: offer }, platform);
assert.equal(card.tone, "success");
assert.deepEqual(kinds(card), []);
card = addonCard({ ...base, installed: true, installedVersion: "0.9.0", available: offer }, platform);
assert.equal(card.actions[0].label, "Update to 1.0.0-android10 (2.1 GB)");
// Outdated: download the current one.
card = addonCard({ ...base, installed: true, outdated: true, installedVersion: "1.0.0-android13" }, platform);
assert.equal(card.badge, "out of date");
assert.deepEqual(kinds(card), ["download"]);

// An explicit override is the operator's: never a Download.
card = addonCard({ ...base, overriddenBy: "APIAXESS_ANALYSIS_RUNTIME", installed: true, path: "D:\\rt" }, platform);
assert.deepEqual(kinds(card), []);
assert.match(card.lines[0], /never downloads over/);
card = addonCard({ ...base, overriddenBy: "APIAXESS_ANALYSIS_RUNTIME", path: "D:\\missing" }, platform);
assert.equal(card.badge, "override not found");
assert.deepEqual(kinds(card), []);

// No add-ons for this platform.
assert.deepEqual(kinds(addonCard(base, null)), []);

// The confirmation names the source, size, destination and hash.
const confirm = downloadConfirmation({ ...base, available: offer });
assert.match(confirm.message, /only from apiaxess\.dev/);
assert.deepEqual(confirm.facts.map((fact) => fact.label), ["Version", "Download", "Installed size", "Installs to", "SHA-256"]);

assert.equal(formatSize(2048), "2 KB");
assert.equal(formatSize(300 * 1024 * 1024), "300 MB");
console.log("add-ons model: all states map correctly");
