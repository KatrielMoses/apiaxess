// Executable check: every update state the engine reports maps to the right
// banner and Settings panel (src/update/model.ts) — nothing offers an install
// the channel cannot do, and nothing installs mid-engagement.
import assert from "node:assert/strict";
import { formatBytes, lastCheckedText, updateView } from "../src/update/model.ts";

const now = new Date("2026-10-07T12:00:00Z");
const base = {
  enabled: true,
  currentVersion: "0.1.0",
  channel: "msi",
  checking: false,
  lastChecked: "2026-10-07T11:55:00Z",
  lastError: null,
  signature: "not_required",
  available: null,
  download: { state: "idle" },
  command: null,
  scheduled: false,
  lastInstall: null,
  busy: [],
};
const available = {
  version: "0.1.1",
  released: "2026-10-07",
  summary: "Faster fuzzing.",
  notesUrl: "https://apiaxess.dev/release-notes#0.1.1",
  supported: true,
  asset: { name: "APIaxess-0.1.1-windows-x64.msi", url: "https://apiaxess.dev/dl/0.1.1/APIaxess-0.1.1-windows-x64.msi", sha256: "ab".repeat(32), size: 457_179_136 },
};
const kinds = (notice) => notice.actions.map((action) => action.kind);

// Off: no banner, nothing to check.
let view = updateView({ ...base, enabled: false }, now, null);
assert.equal(view.banner, null);
assert.equal(view.canCheck, false);
assert.match(view.panel.title, /off/);

// Up to date / never checked / failed quietly: no banner.
view = updateView(base, now, null);
assert.equal(view.banner, null);
assert.match(view.panel.title, /up to date/);
assert.equal(view.lastChecked, "Last checked 5 min ago.");
assert.equal(updateView({ ...base, lastChecked: null }, now, null).lastChecked, "Not checked yet.");
view = updateView({ ...base, lastError: "could not reach apiaxess.dev" }, now, null);
assert.equal(view.banner, null, "an offline check stays quiet");
assert.match(view.panel.title, /Could not check/);

// MSI, available: Update downloads; "Later" hides the banner for that version.
view = updateView({ ...base, available }, now, null);
assert.deepEqual(kinds(view.banner), ["download", "open-url"]);
assert.match(view.banner.actions[0].label, /Update \(436 MB\)/);
assert.equal(updateView({ ...base, available }, now, "0.1.1").banner, null);
assert.notEqual(updateView({ ...base, available }, now, "0.1.0").banner, null);

// Downloading: progress, no actions.
view = updateView({ ...base, available, download: { state: "downloading", received: 228_589_568, total: 457_179_136 } }, now, "0.1.1");
assert.notEqual(view.banner, null, "progress shows even after Later");
assert.match(view.banner.body, /50% · 218 MB of 436 MB/);
assert.deepEqual(kinds(view.banner), []);

// Wrong hash: a clear failure and a retry.
view = updateView({ ...base, available, download: { state: "failed", message: "the download does not match its published SHA-256" } }, now, null);
assert.equal(view.banner.tone, "danger");
assert.match(view.banner.body, /SHA-256/);
assert.deepEqual(kinds(view.banner), ["download", "open-url"]);

// Ready and idle: restart installs now.
const ready = { ...base, available, download: { state: "ready", path: "C:\\x.msi" } };
view = updateView(ready, now, null);
assert.deepEqual(kinds(view.banner), ["install-now", "install-deferred"]);
assert.equal(view.banner.actions[0].disabled, false);

// Ready but busy: never mid-engagement.
view = updateView({ ...ready, busy: ["the capture browser is open"] }, now, null);
assert.equal(view.banner.title, "Update ready — installs when this session ends");
assert.deepEqual(kinds(view.banner), ["install-deferred", "install-now"]);
assert.equal(view.banner.actions[1].disabled, true);
assert.match(view.banner.body, /capture browser is open/);

// Scheduled: can cancel; restart is still offered once idle.
view = updateView({ ...ready, scheduled: true }, now, "0.1.1");
assert.notEqual(view.banner, null);
assert.deepEqual(kinds(view.banner), ["install-now", "cancel-deferred"]);

// Package managers show their command, never an in-app install.
for (const [channel, command] of [["scoop", "scoop update apiaxess"], ["chocolatey", "choco upgrade apiaxess"]]) {
  view = updateView({ ...base, channel, available, command }, now, null);
  assert.equal(view.banner.command, command);
  assert.deepEqual(kinds(view.banner), ["copy-command", "open-url"]);
}

// .deb: download + verify, then the apt command.
view = updateView({ ...base, channel: "deb", available }, now, null);
assert.deepEqual(kinds(view.banner), ["download", "open-url"]);
const aptCommand = "sudo apt install /home/op/.local/share/apiaxess/updates/apiaxess_0.1.1_amd64.deb";
view = updateView({ ...base, channel: "deb", available, download: { state: "ready", path: "/x.deb" }, command: aptCommand }, now, null);
assert.equal(view.banner.command, aptCommand);
assert.ok(!kinds(view.banner).includes("install-now"));

// Portable and source builds: no in-app download.
assert.deepEqual(kinds(updateView({ ...base, channel: "portable", available }, now, null).banner), ["open-url", "open-url"]);
assert.deepEqual(kinds(updateView({ ...base, channel: "source", available }, now, null).banner), ["open-url"]);

// Below min_supported: no in-place update offered.
view = updateView({ ...base, available: { ...available, supported: false } }, now, null);
assert.deepEqual(kinds(view.banner), ["open-url"]);
assert.match(view.banner.body, /too old to update in place/);

assert.equal(formatBytes(512), "512 B");
assert.equal(formatBytes(1536), "1.5 KB");
assert.equal(lastCheckedText({ ...base, lastChecked: "2026-10-01T00:00:00Z" }, now), "Last checked on 2026-10-01.");
console.log("update model: all states map correctly");
