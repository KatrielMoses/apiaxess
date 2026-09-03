# Autonomous app-crawler and secure credential handling

Replaces the shallow 30-event Monkey exerciser (which captured 0 flows on quiet/
FOSS/login-gated apps) with an autonomous state-graph UI crawler, plus a secure,
in-memory-only, redacted-from-capture credential layer so login-gated apps can be
crawled. The crawler *drives* the app over ADB; the workbench proxy captures the
traffic it provokes out-of-band.

Crate: `crates/app-crawler` (`apiaxess-app-crawler`). Wired into the dynamic
pipeline at `crates/engine-shell/src/pipeline.rs::drive_bundled_dynamic`.

## Primary crawler (build-primary)

- **State-graph traversal.** `uiautomator dump` → parse the hierarchy
  (`hierarchy.rs`, quick-xml) → normalize a state signature (`state.rs`:
  activity + the sorted, de-duplicated set of actionable-node signatures, with
  volatile text/counters/list-content stripped by anchoring on
  `resource-id`/`content-desc`) → maintain a visited-state set and a per-state
  frontier of untried `(state, action)` pairs → fire the highest-priority untried
  action → re-dump. Identical list rows collapse to a single action, so infinite
  lists never become infinite taps.
- **API-surface-tuned.** Actions whose label/id/description suggest a network
  call (refresh, load, search, submit, feed, next, …) are explored first
  (`state.rs::NETWORKY_HINTS`). Thoroughness over speed.
- **Budgeted** (`CrawlConfig`): total time budget, per-state action budget,
  per-activity budget, scroll-to-exhaust repeat cap, state revisit cap.
- **Robust** (`heuristics.rs`): permission/consent dialogs are auto-granted;
  onboarding/rate/update dialogs dismissed; login and OTP gates detected. Stall
  recovery: BACK, then restart-to-launcher + shortest-path replay to the nearest
  state with untried actions (parent edges recorded on first discovery).
- **Honest split-coverage telemetry** (`report.rs`): states/activities visited
  and actions fired, split pre-auth / post-auth, plus login gates encountered,
  credential values injected (count only), OTP prompts, walls left uncrossed, and
  actions left untried. Never an inferred "% of API" — the tool has no ground
  truth for the full surface, so any percentage would be fabricated.

## Secure credential handling

Two prompt moments (`CredentialProvider`):

1. **Pre-run** (GUI, before the run): "Does this app require sign-in?" →
   [Feed credentials now] / [Try anyway, prompt if stuck] / [Skip dynamic]. Fed
   credentials ride the loopback `POST /api/v1/pipeline` body and are wrapped as
   `Secret` immediately.
2. **Mid-crawl** (live): when the crawler stalls at a login/OTP screen it raises
   a blocking prompt over the session workbench (`CredentialPromptController` on
   the session-scoped `LiveWorkbench`, mirroring `InterceptController`): the
   prompt (field shapes only, never values) is announced over telemetry; the
   operator's answer returns over the control channel (`ControlMessage::AnswerPrompt`).
   OTP is human-in-the-loop — the operator types the code from their real device.

Security contract (all enforced in code):

- **Never persisted.** Values live only in memory as `Secret` (`zeroize`
  zero-on-drop). No disk, session file, config, or cache.
- **Never captured in the traffic store.** This is the subtle part: we capture
  through our own proxy, so the login request carrying the password/OTP *would*
  be captured unless scrubbed. Each value is registered with a
  `CredentialRedactor` (implements `apiaxess_workbench_store::FlowRedactor`)
  **before** it is typed, and the redactor is installed on the durable store via
  `TrafficStore::set_redactor` **before the crawl begins**. `TrafficStore::upsert`
  scrubs every flow (URL/query, headers, request/response bodies) on an owned
  copy before any blob or metadata touches disk — the single choke-point all
  capture paths funnel through. Redaction covers the raw value plus its
  percent-encoded, form-encoded, and JSON-escaped forms. It is *precise*: only
  the operator's exact values are scrubbed; legitimately captured bearer tokens
  from other flows remain intact (they are the API surface we exist to reveal).
- **Never in logs/diagnostics/errors.** `Secret`'s `Debug`/`Display` render
  `Secret([redacted])`; `PipelineConfig`'s `Debug` prints only a staged-count.
- **Verifiable no-leak.** `app-crawler` test
  `injected_credentials_never_reach_the_store_on_disk` writes a flow carrying the
  value into a real on-disk store with the redactor armed, then greps every file
  under the store root (sqlite + content-addressed blobs) and asserts the value
  appears nowhere.

Out of scope (designed-for-later extension point, not built): manual user
sign-in / take-control handback (the operator driving the emulator directly).

## DroidBot fallback (MIT) — bundling status and SBOM

DroidBot is bundled as an **accelerator / reference / fallback** for the case the
primary traverser stalls early on a quiet or unusually structured app
(`fallback.rs`, `FallbackEngine` + `DroidBotFallback`). The primary hands off to
it when it exhausts its frontier with almost no coverage.

- **License:** MIT. Retain the DroidBot MIT notice in the bundled runtime
  directory and add DroidBot + its pinned Python runtime and dependencies to the
  product SBOM alongside the other bundled analysis tools (JRE, apktool, jadx,
  ffuf, Chromium, QEMU/Android-10).
- **Invocation model:** DroidBot is a host-side Python tool that drives the
  device over adb. `DroidBotFallback::resolve()` discovers the bundled launcher
  in the same resolver layout as the other bundled tools
  (`runtime/droidbot/` on Windows, `share/apiaxess/droidbot/` on Linux) or via
  `APIAXESS_DROIDBOT`.
- **Deferred to the bundled-tools packaging phase (honest status):** vendoring
  the pinned Python runtime + DroidBot and wiring the live host-process
  invocation against the emulator serial is a packaging step, exactly as each
  other bundled tool got its own phase. Until that runtime is vendored,
  `DroidBotFallback::run()` resolves the launcher by path and reports honestly
  that it is unavailable (recorded as a crawl note) rather than pretending to
  have run. The seam, resolver, license/SBOM obligations, and invocation point
  are in place; the actual Python-runtime vendoring + live wiring + on-device
  verification belong to the real-environment packaging run.

APE (Apache-2.0) is an optional future secondary; not built.

## What is verified vs. what needs the live emulator

Verified here (offline, `cargo test`): the whole engine against a mock device
(pre-auth crawl → login detection → credential injection → post-auth crawl),
dialog/login/OTP detection, split-coverage telemetry, the fallback hand-off on a
quiet app, all redaction encodings, and the on-disk no-leak grep.

Needs the live bundled emulator + a real APK (carry into the real-target run):
real UI dumps from a running app, actual flow capture proving the 0-flows failure
is resolved, a credential-assisted crawl on a real login-gated app, and the
no-leak grep across a real credential-assisted run's store/surface/exports/logs.
