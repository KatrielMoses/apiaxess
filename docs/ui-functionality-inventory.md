# APIaxess GUI — functionality inventory & current-UI description

Purpose: complete map of every navbar functionality and the current UI, as the
baseline for overhauling the inner GUI into a true desktop application (away from
"a website inside a container"). Source-grounded from `apps/gui/` on 2026-09-15.

## 0. Architecture of the thing being replaced
- **Single-page shell.** `apps/gui/index.html` (~1,050 lines) contains all **11
  surfaces** as `<section data-view="…" hidden>` blocks. `apps/gui/src/main.ts`
  (~3,076 lines) wires every control. `src/ui/nav.ts` toggles views by setting
  `hidden` — **all views stay mounted for the session's life** so element identity
  (and every live region the engine streams into) is stable. Redesign must keep
  the streaming containers alive across view switches (or re-architect streaming).
- **Routing.** Hash-based (`#apk`, `#web`, …); nav is `[data-nav]` triggers; the
  rail has a responsive overflow edge-fade (`trackNavOverflow`).
- **Transport.** Loopback HTTP + **two WebSockets**:
  - `…/api/v1/workbench/ws/control` — **reliable control** ("Live control connected").
  - `…/api/v1/workbench/ws/telemetry` — **lossy** live-traffic stream.
- **Auth.** Operator bearer token (from `GET /api/v1/workbench/session`) + origin
  pinning; all surfaces loopback-only.
- **Shared UI systems.** `ui/overlay.ts` (modal dialogs), `ui/diagnostics.ts`
  (right-hand Diagnostics drawer), `ui/toast.ts` (toasts), `ui/theme.ts`
  (dark default, pre-paint), `brand/` (logo + icons).

## 1. Persistent chrome (top bar, always visible)
- Brand wordmark (a11y: currently reads "apiaess" — logo glyph lacks a text alt).
- **Session chip** — truncated active session id.
- **"Live control connected"** status dot (driven by the control WS).
- **Diagnostics** button (⚠) → slide-in drawer listing engine diagnostics with
  what/why/fix; shows a live count badge. (Uses a permanent ⚠ even at zero — a
  redesign fix target.)
- **Theme toggle** (dark/light, display-only, no restart).
- **Settings** (gear) → view 10. **About/help** (?) → view 11.

## 2. The 11 surfaces

### 1) Start  (`#start`)
- Hero + two entry cards: **Android APK** (STATIC + DYNAMIC) and **Web domain**
  (START HERE), each with a 3-step summary; three value notes (local / honest
  coverage / authorization). Pure navigation; no backend.

### 2) APK analysis  (`#apk`)
- **Artifact**: APK path + Browse (native `pick-file`), Run ID (auto), Intake
  output root (default); **Passes**: "Run the sandbox dynamic pass" vs "Static
  only" (mutually exclusive); **Run pipeline** (confirm-before-run modal) +
  Refresh status.
- **Scope** (advisory) card.
- **Analysis pipeline**: run id/artifact/dynamic/updated + progress bar + stage
  pills INTAKE→STATIC→DYNAMIC→SIGNING→FUSION→CONFIDENCE→SURFACE; View surface / Export.
- **Pipeline diagnostics**: streamed diagnostics for the run.
- Backend: `POST /api/v1/pipeline`, `GET /api/v1/pipeline/{id}`, `pick-file`.

### 3) Web capture  (`#web`)
- **Target**: URL + "I am authorized to test this target" affirm → **Start web
  session** (records audit, sets scope).
- **Capture browser** (bundled Chromium): Launch/Stop + **Capture health** rows
  (session proxy / capture browser / captured traffic).
- **Fuse and export**: Fuse captured traffic / Export artifacts.
- **Active discovery**: type (Directories/paths | Subdomains), wordlist
  (Small/Medium/Large), **Estimate** (request count/rate/duration) / **Run
  discovery** / Cancel; **Discovery results** (confirmed hits).
- Backend: `session/web`, `workbench/browser`, `workbench/health`, `web/fuse`,
  `discovery/estimate`, `discovery/run`.

### 4) Android target  (`#android`)
- **Launch / Stop** a GUI-drivable AVD.
- **Status** step indicator (boot → provision → stream → ready).
- **Install target APK** (path + Browse → adb install).
- **Screen**: embedded live device stream via the engine's authenticated
  `/android-stream` reverse-proxy (touch-drivable).
- Backend: `android-target/{status,launch,stop,install-apk}`, `/android-stream`.

### 5) Workbench  (`#workbench`, full-width)
- Toolbar: **Intercept matching requests** toggle + intercept-host filter (not the
  engagement scope); **Import HAR** / **Export HAR**; flow counter.
- **Live traffic** (lossy telemetry) — rows stream in.
- **Intercept queue** (reliable control) — paused requests: **Forward /
  Forward modified / Drop**.
- **Select a flow** → request/response metadata + in-flight editor
  (method/headers/body).
- **Resend** and **Fuzzer** drawers (`#resend-panel`, `#fuzzer-panel`),
  populated by "Send to Resend/Fuzzer" from a flow or from the API surface.
- Backend: `workbench/{flows,flows/{id},intercept/pending,resend,resend/…,
  fuzzer,fuzzer/…,har,diagnostics,health}` + 2× WS.

### 6) Devices  (`#devices`)
- **Refresh devices**; **Attached devices** (rooted, over adb).
- **Workbench CA fingerprint** (SHA-256; must match device before accepting).
- **Pairing code** (arm a device → one-time code / QR).
- **Awaiting decision** (accept/decline scanned pairing requests).
- Backend: `pairing/{ca,arm,devices,pending,pending/{id}/accept|decline}`.

### 7) API surface  (`#surface`)
- Stat tiles: **endpoints / confirmed / inferred / static-only / signers**.
- **Honest-coverage** banner (what's unconfirmed, handoffs open/resolved).
- **Endpoints** list: method + path + confidence + provenance; expand → request
  (method/url/headers) & response (or "none observed"); **Send to Resend /
  Send to Fuzzer**.
- **Provenance** (assembly run / schema / signers) + **Surface diagnostics**.
- Backend: `GET /api/v1/surface`.

### 8) Export  (`#export`)
- **Formats**: OpenAPI 3.1 / Python SDK / Postman collection / HAR (checkboxes).
- **Output directory** (relative to engine cwd) → **Export**.
- **Result**: written paths / formats, or failure.
- Backend: `POST /api/v1/export`. (Session-scoped — must match the surface shown.)

### 9) Session  (`#session`)
- **New / Open… (by artifact path) / Save**.
- **Status**: flows / resends / fuzzer jobs counts, session id, lifecycle,
  target type, artifact + store paths, checkpoint.
- **Audit trail**: durable, timestamped, typed records (authorization affirms,
  pipeline stages incl. "skipped honestly", exports incl. failures).
- Backend: `session`, `session/{new,open,save,audit}`.

### 10) Settings / Configuration  (`#settings`)
- **Appearance** (theme).
- **Bundled tools** resolution panel ("N of N resolved": java, apktool, jadx,
  ffuf, chromium, analysis-runtime, android-target) with PRESENT / OVERRIDE /
  ENVIRONMENT-OVERRIDE badges + real paths.
- **Network**: workbench UI listener, intercepting proxy listener.
- **Dynamic analysis**: analysis-runtime location, GUI android-target location.
- **Tool paths (advanced)** overrides (with "wrong path breaks resolution" warning).
- **Save changes** (persist to app config; env always wins; effective on restart).
- Backend: `GET/PUT /api/v1/settings`, `system/status`.

### 11) About  (`#about`)
- **Build** (service / API version / effective endpoint / identity).
- **Keyboard** (Esc = diagnostics drawer / close dialog; Enter = confirm).
- **Identity** (kit version + logo).

## 3. Cross-cutting concepts to carry into the desktop redesign
- **Session is the spine.** Traffic, resend, fuzzer, pipeline, surface, audit,
  and scope all belong to the active session. Unify the *displayed* surface with
  the *session-scoped* actions (Export / Send-to-Resend) — today they can diverge.
- **Honest coverage.** Confidence + provenance per endpoint; unconfirmed shown as
  such, never fabricated.
- **Authorization gating.** Active work requires an affirmed, audited scope.
- **Two-tier transport.** Reliable control vs lossy telemetry — reflect the
  distinction in the UI.
- **Diagnostics as a first-class surface** (drawer), with aggregation (today it can
  firehose dozens of per-finding cards).
- **Self-contained + local.** Everything on 127.0.0.1; bundled tools resolved
  install-relative; nothing uploaded.

## 4. Desktop-app framing opportunities (why it feels like a website now)
- Top nav rail reads like a website menu → a desktop app wants a **persistent left
  sidebar / activity bar** + **titlebar** with global session/scope/connection state.
- Surfaces are long scrolling pages → desktop wants **fixed panes, splitters,
  density**, and per-pane scroll (Workbench already hints at this with full-width).
- Modals/toasts/drawers exist but are web-flavored → unify into a desktop
  **command surface** (command palette, status bar, dockable panels).
- The **Workbench** (Burp-like) is the natural centerpiece for a desktop layout;
  Start/About are the least "app-like" and can shrink.
