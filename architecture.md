# APIaxess architecture map

A pointer map to the backbone. For each capability: what it does + the file(s) to
read first. Deeper design rationale lives in [`docs/architecture/`](docs/architecture/);
the crate-boundary rules live in [`docs/architecture/repository-map.md`](docs/architecture/repository-map.md).

## The spine (read these first)

- **Composition root / CLI** — [`apps/engine/src/main.rs`](apps/engine/src/main.rs).
  Parses the subcommands (`analyze`, `web`, `browse`, `discover`, `export`, `serve`),
  builds the engine, and starts the loopback server. Subcommand-less launch = headless `serve`.
- **Orchestration shell** — [`crates/engine-shell/src/lib.rs`](crates/engine-shell/src/lib.rs)
  and the analysis pipeline in [`crates/engine-shell/src/pipeline.rs`](crates/engine-shell/src/pipeline.rs)
  (intake → static → dynamic → fusion → confidence → surface → signing → export stages).
- **Canonical data model** — [`crates/api-model/src/`](crates/api-model/src/): per-fact
  candidates + `provenance.rs`, merge state in `confidence.rs`, `fact.rs`, the unified
  `unified.rs`/`api.rs` surface, and versioned durable JSON in `document.rs`.
- **Transport** — [`crates/local-api/src/lib.rs`](crates/local-api/src/lib.rs) serves the
  loopback HTTP API + the built GUI (`ServeDir` over `apps/gui/dist`); settings in `settings.rs`.
- **Disciplines that cut across everything** — diagnostics (what/why/fix) in
  [`crates/diagnostics/src/lib.rs`](crates/diagnostics/src/lib.rs); scope/audit/persistence in
  [`crates/session/src/`](crates/session/src/) (`scope.rs`, `audit.rs`, `session.rs`, `document.rs`);
  confidence honesty in [`crates/confidence/src/lib.rs`](crates/confidence/src/lib.rs).
  These four are asserted by [`xtask`](xtask/src/main.rs) (`foundations`, `boundaries`, `contracts`).

## Capabilities

- **APK intake** — resolve/unpack an APK(m) into a workspace: [`plugins/targets/apk/src/lib.rs`](plugins/targets/apk/src/lib.rs)
  (path-traversal guards, size-scaled tool timeouts, layered cleanup: armed `IntakeWorkspaceGuard`
  Drop → `disarm()` on success → explicit `cleanup_intake_workspace` → 24h age-reap) and
  [`crates/artifact-intake/src/lib.rs`](crates/artifact-intake/src/lib.rs). Bundled apktool/jadx/JRE
  resolution: [`plugins/targets/apk/src/bundled.rs`](plugins/targets/apk/src/bundled.rs).
- **Static extraction** — decompile-and-scan for endpoints, libraries, protection markers:
  [`crates/static-pass/src/lib.rs`](crates/static-pass/src/lib.rs) (the intentional
  `APIAXESS_PROFILE_STATIC` instrumentation lives here), endpoint recovery in
  [`crates/network-extraction/src/lib.rs`](crates/network-extraction/src/lib.rs), routing/scope in
  [`crates/network-routing/src/lib.rs`](crates/network-routing/src/lib.rs), protection signals in
  [`crates/protection-detector/src/`](crates/protection-detector/src/).
- **Dynamic capture** — sample-gated runtime observation and requiredness:
  [`crates/dynamic-capture/src/lib.rs`](crates/dynamic-capture/src/lib.rs).
- **Sandbox backends** — device/emulator tiers behind one port:
  [`crates/sandbox/src/lib.rs`](crates/sandbox/src/lib.rs) (`DynamicBackendFactory::backend_for_tier`,
  `BundledEmulatorBackend`/`AvdBackend`), stealth in `stealth.rs`, runtime trust in `runtime_trust.rs`,
  traffic in `traffic.rs`.
- **Transparent interception** — redirect + splice raw client traffic (SNI parse) into the proxy:
  [`crates/workbench-proxy/src/transparent.rs`](crates/workbench-proxy/src/transparent.rs).
- **Frida / pinning bypass** — [`crates/sandbox/src/pinning.rs`](crates/sandbox/src/pinning.rs)
  driving the embedded Frida controller [`crates/sandbox/src/frida_embedded.rs`](crates/sandbox/src/frida_embedded.rs)
  (feature `frida-embedded`); crypto hook payload in [`crates/crypto-capture/src/lib.rs`](crates/crypto-capture/src/lib.rs).
- **App crawler** — autonomous state-graph traversal (replaces the Monkey exerciser):
  [`crates/app-crawler/src/`](crates/app-crawler/src/): `state.rs` (graph), `device.rs` (adb),
  `hierarchy.rs` (view tree), `heuristics.rs` (login/OTP detection), `credentials.rs` (no-leak
  credential layer), `report.rs` (honest coverage), `fallback.rs` (intentional DroidBot seam).
- **Fusion** — merge static + dynamic + capture into the canonical surface, retaining every
  candidate and its provenance: [`crates/fusion/src/lib.rs`](crates/fusion/src/lib.rs); final
  assembly + signer binding in [`crates/unified-surface/src/lib.rs`](crates/unified-surface/src/lib.rs).
- **Workbench proxy (resend / fuzzer / live proxy)** — capture and replay:
  [`crates/workbench-proxy/src/`](crates/workbench-proxy/src/): `backend.rs` (`ProxyBackend`
  trait + hudsucker backend + flow-id/observer wiring), `live.rs` (`FlowEvent`/`FlowObserver`),
  `resend.rs`, `fuzzer.rs`, CA/trust in `ca.rs`/`trust.rs`, bundled Chromium in `bundled.rs`.
- **Web capture + fusion** — HAR import and live web session capture flow into the same store
  and fusion path; import/classification entry in [`crates/workbench-store/src/lib.rs`](crates/workbench-store/src/lib.rs)
  (`import_har`, `TrafficStore::upsert`, `FlowRedactor` choke-point).
- **Discovery** — probe-and-confirm surface discovery via the engine `discover` subcommand
  (see [`apps/engine/src/main.rs`](apps/engine/src/main.rs)); bundled ffuf resolution in external-tools.
- **Artifact export** — OpenAPI 3.1 / Python httpx / Postman+HAR emitters:
  [`crates/openapi-emitter/src/lib.rs`](crates/openapi-emitter/src/lib.rs),
  [`crates/python-sdk-emitter/src/lib.rs`](crates/python-sdk-emitter/src/lib.rs),
  [`crates/collections-emitter/src/lib.rs`](crates/collections-emitter/src/lib.rs); wired in
  [`crates/engine-shell/src/export.rs`](crates/engine-shell/src/export.rs).
- **Crypto signer chain (Phase 4, staged)** — scheme detection → canonicalization → signer IR:
  [`crates/crypto-scheme-detection/`](crates/crypto-scheme-detection/src/lib.rs) →
  [`crates/crypto-canonicalization/`](crates/crypto-canonicalization/src/lib.rs) →
  [`crates/crypto-signer-ir/`](crates/crypto-signer-ir/src/lib.rs). Built and unit-tested;
  the pipeline Signing stage is currently an honest skip (see flagged items in the audit).
- **Sessions / persistence** — engagement scope, API document, append-only audit, opaque
  workbench slot, one versioned durable JSON envelope: [`crates/session/src/session.rs`](crates/session/src/session.rs)
  + `document.rs`; runtime glue in [`crates/engine-shell/src/session_runtime.rs`](crates/engine-shell/src/session_runtime.rs).
- **External-tool boundary** — the *only* place allowed to own child processes (enforced by
  `xtask boundaries`): [`crates/external-tools/src/lib.rs`](crates/external-tools/src/lib.rs)
  (`ManagedProcess`, probe/invoke/version types). Capability tiers in
  [`crates/host-capabilities/src/lib.rs`](crates/host-capabilities/src/lib.rs).
- **Plugin contract** — one gated, reference-based Protobuf IDL spanning trusted Rust / WASI /
  process-RPC plugins: [`contracts/plugin/`](contracts/plugin/) (`INTERFACES.md` + `apiaxess/plugin/**`).
  Engine-facing seam: [`crates/plugin-host/src/lib.rs`](crates/plugin-host/src/lib.rs) (placeholder in 0.x).
- **GUI** — TypeScript local web client, built by vite, served by the engine:
  [`apps/gui/src/main.ts`](apps/gui/src/main.ts) (feature wiring), `src/ui/` (reusable pieces),
  `src/brand/` + `src/styles/tokens.css` (brand/theme).
- **Native desktop app** — Tauri shell that spawns/kills the engine and hosts the served GUI:
  [`apps/desktop/src/main.rs`](apps/desktop/src/main.rs).
- **Installers / packaging** — MSI + .deb inputs bundling the Phase-11 tools into the resolver
  layout: [`packaging/windows/`](packaging/windows/) and [`packaging/debian/`](packaging/debian/).

## Where a new traffic-source plugs in (next phase)

The multi-client traffic-inspection layer has two honest entry points, both already exercised:
implement `ProxyBackend` and emit `FlowEvent`s to a `FlowObserver`
([`crates/workbench-proxy/src/backend.rs`](crates/workbench-proxy/src/backend.rs),
[`live.rs`](crates/workbench-proxy/src/live.rs)), or write provenance-tagged `FlowCapture`
rows straight to `TrafficStore::upsert` through the `FlowRedactor` choke-point
([`crates/workbench-store/src/lib.rs`](crates/workbench-store/src/lib.rs)) — exactly what HAR
import and the transparent path do today. See `architecture-audit.md` for the two structural
items (flow-id allocation, request↔response correlation) to resolve before a second concurrent
source is wired in.
