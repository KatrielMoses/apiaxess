# Phase 11.3 — Proxy: dropped mitmdump for hudsucker (audit-first)

Date: 2026-08-29

Phase 11 makes the product need nothing on the host. The proxy had two backends:
the embedded Rust **hudsucker** (compiled in, zero external dependency) and an
external **mitmdump** (mitmproxy — a Python tool). This sub-phase audited what
mitmdump was actually used for and, on the facts, removed it.

## Audit (before deciding)

- **Backend selection:** production used `ProxyCore::new()` → `RoutedProxyBackend`,
  a router that sniffed each connection and sent HTTP/1.1 + WebSocket-over-h1 to
  hudsucker and **HTTP/2** (TLS-ALPN h2, cleartext h2 prior-knowledge, gRPC) to
  mitmdump.
- **What mitmdump did:** capture only. Its Python addon emitted the *same*
  `FlowEvent`s (request/response/websocket) into the *same* observer/store as
  hudsucker. It ignored the intercept controller entirely, used **no** `.mitm`
  flow format, **no** replay, and **no** mitmproxy addons beyond a tiny RFC 8441
  (WebSocket-over-h2) detector — which was **already reimplemented in Rust** in
  `backend.rs`. Both backends only *detected and rejected* RFC 8441.
- **hudsucker capability:** hudsucker 0.25 already had the `http2` feature
  compiled in; h2 only went to mitmdump because the upstream connector was
  `.enable_http1()`-only and the router diverted h2. Nothing outside the
  workbench-proxy crate constructed a backend; `probe_mitmdump`/`probe_mitmproxy`
  were dead; there was no host-capabilities Python probe and no mitmproxy Cargo
  dependency.

Conclusion: mitmdump served exactly one thing — HTTP/2 capture — that hudsucker
can do itself.

## Decision: drop mitmdump

Enable HTTP/2 on hudsucker's upstream connector (`.enable_http2()`) and route
everything through the embedded hudsucker backend. This removes the entire
Python dependency surface and the mitmdump orphan-process/cold-start bug class,
with no capability regression (RFC 8441 remains a documented known limitation,
still detected in Rust and surfaced as `proxy.websocket-http2-unsupported`).

## Verification (hudsucker covers the real workflows — no host Python)

Wire-level, self-contained (`crates/workbench-proxy/tests/hudsucker_http2.rs`,
raw TLS + h2 clients/servers across the public listener, no external tool):

- **TLS-ALPN HTTP/2** — client negotiates h2 with the MITM leaf; upstream h2
  connect; body returned (200, `h2-simple`).
- **HTTP/2 stream multiplexing** — three concurrent streams observed
  independently.
- **gRPC trailers** — `grpc-status: 0` trailer preserved end-to-end through the
  hudsucker MITM pipeline.
- **Capture into the durable store** — an h2 flow lands in `TrafficStore`
  summaries via the `LiveWorkbench` observer (the same path the web-capture and
  workbench/repeater/intruder flows use).

Existing hudsucker unit tests continue to cover HTTP/1.1 capture into the store
(`origin_form_is_normalized_…`) and per-flow intercept (forward/modify/drop +
timeout). The engine's web-capture path (`ProxyCore::new()` →
`start_with_intercept`) now runs on hudsucker end-to-end.

All four h2 tests pass; the full workbench-proxy suite is green.

## Clean removal

- Deleted: `crates/workbench-proxy/src/mitmdump.rs`, `gate.rs`, `routing.rs`,
  `tests/acceptance_gate.rs`, `docs/workbench-proxy/acceptance-gate.md`.
- `backend.rs`: removed `RoutedProxyBackend` and all routing/H2-sniffing helpers;
  `BackendKind` is now just `Hudsucker`; `ProxyCore::new()` uses hudsucker;
  `ProxyHandle` dropped its external-process/child fields; `BackendHealth` moved
  here as a hudsucker-only `{ hudsucker_available }`.
- Diagnostics removed: `proxy.mitmdump-unavailable`, `proxy.mitmdump-start-failed`,
  `proxy.mitmdump-teardown-failed`, `proxy.acceptance-gate-failed`,
  `proxy.acceptance-oracle-unavailable`, `proxy.backend-route-unavailable`
  (and their `PHASE_2_1` membership).
- `local-api`/`engine-shell` health passthrough kept; `apps/gui` capture-health
  panel now reads only `hudsuckerAvailable` and shows "Intercepting via the
  embedded hudsucker proxy."; the `APIAXESS_CAPSTONE_USE_MITMDUMP` test switch is
  gone.

## Host-independence achieved

The proxy needs nothing on the host: it is the compiled-in hudsucker backend. No
host Python, no host mitmproxy. This also retroactively validates building both
backends in Phase 2 — hudsucker-alone is the answer.

## Out of scope

Frida (11.4), emulator (11.5); installers (Phase 12). Linux verification is
**done** — see [phase-11-linux-verification.md](phase-11-linux-verification.md):
the hudsucker h1 + h2 capture tests pass on Linux with no host Python.
