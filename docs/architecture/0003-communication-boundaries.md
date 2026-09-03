# ADR 0003: Communication boundaries

**Status:** accepted at boundary level; payload contracts deferred

## GUI to engine

The engine is the only local server. It serves immutable GUI assets and a
versioned API under `/api/v1` on `127.0.0.1` (and optionally `::1`) only.

- JSON over HTTP is the command/query baseline.
- Server-Sent Events are the default for ordered job progress and event streams.
- WebSocket is reserved for genuinely bidirectional, latency-sensitive workbench
  sessions; it is not the default transport.
- Large evidence/artifact bytes use streamed endpoints, not JSON/base64.
- The UI never reads engine files or databases directly and never launches tools.

Only a minimal `/api/v1/system/status` skeleton exists in 0.1. Authentication,
authorization, error envelopes, resource payloads, and session semantics belong
to later phases. Until authorization is designed, the server must not expose a
non-loopback bind option.

## Engine to plugins

The engine calls only the internal plugin-host port in `crates/plugin-host`.
That host owns discovery, compatibility negotiation, lifecycle, isolation, and
invocation. Target and brain implementations live under distinct roots in
`plugins/targets` and `plugins/brains`; neither is imported directly by the
engine.

The semantic direction is stable even though the physical language boundary is
open: engine request -> plugin host -> selected implementation -> typed result
and evidence. Whether the last hop is a Rust trait or a supervised process/RPC
protocol is the explicit 0.3 decision.

## Engine to tools and sandboxes

The engine submits intent-level work to `crates/external-tools`; adapters own
tool-specific invocation and evidence collection. Dynamic analysis is submitted
to `crates/sandbox`; a backend may be local or remote and may itself delegate
tool execution to the tool runtime. Neither boundary leaks shell commands,
Docker objects, or remote-host paths into engine or GUI types.

## Stability rule

Transport DTOs, plugin DTOs, and domain types are different layers. Mapping is
explicit at their owning boundary. API/plugin protocol versions advance without
changing internal domain types, and internal refactors do not silently alter a
wire format.

