# Live traffic workbench

Phase 2.2 keeps the interactive surface inside the active session. The local
API remains bound to `127.0.0.1`; it does not create a persistent service.

## Transport boundary

The browser uses two authenticated WebSockets:

- `/api/v1/workbench/ws/control` is the reliable control channel. Intercept
  decisions are matched to a flow ID and delivered to a Rust oneshot. A
  timeout produces `proxy.intercept-timeout` and forwards the original request.
- `/api/v1/workbench/ws/telemetry` is the bounded display firehose. Updates are
  coalesced into batches and broadcast with lag detection. A lagging display
  receives `proxy.telemetry-backpressure`; it cannot delay the control path.

Both channels require the random token returned by the active-session bootstrap
endpoint and an exact `Origin: http://127.0.0.1:<port>`. Origin or token failure
returns the stable diagnostic `proxy.live-origin-rejected` or
`proxy.live-auth-rejected`.

Flow summaries remain bounded in memory for live rendering, while an attached
Phase 2.3 store receives the same request/response/body events. The selected
flow is fetched through `/api/v1/workbench/flows/<id>` from the durable store
when available, with memory as the live-session fallback. Bodies are never
sent on telemetry; the store keeps them as content-addressed SHA-256 blobs.

## Intercept lifecycle

The embedded hudsucker `ProxyBackend` receives the same
`InterceptController`/`FlowObserver` path used by the UI. Requests can be
forwarded, forwarded with a replacement method/header/body, or dropped. A host
filter can narrow matching to an engagement scope. Disabling interception
releases pending requests while telemetry continues. Closing the live session
disables interception, releases pending oneshots, clears in-memory flows, and
does not leave a listener or token behind.

Malformed edits and actions for completed flows produce
`proxy.intercept-edit-invalid` or `proxy.live-desync`; the original request is
never silently replaced by an invalid edit.
