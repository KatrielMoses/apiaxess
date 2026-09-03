# Repeater

The Phase 2.4 repeater is a manual, session-scoped request editor. A captured
flow can be copied into an independent context, where method, absolute URL,
headers, and body are edited without losing the original capture.

The captured request URL is retained as one exact value, including its original
scheme, authority, explicit port, path, and query. Legacy captures without an
exact URL are rejected with a persistence/request diagnostic rather than being
silently rewritten to HTTPS or having their port discarded.

Each send appends a numbered revision containing the exact request, response or
diagnostic, duration, and scope disposition. Failed sends are retained as
history entries, so the UI never implies that an attempt succeeded when it did
not. Any prior revision can be derived back into the current editor.

Contexts are persisted by `TrafficStore` and included in the existing
`workbench.traffic` canonical JSON session slot. Request and response bodies
are written through the same SHA-256 blob directory used by captured traffic;
the JSON session remains the portable authority and can rebuild a fresh
runtime store.

Repeater sends require an attached `ProxyRepeaterSender`. That sender targets
the running session `ProxyHandle` listener and trusts only the session CA, so
resends use the established routed proxy path. There is no direct-request
fallback. If the routed sender is absent, the attempt is recorded with
`proxy.repeater-transport-unavailable`.

The local API exposes:

- `POST /api/v1/workbench/repeater` with `{ "flowId": n }` to create from a
  captured flow, or `{ "request": ... }` for an explicit request.
- `GET /api/v1/workbench/repeater` and
  `GET /api/v1/workbench/repeater/<id>` to list/read contexts.
- `PUT /api/v1/workbench/repeater/<id>` to replace the current edit.
- `POST /api/v1/workbench/repeater/<id>/send` to append a send revision.
- `POST /api/v1/workbench/repeater/<id>/derive/<revision>` to edit from
  history.
