# Resend

The Phase 2.4 resend is a manual, session-scoped request editor. A captured
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

Resend sends require an attached `ProxyResendSender`. That sender targets
the running session `ProxyHandle` listener and trusts only the session CA, so
resends use the established routed proxy path. There is no direct-request
fallback. If the routed sender is absent, the attempt is recorded with
`proxy.resend-transport-unavailable`.

The local API exposes:

- `POST /api/v1/workbench/resend` with `{ "flowId": n }` to create from a
  captured flow, or `{ "request": ... }` for an explicit request.
- `GET /api/v1/workbench/resend` and
  `GET /api/v1/workbench/resend/<id>` to list/read contexts.
- `PUT /api/v1/workbench/resend/<id>` to replace the current edit.
- `POST /api/v1/workbench/resend/<id>/send[?timeoutSecs=n]` to append a send
  revision. The send waits at most `timeoutSecs` (default 30, clamped to
  1–300) and is then recorded with `proxy.resend-timed-out`.
- `POST /api/v1/workbench/resend/<id>/follow/<revision>[?cookies=false&timeoutSecs=n]`
  to follow one redirect hop as a new revision.
- `POST /api/v1/workbench/resend/<id>/cancel` to stop an in-flight send or
  follow. The pending send returns with a `proxy.resend-cancelled` revision.
  Dropping the exchange closes the proxy connection, which closes the
  upstream connection too.
- `PUT /api/v1/workbench/resend/<id>/name` with `{ "name": "…" }` (null or
  blank clears) to set the item's name. Names are stored with the context and
  travel with the session export.
- `POST /api/v1/workbench/resend/<id>/derive/<revision>` to edit from
  history.

When the upstream exchange fails (connection refused, DNS, TLS, the proxy's
own timeout), the proxy's synthetic `502` carries a private
`x-apiaxess-upstream-error` marker. The sender reports it as
`proxy.upstream-unreachable` with the `target` and the underlying `error`, so a
transport failure is never recorded as a server response.
