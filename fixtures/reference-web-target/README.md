# Reference web target

A small local site whose complete request set we know exactly. It is used to measure how completely and
correctly APIaxess's web capture records and fuses what a browser does: REST, a third-party host,
WebSocket, Server-Sent Events, GraphQL and gRPC-Web. It is the web counterpart of
[`../reference-target/`](../reference-target/) (the APK ground truth).

- **Ground truth:** [`GROUND_TRUTH.md`](GROUND_TRUTH.md) (tables) and [`ground-truth.json`](ground-truth.json)
  (machine-readable and authoritative: the server reads it).
- **No dependencies:** one Node script (Node 18 or newer), using only the standard library. The WebSocket
  server is implemented directly (RFC 6455).
- **No login and no navigation:** everything fires on page load or from one of seven buttons.

## Run

```bash
node server.mjs          # or ./run.sh
```

- First-party site: `http://127.0.0.1:9201/`
- Third-party service: `http://localhost:9202/`

Change the ports with `--port` and `--third-party-port`. If you do, the manifest's `origins` must match.

Both listen on loopback only. The server logs every request with its manifest ID, or as `UNDOCUMENTED`.
It also logs WebSocket messages, SSE events, GraphQL operation names and the gRPC-Web message. For a
running summary:

```bash
curl http://127.0.0.1:9201/__ref/coverage
# seen 16/16 documented requests, 0 undocumented
```

The same summary prints on Ctrl-C. `/__ref/coverage` is harness-only: the page never calls it and it is
not counted. Call it directly, not through the capture proxy.

## Capture it with APIaxess

1. Start a web session with target `http://127.0.0.1:9201` and launch the capture browser. It opens the
   page, which fires the load requests.
2. Click the seven buttons: `Create item`, `Update item`, `Delete item`, `Load order`, `Search`,
   `Add to cart (GraphQL)` and `Checkout (gRPC-Web)`. The page's log shows each response.
3. Optional: add `localhost` to the scope, so the third-party calls (W14/W15) fuse too.
4. Fuse, save the fused surface, and score:

```bash
curl -s -X POST -H "Origin: http://127.0.0.1:7777" http://127.0.0.1:7777/api/v1/web/fuse > surface.json
python score.py ground-truth.json surface.json score.json --engine http://127.0.0.1:7777
```

`--engine` reads the capture side live: HTTP flows, the WebSocket connection and its messages, and the
SSE events. To keep a run for later, dump it and score from the file:

```bash
python score.py --dump http://127.0.0.1:7777 capture.json
python score.py ground-truth.json surface.json score.json --capture capture.json
```

A dump contains every flow in the session, including the capture browser's own background traffic,
so treat it as a local run artifact and don't commit it.

### What the scorer reports

- **REST endpoints (fused surface).** Each manifest endpoint is matched by method + host + path skeleton
  (`template`). If that fails it falls back to the concrete sample path (`concrete`: under-templated), then
  to any method (`wrong-method`), and otherwise it is a `MISS`. It checks the party label, query names,
  the manifest's extra headers, request-body keys and whether responses were recorded. Unmatched surface
  endpoints are `PHANTOM`s. The WebSocket handshake or the gRPC-Web call appearing as a REST endpoint is a
  `LEAK`. A third-party miss is annotated when no endpoint exists on that host at all (out of scope).
- **Protocol operations:** GraphQL `type name` (with its endpoint URL) and gRPC `service/method`.
- **Captured HTTP flows:** the capture layer, before fusion, so a capture gap and a fusion gap are told apart.
- **WebSocket:** message by message (direction, kind, payload), plus close code and party.
- **SSE:** the stream flow's state and each event's type, id and data.

[`samples/`](samples/) holds a real run (packaged engine, capture browser, all seven clicks, `localhost`
added to scope). The surface is trimmed to the fields the scorer reads, and the capture is filtered to the
two reference hosts. Scoring it:

```bash
python score.py ground-truth.json samples/surface.sample.json out.json --capture samples/capture.sample.json
# Summary: rest_first_party 12/12; rest_first_party_templated 11/12; rest_third_party 2/2; party_labels_ok 14/14;
#          phantoms 0; leaks 0; protocol_operations 3/3; phantom_operations 0; surface_endpoints 14;
#          captured_flows 16/16; undocumented_flows 0; websocket_messages 9/9; sse_events 5/5
```

`11/12` templated is expected: W08's `ord_9f2c` can't be templated from a single observation.

## Why plain HTTP

The capture proxy verifies upstream TLS against the public web roots plus its own session CA. A
self-signed certificate on this server would therefore be rejected at the proxy (the capture browser's
`--ignore-certificate-errors` only covers the browser-to-proxy leg). That would test a certificate failure,
not the decrypt path. Plain HTTP exercises the whole capture, WebSocket, SSE and fusion path. MITM
decryption itself is covered against real HTTPS sites and by the APK reference target.

## Changing the target

Add or change a request in three places: `ground-truth.json`, the page or handler in `server.mjs`, and
`GROUND_TRUTH.md`. Then load the page, click everything, and confirm `/__ref/coverage` reads
`seen N/N documented requests, 0 undocumented`.
