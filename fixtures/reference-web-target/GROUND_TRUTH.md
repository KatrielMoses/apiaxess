# Reference web target — ground-truth manifest

Every request the reference page makes, every WebSocket message, every SSE event and every GraphQL
and gRPC operation. Fidelity tests score APIaxess's web capture against this list. The machine-readable
copy is [`ground-truth.json`](ground-truth.json), and it is authoritative: `server.mjs` reads it to tag each
request it serves (with the ID below, or as `UNDOCUMENTED`) and to generate the SSE stream. Keep this table
in sync with it.

- **First-party origin:** `http://127.0.0.1:9201`. It serves the page and everything below except W14/W15.
- **Third-party origin:** `http://localhost:9202`, an analytics-style service. It is a different
  registrable host from `127.0.0.1`, so it is classified third-party. It is outside a scope declared for
  `127.0.0.1`, so W14/W15 are captured as flows but only fuse once `localhost` is added to scope.
- **Triggers:** `load` fires when the page loads. `click:<id>` fires once per click on the button with
  that element id. All seven buttons are visible on the page; no login and no navigation.
- **Deterministic:** the same load and clicks always produce exactly this set. There is no favicon request
  (the page declares a `data:` icon). There is one SSE request (the page closes the stream on `done`, so the
  browser never reconnects). The WebSocket exchange is strict request/reply, so its order is fixed.

## HTTP requests

| ID | Method | Origin | Templated path | Query | Body (JSON) | Extra headers | Protocol | Surfaces as | Trigger |
|----|--------|--------|----------------|-------|-------------|---------------|----------|-------------|---------|
| W00 | GET | first | `/` | — | — | — | document (HTML) | endpoint | load |
| W01 | GET | first | `/api/v1/status` | — | — | — | REST | endpoint | load |
| W02 | GET | first | `/api/v1/items` | `page`, `q` | — | — | REST | endpoint | load |
| W03 | GET | first | `/api/v1/items/{id}` | — | — | `X-Client-Version` | REST | endpoint | load |
| W04 | GET | first | `/api/v1/users/{userId}/orders` | `limit` | — | — | REST | endpoint | load |
| W05 | POST | first | `/api/v1/items` | — | `{name, price, tags[]}` | `X-Request-Id` | REST | endpoint | click `btn-create` |
| W06 | PUT | first | `/api/v1/items/{id}` | — | `{name, price}` | — | REST | endpoint | click `btn-update` |
| W07 | DELETE | first | `/api/v1/items/{id}` | — | — | — | REST | endpoint | click `btn-delete` |
| W08 | GET | first | `/api/v1/orders/{orderId}` | — | — | — | REST | endpoint | click `btn-order` |
| W09 | GET | first | `/api/v1/search` | `q`, `page` | — | `X-Client-Version` | REST | endpoint | click `btn-search` |
| W10 | POST | first | `/graphql` | — | `{operationName, query, variables}` | — | GraphQL | endpoint + operations G01, G02 | load (G01), click `btn-cart` (G02) |
| W11 | GET | first | `/api/v1/stream` | `topic` | — | — | SSE (`text/event-stream`) | endpoint + event list | load |
| W12 | POST | first | `/shop.v1.CartService/Checkout` | — | gRPC-Web frame (protobuf) | `X-Grpc-Web` | gRPC-Web (`application/grpc-web+proto`) | operation R01, **not** a REST endpoint | click `btn-checkout` |
| W13 | GET | first | `/ws` | `room` | — | — | WebSocket upgrade | WebSocket tab, **not** a REST endpoint | load |
| W14 | GET | third | `/v1/geo` | `client` | — | — | REST | endpoint (third-party, needs scope) | load |
| W15 | POST | third | `/v1/collect` | — | `{event, page}` sent as `text/plain` | — | REST (beacon) | endpoint (third-party, needs scope) | load |

**Concrete values on the wire:** W03/W06/W07 `{id}` = `42`; W04 `{userId}` = `7`, `?limit=5`;
W08 `{orderId}` = `ord_9f2c`; W02 `?page=1&q=lamp`; W09 `?q=invoice&page=2`; W11 `?topic=prices`;
W13 `?room=ref`; W14 `?client=ref-web`; `X-Client-Version: 1.4.0`, `X-Request-Id: req-0001`.
`ord_9f2c` is deliberately non-numeric. From one observation it can't be told apart from a literal
segment, so a capture-only surface is expected to keep it concrete (the scorer reports that as `concrete`,
not a miss).

W15 is sent without a `content-type` of its own, so the browser labels it `text/plain;charset=UTF-8` and
sends no CORS preflight; that is how real analytics beacons avoid preflights. Every response is real:
JSON bodies for REST/GraphQL/third-party, HTML for W00, an event stream for W11, and a gRPC-Web message
plus trailer frame for W12.

## GraphQL operations (on W10)

| ID | Type | Name | Variables | Trigger |
|----|------|------|-----------|---------|
| G01 | query | `GetProfile` | `{id: "u_7"}` | load |
| G02 | mutation | `AddToCart` | `{sku: "A1", qty: 2}` | click `btn-cart` |

## gRPC operations (W12)

| ID | Service | Method | Request | Response |
|----|---------|--------|---------|----------|
| R01 | `shop.v1.CartService` | `Checkout` | one frame, protobuf `08 07` (field 1 = 7) | frame `08 2a` (field 1 = 42) + trailer `grpc-status:0` |

## WebSocket messages (W13, `ws://127.0.0.1:9201/ws?room=ref`)

| # | Direction | Kind | Payload |
|---|-----------|------|---------|
| 1 | ↓ server→client | text (JSON) | `{"type":"welcome","v":1}` |
| 2 | ↑ client→server | text | `hello` |
| 3 | ↓ | text | `hello back` |
| 4 | ↑ | binary | `00 01 02 fd fe ff` |
| 5 | ↓ | binary | `ff fe fd 02 01 00` (the same bytes reversed) |
| 6 | ↑ | text (JSON) | `{"op":"subscribe","channel":"orders"}` |
| 7 | ↓ | text (JSON) | `{"type":"subscribed","channel":"orders"}` |
| 8 | ↑ | close | code 1000 |
| 9 | ↓ | close | code 1000 |

## SSE events (W11)

The stream opens with a comment (`: stream open`, which is not an event). One event follows every
150 ms; the page closes the stream on `done`, and the server ends the response 1 s later either way.

| # | `event:` | `id:` | `data:` |
|---|----------|-------|---------|
| 1 | `price` | 1 | `{"sku":"A1","price":101}` |
| 2 | `price` | 2 | `{"sku":"A1","price":102}` |
| 3 | *(none: default `message`)* | 3 | two `data:` lines, `line one` / `line two` |
| 4 | `price` | 4 | `{"sku":"B2","price":55}` |
| 5 | `done` | 5 | `{"total":4}` |

## Totals

16 HTTP requests (W00–W15): 14 first-party, 2 third-party; 10 on load, 7 clicks (W10 carries one of each).
In a fused surface: 12 first-party REST endpoints (W00–W11), 2 more once `localhost` is in scope, no
REST endpoint for W12 or W13. Also 2 GraphQL operations, 1 gRPC operation, 9 WebSocket messages and
5 SSE events.
