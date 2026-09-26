// Reference web target: a known-ground-truth site for web-capture fidelity.
//
//   node server.mjs [--port 9201] [--third-party-port 9202]
//
// Serves the first-party site on http://127.0.0.1:<port> (page, REST,
// GraphQL, gRPC-Web, SSE, WebSocket) and a third-party service on
// http://localhost:<third-party-port>. Every request it answers is logged
// with its ground-truth.json ID, or as UNDOCUMENTED, so the log shows whether
// the page emitted exactly the manifest. No dependencies beyond Node.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const manifest = JSON.parse(readFileSync(join(here, "ground-truth.json"), "utf8"));

const argument = (name, fallback) => {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : Number(process.argv[index + 1]);
};
const PORT = argument("--port", 9201);
const THIRD_PARTY_PORT = argument("--third-party-port", 9202);
const FIRST_ORIGIN = `http://127.0.0.1:${PORT}`;
const THIRD_ORIGIN = `http://localhost:${THIRD_PARTY_PORT}`;

/* ---------- manifest-tagged log ---------- */

const routes = manifest.endpoints.map((endpoint) => ({
  ...endpoint,
  pattern: new RegExp(`^${endpoint.path.replace(/[.]/g, "\\.").replace(/\{[^}]+\}/g, "[^/]+")}$`),
}));
const seen = new Set();
let undocumented = 0;

function tag(party, method, url) {
  const path = url.split("?")[0];
  const route = routes.find((candidate) => candidate.party === party && candidate.method === method && candidate.pattern.test(path));
  if (route === undefined) {
    undocumented += 1;
    return "UNDOCUMENTED";
  }
  seen.add(route.id);
  return route.id;
}

function log(line) {
  console.log(`${new Date().toISOString().slice(11, 23)} ${line}`);
}

function coverage() {
  const missing = manifest.endpoints.filter((endpoint) => !seen.has(endpoint.id)).map((endpoint) => `${endpoint.id} (${endpoint.trigger})`);
  return `seen ${seen.size}/${manifest.endpoints.length} documented requests, ${undocumented} undocumented${missing.length === 0 ? "" : `; not yet: ${missing.join(", ")}`}`;
}

/* ---------- helpers ---------- */

function json(response, status, value, extra = {}) {
  response.writeHead(status, { "content-type": "application/json", ...extra });
  response.end(JSON.stringify(value));
}

function readBody(request) {
  return new Promise((resolve) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

function parseJson(bytes) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    return null;
  }
}

/* ---------- the page ---------- */

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Reference web target</title>
<link rel="icon" href="data:," />
<style>
  body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem; max-width: 60rem; }
  button { margin: 0 .5rem .5rem 0; padding: .4rem .8rem; }
  pre { background: #f4f4f4; padding: 1rem; max-height: 24rem; overflow: auto; }
</style>
</head>
<body>
<h1>Reference web target</h1>
<p>Loading this page fires the <em>load</em> requests. Each button fires one documented request.</p>
<div>
  <button id="btn-create">Create item</button>
  <button id="btn-update">Update item</button>
  <button id="btn-delete">Delete item</button>
  <button id="btn-order">Load order</button>
  <button id="btn-search">Search</button>
  <button id="btn-cart">Add to cart (GraphQL)</button>
  <button id="btn-checkout">Checkout (gRPC-Web)</button>
</div>
<pre id="log"></pre>
<script>
const THIRD = ${JSON.stringify(THIRD_ORIGIN)};
const out = document.getElementById("log");
const log = (line) => { out.textContent += line + "\\n"; };
const done = (id) => (value) => log(id + " " + (typeof value === "string" ? value : JSON.stringify(value)));
const getJson = (url, init) => fetch(url, init).then((response) => response.json());
const sendJson = (method, url, body, headers = {}) => getJson(url, { method, headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const graphql = (operationName, query, variables) => sendJson("POST", "/graphql", { operationName, query, variables });

// ---- on load ----
getJson("/api/v1/status").then(done("W01"));
getJson("/api/v1/items?page=1&q=lamp").then(done("W02"));
getJson("/api/v1/items/42", { headers: { "X-Client-Version": "1.4.0" } }).then(done("W03"));
getJson("/api/v1/users/7/orders?limit=5").then(done("W04"));
graphql("GetProfile", "query GetProfile($id: ID!) { profile(id: $id) { id name email } }", { id: "u_7" }).then(done("G01"));
getJson(THIRD + "/v1/geo?client=ref-web").then(done("W14"));
// An analytics-style beacon: a text/plain body, so no CORS preflight.
fetch(THIRD + "/v1/collect", { method: "POST", body: JSON.stringify({ event: "page_view", page: "/" }) }).then((r) => r.json()).then(done("W15"));

// SSE: close on the "done" event so the browser does not reconnect.
const stream = new EventSource("/api/v1/stream?topic=prices");
stream.onmessage = (event) => log("W11 message #" + event.lastEventId + " " + JSON.stringify(event.data));
for (const type of ["price", "done"]) {
  stream.addEventListener(type, (event) => {
    log("W11 " + type + " #" + event.lastEventId + " " + event.data);
    if (type === "done") stream.close();
  });
}

// WebSocket: a strict request/reply exchange, so the message order is fixed.
const socket = new WebSocket("ws://" + location.host + "/ws?room=ref");
socket.binaryType = "arraybuffer";
let step = 0;
socket.onmessage = (event) => {
  const shown = typeof event.data === "string" ? event.data : Array.from(new Uint8Array(event.data), (b) => b.toString(16).padStart(2, "0")).join("");
  log("W13 <- " + shown);
  step += 1;
  if (step === 1) socket.send("hello");
  else if (step === 2) socket.send(new Uint8Array([0x00, 0x01, 0x02, 0xfd, 0xfe, 0xff]));
  else if (step === 3) socket.send(JSON.stringify({ op: "subscribe", channel: "orders" }));
  else if (step === 4) socket.close(1000);
};
socket.onclose = (event) => log("W13 closed " + event.code);

// ---- on click ----
const on = (id, action) => document.getElementById(id).addEventListener("click", action);
on("btn-create", () => sendJson("POST", "/api/v1/items", { name: "Desk lamp", price: 24.5, tags: ["home", "light"] }, { "X-Request-Id": "req-0001" }).then(done("W05")));
on("btn-update", () => sendJson("PUT", "/api/v1/items/42", { name: "Desk lamp v2", price: 26 }).then(done("W06")));
on("btn-delete", () => getJson("/api/v1/items/42", { method: "DELETE" }).then(done("W07")));
on("btn-order", () => getJson("/api/v1/orders/ord_9f2c").then(done("W08")));
on("btn-search", () => getJson("/api/v1/search?q=invoice&page=2", { headers: { "X-Client-Version": "1.4.0" } }).then(done("W09")));
on("btn-cart", () => graphql("AddToCart", "mutation AddToCart($sku: ID!, $qty: Int!) { addToCart(sku: $sku, qty: $qty) { id total } }", { sku: "A1", qty: 2 }).then(done("G02")));
on("btn-checkout", () => fetch("/shop.v1.CartService/Checkout", {
  method: "POST",
  headers: { "content-type": "application/grpc-web+proto", "x-grpc-web": "1" },
  // One length-prefixed protobuf frame: field 1 (cart id) = varint 7.
  body: new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x07]),
}).then((r) => r.arrayBuffer()).then((b) => log("R01 " + Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join(""))));
</script>
</body>
</html>
`;

/* ---------- first-party site ---------- */

const ITEM = { id: 42, name: "Desk lamp", price: 24.5, tags: ["home", "light"], inStock: true };

async function firstParty(request, response) {
  const url = new URL(request.url, FIRST_ORIGIN);
  if (url.pathname === "/__ref/coverage") {
    // Harness only (never called by the page), and not itself counted.
    response.writeHead(200, { "content-type": "text/plain" });
    return response.end(`${coverage()}\n`);
  }
  const id = tag("first", request.method, request.url);
  const body = await readBody(request);
  log(`${id} ${request.method} ${request.url}`);
  const path = url.pathname;
  const method = request.method;

  if (method === "GET" && path === "/") {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    return response.end(PAGE);
  }
  if (method === "GET" && path === "/api/v1/status") return json(response, 200, { status: "ok", version: "1.0.0", uptimeSeconds: 3600 });
  if (method === "GET" && path === "/api/v1/items") {
    return json(response, 200, { page: Number(url.searchParams.get("page")), query: url.searchParams.get("q"), items: [ITEM, { ...ITEM, id: 43, name: "Floor lamp", price: 89 }], total: 2 });
  }
  if (method === "POST" && path === "/api/v1/items") return json(response, 201, { ...ITEM, ...parseJson(body), id: 44 });
  const item = /^\/api\/v1\/items\/([^/]+)$/.exec(path);
  if (item !== null && method === "GET") return json(response, 200, { ...ITEM, id: Number(item[1]) });
  if (item !== null && method === "PUT") return json(response, 200, { ...ITEM, ...parseJson(body), id: Number(item[1]) });
  if (item !== null && method === "DELETE") return json(response, 200, { deleted: true, id: Number(item[1]) });
  const orders = /^\/api\/v1\/users\/([^/]+)\/orders$/.exec(path);
  if (orders !== null && method === "GET") {
    return json(response, 200, { userId: Number(orders[1]), limit: Number(url.searchParams.get("limit")), orders: [{ id: "ord_9f2c", total: 49, status: "shipped" }] });
  }
  const order = /^\/api\/v1\/orders\/([^/]+)$/.exec(path);
  if (order !== null && method === "GET") return json(response, 200, { id: order[1], total: 49, status: "shipped", lines: [{ sku: "A1", qty: 2 }] });
  if (method === "GET" && path === "/api/v1/search") {
    return json(response, 200, { q: url.searchParams.get("q"), page: Number(url.searchParams.get("page")), results: [{ type: "invoice", id: "inv_31" }] });
  }
  if (method === "POST" && path === "/graphql") return graphqlResponse(response, parseJson(body));
  if (method === "POST" && path === "/shop.v1.CartService/Checkout") return grpcWebCheckout(response, body);
  if (method === "GET" && path === "/api/v1/stream") return eventStream(request, response);
  return json(response, 404, { error: "not found" });
}

function graphqlResponse(response, request) {
  log(`     GraphQL operation ${request?.operationName}`);
  if (request?.operationName === "GetProfile") {
    return json(response, 200, { data: { profile: { id: "u_7", name: "Ada", email: "ada@example.test" } } });
  }
  if (request?.operationName === "AddToCart") return json(response, 200, { data: { addToCart: { id: "cart_1", total: 2 } } });
  return json(response, 200, { errors: [{ message: "unknown operation" }] });
}

function grpcWebCheckout(response, body) {
  const length = body.length >= 5 ? body.readUInt32BE(1) : 0;
  log(`     gRPC-Web message ${body.subarray(5, 5 + length).toString("hex")}`);
  const message = Buffer.from([0x08, 0x2a]); // field 1 (order number) = varint 42
  const trailer = Buffer.from("grpc-status:0\r\ngrpc-message:\r\n");
  const frame = (flag, payload) => {
    const head = Buffer.alloc(5);
    head[0] = flag;
    head.writeUInt32BE(payload.length, 1);
    return Buffer.concat([head, payload]);
  };
  response.writeHead(200, { "content-type": "application/grpc-web+proto" });
  response.end(Buffer.concat([frame(0x00, message), frame(0x80, trailer)]));
}

function eventStream(request, response) {
  response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
  response.write(": stream open\n\n");
  const frames = manifest.sse.events.map((event) => {
    const lines = [];
    if (event.event !== null) lines.push(`event: ${event.event}`);
    lines.push(`id: ${event.id}`);
    for (const line of event.data.split("\n")) lines.push(`data: ${line}`);
    return `${lines.join("\n")}\n\n`;
  });
  let index = 0;
  const timer = setInterval(() => {
    if (index < frames.length) {
      response.write(frames[index]);
      log(`     SSE event ${manifest.sse.events[index].seq}`);
      index += 1;
      return;
    }
    clearInterval(timer);
    // The page closes on "done"; end the response shortly after either way.
    setTimeout(() => response.end(), 1000);
  }, 150);
  request.on("close", () => clearInterval(timer));
}

/* ---------- WebSocket (RFC 6455, server side) ---------- */

function upgrade(request, socket) {
  const id = tag("first", request.method, request.url);
  log(`${id} ${request.method} ${request.url} (upgrade)`);
  const key = request.headers["sec-websocket-key"];
  if (!request.url.startsWith("/ws") || typeof key !== "string") {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    return;
  }
  const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);

  const send = (opcode, payload) => {
    const length = payload.length;
    const head = length < 126 ? Buffer.from([0x80 | opcode, length]) : Buffer.from([0x80 | opcode, 126, length >> 8, length & 0xff]);
    socket.write(Buffer.concat([head, payload]));
  };
  const sendText = (text) => {
    log(`     WS -> ${text}`);
    send(0x1, Buffer.from(text));
  };
  let buffered = Buffer.alloc(0);
  let closed = false;
  socket.on("data", (chunk) => {
    buffered = Buffer.concat([buffered, chunk]);
    for (;;) {
      if (buffered.length < 2) return;
      const opcode = buffered[0] & 0x0f;
      const masked = (buffered[1] & 0x80) !== 0;
      let length = buffered[1] & 0x7f;
      let offset = 2;
      if (length === 126) {
        if (buffered.length < 4) return;
        length = buffered.readUInt16BE(2);
        offset = 4;
      } else if (length === 127) {
        if (buffered.length < 10) return;
        length = Number(buffered.readBigUInt64BE(2));
        offset = 10;
      }
      const maskOffset = offset;
      if (masked) offset += 4;
      if (buffered.length < offset + length) return;
      const payload = Buffer.from(buffered.subarray(offset, offset + length));
      if (masked) for (let i = 0; i < payload.length; i += 1) payload[i] ^= buffered[maskOffset + (i % 4)];
      buffered = buffered.subarray(offset + length);
      handle(opcode, payload);
    }
  });
  const handle = (opcode, payload) => {
    if (opcode === 0x1) {
      const text = payload.toString("utf8");
      log(`     WS <- ${text}`);
      if (text === "hello") sendText("hello back");
      else if (parseJson(payload)?.op === "subscribe") sendText(JSON.stringify({ type: "subscribed", channel: parseJson(payload).channel }));
    } else if (opcode === 0x2) {
      log(`     WS <- binary ${payload.toString("hex")}`);
      const reply = Buffer.from(payload).reverse();
      log(`     WS -> binary ${reply.toString("hex")}`);
      send(0x2, reply);
    } else if (opcode === 0x8) {
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
      log(`     WS <- close ${code}`);
      if (!closed) {
        closed = true;
        const reply = Buffer.alloc(2);
        reply.writeUInt16BE(1000, 0);
        log("     WS -> close 1000");
        send(0x8, reply);
        socket.end();
      }
    } else if (opcode === 0x9) {
      send(0xa, payload);
    }
  };
  socket.on("error", () => {});
  sendText(JSON.stringify({ type: "welcome", v: 1 }));
}

/* ---------- third-party service ---------- */

async function thirdParty(request, response) {
  const id = tag("third", request.method, request.url);
  await readBody(request);
  log(`${id} ${request.method} ${THIRD_ORIGIN}${request.url}`);
  const cors = { "access-control-allow-origin": "*" };
  const path = request.url.split("?")[0];
  if (request.method === "GET" && path === "/v1/geo") return json(response, 200, { country: "IN", region: "KA", client: new URL(request.url, THIRD_ORIGIN).searchParams.get("client") }, cors);
  if (request.method === "POST" && path === "/v1/collect") return json(response, 202, { accepted: true }, cors);
  return json(response, 404, { error: "not found" }, cors);
}

/* ---------- start ---------- */

const site = createServer((request, response) => void firstParty(request, response));
site.on("upgrade", upgrade);
site.listen(PORT, "127.0.0.1", () => log(`first-party site  ${FIRST_ORIGIN}/`));
// `localhost` may resolve to either loopback address; answer on both (and
// never on a non-loopback interface).
createServer((request, response) => void thirdParty(request, response)).listen(THIRD_PARTY_PORT, "127.0.0.1", () => log(`third-party host  ${THIRD_ORIGIN}/`));
createServer((request, response) => void thirdParty(request, response))
  .on("error", () => log("third-party host: no IPv6 loopback; serving 127.0.0.1 only"))
  .listen(THIRD_PARTY_PORT, "::1");

process.on("SIGINT", () => {
  log(coverage());
  process.exit(0);
});
