// Executable check for the WebSocket tab's pure model (src/ws/ws-model.ts),
// run under Node's native type-stripping: payload decoding, Pretty/Raw/Hex
// rendering, previews, truncation, and the connection filter.
import assert from "node:assert/strict";
import {
  decodePayload,
  defaultView,
  filterConnections,
  isTruncated,
  previewPayload,
  renderPayload,
  upsertConnection,
} from "../src/ws/ws-model.ts";

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const text = (value) => [...new TextEncoder().encode(value)];
const message = (kind, bytes, over = {}) => ({
  sequence: 1,
  direction: "client_to_server",
  kind,
  payloadBase64: b64(bytes),
  retainedBytes: bytes.length,
  payloadBytes: bytes.length,
  observedAt: "2026-09-25T00:00:00Z",
  ...over,
});

// 1. Decoding round-trips text and arbitrary bytes.
assert.deepEqual(decodePayload(b64([0, 1, 254, 255])), [0, 1, 254, 255]);
assert.deepEqual(decodePayload(""), []);
assert.equal(new TextDecoder().decode(new Uint8Array(decodePayload(b64(text("héllo"))))), "héllo");

// 2. Views: JSON pretty-prints; non-JSON text stays as it is; hex dumps bytes.
const json = text('{"op":"sub","ids":[1,2]}');
assert.equal(renderPayload(json, "pretty"), '{\n  "op": "sub",\n  "ids": [\n    1,\n    2\n  ]\n}');
assert.equal(renderPayload(text("ping {not json"), "pretty"), "ping {not json");
assert.match(renderPayload([0, 1, 2, 255], "hex"), /^00000000  00 01 02 ff/);
assert.equal(renderPayload(text("a\tb"), "raw"), "a→b");

// 3. Default views follow the frame kind.
assert.equal(defaultView(message("text", json), json), "pretty");
assert.equal(defaultView(message("binary", [0, 1]), [0, 1]), "hex");

// 4. Previews are one line and never dump binary.
assert.equal(previewPayload(message("text", text("a\n  b")), text("a\n  b")), "a b");
assert.equal(previewPayload(message("binary", [0, 1, 2]), [0, 1, 2]), "3 bytes binary");
assert.equal(previewPayload(message("close", []), []), "(close)");

// 5. Truncation is reported when fewer bytes were retained than sent.
assert.equal(isTruncated(message("text", text("x"), { payloadBytes: 10 })), true);
assert.equal(isTruncated(message("text", text("x"))), false);

// 6. Connection filter: host patterns, subdomains, open-only.
const connections = [
  { id: 1, url: "wss://a.example.com/s", host: "a.example.com", scope: "in_scope", origin: "capture", openedAt: "", messageCount: 3, closedAt: null },
  { id: 2, url: "wss://feed.other.test/s", host: "feed.other.test", scope: "in_scope", origin: "capture", openedAt: "", messageCount: 1, closedAt: "2026-09-25T00:00:01Z" },
];
assert.deepEqual(filterConnections(connections, "", false).map((c) => c.id), [1, 2]);
assert.deepEqual(filterConnections(connections, "*.example.com", false).map((c) => c.id), [1]);
assert.deepEqual(filterConnections(connections, "other", false).map((c) => c.id), [2]);
assert.deepEqual(filterConnections(connections, "", true).map((c) => c.id), [1]);

// 7. Live upserts replace by id and append new connections.
const updated = upsertConnection(connections, { ...connections[0], messageCount: 4 });
assert.deepEqual(updated.map((c) => [c.id, c.messageCount]), [[1, 4], [2, 1]]);
assert.equal(upsertConnection(connections, { ...connections[0], id: 3 }).length, 3);
// A live record (no party) keeps the party the list read classified.
const classified = [{ ...connections[0], party: "first_party" }];
assert.equal(upsertConnection(classified, { ...connections[0], messageCount: 9 })[0].party, "first_party");

console.log("check-ws-model: ok");
