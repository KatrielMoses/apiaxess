// Executable check for the flow-kind model (src/http/flow-kind.ts), run under
// Node's native type-stripping: SSE row labels, gRPC detection (mirroring the
// engine's parse_grpc_method_path), event data rendering, and live appends.
import assert from "node:assert/strict";
import {
  appendLiveEvents,
  grpcMethodOf,
  isEventTruncated,
  isGrpcContentType,
  parseGrpcMethodPath,
  renderEventData,
  sseLabel,
} from "../src/http/flow-kind.ts";

// 1. A stream's row reads as streaming or ended, never as hung.
assert.equal(sseLabel({ eventCount: 0, closed: false }), "streaming · 0 events");
assert.equal(sseLabel({ eventCount: 1, closed: false }), "streaming · 1 event");
assert.equal(sseLabel({ eventCount: 12, closed: true }), "stream ended · 12 events");

// 2. gRPC method paths: package-qualified or bare service, one rpc segment.
assert.deepEqual(parseGrpcMethodPath("/shop.v1.CartService/AddItem"), { service: "shop.v1.CartService", method: "AddItem" });
assert.deepEqual(parseGrpcMethodPath("/Greeter/SayHello"), { service: "Greeter", method: "SayHello" });
for (const rest of ["/api/v1/items", "/shop.Cart/Add/extra", "shop.Cart/Add", "/shop..Cart/Add", "/shop.Cart/Add-Item", "/shop.Cart/", "/"]) {
  assert.equal(parseGrpcMethodPath(rest), null, rest);
}

// 3. Only a gRPC content type on a method path is a gRPC call.
assert.equal(isGrpcContentType("application/grpc"), true);
assert.equal(isGrpcContentType("Application/gRPC-Web+proto"), true);
assert.equal(isGrpcContentType("application/json"), false);
assert.deepEqual(grpcMethodOf(["application/grpc"], "/shop.v1.CartService/Checkout"), { service: "shop.v1.CartService", method: "Checkout" });
assert.deepEqual(grpcMethodOf([null, "application/grpc-web-text"], "/Greeter/SayHello"), { service: "Greeter", method: "SayHello" });
assert.equal(grpcMethodOf(["application/json"], "/shop.v1.CartService/Checkout"), null);
assert.equal(grpcMethodOf(["application/grpc"], "/api/v1/items/7"), null);

// 4. Event data: JSON indented, text as sent.
assert.equal(renderEventData('{"n":1}'), '{\n  "n": 1\n}');
assert.equal(renderEventData("line one\nline two"), "line one\nline two");
assert.equal(renderEventData("{not json"), "{not json");

// 5. Truncation compares retained UTF-8 bytes with the wire size.
const event = (sequence, data, dataBytes = new TextEncoder().encode(data).length) => ({ flowId: 1, sequence, data, dataBytes, observedAt: "" });
assert.equal(isEventTruncated(event(1, "héllo")), false);
assert.equal(isEventTruncated(event(1, "hé", 10)), true);

// 6. Live appends extend a gap-free list, skip repeats, and flag a gap.
const loaded = [event(1, "a"), event(2, "b")];
assert.equal(appendLiveEvents(loaded, [event(2, "b"), event(3, "c")]), true);
assert.deepEqual(loaded.map((e) => e.sequence), [1, 2, 3]);
assert.equal(appendLiveEvents(loaded, [event(5, "e")]), false);
assert.deepEqual(loaded.map((e) => e.sequence), [1, 2, 3]);

console.log("check-flow-kind: ok");
