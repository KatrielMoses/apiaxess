// Executable check for the protocol-operations model
// (src/surface/operations.ts), run under Node's native type-stripping:
// GraphQL and gRPC operations read from the engine's fused surface JSON,
// observed/in-code from evidence provenance, and GraphQL-by-endpoint lookup.
import assert from "node:assert/strict";
import { graphqlOperationsOn, readProtocolOperations } from "../src/surface/operations.ts";

const presence = (...evidence) => ({ candidates: [{ id: "c", value: "present", evidence }] });
const surface = {
  surface: {
    provenance: {
      entities: [
        { id: "dynamic:flow:1", source_type: "dynamic_capture" },
        { id: "static:doc:1", source_type: "static_analysis" },
      ],
    },
    protocol_operations: [
      { identity: { kind: "graph_ql", endpoint_url: "https://api.example.test/graphql", operation_type: "mutation", operation_name: "AddToCart" }, presence: presence("dynamic:flow:1") },
      { identity: { kind: "graph_ql", endpoint_url: null, operation_type: "query", operation_name: "GetProfile" }, presence: presence("static:doc:1") },
      { identity: { kind: "grpc", service: "shop.v1.CartService", method: "Checkout" }, presence: presence("dynamic:flow:1", "static:doc:1") },
    ],
  },
};

// 1. Each operation reads as its protocol, never as an opaque POST.
const operations = readProtocolOperations(surface);
assert.deepEqual(operations.map((o) => [o.kind, o.label, o.observed, o.inCode]), [
  ["graphql", "mutation AddToCart", true, false],
  ["graphql", "query GetProfile", false, true],
  ["grpc", "shop.v1.CartService / Checkout", true, true],
]);

// 2. A surface without protocol operations reads as none.
assert.deepEqual(readProtocolOperations({ surface: {} }), []);
assert.deepEqual(readProtocolOperations(null), []);

// 3. GraphQL operations are found on their endpoint by host and path.
assert.deepEqual(graphqlOperationsOn(operations, "api.example.test", "/graphql").map((o) => o.label), ["mutation AddToCart"]);
assert.deepEqual(graphqlOperationsOn(operations, "other.test", "/graphql"), []);
assert.deepEqual(graphqlOperationsOn(operations, null, "/graphql/").map((o) => o.label), ["mutation AddToCart"]);
assert.deepEqual(graphqlOperationsOn(operations, "api.example.test", "/v1/items"), []);

console.log("check-surface-operations: ok");
