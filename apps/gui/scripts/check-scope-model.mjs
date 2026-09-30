// Executable check for the scope-rule model (src/scope/scope-model.ts), run
// under Node's native type-stripping: whatever the operator names becomes a
// port-specific rule (never "any port"), a second port on a host already in
// scope is a distinct target, and coverage mirrors the engine's matcher.
import assert from "node:assert/strict";
import { scopeRuleCovers, scopeRuleDisplay, scopeTargetFor } from "../src/scope/scope-model.ts";

const target = (input) => {
  const value = scopeTargetFor(input);
  assert.notEqual(value, null, input);
  return value;
};

// 1. host:port adds exactly that origin, and the label shows the port.
assert.deepEqual(target("localhost:9201"), { label: "localhost:9201", kind: "exact", value: "localhost", ports: [9201] });
assert.deepEqual(target("127.0.0.1:9111"), { label: "127.0.0.1:9111", kind: "exact", value: "127.0.0.1", ports: [9111] });
assert.deepEqual(target("API.Example.com.:8443"), { label: "api.example.com:8443", kind: "exact", value: "api.example.com", ports: [8443] });
assert.deepEqual(target("[::1]:9201"), { label: "[::1]:9201", kind: "exact", value: "::1", ports: [9201] });

// 2. URLs take their port, or the scheme's default.
assert.deepEqual(target("http://127.0.0.1:9201/api/v1/items?x=1").ports, [9201]);
assert.deepEqual(target("https://api.example.com/v1").ports, [443]);
assert.deepEqual(target("http://api.example.com/").ports, [80]);
assert.deepEqual(target("wss://live.example.com/socket").ports, [443]);

// 3. A bare host covers the web defaults only — never "any port".
assert.deepEqual(target("api.example.com").ports, [80, 443]);
assert.equal(target("api.example.com").label, "api.example.com (ports 80, 443)");
for (const input of ["localhost", "127.0.0.1", "api.example.com", "*.example.com", "http://x.test:81"]) {
  assert.ok(!target(input).label.includes("any port"), input);
}

// 4. *.domain is the only way to cover subdomains.
assert.deepEqual(target("*.example.com:443"), { label: "*.example.com:443", kind: "domain_suffix", value: "example.com", ports: [443] });
assert.equal(scopeTargetFor("*.127.0.0.1"), null);

// 5. Nothing usable → null.
for (const input of ["", "   ", "host:", "host:abc", "host:0", "host:70000", "http://", "a b:80"]) {
  assert.equal(scopeTargetFor(input), null, JSON.stringify(input));
}

// 6. Coverage mirrors the engine: port-specific rules cover only their ports.
const rule = (host, ports, kind = "exact") => ({ id: "r", host: kind === "exact" ? { kind, host } : { kind, domain: host }, ports });
const h9201 = rule("127.0.0.1", [9201]);
assert.ok(scopeRuleCovers(h9201, target("127.0.0.1:9201"), 9201));
assert.ok(!scopeRuleCovers(h9201, target("127.0.0.1:9111"), 9111), "a second port on the same host is a distinct target");
assert.ok(!scopeRuleCovers(h9201, target("localhost:9201"), 9201), "localhost is not 127.0.0.1");
assert.ok(scopeRuleCovers(rule("127.0.0.1", []), target("127.0.0.1:9111"), 9111), "an existing any-port rule still covers");
const suffix = rule("example.com", [443], "domain_suffix");
assert.ok(scopeRuleCovers(suffix, target("api.example.com:443"), 443));
assert.ok(scopeRuleCovers(suffix, target("*.api.example.com:443"), 443));
assert.ok(!scopeRuleCovers(suffix, target("badexample.com:443"), 443), "label boundary");
assert.ok(!scopeRuleCovers(rule("api.example.com", [443]), target("*.example.com:443"), 443), "an exact rule never covers a suffix target");

// 7. Labels match the engine's AllowedNetworkTarget::label.
assert.equal(scopeRuleDisplay(rule("127.0.0.1", [9201])), "127.0.0.1:9201");
assert.equal(scopeRuleDisplay(rule("::1", [9201])), "[::1]:9201");
assert.equal(scopeRuleDisplay(rule("127.0.0.1", [80, 443])), "127.0.0.1 (ports 80, 443)");
assert.equal(scopeRuleDisplay(rule("localhost", [])), "localhost (any port)");
assert.equal(scopeRuleDisplay(rule("example.com", [], "domain_suffix")), "*.example.com (any port)");

console.log("scope-model: ok");
