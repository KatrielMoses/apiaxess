// Executable check for the Fuzz raw-HTTP template model (WS5). Runs the REAL
// pure parser (src/fuzz/template.ts) under Node's native type-stripping — no test
// runner required. Verifies raw-request round-trip and that §-marker byte ranges
// land exactly on the marked value in the reconstructed absolute URL / body, so
// the backend applies payloads byte-identically to the pre-raw-template behavior.
import assert from "node:assert/strict";
import {
  countTemplatePositions,
  parseFuzzTemplate,
  rawRequestText,
} from "../src/fuzz/template.ts";

const decode = (bytes) => new TextDecoder().decode(new Uint8Array(bytes));

// 1. Round-trip: an absolute-URL request renders as raw HTTP and parses back to
//    the same method/url/body, with a Host header present.
{
  const req = {
    method: "POST",
    url: "https://api.example.test/items?id=1",
    headers: [["Host", "api.example.test"], ["Content-Type", "application/json"]],
    body: [...new TextEncoder().encode("{\"a\":1}")],
  };
  const raw = rawRequestText(req);
  assert.ok(raw.startsWith("POST /items?id=1 HTTP/1.1\n"), `request-line: ${raw.split("\n")[0]}`);
  assert.ok(raw.includes("\nHost: api.example.test"), "Host header present");
  assert.ok(raw.includes("\n\n{\"a\":1}"), "blank line + body");
  const parsed = parseFuzzTemplate(raw, "https");
  assert.equal(parsed.method, "POST");
  assert.equal(parsed.url, "https://api.example.test/items?id=1");
  assert.equal(decode(parsed.body), "{\"a\":1}");
  assert.equal(parsed.positions.length, 0);
}

// 2. A synthesized Host (absent in the source) is added and round-trips the URL.
{
  const req = { method: "GET", url: "http://host.test/a/b", headers: [], body: null };
  const raw = rawRequestText(req);
  assert.ok(raw.includes("Host: host.test"), "Host synthesized");
  const parsed = parseFuzzTemplate(raw, "http");
  assert.equal(parsed.url, "http://host.test/a/b");
}

// 3. URL path marker: the position must cover exactly the marked value in the
//    reconstructed ABSOLUTE url (the byte range the backend replaces).
{
  const raw = "GET /items?id=§FUZZ§ HTTP/1.1\nHost: api.example.test\n";
  const parsed = parseFuzzTemplate(raw, "https");
  assert.equal(parsed.url, "https://api.example.test/items?id=FUZZ");
  assert.equal(parsed.positions.length, 1);
  const p = parsed.positions[0];
  assert.equal(p.location, "url");
  assert.equal(parsed.url.slice(p.start, p.end), "FUZZ", "URL marker lands on the marked value");
}

// 4. Body marker: position covers the marked value in the body.
{
  const raw = "POST /login HTTP/1.1\nHost: api.example.test\n\nuser=admin&pass=§secret§";
  const parsed = parseFuzzTemplate(raw, "https");
  const body = decode(parsed.body);
  assert.equal(body, "user=admin&pass=secret");
  const p = parsed.positions.find((pos) => pos.location === "body");
  assert.ok(p !== undefined, "body position present");
  assert.equal(body.slice(p.start, p.end), "secret", "body marker lands on the marked value");
}

// 5. Two positions (path + body) keep order [url, body] and both land correctly.
{
  const raw = "POST /a?x=§1§ HTTP/1.1\nHost: h.test\n\nq=§2§";
  const parsed = parseFuzzTemplate(raw, "https");
  assert.equal(countTemplatePositions(raw), 2);
  assert.equal(parsed.positions[0].location, "url");
  assert.equal(parsed.positions[1].location, "body");
  assert.equal(parsed.url.slice(parsed.positions[0].start, parsed.positions[0].end), "1");
  assert.equal(decode(parsed.body).slice(parsed.positions[1].start, parsed.positions[1].end), "2");
}

// 6. Header marker: position covers the value within the header.
{
  const raw = "GET / HTTP/1.1\nHost: h.test\nX-Token: §abc§\n";
  const parsed = parseFuzzTemplate(raw, "https");
  const p = parsed.positions.find((pos) => pos.location === "header");
  assert.ok(p !== undefined && p.headerName === "X-Token");
  const value = parsed.headers.find(([n]) => n === "X-Token")[1];
  assert.equal(value.slice(p.start, p.end), "abc");
}

// 7. Unbalanced markers report an error rather than mis-parsing.
{
  const parsed = parseFuzzTemplate("GET /§x HTTP/1.1\nHost: h.test\n", "https");
  assert.ok(parsed.error !== undefined, "unbalanced markers rejected");
}

console.log("Fuzz template OK: raw round-trip + §-marker placement verified.");
