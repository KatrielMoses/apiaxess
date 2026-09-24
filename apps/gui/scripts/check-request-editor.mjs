// Executable check for the shared raw-HTTP request editor (RS2) and the Pretty
// body view. Runs the REAL pure modules (src/http/*.ts) under Node's native
// type-stripping — no test runner required. Verifies raw round-trip with header
// order/case intact, Target-vs-Host independence, as-sent Content-Length while
// editing, and that Pretty is display-only.
import assert from "node:assert/strict";
import {
  parseRawRequest,
  rawRequestText,
  syncContentLength,
  urlOrigin,
} from "../src/http/request-editor.ts";
import { isJsonBody, prettyBody } from "../src/http/body-view.ts";

const encode = (text) => [...new TextEncoder().encode(text)];
const decode = (bytes) => new TextDecoder().decode(new Uint8Array(bytes));

// 1. Round-trip: request line present; order and case of headers preserved;
//    the URL comes back from Target + request-line path.
{
  const req = {
    method: "post",
    url: "https://api.example.test:8443/items?id=1",
    headers: [["X-Zeta", "z"], ["Host", "api.example.test:8443"], ["content-TYPE", "application/json"]],
    body: encode("{\"a\":1}"),
  };
  const raw = rawRequestText(req, { recomputeContentLength: true });
  assert.equal(
    raw,
    "POST /items?id=1 HTTP/1.1\nX-Zeta: z\nHost: api.example.test:8443\ncontent-TYPE: application/json\nContent-Length: 7\n\n{\"a\":1}",
  );
  const parsed = parseRawRequest(raw, urlOrigin(req.url));
  assert.equal(parsed.error, undefined);
  assert.equal(parsed.method, "POST");
  assert.equal(parsed.url, req.url);
  assert.deepEqual(parsed.headers.map(([name]) => name), ["X-Zeta", "Host", "content-TYPE", "Content-Length"]);
  assert.equal(decode(parsed.body), "{\"a\":1}");
}

// 2. Editing Host never moves the connection: the Target governs the URL.
{
  const parsed = parseRawRequest("GET /vhost HTTP/1.1\nHost: evil.test\n", "http://127.0.0.1:9111");
  assert.equal(parsed.url, "http://127.0.0.1:9111/vhost");
  assert.deepEqual(parsed.headers, [["Host", "evil.test"]]);
  // An absolute-form request target is used as written.
  assert.equal(parseRawRequest("GET http://other.test/x HTTP/1.1\n", "http://127.0.0.1:9111").url, "http://other.test/x");
}

// 3. Honest parse errors instead of silently sending something else.
{
  assert.match(parseRawRequest("GET /x HTTP/1.1\nHost: h\n", "").error ?? "", /target/i);
  assert.match(parseRawRequest("G ET /x HTTP/1.1\n", "http://h").error ?? "", /method|header/i);
  assert.match(parseRawRequest("GET /x HTTP/1.1\nBad Header: v\n", "http://h").error ?? "", /header name/i);
  assert.match(parseRawRequest("", "http://h").error ?? "", /method/i);
}

// 4. As-sent Content-Length while editing: updated in place (case kept) and
//    added when a body appears with no framing header; caret delta reported.
{
  const edited = "POST /x HTTP/1.1\nHost: h\ncontent-length: 2\nAccept: */*\n\nhello";
  const synced = syncContentLength(edited);
  assert.equal(synced?.text, "POST /x HTTP/1.1\nHost: h\ncontent-length: 5\nAccept: */*\n\nhello");
  assert.equal(synced?.delta, 0);
  assert.equal(syncContentLength(synced.text), null, "already as-sent");
  const grown = syncContentLength("POST /x HTTP/1.1\nContent-Length: 9\n\n" + "a".repeat(10));
  assert.equal(grown?.delta, 1);
  const added = syncContentLength("POST /x HTTP/1.1\nHost: h\n\nab");
  assert.equal(added?.text, "POST /x HTTP/1.1\nHost: h\nContent-Length: 2\n\nab");
  assert.equal(syncContentLength("POST /x HTTP/1.1\nTransfer-Encoding: chunked\n\n2\r\nab"), null);
  assert.equal(syncContentLength("GET /x HTTP/1.1\nHost: h\n"), null, "no body, nothing to frame");
}

// 5. Pretty is display-only formatting: JSON detected by type or shape,
//    non-JSON and invalid JSON shown unchanged.
{
  const json = "{\"b\":[1,2],\"a\":{\"c\":true}}";
  assert.ok(isJsonBody([["Content-Type", "application/problem+json; charset=utf-8"]], "x"));
  assert.ok(isJsonBody([], "  [1] "));
  assert.equal(prettyBody([["content-type", "application/json"]], json).text, JSON.stringify(JSON.parse(json), null, 2));
  assert.deepEqual(prettyBody([["content-type", "application/json"]], "{not json"), { text: "{not json", formatted: false });
  assert.deepEqual(prettyBody([["content-type", "text/html"]], "<b>x</b>"), { text: "<b>x</b>", formatted: false });
}

console.log("Request editor OK: raw round-trip (order+case), Target≠Host, as-sent Content-Length, display-only Pretty verified.");
