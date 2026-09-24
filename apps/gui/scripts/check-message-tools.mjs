// Executable check for the Resend message tools (RS5). Runs the REAL pure
// module (src/http/message-tools.ts) under Node's native type-stripping.
// Verifies copy-as-curl quoting, binary detection + hex dump, visible
// non-printables, the Inspector's offsets back into the raw text, method swap,
// URL-encoding, and find.
import assert from "node:assert/strict";
import {
  curlCommand,
  findAll,
  hexDump,
  inspectRequest,
  isBinaryBody,
  requestMethod,
  setRequestMethod,
  shellQuote,
  showNonPrintables,
  urlEncode,
} from "../src/http/message-tools.ts";

const encode = (text) => [...new TextEncoder().encode(text)];

// 1. curl: method only when not implied, headers in order and case, exact body.
{
  const get = curlCommand({ method: "GET", url: "http://h.test/a?b=1", headers: [["X-B", "2"], ["accept", "*/*"]], body: null });
  // curl's own User-Agent/Accept are suppressed unless the request has them.
  assert.equal(get, "curl --http1.1 'http://h.test/a?b=1' -H 'X-B: 2' -H 'accept: */*' -H 'User-Agent:'");
  const put = curlCommand({ method: "put", url: "http://h.test/", headers: [["X-Empty", ""]], body: encode("it's") });
  assert.equal(put, "curl --http1.1 -X 'PUT' 'http://h.test/' -H 'X-Empty;' -H 'User-Agent:' -H 'Accept:' --data-binary 'it'\\''s'");
  const post = curlCommand({ method: "POST", url: "http://h.test/", headers: [], body: [0x00, 0x41, 0x27, 0xff, 0x0a] });
  assert.equal(post, "curl --http1.1 'http://h.test/' -H 'User-Agent:' -H 'Accept:' --data-binary $'\\x00A\\'\\xff\\x0a'");
  assert.equal(curlCommand({ method: "HEAD", url: "http://h.test/", headers: [["User-Agent", "x"], ["Accept", "*/*"]], body: null }), "curl --http1.1 --head 'http://h.test/' -H 'User-Agent: x' -H 'Accept: */*'");
  assert.match(curlCommand({ method: "GET", url: "http://h.test/a/../b", headers: [], body: null }), /--path-as-is/);
  assert.equal(shellQuote("a\tb"), "$'a\\tb'");
}

// 2. Binary detection: content type first, then sniffing.
{
  assert.equal(isBinaryBody([["Content-Type", "image/png"]], [0x89, 0x50]), true);
  assert.equal(isBinaryBody([["content-type", "application/json"]], encode("{\"a\":1}")), false);
  assert.equal(isBinaryBody([], [0x41, 0x00, 0x42]), true, "NUL sniffed");
  assert.equal(isBinaryBody([], [0xff, 0xfe, 0x41]), true, "invalid UTF-8 sniffed");
  assert.equal(isBinaryBody([], encode("héllo\r\nworld")), false, "text with CRLF is text");
  assert.equal(isBinaryBody([["Content-Type", "application/octet-stream"]], []), false, "empty is not binary");
}

// 3. Hex dump: offsets, grouping, ASCII gutter; lossless byte count.
{
  const bytes = [...Array(20).keys()].map((i) => (i === 1 ? 0x41 : i === 2 ? 0xff : i));
  const dump = hexDump(bytes).split("\n");
  assert.equal(dump.length, 2);
  assert.equal(dump[0], "00000000  00 41 ff 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |.A..............|");
  assert.equal(dump[1].slice(0, 8), "00000010");
  assert.equal(dump[1].split("|")[1], "....");
}

// 4. Non-printables become visible; LF stays a line break.
{
  assert.equal(showNonPrintables("a\r\nb\tc\x00\x7f"), "a␍↵\nb→c␀␡");
}

// 5. Inspector: query, cookies, headers, form/JSON body — each offset selects
//    exactly its value in the raw text.
{
  const raw = "POST /api/items?q=a%20b&page=2&flag HTTP/1.1\nHost: h.test\nCookie: sid=abc; theme=dark\nContent-Type: application/x-www-form-urlencoded\n\nuser=bob&pass=p%40ss";
  const inspected = inspectRequest(raw);
  const at = (item) => raw.slice(item.start, item.end);
  assert.deepEqual(inspected.query.map((q) => [q.name, at(q)]), [["q", "a%20b"], ["page", "2"], ["flag", ""]]);
  assert.equal(inspected.query[0].decodedValue, "a b");
  assert.deepEqual(inspected.cookies.map((c) => [c.name, at(c)]), [["sid", "abc"], ["theme", "dark"]]);
  assert.deepEqual(inspected.headers.map((h) => [h.name, at(h)]), [["Host", "h.test"], ["Cookie", "sid=abc; theme=dark"], ["Content-Type", "application/x-www-form-urlencoded"]]);
  assert.equal(inspected.bodyKind, "form");
  assert.deepEqual(inspected.body.map((b) => [b.name, at(b)]), [["user", "bob"], ["pass", "p%40ss"]]);
  assert.equal(inspected.body[1].decodedValue, "p@ss");

  const json = "PUT / HTTP/1.1\nContent-Type: application/json\n\n{\"name\": \"x\", \"n\": 3, \"o\": {\"k\": [1, 2]}}";
  const j = inspectRequest(json);
  assert.equal(j.bodyKind, "json");
  assert.deepEqual(j.body.map((b) => [b.name, json.slice(b.start, b.end)]), [["name", "\"x\""], ["n", "3"], ["o", "{\"k\": [1, 2]}"]]);
  assert.deepEqual(inspectRequest("GET / HTTP/1.1").headers, []);
}

// 6. Method swap touches only the method token; URL-encode; find.
{
  const raw = "GET /a?x=1 HTTP/1.1\nHost: h";
  assert.equal(requestMethod(raw), "GET");
  const swapped = setRequestMethod(raw, "PATCH");
  assert.equal(swapped.text, "PATCH /a?x=1 HTTP/1.1\nHost: h");
  assert.equal(swapped.delta, 2);
  assert.equal(urlEncode("a b&c=d/é!'()*~"), "a%20b%26c%3Dd%2F%C3%A9%21%27%28%29%2A~");
  assert.deepEqual(findAll("abcABCabc", "bc"), [1, 4, 7]);
  assert.deepEqual(findAll("aaaa", "aa"), [0, 2]);
  assert.deepEqual(findAll("x", ""), []);
}

console.log("Message tools OK: curl quoting, binary detection + hex, non-printables, Inspector offsets, method swap, URL-encode, find verified.");
