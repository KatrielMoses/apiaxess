//! Pure helpers for the Resend message editors (RS5): copy-as-curl, hex dump,
//! binary detection, visible non-printables, the read-mostly Inspector's parse
//! of the raw request (with offsets back into the raw text), method swap, and
//! URL-encoding. DOM-free so `scripts/check-message-tools.mjs` can run it.
//!
//! The raw buffer stays the single source of truth: the Inspector only reports
//! where things are in it, and every edit helper returns new raw text.

import type { ResendRequest } from "../main";

/* ------------------------------------------------------------------ *
 * Copy as curl
 * ------------------------------------------------------------------ */

/** POSIX-shell quoting: `'…'` for printable text, `$'…'` with escapes when the
 *  value holds control bytes or non-ASCII that must survive byte-exact. */
export function shellQuote(value: string): string {
  if (!/[\x00-\x1f\x7f]/.test(value)) return `'${value.replace(/'/g, `'\\''`)}'`;
  const escaped = [...value].map((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === "\\") return "\\\\";
    if (ch === "'") return "\\'";
    if (ch === "\n") return "\\n";
    if (ch === "\r") return "\\r";
    if (ch === "\t") return "\\t";
    if (code < 0x20 || code === 0x7f) return `\\x${code.toString(16).padStart(2, "0")}`;
    return ch;
  }).join("");
  return `$'${escaped}'`;
}

/** Whether a body can travel as a plain single-quoted argument: printable
 *  ASCII, tabs and line feeds only. Anything else (non-ASCII, CR, NUL, other
 *  control bytes) is piped instead — see {@link curlCommand}. */
function isPlainAsciiBody(bytes: readonly number[]): boolean {
  return bytes.every((b) => (b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a);
}

/** A POSIX `printf` format that writes exactly `bytes`: printable ASCII as is,
 *  `%` and `\` escaped, every other byte as a 3-digit octal escape. */
function printfFormat(bytes: readonly number[]): string {
  const format = bytes.map((b) => {
    if (b === 0x25) return "%%";
    if (b === 0x5c) return "\\\\";
    if (b >= 0x20 && b < 0x7f) return String.fromCharCode(b);
    return `\\${b.toString(8).padStart(3, "0")}`;
  }).join("");
  return shellQuote(format);
}

/** A runnable curl (bash/zsh) reproducing the request: method, URL, headers in
 *  their written order and case, and the exact body bytes. HTTP/1.1 like the
 *  Resend sender; `--path-as-is` keeps `..`/`.` segments curl would squash.
 *
 *  Content-Length is left to curl, which counts the bytes it actually sends —
 *  a pinned value hangs the server whenever a shell or console code page
 *  changes the body's byte count. A body that is not plain ASCII is piped
 *  through `printf` (octal escapes) into `--data-binary @-`: shell arguments
 *  cannot hold NUL bytes and are re-encoded on the way to Windows `curl.exe`,
 *  but a pipe carries the bytes untouched. */
export function curlCommand(request: ResendRequest): string {
  const method = (request.method || "GET").toUpperCase();
  const body = request.body ?? [];
  const parts = ["curl", "--http1.1"];
  if (/\/\.\.?(\/|$|\?)/.test(request.url)) parts.push("--path-as-is");
  const implied = body.length > 0 ? "POST" : "GET";
  if (method === "HEAD" && body.length === 0) parts.push("--head");
  else if (method !== implied) parts.push("-X", shellQuote(method));
  parts.push(shellQuote(request.url));
  const has = (header: string): boolean => request.headers.some(([name]) => name.toLowerCase() === header);
  for (const [name, value] of request.headers) {
    if (name.toLowerCase() === "content-length") continue;
    // An empty value needs curl's `Name;` form; `Name:` alone removes it.
    parts.push("-H", shellQuote(value === "" ? `${name};` : `${name}: ${value}`));
  }
  // curl adds these by default; drop them when the request does not have them.
  for (const implicit of ["User-Agent", "Accept"]) {
    if (!has(implicit.toLowerCase())) parts.push("-H", shellQuote(`${implicit}:`));
  }
  if (body.length === 0) return parts.join(" ");
  // --data-binary would otherwise add a form Content-Type the request lacks.
  if (!has("content-type")) parts.push("-H", shellQuote("Content-Type:"));
  if (isPlainAsciiBody(body)) {
    parts.push("--data-binary", shellQuote(String.fromCharCode(...body)));
    return parts.join(" ");
  }
  parts.push("--data-binary", "@-");
  return `printf ${printfFormat(body)} | ${parts.join(" ")}`;
}

/* ------------------------------------------------------------------ *
 * Binary detection + hex
 * ------------------------------------------------------------------ */

const TEXT_TYPE = /^(text\/|application\/([\w.+-]+\+)?(json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|x-yaml|csv|x-ndjson|problem\+json|ld\+json|html|xhtml\+xml|sql)\b)|^image\/svg\+xml|^message\/http/;
const BINARY_TYPE = /^(image|audio|video|font)\/|^application\/(octet-stream|pdf|zip|gzip|x-gzip|x-tar|x-7z|x-rar|vnd\.|protobuf|x-protobuf|grpc|msgpack|x-msgpack|cbor|wasm|java-archive|x-java|x-executable|x-sqlite)/;

/** Whether a body should be shown as hex rather than text: by content type
 *  when it is decisive, else by sniffing (NUL bytes or invalid UTF-8). */
export function isBinaryBody(headers: readonly [string, string][], body: readonly number[] | null | undefined): boolean {
  if (body === null || body === undefined || body.length === 0) return false;
  const type = (headers.find(([name]) => name.toLowerCase() === "content-type")?.[1] ?? "").toLowerCase().trim();
  if (TEXT_TYPE.test(type)) return false;
  if (BINARY_TYPE.test(type)) return true;
  const sample = body.slice(0, 4096);
  if (sample.includes(0)) return true;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(sample.length === body.length ? sample : trimPartialUtf8(sample)));
  } catch {
    return true;
  }
  let controls = 0;
  for (const b of sample) if (b < 0x20 && b !== 0x09 && b !== 0x0a && b !== 0x0d && b !== 0x0c && b !== 0x1b) controls += 1;
  return controls / sample.length > 0.1;
}

/** Drops a UTF-8 sequence cut off at the end of a sample. */
function trimPartialUtf8(bytes: number[]): number[] {
  let end = bytes.length;
  for (let back = 1; back <= 3 && end - back >= 0; back += 1) {
    const b = bytes[end - back];
    if ((b & 0xc0) === 0x80) continue;
    const need = b >= 0xf0 ? 4 : b >= 0xe0 ? 3 : b >= 0xc0 ? 2 : 1;
    if (need > back) end -= back;
    break;
  }
  return bytes.slice(0, end);
}

/** Classic hex dump: offset, 16 bytes in two groups of 8, printable ASCII. */
export function hexDump(bytes: readonly number[]): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16);
    const hex = Array.from({ length: 16 }, (_, i) => (i < row.length ? row[i].toString(16).padStart(2, "0") : "  "));
    const ascii = row.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.slice(0, 8).join(" ")}  ${hex.slice(8).join(" ")}  |${ascii}|`);
  }
  return lines.join("\n");
}

/* ------------------------------------------------------------------ *
 * Visible non-printables
 * ------------------------------------------------------------------ */

/** Text with control characters drawn as visible symbols: `␍` before a line
 *  break for CR, `→` for tab, Control Pictures (␀ ␛ …) for the rest, `␡` for DEL.
 *  Line feeds stay real line breaks (shown with a trailing `↵`). */
export function showNonPrintables(text: string): string {
  let out = "";
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === "\n") out += "↵\n";
    else if (ch === "\r") out += "␍";
    else if (ch === "\t") out += "→";
    else if (code < 0x20) out += String.fromCodePoint(0x2400 + code);
    else if (code === 0x7f) out += "␡";
    else if (code === 0xa0) out += "⍽";
    else if (code === 0xfeff || code === 0x200b) out += `⟨U+${code.toString(16).toUpperCase().padStart(4, "0")}⟩`;
    else out += ch;
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * Inspector: structured view of the raw request, with offsets
 * ------------------------------------------------------------------ */

/** One Inspector row. `start`/`end` delimit the value in the raw text (what a
 *  click selects for editing); `lineStart`/`lineEnd` the whole item. */
export interface InspectorItem {
  name: string;
  value: string;
  /** URL-decoded name/value for display, when they differ from the raw. */
  decodedName?: string;
  decodedValue?: string;
  start: number;
  end: number;
  lineStart: number;
  lineEnd: number;
}

export interface InspectedRequest {
  query: InspectorItem[];
  cookies: InspectorItem[];
  headers: InspectorItem[];
  body: InspectorItem[];
  bodyKind: "form" | "json" | null;
}

function safeDecode(text: string): string {
  try { return decodeURIComponent(text.replace(/\+/g, " ")); } catch { return text; }
}

/** `a=1&b=2` pairs at `base` offset in the raw text. */
function pairs(text: string, base: number, separator: string): InspectorItem[] {
  const items: InspectorItem[] = [];
  let cursor = 0;
  for (const segment of text.split(separator)) {
    const segStart = base + cursor;
    cursor += segment.length + separator.length;
    if (segment.trim() === "") continue;
    const leading = segment.length - segment.trimStart().length;
    const body = segment.trim();
    const eq = body.indexOf("=");
    const name = eq === -1 ? body : body.slice(0, eq);
    const value = eq === -1 ? "" : body.slice(eq + 1);
    const nameStart = segStart + leading;
    const valueStart = eq === -1 ? nameStart + name.length : nameStart + eq + 1;
    const item: InspectorItem = { name, value, start: valueStart, end: valueStart + value.length, lineStart: nameStart, lineEnd: nameStart + body.length };
    const dn = safeDecode(name);
    const dv = safeDecode(value);
    if (dn !== name) item.decodedName = dn;
    if (dv !== value) item.decodedValue = dv;
    items.push(item);
  }
  return items;
}

/** Parses the raw editor text (LF line breaks, as a textarea holds it) into
 *  query parameters, cookies, headers, and form/JSON body parameters, each
 *  pointing back at its position in that same text. */
export function inspectRequest(raw: string): InspectedRequest {
  const sep = raw.indexOf("\n\n");
  const headEnd = sep === -1 ? raw.length : sep;
  const lineEnd = raw.indexOf("\n");
  const requestLine = raw.slice(0, lineEnd === -1 || lineEnd > headEnd ? headEnd : lineEnd);
  const result: InspectedRequest = { query: [], cookies: [], headers: [], body: [], bodyKind: null };

  const firstSpace = requestLine.indexOf(" ");
  if (firstSpace !== -1) {
    const targetStart = firstSpace + 1;
    const rest = requestLine.slice(targetStart);
    const version = rest.match(/\s+HTTP\/\d(?:\.\d)?\s*$/i);
    const target = version === null ? rest : rest.slice(0, version.index);
    const q = target.indexOf("?");
    if (q !== -1) {
      const hash = target.indexOf("#", q);
      const query = target.slice(q + 1, hash === -1 ? undefined : hash);
      result.query = pairs(query, targetStart + q + 1, "&");
    }
  }

  let contentType = "";
  let offset = requestLine.length + 1;
  const headLines = raw.slice(offset, headEnd);
  if (offset <= headEnd) {
    for (const line of headLines.split("\n")) {
      const start = offset;
      offset += line.length + 1;
      if (line.trim() === "") continue;
      const colon = line.indexOf(":");
      const name = (colon === -1 ? line : line.slice(0, colon)).trim();
      let valueStart = colon === -1 ? start + line.length : start + colon + 1;
      while (valueStart < start + line.length && raw[valueStart] === " ") valueStart += 1;
      const value = raw.slice(valueStart, start + line.length);
      result.headers.push({ name, value, start: valueStart, end: start + line.length, lineStart: start, lineEnd: start + line.length });
      const lower = name.toLowerCase();
      if (lower === "cookie") result.cookies.push(...pairs(value, valueStart, ";"));
      if (lower === "content-type") contentType = value.toLowerCase();
    }
  }

  if (sep !== -1) {
    const bodyStart = sep + 2;
    const body = raw.slice(bodyStart);
    if (contentType.includes("x-www-form-urlencoded")) {
      result.bodyKind = "form";
      result.body = pairs(body, bodyStart, "&");
    } else if (/json/.test(contentType) || /^\s*\{/.test(body)) {
      const parsed = (() => { try { return JSON.parse(body) as unknown; } catch { return undefined; } })();
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        result.bodyKind = "json";
        let from = 0;
        for (const [key, val] of Object.entries(parsed as Record<string, unknown>)) {
          const quoted = JSON.stringify(key);
          const at = body.indexOf(quoted, from);
          const colon = at === -1 ? -1 : body.indexOf(":", at + quoted.length);
          let valueStart = colon === -1 ? -1 : colon + 1;
          while (valueStart !== -1 && /\s/.test(body[valueStart] ?? "")) valueStart += 1;
          const rendered = JSON.stringify(val);
          const valueEnd = valueStart === -1 ? -1 : valueStart + (typeof val === "object" && val !== null ? jsonValueLength(body, valueStart) : rendered.length);
          const item: InspectorItem = at === -1
            ? { name: key, value: rendered, start: bodyStart, end: bodyStart, lineStart: bodyStart, lineEnd: bodyStart }
            : { name: key, value: typeof val === "string" ? val : rendered, start: bodyStart + valueStart, end: bodyStart + valueEnd, lineStart: bodyStart + at, lineEnd: bodyStart + valueEnd };
          if (at !== -1) from = valueEnd;
          result.body.push(item);
        }
      }
    }
  }
  return result;
}

/** Length of the JSON object/array starting at `start` (bracket matching,
 *  string-aware). */
function jsonValueLength(text: string, start: number): number {
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      if (ch === "\\") i += 1;
      else if (ch === "\"") inString = false;
    } else if (ch === "\"") inString = true;
    else if (ch === "{" || ch === "[") depth += 1;
    else if (ch === "}" || ch === "]") {
      depth -= 1;
      if (depth === 0) return i + 1 - start;
    }
  }
  return text.length - start;
}

/* ------------------------------------------------------------------ *
 * Mutation helpers (all return new raw text)
 * ------------------------------------------------------------------ */

/** The method token of the request line. */
export function requestMethod(raw: string): string {
  const line = raw.split("\n", 1)[0] ?? "";
  const space = line.indexOf(" ");
  return (space === -1 ? line : line.slice(0, space)).trim();
}

/** Replaces the request line's method token, leaving everything else as is. */
export function setRequestMethod(raw: string, method: string): { text: string; delta: number; at: number } {
  const line = raw.split("\n", 1)[0] ?? "";
  const space = line.indexOf(" ");
  const current = space === -1 ? line : line.slice(0, space);
  return { text: method + raw.slice(current.length), delta: method.length - current.length, at: current.length };
}

/** URL-encodes text for a query/form value: RFC 3986 unreserved characters
 *  stay, everything else (including `!'()*`) is percent-encoded as UTF-8. */
export function urlEncode(text: string): string {
  return encodeURIComponent(text).replace(/[!'()*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Every match of `query` (case-insensitive) in `text`, as start offsets. */
export function findAll(text: string, query: string): number[] {
  if (query === "") return [];
  const hay = text.toLowerCase();
  const needle = query.toLowerCase();
  const hits: number[] = [];
  for (let at = hay.indexOf(needle); at !== -1; at = hay.indexOf(needle, at + Math.max(1, needle.length))) hits.push(at);
  return hits;
}
