//! Shared raw-HTTP request editor model (Resend + Fuzz).
//!
//! Pure and DOM-free so it can be checked in isolation (see
//! `scripts/check-fuzz-template.mjs`). The editor buffer is a real HTTP/1.1
//! request: request-line + `Host` + headers + blank line + body. Rendering and
//! parsing round-trip to the backend's `{method, url, headers, body}`. The URL is
//! reconstructed from an *origin* (`scheme://authority`) plus the request-line
//! path — callers decide where the origin comes from (Resend: its Target field,
//! so an edited `Host` never moves the connection; Fuzz: scheme + `Host`).
//! Fuzz's `§` marker layer sits on top of these helpers in `fuzz/template.ts`.

import type { ResendRequest } from "../main";

export function decodeBody(body?: number[] | null): string {
  return body === null || body === undefined ? "" : new TextDecoder().decode(new Uint8Array(body));
}

export function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** Splits an absolute URL into scheme, authority (host[:port]), and path?query. */
export function splitUrl(url: string): { scheme: string; authority: string; pathAndQuery: string } {
  const schemeSep = url.indexOf("://");
  if (schemeSep === -1) return { scheme: "", authority: "", pathAndQuery: url === "" ? "/" : url };
  const rest = url.slice(schemeSep + 3);
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const pathAndQuery = slash === -1 ? "/" : rest.slice(slash);
  return { scheme: url.slice(0, schemeSep), authority, pathAndQuery };
}

/** `scheme://authority` of an absolute URL ("" when it has none). */
export function urlOrigin(url: string): string {
  const { scheme, authority } = splitUrl(url);
  return scheme === "" ? "" : `${scheme}://${authority}`;
}

/** Renders a request as an editable RAW HTTP request: request-line + `Host` +
 *  headers + blank line + body, headers in stored order and case. With
 *  `recomputeContentLength`, `Content-Length` shows the as-sent value (the body
 *  byte length), and an unframed body gains one — exactly what the backend puts
 *  on the wire — rather than a possibly stale stored value. */
export function rawRequestText(req: ResendRequest, opts: { recomputeContentLength?: boolean } = {}): string {
  const method = (req.method || "GET").toUpperCase();
  const { authority, pathAndQuery } = splitUrl(req.url);
  const body = decodeBody(req.body);
  const lines: string[] = [`${method} ${pathAndQuery} HTTP/1.1`];
  const hasHost = req.headers.some(([name]) => name.toLowerCase() === "host");
  if (!hasHost && authority !== "") lines.push(`Host: ${authority}`);
  let contentLengthShown = false;
  for (const [name, value] of req.headers) {
    if (opts.recomputeContentLength === true && name.toLowerCase() === "content-length") {
      lines.push(`${name}: ${byteLength(body)}`);
      contentLengthShown = true;
    } else {
      lines.push(`${name}: ${value}`);
    }
  }
  const framed = req.headers.some(([name]) => name.toLowerCase() === "transfer-encoding");
  if (opts.recomputeContentLength === true && !contentLengthShown && !framed && body !== "") {
    lines.push(`Content-Length: ${byteLength(body)}`);
  }
  const head = lines.join("\n");
  return body === "" ? head : `${head}\n\n${body}`;
}

/** The raw buffer split into its parts, text unmodified (markers intact). */
export interface RawRequestParts {
  /** Method token as written. */
  method: string;
  /** Request-target as written (HTTP version token removed). */
  target: string;
  /** Header lines as `[name, value]`, value with one leading space removed. */
  headers: [string, string][];
  body: string;
}

/** Splits a raw request buffer (CRLF-tolerant) into request-line, headers, and
 *  body on the first blank line. Header names/values keep their case and order. */
export function splitRawRequest(text: string): RawRequestParts {
  const normalized = text.replace(/\r\n/g, "\n");
  const sep = normalized.indexOf("\n\n");
  const head = sep === -1 ? normalized : normalized.slice(0, sep);
  const body = sep === -1 ? "" : normalized.slice(sep + 2);
  const headLines = head.split("\n");
  const requestLine = headLines[0] ?? "";
  const firstSpace = requestLine.indexOf(" ");
  const method = firstSpace === -1 ? requestLine : requestLine.slice(0, firstSpace);
  const rest = firstSpace === -1 ? "" : requestLine.slice(firstSpace + 1);
  // Drop a trailing HTTP-version token (` HTTP/1.1`); the target has no spaces.
  const versionMatch = rest.match(/\s+HTTP\/\d(?:\.\d)?\s*$/i);
  const target = versionMatch === null ? rest : rest.slice(0, versionMatch.index);
  const headers: [string, string][] = [];
  for (const line of headLines.slice(1)) {
    if (line.trim() === "") continue;
    const colon = line.indexOf(":");
    if (colon === -1) { headers.push([line.trim(), ""]); continue; }
    let value = line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    headers.push([line.slice(0, colon).trim(), value]);
  }
  return { method, target, headers, body };
}

/** Absolute URL for a request-target: an absolute-form target is used as-is;
 *  an origin-form path is joined onto `origin` (`scheme://authority`). */
export function absoluteUrl(target: string, origin: string): string {
  if (/^https?:\/\//i.test(target)) return target;
  const path = target.startsWith("/") ? target : `/${target}`;
  return `${origin.replace(/\/+$/, "")}${path}`;
}

/** A parsed raw request, ready for the backend. */
export interface ParsedRawRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body: number[];
  error?: string;
}

/** Parses the editor buffer against `origin`. What the operator wrote is what
 *  is sent: header order and case are kept; nothing is normalized. */
export function parseRawRequest(text: string, origin: string): ParsedRawRequest {
  const parts = splitRawRequest(text);
  const method = parts.method.trim();
  const url = absoluteUrl(parts.target.trim() === "" ? "/" : parts.target.trim(), origin);
  const base = { method: method || "GET", url, headers: parts.headers, body: [...new TextEncoder().encode(parts.body)] };
  if (method === "") return { ...base, error: "The request line needs a method, e.g. GET /path HTTP/1.1." };
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(method)) return { ...base, error: `"${method}" is not a valid HTTP method.` };
  if (/\s/.test(parts.target.trim())) return { ...base, error: "The request line must be METHOD /path HTTP/1.1 (the path cannot contain spaces)." };
  if (!/^https?:\/\/[^/\s]+/i.test(url)) return { ...base, error: "Set the target (e.g. https://api.example.com) or use an absolute URL in the request line." };
  const bad = parts.headers.find(([name]) => !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name));
  if (bad !== undefined) return { ...base, error: `"${bad[0]}" is not a valid header name (expected Name: value).` };
  return base;
}

/** Keeps `Content-Length` showing the as-sent value while the operator edits:
 *  updates an existing header in place, or adds one when a body appears with
 *  no framing header. Returns null when nothing changes; otherwise the new text
 *  and the edit (offset + length delta) so the caller can keep the caret. */
export function syncContentLength(text: string): { text: string; at: number; delta: number } | null {
  const normalized = text.replace(/\r\n/g, "\n");
  if (normalized !== text) return null;
  const sep = text.indexOf("\n\n");
  if (sep === -1) return null;
  const length = String(byteLength(text.slice(sep + 2)));
  const head = text.slice(0, sep);
  const match = /(^|\n)(content-length[ \t]*:[ \t]*)([^\n]*)/i.exec(head);
  if (match !== null) {
    const valueStart = match.index + match[1].length + match[2].length;
    const current = match[3];
    if (current.trim() === length) return null;
    return { text: text.slice(0, valueStart) + length + text.slice(valueStart + current.length), at: valueStart, delta: length.length - current.length };
  }
  if (/(^|\n)transfer-encoding[ \t]*:/i.test(head) || length === "0") return null;
  const line = `\nContent-Length: ${length}`;
  return { text: head + line + text.slice(sep), at: sep, delta: line.length };
}
