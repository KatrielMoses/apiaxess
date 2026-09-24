//! Pure Fuzz request-template model: raw-HTTP rendering and marker parsing.
//!
//! Kept free of DOM/state so it can be unit-checked in isolation (see
//! `scripts/check-fuzz-template.mjs`). The template is a real raw HTTP request —
//! request-line + `Host` + headers + blank line + body — that the operator marks
//! `§…§` positions on, exactly like Burp. Parsing reconstructs the absolute URL
//! (scheme from the captured flow + `Host` header + request-line path) and maps
//! each marker to a byte range in the backend's `{location,start,end}` model.

import type { FuzzerLocation, ResendRequest } from "../main";

/** The payload-position marker (Burp's `§`). Wrap a value in a pair to fuzz it. */
export const FUZZ_MARK = "§";

/** A parsed template: the base request plus payload positions as byte ranges. */
export interface ParsedTemplate {
  method: string;
  url: string;
  headers: [string, string][];
  body: number[];
  positions: { location: FuzzerLocation; headerName: string | null; start: number; end: number }[];
  error?: string;
}

function decodeBody(body?: number[] | null): string {
  return body === null || body === undefined ? "" : new TextDecoder().decode(new Uint8Array(body));
}
function byteLength(text: string): number {
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

/** Renders a request as an editable RAW HTTP request: request-line + `Host` +
 *  headers + blank line + body. With `recomputeContentLength`, `Content-Length`
 *  is shown as the actual body byte length (what goes on the wire), not the
 *  possibly-stale stored value. */
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
  if (opts.recomputeContentLength === true && !contentLengthShown && body !== "") {
    lines.push(`Content-Length: ${byteLength(body)}`);
  }
  const head = lines.join("\n");
  return body === "" ? head : `${head}\n\n${body}`;
}

/** Removes every `§` marker from the text. */
export function stripFuzzMarks(text: string): string {
  return text.split(FUZZ_MARK).join("");
}

/** Number of complete `§…§` marker pairs in the template. */
export function countTemplatePositions(template: string): number {
  return Math.floor((template.split(FUZZ_MARK).length - 1) / 2);
}

/** Extracts marker pairs from one field, recording each as a byte range in the
 *  marker-stripped field. Returns null when the field's markers are unbalanced. */
export function extractFieldMarkers(
  field: string,
  location: FuzzerLocation,
  headerName: string | null,
  out: ParsedTemplate["positions"],
): string | null {
  const parts = field.split(FUZZ_MARK);
  if ((parts.length - 1) % 2 !== 0) return null;
  let clean = "";
  parts.forEach((part, index) => {
    if (index % 2 === 0) { clean += part; return; }
    const start = clean.length;
    clean += part;
    out.push({ location, headerName, start, end: clean.length });
  });
  return clean;
}

/** Compiles a `§`-marked raw HTTP request into a base request plus payload
 *  positions. `scheme` (from the captured flow's origin) reconstructs the
 *  absolute URL from the request-line path and the `Host` header; URL marker
 *  offsets are shifted onto that absolute URL so the backend applies them exactly
 *  as before the raw-template change. */
export function parseFuzzTemplate(template: string, scheme: string): ParsedTemplate {
  const normalized = template.replace(/\r\n/g, "\n");
  const empty: ParsedTemplate = { method: "GET", url: "", headers: [], body: [], positions: [] };
  if ((normalized.split(FUZZ_MARK).length - 1) % 2 !== 0) {
    return { ...empty, error: "Unbalanced § markers — each position needs an opening and a closing §." };
  }
  const sep = normalized.indexOf("\n\n");
  const head = sep === -1 ? normalized : normalized.slice(0, sep);
  const bodyRaw = sep === -1 ? "" : normalized.slice(sep + 2);
  const headLines = head.split("\n");
  const requestLine = headLines[0] ?? "";
  const firstSpace = requestLine.indexOf(" ");
  const method = stripFuzzMarks(firstSpace === -1 ? requestLine : requestLine.slice(0, firstSpace)).trim() || "GET";
  const rawRest = firstSpace === -1 ? "" : requestLine.slice(firstSpace + 1);
  // Drop a trailing HTTP-version token (` HTTP/1.1`); the target has no spaces.
  const versionMatch = rawRest.match(/\s+HTTP\/\d(?:\.\d)?\s*$/i);
  const targetRaw = versionMatch === null ? rawRest : rawRest.slice(0, versionMatch.index);

  // Headers first — to find Host — recording their marker positions.
  const headerPositions: ParsedTemplate["positions"] = [];
  const headers: [string, string][] = [];
  for (const line of headLines.slice(1)) {
    if (line.trim() === "") continue;
    const colon = line.indexOf(":");
    if (colon === -1) { headers.push([stripFuzzMarks(line).trim(), ""]); continue; }
    const name = stripFuzzMarks(line.slice(0, colon)).trim();
    let valueRaw = line.slice(colon + 1);
    if (valueRaw.startsWith(" ")) valueRaw = valueRaw.slice(1);
    const value = extractFieldMarkers(valueRaw, "header", name, headerPositions);
    if (value === null) return { ...empty, error: `Markers in the "${name}" header are unbalanced.` };
    headers.push([name, value]);
  }
  const host = headers.find(([name]) => name.toLowerCase() === "host")?.[1] ?? "";

  // URL: extract markers from the request-line target, then reconstruct the
  // absolute URL and shift the offsets onto it.
  const urlPositions: ParsedTemplate["positions"] = [];
  const cleanTarget = extractFieldMarkers(targetRaw, "url", null, urlPositions);
  if (cleanTarget === null) return { ...empty, error: "Markers in the request line are unbalanced." };
  let url: string;
  if (/^https?:\/\//i.test(cleanTarget)) {
    url = cleanTarget;
  } else {
    const effectiveScheme = scheme || "http";
    const path = cleanTarget.startsWith("/") ? cleanTarget : `/${cleanTarget}`;
    url = `${effectiveScheme}://${host}${path}`;
  }
  const shift = url.length - cleanTarget.length;
  for (const position of urlPositions) { position.start += shift; position.end += shift; }

  // Body last.
  const bodyPositions: ParsedTemplate["positions"] = [];
  const body = extractFieldMarkers(bodyRaw, "body", null, bodyPositions);
  if (body === null) return { ...empty, error: "Markers in the body are unbalanced." };

  // Preserve the historical position order: URL, then headers, then body.
  const positions = [...urlPositions, ...headerPositions, ...bodyPositions];
  return { method, url, headers, body: [...new TextEncoder().encode(body)], positions };
}
