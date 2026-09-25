//! Pure Fuzz request-template model: raw-HTTP rendering and marker parsing.
//!
//! Kept free of DOM/state so it can be unit-checked in isolation (see
//! `scripts/check-fuzz-template.mjs`). The template is a real raw HTTP request —
//! request-line + `Host` + headers + blank line + body — that the operator marks
//! `§…§` positions on, exactly like Burp. Parsing reconstructs the absolute URL
//! (scheme from the captured flow + `Host` header + request-line path) and maps
//! each marker to a byte range in the backend's `{location,start,end}` model.

import type { FuzzerLocation } from "../main";
import { absoluteUrl, splitRawRequest } from "../http/request-editor.ts";

// The raw render/parse core is shared with Resend; re-exported for callers of
// the Fuzz template API.
export { rawRequestText, splitUrl } from "../http/request-editor.ts";

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

/** Removes every `§` marker from the text. */
export function stripFuzzMarks(text: string): string {
  return text.split(FUZZ_MARK).join("");
}

/** Number of complete `§…§` marker pairs in the template. */
export function countTemplatePositions(template: string): number {
  return Math.floor((template.split(FUZZ_MARK).length - 1) / 2);
}

/** Byte ranges of every JSON *value* (not object keys) in `text`, in order.
 *  Strings mark their content inside the quotes; numbers/`true`/`false`/`null`
 *  mark the whole token. Nested object/array members are included; the
 *  containers themselves are not. Returns [] when `text` is not valid JSON, so
 *  Auto § never mangles a body it doesn't understand. */
export function jsonValueSpans(text: string): [number, number][] {
  try {
    JSON.parse(text);
  } catch {
    return [];
  }
  const spans: [number, number][] = [];
  const stack: { array: boolean; expectKey: boolean }[] = [];
  const isWs = (c: string): boolean => c === " " || c === "\t" || c === "\n" || c === "\r";
  const atValue = (): boolean => {
    const top = stack[stack.length - 1];
    return top === undefined || top.array || !top.expectKey;
  };
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (isWs(c)) { i++; continue; }
    if (c === "{") { stack.push({ array: false, expectKey: true }); i++; continue; }
    if (c === "[") { stack.push({ array: true, expectKey: false }); i++; continue; }
    if (c === "}" || c === "]") { stack.pop(); i++; continue; }
    if (c === ":") { const top = stack[stack.length - 1]; if (top !== undefined) top.expectKey = false; i++; continue; }
    if (c === ",") { const top = stack[stack.length - 1]; if (top !== undefined && !top.array) top.expectKey = true; i++; continue; }
    if (c === '"') {
      const start = i;
      i++;
      while (i < text.length) {
        if (text[i] === "\\") { i += 2; continue; }
        if (text[i] === '"') { i++; break; }
        i++;
      }
      // Mark a non-empty string value's content, quotes excluded.
      if (atValue() && i - 1 > start + 1) spans.push([start + 1, i - 1]);
      continue;
    }
    // A bare token: number, true, false, or null.
    const start = i;
    while (i < text.length && !isWs(text[i]) && !",}]".includes(text[i])) i++;
    if (i > start && atValue()) spans.push([start, i]);
  }
  return spans;
}

/** Wraps each JSON value in `body` with `§…§`, preserving keys and structure.
 *  Returns `body` unchanged when it is not JSON or has no markable value. */
export function markJsonBodyValues(body: string): string {
  const spans = jsonValueSpans(body);
  if (spans.length === 0) return body;
  // Insert from the end so earlier offsets stay valid.
  let marked = body;
  for (let index = spans.length - 1; index >= 0; index--) {
    const [start, end] = spans[index];
    marked = `${marked.slice(0, start)}${FUZZ_MARK}${marked.slice(start, end)}${FUZZ_MARK}${marked.slice(end)}`;
  }
  return marked;
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
  const empty: ParsedTemplate = { method: "GET", url: "", headers: [], body: [], positions: [] };
  if ((template.split(FUZZ_MARK).length - 1) % 2 !== 0) {
    return { ...empty, error: "Unbalanced § markers — each position needs an opening and a closing §." };
  }
  const parts = splitRawRequest(template);
  const method = stripFuzzMarks(parts.method).trim() || "GET";
  const targetRaw = parts.target;

  // Headers first — to find Host — recording their marker positions.
  const headerPositions: ParsedTemplate["positions"] = [];
  const headers: [string, string][] = [];
  for (const [nameRaw, valueRaw] of parts.headers) {
    const name = stripFuzzMarks(nameRaw).trim();
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
  const url = absoluteUrl(cleanTarget, `${scheme || "http"}://${host}`);
  const shift = url.length - cleanTarget.length;
  for (const position of urlPositions) { position.start += shift; position.end += shift; }

  // Body last.
  const bodyPositions: ParsedTemplate["positions"] = [];
  const body = extractFieldMarkers(parts.body, "body", null, bodyPositions);
  if (body === null) return { ...empty, error: "Markers in the body are unbalanced." };

  // Preserve the historical position order: URL, then headers, then body.
  const positions = [...urlPositions, ...headerPositions, ...bodyPositions];
  return { method, url, headers, body: [...new TextEncoder().encode(body)], positions };
}
