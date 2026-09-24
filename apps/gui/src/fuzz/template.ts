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
