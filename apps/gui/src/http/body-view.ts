//! Display-only body formatting for the workbench (Pretty | Raw).
//!
//! Pretty is a *view*: it never feeds back into what is sent. Pure so it can be
//! checked in isolation alongside the request editor.

/** Whether the headers or the text itself say this body is JSON. */
export function isJsonBody(headers: readonly [string, string][], text: string): boolean {
  const type = headers.find(([name]) => name.toLowerCase() === "content-type")?.[1].toLowerCase() ?? "";
  if (/(^|[/+])json(\s*;|$)/.test(type)) return true;
  const trimmed = text.trim();
  return (trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"));
}

/** Pretty-printed JSON, or null when the text is not valid JSON. */
export function prettyJson(text: string): string | null {
  if (text.trim() === "") return null;
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return null;
  }
}

/** The body as it should be shown in Pretty mode: formatted JSON when it is
 *  JSON, otherwise the text unchanged. */
export function prettyBody(headers: readonly [string, string][], text: string): { text: string; formatted: boolean } {
  if (!isJsonBody(headers, text)) return { text, formatted: false };
  const pretty = prettyJson(text);
  return pretty === null ? { text, formatted: false } : { text: pretty, formatted: true };
}
