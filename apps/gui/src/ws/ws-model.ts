/* WebSocket tab: pure model helpers (no DOM). Decodes captured payloads and
 * renders them Pretty / Raw / Hex, reusing the Resend message tools, and
 * filters the connection list. Checked by scripts/check-ws-model.mjs. */

import { hexDump, isBinaryBody, showNonPrintables } from "../http/message-tools.ts";

export type WsDirection = "client_to_server" | "server_to_client";
export type WsKind = "text" | "binary" | "ping" | "pong" | "close" | "frame";
export type WsParty = "first_party" | "third_party";
export type WsView = "pretty" | "raw" | "hex";

/** A captured WebSocket connection, as the engine reports it. */
export interface WsConnection {
  readonly id: number;
  readonly url: string;
  readonly host?: string | null;
  readonly path?: string | null;
  readonly scope: string;
  readonly origin: string;
  readonly openedAt: string;
  readonly closedAt?: string | null;
  readonly closeCode?: number | null;
  readonly messageCount: number;
  readonly party?: WsParty | null;
}

/** A captured WebSocket message, as the engine reports it. */
export interface WsMessage {
  readonly sequence: number;
  readonly direction: WsDirection;
  readonly kind: WsKind;
  readonly payloadBase64: string;
  readonly retainedBytes: number;
  readonly payloadBytes: number;
  readonly observedAt: string;
}

/** Payload bytes from their base64 form. */
export function decodePayload(base64: string): number[] {
  if (base64 === "") return [];
  const binary = atob(base64);
  const bytes = new Array<number>(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function utf8(bytes: readonly number[]): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
}

/** The view a message opens in: Hex for binary data, Pretty otherwise. */
export function defaultView(message: WsMessage, bytes: readonly number[]): WsView {
  if (message.kind === "binary") return "hex";
  if (message.kind === "text") return "pretty";
  return isBinaryBody([], bytes) ? "hex" : "raw";
}

/** A payload rendered for display in the chosen view. Pretty indents JSON and
 *  falls back to the raw text for anything that is not JSON. */
export function renderPayload(bytes: readonly number[], view: WsView): string {
  if (view === "hex") return hexDump(bytes);
  const text = utf8(bytes);
  if (view === "pretty") {
    const trimmed = text.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try {
        return JSON.stringify(JSON.parse(trimmed), null, 2);
      } catch {
        /* not JSON: show it as it is */
      }
    }
    return text;
  }
  return showNonPrintables(text);
}

/** A one-line preview of a message for the stream list. */
export function previewPayload(message: WsMessage, bytes: readonly number[], limit = 120): string {
  if (bytes.length === 0) return message.kind === "close" ? "(close)" : "(empty)";
  if (message.kind === "binary" || isBinaryBody([], bytes)) return `${message.payloadBytes} bytes binary`;
  const text = utf8(bytes).replace(/\s+/g, " ").trim();
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
}

/** Whether a message's payload was cut short when captured or streamed. */
export function isTruncated(message: WsMessage): boolean {
  return message.retainedBytes < message.payloadBytes;
}

/** Connections matching a host filter (comma-separated; `*.example.com`
 *  matches subdomains; blank matches all) and the open-only toggle. */
export function filterConnections(connections: readonly WsConnection[], hostFilter: string, openOnly: boolean): WsConnection[] {
  const patterns = hostFilter.split(",").map((value) => value.trim().toLowerCase()).filter((value) => value !== "");
  return connections.filter((connection) => {
    if (openOnly && (connection.closedAt ?? null) !== null) return false;
    if (patterns.length === 0) return true;
    const host = (connection.host ?? "").toLowerCase();
    return patterns.some((pattern) => pattern.startsWith("*.") ? host === pattern.slice(2) || host.endsWith(pattern.slice(1)) : host === pattern || host.includes(pattern));
  });
}

/** Merges a live update into a connection list: replaces by id, keeping order.
 *  Live records carry no party (the engine classifies hosts on list reads),
 *  so a known party is kept. */
export function upsertConnection(connections: readonly WsConnection[], connection: WsConnection): WsConnection[] {
  const index = connections.findIndex((existing) => existing.id === connection.id);
  if (index === -1) return [...connections, connection];
  const next = [...connections];
  next[index] = { ...connection, party: connection.party ?? connections[index]?.party ?? null };
  return next;
}
