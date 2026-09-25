/* What kind of HTTP flow a captured flow is, beyond plain request/response:
 * a Server-Sent Events stream (read as a list of events) or a gRPC call (a
 * protobuf RPC on a /package.Service/Method path). Pure helpers (no DOM),
 * checked by scripts/check-flow-kind.mjs. The gRPC path rule mirrors the
 * engine's parse_grpc_method_path. */

/** The event-stream state the engine reports on an SSE flow. */
export interface SseState {
  readonly eventCount: number;
  readonly closed: boolean;
}

/** One captured Server-Sent Event, as the engine reports it. */
export interface SseEvent {
  readonly flowId: number;
  readonly sequence: number;
  readonly event?: string | null;
  readonly data: string;
  readonly dataBytes: number;
  readonly id?: string | null;
  readonly retryMs?: number | null;
  readonly observedAt: string;
}

/** A gRPC method: the service and the rpc on it. */
export interface GrpcMethod {
  readonly service: string;
  readonly method: string;
}

/** The row label of a streaming flow: never reads as a hung request. */
export function sseLabel(state: SseState): string {
  const count = `${state.eventCount} event${state.eventCount === 1 ? "" : "s"}`;
  return state.closed ? `stream ended · ${count}` : `streaming · ${count}`;
}

const PROTO_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Parses a gRPC method path, `/package.Service/Method`, or returns null. */
export function parseGrpcMethodPath(path: string): GrpcMethod | null {
  if (!path.startsWith("/")) return null;
  const segments = path.slice(1).split("/");
  if (segments.length !== 2) return null;
  const [service = "", method = ""] = segments;
  if (!PROTO_IDENTIFIER.test(method)) return null;
  if (!service.split(".").every((part) => PROTO_IDENTIFIER.test(part))) return null;
  return { service, method };
}

/** Whether a content type is a gRPC one (grpc, grpc+proto, grpc-web, ...). */
export function isGrpcContentType(contentType: string | null | undefined): boolean {
  return (contentType ?? "").trim().toLowerCase().startsWith("application/grpc");
}

/** The gRPC method a flow calls, when it carries a gRPC content type on a
 *  method path; null for anything else. */
export function grpcMethodOf(contentTypes: readonly (string | null | undefined)[], path: string | null | undefined): GrpcMethod | null {
  if (!contentTypes.some(isGrpcContentType)) return null;
  return parseGrpcMethodPath((path ?? "").split("?")[0] ?? "");
}

/** An event's data for display: JSON indented, anything else as sent. */
export function renderEventData(data: string): string {
  const trimmed = data.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      /* not JSON: show it as it is */
    }
  }
  return data;
}

/** Whether an event's data was cut short when captured or streamed. */
export function isEventTruncated(event: SseEvent): boolean {
  return new TextEncoder().encode(event.data).length < event.dataBytes;
}

/** Appends live events to a loaded, gap-free list. Returns false (the list is
 *  then stale and must be re-read) when an event arrives past a gap. */
export function appendLiveEvents(loaded: SseEvent[], events: readonly SseEvent[]): boolean {
  for (const event of events) {
    const last = loaded.at(-1)?.sequence ?? 0;
    if (event.sequence <= last) continue;
    if (event.sequence !== last + 1) return false;
    loaded.push(event);
  }
  return true;
}
