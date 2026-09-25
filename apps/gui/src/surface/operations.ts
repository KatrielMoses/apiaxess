/* Protocol operations of the fused surface: GraphQL operations and gRPC
 * methods, read from the engine's ApiSurface (surface.protocol_operations).
 * Whether each was observed or found in code comes from the provenance of
 * its presence evidence. Pure helpers (no DOM), checked by
 * scripts/check-surface-operations.mjs. */

export type OperationKind = "graphql" | "grpc";

/** One protocol operation, ready to list. */
export interface SurfaceOperation {
  readonly kind: OperationKind;
  /** `query GetProfile`, `mutation AddToCart`, or `shop.v1.CartService / Checkout`. */
  readonly label: string;
  /** The GraphQL endpoint URL, when known. */
  readonly endpointUrl: string | null;
  /** Observed in captured traffic. */
  readonly observed: boolean;
  /** Found in the app's code. */
  readonly inCode: boolean;
}

type Json = Record<string, unknown>;

const asRecord = (value: unknown): Json => (value !== null && typeof value === "object" ? value as Json : {});
const asArray = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** The protocol operations of a raw fused surface (the engine's JSON). */
export function readProtocolOperations(rawSurface: unknown): SurfaceOperation[] {
  const surface = asRecord(asRecord(rawSurface).surface);
  const sources = new Map<string, string>();
  for (const entity of asArray(asRecord(surface.provenance).entities)) {
    const record = asRecord(entity);
    if (typeof record.id === "string" && typeof record.source_type === "string") sources.set(record.id, record.source_type);
  }
  const operations: SurfaceOperation[] = [];
  for (const raw of asArray(surface.protocol_operations)) {
    const operation = asRecord(raw);
    const identity = asRecord(operation.identity);
    const evidence = asArray(asRecord(operation.presence).candidates)
      .flatMap((candidate) => asArray(asRecord(candidate).evidence))
      .map((id) => sources.get(String(id)) ?? "");
    const observed = evidence.includes("dynamic_capture");
    const inCode = evidence.some((source) => source !== "" && source !== "dynamic_capture");
    if (identity.kind === "graphql" || identity.kind === "graph_ql") {
      operations.push({
        kind: "graphql",
        label: `${String(identity.operation_type ?? "query")} ${String(identity.operation_name ?? "")}`,
        endpointUrl: typeof identity.endpoint_url === "string" ? identity.endpoint_url : null,
        observed,
        inCode,
      });
    } else if (identity.kind === "grpc") {
      operations.push({ kind: "grpc", label: `${String(identity.service ?? "")} / ${String(identity.method ?? "")}`, endpointUrl: null, observed, inCode });
    }
  }
  return operations;
}

/** The GraphQL operations carried by the endpoint on `host` at `path`. */
export function graphqlOperationsOn(operations: readonly SurfaceOperation[], host: string | null | undefined, path: string): SurfaceOperation[] {
  return operations.filter((operation) => {
    if (operation.kind !== "graphql" || operation.endpointUrl === null) return false;
    try {
      const url = new URL(operation.endpointUrl);
      const samePath = url.pathname.replace(/\/+$/, "") === path.replace(/\/+$/, "");
      return samePath && (host === null || host === undefined || url.host.toLowerCase() === host.toLowerCase());
    } catch {
      return false;
    }
  });
}
