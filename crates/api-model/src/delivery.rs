//! Delivery-neutral readings of a unified surface that every export emitter
//! (and the GUI) must agree on: which endpoints are confirmed by observation,
//! which origin each endpoint is served from, which request headers are
//! transport mechanics rather than API contract, and which GraphQL operations
//! were captured with their documents. Keeping them here means the emitters
//! cannot drift from each other or from the product's own vocabulary.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{
    Endpoint, EndpointIdentity, GraphQlOperationType, SamplePayload, SourceType, UnifiedApiSurface,
    UnifiedEndpoint, parse_graphql_operations,
};

/// The evidence behind one endpoint, in the product's vocabulary.
///
/// - **confirmed**: the endpoint was observed in dynamic capture (live
///   traffic); it may also be backed by code (`in_code`).
/// - **inferred**: recovered from code only, never observed being hit.
///
/// This is the rule the GUI's `surface/tally.ts` applies (any fact of the
/// endpoint traces to dynamic capture). The engine's `CoveragePicture` uses
/// the same words for a finer fusion split (its "confirmed" means static and
/// dynamic agree); that split is reported separately and never relabeled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EndpointEvidence {
    /// Observed in live traffic.
    pub observed: bool,
    /// Also found in the app's code.
    pub in_code: bool,
}

impl EndpointEvidence {
    /// The endpoint's evidence from its recomputed fact records.
    #[must_use]
    pub fn of(endpoint: &UnifiedEndpoint) -> Self {
        let has = |source: SourceType| {
            endpoint
                .fact_confidence
                .iter()
                .any(|fact| fact.sources.contains(&source))
        };
        Self {
            observed: has(SourceType::DynamicCapture),
            in_code: has(SourceType::StaticAnalysis),
        }
    }

    /// `confirmed` or `inferred`.
    #[must_use]
    pub fn label(self) -> &'static str {
        if self.observed {
            "confirmed"
        } else {
            "inferred"
        }
    }

    /// One human-readable line, e.g. "confirmed (observed in live traffic)".
    #[must_use]
    pub fn describe(self) -> &'static str {
        match (self.observed, self.in_code) {
            (true, true) => "confirmed (observed in live traffic, also found in code)",
            (true, false) => "confirmed (observed in live traffic)",
            (false, _) => "inferred (recovered from code only; not observed being called)",
        }
    }
}

/// Counts of a surface's endpoints by [`EndpointEvidence`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceTally {
    /// All endpoints.
    pub endpoints: usize,
    /// Observed in live traffic.
    pub confirmed: usize,
    /// Observed in live traffic and also found in code.
    pub also_in_code: usize,
    /// Code only; not observed.
    pub inferred: usize,
}

impl EvidenceTally {
    /// "N confirmed (observed), M also in code, K inferred (code only)".
    #[must_use]
    pub fn describe(self) -> String {
        format!(
            "{} confirmed (observed in live traffic), {} of them also in code, {} inferred (code only)",
            self.confirmed, self.also_in_code, self.inferred
        )
    }
}

impl UnifiedApiSurface {
    /// The evidence behind the endpoint with `identity`.
    #[must_use]
    pub fn endpoint_evidence(&self, identity: &EndpointIdentity) -> EndpointEvidence {
        self.endpoints
            .iter()
            .find(|endpoint| &endpoint.endpoint.identity == identity)
            .map(EndpointEvidence::of)
            .unwrap_or_default()
    }

    /// Endpoint counts by the same rule the per-endpoint labels use.
    #[must_use]
    pub fn evidence_tally(&self) -> EvidenceTally {
        let mut tally = EvidenceTally {
            endpoints: self.endpoints.len(),
            ..EvidenceTally::default()
        };
        for endpoint in &self.endpoints {
            let evidence = EndpointEvidence::of(endpoint);
            if evidence.observed {
                tally.confirmed += 1;
                if evidence.in_code {
                    tally.also_in_code += 1;
                }
            }
        }
        tally.inferred = tally.endpoints - tally.confirmed;
        tally
    }

    /// The origin most endpoints are served from: every emitter's default
    /// base URL. Ties prefer the lexically first origin, so output is stable.
    #[must_use]
    pub fn primary_base_url(&self) -> Option<String> {
        let mut counts = BTreeMap::<String, usize>::new();
        for endpoint in &self.surface.endpoints {
            if let Some(base) = endpoint_base_url(endpoint) {
                *counts.entry(base).or_default() += 1;
            }
        }
        let top = counts.values().copied().max()?;
        counts
            .into_iter()
            .find(|(_, count)| *count == top)
            .map(|(base, _)| base)
    }
}

/// The origin (`scheme://host[:port]`, no trailing slash) an endpoint is
/// served from: its selected base URL, when that is absolute.
#[must_use]
pub fn endpoint_base_url(endpoint: &Endpoint) -> Option<String> {
    endpoint
        .base_url
        .as_ref()
        .and_then(|fact| fact.selected_candidate())
        .map(|candidate| candidate.value.trim().trim_end_matches('/').to_owned())
        .filter(|value| value.contains("://"))
}

/// Request headers that are transport or browser mechanics by exact name.
const TRANSPORT_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "origin",
    "referer",
    "cache-control",
    "pragma",
    "dnt",
    "priority",
    "upgrade-insecure-requests",
    "if-none-match",
    "if-modified-since",
    "via",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

/// Whether a request header is transport, proxy, or browser mechanics rather
/// than part of the API contract: hop-by-hop and framing headers, proxy
/// headers (including this product's own markers), browser-generated fetch
/// metadata and client hints, and headers the browser sets for every request.
/// Such headers are real observations and stay in the model, but an export
/// must not present them as parameters a caller has to supply.
#[must_use]
pub fn is_transport_header(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    TRANSPORT_HEADERS.contains(&name.as_str())
        || name.starts_with("proxy-")
        || name.starts_with("sec-")
        || name.starts_with("x-apiaxess-")
}

/// One GraphQL operation captured on an endpoint, with the document and
/// variables exactly as a client sent them.
#[derive(Clone, Debug, PartialEq)]
pub struct CapturedGraphQlOperation {
    /// Query, mutation, or subscription.
    pub operation_type: GraphQlOperationType,
    /// The operation's name.
    pub name: String,
    /// The GraphQL document as sent.
    pub query: String,
    /// The variables as sent (`null` when none were sent).
    pub variables: Value,
}

/// The named GraphQL operations captured in an endpoint's request-body
/// samples (single or batched JSON bodies with a `query` document), one per
/// operation name, in first-seen order. Anonymous operations have no name to
/// key on and are skipped, as the dynamic lift skips them.
#[must_use]
pub fn captured_graphql_operations(endpoint: &Endpoint) -> Vec<CapturedGraphQlOperation> {
    let Some(body) = &endpoint.request_body else {
        return Vec::new();
    };
    let mut operations: Vec<CapturedGraphQlOperation> = Vec::new();
    for observation in &body.observations {
        let SamplePayload::Inline { value } = &observation.payload else {
            continue;
        };
        let items = match value {
            Value::Array(items) => items.iter().collect::<Vec<_>>(),
            other => vec![other],
        };
        for item in items {
            let Some(query) = item.get("query").and_then(Value::as_str) else {
                continue;
            };
            let selected = item.get("operationName").and_then(Value::as_str);
            for header in parse_graphql_operations(query) {
                let Some(name) = header.name else {
                    continue;
                };
                if selected.is_some_and(|selected| selected != name)
                    || operations.iter().any(|known| known.name == name)
                {
                    continue;
                }
                operations.push(CapturedGraphQlOperation {
                    operation_type: header.operation_type,
                    name,
                    query: query.to_owned(),
                    variables: item.get("variables").cloned().unwrap_or(Value::Null),
                });
            }
        }
    }
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_headers_are_recognized_and_app_headers_are_not() {
        for name in [
            "Host",
            "content-length",
            "Proxy-Connection",
            "sec-ch-ua",
            "Sec-Fetch-Mode",
            "accept-encoding",
            "X-APIaxess-Origin",
            "user-agent",
        ] {
            assert!(is_transport_header(name), "{name}");
        }
        for name in [
            "X-Client-Version",
            "Authorization",
            "X-Request-Id",
            "Content-Type",
            "Accept",
            "Cookie",
            "X-Api-Key",
        ] {
            assert!(!is_transport_header(name), "{name}");
        }
    }
}
