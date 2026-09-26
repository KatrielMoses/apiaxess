//! Phase 3.5: turn durable Phase-2 flows into dynamic model facts.
//!
//! The extractor is intentionally non-fusing. It appends dynamic candidates
//! and observed samples to the canonical facts, preserving static candidates
//! and leaving selection to the model's settled per-field policies (with the
//! model-required exception that observed authentication is authoritative).

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
};

use apiaxess_api_model::{
    Activity, Agent, AgentId, AgentKind, ApiDocument, ApiKeyLocation, AuthenticationScheme,
    DynamicCaptureSummary, Endpoint, EndpointIdentity, Entity, EntityId, EntityKind, Fact,
    FactCandidate, FieldClass, HeaderParameter, HttpMethod, PaginationSignal, ParameterName,
    PathParameter, PathTemplate, PathTemplateAssertion, PathTemplateOrigin, PresenceAssertion,
    ProtocolOperation, ProtocolOperationIdentity, ProvenanceRegistry, QueryParameter,
    RequirednessAssertion, Resolution, ResolutionPolicy, ResponseBody, ResponseSelector, RunId,
    SamplePayload, SchemaObservation, SchemaProperty, SchemaShape, SchemaSlot, SourceType,
    normalize_host, parse_graphql_operations, parse_grpc_method_path,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_session::Session;
use apiaxess_workbench_store::{FlowCapture, FlowOrigin, TrafficStore};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// Configuration for one dynamic-capture extraction run.
#[derive(Clone, Debug)]
pub struct DynamicCaptureConfig {
    /// Stable capture run identifier retained in provenance and coverage.
    pub run_id: String,
    /// Minimum samples required before a dynamic requiredness assessment can
    /// become conclusive. The observed tally is always retained.
    pub minimum_dynamic_samples: NonZeroU64,
    /// Optional engine version for the provenance agent.
    pub engine_version: Option<String>,
}

impl DynamicCaptureConfig {
    /// Creates a conservative sample-gated configuration.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `run_id` violates the model identifier rules.
    ///
    /// # Panics
    ///
    /// The built-in sample threshold is a non-zero literal.
    pub fn new(run_id: impl Into<String>) -> Result<Self, Diagnostic> {
        let run_id = run_id.into();
        RunId::new(run_id.clone()).map_err(|error| {
            diagnostic(
                catalogue::DYNAMIC_FACT_EXTRACTION_FAILED,
                "run",
                &error.to_string(),
            )
        })?;
        Ok(Self {
            run_id,
            minimum_dynamic_samples: NonZeroU64::new(2).expect("literal is non-zero"),
            engine_version: None,
        })
    }
}

/// Result of extracting one capture run before any later fusion pass.
#[derive(Clone, Debug)]
pub struct DynamicCaptureReport {
    /// Updated, validated API document containing retained dynamic candidates.
    pub document: ApiDocument,
    /// Honest coverage and handoff accounting written into the document.
    pub coverage: DynamicCaptureSummary,
    /// Warnings and recoverable failures emitted during extraction.
    pub diagnostics: Vec<Diagnostic>,
}

/// Retracts, before a new capture run, what earlier runs whose ID starts with
/// `run_prefix` alone asserted: every endpoint and protocol operation whose
/// presence rests only on those runs' evidence. A capture run re-reads every
/// stored flow, so what is still observed and in scope is asserted again by
/// the new run, while an assertion whose flows have since left the scope (or
/// were never meant to be in it) does not linger in the surface. Anything also
/// backed by other evidence (static analysis, another source) is kept.
/// Returns how many entries were retracted.
pub fn retract_previous_runs(document: &mut ApiDocument, run_prefix: &str) -> usize {
    let prior = document
        .surface
        .provenance
        .entities
        .iter()
        .filter(|entity| entity.run_id.as_str().starts_with(run_prefix))
        .map(|entity| entity.id.clone())
        .collect::<BTreeSet<_>>();
    if prior.is_empty() {
        return 0;
    }
    let only_prior = |fact: &Fact<PresenceAssertion>| {
        !fact.candidates.is_empty()
            && fact.candidates.iter().all(|candidate| {
                !candidate.evidence.is_empty()
                    && candidate
                        .evidence
                        .iter()
                        .all(|entity| prior.contains(entity))
            })
    };
    let before = document.surface.endpoints.len() + document.surface.protocol_operations.len();
    document
        .surface
        .endpoints
        .retain(|endpoint| !only_prior(&endpoint.presence));
    document
        .surface
        .protocol_operations
        .retain(|operation| !only_prior(&operation.presence));
    before - document.surface.endpoints.len() - document.surface.protocol_operations.len()
}

/// Reads the durable Phase-2 traffic store and commits dynamic facts to a
/// live session. A source read or canonical commit failure is returned; flow-
/// local problems remain in the report so evidence is not silently dropped.
///
/// # Errors
///
/// Returns diagnostics when the durable source cannot be read or the validated
/// document cannot be committed to the active session.
pub fn capture_into_session(
    session: &mut Session,
    store: &TrafficStore,
    config: &DynamicCaptureConfig,
    at: DateTime<Utc>,
) -> Result<DynamicCaptureReport, Vec<Diagnostic>> {
    let summaries = store.summaries().map_err(|error| {
        vec![diagnostic(
            catalogue::DYNAMIC_CAPTURE_SOURCE_UNAVAILABLE,
            "summaries",
            &error.to_string(),
        )]
    })?;
    let mut flows = Vec::with_capacity(summaries.len());
    for summary in summaries {
        // Only observed capture traffic feeds the fused API surface. Resend/Fuzz
        // requests are replayed through the same proxy and recorded as flows, but
        // they are tool-synthesized — folding them in would pollute the unified
        // surface with endpoints that were never actually observed.
        if summary.origin != FlowOrigin::Capture {
            continue;
        }
        match store.get(summary.id) {
            Ok(Some(flow)) => flows.push(flow),
            Ok(None) => {
                return Err(vec![diagnostic(
                    catalogue::DYNAMIC_CAPTURE_SOURCE_UNAVAILABLE,
                    "flow",
                    &format!("flow {} disappeared between summary and read", summary.id),
                )]);
            }
            Err(error) => {
                return Err(vec![diagnostic(
                    catalogue::DYNAMIC_CAPTURE_SOURCE_UNAVAILABLE,
                    "flow",
                    &error.to_string(),
                )]);
            }
        }
    }
    let report = capture_into_document(session.api_document(), &flows, config, at)?;
    session
        .commit_api_document(report.document.clone(), at)
        .map_err(|error| {
            vec![diagnostic(
                catalogue::DYNAMIC_MODEL_COMMIT_FAILED,
                "session",
                &error.to_string(),
            )]
        })?;
    Ok(report)
}

/// Extracts dynamic facts from already materialized Phase-2 flows.
///
/// # Errors
///
/// Returns diagnostics when the run identifier is invalid or the resulting
/// candidate/provenance graph fails canonical model validation.
///
/// # Panics
///
/// Generated identifiers and fixed non-zero sample counts are validated before
/// use; a panic indicates an internal identifier-construction bug.
#[allow(clippy::too_many_lines)]
pub fn capture_into_document(
    source: &ApiDocument,
    flows: &[FlowCapture],
    config: &DynamicCaptureConfig,
    at: DateTime<Utc>,
) -> Result<DynamicCaptureReport, Vec<Diagnostic>> {
    let mut document = source.clone();
    let run_id = RunId::new(config.run_id.clone()).map_err(|error| {
        vec![diagnostic(
            catalogue::DYNAMIC_FACT_EXTRACTION_FAILED,
            "run",
            &error.to_string(),
        )]
    })?;
    let agent_id = ensure_agent(&mut document.surface.provenance, config);
    let activity_id = unique_activity_id(&document.surface.provenance, &config.run_id);
    let mut ids = IdFactory::new(&config.run_id);
    let mut diagnostics = Vec::new();
    let mut accumulators: BTreeMap<EndpointIdentity, Accumulator> = BTreeMap::new();
    // GraphQL operations observed in request bodies, with their flows.
    let mut graphql_operations: BTreeMap<ProtocolOperationIdentity, Vec<EntityId>> =
        BTreeMap::new();
    // gRPC calls observed on the wire, with their flows.
    let mut grpc_operations: BTreeMap<ProtocolOperationIdentity, Vec<EntityId>> = BTreeMap::new();
    let mut flow_entities = Vec::new();
    let mut timestamps = Vec::new();
    let mut structured_flow_count = 0_usize;

    for flow in flows
        .iter()
        .filter(|flow| matches!(flow.scope, apiaxess_session::ScopeDisposition::InScope))
    {
        let Some(method_text) = flow.method.as_deref() else {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_INVALID_FLOW,
                flow,
                "missing HTTP method",
            ));
            continue;
        };
        // A MITM proxy records the CONNECT tunnel establishment for every HTTPS
        // origin. That is transport setup, not an application endpoint, and
        // CONNECT is not a representable OpenAPI operation — synthesizing an
        // endpoint from it produces a false-positive `CONNECT /` and later makes
        // the OpenAPI export fail on an unrepresentable method. Skip it.
        if method_text.eq_ignore_ascii_case("CONNECT") {
            continue;
        }
        // A WebSocket handshake is not a REST operation: its traffic is the
        // WebSocket view's, kept out of the fused REST surface.
        if flow.request_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
        }) {
            continue;
        }
        let Ok(method) = HttpMethod::new(method_text) else {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_INVALID_FLOW,
                flow,
                "invalid HTTP method",
            ));
            continue;
        };
        let Some(raw_path) = flow.path.as_deref() else {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_INVALID_FLOW,
                flow,
                "missing request path",
            ));
            continue;
        };
        let path = path_only(raw_path);
        if !path.starts_with('/') {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_INVALID_FLOW,
                flow,
                "request path is not absolute",
            ));
            continue;
        }
        let entity_id = ids.entity("flow", flow.id);
        flow_entities.push((entity_id.clone(), flow.captured_at));
        timestamps.push(flow.captured_at);
        document.surface.provenance.entities.push(Entity {
            id: entity_id.clone(),
            kind: EntityKind::FactEvidence,
            source_type: SourceType::DynamicCapture,
            generated_by: activity_id.clone(),
            attributed_to: agent_id.clone(),
            run_id: run_id.clone(),
            derived_from: Vec::new(),
            recorded_at: flow.captured_at,
            sample_count: NonZeroU64::new(1).expect("literal is non-zero"),
        });
        // A gRPC call is a protobuf RPC, not a REST resource: it surfaces as
        // the service/method operation it is (the identity the static pass
        // reads from generated stubs), not as an opaque POST. Its
        // length-prefixed protobuf body is not decoded: without the .proto
        // schema it yields only field numbers and wire types.
        if let Some(operation) = observed_grpc_operation(flow, &path) {
            grpc_operations
                .entry(operation)
                .or_default()
                .push(entity_id.clone());
            structured_flow_count += 1;
            continue;
        }

        // Host is part of endpoint identity. A static endpoint bound to this
        // flow's host matches first; a host-unknown one is the fallback; one
        // bound to a different host never matches (two hosts serving the
        // same route are different endpoints).
        let flow_host = flow_host(flow);
        let route_matches = |endpoint: &&Endpoint| {
            endpoint.identity.method == method
                && template_matches(endpoint.identity.path_template.as_str(), &path)
        };
        let same_host: Vec<_> = document
            .surface
            .endpoints
            .iter()
            .filter(route_matches)
            .filter(|endpoint| flow_host.is_some() && endpoint.identity.host == flow_host)
            .map(|endpoint| endpoint.identity.clone())
            .collect();
        let static_matches = if same_host.is_empty() {
            document
                .surface
                .endpoints
                .iter()
                .filter(route_matches)
                .filter(|endpoint| endpoint.identity.host.is_none())
                .map(|endpoint| endpoint.identity.clone())
                .collect()
        } else {
            same_host
        };
        let static_target = if static_matches.len() > 1 {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_TEMPLATE_MATCH_AMBIGUOUS,
                flow,
                "multiple static templates matched",
            ));
            continue;
        } else {
            static_matches.into_iter().next()
        };
        let template = if let Some(identity) = &static_target {
            identity.path_template.clone()
        } else {
            match infer_template(&path) {
                Ok(template) => template,
                Err(error) => {
                    diagnostics.push(flow_diagnostic(
                        catalogue::DYNAMIC_UNRESOLVED_ROUTE,
                        flow,
                        &error,
                    ));
                    continue;
                }
            }
        };
        let identity = EndpointIdentity {
            method,
            path_template: template,
            host: flow_host,
        };
        let entry = accumulators
            .entry(identity.clone())
            .or_insert_with(|| Accumulator::new(identity));
        entry.static_target = entry.static_target.take().or(static_target);
        entry.flow_entities.push(entity_id.clone());
        if let Some(origin) = flow_origin(flow) {
            if !entry.hosts.contains(&origin) {
                entry.hosts.push(origin);
            }
        }
        collect_parameters(entry, &path, raw_path, &flow.request_headers);
        entry.auth = entry.auth.clone().or_else(|| observed_auth(flow));
        if let Some(body) = &flow.request_body {
            if let Some(sample) = parse_payload(
                body,
                &flow.request_headers,
                &entity_id,
                flow,
                false,
                &mut diagnostics,
                &mut ids,
                &activity_id,
                &agent_id,
                &run_id,
                &mut document.surface.provenance,
            ) {
                entry.request_samples.push(sample);
            }
        }
        if let Some(status) = flow.status {
            let media = media_type(&flow.response_headers);
            let seen = entry.response_media.entry(status).or_insert(None);
            if seen.is_none() {
                *seen = media;
            }
        }
        if let (Some(status), Some(body)) = (flow.status, flow.response_body.as_ref()) {
            if let Some(sample) = parse_payload(
                body,
                &flow.response_headers,
                &entity_id,
                flow,
                true,
                &mut diagnostics,
                &mut ids,
                &activity_id,
                &agent_id,
                &run_id,
                &mut document.surface.provenance,
            ) {
                entry
                    .response_samples
                    .entry(status)
                    .or_default()
                    .push(sample);
            }
        }
        for operation in observed_graphql_operations(flow, raw_path) {
            graphql_operations
                .entry(operation)
                .or_default()
                .push(entity_id.clone());
        }
        structured_flow_count += 1;
    }

    let now = Utc::now();
    let started_at = timestamps.iter().copied().min().unwrap_or(at).min(now);
    let ended_at = timestamps
        .iter()
        .copied()
        .max()
        .unwrap_or(at)
        .max(started_at)
        .max(at)
        .max(now)
        .checked_add_signed(Duration::minutes(1))
        .unwrap_or(now);
    document.surface.provenance.activities.push(Activity {
        id: activity_id.clone(),
        run_id,
        agent: agent_id,
        source_type: SourceType::DynamicCapture,
        started_at,
        ended_at: Some(ended_at),
    });

    let static_identities: BTreeSet<_> = document
        .surface
        .endpoints
        .iter()
        .map(|e| e.identity.clone())
        .collect();
    // A host-unknown static endpoint takes the observed host only when a
    // single host served it; with several, which one it meant is unknown, so
    // it stays static-only and each observed host is its own endpoint.
    let mut hosts_per_target = BTreeMap::<EndpointIdentity, usize>::new();
    for accumulator in accumulators.values() {
        if let Some(target) = &accumulator.static_target {
            *hosts_per_target.entry(target.clone()).or_default() += 1;
        }
    }
    let mut confirmed_static = BTreeSet::new();
    for accumulator in accumulators.values_mut() {
        let Some(target) = accumulator.static_target.clone() else {
            continue;
        };
        if target == accumulator.identity {
            confirmed_static.insert(target);
        } else if target.host.is_none() && hosts_per_target.get(&target) == Some(&1) {
            if let Some(endpoint) = document
                .surface
                .endpoints
                .iter_mut()
                .find(|endpoint| endpoint.identity == target)
            {
                endpoint
                    .identity
                    .host
                    .clone_from(&accumulator.identity.host);
            }
            confirmed_static.insert(target);
        } else {
            accumulator.static_target = None;
        }
    }
    for (identity, flows) in &graphql_operations {
        apply_graphql_operation(&mut document, identity, flows, &activity_id, &mut ids);
    }
    for (identity, flows) in &grpc_operations {
        apply_grpc_operation(&mut document, identity, flows, &activity_id, &mut ids);
    }
    let mut observed = Vec::new();
    for accumulator in accumulators.values() {
        observed.push(accumulator.identity.clone());
        if let Err(error) =
            apply_accumulator(&mut document, accumulator, config, &activity_id, &mut ids)
        {
            diagnostics.push(diagnostic(
                catalogue::DYNAMIC_FACT_EXTRACTION_FAILED,
                "endpoint",
                &error,
            ));
        }
    }
    observed.sort();
    let static_only_endpoints = static_identities
        .difference(&confirmed_static)
        .cloned()
        .collect::<Vec<_>>();
    let (resolved_handoffs, open_handoffs) = handoff_feedback(&document, &observed);
    if static_only_endpoints.len() < static_identities.len() || observed.is_empty() {
        diagnostics.push(diagnostic(
            if observed.is_empty() {
                catalogue::DYNAMIC_NO_OBSERVATIONS
            } else {
                catalogue::DYNAMIC_COVERAGE_PARTIAL
            },
            "coverage",
            &format!(
                "observed {} endpoint identities; {} static identities remain static-only",
                observed.len(),
                static_only_endpoints.len()
            ),
        ));
    }
    let summary = DynamicCaptureSummary {
        schema_version: 1,
        run_id: config.run_id.clone(),
        flow_count: flows.len(),
        structured_flow_count,
        inferred_endpoint_count: accumulators
            .values()
            .filter(|accumulator| accumulator.static_target.is_none())
            .count(),
        observed_endpoints: observed,
        static_only_endpoints,
        resolved_handoffs,
        open_handoffs,
        minimum_dynamic_samples: config.minimum_dynamic_samples.get(),
        diagnostics: diagnostics.clone(),
    };
    document.dynamic_capture = Some(summary.clone());
    if let Err(error) = document.validate() {
        return Err(vec![diagnostic(
            catalogue::DYNAMIC_MODEL_COMMIT_FAILED,
            "validate",
            &error.to_string(),
        )]);
    }
    Ok(DynamicCaptureReport {
        document,
        coverage: summary,
        diagnostics,
    })
}

#[derive(Clone, Debug)]
struct Sample {
    entity: EntityId,
    value: Value,
}

#[derive(Clone, Debug)]
struct Accumulator {
    identity: EndpointIdentity,
    /// The static endpoint this route was matched against, when any.
    static_target: Option<EndpointIdentity>,
    flow_entities: Vec<EntityId>,
    hosts: Vec<String>,
    query: BTreeMap<String, Vec<Value>>,
    path: BTreeMap<String, Vec<Value>>,
    headers: BTreeMap<String, Vec<Value>>,
    request_samples: Vec<Sample>,
    response_samples: BTreeMap<u16, Vec<Sample>>,
    /// Every observed response status, with the media type seen for it (the
    /// first one observed). A status whose body is not structured data has no
    /// JSON sample but is still a real response.
    response_media: BTreeMap<u16, Option<String>>,
    auth: Option<AuthenticationScheme>,
    pagination: BTreeSet<PaginationSignal>,
}

impl Accumulator {
    fn new(identity: EndpointIdentity) -> Self {
        Self {
            identity,
            static_target: None,
            flow_entities: Vec::new(),
            hosts: Vec::new(),
            query: BTreeMap::new(),
            path: BTreeMap::new(),
            headers: BTreeMap::new(),
            request_samples: Vec::new(),
            response_samples: BTreeMap::new(),
            response_media: BTreeMap::new(),
            auth: None,
            pagination: BTreeSet::new(),
        }
    }
}

struct IdFactory {
    prefix: String,
    counter: u64,
}

impl IdFactory {
    fn new(run_id: &str) -> Self {
        Self {
            prefix: run_id.to_owned(),
            counter: 0,
        }
    }
    fn next(&mut self, kind: &str) -> String {
        self.counter = self.counter.saturating_add(1);
        format!("dynamic:{kind}:{}:{}", self.prefix, self.counter)
    }
    fn entity(&mut self, kind: &str, flow_id: u64) -> EntityId {
        EntityId::new(format!("dynamic:{kind}:{}:{flow_id}", self.prefix)).unwrap_or_else(|_| {
            EntityId::new(self.next("entity")).expect("generated entity ID is valid")
        })
    }
    fn candidate(&mut self) -> apiaxess_api_model::CandidateId {
        apiaxess_api_model::CandidateId::new(self.next("candidate"))
            .expect("generated candidate ID is valid")
    }
}

fn ensure_agent(provenance: &mut ProvenanceRegistry, config: &DynamicCaptureConfig) -> AgentId {
    let id = AgentId::new("dynamic-capture.engine").expect("static agent ID is valid");
    if !provenance.agents.iter().any(|agent| agent.id == id) {
        provenance.agents.push(Agent {
            id: id.clone(),
            kind: AgentKind::Engine,
            name: "APIaxess dynamic capture".to_owned(),
            version: config.engine_version.clone(),
        });
    }
    id
}

fn unique_activity_id(
    provenance: &ProvenanceRegistry,
    run_id: &str,
) -> apiaxess_api_model::ActivityId {
    let base = format!("dynamic-capture:{run_id}");
    let mut candidate = base.clone();
    let mut suffix = 0_u32;
    while provenance
        .activities
        .iter()
        .any(|activity| activity.id.as_str() == candidate)
    {
        suffix = suffix.saturating_add(1);
        candidate = format!("{base}:{suffix}");
    }
    apiaxess_api_model::ActivityId::new(candidate).expect("generated activity ID is valid")
}

#[allow(clippy::too_many_arguments)]
fn parse_payload(
    body: &[u8],
    headers: &[(String, String)],
    flow_entity: &EntityId,
    flow: &FlowCapture,
    response: bool,
    diagnostics: &mut Vec<Diagnostic>,
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
    agent: &AgentId,
    run: &RunId,
    provenance: &mut ProvenanceRegistry,
) -> Option<Sample> {
    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map_or("", |(_, value)| value.as_str());
    let looks_json = content_type.to_ascii_lowercase().contains("json")
        || body
            .iter()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| matches!(byte, b'{' | b'['));
    if !looks_json {
        return None;
    }
    let value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_PAYLOAD_PARSE_FAILED,
                flow,
                &format!(
                    "{} payload: {error}",
                    if response { "response" } else { "request" }
                ),
            ));
            return None;
        }
    };
    let entity = EntityId::new(ids.next(if response {
        "response-sample"
    } else {
        "request-sample"
    }))
    .expect("generated sample ID is valid");
    provenance.entities.push(Entity {
        id: entity.clone(),
        kind: EntityKind::ObservedSample,
        source_type: SourceType::DynamicCapture,
        generated_by: activity.clone(),
        attributed_to: agent.clone(),
        run_id: run.clone(),
        derived_from: vec![flow_entity.clone()],
        recorded_at: flow.captured_at,
        sample_count: NonZeroU64::new(1).expect("literal is non-zero"),
    });
    Some(Sample { entity, value })
}

fn collect_parameters(
    entry: &mut Accumulator,
    path: &str,
    raw_path: &str,
    headers: &[(String, String)],
) {
    let template_segments: Vec<_> = entry
        .identity
        .path_template
        .as_str()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let path_segments: Vec<_> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    for (template, actual) in template_segments.iter().zip(path_segments.iter()) {
        if let Some(name) = placeholder_name(template) {
            entry
                .path
                .entry(name)
                .or_default()
                .push(string_value(actual));
        }
    }
    if let Some((_, query)) = raw_path.split_once('?') {
        for (name, value) in query.split('&').filter_map(|part| part.split_once('=')) {
            if !name.is_empty() {
                if let Some(signal) = pagination_signal(name) {
                    entry.pagination.insert(signal);
                }
                entry
                    .query
                    .entry(name.to_owned())
                    .or_default()
                    .push(string_value(value));
            }
        }
    }
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower != "authorization" && lower != "cookie" && lower != "set-cookie" {
            entry
                .headers
                .entry(name.clone())
                .or_default()
                .push(string_value(value));
        }
        if lower == "link" {
            entry.pagination.insert(PaginationSignal::LinkHeader);
        }
    }
}

fn observed_auth(flow: &FlowCapture) -> Option<AuthenticationScheme> {
    if let Some((_, value)) = flow
        .request_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("bearer ") {
            return Some(AuthenticationScheme::Bearer {
                token_format: value.split('.').count().eq(&3).then(|| "jwt".to_owned()),
            });
        }
        if lower.starts_with("basic ") {
            return Some(AuthenticationScheme::Basic);
        }
        return Some(AuthenticationScheme::Custom {
            scheme: value
                .split_whitespace()
                .next()
                .unwrap_or("authorization")
                .to_owned(),
        });
    }
    for (name, _) in &flow.request_headers {
        if name.eq_ignore_ascii_case("x-api-key") || name.eq_ignore_ascii_case("api-key") {
            return ParameterName::new(name.clone()).ok().map(|name| {
                AuthenticationScheme::ApiKey {
                    location: ApiKeyLocation::Header,
                    name,
                }
            });
        }
    }
    None
}

fn apply_accumulator(
    document: &mut ApiDocument,
    entry: &Accumulator,
    config: &DynamicCaptureConfig,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<(), String> {
    let static_index = document
        .surface
        .endpoints
        .iter()
        .position(|endpoint| endpoint.identity == entry.identity);
    if let Some(index) = static_index {
        let endpoint = &mut document.surface.endpoints[index];
        // Carry the observed origin onto the endpoint; fusion selects the base
        // whose host agrees with the endpoint's identity host.
        for origin in &entry.hosts {
            match &mut endpoint.base_url {
                Some(base_url) => append_candidate(
                    base_url,
                    origin.clone(),
                    &entry.flow_entities,
                    ids.candidate(),
                    false,
                    activity,
                ),
                None => {
                    endpoint.base_url = Some(scalar_fact(
                        origin.clone(),
                        &entry.flow_entities,
                        ids.candidate(),
                        activity,
                    ));
                }
            }
        }
        append_candidate(
            &mut endpoint.presence,
            PresenceAssertion::Present,
            &entry.flow_entities,
            ids.candidate(),
            false,
            activity,
        );
        let dynamic_template = PathTemplateAssertion {
            template: entry.identity.path_template.clone(),
            origin: PathTemplateOrigin::Inferred,
        };
        append_candidate(
            &mut endpoint.path_template,
            dynamic_template,
            &entry.flow_entities,
            ids.candidate(),
            false,
            activity,
        );
        apply_existing_parameters(endpoint, entry, config, activity, ids)?;
    } else {
        document
            .surface
            .endpoints
            .push(new_endpoint(entry, config, activity, ids)?);
    }
    Ok(())
}

fn new_endpoint(
    entry: &Accumulator,
    config: &DynamicCaptureConfig,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<Endpoint, String> {
    let identity = entry.identity.clone();
    let mut endpoint = Endpoint {
        identity: identity.clone(),
        base_url: entry.hosts.first().map(|host| {
            scalar_fact(
                host.clone(),
                &entry.flow_entities,
                ids.candidate(),
                activity,
            )
        }),
        presence: dynamic_fact(
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            &entry.flow_entities,
            ids.candidate(),
            activity,
        ),
        path_template: dynamic_fact(
            FieldClass::PathTemplate,
            ResolutionPolicy::DeclaredBeforeInferred,
            PathTemplateAssertion {
                template: identity.path_template.clone(),
                origin: PathTemplateOrigin::Inferred,
            },
            &entry.flow_entities,
            ids.candidate(),
            activity,
        ),
        query_parameters: Vec::new(),
        path_parameters: Vec::new(),
        headers: Vec::new(),
        authentication: None,
        request_body: None,
        responses: Vec::new(),
        pagination_signals: Vec::new(),
    };
    for (name, values) in &entry.query {
        endpoint
            .query_parameters
            .push(new_query(name, values, entry, config, activity, ids)?);
    }
    for (name, values) in &entry.path {
        endpoint
            .path_parameters
            .push(new_path(name, values, entry, activity, ids)?);
    }
    for (name, values) in &entry.headers {
        endpoint
            .headers
            .push(new_header(name, values, entry, activity, ids)?);
    }
    endpoint.authentication = entry.auth.clone().map(|auth| {
        dynamic_fact(
            FieldClass::Authentication,
            ResolutionPolicy::DynamicAuthoritative,
            auth,
            &entry.flow_entities,
            ids.candidate(),
            activity,
        )
    });
    if !entry.request_samples.is_empty() {
        endpoint.request_body = Some(schema_slot(&entry.request_samples, ids, activity));
    }
    for (status, media) in &entry.response_media {
        let body = match entry.response_samples.get(status) {
            Some(samples) => schema_slot(samples, ids, activity),
            None => opaque_slot(media.as_deref(), &entry.flow_entities, ids, activity),
        };
        endpoint.responses.push(ResponseBody {
            selector: ResponseSelector::Exact(*status),
            presence: dynamic_fact(
                FieldClass::Presence,
                ResolutionPolicy::StaticCompleteDynamicConfirm,
                PresenceAssertion::Present,
                &entry.flow_entities,
                ids.candidate(),
                activity,
            ),
            body,
            media_type: media.clone(),
        });
    }
    endpoint.pagination_signals = entry
        .pagination
        .iter()
        .map(|signal| {
            dynamic_fact(
                FieldClass::Scalar,
                ResolutionPolicy::Explicit,
                *signal,
                &entry.flow_entities,
                ids.candidate(),
                activity,
            )
        })
        .collect();
    Ok(endpoint)
}

#[allow(clippy::too_many_lines)]
fn apply_existing_parameters(
    endpoint: &mut Endpoint,
    entry: &Accumulator,
    config: &DynamicCaptureConfig,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<(), String> {
    for (name, values) in &entry.query {
        if let Some(parameter) = endpoint
            .query_parameters
            .iter_mut()
            .find(|parameter| parameter.name.as_str() == name)
        {
            append_parameter_schema(
                &mut parameter.presence,
                &mut parameter.schema,
                values,
                &entry.flow_entities,
                activity,
                ids,
            );
            append_requiredness(
                &mut parameter.requiredness,
                values.len() as u64,
                entry.flow_entities.len() as u64,
                &entry.flow_entities,
                activity,
                ids,
            );
        } else {
            endpoint
                .query_parameters
                .push(new_query(name, values, entry, config, activity, ids)?);
        }
    }
    for (name, values) in &entry.path {
        if let Some(parameter) = endpoint
            .path_parameters
            .iter_mut()
            .find(|parameter| parameter.name.as_str() == name)
        {
            append_parameter_schema(
                &mut parameter.presence,
                &mut parameter.schema,
                values,
                &entry.flow_entities,
                activity,
                ids,
            );
        } else {
            endpoint
                .path_parameters
                .push(new_path(name, values, entry, activity, ids)?);
        }
    }
    for (name, values) in &entry.headers {
        if let Some(header) = endpoint
            .headers
            .iter_mut()
            .find(|header| header.name.as_str().eq_ignore_ascii_case(name))
        {
            append_parameter_schema(
                &mut header.presence,
                &mut header.schema,
                values,
                &entry.flow_entities,
                activity,
                ids,
            );
        } else {
            endpoint
                .headers
                .push(new_header(name, values, entry, activity, ids)?);
        }
    }
    if let Some(auth) = &entry.auth {
        if let Some(fact) = endpoint.authentication.as_mut() {
            append_candidate(
                fact,
                auth.clone(),
                &entry.flow_entities,
                ids.candidate(),
                true,
                activity,
            );
        } else {
            endpoint.authentication = Some(dynamic_fact(
                FieldClass::Authentication,
                ResolutionPolicy::DynamicAuthoritative,
                auth.clone(),
                &entry.flow_entities,
                ids.candidate(),
                activity,
            ));
        }
    }
    if let Some(samples) = (!entry.request_samples.is_empty()).then_some(&entry.request_samples) {
        if let Some(slot) = endpoint.request_body.as_mut() {
            append_schema(slot, samples, ids, activity);
        } else {
            endpoint.request_body = Some(schema_slot(samples, ids, activity));
        }
    }
    for (status, media) in &entry.response_media {
        let samples = entry.response_samples.get(status);
        if let Some(response) = endpoint
            .responses
            .iter_mut()
            .find(|response| response.selector == ResponseSelector::Exact(*status))
        {
            append_candidate(
                &mut response.presence,
                PresenceAssertion::Present,
                &entry.flow_entities,
                ids.candidate(),
                false,
                activity,
            );
            if let Some(samples) = samples {
                append_schema(&mut response.body, samples, ids, activity);
            }
            if response.media_type.is_none() {
                response.media_type.clone_from(media);
            }
        } else {
            endpoint.responses.push(ResponseBody {
                selector: ResponseSelector::Exact(*status),
                presence: dynamic_fact(
                    FieldClass::Presence,
                    ResolutionPolicy::StaticCompleteDynamicConfirm,
                    PresenceAssertion::Present,
                    &entry.flow_entities,
                    ids.candidate(),
                    activity,
                ),
                body: match samples {
                    Some(samples) => schema_slot(samples, ids, activity),
                    None => opaque_slot(media.as_deref(), &entry.flow_entities, ids, activity),
                },
                media_type: media.clone(),
            });
        }
    }
    for signal in &entry.pagination {
        if let Some(fact) = endpoint.pagination_signals.iter_mut().find(|fact| {
            fact.selected_candidate()
                .is_some_and(|candidate| candidate.value == *signal)
        }) {
            append_candidate(
                fact,
                *signal,
                &entry.flow_entities,
                ids.candidate(),
                false,
                activity,
            );
        } else {
            endpoint.pagination_signals.push(dynamic_fact(
                FieldClass::Scalar,
                ResolutionPolicy::Explicit,
                *signal,
                &entry.flow_entities,
                ids.candidate(),
                activity,
            ));
        }
    }
    Ok(())
}

fn new_query(
    name: &str,
    values: &[Value],
    entry: &Accumulator,
    config: &DynamicCaptureConfig,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<QueryParameter, String> {
    let name = ParameterName::new(name).map_err(|error| error.to_string())?;
    Ok(QueryParameter {
        name,
        presence: dynamic_fact(
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            &entry.flow_entities,
            ids.candidate(),
            activity,
        ),
        schema: schema_from_values(values, &entry.flow_entities, ids, activity),
        requiredness: dynamic_requiredness(
            values.len() as u64,
            entry.flow_entities.len() as u64,
            activity,
            &entry.flow_entities,
            ids,
            config.minimum_dynamic_samples,
        ),
    })
}

fn new_path(
    name: &str,
    values: &[Value],
    entry: &Accumulator,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<PathParameter, String> {
    let name = ParameterName::new(name).map_err(|error| error.to_string())?;
    Ok(PathParameter {
        name,
        presence: dynamic_fact(
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            &entry.flow_entities,
            ids.candidate(),
            activity,
        ),
        schema: schema_from_values(values, &entry.flow_entities, ids, activity),
    })
}
fn new_header(
    name: &str,
    values: &[Value],
    entry: &Accumulator,
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) -> Result<HeaderParameter, String> {
    let name = ParameterName::new(name).map_err(|error| error.to_string())?;
    Ok(HeaderParameter {
        name,
        presence: dynamic_fact(
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            &entry.flow_entities,
            ids.candidate(),
            activity,
        ),
        schema: schema_from_values(values, &entry.flow_entities, ids, activity),
    })
}

fn scalar_fact(
    value: String,
    evidence: &[EntityId],
    candidate: apiaxess_api_model::CandidateId,
    activity: &apiaxess_api_model::ActivityId,
) -> Fact<String> {
    dynamic_fact(
        FieldClass::Scalar,
        ResolutionPolicy::Explicit,
        value,
        evidence,
        candidate,
        activity,
    )
}

fn dynamic_fact<T>(
    field_class: FieldClass,
    policy: ResolutionPolicy,
    value: T,
    evidence: &[EntityId],
    candidate: apiaxess_api_model::CandidateId,
    activity: &apiaxess_api_model::ActivityId,
) -> Fact<T> {
    Fact {
        field_class,
        expected_recoverability_basis_points: None,
        candidates: vec![FactCandidate {
            id: candidate.clone(),
            value,
            evidence: evidence.to_vec(),
        }],
        resolution: Resolution {
            selected: candidate,
            policy,
            resolved_by: activity.clone(),
            resolved_at: Utc::now(),
        },
        merges: Vec::new(),
    }
}

fn append_candidate<T>(
    fact: &mut Fact<T>,
    value: T,
    evidence: &[EntityId],
    candidate: apiaxess_api_model::CandidateId,
    select: bool,
    activity: &apiaxess_api_model::ActivityId,
) {
    fact.candidates.push(FactCandidate {
        id: candidate.clone(),
        value,
        evidence: evidence.to_vec(),
    });
    if select {
        fact.resolution.selected = candidate;
        fact.resolution.resolved_by = activity.clone();
        fact.resolution.resolved_at = Utc::now();
    }
}

fn append_parameter_schema(
    presence: &mut Fact<PresenceAssertion>,
    schema: &mut SchemaSlot,
    values: &[Value],
    evidence: &[EntityId],
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) {
    append_candidate(
        presence,
        PresenceAssertion::Present,
        evidence,
        ids.candidate(),
        false,
        activity,
    );
    append_schema_shape(schema, values, evidence, ids, activity);
}
fn append_requiredness(
    fact: &mut Fact<RequirednessAssertion>,
    present: u64,
    total: u64,
    evidence: &[EntityId],
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) {
    if let Some(total) = NonZeroU64::new(total) {
        append_candidate(
            fact,
            RequirednessAssertion::Observed {
                present_samples: present.min(total.get()),
                total_samples: total,
            },
            evidence,
            ids.candidate(),
            false,
            activity,
        );
    }
}
fn dynamic_requiredness(
    present: u64,
    total: u64,
    activity: &apiaxess_api_model::ActivityId,
    evidence: &[EntityId],
    ids: &mut IdFactory,
    _minimum: NonZeroU64,
) -> Fact<RequirednessAssertion> {
    let total = NonZeroU64::new(total.max(1)).expect("max one is non-zero");
    dynamic_fact(
        FieldClass::Requiredness,
        ResolutionPolicy::SampleGated,
        RequirednessAssertion::Observed {
            present_samples: present.min(total.get()),
            total_samples: total,
        },
        evidence,
        ids.candidate(),
        activity,
    )
}

fn schema_slot(
    samples: &[Sample],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaSlot {
    let values = samples
        .iter()
        .map(|sample| sample.value.clone())
        .collect::<Vec<_>>();
    let mut slot = schema_from_values(
        &values,
        &samples
            .iter()
            .map(|sample| sample.entity.clone())
            .collect::<Vec<_>>(),
        ids,
        activity,
    );
    slot.observations = samples
        .iter()
        .map(|sample| SchemaObservation {
            entity: sample.entity.clone(),
            payload: SamplePayload::Inline {
                value: sample.value.clone(),
            },
        })
        .collect();
    slot
}
/// The media type of a message, lowercased and without parameters.
fn media_type(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .and_then(|(_, value)| value.split(';').next())
        .map(|media| media.trim().to_ascii_lowercase())
        .filter(|media| !media.is_empty())
}

/// The schema of a response body that is not structured data: an HTML
/// document, an event stream, or other text is a string; bytes are a binary
/// string. Nothing is sampled, so nothing is invented. With no media type
/// observed the shape stays unknown.
fn opaque_slot(
    media: Option<&str>,
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaSlot {
    let shape = match media {
        None => SchemaShape::Unknown,
        Some(media) if is_textual_media(media) => SchemaShape::String { format: None },
        Some(_) => SchemaShape::String {
            format: Some("binary".to_owned()),
        },
    };
    SchemaSlot {
        shape: dynamic_fact(
            FieldClass::TypeShape,
            ResolutionPolicy::UnionOrWiden,
            shape,
            evidence,
            ids.candidate(),
            activity,
        ),
        observations: Vec::new(),
    }
}

/// Whether a media type carries text rather than bytes.
fn is_textual_media(media: &str) -> bool {
    media.starts_with("text/")
        || media.contains("json")
        || media.contains("xml")
        || media.contains("javascript")
        || media.contains("graphql")
        || media == "application/x-www-form-urlencoded"
}

fn schema_from_values(
    values: &[Value],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaSlot {
    schema_from_tagged(&tag_samples(values), evidence, ids, activity)
}

fn schema_from_tagged(
    values: &[Tagged],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaSlot {
    SchemaSlot {
        shape: infer_shape_tagged(values, evidence, ids, activity),
        observations: Vec::new(),
    }
}
fn append_schema(
    slot: &mut SchemaSlot,
    samples: &[Sample],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) {
    let values = samples
        .iter()
        .map(|sample| sample.value.clone())
        .collect::<Vec<_>>();
    let evidence = samples
        .iter()
        .map(|sample| sample.entity.clone())
        .collect::<Vec<_>>();
    slot.shape.candidates.push(FactCandidate {
        id: ids.candidate(),
        value: infer_shape(&values, &evidence, ids, activity).selected_candidate_value(),
        evidence: evidence.clone(),
    });
    slot.observations
        .extend(samples.iter().map(|sample| SchemaObservation {
            entity: sample.entity.clone(),
            payload: SamplePayload::Inline {
                value: sample.value.clone(),
            },
        }));
}

fn append_schema_shape(
    slot: &mut SchemaSlot,
    values: &[Value],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) {
    slot.shape.candidates.push(FactCandidate {
        id: ids.candidate(),
        value: infer_shape(values, evidence, ids, activity).selected_candidate_value(),
        evidence: evidence.to_vec(),
    });
}

trait SelectedShape {
    fn selected_candidate_value(self) -> SchemaShape;
}
impl SelectedShape for Fact<SchemaShape> {
    fn selected_candidate_value(self) -> SchemaShape {
        self.candidates
            .into_iter()
            .find(|candidate| candidate.id == self.resolution.selected)
            .map_or(SchemaShape::Unknown, |candidate| candidate.value)
    }
}

fn infer_shape(
    values: &[Value],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> Fact<SchemaShape> {
    infer_shape_tagged(&tag_samples(values), evidence, ids, activity)
}

/// A JSON value tagged with the index of the observed sample (flow) it came
/// from. Array elements inherit their parent's sample, so shape inference can
/// tally requiredness per *sample* — the unit the dynamic provenance counts —
/// rather than per array element.
type Tagged = (usize, Value);

/// Tags top-level values: each one is its own sample.
fn tag_samples(values: &[Value]) -> Vec<Tagged> {
    values.iter().cloned().enumerate().collect()
}

fn infer_shape_tagged(
    values: &[Tagged],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> Fact<SchemaShape> {
    let shape = infer_shape_value(values, evidence, ids, activity);
    dynamic_fact(
        FieldClass::TypeShape,
        ResolutionPolicy::UnionOrWiden,
        shape,
        evidence,
        ids.candidate(),
        activity,
    )
}

/// Requiredness of object property `name` over `objects`, tallied per sample:
/// `total` is the number of distinct samples observed, `present` the number of
/// those in which *every* object carried the property. A property missing
/// from any element of a sample's array therefore stays optional, and the
/// tally never exceeds the samples backing it.
fn sample_requiredness(objects: &[Tagged], name: &str) -> (u64, u64) {
    let mut per_sample: BTreeMap<usize, bool> = BTreeMap::new();
    for (sample, value) in objects {
        let has = value.get(name).is_some();
        per_sample
            .entry(*sample)
            .and_modify(|all| *all &= has)
            .or_insert(has);
    }
    let present = per_sample.values().filter(|all| **all).count() as u64;
    (present, per_sample.len() as u64)
}

fn infer_shape_value(
    values: &[Tagged],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaShape {
    if values.is_empty() {
        return SchemaShape::Unknown;
    }
    if values.iter().all(|(_, value)| value.is_object()) {
        let mut names = BTreeSet::new();
        for (_, value) in values {
            if let Some(object) = value.as_object() {
                names.extend(object.keys().cloned());
            }
        }
        let properties = names
            .into_iter()
            .filter_map(|name| {
                let present = values
                    .iter()
                    .filter_map(|(sample, value)| value.get(&name).map(|v| (*sample, v.clone())))
                    .collect::<Vec<_>>();
                let (present_samples, total_samples) = sample_requiredness(values, &name);
                let name_id = ParameterName::new(name).ok()?;
                Some(SchemaProperty {
                    name: name_id,
                    schema: schema_from_tagged(&present, evidence, ids, activity),
                    requiredness: dynamic_fact(
                        FieldClass::Requiredness,
                        ResolutionPolicy::SampleGated,
                        RequirednessAssertion::Observed {
                            present_samples,
                            total_samples: NonZeroU64::new(total_samples).unwrap_or_else(|| {
                                NonZeroU64::new(1).expect("literal is non-zero")
                            }),
                        },
                        evidence,
                        ids.candidate(),
                        activity,
                    ),
                })
            })
            .collect();
        return SchemaShape::Object {
            properties,
            openness: apiaxess_api_model::ObjectOpenness::Unknown,
        };
    }
    if values.iter().all(|(_, value)| value.is_array()) {
        // Elements keep their parent's sample tag: three objects in one
        // request's array are one sample, not three.
        let items = values
            .iter()
            .flat_map(|(sample, value)| {
                value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(move |item| (*sample, item.clone()))
            })
            .collect::<Vec<_>>();
        return SchemaShape::Array {
            items: Box::new(schema_from_tagged(&items, evidence, ids, activity)),
        };
    }
    let mut variants = Vec::new();
    for tagged in values {
        let (_, value) = tagged;
        let shape = match value {
            Value::Null => SchemaShape::Null,
            Value::Bool(_) => SchemaShape::Boolean,
            Value::Number(number) if number.is_i64() || number.is_u64() => {
                SchemaShape::Integer { format: None }
            }
            Value::Number(_) => SchemaShape::Number { format: None },
            Value::String(_) => SchemaShape::String { format: None },
            Value::Array(_) | Value::Object(_) => {
                infer_shape_value(std::slice::from_ref(tagged), evidence, ids, activity)
            }
        };
        if !variants.contains(&shape) {
            variants.push(shape);
        }
    }
    if variants.len() == 1 {
        variants.remove(0)
    } else {
        SchemaShape::Union { variants }
    }
}

/// The path of a request target, without its query string or fragment.
/// The GraphQL operations a request carries, recognized by shape: a JSON
/// body (or batched array of bodies) with a `query` document and optional
/// `operationName`, an `application/graphql` body, or a GET `query=`
/// parameter. `operationName` selects the operation that runs; anonymous
/// operations have no name to key on and are not lifted.
fn observed_graphql_operations(
    flow: &FlowCapture,
    raw_path: &str,
) -> Vec<ProtocolOperationIdentity> {
    // Without a recorded URL the scheme is unknown: `host/path` then.
    let Some(origin) = flow_origin(flow) else {
        return Vec::new();
    };
    let endpoint_url = format!("{origin}{}", path_only(raw_path));
    let content_type = flow
        .request_headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .unwrap_or_default();
    let mut requests: Vec<(String, Option<String>)> = Vec::new();
    if let Some(body) = &flow.request_body {
        if content_type.starts_with("application/graphql") {
            requests.push((String::from_utf8_lossy(body).into_owned(), None));
        } else if let Ok(value) = serde_json::from_slice::<Value>(body) {
            let items = match value {
                Value::Array(items) => items,
                other => vec![other],
            };
            for item in items {
                if let Some(query) = item.get("query").and_then(Value::as_str) {
                    let name = item
                        .get("operationName")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    requests.push((query.to_owned(), name));
                }
            }
        }
    } else if let Some((_, query_string)) = raw_path.split_once('?') {
        let parameter = |key: &str| {
            query_string.split('&').find_map(|pair| {
                let (name, value) = pair.split_once('=')?;
                (name == key).then(|| percent_decode(value))
            })
        };
        if let Some(query) = parameter("query") {
            requests.push((query, parameter("operationName")));
        }
    }
    let mut operations = Vec::new();
    for (document, selected) in requests {
        for header in parse_graphql_operations(&document) {
            let Some(name) = header.name else {
                continue;
            };
            if selected.as_ref().is_some_and(|selected| *selected != name) {
                continue;
            }
            let identity = ProtocolOperationIdentity::GraphQl {
                endpoint_url: Some(endpoint_url.clone()),
                operation_type: header.operation_type,
                operation_name: name,
            };
            if !operations.contains(&identity) {
                operations.push(identity);
            }
        }
    }
    operations
}

/// The gRPC operation a flow is, when it carries a gRPC content type
/// (`application/grpc`, `+proto`, `-web`, `-web-text`, ...) on a
/// `/package.Service/Method` path.
fn observed_grpc_operation(flow: &FlowCapture, path: &str) -> Option<ProtocolOperationIdentity> {
    let grpc = |headers: &[(String, String)]| {
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value
                    .trim()
                    .get(..16)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc"))
        })
    };
    if !grpc(&flow.request_headers) && !grpc(&flow.response_headers) {
        return None;
    }
    let (service, method) = parse_grpc_method_path(path)?;
    Some(ProtocolOperationIdentity::Grpc { service, method })
}

/// Records an observed gRPC call: it confirms the same service/method (from
/// the static pass or an earlier flow) or adds it as a dynamic operation.
fn apply_grpc_operation(
    document: &mut ApiDocument,
    identity: &ProtocolOperationIdentity,
    flows: &[EntityId],
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) {
    let operations = &mut document.surface.protocol_operations;
    match operations
        .iter_mut()
        .find(|operation| &operation.identity == identity)
    {
        Some(operation) => append_candidate(
            &mut operation.presence,
            PresenceAssertion::Present,
            flows,
            ids.candidate(),
            false,
            activity,
        ),
        None => operations.push(ProtocolOperation {
            identity: identity.clone(),
            presence: dynamic_fact(
                FieldClass::Presence,
                ResolutionPolicy::StaticCompleteDynamicConfirm,
                PresenceAssertion::Present,
                flows,
                ids.candidate(),
                activity,
            ),
            request_body: None,
            response_body: None,
        }),
    }
}

/// Decodes `%XX` escapes and `+` in a URL query component.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let hex = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|digit| u8::try_from(digit).ok())
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = match bytes[index] {
            b'+' => Some((b' ', 1)),
            b'%' => bytes
                .get(index + 1)
                .copied()
                .and_then(hex)
                .zip(bytes.get(index + 2).copied().and_then(hex))
                .map(|(high, low)| (high * 16 + low, 3)),
            _ => None,
        };
        let (byte, width) = decoded.unwrap_or((bytes[index], 1));
        out.push(byte);
        index += width;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Records an observed GraphQL operation. It confirms an existing operation
/// of the same type and name on the same URL, or one whose URL was unknown
/// (which takes the observed URL); on another URL it is a separate operation.
fn apply_graphql_operation(
    document: &mut ApiDocument,
    identity: &ProtocolOperationIdentity,
    flows: &[EntityId],
    activity: &apiaxess_api_model::ActivityId,
    ids: &mut IdFactory,
) {
    let ProtocolOperationIdentity::GraphQl {
        endpoint_url,
        operation_type,
        operation_name,
    } = identity
    else {
        return;
    };
    let same_url = |existing: &Option<String>| match (existing, endpoint_url) {
        (Some(existing), Some(observed)) => same_endpoint_url(existing, observed),
        _ => false,
    };
    let operations = &mut document.surface.protocol_operations;
    let position = operations
        .iter()
        .position(|operation| matches!(&operation.identity, ProtocolOperationIdentity::GraphQl { endpoint_url: existing, operation_type: existing_type, operation_name: existing_name } if existing_type == operation_type && existing_name == operation_name && same_url(existing)))
        .or_else(|| {
            operations.iter().position(|operation| {
                matches!(&operation.identity, ProtocolOperationIdentity::GraphQl { endpoint_url: None, operation_type: existing_type, operation_name: existing_name } if existing_type == operation_type && existing_name == operation_name)
            })
        });
    match position {
        Some(index) => {
            let operation = &mut operations[index];
            if let ProtocolOperationIdentity::GraphQl {
                endpoint_url: existing @ None,
                ..
            } = &mut operation.identity
            {
                existing.clone_from(endpoint_url);
            }
            append_candidate(
                &mut operation.presence,
                PresenceAssertion::Present,
                flows,
                ids.candidate(),
                false,
                activity,
            );
        }
        None => operations.push(ProtocolOperation {
            identity: identity.clone(),
            presence: dynamic_fact(
                FieldClass::Presence,
                ResolutionPolicy::StaticCompleteDynamicConfirm,
                PresenceAssertion::Present,
                flows,
                ids.candidate(),
                activity,
            ),
            request_body: None,
            response_body: None,
        }),
    }
}

/// Two endpoint URLs name the same endpoint when host and path agree.
fn same_endpoint_url(left: &str, right: &str) -> bool {
    let path = |url: &str| {
        let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
        let path = rest.find('/').map_or("/", |index| &rest[index..]);
        path.split(['?', '#'])
            .next()
            .unwrap_or("/")
            .trim_end_matches('/')
            .to_owned()
    };
    normalize_host(left) == normalize_host(right) && path(left) == path(right)
}

/// The flow's normalized host, from its exact URL when recorded.
fn flow_host(flow: &FlowCapture) -> Option<String> {
    flow.url
        .as_deref()
        .and_then(normalize_host)
        .or_else(|| flow.host.as_deref().and_then(normalize_host))
}

/// The flow's origin (`scheme://host[:port]`) as a base URL candidate, or the
/// bare host when the flow recorded no URL.
fn flow_origin(flow: &FlowCapture) -> Option<String> {
    let host = flow_host(flow)?;
    let scheme = flow
        .url
        .as_deref()
        .and_then(|url| url.split_once("://"))
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    Some(match scheme {
        Some(scheme) => format!("{scheme}://{host}"),
        None => host,
    })
}

fn path_only(target: &str) -> String {
    let end = target.find(['?', '#']).unwrap_or(target.len());
    target[..end].to_owned()
}
fn string_value(value: &str) -> Value {
    Value::String(value.to_owned())
}
fn pagination_signal(name: &str) -> Option<PaginationSignal> {
    match name.to_ascii_lowercase().as_str() {
        "page" | "page_number" | "pageno" => Some(PaginationSignal::Page),
        "page_size" | "pagesize" | "limit" | "per_page" | "perpage" => {
            Some(PaginationSignal::PageSize)
        }
        "offset" | "start" => Some(PaginationSignal::Offset),
        "cursor" | "next_cursor" | "page_token" | "continuation_token" => {
            Some(PaginationSignal::Cursor)
        }
        _ => None,
    }
}
fn placeholder_name(segment: &str) -> Option<String> {
    if segment.starts_with('{') && segment.ends_with('}') {
        Some(segment[1..segment.len() - 1].to_owned())
    } else if let Some(name) = segment.strip_prefix(':') {
        Some(name.to_owned())
    } else if segment == "*" {
        Some("wildcard".to_owned())
    } else {
        None
    }
}
fn template_matches(template: &str, path: &str) -> bool {
    let left: Vec<_> = template
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let right: Vec<_> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(expected, actual)| placeholder_name(expected).is_some() || *expected == actual)
}
fn infer_template(path: &str) -> Result<PathTemplate, String> {
    let segments = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|segment| {
            if looks_dynamic(segment) {
                "{id}".to_owned()
            } else {
                segment.to_owned()
            }
        })
        .collect::<Vec<_>>();
    PathTemplate::new(format!("/{}", segments.join("/"))).map_err(|error| error.to_string())
}
/// Whether a path segment has an identifier's shape — numeric, a UUID, a long
/// hex hash, or a mixed letters+digits token — so it is templated as `{id}`.
/// Words stay literal, including words carrying a single digit (`oauth2`,
/// `v2`, `oauth2callback`): an id-like mixed token needs at least two digits.
fn looks_dynamic(segment: &str) -> bool {
    let digits = segment.bytes().filter(u8::is_ascii_digit).count();
    let alnum = segment.bytes().all(|byte| byte.is_ascii_alphanumeric());
    (!segment.is_empty() && digits == segment.len())
        || is_uuid(segment)
        || (segment.len() >= 12 && segment.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (alnum
            && segment.len() >= 8
            && digits >= 2
            && segment.bytes().any(|byte| byte.is_ascii_alphabetic()))
}

/// `8-4-4-4-12` hex with dashes.
fn is_uuid(segment: &str) -> bool {
    let groups: Vec<_> = segment.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn handoff_feedback(
    document: &ApiDocument,
    observed: &[EndpointIdentity],
) -> (Vec<String>, Vec<String>) {
    let Some(static_pass) = &document.static_pass else {
        return (Vec::new(), Vec::new());
    };
    let mut resolved = Vec::new();
    let mut open = Vec::new();
    for handoff in &static_pass.dynamic_handoffs {
        if observed.iter().any(|identity| {
            identity.path_template.as_str() == handoff.location
                || handoff.location.contains(identity.path_template.as_str())
        }) {
            resolved.push(handoff.id.clone());
        } else {
            open.push(handoff.id.clone());
        }
    }
    (resolved, open)
}

fn flow_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    flow: &FlowCapture,
    detail: &str,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "flow_id".to_owned(),
        DiagnosticValue::Integer(i64::try_from(flow.id).unwrap_or(i64::MAX)),
    );
    context.insert(
        "detail".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    definition.instantiate(context)
}
fn diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    operation: &str,
    detail: &str,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "detail".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    definition.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_api_model::{ApiSurface, ProvenanceRegistry};
    use apiaxess_session::ScopeDisposition;

    fn flow(id: u64, path: &str, body: &[u8]) -> FlowCapture {
        FlowCapture {
            id,
            captured_at: Utc::now(),
            protocol: "HTTP/2".to_owned(),
            method: Some("GET".to_owned()),
            host: Some("api.example.test".to_owned()),
            url: None,
            path: Some(path.to_owned()),
            status: Some(200),
            duration_ms: Some(1),
            request_headers: vec![("authorization".to_owned(), "Bearer ey.x.z".to_owned())],
            response_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            request_body: None,
            response_body: Some(body.to_vec()),
            scope: ScopeDisposition::InScope,
            provenance: "proxy.test".to_owned(),
            origin: apiaxess_workbench_store::FlowOrigin::Capture,
        }
    }

    #[test]
    fn unmatched_id_route_becomes_dynamic_fact_with_provenance() {
        let document = ApiDocument::new(ApiSurface {
            provenance: ProvenanceRegistry::default(),
            endpoints: Vec::new(),
            protocol_operations: Vec::new(),
            loose_findings: Vec::new(),
            signers: Vec::new(),
        });
        let config = DynamicCaptureConfig::new("run:test").expect("config");
        let report = capture_into_document(
            &document,
            &[
                flow(1, "/users/123", br#"{"ok":true}"#),
                flow(2, "/users/456", br#"{"ok":false}"#),
            ],
            &config,
            Utc::now(),
        )
        .expect("report");
        assert_eq!(report.document.surface.endpoints.len(), 1);
        assert_eq!(
            report.document.surface.endpoints[0]
                .identity
                .path_template
                .as_str(),
            "/users/{id}"
        );
        assert_eq!(
            report
                .document
                .surface
                .provenance
                .entities
                .iter()
                .filter(|entity| entity.kind == EntityKind::ObservedSample)
                .count(),
            2
        );
        report.document.validate().expect("valid dynamic document");
    }

    fn post(id: u64, path: &str, request: &[u8]) -> FlowCapture {
        let mut flow = flow(id, path, br#"{"ok":true}"#);
        flow.method = Some("POST".to_owned());
        flow.request_headers
            .push(("content-type".to_owned(), "application/json".to_owned()));
        flow.request_body = Some(request.to_vec());
        flow
    }

    fn empty_document() -> ApiDocument {
        ApiDocument::new(ApiSurface {
            provenance: ProvenanceRegistry::default(),
            endpoints: Vec::new(),
            protocol_operations: Vec::new(),
            loose_findings: Vec::new(),
            signers: Vec::new(),
        })
    }

    fn templates(flows: &[FlowCapture]) -> Vec<String> {
        let config = DynamicCaptureConfig::new("run:test").expect("config");
        let report =
            capture_into_document(&empty_document(), flows, &config, Utc::now()).expect("report");
        let mut templates: Vec<_> = report
            .document
            .surface
            .endpoints
            .iter()
            .map(|e| {
                format!(
                    "{} {}",
                    e.identity.method,
                    e.identity.path_template.as_str()
                )
            })
            .collect();
        templates.sort();
        templates
    }

    fn on_host(id: u64, host: &str, path: &str) -> FlowCapture {
        let mut flow = flow(id, path, br#"{"ok":true}"#);
        flow.host = Some(host.to_owned());
        flow.url = Some(format!("https://{host}{path}"));
        flow
    }

    fn capture(document: &ApiDocument, flows: &[FlowCapture]) -> DynamicCaptureReport {
        // Each run needs its own ID, as a real second capture run would.
        let run = format!("run:test:{}", document.surface.provenance.activities.len());
        let config = DynamicCaptureConfig::new(run).expect("config");
        capture_into_document(document, flows, &config, Utc::now()).expect("report")
    }

    fn hosts(document: &ApiDocument) -> Vec<Option<String>> {
        let mut hosts: Vec<_> = document
            .surface
            .endpoints
            .iter()
            .map(|endpoint| endpoint.identity.host.clone())
            .collect();
        hosts.sort();
        hosts
    }

    fn selected_bases(endpoint: &Endpoint) -> Vec<String> {
        endpoint
            .base_url
            .iter()
            .flat_map(|fact| {
                fact.candidates
                    .iter()
                    .map(|candidate| candidate.value.clone())
            })
            .collect()
    }

    fn graphql_post(id: u64, body: &str) -> FlowCapture {
        let mut flow = post(id, "/graphql", body.as_bytes());
        flow.url = Some("https://api.example.test/graphql".to_owned());
        flow
    }

    fn operations(document: &ApiDocument) -> Vec<(Option<String>, &'static str, String, usize)> {
        document
            .surface
            .protocol_operations
            .iter()
            .filter_map(|operation| match &operation.identity {
                ProtocolOperationIdentity::GraphQl {
                    endpoint_url,
                    operation_type,
                    operation_name,
                } => Some((
                    endpoint_url.clone(),
                    match operation_type {
                        apiaxess_api_model::GraphQlOperationType::Query => "query",
                        apiaxess_api_model::GraphQlOperationType::Mutation => "mutation",
                        apiaxess_api_model::GraphQlOperationType::Subscription => "subscription",
                    },
                    operation_name.clone(),
                    operation.presence.candidates.len(),
                )),
                ProtocolOperationIdentity::Grpc { .. } => None,
            })
            .collect()
    }

    #[test]
    fn a_graphql_post_lifts_its_operation_name_and_type() {
        let report = capture(
            &empty_document(),
            &[graphql_post(
                1,
                r#"{"operationName":"GetProfile","query":"query GetProfile($id: ID!) { profile(id: $id) { id } }","variables":{"id":7}}"#,
            )],
        );
        assert_eq!(
            operations(&report.document),
            vec![(
                Some("https://api.example.test/graphql".to_owned()),
                "query",
                "GetProfile".to_owned(),
                1
            )]
        );
        // The transport endpoint is still there, alongside its operation.
        assert_eq!(report.document.surface.endpoints.len(), 1);
    }

    fn grpc_call(id: u64, path: &str, content_type: &str) -> FlowCapture {
        let mut flow = flow(id, path, &[0, 0, 0, 0, 2, 8, 1]);
        flow.method = Some("POST".to_owned());
        flow.request_headers
            .push(("content-type".to_owned(), content_type.to_owned()));
        flow.request_body = Some(vec![0, 0, 0, 0, 3, 10, 1, 120]);
        flow.response_headers = vec![("content-type".to_owned(), content_type.to_owned())];
        flow
    }

    fn grpc_operations(document: &ApiDocument) -> Vec<(String, String, usize)> {
        document
            .surface
            .protocol_operations
            .iter()
            .filter_map(|operation| match &operation.identity {
                ProtocolOperationIdentity::Grpc { service, method } => Some((
                    service.clone(),
                    method.clone(),
                    operation.presence.candidates.len(),
                )),
                ProtocolOperationIdentity::GraphQl { .. } => None,
            })
            .collect()
    }

    #[test]
    fn a_grpc_call_surfaces_as_its_service_method_not_an_opaque_post() {
        let report = capture(
            &empty_document(),
            &[
                grpc_call(1, "/shop.v1.CartService/AddItem", "application/grpc"),
                grpc_call(2, "/shop.v1.CartService/AddItem", "application/grpc+proto"),
                grpc_call(3, "/Greeter/SayHello", "application/grpc-web-text"),
            ],
        );
        assert_eq!(
            grpc_operations(&report.document),
            vec![
                ("Greeter".to_owned(), "SayHello".to_owned(), 1),
                ("shop.v1.CartService".to_owned(), "AddItem".to_owned(), 1),
            ]
        );
        // Not a REST endpoint, and no schema is invented for the protobuf body.
        assert!(report.document.surface.endpoints.is_empty());
        assert!(
            report
                .document
                .surface
                .protocol_operations
                .iter()
                .all(|operation| operation.request_body.is_none()
                    && operation.response_body.is_none())
        );
        // A second capture of the same call confirms the one operation.
        let again = capture(
            &report.document,
            &[grpc_call(
                4,
                "/shop.v1.CartService/AddItem",
                "application/grpc",
            )],
        );
        assert_eq!(
            grpc_operations(&again.document),
            vec![
                ("Greeter".to_owned(), "SayHello".to_owned(), 1),
                ("shop.v1.CartService".to_owned(), "AddItem".to_owned(), 2),
            ]
        );
    }

    #[test]
    fn non_json_responses_are_recorded_with_their_media_type_and_no_invented_schema() {
        let mut page = flow(1, "/", b"<!doctype html><title>x</title>");
        page.response_headers = vec![(
            "content-type".to_owned(),
            "text/html; charset=utf-8".to_owned(),
        )];
        // An event stream's events are stored apart from the flow: no body.
        let mut stream = flow(2, "/api/v1/stream", b"");
        stream.response_body = None;
        stream.response_headers = vec![("content-type".to_owned(), "text/event-stream".to_owned())];
        let mut empty = flow(3, "/api/v1/ping", b"");
        empty.response_body = None;
        empty.status = Some(204);
        empty.response_headers = Vec::new();
        let json = flow(4, "/api/v1/status", br#"{"ok":true}"#);
        let report = capture(&empty_document(), &[page, stream, empty, json]);
        let response = |path: &str| {
            let endpoint = report
                .document
                .surface
                .endpoints
                .iter()
                .find(|endpoint| endpoint.identity.path_template.as_str() == path)
                .expect("endpoint");
            assert_eq!(endpoint.responses.len(), 1, "{path}");
            let response = &endpoint.responses[0];
            (
                response.media_type.clone(),
                response
                    .body
                    .shape
                    .selected_candidate()
                    .map(|c| c.value.clone()),
                response.body.observations.len(),
            )
        };
        assert_eq!(
            response("/"),
            (
                Some("text/html".to_owned()),
                Some(SchemaShape::String { format: None }),
                0
            )
        );
        assert_eq!(
            response("/api/v1/stream"),
            (
                Some("text/event-stream".to_owned()),
                Some(SchemaShape::String { format: None }),
                0
            )
        );
        assert_eq!(
            response("/api/v1/ping"),
            (None, Some(SchemaShape::Unknown), 0)
        );
        let (media, shape, samples) = response("/api/v1/status");
        assert_eq!(media.as_deref(), Some("application/json"));
        assert!(matches!(shape, Some(SchemaShape::Object { .. })));
        assert_eq!(samples, 1);
    }

    #[test]
    fn only_a_grpc_content_type_on_a_method_path_is_read_as_grpc() {
        // A REST POST that happens to look like a method path stays REST.
        let report = capture(
            &empty_document(),
            &[
                post(1, "/shop.v1.CartService/AddItem", br#"{"sku":"a"}"#),
                grpc_call(2, "/api/v1/items/7", "application/grpc"),
            ],
        );
        assert!(grpc_operations(&report.document).is_empty());
        assert_eq!(report.document.surface.endpoints.len(), 2);
    }

    #[test]
    fn distinct_graphql_operations_on_one_endpoint_stay_distinct() {
        let report = capture(
            &empty_document(),
            &[
                graphql_post(1, r#"{"query":"query Feed { feed { id } }"}"#),
                graphql_post(
                    2,
                    r#"[{"query":"mutation Like($id: ID!) { like(id: $id) }"},{"query":"{ me { id } }"}]"#,
                ),
                graphql_post(
                    3,
                    r#"{"operationName":"B","query":"query A { a } query B { b }"}"#,
                ),
                graphql_post(4, r#"{"query":"query Feed { feed { id } }"}"#),
            ],
        );
        let names = operations(&report.document)
            .into_iter()
            .map(|(_, kind, name, samples)| (kind, name, samples))
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                ("query", "B".to_owned(), 1),
                ("query", "Feed".to_owned(), 1),
                ("mutation", "Like".to_owned(), 1),
            ]
        );
        let feed = &report.document.surface.protocol_operations[1];
        // Both Feed requests are evidence for the one operation.
        assert_eq!(feed.presence.candidates[0].evidence.len(), 2);
    }

    #[test]
    fn an_observed_operation_confirms_the_static_one_and_supplies_its_url() {
        let mut seeded = capture(
            &empty_document(),
            &[graphql_post(1, r#"{"query":"query GetProfile { p }"}"#)],
        );
        if let ProtocolOperationIdentity::GraphQl { endpoint_url, .. } =
            &mut seeded.document.surface.protocol_operations[0].identity
        {
            *endpoint_url = None;
        }
        let report = capture(
            &seeded.document,
            &[graphql_post(2, r#"{"query":"query GetProfile { p }"}"#)],
        );
        assert_eq!(
            operations(&report.document),
            vec![(
                Some("https://api.example.test/graphql".to_owned()),
                "query",
                "GetProfile".to_owned(),
                2
            )]
        );
    }

    #[test]
    fn graphql_over_get_is_lifted_from_the_query_string() {
        let mut flow = flow(
            1,
            "/graphql?query=query%20Me%20%7B%20me%20%7B%20id%20%7D%20%7D&operationName=Me",
            br#"{"data":{}}"#,
        );
        flow.url = Some("https://api.example.test/graphql?query=x".to_owned());
        let report = capture(&empty_document(), &[flow]);
        assert_eq!(
            operations(&report.document),
            vec![(
                Some("https://api.example.test/graphql".to_owned()),
                "query",
                "Me".to_owned(),
                1
            )]
        );
    }

    #[test]
    fn a_new_run_retracts_what_only_earlier_runs_asserted_and_keeps_other_evidence() {
        let paths = |document: &ApiDocument| {
            let mut paths = document
                .surface
                .endpoints
                .iter()
                .map(|endpoint| endpoint.identity.path_template.as_str().to_owned())
                .collect::<Vec<_>>();
            paths.sort();
            paths
        };
        // Another source's run (standing in for static knowledge) is kept.
        let other = DynamicCaptureConfig::new("other:run").expect("config");
        let base = capture_into_document(
            &empty_document(),
            &[on_host(1, "api.one.test", "/v1/kept")],
            &other,
            Utc::now(),
        )
        .expect("report")
        .document;
        let first = capture(
            &base,
            &[
                on_host(2, "api.one.test", "/v1/still-observed"),
                on_host(3, "noise.test", "/v1/left-scope"),
            ],
        );
        assert_eq!(
            paths(&first.document),
            vec!["/v1/kept", "/v1/left-scope", "/v1/still-observed"]
        );
        let mut document = first.document;
        assert_eq!(retract_previous_runs(&mut document, "run:test:"), 2);
        assert_eq!(paths(&document), vec!["/v1/kept"]);
        // The next run re-asserts only what is still observed.
        let second = capture(
            &document,
            &[on_host(2, "api.one.test", "/v1/still-observed")],
        );
        assert_eq!(
            paths(&second.document),
            vec!["/v1/kept", "/v1/still-observed"]
        );
    }

    #[test]
    fn a_websocket_handshake_is_not_a_rest_endpoint() {
        let mut handshake = on_host(1, "api.one.test", "/socket");
        handshake
            .request_headers
            .push(("Upgrade".to_owned(), "websocket".to_owned()));
        let report = capture(
            &empty_document(),
            &[handshake, on_host(2, "api.one.test", "/v1/status")],
        );
        let paths = report
            .document
            .surface
            .endpoints
            .iter()
            .map(|endpoint| endpoint.identity.path_template.as_str().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["/v1/status".to_owned()]);
    }

    #[test]
    fn two_hosts_serving_the_same_route_stay_distinct_endpoints() {
        let report = capture(
            &empty_document(),
            &[
                on_host(1, "api.one.test", "/v1/status"),
                on_host(2, "api.two.test", "/v1/status"),
                on_host(3, "api.one.test", "/v1/status"),
            ],
        );
        assert_eq!(
            hosts(&report.document),
            vec![
                Some("api.one.test".to_owned()),
                Some("api.two.test".to_owned())
            ]
        );
    }

    #[test]
    fn a_host_bound_endpoint_fuses_only_with_traffic_from_its_own_host() {
        let seeded = capture(
            &empty_document(),
            &[on_host(1, "api.one.test", "/v1/status")],
        );
        let report = capture(
            &seeded.document,
            &[
                on_host(2, "api.one.test", "/v1/status"),
                on_host(3, "api.two.test", "/v1/status"),
            ],
        );
        let endpoints = &report.document.surface.endpoints;
        assert_eq!(endpoints.len(), 2);
        let own = endpoints
            .iter()
            .find(|endpoint| endpoint.identity.host.as_deref() == Some("api.one.test"))
            .expect("existing endpoint kept");
        // The second observation merged into the existing endpoint.
        assert_eq!(own.presence.candidates.len(), 2);
        assert!(report.coverage.static_only_endpoints.is_empty());
    }

    #[test]
    fn a_host_unknown_endpoint_takes_the_single_host_it_was_observed_on() {
        let mut seeded = capture(
            &empty_document(),
            &[on_host(1, "api.one.test", "/v1/status")],
        );
        let endpoint = &mut seeded.document.surface.endpoints[0];
        endpoint.identity.host = None;
        endpoint.base_url = None;
        let report = capture(
            &seeded.document,
            &[on_host(2, "feed.vendor.test", "/v1/status")],
        );
        let endpoints = &report.document.surface.endpoints;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(
            endpoints[0].identity.host.as_deref(),
            Some("feed.vendor.test")
        );
        assert_eq!(
            selected_bases(&endpoints[0]),
            vec!["https://feed.vendor.test".to_owned()]
        );
        assert!(report.coverage.static_only_endpoints.is_empty());
    }

    #[test]
    fn a_host_unknown_endpoint_seen_on_two_hosts_is_not_assigned_either() {
        let mut seeded = capture(
            &empty_document(),
            &[on_host(1, "api.one.test", "/v1/status")],
        );
        seeded.document.surface.endpoints[0].identity.host = None;
        let report = capture(
            &seeded.document,
            &[
                on_host(2, "api.one.test", "/v1/status"),
                on_host(3, "api.two.test", "/v1/status"),
            ],
        );
        assert_eq!(
            hosts(&report.document),
            vec![
                None,
                Some("api.one.test".to_owned()),
                Some("api.two.test".to_owned())
            ]
        );
        assert_eq!(report.coverage.static_only_endpoints.len(), 1);
        assert_eq!(report.coverage.inferred_endpoint_count, 2);
    }

    /// Regression: a query string leaked into templating (`path_only` returned
    /// the whole target when there was no `#`), so `/api/search?q=shoes&page=2`
    /// was read as segment `search?q=shoes&page=2` and became `/api/{id}`.
    #[test]
    fn constant_words_stay_literal_and_varying_ids_template() {
        let flows = [
            flow(1, "/api/users/101?include=profile", br#"{"ok":true}"#),
            flow(2, "/api/users/102", br#"{"ok":true}"#),
            flow(3, "/api/search?q=shoes&page=2", br#"{"ok":true}"#),
            flow(4, "/api/search?q=hats&page=10#top", br#"{"ok":true}"#),
            flow(5, "/api/orders/7f3c2a90-1b4e-4c1a-9d2f-0a1b2c3d4e5f", b"{}"),
            flow(6, "/oauth2callback?code=abc123", b"{}"),
            flow(7, "/files/9f86d081884c7d659a2feaa0", b"{}"),
        ];
        assert_eq!(
            templates(&flows),
            [
                "GET /api/orders/{id}",
                "GET /api/search",
                "GET /api/users/{id}",
                "GET /files/{id}",
                "GET /oauth2callback",
            ]
        );
    }

    #[test]
    fn path_only_strips_query_and_fragment() {
        assert_eq!(path_only("/a/b?x=1&y=2"), "/a/b");
        assert_eq!(path_only("/a/b#frag"), "/a/b");
        assert_eq!(path_only("/a?x=1#f"), "/a");
        assert_eq!(path_only("/a/b"), "/a/b");
    }

    /// The selected shape of a schema slot.
    fn shape(slot: &SchemaSlot) -> &SchemaShape {
        &slot.shape.candidates[0].value
    }

    fn property<'a>(shape: &'a SchemaShape, name: &str) -> &'a SchemaProperty {
        let SchemaShape::Object { properties, .. } = shape else {
            panic!("expected an object shape, got {shape:?}");
        };
        properties
            .iter()
            .find(|property| property.name.as_str() == name)
            .unwrap_or_else(|| panic!("property {name} missing"))
    }

    fn tally(property: &SchemaProperty) -> (u64, u64) {
        match property.requiredness.candidates[0].value {
            RequirednessAssertion::Observed {
                present_samples,
                total_samples,
            } => (present_samples, total_samples.get()),
            RequirednessAssertion::Declared { .. } => panic!("expected observed requiredness"),
        }
    }

    /// Regression (P0 fuse blocker): objects inside a request-body array were
    /// tallied per array element, so a single request with three items claimed
    /// a requiredness tally of 3 against 1 dynamic sample and the whole surface
    /// failed model validation. The tally is per sample now.
    #[test]
    fn array_of_objects_body_tallies_requiredness_per_sample() {
        let config = DynamicCaptureConfig::new("run:test").expect("config");
        let flows = [
            post(
                1,
                "/api/batch",
                br#"{"items":[{"id":1,"tag":"x"},{"id":2},{"id":3,"tag":"y"}]}"#,
            ),
            post(2, "/api/batch", br#"{"items":[{"id":4,"tag":"z"}]}"#),
        ];
        let report = capture_into_document(&empty_document(), &flows, &config, Utc::now())
            .expect("array-of-objects bodies commit");
        report.document.validate().expect("valid document");
        let endpoint = &report.document.surface.endpoints[0];
        let body = shape(endpoint.request_body.as_ref().expect("request body"));
        let items = property(body, "items");
        let SchemaShape::Array { items: element } = shape(&items.schema) else {
            panic!("items is an array");
        };
        let element = shape(element);
        // `id` is in every element of both samples: required (2 of 2).
        assert_eq!(tally(property(element, "id")), (2, 2));
        // `tag` is missing from one element of sample 1: optional (1 of 2).
        assert_eq!(tally(property(element, "tag")), (1, 2));
        // Top-level fields keep their per-sample tally.
        assert_eq!(tally(items), (2, 2));
    }

    #[test]
    fn json_body_across_samples_and_refuse_commit() {
        let config = DynamicCaptureConfig::new("run:test").expect("config");
        let flows = [
            post(1, "/api/items", br#"{"name":"a","qty":1}"#),
            post(2, "/api/items", br#"{"name":"b"}"#),
        ];
        let first = capture_into_document(&empty_document(), &flows, &config, Utc::now())
            .expect("first fuse");
        first.document.validate().expect("first valid");
        let body = shape(
            first.document.surface.endpoints[0]
                .request_body
                .as_ref()
                .expect("body"),
        );
        assert_eq!(tally(property(body, "name")), (2, 2));
        assert_eq!(tally(property(body, "qty")), (1, 2));
        // The GUI re-fuses repeatedly, onto the already-fused document, with
        // the capture growing in between.
        let more = [
            post(1, "/api/items", br#"{"name":"a","qty":1}"#),
            post(2, "/api/items", br#"{"name":"b"}"#),
            post(3, "/api/items", br#"{"items":[{"k":1},{"k":2}]}"#),
        ];
        let config = DynamicCaptureConfig::new("run:test2").expect("config");
        let second = capture_into_document(&first.document, &more, &config, Utc::now())
            .expect("re-fuse commits");
        second.document.validate().expect("re-fuse valid");
    }
}
