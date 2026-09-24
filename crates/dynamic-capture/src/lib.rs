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
    ProvenanceRegistry, QueryParameter, RequirednessAssertion, Resolution, ResolutionPolicy,
    ResponseBody, ResponseSelector, RunId, SamplePayload, SchemaObservation, SchemaProperty,
    SchemaShape, SchemaSlot, SourceType,
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

        let static_matches: Vec<_> = document
            .surface
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.identity.method == method
                    && template_matches(endpoint.identity.path_template.as_str(), &path)
            })
            .map(|endpoint| endpoint.identity.clone())
            .collect();
        let template = if static_matches.len() > 1 {
            diagnostics.push(flow_diagnostic(
                catalogue::DYNAMIC_TEMPLATE_MATCH_AMBIGUOUS,
                flow,
                "multiple static templates matched",
            ));
            continue;
        } else if let Some(identity) = static_matches.into_iter().next() {
            identity.path_template
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
        };
        let entry = accumulators
            .entry(identity.clone())
            .or_insert_with(|| Accumulator::new(identity));
        entry.flow_entities.push(entity_id.clone());
        entry.hosts.extend(flow.host.clone());
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
    let observed_set: BTreeSet<_> = observed.iter().cloned().collect();
    let static_only_endpoints = static_identities
        .difference(&observed_set)
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
        inferred_endpoint_count: observed
            .iter()
            .filter(|identity| !static_identities.contains(*identity))
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
    flow_entities: Vec<EntityId>,
    hosts: Vec<String>,
    query: BTreeMap<String, Vec<Value>>,
    path: BTreeMap<String, Vec<Value>>,
    headers: BTreeMap<String, Vec<Value>>,
    request_samples: Vec<Sample>,
    response_samples: BTreeMap<u16, Vec<Sample>>,
    auth: Option<AuthenticationScheme>,
    pagination: BTreeSet<PaginationSignal>,
}

impl Accumulator {
    fn new(identity: EndpointIdentity) -> Self {
        Self {
            identity,
            flow_entities: Vec::new(),
            hosts: Vec::new(),
            query: BTreeMap::new(),
            path: BTreeMap::new(),
            headers: BTreeMap::new(),
            request_samples: Vec::new(),
            response_samples: BTreeMap::new(),
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
    for (status, samples) in &entry.response_samples {
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
            body: schema_slot(samples, ids, activity),
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
    for (status, samples) in &entry.response_samples {
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
            append_schema(&mut response.body, samples, ids, activity);
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
                body: schema_slot(samples, ids, activity),
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
fn schema_from_values(
    values: &[Value],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaSlot {
    let shape = infer_shape(values, evidence, ids, activity);
    SchemaSlot {
        shape,
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

fn infer_shape_value(
    values: &[Value],
    evidence: &[EntityId],
    ids: &mut IdFactory,
    activity: &apiaxess_api_model::ActivityId,
) -> SchemaShape {
    if values.is_empty() {
        return SchemaShape::Unknown;
    }
    if values.iter().all(Value::is_object) {
        let mut names = BTreeSet::new();
        for value in values {
            if let Some(object) = value.as_object() {
                names.extend(object.keys().cloned());
            }
        }
        let properties = names
            .into_iter()
            .filter_map(|name| {
                let present = values
                    .iter()
                    .filter_map(|value| value.get(&name))
                    .cloned()
                    .collect::<Vec<_>>();
                let name_id = ParameterName::new(name).ok()?;
                let present_count = present.len() as u64;
                Some(SchemaProperty {
                    name: name_id,
                    schema: schema_from_values(&present, evidence, ids, activity),
                    requiredness: dynamic_fact(
                        FieldClass::Requiredness,
                        ResolutionPolicy::SampleGated,
                        RequirednessAssertion::Observed {
                            present_samples: present_count,
                            total_samples: NonZeroU64::new(values.len() as u64).unwrap_or_else(
                                || NonZeroU64::new(1).expect("literal is non-zero"),
                            ),
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
    if values.iter().all(Value::is_array) {
        let items = values
            .iter()
            .flat_map(|value| value.as_array().into_iter().flatten().cloned())
            .collect::<Vec<_>>();
        return SchemaShape::Array {
            items: Box::new(schema_from_values(&items, evidence, ids, activity)),
        };
    }
    let mut variants = Vec::new();
    for value in values {
        let shape = match value {
            Value::Null => SchemaShape::Null,
            Value::Bool(_) => SchemaShape::Boolean,
            Value::Number(number) if number.is_i64() || number.is_u64() => {
                SchemaShape::Integer { format: None }
            }
            Value::Number(_) => SchemaShape::Number { format: None },
            Value::String(_) => SchemaShape::String { format: None },
            Value::Array(_) | Value::Object(_) => {
                infer_shape_value(std::slice::from_ref(value), evidence, ids, activity)
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

fn path_only(path: &str) -> String {
    path.split_once('?')
        .map_or(path, |(path, _)| path)
        .split_once('#')
        .map_or_else(|| path.to_owned(), |(path, _)| path.to_owned())
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
fn looks_dynamic(segment: &str) -> bool {
    segment.bytes().all(|byte| byte.is_ascii_digit())
        || (segment.len() >= 12 && segment.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || (segment.len() >= 8
            && segment.chars().any(|c| c.is_ascii_digit())
            && segment.chars().any(|c| c.is_ascii_alphabetic()))
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
}
