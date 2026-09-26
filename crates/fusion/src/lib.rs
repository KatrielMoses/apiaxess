//! Phase 5.1: non-destructive fusion of static and dynamic API facts.
//!
//! The capture and static passes deliberately leave candidates side by side.
//! This crate is the pure compute boundary that adds auditable merge records,
//! applies the settled field-class policies, and retains every input value and
//! provenance link. It never performs capture, network I/O, or inference from
//! dynamic silence.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    time::Instant,
};

use apiaxess_api_model::{
    Activity, ActivityId, Agent, AgentId, AgentKind, ApiDocument, AuthenticationScheme, Endpoint,
    EndpointIdentity, Entity, EntityId, EntityKind, Fact, FactCandidate, FieldClass,
    HeaderParameter, MergeInput, MergeRecord, MergeRelation, PathParameter, PathTemplateAssertion,
    PresenceAssertion, ProtocolOperation, QueryParameter, ResponseBody, RunId, SchemaShape,
    SchemaSlot, SourceType, normalize_host,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use chrono::{DateTime, Utc};

/// Phase 5.1 fusion configuration.
#[derive(Clone, Debug)]
pub struct FusionConfig {
    /// Stable run identifier retained in the fusion activity.
    pub run_id: String,
    /// Optional engine version attributed to the fusion activity.
    pub engine_version: Option<String>,
}

impl FusionConfig {
    /// Creates a fusion configuration after validating its run identifier.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic when the identifier is invalid.
    pub fn new(run_id: impl Into<String>) -> Result<Self, Diagnostic> {
        let run_id = run_id.into();
        RunId::new(run_id.clone()).map_err(|error| {
            diagnostic(catalogue::FUSION_INVALID_INPUT, "run", &error.to_string())
        })?;
        Ok(Self {
            run_id,
            engine_version: None,
        })
    }
}

/// Result of a successful pure fusion pass.
#[derive(Clone, Debug)]
pub struct FusionReport {
    /// Validated document containing the merged fact layer.
    pub document: ApiDocument,
    /// Diagnostics for the pass. True conflicts are represented in facts and
    /// are intentionally not diagnostics by themselves.
    pub diagnostics: Vec<Diagnostic>,
    /// Number of fact fields that received at least one merge record.
    pub merged_fact_count: usize,
}

struct FusionIds {
    prefix: String,
    counter: u64,
}

impl FusionIds {
    fn new(run_id: &str) -> Self {
        Self {
            prefix: run_id.to_owned(),
            counter: 0,
        }
    }

    fn next(&mut self, kind: &str) -> String {
        self.counter = self.counter.saturating_add(1);
        format!("fusion:{kind}:{}:{}", self.prefix, self.counter)
    }

    fn candidate(&mut self) -> apiaxess_api_model::CandidateId {
        apiaxess_api_model::CandidateId::new(self.next("candidate"))
            .expect("generated candidate identifier is valid")
    }

    fn entity(&mut self) -> EntityId {
        EntityId::new(self.next("entity")).expect("generated entity identifier is valid")
    }
}

/// Fuses every REST fact in a validated API document.
///
/// Endpoint identity is the existing method plus path-template key. Static
/// identities are therefore naturally primary, while dynamic-only identities
/// remain in the output as dynamic evidence. Facts are merged in place inside
/// the cloned document; no candidate or provenance evidence is removed.
///
/// # Errors
///
/// Returns diagnostics and leaves the caller's input untouched if the input
/// is invalid, an identity collision is found, provenance cannot be traced, or
/// the resulting document fails canonical validation.
///
/// # Panics
///
/// Panics only if a previously validated `FusionConfig` or an internally
/// generated identifier is inconsistent with its constructor contract.
#[allow(clippy::too_many_lines)]
pub fn fuse_document(
    source: &ApiDocument,
    config: &FusionConfig,
    at: DateTime<Utc>,
) -> Result<FusionReport, Vec<Diagnostic>> {
    let profiling_started = Instant::now();
    profile_mark("fusion.begin", profiling_started);
    if let Some(identity) = duplicate_identity(&source.surface.endpoints) {
        return Err(vec![diagnostic(
            catalogue::FUSION_IDENTITY_COLLISION,
            "identity",
            &format!(
                "duplicate endpoint identity {} {}{}",
                identity.method,
                identity.host.as_deref().unwrap_or_default(),
                identity.path_template
            ),
        )]);
    }
    if let Err(error) = source.validate() {
        return Err(vec![diagnostic(
            catalogue::FUSION_INVALID_INPUT,
            "validate",
            &error.to_string(),
        )]);
    }
    profile_mark("fusion.input-validated", profiling_started);

    let mut document = source.clone();
    let run = RunId::new(config.run_id.clone()).expect("FusionConfig validates its run ID");
    let (_, activity) = add_fusion_activity(
        &mut document.surface.provenance,
        &run,
        config.engine_version.clone(),
        at,
    );
    let mut ids = FusionIds::new(&config.run_id);
    let indexed_provenance = document.surface.provenance.clone();
    let provenance_index = indexed_provenance.entity_index();
    let mut merged_fact_count = 0_usize;

    for (index, endpoint) in document.surface.endpoints.iter_mut().enumerate() {
        merged_fact_count += fuse_endpoint(
            endpoint,
            &mut document.surface.provenance,
            &provenance_index,
            &activity,
            at,
            &mut ids,
            &format!("endpoints[{index}]"),
        )
        .map_err(|error| {
            vec![diagnostic(
                catalogue::FUSION_CONTRADICTORY_PROVENANCE,
                "endpoint",
                &error,
            )]
        })?;
    }
    profile_mark("fusion.endpoints-merged", profiling_started);

    for (index, operation) in document.surface.protocol_operations.iter_mut().enumerate() {
        merged_fact_count += fuse_protocol_operation(
            operation,
            &mut document.surface.provenance,
            &provenance_index,
            &activity,
            at,
            &mut ids,
            &format!("protocol_operations[{index}]"),
        )
        .map_err(|error| {
            vec![diagnostic(
                catalogue::FUSION_CONTRADICTORY_PROVENANCE,
                "protocol-operation",
                &error,
            )]
        })?;
    }
    profile_mark("fusion.protocol-operations-merged", profiling_started);
    for (index, finding) in document.surface.loose_findings.iter_mut().enumerate() {
        merged_fact_count += merge_fact(
            &mut finding.value,
            &mut document.surface.provenance,
            &provenance_index,
            &activity,
            at,
            &mut ids,
            &format!("loose_findings[{index}].value"),
            classify_scalar,
            |_left, _right| None,
        )
        .map_err(|error| {
            vec![diagnostic(
                catalogue::FUSION_CONTRADICTORY_PROVENANCE,
                "loose-finding",
                &error,
            )]
        })?;
    }
    profile_mark("fusion.loose-findings-merged", profiling_started);

    if let Err(error) = document.validate() {
        return Err(vec![diagnostic(
            catalogue::FUSION_MODEL_COMMIT_FAILED,
            "validate",
            &error.to_string(),
        )]);
    }
    profile_mark("fusion.output-validated", profiling_started);
    let diagnostics = Vec::new();
    Ok(FusionReport {
        document,
        diagnostics,
        merged_fact_count,
    })
}

fn profile_mark(label: &str, started: Instant) {
    if std::env::var_os("APIAXESS_PROFILE_PIPELINE").is_some() {
        eprintln!(
            "[pipeline-profile] {label} elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
}

fn add_fusion_activity(
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    run: &RunId,
    version: Option<String>,
    at: DateTime<Utc>,
) -> (AgentId, ActivityId) {
    let agent_id = AgentId::new("fusion.engine").expect("static fusion agent identifier is valid");
    if !provenance.agents.iter().any(|agent| agent.id == agent_id) {
        provenance.agents.push(Agent {
            id: agent_id.clone(),
            kind: AgentKind::Engine,
            name: "APIaxess fusion".to_owned(),
            version,
        });
    }
    let base = format!("fusion:phase-5.1:{run}");
    let mut value = base.clone();
    let mut suffix = 0_u32;
    while provenance
        .activities
        .iter()
        .any(|activity| activity.id.as_str() == value)
    {
        suffix = suffix.saturating_add(1);
        value = format!("{base}:{suffix}");
    }
    let activity_id =
        ActivityId::new(value).expect("generated fusion activity identifier is valid");
    provenance.activities.push(Activity {
        id: activity_id.clone(),
        run_id: run.clone(),
        agent: agent_id.clone(),
        source_type: SourceType::Fusion,
        started_at: at,
        ended_at: Some(at),
    });
    (agent_id, activity_id)
}

fn duplicate_identity(endpoints: &[Endpoint]) -> Option<EndpointIdentity> {
    let mut identities = BTreeSet::new();
    endpoints.iter().find_map(|endpoint| {
        if identities.insert(&endpoint.identity) {
            None
        } else {
            Some(endpoint.identity.clone())
        }
    })
}

#[allow(clippy::too_many_lines)]
fn fuse_endpoint(
    endpoint: &mut Endpoint,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = 0;
    if let Some(base_url) = &mut endpoint.base_url {
        count += merge_fact(
            base_url,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.base_url"),
            classify_scalar,
            |_left, _right| None,
        )?;
        if let Some(host) = &endpoint.identity.host {
            select_base_for_host(base_url, host, activity, at);
        }
    }
    count += merge_fact(
        &mut endpoint.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    count += merge_fact(
        &mut endpoint.path_template,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.path_template"),
        classify_path_template,
        |_left, _right| None,
    )?;
    if let Some(authentication) = &mut endpoint.authentication {
        count += merge_fact(
            authentication,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.authentication"),
            classify_authentication,
            |_left, _right| None,
        )?;
    }
    for (index, parameter) in endpoint.query_parameters.iter_mut().enumerate() {
        count += fuse_query(
            parameter,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.query_parameters[{index}]"),
        )?;
    }
    for (index, parameter) in endpoint.path_parameters.iter_mut().enumerate() {
        count += fuse_path(
            parameter,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.path_parameters[{index}]"),
        )?;
    }
    for (index, header) in endpoint.headers.iter_mut().enumerate() {
        count += fuse_header(
            header,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.headers[{index}]"),
        )?;
    }
    if let Some(body) = &mut endpoint.request_body {
        count += fuse_schema(
            body,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.request_body"),
        )?;
    }
    for (index, response) in endpoint.responses.iter_mut().enumerate() {
        count += fuse_response(
            response,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.responses[{index}]"),
        )?;
    }
    for (index, signal) in endpoint.pagination_signals.iter_mut().enumerate() {
        count += merge_fact(
            signal,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.pagination_signals[{index}]"),
            classify_scalar,
            |_left, _right| None,
        )?;
    }
    Ok(count)
}

fn fuse_query(
    parameter: &mut QueryParameter,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = merge_fact(
        &mut parameter.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    count += fuse_schema(
        &mut parameter.schema,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.schema"),
    )?;
    count += merge_fact(
        &mut parameter.requiredness,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.requiredness"),
        classify_requiredness,
        |_left, _right| None,
    )?;
    Ok(count)
}

fn fuse_path(
    parameter: &mut PathParameter,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = merge_fact(
        &mut parameter.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    count += fuse_schema(
        &mut parameter.schema,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.schema"),
    )?;
    Ok(count)
}

fn fuse_header(
    header: &mut HeaderParameter,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = merge_fact(
        &mut header.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    count += fuse_schema(
        &mut header.schema,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.schema"),
    )?;
    Ok(count)
}

fn fuse_schema(
    schema: &mut SchemaSlot,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    merge_fact(
        &mut schema.shape,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.shape"),
        classify_schema,
        widen_schema,
    )
}

fn fuse_response(
    response: &mut ResponseBody,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = merge_fact(
        &mut response.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    count += fuse_schema(
        &mut response.body,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.body"),
    )?;
    Ok(count)
}

fn fuse_protocol_operation(
    operation: &mut ProtocolOperation,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
) -> Result<usize, String> {
    let mut count = merge_fact(
        &mut operation.presence,
        provenance,
        provenance_index,
        activity,
        at,
        ids,
        &format!("{path}.presence"),
        classify_presence,
        |_left, _right| None,
    )?;
    if let Some(body) = &mut operation.request_body {
        count += fuse_schema(
            body,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.request_body"),
        )?;
    }
    if let Some(body) = &mut operation.response_body {
        count += fuse_schema(
            body,
            provenance,
            provenance_index,
            activity,
            at,
            ids,
            &format!("{path}.response_body"),
        )?;
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn merge_fact<T, C, W>(
    fact: &mut Fact<T>,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
    activity: &ActivityId,
    at: DateTime<Utc>,
    ids: &mut FusionIds,
    path: &str,
    classify: C,
    widen: W,
) -> Result<usize, String>
where
    T: Clone + PartialEq,
    C: Fn(&T, &T) -> MergeRelation,
    W: Fn(&T, &T) -> Option<T>,
{
    let mut static_candidates = Vec::new();
    let mut dynamic_candidates = Vec::new();
    for candidate in &fact.candidates {
        let mask = candidate_source_mask(candidate, provenance, provenance_index)
            .map_err(|error| format!("{path}: {error}"))?;
        if mask & 1 != 0 {
            static_candidates.push(candidate.clone());
        }
        if mask & 2 != 0 {
            dynamic_candidates.push(candidate.clone());
        }
    }
    if static_candidates.is_empty() && dynamic_candidates.is_empty() {
        return Ok(0);
    }

    let mut records_added = 0;
    if static_candidates.is_empty() {
        for dynamic in &dynamic_candidates {
            records_added += add_merge(
                fact,
                MergeRecord {
                    left: MergeInput {
                        source_type: SourceType::StaticAnalysis,
                        candidate: None,
                    },
                    right: MergeInput {
                        source_type: SourceType::DynamicCapture,
                        candidate: Some(dynamic.id.clone()),
                    },
                    relation: MergeRelation::GapFill,
                    result: dynamic.id.clone(),
                    recorded_by: activity.clone(),
                    recorded_at: at,
                },
            );
        }
    } else if dynamic_candidates.is_empty() {
        for static_candidate in &static_candidates {
            records_added += add_merge(
                fact,
                MergeRecord {
                    left: MergeInput {
                        source_type: SourceType::StaticAnalysis,
                        candidate: Some(static_candidate.id.clone()),
                    },
                    right: MergeInput {
                        source_type: SourceType::DynamicCapture,
                        candidate: None,
                    },
                    relation: MergeRelation::GapFill,
                    result: static_candidate.id.clone(),
                    recorded_by: activity.clone(),
                    recorded_at: at,
                },
            );
        }
    } else {
        for static_candidate in &static_candidates {
            for dynamic_candidate in &dynamic_candidates {
                let relation = if static_candidate.value == dynamic_candidate.value {
                    MergeRelation::Agreement
                } else {
                    classify(&static_candidate.value, &dynamic_candidate.value)
                };
                let result = if relation == MergeRelation::Refinement {
                    if let Some(value) = widen(&static_candidate.value, &dynamic_candidate.value) {
                        derived_candidate(
                            fact,
                            provenance,
                            ids,
                            value,
                            [static_candidate, dynamic_candidate],
                            activity,
                            at,
                        )?
                    } else {
                        dynamic_candidate.id.clone()
                    }
                } else {
                    dynamic_candidate.id.clone()
                };
                records_added += add_merge(
                    fact,
                    MergeRecord {
                        left: MergeInput {
                            source_type: SourceType::StaticAnalysis,
                            candidate: Some(static_candidate.id.clone()),
                        },
                        right: MergeInput {
                            source_type: SourceType::DynamicCapture,
                            candidate: Some(dynamic_candidate.id.clone()),
                        },
                        relation,
                        result,
                        recorded_by: activity.clone(),
                        recorded_at: at,
                    },
                );
            }
        }
    }
    select_resolution(fact, &static_candidates, &dynamic_candidates, activity, at);
    Ok(records_added)
}

fn candidate_source_mask<T>(
    candidate: &FactCandidate<T>,
    provenance: &apiaxess_api_model::ProvenanceRegistry,
    provenance_index: &BTreeMap<&apiaxess_api_model::EntityId, &apiaxess_api_model::Entity>,
) -> Result<u8, String> {
    if candidate.evidence.iter().any(|id| {
        provenance
            .entity(id)
            .is_some_and(|entity| entity.source_type == SourceType::Fusion)
    }) {
        return Ok(0);
    }
    let leaves = provenance
        .leaf_entities_with_index(&candidate.evidence, provenance_index)
        .map_err(|error| error.to_string())?;
    let mut mask = 0_u8;
    for entity in leaves {
        match entity.source_type {
            SourceType::StaticAnalysis => mask |= 1,
            SourceType::DynamicCapture => mask |= 2,
            SourceType::Fusion => {}
        }
    }
    if mask == 0 {
        return Err("candidate has no static or dynamic leaf evidence".to_owned());
    }
    Ok(mask)
}

fn derived_candidate<T>(
    fact: &mut Fact<T>,
    provenance: &mut apiaxess_api_model::ProvenanceRegistry,
    ids: &mut FusionIds,
    value: T,
    inputs: [&FactCandidate<T>; 2],
    activity: &ActivityId,
    at: DateTime<Utc>,
) -> Result<apiaxess_api_model::CandidateId, String>
where
    T: Clone + PartialEq,
{
    if let Some(existing) = fact
        .candidates
        .iter()
        .find(|candidate| candidate.value == value)
    {
        return Ok(existing.id.clone());
    }
    let mut derived_from = Vec::new();
    for input in inputs {
        for entity in &input.evidence {
            if !derived_from.contains(entity) {
                derived_from.push(entity.clone());
            }
        }
    }
    let entity_id = ids.entity();
    provenance.entities.push(Entity {
        id: entity_id.clone(),
        kind: EntityKind::DerivedFact,
        source_type: SourceType::Fusion,
        generated_by: activity.clone(),
        attributed_to: provenance
            .activity(activity)
            .ok_or_else(|| "fusion activity is missing".to_owned())?
            .agent
            .clone(),
        run_id: provenance
            .activity(activity)
            .ok_or_else(|| "fusion activity is missing".to_owned())?
            .run_id
            .clone(),
        derived_from,
        recorded_at: at,
        sample_count: NonZeroU64::new(1).expect("literal is non-zero"),
    });
    let candidate_id = ids.candidate();
    fact.candidates.push(FactCandidate {
        id: candidate_id.clone(),
        value,
        evidence: vec![entity_id],
    });
    Ok(candidate_id)
}

fn add_merge(fact: &mut Fact<impl Clone>, record: MergeRecord) -> usize {
    if fact.merges.iter().any(|existing| {
        existing.left == record.left
            && existing.right == record.right
            && existing.relation == record.relation
    }) {
        0
    } else {
        fact.merges.push(record);
        1
    }
}

fn select_resolution<T: Clone + PartialEq>(
    fact: &mut Fact<T>,
    static_candidates: &[FactCandidate<T>],
    dynamic_candidates: &[FactCandidate<T>],
    activity: &ActivityId,
    at: DateTime<Utc>,
) {
    let selected = match fact.field_class {
        FieldClass::Authentication => dynamic_candidates
            .first()
            .or_else(|| static_candidates.first()),
        FieldClass::Presence => static_candidates
            .first()
            .or_else(|| dynamic_candidates.first()),
        FieldClass::PathTemplate => static_candidates
            .first()
            .or_else(|| dynamic_candidates.first()),
        FieldClass::TypeShape => fact
            .candidates
            .iter()
            .find(|candidate| candidate.id.as_str().starts_with("fusion:candidate:"))
            .or_else(|| dynamic_candidates.first())
            .or_else(|| static_candidates.first()),
        FieldClass::Requiredness => dynamic_candidates
            .first()
            .or_else(|| static_candidates.first()),
        FieldClass::Scalar => fact
            .candidates
            .iter()
            .find(|candidate| candidate.id == fact.resolution.selected)
            .or_else(|| dynamic_candidates.first())
            .or_else(|| static_candidates.first()),
    };
    if let Some(selected) = selected {
        fact.resolution.selected = selected.id.clone();
        fact.resolution.resolved_by = activity.clone();
        fact.resolution.resolved_at = at;
    }
}

/// The endpoint's identity host is authoritative for its base URL: a static
/// base guessed for a host-unknown route is superseded by the base observed
/// on the host the endpoint is bound to.
fn select_base_for_host(
    fact: &mut Fact<String>,
    host: &str,
    activity: &ActivityId,
    at: DateTime<Utc>,
) {
    let on_host = |candidate: &FactCandidate<String>| {
        normalize_host(&candidate.value).as_deref() == Some(host)
    };
    if fact
        .candidates
        .iter()
        .any(|candidate| candidate.id == fact.resolution.selected && on_host(candidate))
    {
        return;
    }
    // Prefer a full origin (`scheme://host`) over a bare host.
    let selected = fact
        .candidates
        .iter()
        .filter(|candidate| on_host(candidate))
        .max_by_key(|candidate| candidate.value.contains("://"))
        .map(|candidate| candidate.id.clone());
    if let Some(selected) = selected {
        fact.resolution.selected = selected;
        fact.resolution.resolved_by = activity.clone();
        fact.resolution.resolved_at = at;
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn classify_presence(_left: &PresenceAssertion, _right: &PresenceAssertion) -> MergeRelation {
    MergeRelation::TrueConflict
}

fn classify_authentication(
    _left: &AuthenticationScheme,
    _right: &AuthenticationScheme,
) -> MergeRelation {
    MergeRelation::TrueConflict
}

fn classify_scalar<T>(_left: &T, _right: &T) -> MergeRelation {
    MergeRelation::TrueConflict
}

fn classify_path_template(
    left: &PathTemplateAssertion,
    right: &PathTemplateAssertion,
) -> MergeRelation {
    if left.template == right.template {
        MergeRelation::Refinement
    } else {
        MergeRelation::TrueConflict
    }
}

fn classify_requiredness(
    left: &apiaxess_api_model::RequirednessAssertion,
    right: &apiaxess_api_model::RequirednessAssertion,
) -> MergeRelation {
    match (left, right) {
        (
            apiaxess_api_model::RequirednessAssertion::Declared { .. },
            apiaxess_api_model::RequirednessAssertion::Observed { .. },
        ) => MergeRelation::Refinement,
        _ => MergeRelation::TrueConflict,
    }
}

fn classify_schema(_left: &SchemaShape, _right: &SchemaShape) -> MergeRelation {
    MergeRelation::Refinement
}

fn widen_schema(left: &SchemaShape, right: &SchemaShape) -> Option<SchemaShape> {
    if left == right {
        return None;
    }
    if matches!(left, SchemaShape::Unknown) {
        return Some(right.clone());
    }
    if matches!(right, SchemaShape::Unknown) {
        return Some(left.clone());
    }
    let mut variants = Vec::new();
    append_schema_variants(left, &mut variants);
    append_schema_variants(right, &mut variants);
    if variants.len() == 1 {
        variants.into_iter().next()
    } else {
        Some(SchemaShape::Union { variants })
    }
}

fn append_schema_variants(shape: &SchemaShape, variants: &mut Vec<SchemaShape>) {
    match shape {
        SchemaShape::Union { variants: nested } => {
            for variant in nested {
                append_schema_variants(variant, variants);
            }
        }
        value if !variants.contains(value) => variants.push(value.clone()),
        _ => {}
    }
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
    use apiaxess_api_model::{
        ApiSurface, CandidateId, EntityId, Fact, FactCandidate, FieldClass, HttpMethod,
        LooseFinding, LooseFindingKind, PathTemplate, PathTemplateOrigin, Resolution,
        ResolutionPolicy,
    };
    use chrono::TimeZone;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, second)
            .single()
            .unwrap()
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> (ApiDocument, EntityId, EntityId) {
        let static_agent = AgentId::new("agent:static").unwrap();
        let dynamic_agent = AgentId::new("agent:dynamic").unwrap();
        let static_activity = ActivityId::new("activity:static").unwrap();
        let dynamic_activity = ActivityId::new("activity:dynamic").unwrap();
        let static_run = RunId::new("run:static").unwrap();
        let dynamic_run = RunId::new("run:dynamic").unwrap();
        let static_entity = EntityId::new("entity:static").unwrap();
        let dynamic_entity = EntityId::new("entity:dynamic").unwrap();
        let provenance = apiaxess_api_model::ProvenanceRegistry {
            agents: vec![
                Agent {
                    id: static_agent.clone(),
                    kind: AgentKind::ExternalTool,
                    name: "static".into(),
                    version: None,
                },
                Agent {
                    id: dynamic_agent.clone(),
                    kind: AgentKind::ExternalTool,
                    name: "dynamic".into(),
                    version: None,
                },
            ],
            activities: vec![
                Activity {
                    id: static_activity.clone(),
                    run_id: static_run.clone(),
                    agent: static_agent,
                    source_type: SourceType::StaticAnalysis,
                    started_at: at(0),
                    ended_at: Some(at(1)),
                },
                Activity {
                    id: dynamic_activity.clone(),
                    run_id: dynamic_run.clone(),
                    agent: dynamic_agent,
                    source_type: SourceType::DynamicCapture,
                    started_at: at(2),
                    ended_at: Some(at(3)),
                },
            ],
            entities: vec![
                Entity {
                    id: static_entity.clone(),
                    kind: EntityKind::FactEvidence,
                    source_type: SourceType::StaticAnalysis,
                    generated_by: static_activity.clone(),
                    attributed_to: AgentId::new("agent:static").unwrap(),
                    run_id: static_run,
                    derived_from: vec![],
                    recorded_at: at(1),
                    sample_count: NonZeroU64::new(1).unwrap(),
                },
                Entity {
                    id: dynamic_entity.clone(),
                    kind: EntityKind::FactEvidence,
                    source_type: SourceType::DynamicCapture,
                    generated_by: dynamic_activity.clone(),
                    attributed_to: AgentId::new("agent:dynamic").unwrap(),
                    run_id: dynamic_run,
                    derived_from: vec![],
                    recorded_at: at(3),
                    sample_count: NonZeroU64::new(4).unwrap(),
                },
            ],
        };
        let static_presence = Fact {
            field_class: FieldClass::Presence,
            expected_recoverability_basis_points: None,
            candidates: vec![FactCandidate {
                id: CandidateId::new("candidate:static:presence").unwrap(),
                value: PresenceAssertion::Present,
                evidence: vec![static_entity.clone()],
            }],
            resolution: Resolution {
                selected: CandidateId::new("candidate:static:presence").unwrap(),
                policy: ResolutionPolicy::StaticCompleteDynamicConfirm,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges: vec![],
        };
        let static_template = Fact {
            field_class: FieldClass::PathTemplate,
            expected_recoverability_basis_points: None,
            candidates: vec![FactCandidate {
                id: CandidateId::new("candidate:static:template").unwrap(),
                value: PathTemplateAssertion {
                    template: PathTemplate::new("/users/{id}").unwrap(),
                    origin: PathTemplateOrigin::Declared,
                },
                evidence: vec![static_entity.clone()],
            }],
            resolution: Resolution {
                selected: CandidateId::new("candidate:static:template").unwrap(),
                policy: ResolutionPolicy::DeclaredBeforeInferred,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges: vec![],
        };
        let shape = Fact {
            field_class: FieldClass::TypeShape,
            expected_recoverability_basis_points: None,
            candidates: vec![FactCandidate {
                id: CandidateId::new("candidate:static:type").unwrap(),
                value: SchemaShape::Integer { format: None },
                evidence: vec![static_entity.clone()],
            }],
            resolution: Resolution {
                selected: CandidateId::new("candidate:static:type").unwrap(),
                policy: ResolutionPolicy::UnionOrWiden,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges: vec![],
        };
        let dynamic_auth = Fact {
            field_class: FieldClass::Authentication,
            expected_recoverability_basis_points: None,
            candidates: vec![FactCandidate {
                id: CandidateId::new("candidate:dynamic:auth").unwrap(),
                value: AuthenticationScheme::Bearer { token_format: None },
                evidence: vec![dynamic_entity.clone()],
            }],
            resolution: Resolution {
                selected: CandidateId::new("candidate:dynamic:auth").unwrap(),
                policy: ResolutionPolicy::DynamicAuthoritative,
                resolved_by: ActivityId::new("activity:dynamic").unwrap(),
                resolved_at: at(3),
            },
            merges: vec![],
        };
        let endpoint = Endpoint {
            identity: EndpointIdentity {
                method: HttpMethod::new("GET").unwrap(),
                path_template: PathTemplate::new("/users/{id}").unwrap(),
                host: None,
            },
            base_url: None,
            presence: static_presence,
            path_template: static_template,
            query_parameters: vec![],
            path_parameters: vec![],
            headers: vec![],
            authentication: Some(dynamic_auth),
            request_body: Some(SchemaSlot {
                shape,
                observations: vec![],
            }),
            request_media_type: None,
            responses: vec![],
            pagination_signals: vec![],
        };
        (
            ApiDocument::new(ApiSurface {
                provenance,
                endpoints: vec![endpoint],
                protocol_operations: vec![],
                loose_findings: vec![],
                signers: vec![],
            }),
            static_entity,
            dynamic_entity,
        )
    }

    #[test]
    fn partially_exercised_static_facts_are_gap_filled_without_negation() {
        let (document, _static_entity, _dynamic_entity) = fixture();
        let config = FusionConfig::new("run:fusion").unwrap();
        let report = fuse_document(&document, &config, at(4)).unwrap();
        let endpoint = &report.document.surface.endpoints[0];
        assert_eq!(endpoint.presence.candidates.len(), 1);
        assert_eq!(endpoint.presence.merges[0].relation, MergeRelation::GapFill);
        assert!(endpoint.presence.merges[0].right.candidate.is_none());
    }

    #[test]
    fn the_observed_base_on_the_identity_host_supersedes_a_guessed_static_base() {
        let (mut document, static_entity, dynamic_entity) = fixture();
        let endpoint = &mut document.surface.endpoints[0];
        // Static guessed one app-wide base; capture bound the route to the
        // host it was actually served from.
        endpoint.identity.host = Some("feed.vendor.test".to_owned());
        endpoint.base_url = Some(Fact {
            field_class: FieldClass::Scalar,
            expected_recoverability_basis_points: None,
            candidates: vec![
                FactCandidate {
                    id: CandidateId::new("candidate:static:base").unwrap(),
                    value: "https://api.app.test".to_owned(),
                    evidence: vec![static_entity],
                },
                FactCandidate {
                    id: CandidateId::new("candidate:dynamic:base").unwrap(),
                    value: "https://feed.vendor.test".to_owned(),
                    evidence: vec![dynamic_entity],
                },
            ],
            resolution: Resolution {
                selected: CandidateId::new("candidate:static:base").unwrap(),
                policy: ResolutionPolicy::Explicit,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges: vec![],
        });
        let report =
            fuse_document(&document, &FusionConfig::new("run:fusion").unwrap(), at(4)).unwrap();
        let base = report.document.surface.endpoints[0]
            .base_url
            .as_ref()
            .unwrap();
        assert_eq!(
            base.selected_candidate().unwrap().value,
            "https://feed.vendor.test"
        );
        // The static guess is retained as evidence, not discarded.
        assert_eq!(base.candidates.len(), 2);
    }

    #[test]
    fn authentication_uses_dynamic_policy_and_keeps_conflicting_candidates() {
        let (mut document, static_entity, dynamic_entity) = fixture();
        document.surface.endpoints[0]
            .authentication
            .as_mut()
            .unwrap()
            .candidates
            .push(FactCandidate {
                id: CandidateId::new("candidate:static:auth").unwrap(),
                value: AuthenticationScheme::Basic,
                evidence: vec![static_entity],
            });
        let _ = dynamic_entity;
        let report =
            fuse_document(&document, &FusionConfig::new("run:fusion").unwrap(), at(4)).unwrap();
        let fact = report.document.surface.endpoints[0]
            .authentication
            .as_ref()
            .unwrap();
        assert_eq!(fact.candidates.len(), 2);
        assert_eq!(
            fact.merges
                .iter()
                .find(|merge| merge.relation == MergeRelation::TrueConflict)
                .unwrap()
                .relation,
            MergeRelation::TrueConflict
        );
        assert_eq!(
            fact.selected_candidate().unwrap().value,
            AuthenticationScheme::Bearer { token_format: None }
        );
    }

    #[test]
    fn high_volume_loose_findings_have_bounded_fusion_cost() {
        const FINDING_COUNT: usize = 27_473;
        let (mut document, _static_entity, _dynamic_entity) = fixture();
        let recorded_by = ActivityId::new("activity:static").unwrap();
        let mut evidence_ids = Vec::with_capacity(FINDING_COUNT);
        for index in 0..FINDING_COUNT {
            let evidence_id =
                EntityId::new(format!("entity:loose:{index}")).expect("evidence entity ID");
            let mut entity = document.surface.provenance.entities[0].clone();
            entity.id = evidence_id.clone();
            document.surface.provenance.entities.push(entity);
            evidence_ids.push(evidence_id);
        }
        document.surface.loose_findings = (0..FINDING_COUNT)
            .map(|index| {
                let candidate_id =
                    CandidateId::new(format!("candidate:loose:{index}")).expect("candidate ID");
                LooseFinding {
                    kind: LooseFindingKind::Url,
                    value: Fact {
                        field_class: FieldClass::Scalar,
                        expected_recoverability_basis_points: None,
                        candidates: vec![FactCandidate {
                            id: candidate_id.clone(),
                            value: format!("https://example.test/api/{index}"),
                            evidence: vec![evidence_ids[index].clone()],
                        }],
                        resolution: Resolution {
                            selected: candidate_id,
                            policy: ResolutionPolicy::Explicit,
                            resolved_by: recorded_by.clone(),
                            resolved_at: at(1),
                        },
                        merges: vec![],
                    },
                }
            })
            .collect();

        let started = std::time::Instant::now();
        let report = fuse_document(
            &document,
            &FusionConfig::new("run:high-volume-fusion").unwrap(),
            at(4),
        )
        .unwrap();

        assert_eq!(report.document.surface.loose_findings.len(), FINDING_COUNT);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "high-volume fusion exceeded 30s: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn schema_values_widen_and_all_inputs_survive() {
        let (mut document, _static_entity, dynamic_entity) = fixture();
        document.surface.endpoints[0]
            .request_body
            .as_mut()
            .unwrap()
            .shape
            .candidates
            .push(FactCandidate {
                id: CandidateId::new("candidate:dynamic:type").unwrap(),
                value: SchemaShape::String { format: None },
                evidence: vec![dynamic_entity],
            });
        let report =
            fuse_document(&document, &FusionConfig::new("run:fusion").unwrap(), at(4)).unwrap();
        let fact = &report.document.surface.endpoints[0]
            .request_body
            .as_ref()
            .unwrap()
            .shape;
        assert_eq!(fact.candidates.len(), 3);
        assert!(
            fact.candidates
                .iter()
                .any(|candidate| matches!(candidate.value, SchemaShape::Union { .. }))
        );
        assert_eq!(fact.merges[0].relation, MergeRelation::Refinement);
    }

    #[test]
    fn durable_round_trip_preserves_fusion_records_and_provenance() {
        let (document, _, _) = fixture();
        let report =
            fuse_document(&document, &FusionConfig::new("run:fusion").unwrap(), at(4)).unwrap();
        let bytes = report.document.to_json_pretty().unwrap();
        let loaded = ApiDocument::from_json(&bytes).unwrap();
        assert_eq!(loaded, report.document);
        assert!(
            loaded
                .surface
                .provenance
                .activities
                .iter()
                .any(|activity| activity.source_type == SourceType::Fusion)
        );
    }
}
