//! Phase 5.2: recomputable confidence, handoff resolution, and honest coverage.
//!
//! This crate consumes a validated Phase 5.1 document. It does not merge or
//! infer facts. Every score is derived from retained candidates, merge records,
//! and leaf provenance, while every static-to-dynamic handoff remains open
//! unless matching dynamic evidence is present.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

use apiaxess_api_model::{
    Activity, ActivityId, Agent, AgentId, AgentKind, ApiDocument, CONFIDENCE_SCHEMA_VERSION,
    ConfidenceSummary, CoveragePicture, DynamicCaptureSummary, Endpoint, EndpointIdentity,
    EntityId, Fact, FactConfidence, HandoffResolution, MergeCounts, MergeRelation,
    ProvenanceRegistry, RunId, SchemaShape, SchemaSlot, SourceType,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use chrono::{DateTime, Utc};

/// Configuration for one confidence and handoff recomputation.
#[derive(Clone, Debug)]
pub struct ConfidenceConfig {
    /// Stable scoring run identifier retained in provenance.
    pub run_id: String,
    /// Facts below this score receive a review diagnostic.
    pub low_confidence_threshold: f64,
    /// Optional engine version attributed to the scoring activity.
    pub engine_version: Option<String>,
}

impl ConfidenceConfig {
    /// Creates a conservative Phase 5.2 configuration.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic for an invalid run ID or threshold.
    pub fn new(run_id: impl Into<String>) -> Result<Self, Diagnostic> {
        let run_id = run_id.into();
        RunId::new(run_id.clone()).map_err(|error| {
            diagnostic(
                catalogue::CONFIDENCE_INVALID_INPUT,
                "run_id",
                &error.to_string(),
            )
        })?;
        let config = Self {
            run_id,
            low_confidence_threshold: 0.5,
            engine_version: None,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the threshold is not finite or is outside the
    /// inclusive confidence range.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        RunId::new(self.run_id.clone()).map_err(|error| {
            diagnostic(
                catalogue::CONFIDENCE_INVALID_INPUT,
                "run_id",
                &error.to_string(),
            )
        })?;
        if !self.low_confidence_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.low_confidence_threshold)
        {
            return Err(diagnostic(
                catalogue::CONFIDENCE_INVALID_INPUT,
                "low_confidence_threshold",
                "threshold must be finite and between zero and one",
            ));
        }
        Ok(())
    }
}

/// Result of one pure Phase 5.2 recomputation.
#[derive(Clone, Debug)]
pub struct ConfidenceReport {
    /// Updated document with the auditable summary attached.
    pub document: ApiDocument,
    /// Same summary attached to `document.confidence`.
    pub summary: ConfidenceSummary,
    /// Informational and actionable diagnostics emitted by scoring.
    pub diagnostics: Vec<Diagnostic>,
}

/// Recomputes confidence and resolves handoffs over an already fused model.
///
/// # Errors
///
/// Returns diagnostics when the input or resulting document violates a model
/// invariant. The input is never modified.
pub fn recompute_document(
    source: &ApiDocument,
    config: &ConfidenceConfig,
    at: DateTime<Utc>,
) -> Result<ConfidenceReport, Vec<Diagnostic>> {
    let profiling_started = Instant::now();
    profile_mark("confidence.begin", profiling_started);
    if let Err(error) = config.validate() {
        return Err(vec![error]);
    }
    if let Err(error) = source.validate() {
        return Err(vec![diagnostic(
            catalogue::CONFIDENCE_INVALID_INPUT,
            "document",
            &error.to_string(),
        )]);
    }
    profile_mark("confidence.input-validated", profiling_started);

    let mut document = source.clone();
    let (agent_id, activity_id) = ensure_activity(&mut document.surface.provenance, config, at);
    let provenance_index = document.surface.provenance.entity_index();
    let mut scorer = Scorer {
        provenance: &document.surface.provenance,
        provenance_index,
        facts: Vec::new(),
        endpoint_sources: BTreeMap::new(),
        endpoint_dynamic_evidence: BTreeMap::new(),
        diagnostics: Vec::new(),
        threshold: config.low_confidence_threshold,
    };
    score_surface(&document, &mut scorer);
    profile_mark("confidence.facts-scored", profiling_started);
    let (handoffs, resolved_handoffs, open_handoffs) = resolve_handoffs(&document, &mut scorer);
    profile_mark("confidence.handoffs-resolved", profiling_started);
    let coverage = coverage_picture(&scorer, &handoffs);
    let facts = std::mem::take(&mut scorer.facts);
    let summary = ConfidenceSummary {
        schema_version: CONFIDENCE_SCHEMA_VERSION,
        run_id: config.run_id.clone(),
        computed_by: activity_id,
        computed_at: at,
        facts,
        handoffs,
        coverage,
        diagnostics: scorer.diagnostics.clone(),
    };
    let diagnostics = summary.diagnostics.clone();
    drop(scorer);
    update_dynamic_summary(
        &mut document.dynamic_capture,
        &summary,
        resolved_handoffs,
        open_handoffs,
    );
    document.confidence = Some(summary.clone());
    if let Err(error) = document.validate() {
        return Err(vec![diagnostic(
            catalogue::CONFIDENCE_MODEL_COMMIT_FAILED,
            "document",
            &error.to_string(),
        )]);
    }
    profile_mark("confidence.output-validated", profiling_started);
    let _ = agent_id;
    Ok(ConfidenceReport {
        document,
        summary,
        diagnostics,
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

struct Scorer<'a> {
    provenance: &'a ProvenanceRegistry,
    provenance_index: BTreeMap<&'a EntityId, &'a apiaxess_api_model::Entity>,
    facts: Vec<FactConfidence>,
    endpoint_sources: BTreeMap<EndpointIdentity, u8>,
    endpoint_dynamic_evidence: BTreeMap<EndpointIdentity, Vec<EntityId>>,
    diagnostics: Vec<Diagnostic>,
    threshold: f64,
}

fn ensure_activity(
    provenance: &mut ProvenanceRegistry,
    config: &ConfidenceConfig,
    at: DateTime<Utc>,
) -> (AgentId, ActivityId) {
    let agent_id = AgentId::new("confidence.engine").expect("static confidence agent ID");
    if !provenance.agents.iter().any(|agent| agent.id == agent_id) {
        provenance.agents.push(Agent {
            id: agent_id.clone(),
            kind: AgentKind::Engine,
            name: "APIaxess confidence recomputation".to_owned(),
            version: config.engine_version.clone(),
        });
    }
    let run_id = RunId::new(config.run_id.clone()).expect("validated confidence run ID");
    let base = format!("confidence:phase-5.2:{}", config.run_id);
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
    let activity_id = ActivityId::new(value).expect("generated confidence activity ID");
    provenance.activities.push(Activity {
        id: activity_id.clone(),
        run_id,
        agent: agent_id.clone(),
        source_type: SourceType::Fusion,
        started_at: at,
        ended_at: Some(at),
    });
    (agent_id, activity_id)
}

fn score_surface(document: &ApiDocument, scorer: &mut Scorer<'_>) {
    for (index, endpoint) in document.surface.endpoints.iter().enumerate() {
        score_endpoint(endpoint, index, scorer);
    }
    for (index, operation) in document.surface.protocol_operations.iter().enumerate() {
        score_fact(
            &operation.presence,
            &format!("protocol_operations[{index}].presence"),
            None,
            scorer,
        );
        if let Some(body) = &operation.request_body {
            score_schema_slot(
                body,
                &format!("protocol_operations[{index}].request_body"),
                None,
                scorer,
            );
        }
        if let Some(body) = &operation.response_body {
            score_schema_slot(
                body,
                &format!("protocol_operations[{index}].response_body"),
                None,
                scorer,
            );
        }
    }
    for (index, finding) in document.surface.loose_findings.iter().enumerate() {
        score_fact(
            &finding.value,
            &format!("loose_findings[{index}].value"),
            None,
            scorer,
        );
    }
}

fn score_endpoint(endpoint: &Endpoint, index: usize, scorer: &mut Scorer<'_>) {
    let path = format!("endpoints[{index}]");
    let identity = Some(&endpoint.identity);
    if let Some(fact) = &endpoint.base_url {
        score_fact(fact, &format!("{path}.base_url"), identity, scorer);
    }
    score_fact(
        &endpoint.presence,
        &format!("{path}.presence"),
        identity,
        scorer,
    );
    score_fact(
        &endpoint.path_template,
        &format!("{path}.path_template"),
        identity,
        scorer,
    );
    for (parameter_index, parameter) in endpoint.query_parameters.iter().enumerate() {
        let path = format!("{path}.query_parameters[{parameter_index}]");
        score_fact(
            &parameter.presence,
            &format!("{path}.presence"),
            identity,
            scorer,
        );
        score_schema_slot(
            &parameter.schema,
            &format!("{path}.schema"),
            identity,
            scorer,
        );
        score_fact(
            &parameter.requiredness,
            &format!("{path}.requiredness"),
            identity,
            scorer,
        );
    }
    for (parameter_index, parameter) in endpoint.path_parameters.iter().enumerate() {
        let path = format!("{path}.path_parameters[{parameter_index}]");
        score_fact(
            &parameter.presence,
            &format!("{path}.presence"),
            identity,
            scorer,
        );
        score_schema_slot(
            &parameter.schema,
            &format!("{path}.schema"),
            identity,
            scorer,
        );
    }
    for (header_index, header) in endpoint.headers.iter().enumerate() {
        let path = format!("{path}.headers[{header_index}]");
        score_fact(
            &header.presence,
            &format!("{path}.presence"),
            identity,
            scorer,
        );
        score_schema_slot(&header.schema, &format!("{path}.schema"), identity, scorer);
    }
    if let Some(fact) = &endpoint.authentication {
        score_fact(fact, &format!("{path}.authentication"), identity, scorer);
    }
    if let Some(schema) = &endpoint.request_body {
        score_schema_slot(schema, &format!("{path}.request_body"), identity, scorer);
    }
    for (response_index, response) in endpoint.responses.iter().enumerate() {
        let path = format!("{path}.responses[{response_index}]");
        score_fact(
            &response.presence,
            &format!("{path}.presence"),
            identity,
            scorer,
        );
        score_schema_slot(&response.body, &format!("{path}.body"), identity, scorer);
    }
    for (signal_index, signal) in endpoint.pagination_signals.iter().enumerate() {
        score_fact(
            signal,
            &format!("{path}.pagination_signals[{signal_index}]"),
            identity,
            scorer,
        );
    }
}

fn score_schema_slot(
    slot: &SchemaSlot,
    path: &str,
    endpoint: Option<&EndpointIdentity>,
    scorer: &mut Scorer<'_>,
) {
    score_fact(&slot.shape, &format!("{path}.shape"), endpoint, scorer);
    for (index, candidate) in slot.shape.candidates.iter().enumerate() {
        score_shape(
            &candidate.value,
            &format!("{path}.candidates[{index}].value"),
            endpoint,
            scorer,
        );
    }
}

fn score_shape(
    shape: &SchemaShape,
    path: &str,
    endpoint: Option<&EndpointIdentity>,
    scorer: &mut Scorer<'_>,
) {
    match shape {
        SchemaShape::Array { items } => {
            score_schema_slot(items, &format!("{path}.items"), endpoint, scorer);
        }
        SchemaShape::Object { properties, .. } => {
            for (index, property) in properties.iter().enumerate() {
                let path = format!("{path}.properties[{index}]");
                score_schema_slot(
                    &property.schema,
                    &format!("{path}.schema"),
                    endpoint,
                    scorer,
                );
                score_fact(
                    &property.requiredness,
                    &format!("{path}.requiredness"),
                    endpoint,
                    scorer,
                );
            }
        }
        SchemaShape::Union { variants } => {
            for (index, variant) in variants.iter().enumerate() {
                score_shape(
                    variant,
                    &format!("{path}.variants[{index}]"),
                    endpoint,
                    scorer,
                );
            }
        }
        SchemaShape::Unknown
        | SchemaShape::Null
        | SchemaShape::Boolean
        | SchemaShape::Integer { .. }
        | SchemaShape::Number { .. }
        | SchemaShape::String { .. } => {}
    }
}

// Fact scoring stays in one traversal to keep the evidence-to-score mapping
// visible alongside its validation branches.
#[allow(clippy::too_many_lines)]
fn score_fact<T>(
    fact: &Fact<T>,
    path: &str,
    endpoint: Option<&EndpointIdentity>,
    scorer: &mut Scorer<'_>,
) {
    let Ok(selected) = fact
        .selected_candidate()
        .ok_or_else(|| "selected candidate is missing".to_owned())
    else {
        scorer.diagnostics.push(diagnostic(
            catalogue::CONFIDENCE_INVALID_INPUT,
            "fact",
            &format!("{path}: selected candidate is missing"),
        ));
        return;
    };
    let mut counts = MergeCounts::default();
    for merge in &fact.merges {
        match merge.relation {
            MergeRelation::GapFill => counts.gap_fill = counts.gap_fill.saturating_add(1),
            MergeRelation::Refinement => counts.refinement = counts.refinement.saturating_add(1),
            MergeRelation::TrueConflict => {
                counts.true_conflict = counts.true_conflict.saturating_add(1);
            }
            MergeRelation::Agreement => counts.agreement = counts.agreement.saturating_add(1),
        }
    }
    let mut roots = selected.evidence.clone();
    for merge in &fact.merges {
        let selected_in_merge = merge.result == selected.id
            || merge.left.candidate.as_ref() == Some(&selected.id)
            || merge.right.candidate.as_ref() == Some(&selected.id);
        if !selected_in_merge {
            continue;
        }
        if matches!(
            merge.relation,
            MergeRelation::Agreement | MergeRelation::Refinement | MergeRelation::TrueConflict
        ) {
            if let Some(id) = &merge.left.candidate {
                add_candidate_roots(&mut roots, fact, id);
            }
            if let Some(id) = &merge.right.candidate {
                add_candidate_roots(&mut roots, fact, id);
            }
        }
    }
    roots.sort();
    roots.dedup();
    let leaves = match scorer
        .provenance
        .leaf_entities_with_index(&roots, &scorer.provenance_index)
    {
        Ok(leaves) => leaves,
        Err(error) => {
            scorer.diagnostics.push(diagnostic(
                catalogue::CONFIDENCE_INVALID_INPUT,
                "provenance",
                &format!("{path}: {error}"),
            ));
            return;
        }
    };
    let evidence = leaves
        .iter()
        .map(|entity| entity.id.clone())
        .collect::<Vec<_>>();
    let mut static_sample_count = 0_u64;
    let mut dynamic_sample_count = 0_u64;
    let mut sources = BTreeSet::new();
    for entity in &leaves {
        match entity.source_type {
            SourceType::StaticAnalysis => {
                static_sample_count = static_sample_count.saturating_add(entity.sample_count.get());
                sources.insert(SourceType::StaticAnalysis);
            }
            SourceType::DynamicCapture => {
                dynamic_sample_count =
                    dynamic_sample_count.saturating_add(entity.sample_count.get());
                sources.insert(SourceType::DynamicCapture);
            }
            SourceType::Fusion => {}
        }
    }
    let source_agreement = static_sample_count > 0
        && dynamic_sample_count > 0
        && (counts.agreement > 0 || counts.refinement > 0)
        && counts.true_conflict == 0;
    let sample_count = static_sample_count.saturating_add(dynamic_sample_count);
    let mut fact_confidence = FactConfidence {
        path: path.to_owned(),
        endpoint: endpoint.cloned(),
        field_class: fact.field_class,
        selected_candidate: selected.id.clone(),
        score: 0.0,
        sample_count,
        static_sample_count,
        dynamic_sample_count,
        sources: sources.iter().copied().collect(),
        source_agreement,
        merge_counts: counts,
        evidence: evidence.clone(),
    };
    fact_confidence.score = fact_confidence.recompute_score();
    let score = fact_confidence.score;
    if score < scorer.threshold {
        scorer.diagnostics.push(fact_diagnostic(
            catalogue::CONFIDENCE_LOW_FACT,
            path,
            &fact_confidence,
        ));
    }
    if counts.true_conflict > 0 {
        scorer.diagnostics.push(fact_diagnostic(
            catalogue::CONFIDENCE_TRUE_CONFLICT,
            path,
            &fact_confidence,
        ));
    }
    if let Some(identity) = endpoint {
        let mask = scorer.endpoint_sources.entry(identity.clone()).or_default();
        if static_sample_count > 0 {
            *mask |= 1;
        }
        if dynamic_sample_count > 0 {
            *mask |= 2;
            scorer
                .endpoint_dynamic_evidence
                .entry(identity.clone())
                .or_default()
                .extend(
                    evidence
                        .iter()
                        .filter(|id| {
                            scorer.provenance.entity(id).is_some_and(|entity| {
                                entity.source_type == SourceType::DynamicCapture
                            })
                        })
                        .cloned(),
                );
        }
    }
    scorer.facts.push(fact_confidence);
}

fn add_candidate_roots<T>(
    roots: &mut Vec<EntityId>,
    fact: &Fact<T>,
    id: &apiaxess_api_model::CandidateId,
) {
    if let Some(candidate) = fact.candidates.iter().find(|candidate| &candidate.id == id) {
        roots.extend(candidate.evidence.iter().cloned());
    }
}

fn resolve_handoffs(
    document: &ApiDocument,
    scorer: &mut Scorer<'_>,
) -> (Vec<HandoffResolution>, Vec<String>, Vec<String>) {
    let Some(static_pass) = &document.static_pass else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    let mut results = Vec::new();
    let mut resolved_ids = Vec::new();
    let mut open_ids = Vec::new();
    for handoff in &static_pass.dynamic_handoffs {
        let mut matched = document
            .surface
            .endpoints
            .iter()
            .filter(|endpoint| handoff_matches(&endpoint.identity, &handoff.location))
            .map(|endpoint| endpoint.identity.clone())
            .collect::<Vec<_>>();
        matched.sort();
        matched.dedup();
        let mut dynamic_evidence = matched
            .iter()
            .flat_map(|identity| {
                scorer
                    .endpoint_dynamic_evidence
                    .get(identity)
                    .into_iter()
                    .flatten()
            })
            .cloned()
            .collect::<Vec<_>>();
        dynamic_evidence.sort();
        dynamic_evidence.dedup();
        let resolved = !dynamic_evidence.is_empty();
        let result = HandoffResolution {
            id: handoff.id.clone(),
            location: handoff.location.clone(),
            reason: handoff.reason,
            resolved,
            matched_endpoints: matched,
            dynamic_evidence,
        };
        let definition = if result.resolved {
            catalogue::CONFIDENCE_HANDOFF_RESOLVED
        } else {
            catalogue::CONFIDENCE_HANDOFF_OPEN
        };
        let mut context = DiagnosticContext::new();
        context.insert(
            "handoff_id".to_owned(),
            DiagnosticValue::String(result.id.clone()),
        );
        context.insert(
            "location".to_owned(),
            DiagnosticValue::String(result.location.clone()),
        );
        context.insert(
            "resolved".to_owned(),
            DiagnosticValue::Boolean(result.resolved),
        );
        scorer.diagnostics.push(definition.instantiate(context));
        scorer_handoff_diagnostic(&result, &mut results, &mut resolved_ids, &mut open_ids);
    }
    (results, resolved_ids, open_ids)
}

fn scorer_handoff_diagnostic(
    result: &HandoffResolution,
    results: &mut Vec<HandoffResolution>,
    resolved_ids: &mut Vec<String>,
    open_ids: &mut Vec<String>,
) {
    results.push(result.clone());
    if result.resolved {
        resolved_ids.push(result.id.clone());
    } else {
        open_ids.push(result.id.clone());
    }
}

fn handoff_matches(identity: &EndpointIdentity, location: &str) -> bool {
    let path = identity.path_template.as_str();
    let location = location.trim();
    location == path
        || location.contains(path)
        || (location.starts_with('/') && path.contains(location))
}

fn coverage_picture(scorer: &Scorer<'_>, handoffs: &[HandoffResolution]) -> CoveragePicture {
    let mut confirmed = 0_u64;
    let mut inferred = 0_u64;
    let mut static_only = 0_u64;
    for mask in scorer.endpoint_sources.values() {
        match mask {
            3 => confirmed = confirmed.saturating_add(1),
            2 => inferred = inferred.saturating_add(1),
            _ => static_only = static_only.saturating_add(1),
        }
    }
    let endpoint_count = confirmed
        .saturating_add(inferred)
        .saturating_add(static_only);
    let basis_points = |count: u64| -> u16 {
        if endpoint_count == 0 {
            0
        } else {
            u16::try_from((count.saturating_mul(10_000) / endpoint_count).min(10_000))
                .unwrap_or(10_000)
        }
    };
    let resolved = handoffs.iter().filter(|handoff| handoff.resolved).count() as u64;
    let true_conflicts = scorer
        .facts
        .iter()
        .filter(|fact| fact.merge_counts.true_conflict > 0)
        .count() as u64;
    CoveragePicture {
        endpoint_count,
        confirmed_endpoint_count: confirmed,
        inferred_endpoint_count: inferred,
        static_only_endpoint_count: static_only,
        dynamic_ground_truth_endpoint_count: confirmed.saturating_add(inferred),
        confirmed_basis_points: basis_points(confirmed),
        inferred_basis_points: basis_points(inferred),
        static_only_basis_points: basis_points(static_only),
        handoff_count: handoffs.len() as u64,
        resolved_handoff_count: resolved,
        open_handoff_count: handoffs.len() as u64 - resolved,
        low_confidence_fact_count: scorer
            .facts
            .iter()
            .filter(|fact| fact.score < scorer.threshold)
            .count() as u64,
        true_conflict_fact_count: true_conflicts,
    }
}

fn update_dynamic_summary(
    summary: &mut Option<DynamicCaptureSummary>,
    confidence: &ConfidenceSummary,
    resolved: Vec<String>,
    open: Vec<String>,
) {
    if let Some(summary) = summary {
        summary.resolved_handoffs = resolved;
        summary.open_handoffs = open;
        summary.diagnostics.extend(
            confidence
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.id.as_ref() == catalogue::CONFIDENCE_HANDOFF_RESOLVED.id
                        || diagnostic.id.as_ref() == catalogue::CONFIDENCE_HANDOFF_OPEN.id
                })
                .cloned(),
        );
    }
}

fn fact_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    path: &str,
    fact: &FactConfidence,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("path".to_owned(), DiagnosticValue::String(path.to_owned()));
    context.insert(
        "score".to_owned(),
        DiagnosticValue::String(format!("{:.6}", fact.score)),
    );
    context.insert(
        "sample_count".to_owned(),
        DiagnosticValue::Integer(i64::try_from(fact.sample_count).unwrap_or(i64::MAX)),
    );
    context.insert(
        "true_conflict_count".to_owned(),
        DiagnosticValue::Integer(
            i64::try_from(fact.merge_counts.true_conflict).unwrap_or(i64::MAX),
        ),
    );
    // Name the endpoint and the kind of fact, so a reader can act on it
    // without decoding the model path.
    if let Some(endpoint) = &fact.endpoint {
        context.insert(
            "endpoint".to_owned(),
            DiagnosticValue::String(format!(
                "{} {}{}",
                endpoint.method.as_str(),
                endpoint.host.as_deref().unwrap_or(""),
                endpoint.path_template.as_str()
            )),
        );
    }
    context.insert(
        "fact".to_owned(),
        DiagnosticValue::String(words(&format!("{:?}", fact.field_class))),
    );
    definition.instantiate(context)
}

/// `RequestSchema` → `request schema`.
fn words(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len() + 4);
    for (index, ch) in camel.chars().enumerate() {
        if ch.is_ascii_uppercase() && index > 0 {
            out.push(' ');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

fn diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    field: &str,
    detail: &str,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "field".to_owned(),
        DiagnosticValue::String(field.to_owned()),
    );
    context.insert(
        "detail".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    definition.instantiate(context)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use apiaxess_api_model::{
        ApiSurface, CandidateId, DynamicHandoff, Endpoint, FactCandidate, FieldClass, HttpMethod,
        PathTemplate, PathTemplateAssertion, PathTemplateOrigin, PresenceAssertion, Resolution,
        ResolutionPolicy, StaticBoundaryReason, StaticCoverage, StaticPassSummary,
    };
    use chrono::TimeZone;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 23, 12, 0, second)
            .single()
            .unwrap()
    }

    fn candidate<T>(id: &str, value: T, evidence: &str) -> FactCandidate<T> {
        FactCandidate {
            id: CandidateId::new(id).unwrap(),
            value,
            evidence: vec![EntityId::new(evidence).unwrap()],
        }
    }

    fn merge(
        left: Option<&str>,
        right: Option<&str>,
        relation: MergeRelation,
        result: &str,
    ) -> apiaxess_api_model::MergeRecord {
        apiaxess_api_model::MergeRecord {
            left: apiaxess_api_model::MergeInput {
                source_type: SourceType::StaticAnalysis,
                candidate: left.map(|id| CandidateId::new(id).unwrap()),
            },
            right: apiaxess_api_model::MergeInput {
                source_type: SourceType::DynamicCapture,
                candidate: right.map(|id| CandidateId::new(id).unwrap()),
            },
            relation,
            result: CandidateId::new(result).unwrap(),
            recorded_by: ActivityId::new("activity:fusion").unwrap(),
            recorded_at: at(8),
        }
    }

    fn presence(
        static_value: Option<(&str, &str)>,
        dynamic_value: Option<(&str, &str)>,
        selected: &str,
        merges: Vec<apiaxess_api_model::MergeRecord>,
    ) -> Fact<PresenceAssertion> {
        let mut candidates = Vec::new();
        if let Some((id, evidence)) = static_value {
            candidates.push(candidate(id, PresenceAssertion::Present, evidence));
        }
        if let Some((id, evidence)) = dynamic_value {
            candidates.push(candidate(id, PresenceAssertion::Present, evidence));
        }
        Fact {
            field_class: FieldClass::Presence,
            expected_recoverability_basis_points: None,
            candidates,
            resolution: Resolution {
                selected: CandidateId::new(selected).unwrap(),
                policy: ResolutionPolicy::StaticCompleteDynamicConfirm,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges,
        }
    }

    fn path_fact(
        path: &str,
        static_value: Option<(&str, &str, PathTemplateOrigin)>,
        dynamic_value: Option<(&str, &str, PathTemplateOrigin)>,
        selected: &str,
        merges: Vec<apiaxess_api_model::MergeRecord>,
    ) -> Fact<PathTemplateAssertion> {
        let template = PathTemplate::new(path).unwrap();
        let mut candidates = Vec::new();
        if let Some((id, evidence, origin)) = static_value {
            candidates.push(candidate(
                id,
                PathTemplateAssertion {
                    template: template.clone(),
                    origin,
                },
                evidence,
            ));
        }
        if let Some((id, evidence, origin)) = dynamic_value {
            candidates.push(candidate(
                id,
                PathTemplateAssertion { template, origin },
                evidence,
            ));
        }
        Fact {
            field_class: FieldClass::PathTemplate,
            expected_recoverability_basis_points: None,
            candidates,
            resolution: Resolution {
                selected: CandidateId::new(selected).unwrap(),
                policy: ResolutionPolicy::DeclaredBeforeInferred,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges,
        }
    }

    fn scalar_fact(
        static_value: Option<(&str, &str, &str)>,
        dynamic_value: Option<(&str, &str, &str)>,
        selected: &str,
        merges: Vec<apiaxess_api_model::MergeRecord>,
    ) -> Fact<String> {
        let mut candidates = Vec::new();
        if let Some((id, value, evidence)) = static_value {
            candidates.push(candidate(id, value.to_owned(), evidence));
        }
        if let Some((id, value, evidence)) = dynamic_value {
            candidates.push(candidate(id, value.to_owned(), evidence));
        }
        Fact {
            field_class: FieldClass::Scalar,
            expected_recoverability_basis_points: None,
            candidates,
            resolution: Resolution {
                selected: CandidateId::new(selected).unwrap(),
                policy: ResolutionPolicy::Explicit,
                resolved_by: ActivityId::new("activity:static").unwrap(),
                resolved_at: at(1),
            },
            merges,
        }
    }

    fn endpoint(
        path: &str,
        presence: Fact<PresenceAssertion>,
        path_template: Fact<PathTemplateAssertion>,
        base_url: Option<Fact<String>>,
    ) -> Endpoint {
        Endpoint {
            identity: EndpointIdentity {
                method: HttpMethod::new("GET").unwrap(),
                path_template: PathTemplate::new(path).unwrap(),
                host: None,
            },
            base_url,
            presence,
            path_template,
            query_parameters: vec![],
            path_parameters: vec![],
            headers: vec![],
            authentication: None,
            request_body: None,
            request_media_type: None,
            responses: vec![],
            pagination_signals: vec![],
        }
    }

    // This fixture intentionally constructs the complete confidence document.
    #[allow(clippy::too_many_lines)]
    fn fixture() -> ApiDocument {
        let static_agent = AgentId::new("agent:static").unwrap();
        let dynamic_agent = AgentId::new("agent:dynamic").unwrap();
        let static_activity = ActivityId::new("activity:static").unwrap();
        let dynamic_activity = ActivityId::new("activity:dynamic").unwrap();
        let static_run = RunId::new("run:static").unwrap();
        let dynamic_run = RunId::new("run:dynamic").unwrap();
        let provenance = ProvenanceRegistry {
            agents: vec![
                Agent {
                    id: static_agent.clone(),
                    kind: AgentKind::ExternalTool,
                    name: "static".to_owned(),
                    version: None,
                },
                Agent {
                    id: dynamic_agent.clone(),
                    kind: AgentKind::ExternalTool,
                    name: "dynamic".to_owned(),
                    version: None,
                },
            ],
            activities: vec![
                Activity {
                    id: static_activity,
                    run_id: static_run.clone(),
                    agent: static_agent,
                    source_type: SourceType::StaticAnalysis,
                    started_at: at(0),
                    ended_at: Some(at(2)),
                },
                Activity {
                    id: dynamic_activity,
                    run_id: dynamic_run.clone(),
                    agent: dynamic_agent,
                    source_type: SourceType::DynamicCapture,
                    started_at: at(3),
                    ended_at: Some(at(5)),
                },
                Activity {
                    id: ActivityId::new("activity:fusion").unwrap(),
                    run_id: RunId::new("run:fusion").unwrap(),
                    agent: AgentId::new("agent:static").unwrap(),
                    source_type: SourceType::Fusion,
                    started_at: at(7),
                    ended_at: Some(at(8)),
                },
            ],
            entities: vec![
                apiaxess_api_model::Entity {
                    id: EntityId::new("entity:static").unwrap(),
                    kind: apiaxess_api_model::EntityKind::FactEvidence,
                    source_type: SourceType::StaticAnalysis,
                    generated_by: ActivityId::new("activity:static").unwrap(),
                    attributed_to: AgentId::new("agent:static").unwrap(),
                    run_id: static_run,
                    derived_from: vec![],
                    recorded_at: at(2),
                    sample_count: NonZeroU64::new(2).unwrap(),
                },
                apiaxess_api_model::Entity {
                    id: EntityId::new("entity:dynamic").unwrap(),
                    kind: apiaxess_api_model::EntityKind::FactEvidence,
                    source_type: SourceType::DynamicCapture,
                    generated_by: ActivityId::new("activity:dynamic").unwrap(),
                    attributed_to: AgentId::new("agent:dynamic").unwrap(),
                    run_id: dynamic_run,
                    derived_from: vec![],
                    recorded_at: at(5),
                    sample_count: NonZeroU64::new(2).unwrap(),
                },
            ],
        };

        let static_presence = |id: &str| {
            presence(
                Some((id, "entity:static")),
                None,
                id,
                vec![merge(Some(id), None, MergeRelation::GapFill, id)],
            )
        };
        let static_path = |path: &str, id: &str| {
            path_fact(
                path,
                Some((id, "entity:static", PathTemplateOrigin::Declared)),
                None,
                id,
                vec![merge(Some(id), None, MergeRelation::GapFill, id)],
            )
        };
        let endpoint_agreement = endpoint(
            "/agreement",
            presence(
                Some(("candidate:agreement:static", "entity:static")),
                Some(("candidate:agreement:dynamic", "entity:dynamic")),
                "candidate:agreement:static",
                vec![merge(
                    Some("candidate:agreement:static"),
                    Some("candidate:agreement:dynamic"),
                    MergeRelation::Agreement,
                    "candidate:agreement:static",
                )],
            ),
            path_fact(
                "/agreement",
                Some((
                    "candidate:agreement:path",
                    "entity:static",
                    PathTemplateOrigin::Declared,
                )),
                None,
                "candidate:agreement:path",
                vec![merge(
                    Some("candidate:agreement:path"),
                    None,
                    MergeRelation::GapFill,
                    "candidate:agreement:path",
                )],
            ),
            None,
        );
        let endpoint_gap = endpoint(
            "/gap",
            static_presence("candidate:gap:presence"),
            static_path("/gap", "candidate:gap:path"),
            None,
        );
        let endpoint_conflict = endpoint(
            "/conflict",
            static_presence("candidate:conflict:presence"),
            static_path("/conflict", "candidate:conflict:path"),
            Some(scalar_fact(
                Some((
                    "candidate:conflict:static",
                    "https://static",
                    "entity:static",
                )),
                Some((
                    "candidate:conflict:dynamic",
                    "https://dynamic",
                    "entity:dynamic",
                )),
                "candidate:conflict:static",
                vec![merge(
                    Some("candidate:conflict:static"),
                    Some("candidate:conflict:dynamic"),
                    MergeRelation::TrueConflict,
                    "candidate:conflict:dynamic",
                )],
            )),
        );
        let endpoint_refinement = endpoint(
            "/refined",
            static_presence("candidate:refined:presence"),
            path_fact(
                "/refined",
                Some((
                    "candidate:refined:static",
                    "entity:static",
                    PathTemplateOrigin::Declared,
                )),
                Some((
                    "candidate:refined:dynamic",
                    "entity:dynamic",
                    PathTemplateOrigin::Inferred,
                )),
                "candidate:refined:static",
                vec![merge(
                    Some("candidate:refined:static"),
                    Some("candidate:refined:dynamic"),
                    MergeRelation::Refinement,
                    "candidate:refined:dynamic",
                )],
            ),
            None,
        );
        let endpoint_inferred = endpoint(
            "/runtime",
            presence(
                None,
                Some(("candidate:runtime:presence", "entity:dynamic")),
                "candidate:runtime:presence",
                vec![merge(
                    None,
                    Some("candidate:runtime:presence"),
                    MergeRelation::GapFill,
                    "candidate:runtime:presence",
                )],
            ),
            path_fact(
                "/runtime",
                None,
                Some((
                    "candidate:runtime:path",
                    "entity:dynamic",
                    PathTemplateOrigin::Inferred,
                )),
                "candidate:runtime:path",
                vec![merge(
                    None,
                    Some("candidate:runtime:path"),
                    MergeRelation::GapFill,
                    "candidate:runtime:path",
                )],
            ),
            None,
        );
        ApiDocument::new(ApiSurface {
            provenance,
            endpoints: vec![
                endpoint_agreement,
                endpoint_gap,
                endpoint_conflict,
                endpoint_refinement,
                endpoint_inferred,
            ],
            protocol_operations: vec![],
            loose_findings: vec![],
            signers: vec![],
        })
        .with_static_pass(StaticPassSummary {
            schema_version: 1,
            coverage: StaticCoverage {
                expected_basis_points: 10_000,
                covered_basis_points: 5_000,
                methodology: "fixture".to_owned(),
                libraries: vec![],
            },
            dynamic_handoffs: vec![
                DynamicHandoff {
                    id: "handoff:agreement".to_owned(),
                    library_id: Some("fixture".to_owned()),
                    location: "/agreement".to_owned(),
                    reason: StaticBoundaryReason::RuntimeAssembly,
                    detail: "dynamic recommended".to_owned(),
                    static_silence: false,
                },
                DynamicHandoff {
                    id: "handoff:missing".to_owned(),
                    library_id: Some("fixture".to_owned()),
                    location: "/not-captured".to_owned(),
                    reason: StaticBoundaryReason::NativeLogic,
                    detail: "dynamic recommended".to_owned(),
                    static_silence: false,
                },
            ],
            diagnostics: vec![],
        })
    }

    #[test]
    fn agreement_refinement_gap_and_conflict_follow_distinct_policies() {
        let report = recompute_document(
            &fixture(),
            &ConfidenceConfig::new("run:confidence").unwrap(),
            at(9),
        )
        .unwrap();
        let find = |path: &str| {
            report
                .summary
                .facts
                .iter()
                .find(|fact| fact.path == path)
                .unwrap()
        };
        let agreement = find("endpoints[0].presence");
        let gap = find("endpoints[1].presence");
        let conflict = find("endpoints[2].base_url");
        let refinement = find("endpoints[3].path_template");
        assert!(agreement.source_agreement);
        assert!(refinement.source_agreement);
        assert!(!conflict.source_agreement);
        assert_eq!(gap.merge_counts.gap_fill, 1);
        assert_eq!(refinement.merge_counts.refinement, 1);
        assert_eq!(conflict.merge_counts.true_conflict, 1);
        assert!(agreement.score > gap.score);
        assert!(agreement.score > conflict.score);
        assert!(conflict.score < 0.5);
        assert_eq!(gap.dynamic_sample_count, 0);
        assert_eq!(conflict.static_sample_count, 2);
        assert_eq!(conflict.dynamic_sample_count, 2);
    }

    #[test]
    fn handoffs_resolve_only_with_matching_dynamic_evidence_and_coverage_is_partitioned() {
        let report = recompute_document(
            &fixture(),
            &ConfidenceConfig::new("run:coverage").unwrap(),
            at(9),
        )
        .unwrap();
        let resolved = report
            .summary
            .handoffs
            .iter()
            .find(|handoff| handoff.id == "handoff:agreement")
            .unwrap();
        let open = report
            .summary
            .handoffs
            .iter()
            .find(|handoff| handoff.id == "handoff:missing")
            .unwrap();
        assert!(resolved.resolved);
        assert!(!resolved.dynamic_evidence.is_empty());
        assert!(!open.resolved);
        assert!(open.dynamic_evidence.is_empty());
        assert_eq!(report.summary.coverage.endpoint_count, 5);
        assert_eq!(report.summary.coverage.confirmed_endpoint_count, 3);
        assert_eq!(report.summary.coverage.inferred_endpoint_count, 1);
        assert_eq!(report.summary.coverage.static_only_endpoint_count, 1);
        assert_eq!(report.summary.coverage.resolved_handoff_count, 1);
        assert_eq!(report.summary.coverage.open_handoff_count, 1);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref()
                    == catalogue::CONFIDENCE_HANDOFF_RESOLVED.id)
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == catalogue::CONFIDENCE_HANDOFF_OPEN.id)
        );
    }

    #[test]
    fn confidence_summary_round_trips_with_auditable_inputs() {
        let report = recompute_document(
            &fixture(),
            &ConfidenceConfig::new("run:roundtrip").unwrap(),
            at(9),
        )
        .unwrap();
        let encoded = report.document.to_json_pretty().unwrap();
        let decoded = ApiDocument::from_json(&encoded).unwrap();
        assert_eq!(decoded.confidence, Some(report.summary));
    }
}
