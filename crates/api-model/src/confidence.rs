//! Durable, recomputable Phase 5.2 confidence and handoff accounting.

use std::collections::BTreeSet;

use apiaxess_diagnostics::Diagnostic;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    api::{EndpointIdentity, StaticBoundaryReason},
    error::{ModelError, ModelResult},
    fact::{FieldClass, MergeRelation},
    ids::{ActivityId, CandidateId, EntityId, RunId},
    provenance::{ProvenanceRegistry, SourceType},
};

/// Current durable schema for the Phase 5.2 confidence summary.
pub const CONFIDENCE_SCHEMA_VERSION: u32 = 1;

/// Recomputed confidence and static-to-dynamic handoff result for one model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceSummary {
    /// Schema version for this summary.
    pub schema_version: u32,
    /// Stable scoring run identifier.
    pub run_id: String,
    /// Provenance activity that computed this snapshot.
    pub computed_by: ActivityId,
    /// Time at which the snapshot was computed.
    pub computed_at: DateTime<Utc>,
    /// One transparent score for every fact visited by the scorer.
    pub facts: Vec<FactConfidence>,
    /// Resolution state for every static-pass handoff.
    pub handoffs: Vec<HandoffResolution>,
    /// Endpoint-level honest coverage picture.
    pub coverage: CoveragePicture,
    /// Actionable scoring and handoff diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Confidence for one fact, including every input needed to recompute it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactConfidence {
    /// Stable model path of the scored fact.
    pub path: String,
    /// Endpoint identity when this fact belongs to an endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<EndpointIdentity>,
    /// Semantic field class used by the model policy.
    pub field_class: FieldClass,
    /// Candidate selected by the fused fact resolution.
    pub selected_candidate: CandidateId,
    /// Recomputed scalar in the inclusive range 0..=1.
    pub score: f64,
    /// Total source-leaf samples contributing to this score.
    pub sample_count: u64,
    /// Samples attributable to static leaf evidence.
    pub static_sample_count: u64,
    /// Samples attributable to dynamic leaf evidence.
    pub dynamic_sample_count: u64,
    /// Source categories contributing to the effective assertion.
    pub sources: Vec<SourceType>,
    /// Whether the selected/effective assertion has source agreement.
    pub source_agreement: bool,
    /// Counts of the retained 5.1 merge cases.
    pub merge_counts: MergeCounts,
    /// Leaf evidence IDs used by the computation.
    pub evidence: Vec<EntityId>,
}

impl FactConfidence {
    /// Recomputes the score from this record's retained inputs.
    #[must_use]
    pub fn recompute_score(&self) -> f64 {
        let bounded_samples = u32::try_from(self.sample_count).unwrap_or(u32::MAX);
        let samples = f64::from(bounded_samples);
        let sample_strength = samples / (samples + 4.0);
        let source_strength = if self.source_agreement { 1.0 } else { 0.5 };
        let case_strength = if self.merge_counts.true_conflict > 0 {
            0.25
        } else if self.merge_counts.agreement > 0 {
            1.0
        } else if self.merge_counts.refinement > 0 {
            0.9
        } else {
            0.5
        };
        let conflict_penalty = if self.merge_counts.true_conflict == 0 {
            1.0
        } else {
            let conflicts =
                f64::from(u32::try_from(self.merge_counts.true_conflict).unwrap_or(u32::MAX));
            1.0 / (1.0 + 0.5 * conflicts)
        };
        let score = ((0.6 * sample_strength) + (0.25 * source_strength) + (0.15 * case_strength))
            * conflict_penalty;
        (score * 1_000_000.0).round() / 1_000_000.0
    }
}

/// Number of each 5.1 merge relation observed for a fact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeCounts {
    /// Silent-source gap fills.
    pub gap_fill: u64,
    /// Narrowing or concrete refinements.
    pub refinement: u64,
    /// Incompatible source assertions.
    pub true_conflict: u64,
    /// Equal source assertions.
    pub agreement: u64,
}

impl MergeCounts {
    /// Returns the count for one merge relation.
    #[must_use]
    pub const fn get(self, relation: MergeRelation) -> u64 {
        match relation {
            MergeRelation::GapFill => self.gap_fill,
            MergeRelation::Refinement => self.refinement,
            MergeRelation::TrueConflict => self.true_conflict,
            MergeRelation::Agreement => self.agreement,
        }
    }
}

/// Resolution result for one static-to-dynamic handoff marker.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffResolution {
    /// Stable static-pass handoff ID.
    pub id: String,
    /// Static location retained for human and machine routing.
    pub location: String,
    /// Machine-readable boundary reason.
    pub reason: StaticBoundaryReason,
    /// Whether dynamic evidence actually landed for this marker.
    pub resolved: bool,
    /// Matching endpoint identities, whether or not dynamic evidence landed.
    pub matched_endpoints: Vec<EndpointIdentity>,
    /// Dynamic leaf evidence that justified resolution.
    pub dynamic_evidence: Vec<EntityId>,
}

/// Honest endpoint coverage computed from static and dynamic leaf evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoveragePicture {
    /// Number of canonical endpoint identities in the fused surface.
    pub endpoint_count: u64,
    /// Endpoints with both static and dynamic evidence.
    pub confirmed_endpoint_count: u64,
    /// Endpoints with dynamic evidence but no static evidence.
    pub inferred_endpoint_count: u64,
    /// Endpoints with static evidence but no dynamic evidence.
    pub static_only_endpoint_count: u64,
    /// Endpoints with any dynamic ground-truth evidence.
    pub dynamic_ground_truth_endpoint_count: u64,
    /// Confirmed endpoints as basis points of the surface.
    pub confirmed_basis_points: u16,
    /// Dynamic-only inferred endpoints as basis points of the surface.
    pub inferred_basis_points: u16,
    /// Static-only endpoints as basis points of the surface.
    pub static_only_basis_points: u16,
    /// Number of static handoffs.
    pub handoff_count: u64,
    /// Handoffs resolved by dynamic evidence.
    pub resolved_handoff_count: u64,
    /// Handoffs still open after scoring.
    pub open_handoff_count: u64,
    /// Facts below the configured review threshold.
    pub low_confidence_fact_count: u64,
    /// Facts with at least one true conflict.
    pub true_conflict_fact_count: u64,
}

impl ConfidenceSummary {
    /// Validates the durable summary and all provenance references it carries.
    ///
    /// # Errors
    ///
    /// Returns the first malformed summary or missing provenance reference.
    // This cross-record validator is intentionally kept together so every
    // invariant is checked against the same durable summary.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self, provenance: &ProvenanceRegistry) -> ModelResult<()> {
        if self.schema_version != CONFIDENCE_SCHEMA_VERSION {
            return Err(ModelError::UnsupportedFormat {
                found: self.schema_version,
                expected: CONFIDENCE_SCHEMA_VERSION,
            });
        }
        RunId::new(self.run_id.clone())
            .map_err(|error| ModelError::invariant("confidence.run_id", error.to_string()))?;
        let activity = provenance.activity(&self.computed_by).ok_or_else(|| {
            ModelError::invariant(
                "confidence.computed_by",
                "computing activity is not registered",
            )
        })?;
        if activity.source_type != SourceType::Fusion {
            return Err(ModelError::invariant(
                "confidence.computed_by",
                "confidence must be recorded by a fusion activity",
            ));
        }
        if self.computed_at < activity.started_at
            || activity
                .ended_at
                .is_some_and(|ended| self.computed_at > ended)
        {
            return Err(ModelError::invariant(
                "confidence.computed_at",
                "timestamp must fall within the computing activity",
            ));
        }

        let mut fact_paths = BTreeSet::new();
        for (index, fact) in self.facts.iter().enumerate() {
            let path = format!("confidence.facts[{index}]");
            if fact.path.trim().is_empty() || !fact_paths.insert(&fact.path) {
                return Err(ModelError::invariant(
                    format!("{path}.path"),
                    "fact paths must be non-empty and unique",
                ));
            }
            if !fact.score.is_finite() || !(0.0..=1.0).contains(&fact.score) {
                return Err(ModelError::invariant(
                    format!("{path}.score"),
                    "confidence score must be finite and between zero and one",
                ));
            }
            if (fact.score - fact.recompute_score()).abs() > 0.000_001 {
                return Err(ModelError::invariant(
                    format!("{path}.score"),
                    "confidence score does not match its retained inputs",
                ));
            }
            if fact.sample_count
                != fact
                    .static_sample_count
                    .saturating_add(fact.dynamic_sample_count)
            {
                return Err(ModelError::invariant(
                    format!("{path}.sample_count"),
                    "sample count must equal static plus dynamic sample counts",
                ));
            }
            if fact.sources.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(ModelError::invariant(
                    format!("{path}.sources"),
                    "source categories must be sorted and unique",
                ));
            }
            if fact.evidence.is_empty() {
                return Err(ModelError::invariant(
                    format!("{path}.evidence"),
                    "confidence must retain at least one leaf evidence ID",
                ));
            }
            let mut evidence = BTreeSet::new();
            let mut static_samples = 0_u64;
            let mut dynamic_samples = 0_u64;
            for id in &fact.evidence {
                let Some(entity) = provenance.entity(id) else {
                    return Err(ModelError::invariant(
                        format!("{path}.evidence"),
                        "evidence IDs must be registered and unique",
                    ));
                };
                if !evidence.insert(id) {
                    return Err(ModelError::invariant(
                        format!("{path}.evidence"),
                        "evidence IDs must be registered and unique",
                    ));
                }
                match entity.source_type {
                    SourceType::StaticAnalysis => {
                        static_samples = static_samples.saturating_add(entity.sample_count.get());
                    }
                    SourceType::DynamicCapture => {
                        dynamic_samples = dynamic_samples.saturating_add(entity.sample_count.get());
                    }
                    SourceType::Fusion => {}
                }
            }
            if static_samples != fact.static_sample_count
                || dynamic_samples != fact.dynamic_sample_count
            {
                return Err(ModelError::invariant(
                    format!("{path}.sample_count"),
                    "source sample counts do not match retained provenance leaves",
                ));
            }
        }

        let mut handoff_ids = BTreeSet::new();
        let mut resolved = 0_u64;
        for (index, handoff) in self.handoffs.iter().enumerate() {
            let path = format!("confidence.handoffs[{index}]");
            if handoff.id.trim().is_empty() || !handoff_ids.insert(&handoff.id) {
                return Err(ModelError::invariant(
                    format!("{path}.id"),
                    "handoff IDs must be non-empty and unique",
                ));
            }
            if handoff.location.trim().is_empty() {
                return Err(ModelError::invariant(
                    format!("{path}.location"),
                    "handoff location must be non-empty",
                ));
            }
            if handoff
                .matched_endpoints
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(ModelError::invariant(
                    format!("{path}.matched_endpoints"),
                    "matched endpoints must be sorted and unique",
                ));
            }
            for id in &handoff.dynamic_evidence {
                let Some(entity) = provenance.entity(id) else {
                    return Err(ModelError::invariant(
                        format!("{path}.dynamic_evidence"),
                        "dynamic handoff evidence must be registered",
                    ));
                };
                if entity.source_type != SourceType::DynamicCapture {
                    return Err(ModelError::invariant(
                        format!("{path}.dynamic_evidence"),
                        "handoff evidence must come from dynamic capture",
                    ));
                }
            }
            if handoff.resolved {
                if handoff.dynamic_evidence.is_empty() {
                    return Err(ModelError::invariant(
                        format!("{path}.dynamic_evidence"),
                        "a resolved handoff must have dynamic evidence",
                    ));
                }
                resolved = resolved.saturating_add(1);
            }
        }
        let open = u64::try_from(self.handoffs.len())
            .unwrap_or(u64::MAX)
            .saturating_sub(resolved);
        if self.coverage.handoff_count != self.handoffs.len() as u64
            || self.coverage.resolved_handoff_count != resolved
            || self.coverage.open_handoff_count != open
        {
            return Err(ModelError::invariant(
                "confidence.coverage.handoffs",
                "handoff coverage counts do not match handoff records",
            ));
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            diagnostic.validate().map_err(|error| {
                ModelError::invariant(
                    format!("confidence.diagnostics[{index}]"),
                    error.to_string(),
                )
            })?;
        }
        validate_coverage(&self.coverage)
    }
}

fn validate_coverage(coverage: &CoveragePicture) -> ModelResult<()> {
    let endpoint_total = coverage
        .confirmed_endpoint_count
        .saturating_add(coverage.inferred_endpoint_count)
        .saturating_add(coverage.static_only_endpoint_count);
    if endpoint_total != coverage.endpoint_count
        || coverage.dynamic_ground_truth_endpoint_count
            != coverage
                .confirmed_endpoint_count
                .saturating_add(coverage.inferred_endpoint_count)
    {
        return Err(ModelError::invariant(
            "confidence.coverage.endpoint_counts",
            "endpoint coverage counts do not partition the surface",
        ));
    }
    if coverage.confirmed_basis_points > 10_000
        || coverage.inferred_basis_points > 10_000
        || coverage.static_only_basis_points > 10_000
    {
        return Err(ModelError::invariant(
            "confidence.coverage.basis_points",
            "coverage basis points must be between zero and 10000",
        ));
    }
    Ok(())
}
