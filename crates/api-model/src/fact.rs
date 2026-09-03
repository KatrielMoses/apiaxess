//! Evidence-preserving candidate facts, merge classifications, and confidence.

use std::collections::{BTreeSet, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ModelError, ModelResult},
    ids::{ActivityId, CandidateId, EntityId},
    provenance::{ProvenanceRegistry, SourceType},
};

/// Semantic class controlling which resolution policy is legal for a fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldClass {
    /// Authentication mechanism or applicability.
    Authentication,
    /// Schema or scalar type shape.
    TypeShape,
    /// Endpoint or parameter existence.
    Presence,
    /// Declared or inferred route template.
    PathTemplate,
    /// Requiredness based on declarations or sample tallies.
    Requiredness,
    /// A field with an explicitly named local policy.
    Scalar,
}

/// Per-field resolution policy. No global winner or time ordering exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPolicy {
    /// Dynamic evidence is authoritative when any exists.
    DynamicAuthoritative,
    /// Select a union/widened candidate across observed types.
    UnionOrWiden,
    /// Static evidence establishes completeness; dynamic evidence confirms only.
    StaticCompleteDynamicConfirm,
    /// Declared route tables precede inferred fallback templates.
    DeclaredBeforeInferred,
    /// Requiredness is evaluated against an explicit sample threshold.
    SampleGated,
    /// Named/manual choice for fields without a universal policy.
    Explicit,
}

impl ResolutionPolicy {
    fn supports(self, field_class: FieldClass) -> bool {
        matches!(
            (field_class, self),
            (FieldClass::Authentication, Self::DynamicAuthoritative)
                | (FieldClass::TypeShape, Self::UnionOrWiden)
                | (FieldClass::Presence, Self::StaticCompleteDynamicConfirm)
                | (FieldClass::PathTemplate, Self::DeclaredBeforeInferred)
                | (FieldClass::Requiredness, Self::SampleGated)
                | (FieldClass::Scalar, Self::Explicit)
        )
    }
}

/// One retained candidate value and the evidence entities supporting it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"), deny_unknown_fields)]
pub struct FactCandidate<T> {
    /// Stable candidate ID used by merge and resolution records.
    pub id: CandidateId,
    /// Candidate value.
    pub value: T,
    /// One or more direct or derived provenance entities supporting the value.
    pub evidence: Vec<EntityId>,
}

/// Current selection for a multi-candidate fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    /// Selected candidate; alternatives remain retained.
    pub selected: CandidateId,
    /// Per-field policy used for the selection.
    pub policy: ResolutionPolicy,
    /// Activity that made or reaffirmed this selection.
    pub resolved_by: ActivityId,
    /// Time at which the selection was made.
    pub resolved_at: DateTime<Utc>,
}

/// Semantic relationship between assertions during fusion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRelation {
    /// One source is silent and the other supplies an assertion.
    GapFill,
    /// A source supplies a narrower or more concrete value.
    Refinement,
    /// Sources assert incompatible values.
    TrueConflict,
    /// Sources support the same candidate value.
    Agreement,
}

/// One side of a merge, including explicit source silence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeInput {
    /// Source being compared.
    pub source_type: SourceType,
    /// Candidate supplied by that source, or `None` for silence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<CandidateId>,
}

/// Durable record of how two source statements were classified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeRecord {
    /// First source/operand.
    pub left: MergeInput,
    /// Second source/operand.
    pub right: MergeInput,
    /// Gap-fill, refinement, true conflict, or agreement.
    pub relation: MergeRelation,
    /// Candidate selected or derived from this merge.
    pub result: CandidateId,
    /// Fusion activity that recorded the classification.
    pub recorded_by: ActivityId,
    /// Classification time.
    pub recorded_at: DateTime<Utc>,
}

/// A fact retaining every candidate, merge classification, and current policy pick.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"), deny_unknown_fields)]
pub struct Fact<T> {
    /// Policy class for this field.
    pub field_class: FieldClass,
    /// Static recoverability expectation supplied by the responsible extractor.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_recoverability_basis_points: Option<u16>,
    /// All retained candidate values.
    pub candidates: Vec<FactCandidate<T>>,
    /// Current selected candidate.
    pub resolution: Resolution,
    /// Append-only semantic merge history.
    pub merges: Vec<MergeRecord>,
}

impl<T> Fact<T> {
    /// Returns the currently selected candidate.
    #[must_use]
    pub fn selected_candidate(&self) -> Option<&FactCandidate<T>> {
        self.candidates
            .iter()
            .find(|candidate| candidate.id == self.resolution.selected)
    }

    /// Recomputes transparent scalar confidence and returns its inputs.
    ///
    /// The scalar is intentionally not serializable. Retained evidence is the
    /// durable truth and permits a future calibrated policy to replace this one.
    ///
    /// # Errors
    ///
    /// Fails if the selected candidate or any provenance reference is invalid.
    pub fn confidence(&self, provenance: &ProvenanceRegistry) -> ModelResult<ConfidenceAssessment> {
        let selected = self.selected_candidate().ok_or_else(|| {
            ModelError::invariant("fact.resolution.selected", "selected candidate is missing")
        })?;
        let mut roots = selected.evidence.clone();
        for merge in &self.merges {
            let selected_in_merge = merge.result == selected.id
                || merge.left.candidate.as_ref() == Some(&selected.id)
                || merge.right.candidate.as_ref() == Some(&selected.id);
            if selected_in_merge
                && matches!(
                    merge.relation,
                    MergeRelation::Agreement
                        | MergeRelation::Refinement
                        | MergeRelation::TrueConflict
                )
            {
                for candidate_id in [
                    merge.left.candidate.as_ref(),
                    merge.right.candidate.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    if let Some(candidate) = self
                        .candidates
                        .iter()
                        .find(|candidate| &candidate.id == candidate_id)
                    {
                        roots.extend(candidate.evidence.iter().cloned());
                    }
                }
            }
        }
        roots.sort();
        roots.dedup();
        let leaves = provenance.leaf_entities(&roots)?;
        let sample_count = leaves.iter().try_fold(0_u64, |total, entity| {
            total
                .checked_add(entity.sample_count.get())
                .ok_or_else(|| ModelError::invariant("fact.confidence", "sample count overflow"))
        })?;
        let sources: BTreeSet<_> = leaves
            .iter()
            .filter_map(|entity| match entity.source_type {
                SourceType::StaticAnalysis | SourceType::DynamicCapture => Some(entity.source_type),
                SourceType::Fusion => None,
            })
            .collect();
        let true_conflict_count = self
            .merges
            .iter()
            .filter(|record| record.relation == MergeRelation::TrueConflict)
            .count();

        let bounded_samples = u32::try_from(sample_count).unwrap_or(u32::MAX);
        let sample_strength = f64::from(bounded_samples) / (f64::from(bounded_samples) + 4.0);
        let source_agreement = sources.contains(&SourceType::StaticAnalysis)
            && sources.contains(&SourceType::DynamicCapture);
        let source_agreement = source_agreement
            && self.merges.iter().any(|merge| {
                matches!(
                    merge.relation,
                    MergeRelation::Agreement | MergeRelation::Refinement
                )
            })
            && true_conflict_count == 0;
        let source_strength = if source_agreement { 1.0 } else { 0.5 };
        let case_strength = if true_conflict_count > 0 {
            0.25
        } else if self
            .merges
            .iter()
            .any(|merge| merge.relation == MergeRelation::Agreement)
        {
            1.0
        } else if self
            .merges
            .iter()
            .any(|merge| merge.relation == MergeRelation::Refinement)
        {
            0.9
        } else {
            0.5
        };
        let conflict_penalty = if true_conflict_count == 0 {
            1.0
        } else {
            let conflicts = f64::from(u32::try_from(true_conflict_count).unwrap_or(u32::MAX));
            1.0 / (1.0 + 0.5 * conflicts)
        };
        let score = ((0.6 * sample_strength) + (0.25 * source_strength) + (0.15 * case_strength))
            * conflict_penalty;
        let score = (score * 1_000_000.0).round() / 1_000_000.0;

        Ok(ConfidenceAssessment {
            score,
            sample_count,
            source_agreement,
            true_conflict_count,
        })
    }

    pub(crate) fn validate(
        &self,
        provenance: &ProvenanceRegistry,
        path: &str,
        known_entity_ids: Option<&BTreeSet<&EntityId>>,
    ) -> ModelResult<()> {
        if self
            .expected_recoverability_basis_points
            .is_some_and(|basis_points| basis_points > 10_000)
        {
            return Err(ModelError::invariant(
                format!("{path}.expected_recoverability_basis_points"),
                "recoverability basis points must be between 0 and 10000",
            ));
        }
        if self.candidates.is_empty() {
            return Err(ModelError::invariant(
                format!("{path}.candidates"),
                "a fact must retain at least one candidate",
            ));
        }
        if !self.resolution.policy.supports(self.field_class) {
            return Err(ModelError::invariant(
                format!("{path}.resolution.policy"),
                format!(
                    "policy {:?} is not valid for field class {:?}",
                    self.resolution.policy, self.field_class
                ),
            ));
        }
        provenance.validate_activity_time(
            &self.resolution.resolved_by,
            self.resolution.resolved_at,
            &format!("{path}.resolution"),
        )?;

        let mut candidate_ids = HashSet::new();
        for (index, candidate) in self.candidates.iter().enumerate() {
            if !candidate_ids.insert(&candidate.id) {
                return Err(ModelError::invariant(
                    format!("{path}.candidates[{index}].id"),
                    "candidate IDs must be unique within a fact",
                ));
            }
            if candidate.evidence.is_empty() {
                return Err(ModelError::invariant(
                    format!("{path}.candidates[{index}].evidence"),
                    "every candidate must reference provenance evidence",
                ));
            }
            if candidate.evidence.iter().collect::<HashSet<_>>().len() != candidate.evidence.len() {
                return Err(ModelError::invariant(
                    format!("{path}.candidates[{index}].evidence"),
                    "candidate evidence references must be unique",
                ));
            }
            for evidence in &candidate.evidence {
                let registered = known_entity_ids.map_or_else(
                    || provenance.entity(evidence).is_some(),
                    |entity_ids| entity_ids.contains(evidence),
                );
                if !registered {
                    return Err(ModelError::invariant(
                        format!("{path}.candidates[{index}].evidence"),
                        format!("entity `{evidence}` is not registered"),
                    ));
                }
            }
        }
        if !candidate_ids.contains(&self.resolution.selected) {
            return Err(ModelError::invariant(
                format!("{path}.resolution.selected"),
                "selected candidate is not retained by the fact",
            ));
        }

        for (index, merge) in self.merges.iter().enumerate() {
            validate_merge(
                merge,
                &candidate_ids,
                provenance,
                &format!("{path}.merges[{index}]"),
            )?;
        }

        if self.field_class == FieldClass::Authentication
            && self.resolution.policy == ResolutionPolicy::DynamicAuthoritative
        {
            let any_dynamic = self.candidates.iter().try_fold(false, |found, candidate| {
                candidate_has_source(candidate, provenance, SourceType::DynamicCapture)
                    .map(|candidate_dynamic| found || candidate_dynamic)
            })?;
            let selected = self
                .selected_candidate()
                .expect("selected candidate was validated");
            if any_dynamic
                && !candidate_has_source(selected, provenance, SourceType::DynamicCapture)?
            {
                return Err(ModelError::invariant(
                    format!("{path}.resolution.selected"),
                    "authentication must select dynamic-supported evidence when it exists",
                ));
            }
        }
        Ok(())
    }
}

/// Derived confidence plus the retained inputs used to compute it.
#[derive(Clone, Debug, PartialEq)]
pub struct ConfidenceAssessment {
    /// Provisional scalar in the inclusive range 0..=1.
    pub score: f64,
    /// Total non-duplicated leaf observations.
    pub sample_count: u64,
    /// Whether both static and dynamic evidence support the selected candidate.
    pub source_agreement: bool,
    /// Number of explicitly recorded true conflicts on this fact.
    pub true_conflict_count: usize,
}

fn candidate_has_source<T>(
    candidate: &FactCandidate<T>,
    provenance: &ProvenanceRegistry,
    source_type: SourceType,
) -> ModelResult<bool> {
    Ok(provenance
        .leaf_entities(&candidate.evidence)?
        .iter()
        .any(|entity| entity.source_type == source_type))
}

fn validate_merge(
    merge: &MergeRecord,
    candidate_ids: &HashSet<&CandidateId>,
    provenance: &ProvenanceRegistry,
    path: &str,
) -> ModelResult<()> {
    let present_count =
        usize::from(merge.left.candidate.is_some()) + usize::from(merge.right.candidate.is_some());
    match merge.relation {
        MergeRelation::GapFill if present_count != 1 => {
            return Err(ModelError::invariant(
                path,
                "gap-fill must contain exactly one assertion and one silent source",
            ));
        }
        MergeRelation::Refinement | MergeRelation::TrueConflict | MergeRelation::Agreement
            if present_count != 2 =>
        {
            return Err(ModelError::invariant(
                path,
                "refinement, conflict, and agreement require two assertions",
            ));
        }
        _ => {}
    }
    for candidate in [
        merge.left.candidate.as_ref(),
        merge.right.candidate.as_ref(),
        Some(&merge.result),
    ]
    .into_iter()
    .flatten()
    {
        if !candidate_ids.contains(candidate) {
            return Err(ModelError::invariant(
                path,
                format!("merge references unknown candidate `{candidate}`"),
            ));
        }
    }
    provenance.validate_activity_time(&merge.recorded_by, merge.recorded_at, path)
}
