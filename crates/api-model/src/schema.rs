//! Independent recursive schema shapes, observations, and sample-gated requiredness.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::{
    error::{ModelError, ModelResult},
    fact::{Fact, FieldClass, ResolutionPolicy},
    ids::{EntityId, ParameterName},
    provenance::ProvenanceRegistry,
};

/// Inference-friendly schema slot retaining candidates and observed samples.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaSlot {
    /// Candidate and selected/widened schema shapes.
    pub shape: Fact<SchemaShape>,
    /// Samples made available to an orchestrated inference adapter.
    pub observations: Vec<SchemaObservation>,
}

/// Retained sample payload supporting schema inference.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaObservation {
    /// Provenance entity for this observed sample or sample batch.
    pub entity: EntityId,
    /// Inline JSON or a durable artifact reference.
    pub payload: SamplePayload,
}

/// Inline or artifact-backed sample storage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "storage")]
pub enum SamplePayload {
    /// JSON value retained directly in the model.
    Inline {
        /// Exact observed JSON value.
        value: serde_json::Value,
    },
    /// Content stored as a separately managed session artifact.
    Artifact {
        /// Entity identifying the durable artifact.
        entity: EntityId,
        /// Media type of the artifact payload.
        media_type: String,
    },
}

/// Internal schema shape, deliberately independent of JSON Schema/OpenAPI.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum SchemaShape {
    /// Insufficient evidence to narrow the value.
    Unknown,
    /// JSON null.
    Null,
    /// Boolean value.
    Boolean,
    /// Integer value with an optional inferred format hint.
    Integer {
        /// Format hint such as `int32`; not an `OpenAPI` contract.
        format: Option<String>,
    },
    /// Non-integer numeric value with an optional format hint.
    Number {
        /// Format hint such as `double`.
        format: Option<String>,
    },
    /// String value with an optional semantic format hint.
    String {
        /// Format hint such as `uuid` or `date-time`.
        format: Option<String>,
    },
    /// Array whose items have their own evidence-preserving schema slot.
    Array {
        /// Candidate item shapes and observations.
        items: Box<SchemaSlot>,
    },
    /// Object with independently evidenced properties.
    Object {
        /// Property inventory.
        properties: Vec<SchemaProperty>,
        /// Whether evidence permits properties outside the inventory.
        openness: ObjectOpenness,
    },
    /// Explicit widened alternatives.
    Union {
        /// Distinct variants retained by the widening result.
        variants: Vec<SchemaShape>,
    },
}

/// Whether an inferred object is closed or may have unseen properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectOpenness {
    /// Additional properties were allowed or observed.
    Open,
    /// A trusted declaration says the property set is closed.
    Closed,
    /// Available evidence cannot decide.
    Unknown,
}

/// One object property with per-field schema and requiredness evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaProperty {
    /// Property name.
    pub name: ParameterName,
    /// Property schema candidates and observations.
    pub schema: SchemaSlot,
    /// Declared or observed requiredness evidence.
    pub requiredness: Fact<RequirednessAssertion>,
}

/// Requiredness evidence that remains evaluable under a future threshold.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "basis")]
pub enum RequirednessAssertion {
    /// Trusted static declaration.
    Declared {
        /// Whether the declaration marks the field required.
        required: bool,
    },
    /// Dynamic presence tally. It does not directly assert requiredness.
    Observed {
        /// Samples in which the field appeared.
        present_samples: u64,
        /// Total relevant samples.
        total_samples: NonZeroU64,
    },
}

/// Recomputed requiredness result under an explicit threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequirednessAssessment {
    /// Evidence establishes requiredness under the supplied policy.
    Required,
    /// Evidence establishes optionality under the supplied policy.
    Optional,
    /// Dynamic evidence has not reached the minimum sample count.
    Inconclusive,
}

impl Fact<RequirednessAssertion> {
    /// Evaluates selected requiredness evidence without storing a Boolean result.
    ///
    /// # Errors
    ///
    /// Fails when the fact has no valid selected candidate.
    pub fn assess_requiredness(
        &self,
        minimum_dynamic_samples: NonZeroU64,
    ) -> ModelResult<RequirednessAssessment> {
        let selected = self.selected_candidate().ok_or_else(|| {
            ModelError::invariant(
                "requiredness.resolution.selected",
                "selected candidate is missing",
            )
        })?;
        match selected.value {
            RequirednessAssertion::Declared { required } => Ok(if required {
                RequirednessAssessment::Required
            } else {
                RequirednessAssessment::Optional
            }),
            RequirednessAssertion::Observed {
                present_samples: _,
                total_samples,
            } if total_samples < minimum_dynamic_samples => {
                Ok(RequirednessAssessment::Inconclusive)
            }
            RequirednessAssertion::Observed {
                present_samples,
                total_samples,
            } => Ok(if present_samples == total_samples.get() {
                RequirednessAssessment::Required
            } else {
                RequirednessAssessment::Optional
            }),
        }
    }
}

impl SchemaSlot {
    pub(crate) fn validate(&self, provenance: &ProvenanceRegistry, path: &str) -> ModelResult<()> {
        if self.shape.field_class != FieldClass::TypeShape
            || self.shape.resolution.policy != ResolutionPolicy::UnionOrWiden
        {
            return Err(ModelError::invariant(
                format!("{path}.shape"),
                "schema shapes must use the type-shape field class and union/widen policy",
            ));
        }
        self.shape
            .validate(provenance, &format!("{path}.shape"), None)?;
        for (index, candidate) in self.shape.candidates.iter().enumerate() {
            candidate.value.validate(
                provenance,
                &format!("{path}.shape.candidates[{index}].value"),
            )?;
        }
        for (index, observation) in self.observations.iter().enumerate() {
            let entity = provenance.entity(&observation.entity).ok_or_else(|| {
                ModelError::invariant(
                    format!("{path}.observations[{index}].entity"),
                    "sample entity is not registered",
                )
            })?;
            if entity.kind != crate::provenance::EntityKind::ObservedSample {
                return Err(ModelError::invariant(
                    format!("{path}.observations[{index}].entity"),
                    "schema observation must reference an observed-sample entity",
                ));
            }
            if let SamplePayload::Artifact { entity, media_type } = &observation.payload {
                if provenance.entity(entity).is_none() {
                    return Err(ModelError::invariant(
                        format!("{path}.observations[{index}].payload.entity"),
                        "sample artifact entity is not registered",
                    ));
                }
                if media_type.trim().is_empty() {
                    return Err(ModelError::invariant(
                        format!("{path}.observations[{index}].payload.media_type"),
                        "artifact media type must not be blank",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl SchemaShape {
    fn validate(&self, provenance: &ProvenanceRegistry, path: &str) -> ModelResult<()> {
        match self {
            Self::Array { items } => items.validate(provenance, &format!("{path}.items")),
            Self::Object { properties, .. } => {
                let mut names = BTreeSet::new();
                for (index, property) in properties.iter().enumerate() {
                    if !names.insert(&property.name) {
                        return Err(ModelError::invariant(
                            format!("{path}.properties[{index}].name"),
                            "object property names must be unique",
                        ));
                    }
                    property
                        .schema
                        .validate(provenance, &format!("{path}.properties[{index}].schema"))?;
                    validate_requiredness(
                        &property.requiredness,
                        provenance,
                        &format!("{path}.properties[{index}].requiredness"),
                    )?;
                }
                Ok(())
            }
            Self::Union { variants } => {
                if variants.len() < 2 {
                    return Err(ModelError::invariant(
                        format!("{path}.variants"),
                        "a union must retain at least two variants",
                    ));
                }
                for (index, variant) in variants.iter().enumerate() {
                    if variants[..index].contains(variant) {
                        return Err(ModelError::invariant(
                            format!("{path}.variants[{index}]"),
                            "union variants must be distinct",
                        ));
                    }
                    variant.validate(provenance, &format!("{path}.variants[{index}]"))?;
                }
                Ok(())
            }
            Self::Unknown
            | Self::Null
            | Self::Boolean
            | Self::Integer { .. }
            | Self::Number { .. }
            | Self::String { .. } => Ok(()),
        }
    }
}

pub(crate) fn validate_requiredness(
    fact: &Fact<RequirednessAssertion>,
    provenance: &ProvenanceRegistry,
    path: &str,
) -> ModelResult<()> {
    if fact.field_class != FieldClass::Requiredness
        || fact.resolution.policy != ResolutionPolicy::SampleGated
    {
        return Err(ModelError::invariant(
            path,
            "requiredness must use the requiredness field class and sample-gated policy",
        ));
    }
    fact.validate(provenance, path, None)?;
    for (index, candidate) in fact.candidates.iter().enumerate() {
        let sources: BTreeSet<_> = provenance
            .leaf_entities(&candidate.evidence)?
            .into_iter()
            .map(|entity| entity.source_type)
            .collect();
        match candidate.value {
            RequirednessAssertion::Observed {
                present_samples,
                total_samples,
            } => {
                if present_samples > total_samples.get() {
                    return Err(ModelError::invariant(
                        format!("{path}.candidates[{index}].value"),
                        "present samples cannot exceed total samples",
                    ));
                }
                if !sources.contains(&crate::provenance::SourceType::DynamicCapture) {
                    return Err(ModelError::invariant(
                        format!("{path}.candidates[{index}].evidence"),
                        "observed requiredness must trace to dynamic evidence",
                    ));
                }
                let dynamic_samples = provenance
                    .leaf_entities(&candidate.evidence)?
                    .into_iter()
                    .filter(|entity| {
                        entity.source_type == crate::provenance::SourceType::DynamicCapture
                    })
                    .try_fold(0_u64, |total, entity| {
                        total.checked_add(entity.sample_count.get()).ok_or_else(|| {
                            ModelError::invariant(path, "dynamic sample count overflow")
                        })
                    })?;
                if dynamic_samples < total_samples.get() {
                    return Err(ModelError::invariant(
                        format!("{path}.candidates[{index}].evidence"),
                        "dynamic provenance sample count cannot be smaller than the requiredness tally",
                    ));
                }
            }
            RequirednessAssertion::Declared { .. }
                if !sources.contains(&crate::provenance::SourceType::StaticAnalysis) =>
            {
                return Err(ModelError::invariant(
                    format!("{path}.candidates[{index}].evidence"),
                    "declared requiredness must trace to static evidence",
                ));
            }
            RequirednessAssertion::Declared { .. } => {}
        }
    }
    Ok(())
}
