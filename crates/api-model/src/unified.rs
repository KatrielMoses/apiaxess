//! Durable Phase 5.3 unified API surface.
//!
//! This is a self-contained, evidence-preserving view over the fused API
//! surface. It keeps the original model intact while adding the confidence
//! records and explicit signer bindings that Phase 6 consumes.

use std::collections::BTreeSet;

use apiaxess_diagnostics::Diagnostic;
use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};

use crate::{
    ApiSurface, ConfidenceSummary, Endpoint, EndpointIdentity, FactConfidence, ModelError,
    ModelResult, RunId, SignerArtifact, SignerMode,
};

/// Current durable schema for the Phase 5.3 unified surface.
pub const UNIFIED_SURFACE_SCHEMA_VERSION: u32 = 1;

/// One signer attachment target.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SignerTarget {
    /// The signer authenticates the API as a whole.
    ApiWide,
    /// The signer authenticates one canonical endpoint.
    Endpoint {
        /// Endpoint identity authenticated by this signer.
        identity: EndpointIdentity,
    },
}

/// Explicit relationship between a signer artifact and the API it protects.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerBinding {
    /// Signer artifact identifier.
    pub signer_id: String,
    /// API-wide or endpoint-specific scope.
    pub target: SignerTarget,
    /// Authentication fact path, when the binding can be linked precisely.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_fact_path: Option<String>,
}

/// Complete confidence-scored view of one endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnifiedEndpoint {
    /// Full fused endpoint facts: method, path, parameters, schemas, and auth.
    pub endpoint: Endpoint,
    /// All recomputed confidence records belonging to this endpoint.
    pub fact_confidence: Vec<FactConfidence>,
    /// Signers attached to this endpoint.
    pub signers: Vec<String>,
    /// Whether the endpoint's host is the app's own backend or a third party,
    /// when both its host and the app's own host(s) are known.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<HostParty>,
}

/// First- or third-party relation of a host to the analyzed app.
///
/// Structural, not an allowlist: first-party means the host belongs to the
/// app's own backend domain(s); every other host is third-party.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostParty {
    /// The app's own backend.
    FirstParty,
    /// Any host outside the app's own backend domain(s).
    ThirdParty,
}

/// The single durable Phase 5.3 deliverable consumed by Phase 6.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnifiedApiSurface {
    /// Unified surface schema version.
    pub schema_version: u32,
    /// Stable Phase 5.3 assembly run identifier.
    pub assembly_run_id: String,
    /// Time at which this durable projection was assembled.
    pub assembled_at: DateTime<Utc>,
    /// Complete fused API model, including all retained candidates/provenance.
    pub surface: ApiSurface,
    /// Recomputed confidence, handoff resolution, and coverage.
    pub confidence: ConfidenceSummary,
    /// Endpoint-centric projection for generators and review tooling.
    pub endpoints: Vec<UnifiedEndpoint>,
    /// Explicit API-wide and endpoint-specific signer attachments.
    pub signer_bindings: Vec<SignerBinding>,
    /// Phase 5.3 assembly and inherited actionable diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl UnifiedApiSurface {
    /// Returns a signer artifact by stable ID.
    #[must_use]
    pub fn signer(&self, signer_id: &str) -> Option<&SignerArtifact> {
        self.surface
            .signers
            .iter()
            .find(|signer| signer.signer_id == signer_id)
    }

    /// Returns endpoint-specific and API-wide signers for one identity.
    #[must_use]
    pub fn signers_for(&self, identity: &EndpointIdentity) -> Vec<&SignerArtifact> {
        self.signer_bindings
            .iter()
            .filter_map(|binding| match &binding.target {
                SignerTarget::Endpoint { identity: target } if target == identity => {
                    self.signer(&binding.signer_id)
                }
                SignerTarget::ApiWide => self.signer(&binding.signer_id),
                SignerTarget::Endpoint { .. } => None,
            })
            .collect()
    }

    /// Validates the complete durable surface and all cross-links.
    ///
    /// # Errors
    ///
    /// Returns an error when a durable value or one of its cross-links is
    /// malformed.
    ///
    /// # Panics
    ///
    /// This validator relies on an internal identity lookup established by
    /// the preceding cross-link check.
    // Cross-link validation is intentionally kept in one pass so the durable
    // surface cannot be observed between dependent invariant checks.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> ModelResult<()> {
        if self.schema_version != UNIFIED_SURFACE_SCHEMA_VERSION {
            return Err(ModelError::UnsupportedFormat {
                found: self.schema_version,
                expected: UNIFIED_SURFACE_SCHEMA_VERSION,
            });
        }
        self.surface.validate_for_unified()?;
        self.confidence.validate(&self.surface.provenance)?;
        RunId::new(self.assembly_run_id.clone())
            .map_err(|error| ModelError::invariant("assembly_run_id", error.to_string()))?;

        let identities = self
            .surface
            .endpoints
            .iter()
            .map(|endpoint| endpoint.identity.clone())
            .collect::<BTreeSet<_>>();
        let mut view_identities = BTreeSet::new();
        for (index, view) in self.endpoints.iter().enumerate() {
            if !identities.contains(&view.endpoint.identity)
                || !view_identities.insert(view.endpoint.identity.clone())
            {
                return Err(ModelError::invariant(
                    format!("endpoints[{index}].endpoint.identity"),
                    "unified endpoint views must match unique fused endpoints",
                ));
            }
            let source_endpoint = self
                .surface
                .endpoints
                .iter()
                .find(|endpoint| endpoint.identity == view.endpoint.identity)
                .expect("identity was checked above");
            if source_endpoint != &view.endpoint {
                return Err(ModelError::invariant(
                    format!("endpoints[{index}].endpoint"),
                    "unified endpoint view must preserve the complete fused endpoint",
                ));
            }
            let expected_fact_paths = self
                .confidence
                .facts
                .iter()
                .filter(|fact| fact.endpoint.as_ref() == Some(&view.endpoint.identity))
                .map(|fact| fact.path.as_str())
                .collect::<BTreeSet<_>>();
            let actual_fact_paths = view
                .fact_confidence
                .iter()
                .map(|fact| fact.path.as_str())
                .collect::<BTreeSet<_>>();
            if expected_fact_paths != actual_fact_paths {
                return Err(ModelError::invariant(
                    format!("endpoints[{index}].fact_confidence"),
                    "endpoint confidence projection must retain every endpoint fact",
                ));
            }
            for fact in &view.fact_confidence {
                if fact.endpoint.as_ref() != Some(&view.endpoint.identity) {
                    return Err(ModelError::invariant(
                        format!("endpoints[{index}].fact_confidence"),
                        "endpoint confidence records must point to their containing endpoint",
                    ));
                }
                if !self
                    .confidence
                    .facts
                    .iter()
                    .any(|candidate| candidate == fact)
                {
                    return Err(ModelError::invariant(
                        format!("endpoints[{index}].fact_confidence"),
                        "endpoint confidence records must be retained by the summary",
                    ));
                }
            }
            for signer_id in &view.signers {
                let has_binding = self.signer_bindings.iter().any(|binding| {
                    binding.signer_id == *signer_id
                        && (binding.target
                            == (SignerTarget::Endpoint {
                                identity: view.endpoint.identity.clone(),
                            })
                            || binding.target == SignerTarget::ApiWide)
                });
                if !has_binding || self.signer(signer_id).is_none() {
                    return Err(ModelError::invariant(
                        format!("endpoints[{index}].signers"),
                        "endpoint signer references must have an artifact and binding",
                    ));
                }
            }
        }
        if view_identities != identities {
            return Err(ModelError::invariant(
                "endpoints",
                "unified endpoint views must cover the complete fused endpoint inventory",
            ));
        }

        let signer_ids = self
            .surface
            .signers
            .iter()
            .map(|signer| signer.signer_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut binding_keys = BTreeSet::new();
        for (index, binding) in self.signer_bindings.iter().enumerate() {
            if !signer_ids.contains(binding.signer_id.as_str())
                || !binding_keys.insert((binding.signer_id.as_str(), &binding.target))
            {
                return Err(ModelError::invariant(
                    format!("signer_bindings[{index}]"),
                    "signer bindings must reference existing signers and be unique",
                ));
            }
            if let SignerTarget::Endpoint { identity } = &binding.target {
                if !identities.contains(identity) {
                    return Err(ModelError::invariant(
                        format!("signer_bindings[{index}].target"),
                        "endpoint signer binding targets an unknown endpoint",
                    ));
                }
            }
            if let Some(path) = &binding.authentication_fact_path {
                if !self.confidence.facts.iter().any(|fact| {
                    fact.path == *path && fact.field_class == crate::FieldClass::Authentication
                }) {
                    return Err(ModelError::invariant(
                        format!("signer_bindings[{index}].authentication_fact_path"),
                        "authentication fact path is not retained in confidence records",
                    ));
                }
            }
        }
        if self.surface.signers.iter().any(|signer| {
            !self
                .signer_bindings
                .iter()
                .any(|binding| binding.signer_id == signer.signer_id)
        }) {
            return Err(ModelError::invariant(
                "signer_bindings",
                "every signer artifact must be attached API-wide or to an endpoint",
            ));
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            diagnostic.validate().map_err(|error| {
                ModelError::invariant(format!("diagnostics[{index}]"), error.to_string())
            })?;
        }
        Ok(())
    }

    /// Returns whether a signer is usable as clean generated signing logic.
    #[must_use]
    pub fn is_reproducible_signer(&self, signer_id: &str) -> bool {
        self.signer(signer_id)
            .is_some_and(|signer| signer.signer_mode == SignerMode::Reproducible)
    }
}

impl ApiSurface {
    fn validate_for_unified(&self) -> ModelResult<()> {
        self.validate()
    }
}
