//! Phase 5.3: signer integration and unified API surface assembly.
//!
//! This crate performs no capture or merging. It validates the already-fused
//! document, attaches explicitly scoped signer artifacts, and creates the
//! durable single model consumed by Phase 6.

use std::{collections::BTreeSet, time::Instant};

use apiaxess_api_model::{
    ApiDocument, ApiSurface, EndpointIdentity, FieldClass, SignerBinding, SignerMode, SignerTarget,
    UNIFIED_SURFACE_SCHEMA_VERSION, UnifiedApiSurface, UnifiedEndpoint,
};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use chrono::{DateTime, Utc};

/// Configuration for one pure Phase 5.3 assembly.
#[derive(Clone, Debug)]
pub struct UnifiedSurfaceConfig {
    /// Stable assembly run identifier.
    pub run_id: String,
    /// Emit low-coverage guidance below this confirmed-surface threshold.
    pub minimum_confirmed_basis_points: u16,
    /// Explicit API-wide or endpoint-specific signer attachments.
    pub signer_bindings: Vec<SignerBinding>,
}

impl UnifiedSurfaceConfig {
    /// Creates a configuration with a 50% confirmed-surface review threshold.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when `run_id` is not a valid run identifier.
    pub fn new(run_id: impl Into<String>) -> Result<Self, Diagnostic> {
        let run_id = run_id.into();
        if apiaxess_api_model::RunId::new(run_id.clone()).is_err() {
            return Err(simple_diagnostic(
                catalogue::SURFACE_INVALID_INPUT,
                "run_id",
                "assembly run ID is invalid",
            ));
        }
        Ok(Self {
            run_id,
            minimum_confirmed_basis_points: 5_000,
            signer_bindings: Vec::new(),
        })
    }
}

/// Result containing both the standalone unified artifact and a document with
/// that artifact durably attached.
#[derive(Clone, Debug)]
pub struct UnifiedSurfaceReport {
    /// Standalone Phase 5.3 artifact for Phase 6 consumers.
    pub unified: UnifiedApiSurface,
    /// Source document with the same artifact attached.
    pub document: ApiDocument,
    /// Diagnostics emitted while assembling the projection.
    pub diagnostics: Vec<Diagnostic>,
}

/// Assembles a confidence-scored surface from a validated Phase 5.2 document.
///
/// Signer scope is intentionally explicit: the assembler never guesses which
/// endpoint a signer protects from a string or from dynamic silence.
///
/// # Errors
///
/// Returns diagnostics when the source document is invalid or signer bindings
/// cannot be applied to the validated surface.
// This assembly remains linear so the unified artifact fields stay auditable.
#[allow(clippy::too_many_lines)]
pub fn assemble_document(
    source: &ApiDocument,
    config: &UnifiedSurfaceConfig,
    at: DateTime<Utc>,
) -> Result<UnifiedSurfaceReport, Vec<Diagnostic>> {
    let profiling_started = Instant::now();
    profile_mark("surface.begin", profiling_started);
    if let Err(error) = source.validate() {
        return Err(vec![simple_diagnostic(
            catalogue::SURFACE_INVALID_INPUT,
            "document",
            &error.to_string(),
        )]);
    }
    profile_mark("surface.input-validated", profiling_started);
    let Some(confidence) = source.confidence.clone() else {
        return Err(vec![simple_diagnostic(
            catalogue::SURFACE_INVALID_INPUT,
            "confidence",
            "Phase 5.2 confidence summary is required before unified assembly",
        )]);
    };
    let surface = source.surface.clone();
    if let Err(error) = validate_bindings(&surface, &confidence, &config.signer_bindings) {
        return Err(vec![simple_diagnostic(
            catalogue::SURFACE_INVALID_INPUT,
            "signer_bindings",
            &error,
        )]);
    }

    let mut diagnostics = confidence.diagnostics.clone();
    let api_wide_signers = config
        .signer_bindings
        .iter()
        .filter(|binding| matches!(binding.target, SignerTarget::ApiWide))
        .map(|binding| binding.signer_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut endpoints = Vec::with_capacity(surface.endpoints.len());
    for endpoint in &surface.endpoints {
        let endpoint_signers = config
            .signer_bindings
            .iter()
            .filter(|binding| {
                binding.target
                    == (SignerTarget::Endpoint {
                        identity: endpoint.identity.clone(),
                    })
            })
            .map(|binding| binding.signer_id.clone())
            .collect::<Vec<_>>();
        let mut all_signers = endpoint_signers.clone();
        all_signers.extend(api_wide_signers.iter().map(|id| (*id).to_owned()));
        all_signers.sort();
        all_signers.dedup();
        let has_signer = !all_signers.is_empty();

        let fact_confidence = confidence
            .facts
            .iter()
            .filter(|fact| fact.endpoint.as_ref() == Some(&endpoint.identity))
            .cloned()
            .collect();
        endpoints.push(UnifiedEndpoint {
            endpoint: endpoint.clone(),
            fact_confidence,
            signers: all_signers,
        });

        if endpoint.authentication.is_none() && !has_signer {
            diagnostics.push(endpoint_auth_diagnostic(&endpoint.identity));
        }
    }
    profile_mark("surface.endpoints-assembled", profiling_started);

    for binding in &config.signer_bindings {
        let Some(signer) = surface
            .signers
            .iter()
            .find(|signer| signer.signer_id == binding.signer_id)
        else {
            continue;
        };
        diagnostics.push(signer_diagnostic(signer, binding));
        if signer.signer_mode != SignerMode::Reproducible {
            diagnostics.push(signer_review_diagnostic(signer, binding));
        }
    }
    if confidence.coverage.confirmed_basis_points < config.minimum_confirmed_basis_points {
        diagnostics.push(coverage_diagnostic(&confidence));
    }

    let unified = UnifiedApiSurface {
        schema_version: UNIFIED_SURFACE_SCHEMA_VERSION,
        assembly_run_id: config.run_id.clone(),
        assembled_at: at,
        surface,
        confidence,
        endpoints,
        signer_bindings: config.signer_bindings.clone(),
        diagnostics: diagnostics.clone(),
    };
    if let Err(error) = unified.validate() {
        return Err(vec![simple_diagnostic(
            catalogue::SURFACE_INVALID_INPUT,
            "unified",
            &error.to_string(),
        )]);
    }
    profile_mark("surface.unified-validated", profiling_started);
    let document = source.clone().with_unified_surface(unified.clone());
    // `source` was validated before assembly and `unified` was validated
    // above. Attaching the already-validated projection cannot invalidate the
    // unchanged source fields, so validating the complete document here would
    // repeat every high-volume loose-finding check once more.
    profile_mark("surface.document-attached", profiling_started);
    Ok(UnifiedSurfaceReport {
        unified,
        document,
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

fn validate_bindings(
    surface: &ApiSurface,
    confidence: &apiaxess_api_model::ConfidenceSummary,
    bindings: &[SignerBinding],
) -> Result<(), String> {
    let signer_ids = surface
        .signers
        .iter()
        .map(|signer| signer.signer_id.as_str())
        .collect::<BTreeSet<_>>();
    let endpoint_ids = surface
        .endpoints
        .iter()
        .map(|endpoint| &endpoint.identity)
        .collect::<BTreeSet<_>>();
    let mut keys = BTreeSet::new();
    for binding in bindings {
        if !signer_ids.contains(binding.signer_id.as_str()) {
            return Err(format!("unknown signer `{}`", binding.signer_id));
        }
        if !keys.insert((&binding.signer_id, &binding.target)) {
            return Err(format!("duplicate binding for `{}`", binding.signer_id));
        }
        if let SignerTarget::Endpoint { identity } = &binding.target {
            if !endpoint_ids.contains(identity) {
                return Err(format!("unknown endpoint target {identity:?}"));
            }
        }
        if let Some(path) = &binding.authentication_fact_path {
            if !confidence
                .facts
                .iter()
                .any(|fact| fact.path == *path && fact.field_class == FieldClass::Authentication)
            {
                return Err(format!("unknown authentication fact path `{path}`"));
            }
        }
    }
    for signer in &surface.signers {
        if !bindings
            .iter()
            .any(|binding| binding.signer_id == signer.signer_id)
        {
            return Err(format!("signer `{}` is unattached", signer.signer_id));
        }
    }
    Ok(())
}

fn signer_diagnostic(
    signer: &apiaxess_api_model::SignerArtifact,
    binding: &SignerBinding,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "signer_id".to_owned(),
        DiagnosticValue::String(signer.signer_id.clone()),
    );
    context.insert(
        "mode".to_owned(),
        DiagnosticValue::String(format!("{:?}", signer.signer_mode).to_ascii_lowercase()),
    );
    context.insert(
        "confidence".to_owned(),
        DiagnosticValue::String(format!("{:.6}", signer.confidence)),
    );
    context.insert(
        "target".to_owned(),
        DiagnosticValue::String(format!("{:?}", binding.target)),
    );
    catalogue::SURFACE_SIGNER_ATTACHED.instantiate(context)
}

fn signer_review_diagnostic(
    signer: &apiaxess_api_model::SignerArtifact,
    binding: &SignerBinding,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "signer_id".to_owned(),
        DiagnosticValue::String(signer.signer_id.clone()),
    );
    context.insert(
        "mode".to_owned(),
        DiagnosticValue::String(format!("{:?}", signer.signer_mode).to_ascii_lowercase()),
    );
    context.insert(
        "target".to_owned(),
        DiagnosticValue::String(format!("{:?}", binding.target)),
    );
    catalogue::SURFACE_SIGNER_NEEDS_REVIEW.instantiate(context)
}

fn endpoint_auth_diagnostic(identity: &EndpointIdentity) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "method".to_owned(),
        DiagnosticValue::String(identity.method.to_string()),
    );
    context.insert(
        "path_template".to_owned(),
        DiagnosticValue::String(identity.path_template.to_string()),
    );
    catalogue::SURFACE_ENDPOINT_NO_RECOVERED_AUTH.instantiate(context)
}

fn coverage_diagnostic(confidence: &apiaxess_api_model::ConfidenceSummary) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "confirmed_basis_points".to_owned(),
        DiagnosticValue::Integer(i64::from(confidence.coverage.confirmed_basis_points)),
    );
    context.insert(
        "static_only_endpoint_count".to_owned(),
        DiagnosticValue::Integer(
            i64::try_from(confidence.coverage.static_only_endpoint_count).unwrap_or(i64::MAX),
        ),
    );
    catalogue::SURFACE_LOW_COVERAGE.instantiate(context)
}

fn simple_diagnostic(
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
    use super::*;
    use std::num::NonZeroU64;

    use apiaxess_api_model::{
        Activity, ActivityId, Agent, AgentId, AgentKind, ApiSurface, AuthenticationScheme,
        CandidateId, ConfidenceSummary, Entity, EntityId, EntityKind, Fact, FactCandidate,
        FactConfidence, FieldClass, HttpMethod, LooseFinding, LooseFindingKind, MergeCounts,
        PathTemplate, PathTemplateAssertion, PathTemplateOrigin, PresenceAssertion,
        ProvenanceRegistry, Resolution, ResolutionPolicy, SignerInterface, SignerKeySource,
        SignerProvenance, SignerScheme,
    };
    use chrono::{TimeZone, Utc};

    // This fixture intentionally spells out the complete provenance graph.
    #[allow(clippy::too_many_lines)]
    fn fixture_document() -> ApiDocument {
        let at = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
        let static_agent = AgentId::new("agent:static").unwrap();
        let dynamic_agent = AgentId::new("agent:dynamic").unwrap();
        let fusion_agent = AgentId::new("agent:fusion").unwrap();
        let static_activity = ActivityId::new("activity:static").unwrap();
        let dynamic_activity = ActivityId::new("activity:dynamic").unwrap();
        let fusion_activity = ActivityId::new("activity:fusion").unwrap();
        let static_run = apiaxess_api_model::RunId::new("run:static").unwrap();
        let dynamic_run = apiaxess_api_model::RunId::new("run:dynamic").unwrap();
        let fusion_run = apiaxess_api_model::RunId::new("run:fusion").unwrap();
        let static_entity = EntityId::new("entity:static").unwrap();
        let dynamic_entity = EntityId::new("entity:dynamic").unwrap();
        let provenance = ProvenanceRegistry {
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
                Agent {
                    id: fusion_agent.clone(),
                    kind: AgentKind::Engine,
                    name: "fusion".into(),
                    version: None,
                },
            ],
            activities: vec![
                Activity {
                    id: static_activity.clone(),
                    run_id: static_run.clone(),
                    agent: static_agent.clone(),
                    source_type: apiaxess_api_model::SourceType::StaticAnalysis,
                    started_at: at,
                    ended_at: Some(at),
                },
                Activity {
                    id: dynamic_activity.clone(),
                    run_id: dynamic_run.clone(),
                    agent: dynamic_agent.clone(),
                    source_type: apiaxess_api_model::SourceType::DynamicCapture,
                    started_at: at,
                    ended_at: Some(at),
                },
                Activity {
                    id: fusion_activity.clone(),
                    run_id: fusion_run.clone(),
                    agent: fusion_agent.clone(),
                    source_type: apiaxess_api_model::SourceType::Fusion,
                    started_at: at,
                    ended_at: Some(at),
                },
            ],
            entities: vec![
                Entity {
                    id: static_entity.clone(),
                    kind: EntityKind::FactEvidence,
                    source_type: apiaxess_api_model::SourceType::StaticAnalysis,
                    generated_by: static_activity,
                    attributed_to: AgentId::new("agent:static").unwrap(),
                    run_id: static_run,
                    derived_from: vec![],
                    recorded_at: at,
                    sample_count: NonZeroU64::new(1).unwrap(),
                },
                Entity {
                    id: dynamic_entity.clone(),
                    kind: EntityKind::FactEvidence,
                    source_type: apiaxess_api_model::SourceType::DynamicCapture,
                    generated_by: dynamic_activity,
                    attributed_to: AgentId::new("agent:dynamic").unwrap(),
                    run_id: dynamic_run,
                    derived_from: vec![],
                    recorded_at: at,
                    sample_count: NonZeroU64::new(3).unwrap(),
                },
            ],
        };
        let identity = EndpointIdentity {
            method: HttpMethod::new("GET").unwrap(),
            path_template: PathTemplate::new("/users").unwrap(),
        };
        let presence = fact(
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            dynamic_entity.clone(),
            &fusion_activity,
            at,
            "candidate:presence",
        );
        let path = fact(
            FieldClass::PathTemplate,
            ResolutionPolicy::DeclaredBeforeInferred,
            PathTemplateAssertion {
                template: identity.path_template.clone(),
                origin: PathTemplateOrigin::Declared,
            },
            static_entity.clone(),
            &fusion_activity,
            at,
            "candidate:path",
        );
        let authentication = fact(
            FieldClass::Authentication,
            ResolutionPolicy::DynamicAuthoritative,
            AuthenticationScheme::Bearer { token_format: None },
            dynamic_entity.clone(),
            &fusion_activity,
            at,
            "candidate:auth",
        );
        let surface = ApiSurface {
            provenance,
            endpoints: vec![apiaxess_api_model::Endpoint {
                identity: identity.clone(),
                base_url: None,
                presence,
                path_template: path,
                query_parameters: vec![],
                path_parameters: vec![],
                headers: vec![],
                authentication: Some(authentication),
                request_body: None,
                responses: vec![],
                pagination_signals: vec![],
            }],
            protocol_operations: vec![],
            loose_findings: vec![],
            signers: vec![
                signer("signer:reproducible", SignerMode::Reproducible),
                signer("signer:device", SignerMode::DeviceOracle),
            ],
        };
        let facts = vec![
            confidence_fact(
                "endpoints[0].presence",
                identity.clone(),
                FieldClass::Presence,
                1,
                3,
                vec![static_entity.clone(), dynamic_entity.clone()],
                true,
            ),
            confidence_fact(
                "endpoints[0].path_template",
                identity.clone(),
                FieldClass::PathTemplate,
                1,
                0,
                vec![static_entity.clone()],
                false,
            ),
            confidence_fact(
                "endpoints[0].authentication",
                identity.clone(),
                FieldClass::Authentication,
                0,
                3,
                vec![dynamic_entity.clone()],
                false,
            ),
        ];
        let confidence = ConfidenceSummary {
            schema_version: apiaxess_api_model::CONFIDENCE_SCHEMA_VERSION,
            run_id: "run:confidence".into(),
            computed_by: fusion_activity,
            computed_at: at,
            facts,
            handoffs: vec![],
            coverage: apiaxess_api_model::CoveragePicture {
                endpoint_count: 1,
                confirmed_endpoint_count: 1,
                inferred_endpoint_count: 0,
                static_only_endpoint_count: 0,
                dynamic_ground_truth_endpoint_count: 1,
                confirmed_basis_points: 10_000,
                inferred_basis_points: 0,
                static_only_basis_points: 0,
                handoff_count: 0,
                resolved_handoff_count: 0,
                open_handoff_count: 0,
                low_confidence_fact_count: 0,
                true_conflict_fact_count: 0,
            },
            diagnostics: vec![],
        };
        let mut document = ApiDocument::new(surface);
        document.confidence = Some(confidence);
        document
    }

    fn fact<T: Clone>(
        field_class: FieldClass,
        policy: ResolutionPolicy,
        value: T,
        evidence: EntityId,
        activity: &ActivityId,
        at: chrono::DateTime<Utc>,
        candidate_id: &str,
    ) -> Fact<T> {
        Fact {
            field_class,
            expected_recoverability_basis_points: None,
            candidates: vec![FactCandidate {
                id: CandidateId::new(candidate_id).unwrap(),
                value,
                evidence: vec![evidence],
            }],
            resolution: Resolution {
                selected: CandidateId::new(candidate_id).unwrap(),
                policy,
                resolved_by: activity.clone(),
                resolved_at: at,
            },
            merges: vec![],
        }
    }

    fn confidence_fact(
        path: &str,
        endpoint: EndpointIdentity,
        field_class: FieldClass,
        static_samples: u64,
        dynamic_samples: u64,
        evidence: Vec<EntityId>,
        agreement: bool,
    ) -> FactConfidence {
        let mut fact = FactConfidence {
            path: path.into(),
            endpoint: Some(endpoint),
            field_class,
            selected_candidate: CandidateId::new(format!("candidate:{path}")).unwrap(),
            score: 0.0,
            sample_count: static_samples + dynamic_samples,
            static_sample_count: static_samples,
            dynamic_sample_count: dynamic_samples,
            sources: if static_samples > 0 && dynamic_samples > 0 {
                vec![
                    apiaxess_api_model::SourceType::StaticAnalysis,
                    apiaxess_api_model::SourceType::DynamicCapture,
                ]
            } else if static_samples > 0 {
                vec![apiaxess_api_model::SourceType::StaticAnalysis]
            } else {
                vec![apiaxess_api_model::SourceType::DynamicCapture]
            },
            source_agreement: agreement,
            merge_counts: MergeCounts {
                agreement: u64::from(agreement),
                ..MergeCounts::default()
            },
            evidence,
        };
        fact.score = fact.recompute_score();
        fact
    }

    fn signer(id: &str, mode: SignerMode) -> apiaxess_api_model::SignerArtifact {
        apiaxess_api_model::SignerArtifact {
            schema_version: apiaxess_api_model::SIGNER_IR_SCHEMA_VERSION,
            signer_id: id.into(),
            scheme: SignerScheme::CustomHmac,
            signer_mode: mode,
            confidence: 0.8,
            coverage: vec![],
            canonicalization_steps: vec![],
            primitive: None,
            key_source: Some(if mode == SignerMode::DeviceOracle {
                SignerKeySource::DeviceOracle {
                    callback_id: "callback:device".into(),
                    reason: "hardware-backed".into(),
                }
            } else {
                SignerKeySource::CredentialReference {
                    secret_ref: "credential://test".into(),
                    provider: None,
                }
            }),
            output: None,
            runtime: apiaxess_api_model::SignerRuntime::default(),
            fixtures: vec![],
            ranked_alternatives: vec![],
            interface: SignerInterface::default(),
            reproduction: if mode == SignerMode::DeviceOracle {
                "requires original runtime".into()
            } else {
                "pure signer".into()
            },
            provenance: vec![SignerProvenance {
                source_type: apiaxess_api_model::SourceType::DynamicCapture,
                evidence_ids: vec!["capture:test".into()],
                detail: "fixture".into(),
            }],
        }
    }

    #[test]
    fn assembles_scored_endpoints_and_preserves_signer_modes() {
        let document = fixture_document();
        let mut config = UnifiedSurfaceConfig::new("run:phase-5-3").unwrap();
        let identity = document.surface.endpoints[0].identity.clone();
        config.signer_bindings = vec![
            SignerBinding {
                signer_id: "signer:reproducible".to_owned(),
                target: SignerTarget::Endpoint {
                    identity: identity.clone(),
                },
                authentication_fact_path: Some("endpoints[0].authentication".to_owned()),
            },
            SignerBinding {
                signer_id: "signer:device".to_owned(),
                target: SignerTarget::ApiWide,
                authentication_fact_path: None,
            },
        ];
        let report = assemble_document(&document, &config, chrono::Utc::now()).unwrap();
        assert_eq!(report.unified.endpoints.len(), 1);
        assert_eq!(report.unified.endpoints[0].signers.len(), 2);
        assert_eq!(report.unified.signers_for(&identity).len(), 2);
        assert!(report.unified.is_reproducible_signer("signer:reproducible"));
        assert!(!report.unified.is_reproducible_signer("signer:device"));
        assert_eq!(
            report.document.unified_surface,
            Some(report.unified.clone())
        );
        let bytes = report.document.to_json_pretty().unwrap();
        let loaded = ApiDocument::from_json(&bytes).unwrap();
        assert_eq!(loaded.unified_surface, report.document.unified_surface);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref()
                    == catalogue::SURFACE_SIGNER_NEEDS_REVIEW.id)
        );
    }

    #[test]
    fn unbound_signer_is_rejected_instead_of_being_presented_as_api_auth() {
        let document = fixture_document();
        let config = UnifiedSurfaceConfig::new("run:phase-5-3-unbound").unwrap();
        let error = assemble_document(&document, &config, chrono::Utc::now()).unwrap_err();
        assert!(error[0].context.contains_key("field"));
    }

    #[test]
    fn high_volume_surface_assembly_has_bounded_validation_cost() {
        const FINDING_COUNT: usize = 27_473;
        let mut document = fixture_document();
        document.surface.signers.clear();
        let recorded_by = ActivityId::new("activity:static").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap();
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
                    value: fact(
                        FieldClass::Scalar,
                        ResolutionPolicy::Explicit,
                        format!("https://example.test/api/{index}"),
                        evidence_ids[index].clone(),
                        &recorded_by,
                        at,
                        &candidate_id.to_string(),
                    ),
                }
            })
            .collect();

        let started = std::time::Instant::now();
        let report = assemble_document(
            &document,
            &UnifiedSurfaceConfig::new("run:high-volume-surface").unwrap(),
            at,
        )
        .unwrap();

        assert_eq!(report.unified.surface.loose_findings.len(), FINDING_COUNT);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "high-volume surface assembly exceeded 60s: {:?}",
            started.elapsed()
        );
    }
}
