use std::num::NonZeroU64;

use apiaxess_api_model::{
    Activity, ActivityId, Agent, AgentId, AgentKind, ApiDocument, ApiSurface, CandidateId,
    Endpoint, EndpointIdentity, Entity, EntityId, EntityKind, Fact, FactCandidate, FieldClass,
    HttpMethod, PathTemplate, PathTemplateAssertion, PathTemplateOrigin, PresenceAssertion,
    ProvenanceRegistry, Resolution, ResolutionPolicy, RunId, SourceType,
};
use apiaxess_diagnostics::catalogue::{
    SCOPE_OUTSIDE_DECLARATION, SESSION_API_MODEL_INVALID, SESSION_FORMAT_UNSUPPORTED,
    SESSION_INVALID_TRANSITION, SESSION_UNKNOWN_FIELDS,
};
use chrono::{DateTime, TimeZone, Utc};

use super::*;

fn at(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 18, 12, 0, second)
        .single()
        .expect("valid fixture timestamp")
}

fn model_id<T>(
    value: &str,
    constructor: impl FnOnce(String) -> Result<T, apiaxess_api_model::ModelError>,
) -> T {
    constructor(value.to_owned()).expect("valid model fixture ID")
}

fn fact<T>(
    field_class: FieldClass,
    policy: ResolutionPolicy,
    candidate_id: &str,
    value: T,
    entity_id: &EntityId,
    activity_id: &ActivityId,
) -> Fact<T> {
    Fact {
        field_class,
        expected_recoverability_basis_points: None,
        candidates: vec![FactCandidate {
            id: model_id(candidate_id, CandidateId::new),
            value,
            evidence: vec![entity_id.clone()],
        }],
        resolution: Resolution {
            selected: model_id(candidate_id, CandidateId::new),
            policy,
            resolved_by: activity_id.clone(),
            resolved_at: at(2),
        },
        merges: vec![],
    }
}

fn api_document() -> ApiDocument {
    let agent_id = model_id("agent:fixture", AgentId::new);
    let activity_id = model_id("activity:fixture", ActivityId::new);
    let run_id = model_id("run:fixture", RunId::new);
    let entity_id = model_id("entity:fixture", EntityId::new);
    let provenance = ProvenanceRegistry {
        agents: vec![Agent {
            id: agent_id.clone(),
            kind: AgentKind::Engine,
            name: "phase 0.4 fixture".to_owned(),
            version: Some("0.1.0".to_owned()),
        }],
        activities: vec![Activity {
            id: activity_id.clone(),
            run_id: run_id.clone(),
            agent: agent_id.clone(),
            source_type: SourceType::StaticAnalysis,
            started_at: at(0),
            ended_at: Some(at(2)),
        }],
        entities: vec![Entity {
            id: entity_id.clone(),
            kind: EntityKind::FactEvidence,
            source_type: SourceType::StaticAnalysis,
            generated_by: activity_id.clone(),
            attributed_to: agent_id,
            run_id,
            derived_from: vec![],
            recorded_at: at(1),
            sample_count: NonZeroU64::new(1).unwrap(),
        }],
    };
    ApiDocument::new(ApiSurface {
        provenance,
        endpoints: vec![Endpoint {
            base_url: None,
            identity: EndpointIdentity {
                method: HttpMethod::new("GET").unwrap(),
                path_template: PathTemplate::new("/users/{id}").unwrap(),
            },
            presence: fact(
                FieldClass::Presence,
                ResolutionPolicy::StaticCompleteDynamicConfirm,
                "candidate:presence",
                PresenceAssertion::Present,
                &entity_id,
                &activity_id,
            ),
            path_template: fact(
                FieldClass::PathTemplate,
                ResolutionPolicy::DeclaredBeforeInferred,
                "candidate:path",
                PathTemplateAssertion {
                    template: PathTemplate::new("/users/{id}").unwrap(),
                    origin: PathTemplateOrigin::Declared,
                },
                &entity_id,
                &activity_id,
            ),
            query_parameters: vec![],
            path_parameters: vec![],
            headers: vec![],
            authentication: None,
            request_body: None,
            responses: vec![],
            pagination_signals: Vec::new(),
        }],
        protocol_operations: vec![],
        loose_findings: vec![],
        signers: Vec::new(),
    })
}

fn scope() -> EngagementScope {
    EngagementScope {
        declared_at: at(3),
        target: TargetIdentity {
            target_type: "apk".to_owned(),
            primary: TargetIdentifier {
                kind: "artifact.sha256".to_owned(),
                value: "00".repeat(32),
            },
            aliases: vec![TargetIdentifier {
                kind: "android.package".to_owned(),
                value: "com.example.fixture".to_owned(),
            }],
        },
        allowed_targets: vec![AllowedNetworkTarget {
            id: "rule.api-example".to_owned(),
            host: HostMatch::DomainSuffix {
                domain: "api.example.test".to_owned(),
            },
            ports: vec![443],
        }],
    }
}

fn active_session() -> Session {
    let mut session = Session::new(
        SessionId::new("session:fixture").unwrap(),
        scope(),
        api_document(),
        at(3),
    );
    session.activate(at(4)).unwrap();
    session
}

fn action(id: &str, host: &str, at: DateTime<Utc>) -> ActionRecordInput {
    ActionRecordInput {
        id: id.to_owned(),
        occurred_at: at,
        actor: AuditActor::User,
        action: ActionDescriptor {
            kind: "workbench.request".to_owned(),
            summary: format!("send request to {host}"),
        },
        target: ActionTarget::Network {
            host: host.to_owned(),
            port: Some(443),
        },
        outcome: ActionOutcome::Completed,
        diagnostics: vec![],
    }
}

#[test]
fn outside_scope_action_is_warned_and_recorded_without_blocking() {
    let mut session = active_session();
    let assessment = session
        .record_action(action("action:outside", "unrelated.example", at(5)))
        .expect("advisory scope never blocks the record");

    assert_eq!(
        assessment.disposition,
        ScopeDisposition::OutsideDeclaredScope
    );
    assert!(
        session.audit_trail()[0]
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.id.as_ref() == SCOPE_OUTSIDE_DECLARATION.id)
    );
    assert_eq!(session.audit_trail().len(), 1);
}

#[test]
fn exact_domain_boundary_and_port_are_part_of_scope_assessment() {
    let scope = scope();
    let in_scope = scope.assess(&ActionTarget::Network {
        host: "v2.api.example.test".to_owned(),
        port: Some(443),
    });
    let deceptive_suffix = scope.assess(&ActionTarget::Network {
        host: "notapi.example.test".to_owned(),
        port: Some(443),
    });
    let wrong_port = scope.assess(&ActionTarget::Network {
        host: "api.example.test".to_owned(),
        port: Some(80),
    });

    assert_eq!(in_scope.disposition, ScopeDisposition::InScope);
    assert_eq!(
        deceptive_suffix.disposition,
        ScopeDisposition::OutsideDeclaredScope
    );
    assert_eq!(
        wrong_port.disposition,
        ScopeDisposition::OutsideDeclaredScope
    );
}

#[test]
fn invalid_lifecycle_transition_is_a_canonical_diagnostic() {
    let mut session = active_session();
    let error = session.activate(at(5)).expect_err("cannot activate twice");

    assert_eq!(error.id.as_ref(), SESSION_INVALID_TRANSITION.id);
    assert!(!error.what.is_empty());
    assert!(!error.why.is_empty());
    assert!(!error.fix.is_empty());
}

#[test]
fn complete_session_round_trip_preserves_scope_evidence_audit_and_workbench_slot() {
    let mut session = active_session();
    session
        .record_action(action("action:inside", "v2.api.example.test", at(5)))
        .unwrap();
    session
        .set_workbench_state(
            Some(WorkbenchStateSlot {
                schema_id: "workbench.state".to_owned(),
                format_version: 1,
                payload: serde_json::json!({
                    "future_unknown_to_session": {"tabs": ["one", "two"]}
                }),
            }),
            at(6),
        )
        .unwrap();
    let original = SessionDocument::new(session, at(7));

    let bytes = original.to_json_pretty().expect("session serializes");
    let loaded = SessionDocument::from_json(&bytes).expect("session loads");

    assert_eq!(loaded, original);
    assert_eq!(
        loaded
            .session
            .api_document()
            .surface
            .provenance
            .entities
            .len(),
        1
    );
    assert_eq!(
        loaded.session.api_document().surface.endpoints[0]
            .presence
            .candidates
            .len(),
        1
    );
    assert_eq!(
        loaded.session.api_document().surface.endpoints[0]
            .presence
            .candidates[0]
            .evidence
            .len(),
        1
    );
}

#[test]
fn scope_updates_preserve_historical_audit_assessments() {
    let mut session = active_session();
    session
        .record_action(action("action:historical", "v2.api.example.test", at(5)))
        .unwrap();
    let mut updated = scope();
    updated.allowed_targets.clear();
    session
        .update_engagement_scope(updated, at(6))
        .expect("active scope can be updated");

    session
        .validate()
        .expect("historical assessment remains valid");
    assert_eq!(
        session.audit_trail()[0].scope.disposition,
        ScopeDisposition::InScope
    );
}

#[test]
fn analysis_pipeline_state_round_trips_with_the_session() {
    let mut session = active_session();
    session
        .set_analysis_pipeline_state(
            AnalysisPipelineState {
                schema_version: 1,
                run_id: "pipeline:fixture".to_owned(),
                artifact_path: "fixtures/capstone/feeder.apk".to_owned(),
                stage: "completed".to_owned(),
                status: "completed".to_owned(),
                progress_basis_points: 10_000,
                dynamic_requested: false,
                dynamic_ran: false,
                diagnostics: Vec::new(),
                updated_at: at(5),
            },
            at(5),
        )
        .unwrap();
    let document = SessionDocument::new(session, at(6));
    let bytes = document.to_json_pretty().unwrap();
    let loaded = SessionDocument::from_json(&bytes).unwrap();
    assert_eq!(loaded, document);
    assert_eq!(
        loaded
            .session
            .analysis_pipeline_state()
            .unwrap()
            .progress_basis_points,
        10_000
    );
}

#[test]
fn unsupported_versions_and_unknown_fields_fail_with_stable_diagnostics() {
    let document = SessionDocument::new(active_session(), at(5));
    let mut value = serde_json::to_value(&document).unwrap();
    value["format_version"] = serde_json::json!(99);
    let error = SessionDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(error.id.as_ref(), SESSION_FORMAT_UNSUPPORTED.id);

    let mut value = serde_json::to_value(&document).unwrap();
    value["discard_me"] = serde_json::json!(true);
    let error = SessionDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(error.id.as_ref(), SESSION_UNKNOWN_FIELDS.id);
}

#[test]
fn embedded_model_failure_uses_the_canonical_data_model_diagnostic() {
    let document = SessionDocument::new(active_session(), at(5));
    let mut value = serde_json::to_value(&document).unwrap();
    value["session"]["api_document"]["format_version"] = serde_json::json!(99);

    let error = SessionDocument::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(error.id.as_ref(), SESSION_API_MODEL_INVALID.id);
}

#[test]
fn compact_checkpoint_recovers_metadata_without_copying_evidence_or_workbench_state() {
    let mut current = active_session();
    current
        .record_action(action("action:checkpointed", "v2.api.example.test", at(5)))
        .unwrap();
    current
        .set_analysis_pipeline_state(
            AnalysisPipelineState {
                schema_version: 1,
                run_id: "pipeline:checkpoint".to_owned(),
                artifact_path: "fixtures/feeder.apk".to_owned(),
                stage: "intake".to_owned(),
                status: "running".to_owned(),
                progress_basis_points: 500,
                dynamic_requested: false,
                dynamic_ran: false,
                diagnostics: Vec::new(),
                updated_at: at(6),
            },
            at(6),
        )
        .unwrap();
    let checkpoint = SessionCheckpoint::from_session(&current, at(7));
    let bytes = checkpoint.to_json().expect("checkpoint serializes");
    let checkpoint = SessionCheckpoint::from_json(&bytes).expect("checkpoint parses");

    let mut recovered = active_session();
    let evidence_before = recovered.api_document().clone();
    recovered
        .apply_checkpoint(&checkpoint)
        .expect("newer metadata applies");

    assert_eq!(recovered.api_document(), &evidence_before);
    assert!(recovered.workbench_state().is_none());
    assert_eq!(recovered.audit_trail().len(), 1);
    assert_eq!(
        recovered.analysis_pipeline_state().unwrap().run_id,
        "pipeline:checkpoint"
    );
    recovered.validate().expect("recovered session validates");
}

#[test]
fn checkpoint_versions_and_unknown_fields_fail_explicitly() {
    let checkpoint = SessionCheckpoint::from_session(&active_session(), at(5));
    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["format_version"] = serde_json::json!(99);
    let error = SessionCheckpoint::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(error.id.as_ref(), SESSION_FORMAT_UNSUPPORTED.id);

    let mut value = serde_json::to_value(&checkpoint).unwrap();
    value["discard_me"] = serde_json::json!(true);
    let error = SessionCheckpoint::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err();
    assert_eq!(error.id.as_ref(), "persistence.session-json-invalid");
}
