use std::num::NonZeroU64;

use chrono::{TimeZone, Utc};

use super::*;

fn id<T>(value: &str, constructor: impl FnOnce(String) -> Result<T, ModelError>) -> T {
    constructor(value.to_owned()).expect("fixture ID is valid")
}

fn timestamp(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 18, 12, 0, second)
        .single()
        .expect("fixture timestamp is valid")
}

struct FixtureIds {
    static_agent: AgentId,
    dynamic_agent: AgentId,
    fusion_agent: AgentId,
    static_activity: ActivityId,
    dynamic_activity: ActivityId,
    fusion_activity: ActivityId,
    static_run: RunId,
    dynamic_run: RunId,
    fusion_run: RunId,
    static_entity: EntityId,
    dynamic_entity: EntityId,
    fused_entity: EntityId,
    sample_entity: EntityId,
}

#[allow(clippy::too_many_lines)]
fn provenance() -> (ProvenanceRegistry, FixtureIds) {
    let ids = FixtureIds {
        static_agent: id("agent:jadx", AgentId::new),
        dynamic_agent: id("agent:frida", AgentId::new),
        fusion_agent: id("agent:engine", AgentId::new),
        static_activity: id("activity:static", ActivityId::new),
        dynamic_activity: id("activity:dynamic", ActivityId::new),
        fusion_activity: id("activity:fusion", ActivityId::new),
        static_run: id("run:static", RunId::new),
        dynamic_run: id("run:dynamic", RunId::new),
        fusion_run: id("run:fusion", RunId::new),
        static_entity: id("entity:static", EntityId::new),
        dynamic_entity: id("entity:dynamic", EntityId::new),
        fused_entity: id("entity:fused", EntityId::new),
        sample_entity: id("entity:sample", EntityId::new),
    };
    let agents = vec![
        Agent {
            id: ids.static_agent.clone(),
            kind: AgentKind::ExternalTool,
            name: "jadx".to_owned(),
            version: Some("fixture".to_owned()),
        },
        Agent {
            id: ids.dynamic_agent.clone(),
            kind: AgentKind::ExternalTool,
            name: "Frida".to_owned(),
            version: Some("fixture".to_owned()),
        },
        Agent {
            id: ids.fusion_agent.clone(),
            kind: AgentKind::Engine,
            name: "APIaxess fusion".to_owned(),
            version: Some("0.1.0".to_owned()),
        },
    ];
    let activities = vec![
        Activity {
            id: ids.static_activity.clone(),
            run_id: ids.static_run.clone(),
            agent: ids.static_agent.clone(),
            source_type: SourceType::StaticAnalysis,
            started_at: timestamp(0),
            ended_at: Some(timestamp(1)),
        },
        Activity {
            id: ids.dynamic_activity.clone(),
            run_id: ids.dynamic_run.clone(),
            agent: ids.dynamic_agent.clone(),
            source_type: SourceType::DynamicCapture,
            started_at: timestamp(2),
            ended_at: Some(timestamp(3)),
        },
        Activity {
            id: ids.fusion_activity.clone(),
            run_id: ids.fusion_run.clone(),
            agent: ids.fusion_agent.clone(),
            source_type: SourceType::Fusion,
            started_at: timestamp(4),
            ended_at: Some(timestamp(5)),
        },
    ];
    let entities = vec![
        Entity {
            id: ids.static_entity.clone(),
            kind: EntityKind::FactEvidence,
            source_type: SourceType::StaticAnalysis,
            generated_by: ids.static_activity.clone(),
            attributed_to: ids.static_agent.clone(),
            run_id: ids.static_run.clone(),
            derived_from: vec![],
            recorded_at: timestamp(1),
            sample_count: NonZeroU64::new(1).unwrap(),
        },
        Entity {
            id: ids.dynamic_entity.clone(),
            kind: EntityKind::FactEvidence,
            source_type: SourceType::DynamicCapture,
            generated_by: ids.dynamic_activity.clone(),
            attributed_to: ids.dynamic_agent.clone(),
            run_id: ids.dynamic_run.clone(),
            derived_from: vec![],
            recorded_at: timestamp(3),
            sample_count: NonZeroU64::new(8).unwrap(),
        },
        Entity {
            id: ids.fused_entity.clone(),
            kind: EntityKind::DerivedFact,
            source_type: SourceType::Fusion,
            generated_by: ids.fusion_activity.clone(),
            attributed_to: ids.fusion_agent.clone(),
            run_id: ids.fusion_run.clone(),
            derived_from: vec![ids.static_entity.clone(), ids.dynamic_entity.clone()],
            recorded_at: timestamp(5),
            sample_count: NonZeroU64::new(9).unwrap(),
        },
        Entity {
            id: ids.sample_entity.clone(),
            kind: EntityKind::ObservedSample,
            source_type: SourceType::DynamicCapture,
            generated_by: ids.dynamic_activity.clone(),
            attributed_to: ids.dynamic_agent.clone(),
            run_id: ids.dynamic_run.clone(),
            derived_from: vec![],
            recorded_at: timestamp(3),
            sample_count: NonZeroU64::new(1).unwrap(),
        },
    ];
    (
        ProvenanceRegistry {
            agents,
            activities,
            entities,
        },
        ids,
    )
}

fn candidate<T>(id_value: &str, value: T, evidence: Vec<EntityId>) -> FactCandidate<T> {
    FactCandidate {
        id: id(id_value, CandidateId::new),
        value,
        evidence,
    }
}

fn fact<T>(
    field_class: FieldClass,
    policy: ResolutionPolicy,
    candidates: Vec<FactCandidate<T>>,
    selected: &str,
    activity: &ActivityId,
) -> Fact<T> {
    Fact {
        field_class,
        expected_recoverability_basis_points: None,
        candidates,
        resolution: Resolution {
            selected: id(selected, CandidateId::new),
            policy,
            resolved_by: activity.clone(),
            resolved_at: timestamp(5),
        },
        merges: vec![],
    }
}

fn schema(ids: &FixtureIds) -> SchemaSlot {
    let mut shape = fact(
        FieldClass::TypeShape,
        ResolutionPolicy::UnionOrWiden,
        vec![candidate(
            "candidate:schema:string",
            SchemaShape::String { format: None },
            vec![ids.fused_entity.clone()],
        )],
        "candidate:schema:string",
        &ids.fusion_activity,
    );
    shape.merges.push(MergeRecord {
        left: MergeInput {
            source_type: SourceType::StaticAnalysis,
            candidate: Some(id("candidate:schema:string", CandidateId::new)),
        },
        right: MergeInput {
            source_type: SourceType::DynamicCapture,
            candidate: Some(id("candidate:schema:string", CandidateId::new)),
        },
        relation: MergeRelation::Agreement,
        result: id("candidate:schema:string", CandidateId::new),
        recorded_by: ids.fusion_activity.clone(),
        recorded_at: timestamp(5),
    });
    SchemaSlot {
        shape,
        observations: vec![SchemaObservation {
            entity: ids.sample_entity.clone(),
            payload: SamplePayload::Inline {
                value: serde_json::json!("alice"),
            },
        }],
    }
}

fn requiredness(ids: &FixtureIds) -> Fact<RequirednessAssertion> {
    fact(
        FieldClass::Requiredness,
        ResolutionPolicy::SampleGated,
        vec![candidate(
            "candidate:requiredness",
            RequirednessAssertion::Observed {
                present_samples: 8,
                total_samples: NonZeroU64::new(8).unwrap(),
            },
            vec![ids.dynamic_entity.clone()],
        )],
        "candidate:requiredness",
        &ids.fusion_activity,
    )
}

fn document() -> ApiDocument {
    let (provenance, ids) = provenance();
    let presence = fact(
        FieldClass::Presence,
        ResolutionPolicy::StaticCompleteDynamicConfirm,
        vec![candidate(
            "candidate:present",
            PresenceAssertion::Present,
            vec![ids.fused_entity.clone()],
        )],
        "candidate:present",
        &ids.fusion_activity,
    );
    let template = fact(
        FieldClass::PathTemplate,
        ResolutionPolicy::DeclaredBeforeInferred,
        vec![candidate(
            "candidate:template",
            PathTemplateAssertion {
                template: PathTemplate::new("/users/{id}").unwrap(),
                origin: PathTemplateOrigin::Declared,
            },
            vec![ids.static_entity.clone()],
        )],
        "candidate:template",
        &ids.fusion_activity,
    );
    let authentication = fact(
        FieldClass::Authentication,
        ResolutionPolicy::DynamicAuthoritative,
        vec![
            candidate(
                "candidate:auth:basic",
                AuthenticationScheme::Basic,
                vec![ids.static_entity.clone()],
            ),
            candidate(
                "candidate:auth:bearer",
                AuthenticationScheme::Bearer { token_format: None },
                vec![ids.dynamic_entity.clone()],
            ),
        ],
        "candidate:auth:bearer",
        &ids.fusion_activity,
    );
    ApiDocument::new(ApiSurface {
        provenance,
        endpoints: vec![Endpoint {
            base_url: None,
            identity: EndpointIdentity {
                method: HttpMethod::new("get").unwrap(),
                path_template: PathTemplate::new("/users/{id}").unwrap(),
                host: None,
            },
            presence: presence.clone(),
            path_template: template,
            query_parameters: vec![QueryParameter {
                name: ParameterName::new("expand").unwrap(),
                presence,
                schema: schema(&ids),
                requiredness: requiredness(&ids),
            }],
            path_parameters: vec![],
            headers: vec![],
            authentication: Some(authentication),
            request_body: None,
            responses: vec![ResponseBody {
                selector: ResponseSelector::Exact(200),
                presence: fact(
                    FieldClass::Presence,
                    ResolutionPolicy::StaticCompleteDynamicConfirm,
                    vec![candidate(
                        "candidate:response:present",
                        PresenceAssertion::Present,
                        vec![ids.dynamic_entity.clone()],
                    )],
                    "candidate:response:present",
                    &ids.fusion_activity,
                ),
                body: schema(&ids),
            }],
            pagination_signals: Vec::new(),
        }],
        protocol_operations: vec![],
        loose_findings: vec![],
        signers: Vec::new(),
    })
}

#[test]
fn durable_json_round_trip_preserves_every_candidate_and_provenance_link() {
    let original = document();
    let bytes = original.to_json_pretty().expect("fixture serializes");
    let loaded = ApiDocument::from_json(&bytes).expect("fixture loads");

    assert_eq!(loaded, original);
    assert_eq!(loaded.surface.provenance.entities.len(), 4);
    assert_eq!(
        loaded.surface.endpoints[0]
            .authentication
            .as_ref()
            .unwrap()
            .candidates
            .len(),
        2
    );
}

#[test]
fn endpoint_identity_ignores_query_inventory_and_normalizes_method() {
    let left = EndpointIdentity {
        method: HttpMethod::new("get").unwrap(),
        path_template: PathTemplate::new("/users/{id}").unwrap(),
        host: None,
    };
    let right = EndpointIdentity {
        method: HttpMethod::new("GET").unwrap(),
        path_template: PathTemplate::new("/users/{id}").unwrap(),
        host: None,
    };
    assert_eq!(left, right);
    assert!(PathTemplate::new("/users/{id}?sort=x").is_err());
}

#[test]
fn dynamic_authentication_evidence_must_win_hard() {
    let mut invalid = document();
    invalid.surface.endpoints[0]
        .authentication
        .as_mut()
        .unwrap()
        .resolution
        .selected = id("candidate:auth:basic", CandidateId::new);

    let error = invalid
        .validate()
        .expect_err("static auth cannot beat dynamic");
    assert!(error.to_string().contains("dynamic-supported"));
}

#[test]
fn gap_fill_represents_silence_without_an_absence_candidate() {
    let mut model = document();
    model.surface.endpoints[0]
        .presence
        .merges
        .push(MergeRecord {
            left: MergeInput {
                source_type: SourceType::StaticAnalysis,
                candidate: Some(id("candidate:present", CandidateId::new)),
            },
            right: MergeInput {
                source_type: SourceType::DynamicCapture,
                candidate: None,
            },
            relation: MergeRelation::GapFill,
            result: id("candidate:present", CandidateId::new),
            recorded_by: id("activity:fusion", ActivityId::new),
            recorded_at: timestamp(5),
        });

    model.validate().expect("dynamic silence is valid gap-fill");
    assert_eq!(model.surface.endpoints[0].presence.candidates.len(), 1);
}

#[test]
fn requiredness_is_inconclusive_until_the_selected_threshold_is_met() {
    let model = document();
    let requiredness = &model.surface.endpoints[0].query_parameters[0].requiredness;
    assert_eq!(
        requiredness
            .assess_requiredness(NonZeroU64::new(10).unwrap())
            .unwrap(),
        RequirednessAssessment::Inconclusive
    );
    assert_eq!(
        requiredness
            .assess_requiredness(NonZeroU64::new(5).unwrap())
            .unwrap(),
        RequirednessAssessment::Required
    );
}

#[test]
fn confidence_is_recomputed_from_leaf_evidence_without_double_counting_fusion() {
    let model = document();
    let shape = &model.surface.endpoints[0].responses[0].body.shape;
    let confidence = shape.confidence(&model.surface.provenance).unwrap();

    assert_eq!(confidence.sample_count, 9);
    assert!(confidence.source_agreement);
    assert!(confidence.score > 0.7);
}

#[test]
fn merge_relations_remain_distinct_and_keep_all_candidates() {
    let mut model = document();
    let authentication = model.surface.endpoints[0].authentication.as_mut().unwrap();
    authentication.merges = vec![
        MergeRecord {
            left: MergeInput {
                source_type: SourceType::StaticAnalysis,
                candidate: Some(id("candidate:auth:basic", CandidateId::new)),
            },
            right: MergeInput {
                source_type: SourceType::DynamicCapture,
                candidate: None,
            },
            relation: MergeRelation::GapFill,
            result: id("candidate:auth:basic", CandidateId::new),
            recorded_by: id("activity:fusion", ActivityId::new),
            recorded_at: timestamp(4),
        },
        MergeRecord {
            left: MergeInput {
                source_type: SourceType::StaticAnalysis,
                candidate: Some(id("candidate:auth:basic", CandidateId::new)),
            },
            right: MergeInput {
                source_type: SourceType::DynamicCapture,
                candidate: Some(id("candidate:auth:bearer", CandidateId::new)),
            },
            relation: MergeRelation::TrueConflict,
            result: id("candidate:auth:bearer", CandidateId::new),
            recorded_by: id("activity:fusion", ActivityId::new),
            recorded_at: timestamp(5),
        },
    ];

    model.validate().unwrap();
    let authentication = model.surface.endpoints[0].authentication.as_ref().unwrap();
    assert_eq!(authentication.candidates.len(), 2);
    assert_ne!(
        authentication.merges[0].relation,
        authentication.merges[1].relation
    );
}

#[test]
fn type_widening_can_select_a_union_without_erasing_input_shapes() {
    let mut model = document();
    let shape = &mut model.surface.endpoints[0].responses[0].body.shape;
    shape.candidates = vec![
        candidate(
            "candidate:type:integer",
            SchemaShape::Integer { format: None },
            vec![id("entity:static", EntityId::new)],
        ),
        candidate(
            "candidate:type:string",
            SchemaShape::String { format: None },
            vec![id("entity:dynamic", EntityId::new)],
        ),
        candidate(
            "candidate:type:union",
            SchemaShape::Union {
                variants: vec![
                    SchemaShape::Integer { format: None },
                    SchemaShape::String { format: None },
                ],
            },
            vec![id("entity:fused", EntityId::new)],
        ),
    ];
    shape.resolution.selected = id("candidate:type:union", CandidateId::new);
    shape.merges = vec![MergeRecord {
        left: MergeInput {
            source_type: SourceType::StaticAnalysis,
            candidate: Some(id("candidate:type:integer", CandidateId::new)),
        },
        right: MergeInput {
            source_type: SourceType::DynamicCapture,
            candidate: Some(id("candidate:type:string", CandidateId::new)),
        },
        relation: MergeRelation::Refinement,
        result: id("candidate:type:union", CandidateId::new),
        recorded_by: id("activity:fusion", ActivityId::new),
        recorded_at: timestamp(5),
    }];

    model.validate().unwrap();
    let shape = &model.surface.endpoints[0].responses[0].body.shape;
    assert_eq!(shape.candidates.len(), 3);
    assert_eq!(shape.merges[0].relation, MergeRelation::Refinement);
}

#[test]
fn unsupported_versions_and_unknown_fields_fail_explicitly() {
    let mut value = serde_json::to_value(document()).unwrap();
    value["format_version"] = serde_json::json!(99);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        ApiDocument::from_json(&bytes),
        Err(ModelError::UnsupportedFormat { .. })
    ));

    let mut value = serde_json::to_value(document()).unwrap();
    value["discard_me"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        ApiDocument::from_json(&bytes),
        Err(ModelError::Json(_))
    ));

    let mut value = serde_json::to_value(document()).unwrap();
    value["surface"]["endpoints"][0]["authentication"]["candidates"][0]["value"]["discard_me"] =
        serde_json::json!(true);
    let bytes = serde_json::to_vec(&value).unwrap();
    let result = ApiDocument::from_json(&bytes);
    assert!(
        matches!(result, Err(ModelError::UnknownFields { .. })),
        "unexpected result: {result:?}"
    );
}

#[test]
fn graphql_operation_headers_parse_name_and_type_without_variable_fragments() {
    use crate::{GraphQlOperationHeader, GraphQlOperationType, parse_graphql_operations};
    let header = |operation_type, name: Option<&str>| GraphQlOperationHeader {
        operation_type,
        name: name.map(ToOwned::to_owned),
    };
    assert_eq!(
        parse_graphql_operations(
            "query GetProfile($id: ID!) { profile(id: $id) { id displayName } }"
        ),
        vec![header(GraphQlOperationType::Query, Some("GetProfile"))]
    );
    assert_eq!(
        parse_graphql_operations(
            "# comment\nfragment F on User { id }\nmutation Rename($n: String = \"a}b\") @live { rename(n: $n) { ...F } }"
        ),
        vec![header(GraphQlOperationType::Mutation, Some("Rename"))]
    );
    assert_eq!(
        parse_graphql_operations("{ me { id } }"),
        vec![header(GraphQlOperationType::Query, None)]
    );
    assert_eq!(
        parse_graphql_operations("subscription OnMessage { message { id } } query Two { a }"),
        vec![
            header(GraphQlOperationType::Subscription, Some("OnMessage")),
            header(GraphQlOperationType::Query, Some("Two")),
        ]
    );
    // Prose starting with "query", and unterminated fragments, are not documents.
    assert!(parse_graphql_operations("query the server for updates").is_empty());
    assert!(parse_graphql_operations("query GetProfile($id").is_empty());
}

#[test]
fn grpc_method_paths_parse_to_service_and_method() {
    use crate::parse_grpc_method_path;
    assert_eq!(
        parse_grpc_method_path("/shop.v1.CartService/AddItem"),
        Some(("shop.v1.CartService".to_owned(), "AddItem".to_owned()))
    );
    assert_eq!(
        parse_grpc_method_path("/Greeter/SayHello"),
        Some(("Greeter".to_owned(), "SayHello".to_owned()))
    );
    for rest in [
        "/api/v1/items",
        "/shop.v1.CartService/AddItem/extra",
        "shop.v1.CartService/AddItem",
        "/shop..Cart/Add",
        "/shop.Cart/Add-Item",
        "/shop.Cart/",
        "/",
    ] {
        assert_eq!(parse_grpc_method_path(rest), None, "{rest}");
    }
}
