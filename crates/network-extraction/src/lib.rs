//! Phase 1.3 bounded static networking extraction.
//!
//! Extractors consume the routed 1.2 map and never perform deep
//! interprocedural reconstruction or dynamic analysis. Each extractor is a
//! protocol-decoder sibling behind the same seam; unresolved composition is
//! retained as a partial finding with a dynamic-capture recommendation.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::Instant,
};

use apiaxess_api_model::{
    ApiDocument, ApiSurface, Endpoint, EndpointIdentity, Fact, FactCandidate, FieldClass,
    GraphQlOperationType, HeaderParameter, LooseFinding, LooseFindingKind, ObjectOpenness,
    PathParameter, PathTemplate, PathTemplateAssertion, PathTemplateOrigin, PresenceAssertion,
    ProtocolOperation, ProtocolOperationIdentity, QueryParameter, Resolution, ResolutionPolicy,
    SchemaProperty, SchemaShape, SchemaSlot,
};
use apiaxess_artifact_intake::NormalizedUnpackedArtifact;
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        EXTRACTION_DECODER_DEFERRED, EXTRACTION_LOOSE_FINDINGS_FILTERED,
        EXTRACTION_PARTIAL_RECOVERY, EXTRACTION_UNBOUND_STRING_CANDIDATE,
    },
};
use apiaxess_network_routing::{CorpusDocument, LibraryDetection, SignatureCorpus, SourceKind};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod dto;
mod java_scope;

use dto::{BodyField, BodyShape, DtoIndex, StaticBody};
use java_scope::{BodyRef, CallSite, HttpClient};

/// A structured failure to produce an invariant-valid API document.
#[derive(Clone, Debug)]
pub struct ExtractionFailure {
    /// Actionable diagnostic.
    pub diagnostic: Diagnostic,
}

impl std::fmt::Display for ExtractionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for ExtractionFailure {}

/// One extractor's contribution to the Phase 1.3 report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtractionRecord {
    /// Library identity.
    pub library_id: String,
    /// Protocol-decoder extractor ID.
    pub extractor_id: String,
    /// Number of REST endpoints added.
    pub endpoint_count: usize,
    /// Number of native protocol operations added.
    pub operation_count: usize,
    /// Number of partial recoveries recorded.
    pub partial_count: usize,
}

/// An honest boundary where bounded static analysis stopped.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PartialRecovery {
    /// Library identity.
    pub library_id: String,
    /// Extractor location that triggered the partial finding.
    pub location: String,
    /// Why the value is incomplete.
    pub reason: String,
    /// Whether dynamic capture is the recommended next step.
    pub dynamic_recommended: bool,
}

/// Timing breakdown for one static extraction pass.
///
/// Timings are always collected so callers can record them with a capstone
/// report. The library only prints them when `APIAXESS_PROFILE_STATIC=1` is
/// set, keeping normal runs quiet.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtractionTiming {
    /// Time spent constructing the bounded corpus metadata.
    pub corpus_from_artifact_millis: u128,
    /// Time spent scanning the corpus for string-pool candidates.
    pub string_pool_millis: u128,
    /// Time spent running each selected protocol extractor.
    pub extractors: Vec<ExtractorTiming>,
    /// Time spent converting retained string candidates into loose findings.
    pub loose_finding_collection_millis: u128,
    /// Time spent classifying and removing only explicit packaged-noise
    /// candidates before facts are allocated.
    #[serde(default)]
    pub loose_finding_filtering_millis: u128,
    /// Time spent deduplicating and merging loose findings.
    pub loose_finding_deduplication_millis: u128,
    /// Time spent assembling and validating the final extraction report.
    pub finalization_millis: u128,
}

/// Timing for one protocol-decoder extractor invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtractorTiming {
    /// Library identity from the routed detection.
    pub library_id: String,
    /// Protocol-decoder identity.
    pub extractor_id: String,
    /// Elapsed extractor time in milliseconds.
    pub millis: u128,
}

/// Complete Phase 1.3 handoff.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtractionReport {
    /// Canonical API model document containing extracted facts.
    pub document: ApiDocument,
    /// Diagnostics retained for the GUI and audit trail.
    pub diagnostics: Vec<Diagnostic>,
    /// Per-extractor accounting.
    pub records: Vec<ExtractionRecord>,
    /// Explicitly partial findings.
    pub partial_recoveries: Vec<PartialRecovery>,
    /// Per-subphase performance measurements for this extraction.
    pub timing: ExtractionTiming,
}

/// Protocol-decoder extractor seam used by the extraction registry.
pub trait ProtocolDecoderExtractor: Send + Sync {
    /// Stable routed protocol-decoder ID.
    fn protocol_decoder_id(&self) -> &'static str;

    /// Extracts only bounded, statically supported values.
    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    );
}

/// Extensible registry of sibling protocol-decoder extractors.
pub struct ExtractorRegistry {
    extractors: Vec<Box<dyn ProtocolDecoderExtractor>>,
}

impl std::fmt::Debug for ExtractorRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExtractorRegistry")
            .field("extractor_count", &self.extractors.len())
            .finish()
    }
}

impl Default for ExtractorRegistry {
    fn default() -> Self {
        Self::with_extractors(vec![
            Box::new(RetrofitExtractor),
            Box::new(KtorExtractor),
            Box::new(GrpcExtractor),
            Box::new(ApolloExtractor),
            Box::new(OkHttpExtractor),
            Box::new(VolleyExtractor),
            Box::new(ApacheExtractor),
            Box::new(HttpUrlConnectionExtractor),
            Box::new(WebViewExtractor),
            Box::new(RawSocketExtractor),
        ])
    }
}

impl ExtractorRegistry {
    /// Creates a registry from sibling extractor implementations.
    #[must_use]
    pub fn with_extractors(extractors: Vec<Box<dyn ProtocolDecoderExtractor>>) -> Self {
        Self { extractors }
    }

    /// Extracts the bounded static API surface from a routed artifact.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic if the resulting model violates a
    /// canonical 0.2 invariant.
    ///
    /// # Panics
    ///
    /// Panics only if an internal extraction invariant is violated while
    /// assembling the canonical model.
    pub fn extract(
        &self,
        artifact: &NormalizedUnpackedArtifact,
        routed: &apiaxess_network_routing::RoutedDetectionMap,
    ) -> Result<ExtractionReport, ExtractionFailure> {
        let mut timing = ExtractionTiming::default();
        let started = Instant::now();
        let (corpus, corpus_diagnostics) = SignatureCorpus::from_artifact(artifact);
        timing.corpus_from_artifact_millis = started.elapsed().as_millis();
        let mut builder = ModelBuilder::new();
        builder.diagnostics.extend(corpus_diagnostics);

        let started = Instant::now();
        StringPoolExtractor::extract_global(&corpus, &mut builder);
        timing.string_pool_millis = started.elapsed().as_millis();
        if profile_static_enabled() {
            eprintln!(
                "STATIC EXTRACTION PHASE: string_pool_done millis={} candidates={}",
                timing.string_pool_millis,
                builder.string_candidates.len()
            );
        }
        for detection in &routed.detections {
            if let Some(extractor) = self
                .extractors
                .iter()
                .find(|extractor| extractor.protocol_decoder_id() == detection.protocol_decoder_id)
            {
                if profile_static_enabled() {
                    eprintln!(
                        "STATIC EXTRACTION PHASE: extractor_start library={} extractor={}",
                        detection.library_id,
                        extractor.protocol_decoder_id()
                    );
                }
                let started = Instant::now();
                let before_endpoints = builder.endpoints.len();
                let before_operations = builder.operations.len();
                let before_partials = builder.partial_recoveries.len();
                extractor.extract(detection, &corpus, &mut builder);
                timing.extractors.push(ExtractorTiming {
                    library_id: detection.library_id.clone(),
                    extractor_id: extractor.protocol_decoder_id().to_owned(),
                    millis: started.elapsed().as_millis(),
                });
                if profile_static_enabled() {
                    eprintln!(
                        "STATIC EXTRACTION PHASE: extractor_done library={} extractor={} millis={}",
                        detection.library_id,
                        extractor.protocol_decoder_id(),
                        timing
                            .extractors
                            .last()
                            .expect("timing was just pushed")
                            .millis
                    );
                }
                builder.records.push(ExtractionRecord {
                    library_id: detection.library_id.clone(),
                    extractor_id: extractor.protocol_decoder_id().to_owned(),
                    endpoint_count: builder.endpoints.len() - before_endpoints,
                    operation_count: builder.operations.len() - before_operations,
                    partial_count: builder.partial_recoveries.len() - before_partials,
                });
            } else {
                builder.diagnostics.push(deferred_diagnostic(detection));
            }
        }

        builder.diagnostics.extend(corpus.take_scan_diagnostics());

        let report = builder.finish(artifact, routed, timing)?;
        if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
            eprintln!("STATIC EXTRACTION PROFILE: {:?}", report.timing);
        }
        Ok(report)
    }
}

/// Convenience entry point using the built-in extractor registry.
///
/// # Errors
///
/// Returns the canonical extraction diagnostic if the assembled API document
/// fails model validation.
pub fn extract(
    artifact: &NormalizedUnpackedArtifact,
    routed: &apiaxess_network_routing::RoutedDetectionMap,
) -> Result<ExtractionReport, ExtractionFailure> {
    ExtractorRegistry::default().extract(artifact, routed)
}

#[derive(Clone)]
struct ExtractorContext {
    agent_id: apiaxess_api_model::AgentId,
    activity_id: apiaxess_api_model::ActivityId,
}

#[derive(Clone)]
struct StaticStringCandidate {
    kind: LooseFindingKind,
    value: String,
    path: String,
}

#[derive(Default)]
struct FilteredNoiseStats {
    count: usize,
    examples: Vec<String>,
}

/// Internal model/provenance assembly service.
pub struct ModelBuilder {
    provenance: apiaxess_api_model::ProvenanceRegistry,
    endpoints: Vec<Endpoint>,
    operations: Vec<ProtocolOperation>,
    loose_findings: Vec<LooseFinding>,
    diagnostics: Vec<Diagnostic>,
    records: Vec<ExtractionRecord>,
    partial_recoveries: Vec<PartialRecovery>,
    string_candidates: Vec<StaticStringCandidate>,
    string_candidate_keys: BTreeSet<(LooseFindingKind, String)>,
    filtered_noise: BTreeMap<&'static str, FilteredNoiseStats>,
    bound_values: BTreeSet<String>,
    contexts: BTreeMap<String, ExtractorContext>,
    run_id: apiaxess_api_model::RunId,
    now: DateTime<Utc>,
    next_entity: u64,
    next_candidate: u64,
}

impl ModelBuilder {
    fn new() -> Self {
        Self {
            provenance: apiaxess_api_model::ProvenanceRegistry::default(),
            endpoints: Vec::new(),
            operations: Vec::new(),
            loose_findings: Vec::new(),
            diagnostics: Vec::new(),
            records: Vec::new(),
            partial_recoveries: Vec::new(),
            string_candidates: Vec::new(),
            string_candidate_keys: BTreeSet::new(),
            filtered_noise: BTreeMap::new(),
            bound_values: BTreeSet::new(),
            contexts: BTreeMap::new(),
            run_id: apiaxess_api_model::RunId::new("run:phase-1.3").expect("stable run ID"),
            now: Utc::now(),
            next_entity: 0,
            next_candidate: 0,
        }
    }

    fn context(&mut self, extractor_id: &str) -> ExtractorContext {
        if !self.contexts.contains_key(extractor_id) {
            let token = safe_token(extractor_id);
            let agent_id = apiaxess_api_model::AgentId::new(format!("agent:phase-1.3:{token}"))
                .expect("stable extractor agent ID");
            let activity_id =
                apiaxess_api_model::ActivityId::new(format!("activity:phase-1.3:{token}"))
                    .expect("stable extractor activity ID");
            self.provenance.agents.push(apiaxess_api_model::Agent {
                id: agent_id.clone(),
                kind: apiaxess_api_model::AgentKind::Engine,
                name: format!("APIaxess {extractor_id} protocol-decoder extractor"),
                version: Some("0.1.0".to_owned()),
            });
            self.provenance
                .activities
                .push(apiaxess_api_model::Activity {
                    id: activity_id.clone(),
                    run_id: self.run_id.clone(),
                    agent: agent_id.clone(),
                    source_type: apiaxess_api_model::SourceType::StaticAnalysis,
                    started_at: self.now,
                    ended_at: Some(self.now),
                });
            self.contexts.insert(
                extractor_id.to_owned(),
                ExtractorContext {
                    agent_id,
                    activity_id,
                },
            );
        }
        self.contexts
            .get(extractor_id)
            .expect("extractor context was inserted")
            .clone()
    }

    fn evidence(&mut self, extractor_id: &str, path: &str) -> apiaxess_api_model::EntityId {
        let context = self.context(extractor_id);
        self.next_entity += 1;
        let entity_id =
            apiaxess_api_model::EntityId::new(format!("entity:phase-1.3:{}", self.next_entity))
                .expect("stable evidence entity ID");
        self.provenance.entities.push(apiaxess_api_model::Entity {
            id: entity_id.clone(),
            kind: apiaxess_api_model::EntityKind::FactEvidence,
            source_type: apiaxess_api_model::SourceType::StaticAnalysis,
            generated_by: context.activity_id,
            attributed_to: context.agent_id,
            run_id: self.run_id.clone(),
            derived_from: Vec::new(),
            recorded_at: self.now,
            sample_count: NonZeroU64::new(1).expect("one static observation"),
        });
        let _ = path;
        entity_id
    }

    fn fact<T>(
        &mut self,
        extractor_id: &str,
        field_class: FieldClass,
        policy: ResolutionPolicy,
        value: T,
        evidence: apiaxess_api_model::EntityId,
        expected: u16,
    ) -> Fact<T> {
        self.next_candidate += 1;
        let candidate_id = apiaxess_api_model::CandidateId::new(format!(
            "candidate:phase-1.3:{}",
            self.next_candidate
        ))
        .expect("stable candidate ID");
        let context = self.context(extractor_id);
        Fact {
            field_class,
            expected_recoverability_basis_points: Some(expected),
            candidates: vec![FactCandidate {
                id: candidate_id.clone(),
                value,
                evidence: vec![evidence],
            }],
            resolution: Resolution {
                selected: candidate_id,
                policy,
                resolved_by: context.activity_id,
                resolved_at: self.now,
            },
            merges: Vec::new(),
        }
    }

    fn schema(
        &mut self,
        extractor_id: &str,
        evidence: apiaxess_api_model::EntityId,
        expected: u16,
    ) -> SchemaSlot {
        SchemaSlot {
            shape: self.fact(
                extractor_id,
                FieldClass::TypeShape,
                ResolutionPolicy::UnionOrWiden,
                SchemaShape::Unknown,
                evidence,
                expected,
            ),
            observations: Vec::new(),
        }
    }

    /// A request-body schema from a statically resolved field set: an object
    /// whose properties are exactly the resolved fields, never more.
    fn body_schema(
        &mut self,
        extractor_id: &str,
        evidence: &apiaxess_api_model::EntityId,
        expected: u16,
        fields: &[BodyField],
    ) -> SchemaSlot {
        let shape = self.object_shape(extractor_id, evidence, expected, fields);
        SchemaSlot {
            shape: self.fact(
                extractor_id,
                FieldClass::TypeShape,
                ResolutionPolicy::UnionOrWiden,
                shape,
                evidence.clone(),
                expected,
            ),
            observations: Vec::new(),
        }
    }

    fn object_shape(
        &mut self,
        extractor_id: &str,
        evidence: &apiaxess_api_model::EntityId,
        expected: u16,
        fields: &[BodyField],
    ) -> SchemaShape {
        let mut properties = Vec::new();
        for field in fields {
            let Ok(name) = apiaxess_api_model::ParameterName::new(field.name.clone()) else {
                continue;
            };
            let shape = self.body_shape(extractor_id, evidence, expected, &field.shape);
            properties.push(SchemaProperty {
                name,
                schema: SchemaSlot {
                    shape: self.fact(
                        extractor_id,
                        FieldClass::TypeShape,
                        ResolutionPolicy::UnionOrWiden,
                        shape,
                        evidence.clone(),
                        expected,
                    ),
                    observations: Vec::new(),
                },
                requiredness: self.fact(
                    extractor_id,
                    FieldClass::Requiredness,
                    ResolutionPolicy::SampleGated,
                    apiaxess_api_model::RequirednessAssertion::Declared {
                        required: field.required,
                    },
                    evidence.clone(),
                    expected,
                ),
            });
        }
        SchemaShape::Object {
            properties,
            // The field set comes from a declaration (a class, or the literal
            // keys written in one method); nothing indicates extra fields.
            openness: ObjectOpenness::Closed,
        }
    }

    fn body_shape(
        &mut self,
        extractor_id: &str,
        evidence: &apiaxess_api_model::EntityId,
        expected: u16,
        shape: &BodyShape,
    ) -> SchemaShape {
        match shape {
            BodyShape::Unknown => SchemaShape::Unknown,
            BodyShape::String => SchemaShape::String { format: None },
            BodyShape::Integer(format) => SchemaShape::Integer {
                format: format.map(ToOwned::to_owned),
            },
            BodyShape::Number(format) => SchemaShape::Number {
                format: format.map(ToOwned::to_owned),
            },
            BodyShape::Boolean => SchemaShape::Boolean,
            BodyShape::Array(items) => {
                let item = self.body_shape(extractor_id, evidence, expected, items);
                SchemaShape::Array {
                    items: Box::new(SchemaSlot {
                        shape: self.fact(
                            extractor_id,
                            FieldClass::TypeShape,
                            ResolutionPolicy::UnionOrWiden,
                            item,
                            evidence.clone(),
                            expected,
                        ),
                        observations: Vec::new(),
                    }),
                }
            }
            BodyShape::Object(fields) => {
                self.object_shape(extractor_id, evidence, expected, fields)
            }
        }
    }

    fn presence(
        &mut self,
        extractor_id: &str,
        evidence: apiaxess_api_model::EntityId,
        expected: u16,
    ) -> Fact<PresenceAssertion> {
        self.fact(
            extractor_id,
            FieldClass::Presence,
            ResolutionPolicy::StaticCompleteDynamicConfirm,
            PresenceAssertion::Present,
            evidence,
            expected,
        )
    }

    #[allow(clippy::too_many_arguments)]
    // A single cohesive endpoint builder: artifact rejection, identity/dedup, and
    // the parallel query/path/header parameter assembly all belong together, so it
    // sits just over the line heuristic rather than being split for its own sake.
    #[allow(clippy::too_many_lines)]
    fn add_rest(
        &mut self,
        extractor_id: &str,
        detection: &LibraryDetection,
        method: &str,
        path: &str,
        origin: PathTemplateOrigin,
        base_url: Option<String>,
        query_names: &[String],
        path_names: &[String],
        header_names: &[String],
        body: &StaticBody,
        evidence_path: &str,
    ) {
        let path = normalize_path(path);
        // Reject the Compose `LinkAnnotation.Url(` decompiler artifact before it
        // becomes a structured endpoint. `is_url_extraction_artifact` cannot be
        // used here — a templated path legitimately contains `{`/`}` — so match
        // only the annotation signature.
        if is_compose_annotation_artifact(&path) {
            self.partial(
                &detection.library_id,
                evidence_path,
                "path was a decompiler/parse artifact, not a real endpoint",
            );
            return;
        }
        // Reject filesystem/kernel paths misread as HTTP endpoints. A bundled SDK
        // reads sysfs/procfs and app-storage paths (device fingerprinting, file
        // I/O); those string literals are not HTTP paths, and gluing one onto a
        // base URL (`assets.juspay.in/sys/devices/system/cpu/`) is pure extraction
        // noise. Real API paths never live under these roots, so this is safe.
        if is_non_http_path(&path) {
            self.partial(
                &detection.library_id,
                evidence_path,
                "path was a filesystem/kernel path, not an HTTP endpoint",
            );
            return;
        }
        let Ok(method) = apiaxess_api_model::HttpMethod::new(method) else {
            return;
        };
        let Ok(path_template) = PathTemplate::new(path.clone()) else {
            self.partial(
                &detection.library_id,
                evidence_path,
                "path template was not an absolute static path",
            );
            return;
        };
        // Only a base bound to this call site (its own URL, or the Retrofit
        // instance that built its interface) makes the host part of identity.
        // The sole-discovered fallback below is a guess and stays out of it.
        let identity = EndpointIdentity {
            method,
            path_template: path_template.clone(),
            host: base_url
                .as_deref()
                .and_then(apiaxess_api_model::normalize_host),
        };
        if let Some(index) = self.endpoints.iter().position(|endpoint| {
            endpoint.identity == identity
                || (identity.host.is_none() && endpoint.identity.same_route(&identity))
        }) {
            // Another view of the same route (smali vs Java, or a second
            // extractor) may know the body's fields when the first did not.
            if let StaticBody::Fields(fields) = body {
                let unknown = self.endpoints[index]
                    .request_body
                    .as_ref()
                    .is_none_or(|slot| {
                        matches!(
                            slot.shape
                                .selected_candidate()
                                .map(|candidate| &candidate.value),
                            None | Some(SchemaShape::Unknown)
                        )
                    });
                if unknown {
                    let evidence = self.evidence(extractor_id, evidence_path);
                    let expected = detection.recoverability.adjusted_basis_points;
                    let slot = self.body_schema(extractor_id, &evidence, expected, fields);
                    self.endpoints[index].request_body = Some(slot);
                }
            }
            return;
        }
        // A host-bound view of a route supersedes a host-less view of it
        // (e.g. the same Retrofit route read from smali with its instance
        // binding and from Java without one).
        if identity.host.is_some() {
            self.endpoints.retain(|endpoint| {
                !(endpoint.identity.host.is_none() && endpoint.identity.same_route(&identity))
            });
        }
        let evidence = self.evidence(extractor_id, evidence_path);
        let expected = detection.recoverability.adjusted_basis_points;
        let presence = self.presence(extractor_id, evidence.clone(), expected);
        let path_fact = self.fact(
            extractor_id,
            FieldClass::PathTemplate,
            ResolutionPolicy::DeclaredBeforeInferred,
            PathTemplateAssertion {
                template: path_template,
                origin,
            },
            evidence.clone(),
            expected,
        );
        let query_parameters = unique_names(query_names)
            .into_iter()
            .map(|name| QueryParameter {
                name: apiaxess_api_model::ParameterName::new(name).expect("static query name"),
                presence: self.presence(extractor_id, evidence.clone(), expected),
                schema: self.schema(extractor_id, evidence.clone(), expected),
                requiredness: self.fact(
                    extractor_id,
                    FieldClass::Requiredness,
                    ResolutionPolicy::SampleGated,
                    apiaxess_api_model::RequirednessAssertion::Declared { required: false },
                    evidence.clone(),
                    expected,
                ),
            })
            .collect();
        let path_parameters = unique_names(path_names)
            .into_iter()
            .map(|name| PathParameter {
                name: apiaxess_api_model::ParameterName::new(name).expect("static path name"),
                presence: self.presence(extractor_id, evidence.clone(), expected),
                schema: self.schema(extractor_id, evidence.clone(), expected),
            })
            .collect();
        let headers = unique_names(header_names)
            .into_iter()
            .map(|name| HeaderParameter {
                name: apiaxess_api_model::ParameterName::new(name).expect("static header name"),
                presence: self.presence(extractor_id, evidence.clone(), expected),
                schema: self.schema(extractor_id, evidence.clone(), expected),
            })
            .collect();
        // Only associate a discovered base URL when there is a single unambiguous
        // one. In a multi-SDK app the string pool holds several base URLs (Juspay,
        // Razorpay, Firebase, …); gluing an arbitrary one onto a path that had no
        // base of its own fabricates a wrong endpoint (the classic
        // `assets.juspay.in/.well-known/oauth/...` mis-pairing). When ambiguous,
        // leave the base unresolved — an honest "path known, host unknown" — rather
        // than assert a host the path was never seen with.
        let base_url = base_url.or_else(|| self.sole_discovered_base_url());
        let base_url_fact = base_url.map(|value| {
            self.bound_values.insert(value.clone());
            self.fact(
                extractor_id,
                FieldClass::Scalar,
                ResolutionPolicy::Explicit,
                value,
                evidence.clone(),
                expected,
            )
        });
        self.bound_values.insert(path.clone());
        for name in query_names.iter().chain(path_names).chain(header_names) {
            self.bound_values.insert(name.clone());
        }
        let request_body = match body {
            StaticBody::Absent => None,
            StaticBody::Opaque => Some(self.schema(extractor_id, evidence.clone(), expected)),
            StaticBody::Fields(fields) => {
                Some(self.body_schema(extractor_id, &evidence, expected, fields))
            }
        };
        self.endpoints.push(Endpoint {
            identity,
            base_url: base_url_fact,
            presence,
            path_template: path_fact,
            query_parameters,
            path_parameters,
            headers,
            authentication: None,
            request_body,
            request_media_type: None,
            responses: Vec::new(),
            pagination_signals: Vec::new(),
        });
    }

    fn add_operation(
        &mut self,
        extractor_id: &str,
        detection: &LibraryDetection,
        identity: ProtocolOperationIdentity,
        evidence_path: &str,
    ) {
        if self.operations.iter().any(|operation| {
            operation.identity == identity
                || same_graphql_operation_unbound(&identity, &operation.identity)
        }) {
            return;
        }
        // A GraphQL operation bound to the URL it is posted to supersedes a
        // view of it that could not see the URL (a bare document literal).
        if let ProtocolOperationIdentity::GraphQl {
            endpoint_url: Some(_),
            ..
        } = &identity
        {
            self.operations.retain(|operation| {
                !same_graphql_operation_unbound(&operation.identity, &identity)
            });
        }
        let evidence = self.evidence(extractor_id, evidence_path);
        let expected = detection.recoverability.adjusted_basis_points;
        let presence = self.presence(extractor_id, evidence.clone(), expected);
        let request_body = Some(self.schema(extractor_id, evidence.clone(), expected));
        let response_body = Some(self.schema(extractor_id, evidence, expected));
        self.operations.push(ProtocolOperation {
            identity,
            presence,
            request_body,
            response_body,
        });
    }

    /// Records the GraphQL operations a call site posts: the named
    /// operations of the literal `query` document, or the literal
    /// `operationName` when the document is not literal.
    fn add_graphql_call(
        &mut self,
        extractor_id: &str,
        detection: &LibraryDetection,
        call: &java_scope::ResolvedCall,
        evidence_path: &str,
    ) {
        let Some(BodyRef::Keys(keys)) = &call.body else {
            return;
        };
        let literal = |name: &str| {
            keys.iter()
                .find(|key| key.name == name)
                .and_then(|key| key.literal.clone())
        };
        let operation_name = literal("operationName");
        let mut operations = literal("query")
            .map(|document| graphql_operations(&document))
            .unwrap_or_default();
        if let Some(name) = &operation_name {
            // The server executes the operation `operationName` selects.
            operations.retain(|(_, operation)| operation == name);
        }
        let endpoint_url = call
            .base_url
            .as_ref()
            .map(|base| format!("{}{}", base.trim_end_matches('/'), call.path));
        for (operation_type, operation_name) in operations {
            self.add_operation(
                extractor_id,
                detection,
                ProtocolOperationIdentity::GraphQl {
                    endpoint_url: endpoint_url.clone(),
                    operation_type,
                    operation_name,
                },
                evidence_path,
            );
        }
    }

    fn partial(&mut self, library_id: &str, location: &str, reason: &str) {
        self.partial_recoveries.push(PartialRecovery {
            library_id: library_id.to_owned(),
            location: location.to_owned(),
            reason: reason.to_owned(),
            dynamic_recommended: true,
        });
        let mut context = DiagnosticContext::new();
        context.insert(
            "library_id".to_owned(),
            DiagnosticValue::String(library_id.to_owned()),
        );
        context.insert(
            "location".to_owned(),
            DiagnosticValue::String(location.to_owned()),
        );
        let mut diagnostic = EXTRACTION_PARTIAL_RECOVERY.instantiate(context);
        diagnostic.why = reason.to_owned().into_boxed_str();
        self.diagnostics.push(diagnostic);
    }

    fn collect_string(&mut self, kind: LooseFindingKind, value: String, path: String) {
        if !value.trim().is_empty() && self.string_candidate_keys.insert((kind, value.clone())) {
            self.string_candidates
                .push(StaticStringCandidate { kind, value, path });
        }
    }

    fn record_filtered_noise(&mut self, reason: &'static str, candidate: &StaticStringCandidate) {
        let stats = self.filtered_noise.entry(reason).or_default();
        stats.count = stats.count.saturating_add(1);
        if stats.examples.len() < 4 {
            stats.examples.push(format!(
                "{:?}: {} @ {}",
                candidate.kind,
                display_sample(&candidate.value),
                candidate.path
            ));
        }
    }

    fn emit_filtered_noise_diagnostic(&mut self, retained_candidates: usize) {
        if self.filtered_noise.is_empty() {
            return;
        }
        let filtered_count = self
            .filtered_noise
            .values()
            .map(|stats| stats.count)
            .sum::<usize>();
        let mut context = DiagnosticContext::new();
        context.insert(
            "filtered_count".to_owned(),
            DiagnosticValue::Integer(i64::try_from(filtered_count).unwrap_or(i64::MAX)),
        );
        context.insert(
            "retained_candidates".to_owned(),
            DiagnosticValue::Integer(i64::try_from(retained_candidates).unwrap_or(i64::MAX)),
        );
        context.insert(
            "reasons".to_owned(),
            DiagnosticValue::StringList(
                self.filtered_noise
                    .iter()
                    .map(|(reason, stats)| format!("{reason}={}", stats.count))
                    .collect(),
            ),
        );
        context.insert(
            "examples".to_owned(),
            DiagnosticValue::StringList(
                self.filtered_noise
                    .values()
                    .flat_map(|stats| stats.examples.iter().cloned())
                    .collect(),
            ),
        );
        self.diagnostics
            .push(EXTRACTION_LOOSE_FINDINGS_FILTERED.instantiate(context));
    }

    fn retain_non_noise_candidates(&mut self) -> Vec<StaticStringCandidate> {
        let candidates = std::mem::take(&mut self.string_candidates);
        let mut retained = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if let Some(reason) = loose_noise_reason(&candidate) {
                self.record_filtered_noise(reason, &candidate);
            } else {
                retained.push(candidate);
            }
        }
        retained
    }

    /// The single unambiguous discovered base URL, or `None` when there are zero
    /// or several distinct API hosts. Used as an endpoint's base only when there
    /// is exactly one candidate, so a multi-SDK app never mis-glues a path to an
    /// unrelated SDK host. Documentation/attribution hosts are excluded.
    fn sole_discovered_base_url(&self) -> Option<String> {
        let mut distinct: Vec<String> = Vec::new();
        for candidate in &self.string_candidates {
            if candidate.kind != LooseFindingKind::BaseUrl {
                continue;
            }
            let Some(host) = finding_host(&candidate.value) else {
                continue;
            };
            if is_documentation_host(&host) {
                continue;
            }
            if !distinct
                .iter()
                .any(|value| finding_host(value).as_deref() == Some(host.as_str()))
            {
                distinct.push(candidate.value.clone());
            }
        }
        match distinct.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        }
    }

    fn finish(
        mut self,
        artifact: &NormalizedUnpackedArtifact,
        routed: &apiaxess_network_routing::RoutedDetectionMap,
        mut timing: ExtractionTiming,
    ) -> Result<ExtractionReport, ExtractionFailure> {
        if std::env::var_os("APIAXESS_BREAKDOWN_LOOSE").is_some() {
            print_loose_breakdown(&self.string_candidates, &self.bound_values);
        }
        let started = Instant::now();
        let retained_candidates = self.retain_non_noise_candidates();
        timing.loose_finding_filtering_millis = started.elapsed().as_millis();
        self.emit_filtered_noise_diagnostic(retained_candidates.len());
        if profile_static_enabled() {
            eprintln!(
                "STATIC EXTRACTION PHASE: loose_filter_done millis={} filtered={} retained={}",
                timing.loose_finding_filtering_millis,
                self.filtered_noise
                    .values()
                    .map(|stats| stats.count)
                    .sum::<usize>(),
                retained_candidates.len()
            );
        }
        let started = Instant::now();
        for candidate in retained_candidates {
            if self.bound_values.contains(&candidate.value) {
                continue;
            }
            let evidence = self.evidence("string-pool", &candidate.path);
            let expected = 2500;
            let value = self.fact(
                "string-pool",
                FieldClass::Scalar,
                ResolutionPolicy::Explicit,
                candidate.value.clone(),
                evidence,
                expected,
            );
            self.loose_findings.push(LooseFinding {
                kind: candidate.kind,
                value,
            });
            let mut context = DiagnosticContext::new();
            context.insert(
                "value_kind".to_owned(),
                DiagnosticValue::String(format!("{:?}", candidate.kind).to_ascii_lowercase()),
            );
            context.insert("path".to_owned(), DiagnosticValue::String(candidate.path));
            self.diagnostics
                .push(EXTRACTION_UNBOUND_STRING_CANDIDATE.instantiate(context));
        }
        timing.loose_finding_collection_millis = started.elapsed().as_millis();
        if profile_static_enabled() {
            eprintln!(
                "STATIC EXTRACTION PHASE: loose_collection_done millis={} loose_findings={}",
                timing.loose_finding_collection_millis,
                self.loose_findings.len()
            );
        }
        timing.loose_finding_deduplication_millis = self.coalesce_findings();
        if profile_static_enabled() {
            eprintln!(
                "STATIC EXTRACTION PHASE: coalesce_done loose_dedup_millis={} loose_findings={}",
                timing.loose_finding_deduplication_millis,
                self.loose_findings.len()
            );
        }
        let started = Instant::now();
        let surface = ApiSurface {
            provenance: self.provenance,
            endpoints: self.endpoints,
            protocol_operations: self.operations,
            loose_findings: self.loose_findings,
            signers: Vec::new(),
        };
        let document = ApiDocument::new(surface);
        if profile_static_enabled() {
            eprintln!("STATIC EXTRACTION PHASE: model_validate_start");
        }
        if let Err(error) = document.validate() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "model_error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            return Err(ExtractionFailure {
                diagnostic: apiaxess_diagnostics::catalogue::EXTRACTION_MODEL_INVALID
                    .instantiate(context),
            });
        }
        if profile_static_enabled() {
            eprintln!("STATIC EXTRACTION PHASE: model_validate_done");
        }
        let _ = artifact;
        let _ = routed;
        timing.finalization_millis = started.elapsed().as_millis();
        Ok(ExtractionReport {
            document,
            diagnostics: self.diagnostics,
            records: self.records,
            partial_recoveries: self.partial_recoveries,
            timing,
        })
    }

    fn coalesce_findings(&mut self) -> u128 {
        let mut endpoints = Vec::new();
        for endpoint in std::mem::take(&mut self.endpoints) {
            if let Some(existing) = endpoints
                .iter_mut()
                .find(|existing: &&mut Endpoint| existing.identity == endpoint.identity)
            {
                merge_endpoint(existing, endpoint);
            } else {
                endpoints.push(endpoint);
            }
        }
        endpoints.sort_by(|left, right| left.identity.cmp(&right.identity));
        self.endpoints = endpoints;

        let mut operations = Vec::new();
        for operation in std::mem::take(&mut self.operations) {
            if let Some(existing) = operations
                .iter_mut()
                .find(|existing: &&mut ProtocolOperation| existing.identity == operation.identity)
            {
                merge_operation(existing, operation);
            } else {
                operations.push(operation);
            }
        }
        operations.sort_by(|left, right| left.identity.cmp(&right.identity));
        self.operations = operations;

        let loose_started = Instant::now();
        let mut loose_findings: BTreeMap<(LooseFindingKind, String), LooseFinding> =
            BTreeMap::new();
        for finding in std::mem::take(&mut self.loose_findings) {
            let value = finding
                .value
                .selected_candidate()
                .map_or_else(String::new, |candidate| candidate.value.clone());
            let key = (finding.kind, value);
            if let Some(existing) = loose_findings.get_mut(&key) {
                merge_fact(&mut existing.value, finding.value);
            } else {
                loose_findings.insert(key, finding);
            }
        }
        let mut loose_findings = loose_findings.into_values().collect::<Vec<_>>();
        // Within a kind, rank genuine API hosts ahead of documentation/
        // attribution hosts so the surfaced findings lead with likely-API bases.
        loose_findings.sort_by(|left, right| {
            let key = |finding: &LooseFinding| {
                let text = selected_text(&finding.value);
                let is_doc = finding_host(&text).is_some_and(|host| is_documentation_host(&host));
                (finding.kind, is_doc, text)
            };
            key(left).cmp(&key(right))
        });
        self.loose_findings = loose_findings;
        loose_started.elapsed().as_millis()
    }
}

fn print_loose_breakdown(candidates: &[StaticStringCandidate], bound_values: &BTreeSet<String>) {
    let mut kind_counts = BTreeMap::<LooseFindingKind, usize>::new();
    let mut source_counts = BTreeMap::<String, usize>::new();
    let mut host_counts = BTreeMap::<String, usize>::new();
    let mut bound = 0usize;
    let mut samples = BTreeMap::<LooseFindingKind, Vec<String>>::new();

    for candidate in candidates {
        *kind_counts.entry(candidate.kind).or_default() += 1;
        *source_counts
            .entry(source_bucket(&candidate.path))
            .or_default() += 1;
        if bound_values.contains(&candidate.value) {
            bound += 1;
        }
        if let Some(host) = url_host(&candidate.value) {
            *host_counts.entry(host).or_default() += 1;
        }
        let values = samples.entry(candidate.kind).or_default();
        if values.len() < 8 && !values.contains(&candidate.value) {
            values.push(candidate.value.clone());
        }
    }

    eprintln!(
        "STATIC LOOSE BREAKDOWN: candidates={} bound={} loose={} kinds={:?} sources={:?}",
        candidates.len(),
        bound,
        candidates.len().saturating_sub(bound),
        kind_counts,
        source_counts
    );
    eprintln!(
        "STATIC LOOSE BREAKDOWN: top_hosts={:?}",
        top_counts(&host_counts, 20)
    );
    for (kind, values) in samples {
        let display_values = values
            .iter()
            .map(|value| display_sample(value))
            .collect::<Vec<_>>();
        eprintln!("STATIC LOOSE BREAKDOWN: samples kind={kind:?} values={display_values:?}");
    }
}

fn display_sample(value: &str) -> String {
    let mut displayed = value
        .chars()
        .take(160)
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>();
    if value.chars().count() > 160 {
        displayed.push('…');
    }
    displayed
}

fn source_bucket(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if let Some(marker) = std::env::var_os("APIAXESS_BREAKDOWN_TARGET_MARKER") {
        let marker = marker.to_string_lossy().to_ascii_lowercase();
        if !marker.is_empty() && lower.contains(&marker) {
            return "target-package".to_owned();
        }
    }
    if lower.contains("!/res/") || lower.contains("\\res\\") {
        "resources".to_owned()
    } else if lower.contains("!/assets/") || lower.contains("\\assets\\") {
        "assets".to_owned()
    } else if lower.contains("/androidx/")
        || lower.contains("\\androidx\\")
        || lower.contains("/kotlin/")
        || lower.contains("\\kotlin\\")
        || lower.contains("/com/google/")
        || lower.contains("\\com\\google\\")
        || lower.contains("/com/squareup/")
        || lower.contains("\\com\\squareup\\")
        || lower.contains("/okhttp/")
        || lower.contains("\\okhttp\\")
    {
        "third-party-or-platform".to_owned()
    } else if lower.contains("!/meta-inf/") || lower.contains("\\meta-inf\\") {
        "archive-metadata".to_owned()
    } else {
        "other-code-or-binary".to_owned()
    }
}

/// Classifies only source locations whose contents are unambiguously packaged
/// data or binary support tables. Code, DEX, JavaScript, HTML, and ordinary
/// XML/resource candidates remain loose evidence because they may contain a
/// real endpoint or parameter. This is intentionally a source-level filter:
/// it does not inspect, rewrite, or promote endpoint facts.
fn loose_noise_reason(candidate: &StaticStringCandidate) -> Option<&'static str> {
    if candidate.kind == LooseFindingKind::Path && is_jvm_descriptor_path(&candidate.value) {
        return Some("jvm-descriptor");
    }
    let path = candidate.path.to_ascii_lowercase().replace('\\', "/");
    let member = path
        .rsplit_once("!/")
        .map_or(path.as_str(), |(_, member)| member);
    let file_name = member.rsplit('/').next().unwrap_or(member);
    let extension = file_name
        .rsplit_once('.')
        .map_or("", |(_, extension)| extension);

    if member.starts_with("meta-inf/")
        || file_name.ends_with(".kotlin_module")
        || file_name.ends_with(".version")
    {
        return Some("packaged-metadata");
    }

    if member.starts_with("lib/")
        || matches!(
            extension,
            "arsc" | "bin" | "brk" | "dat" | "dict" | "icu" | "nrm" | "res" | "so"
        )
        || member.contains("/com/ibm/icu/")
    {
        return Some("binary-support-data");
    }

    // Android resource JSON/CSV files are often bundled catalogs or seed
    // databases. Keep assets and XML resource values eligible: those are
    // common WebView/API configuration carriers and remain ambiguous.
    if member.starts_with("res/") && matches!(extension, "csv" | "json" | "tsv") {
        return Some("packaged-resource-data");
    }

    // The same rule also covers a materialized apktool resource root.
    if path.contains("/res/") && matches!(extension, "csv" | "json" | "tsv") {
        return Some("packaged-resource-data");
    }

    let _ = candidate.kind;
    None
}

/// Whether a path is a filesystem/kernel path misread as an HTTP endpoint rather
/// than a real API route.
///
/// High precision, so real API routes are never dropped (requirement: preserve
/// real static signal):
/// - The kernel pseudo-filesystems `/sys`, `/proc`, `/dev` are never HTTP roots.
/// - Deeper Android/Unix filesystem signatures (`/data/data/`, `/system/bin`,
///   `/storage/emulated`, `/sdcard/`, …) confirm a real path, not an API resource
///   that merely shares a first word (so `/data/users` — a plausible API — stays).
/// - The JVM class-descriptor form is not an HTTP path.
fn is_non_http_path(path: &str) -> bool {
    let raw = path.trim();
    // JVM descriptor form (`Lcom/foo/Bar;`) — check before lowercasing, its `L`
    // prefix and `;` suffix are case-significant.
    if is_jvm_descriptor_path(raw) {
        return true;
    }
    // Decompiler string-literal artifacts that are not real request paths: log
    // lines and code comments (contain whitespace), HTML/markup fragments, format
    // strings, and `toString()` shrapnel. A real HTTP path template never contains
    // whitespace or these structural characters. `{`/`}` are intentionally allowed
    // so genuine Retrofit templates like `/users/{id}` survive.
    if raw
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '=' | '"' | '\\'))
    {
        return true;
    }
    // printf/format specifiers (`%s`, `%d`, `%1$s`, `%@`): a real percent-escape is
    // `%` followed by two hex digits, so a `%` followed by anything else is a
    // format string, not a path.
    if let Some(rest) = raw.split_once('%').map(|(_, rest)| rest) {
        let is_hex_escape = rest.as_bytes().first().is_some_and(u8::is_ascii_hexdigit)
            && rest.as_bytes().get(1).is_some_and(u8::is_ascii_hexdigit);
        if !is_hex_escape {
            return true;
        }
    }
    let lower = raw.to_ascii_lowercase();
    // A lone segment that is exactly an HTTP header name or protocol keyword is a
    // string-constant artifact, not an endpoint. Kept deliberately narrow so common
    // single-segment API roots (`/videos`, `/login`) are never caught.
    let single = lower.trim_start_matches('/').trim_end_matches('/');
    if !single.contains('/')
        && matches!(
            single,
            "authorization"
                | "host"
                | "location"
                | "accept"
                | "accept-type"
                | "accept-encoding"
                | "content-type"
                | "content-length"
                | "user-agent"
                | "cookie"
                | "set-cookie"
                | "www-authenticate"
                | "cache-control"
                | "connection"
                | "http"
                | "https"
                | "websocket"
        )
    {
        return true;
    }
    let segments: Vec<&str> = lower
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let first = segments.first().copied().unwrap_or("");
    // Kernel pseudo-filesystems and single-root mounts: never HTTP roots.
    if matches!(
        first,
        "sys" | "proc" | "dev" | "sdcard" | "mnt" | "acct" | "apex" | "dalvik-cache"
    ) {
        return true;
    }
    // Two-segment filesystem prefixes matched by *segment equality* so a real API
    // that merely shares a first word is not caught (e.g. `/data/users` and
    // `/system/status` stay, while `/data/user/0` and `/system/bin/sh` are cut).
    let second = segments.get(1).copied().unwrap_or("");
    matches!(
        (first, second),
        ("data", "data" | "app" | "user" | "local" | "dalvik-cache")
            | (
                "system",
                "bin" | "xbin" | "lib" | "lib64" | "framework" | "app" | "priv-app" | "etc"
            )
            | ("vendor", "lib" | "bin" | "etc")
            | ("storage", "emulated")
    )
}

/// A slash-prefixed class descriptor cannot be an HTTP path. Ordinary short
/// paths such as `/v1/a` stay eligible; only the unambiguous JVM form is
/// rejected.
fn is_jvm_descriptor_path(value: &str) -> bool {
    let value = value.trim_start_matches('/');
    value.ends_with(';')
        && value.strip_prefix('L').is_some_and(|class| {
            class.contains('/')
                && class.trim_end_matches(';').split('/').all(|segment| {
                    !segment.is_empty()
                        && segment.chars().all(|character| {
                            character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
                        })
                })
        })
}

fn url_host(value: &str) -> Option<String> {
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    Some(
        authority
            .split(['/', ':'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase(),
    )
}

/// The host of a URL or bare-domain finding value, for classification/ranking.
fn finding_host(value: &str) -> Option<String> {
    url_host(value).or_else(|| {
        let host = value.trim().to_ascii_lowercase();
        (!host.is_empty() && host.contains('.') && !host.contains('/')).then_some(host)
    })
}

/// Whether a host is documentation, attribution, schema, license, or SDK
/// infrastructure — not the app's own API. Genuine API bases are ranked ahead of
/// these; they are kept (observed), never fabricated away.
fn is_documentation_host(host: &str) -> bool {
    const DOC_HOSTS: &[&str] = &[
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "w3.org",
        "apache.org",
        "schemas.android.com",
        "xmlpull.org",
        "json-schema.org",
        "opensource.org",
        "creativecommons.org",
        "gnu.org",
        "oracle.com",
        "kotlinlang.org",
        "readthedocs.io",
        "wikipedia.org",
        "mozilla.org",
        "stackoverflow.com",
        "medium.com",
        "ietf.org",
        "rfc-editor.org",
        "unicode.org",
        "slf4j.org",
        "sun.com",
        "xml.org",
        "dagger.dev",
        "reactivex.io",
        "example.com",
        "example.org",
        "localhost",
    ];
    if host.starts_with("docs.")
        || host.starts_with("developer.")
        || host.starts_with("support.")
        || host.starts_with("help.")
        || host.starts_with("schemas.")
        || host.starts_with("schema.")
        || host.ends_with(".github.io")
    {
        return true;
    }
    DOC_HOSTS
        .iter()
        .any(|doc| host == *doc || host.ends_with(&format!(".{doc}")))
}

/// The Jetpack Compose `LinkAnnotation.Url(url=` decompiler artifact, matched on
/// its own so it can be rejected even at the endpoint-path stage where a real
/// templated path legitimately contains `{`/`}` placeholders.
fn is_compose_annotation_artifact(value: &str) -> bool {
    value.contains("LinkAnnotation.Url(") || value.contains("Annotation.Url(")
}

/// Whether a URL candidate is decompiler/parse noise rather than a real URL:
/// the consistent `LinkAnnotation.Url(url=` Compose artifact, or characters that
/// can never appear unencoded in a URL (over-captured adjacent source text).
///
/// Only for raw URL/path *candidate* strings — not for an already-templated
/// endpoint path, whose `{name}` placeholders would trip the character check.
fn is_url_extraction_artifact(value: &str) -> bool {
    is_compose_annotation_artifact(value)
        || value.chars().any(|character| {
            matches!(
                character,
                ' ' | '"' | '\'' | '`' | '<' | '>' | '{' | '}' | '|' | '\\' | '^'
            )
        })
}

fn top_counts(counts: &BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut values = counts
        .iter()
        .map(|(key, count)| (key.clone(), *count))
        .collect::<Vec<_>>();
    values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    values.truncate(limit);
    values
}

fn merge_fact<T>(target: &mut Fact<T>, source: Fact<T>) {
    for candidate in source.candidates {
        if !target
            .candidates
            .iter()
            .any(|existing| existing.id == candidate.id)
        {
            target.candidates.push(candidate);
        }
    }
    for merge in source.merges {
        if !target.merges.contains(&merge) {
            target.merges.push(merge);
        }
    }
}

fn merge_schema(target: &mut SchemaSlot, source: SchemaSlot) {
    merge_fact(&mut target.shape, source.shape);
    for observation in source.observations {
        if !target.observations.contains(&observation) {
            target.observations.push(observation);
        }
    }
}

fn merge_endpoint(target: &mut Endpoint, source: Endpoint) {
    merge_fact(&mut target.presence, source.presence);
    if target.request_media_type.is_none() {
        target
            .request_media_type
            .clone_from(&source.request_media_type);
    }
    merge_fact(&mut target.path_template, source.path_template);
    match (&mut target.base_url, source.base_url) {
        (Some(target), Some(source)) => merge_fact(target, source),
        (None, source) => target.base_url = source,
        (Some(_), None) => {}
    }
    for parameter in source.query_parameters {
        if let Some(existing) = target
            .query_parameters
            .iter_mut()
            .find(|existing| existing.name == parameter.name)
        {
            merge_fact(&mut existing.presence, parameter.presence);
            merge_schema(&mut existing.schema, parameter.schema);
            merge_fact(&mut existing.requiredness, parameter.requiredness);
        } else {
            target.query_parameters.push(parameter);
        }
    }
    for parameter in source.path_parameters {
        if let Some(existing) = target
            .path_parameters
            .iter_mut()
            .find(|existing| existing.name == parameter.name)
        {
            merge_fact(&mut existing.presence, parameter.presence);
            merge_schema(&mut existing.schema, parameter.schema);
        } else {
            target.path_parameters.push(parameter);
        }
    }
    for header in source.headers {
        if let Some(existing) = target
            .headers
            .iter_mut()
            .find(|existing| existing.name == header.name)
        {
            merge_fact(&mut existing.presence, header.presence);
            merge_schema(&mut existing.schema, header.schema);
        } else {
            target.headers.push(header);
        }
    }
    match (&mut target.authentication, source.authentication) {
        (Some(target), Some(source)) => merge_fact(target, source),
        (None, source) => target.authentication = source,
        (Some(_), None) => {}
    }
    match (&mut target.request_body, source.request_body) {
        (Some(target), Some(source)) => merge_schema(target, source),
        (None, source) => target.request_body = source,
        (Some(_), None) => {}
    }
    for response in source.responses {
        if let Some(existing) = target
            .responses
            .iter_mut()
            .find(|existing| existing.selector == response.selector)
        {
            merge_fact(&mut existing.presence, response.presence);
            merge_schema(&mut existing.body, response.body);
        } else {
            target.responses.push(response);
        }
    }
}

fn merge_operation(target: &mut ProtocolOperation, source: ProtocolOperation) {
    merge_fact(&mut target.presence, source.presence);
    match (&mut target.request_body, source.request_body) {
        (Some(target), Some(source)) => merge_schema(target, source),
        (None, source) => target.request_body = source,
        (Some(_), None) => {}
    }
    match (&mut target.response_body, source.response_body) {
        (Some(target), Some(source)) => merge_schema(target, source),
        (None, source) => target.response_body = source,
        (Some(_), None) => {}
    }
}

fn selected_text(fact: &Fact<String>) -> String {
    fact.selected_candidate()
        .map_or_else(String::new, |candidate| candidate.value.clone())
}

struct StringPoolExtractor;

impl StringPoolExtractor {
    fn extract_global(corpus: &SignatureCorpus, builder: &mut ModelBuilder) {
        let mut documents = 0usize;
        let mut classified = 0usize;
        corpus.for_each_text(|document, text| {
            // For indexed APKs, the archive's DEX/resources are the
            // authoritative global string pool. Materialized smali/jadx
            // views are retained only for targeted structured extractors;
            // rescanning them here duplicates the same constants and brings
            // back the large-app CPU cliff.
            if corpus.has_indexed_archives()
                && matches!(
                    document.source_kind,
                    SourceKind::Smali | SourceKind::DecompiledSource
                )
            {
                return;
            }
            documents += 1;
            for literal in document_string_literals(document, text) {
                if let Some(kind) = classify_string(&literal) {
                    classified += 1;
                    builder.collect_string(kind, literal, document.path.clone());
                }
            }
            if profile_static_enabled() && documents % 1_000 == 0 {
                eprintln!(
                    "STATIC EXTRACTION PHASE: string_pool_progress documents={} classified={} candidates={}",
                    documents,
                    classified,
                    builder.string_candidates.len()
                );
            }
        });
        if profile_static_enabled() {
            eprintln!(
                "STATIC EXTRACTION PHASE: string_pool_scan_complete documents={} classified={} candidates={}",
                documents,
                classified,
                builder.string_candidates.len()
            );
        }
    }
}

fn profile_static_enabled() -> bool {
    std::env::var_os("APIAXESS_PROFILE_STATIC").is_some()
}

struct RetrofitExtractor;
struct KtorExtractor;
struct GrpcExtractor;
struct ApolloExtractor;
struct OkHttpExtractor;
struct VolleyExtractor;
struct ApacheExtractor;
struct HttpUrlConnectionExtractor;
struct WebViewExtractor;
struct RawSocketExtractor;

macro_rules! simple_id {
    ($type:ty, $id:literal) => {
        impl ProtocolDecoderExtractor for $type {
            fn protocol_decoder_id(&self) -> &'static str {
                $id
            }

            fn extract(
                &self,
                detection: &LibraryDetection,
                corpus: &SignatureCorpus,
                builder: &mut ModelBuilder,
            ) {
                extract_simple_url_calls(detection, corpus, builder, $id);
            }
        }
    };
}

impl ProtocolDecoderExtractor for RetrofitExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "retrofit"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        // Each service interface resolves against the base URL of the
        // Retrofit instance that created it, never an app-wide guess.
        let service_bases = retrofit_service_bases(corpus);
        let mut dtos = DtoIndex::new(corpus);
        // Routing evidence can originate in indexed DEX while the explicit
        // method/path pairing lives in apktool's decoded service interface.
        // Scan only decoded source views that themselves carry a Retrofit
        // annotation; an endpoint still requires an explicit method and path.
        for document in corpus.documents().iter().filter(|document| {
            matches!(
                document.source_kind,
                SourceKind::Smali | SourceKind::DecompiledSource
            ) && corpus.text_for(document).is_some_and(|text| {
                text.contains("retrofit2/http/") || text.contains("retrofit2.http.")
            })
        }) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            let service = match document.source_kind {
                SourceKind::Smali => java_scope::smali_class_name(&text),
                SourceKind::DecompiledSource => java_scope::java_class_name(&document.path, &text),
                _ => None,
            };
            let service_base = service
                .as_ref()
                .and_then(|service| service_bases.get(service).cloned().flatten());
            for block in method_blocks(&text) {
                let body_type = retrofit_smali_body_type(&block);
                let mut route = None;
                let mut queries = Vec::new();
                let mut paths = Vec::new();
                let mut headers = Vec::new();
                let mut body = false;
                for (annotation, content) in annotation_blocks(&block) {
                    let value = first_quoted(&content).unwrap_or_default();
                    match annotation.as_str() {
                        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" => {
                            route = Some((annotation, value));
                        }
                        "Query" => queries.push(value),
                        "Path" => paths.push(value),
                        "Header" | "Headers" => {
                            if !value.is_empty() {
                                headers.push(value);
                            }
                        }
                        "Body" => body = true,
                        _ => {}
                    }
                }
                if let Some((method, route)) = route {
                    let (base_url, path) = resolve_retrofit_route(service_base.as_deref(), &route);
                    let body = match (&body_type, &service) {
                        (Some(class), Some(service)) => dtos.body(class, service),
                        _ if body => StaticBody::Opaque,
                        _ => StaticBody::Absent,
                    };
                    builder.add_rest(
                        "retrofit",
                        detection,
                        &method,
                        &path,
                        PathTemplateOrigin::Declared,
                        base_url,
                        &queries,
                        &paths,
                        &headers,
                        &body,
                        &document.path,
                    );
                }
            }
        }

        // R8 can rename Retrofit's runtime-retained annotation classes while
        // leaving the service interface and its path literals intact.  Tusky,
        // for example, decompiles these as `@ol.f("api/...")` and
        // `@o("api/...")`; neither the Java document nor its method boundaries
        // contains the original `retrofit2.http` spelling.  Preserve the
        // structural requirement (an annotation immediately attached to an
        // interface method) and decode the stable Retrofit annotation shape.
        // This is deliberately limited to route-looking literals, so arbitrary
        // annotated application methods cannot become invented endpoints.
        for document in corpus.documents().iter().filter(|document| {
            matches!(document.source_kind, SourceKind::DecompiledSource)
                && corpus
                    .text_for(document)
                    .is_some_and(|text| text.contains("api/v") || text.contains("oauth/"))
        }) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            for (method, path) in obfuscated_retrofit_routes(&text) {
                builder.add_rest(
                    "retrofit",
                    detection,
                    &method,
                    &path,
                    PathTemplateOrigin::Declared,
                    None,
                    &[],
                    &placeholders(&path),
                    &[],
                    &StaticBody::Absent,
                    &document.path,
                );
            }
        }
    }
}

/// The declared type of a smali Retrofit method's `@Body` parameter, as a
/// dotted class name (`.param pN # La/b/Dto;` carrying `Lretrofit2/http/Body;`).
fn retrofit_smali_body_type(block: &str) -> Option<String> {
    let mut param_type = None;
    for line in block.lines() {
        let line = line.trim();
        if line.starts_with(".param ") {
            param_type = line
                .split_once('#')
                .map(|(_, descriptor)| descriptor.trim())
                .and_then(|descriptor| descriptor.strip_prefix('L'))
                .and_then(|descriptor| descriptor.strip_suffix(';'))
                .map(|internal| internal.replace(['/', '$'], "."));
        } else if line.starts_with(".end param") {
            param_type = None;
        } else if line.contains("Lretrofit2/http/Body;") && param_type.is_some() {
            return param_type;
        }
    }
    None
}

/// Maps each Retrofit service interface to the base URL of the instance that
/// created it (`new Retrofit.Builder().baseUrl(..).build().create(S.class)`).
/// A service is bound only when every creation site agrees on one resolved
/// base; an unresolved or conflicting base leaves it unbound (`None`).
fn retrofit_service_bases(corpus: &SignatureCorpus) -> BTreeMap<String, Option<String>> {
    let paths = corpus
        .hits_for(&["retrofit2.retrofit"])
        .into_iter()
        .filter(|hit| hit.source_kind == SourceKind::DecompiledSource)
        .map(|hit| hit.path)
        .collect::<BTreeSet<_>>();
    let mut constants = java_scope::ConstantIndex::new(corpus);
    let mut bases = BTreeMap::<String, BTreeSet<Option<String>>>::new();
    for document in corpus
        .documents()
        .iter()
        .filter(|document| paths.contains(&document.path))
    {
        let Some(text) = corpus.text_for(document) else {
            continue;
        };
        for binding in java_scope::retrofit_bindings(document, &text, &mut constants) {
            bases
                .entry(binding.service)
                .or_default()
                .insert(binding.base_url);
        }
    }
    bases
        .into_iter()
        .map(|(service, bases)| {
            let base = match bases.into_iter().collect::<Vec<_>>().as_slice() {
                [Some(base)] => Some(base.clone()),
                _ => None,
            };
            (service, base)
        })
        .collect()
}

/// Resolves a Retrofit route against its instance's base URL the way
/// Retrofit (`HttpUrl.resolve`) does: an absolute route stands alone, a
/// root-relative route (`/x`) replaces the base path, and a relative route
/// is appended to the base path's directory. Returns the origin and path.
fn resolve_retrofit_route(base: Option<&str>, route: &str) -> (Option<String>, String) {
    if route.contains("://") {
        return split_url(route);
    }
    let Some((Some(origin), base_path)) = base.map(split_url) else {
        return (None, route.to_owned());
    };
    if route.starts_with('/') {
        return (Some(origin), route.to_owned());
    }
    let directory = match base_path.rfind('/') {
        Some(index) => &base_path[..=index],
        None => "/",
    };
    (Some(origin), format!("{directory}{route}"))
}

/// Recovers route annotations from a decompiled, R8-obfuscated Retrofit
/// interface.  Retrofit's built-in annotations are often shortened to one
/// letter; their method/path payload remains runtime-visible in Java output.
fn obfuscated_retrofit_routes(text: &str) -> Vec<(String, String)> {
    let mut routes = Vec::new();
    let mut pending = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(annotation) = trimmed.strip_prefix('@') {
            let name = annotation
                .split_once('(')
                .map_or(annotation, |(name, _)| name)
                .rsplit('.')
                .next()
                .unwrap_or_default();
            let route = match name {
                // Tusky's R8 mappings for Retrofit GET/DELETE/PUT/PATCH/POST.
                "f" => first_quoted(annotation).map(|path| ("GET".to_owned(), path)),
                "b" => first_quoted(annotation).map(|path| ("DELETE".to_owned(), path)),
                "p" => first_quoted(annotation).map(|path| ("PUT".to_owned(), path)),
                "n" => first_quoted(annotation).map(|path| ("PATCH".to_owned(), path)),
                "o" => first_quoted(annotation).map(|path| ("POST".to_owned(), path)),
                // Retrofit's generic HTTP annotation keeps explicit members.
                "h" => named_quoted(annotation, "method").zip(named_quoted(annotation, "path")),
                _ => None,
            };
            if let Some((method, path)) = route
                && (path.starts_with("api/")
                    || path.starts_with("/api/")
                    || path.starts_with("oauth/"))
            {
                pending.push((method, path));
            }
            continue;
        }
        if (trimmed.starts_with("Object ") || trimmed.starts_with("fun ")) && trimmed.contains('(')
        {
            routes.append(&mut pending);
        } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
            pending.clear();
        }
    }
    routes
}

fn named_quoted(text: &str, name: &str) -> Option<String> {
    let (_, value) = text.split_once(name)?;
    first_quoted(value)
}

impl ProtocolDecoderExtractor for KtorExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "ktor-client"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        for document in matching_documents(detection, corpus) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            let methods = http_methods(&text);
            for block in annotation_blocks(&text)
                .into_iter()
                .filter(|(name, _)| name == "Resource")
            {
                let path = first_quoted(&block.1).unwrap_or_else(|| "/".to_owned());
                let path_names = placeholders(&path);
                for method in &methods {
                    builder.add_rest(
                        "ktor-client",
                        detection,
                        method,
                        &path,
                        PathTemplateOrigin::Declared,
                        None,
                        &[],
                        &path_names,
                        &[],
                        &StaticBody::Absent,
                        &document.path,
                    );
                }
            }
        }
    }
}

impl ProtocolDecoderExtractor for GrpcExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "grpc-java"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        for document in matching_documents(detection, corpus) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            for line in text.lines() {
                let strings = document_string_literals(document, line);
                if line.contains("generateFullMethodName") && strings.len() >= 2 {
                    // `generateFullMethodName(service, method)` — but decompiled token
                    // order is unreliable and the surrounding line often yields
                    // non-literal tokens (Kotlin `$lambda$0` synthetics, member names).
                    // Only emit when the pair validates as a real gRPC service+method,
                    // orienting by shape (the service is package-qualified, the method
                    // is a bare proto identifier) so swapped captures are corrected and
                    // synthetic-name garbage is dropped.
                    if let Some((service, method)) = orient_grpc_pair(&strings[0], &strings[1]) {
                        builder.add_operation(
                            "grpc-java",
                            detection,
                            ProtocolOperationIdentity::Grpc { service, method },
                            &document.path,
                        );
                    }
                } else if let Some((service, method)) = grpc_path(line) {
                    builder.add_operation(
                        "grpc-java",
                        detection,
                        ProtocolOperationIdentity::Grpc { service, method },
                        &document.path,
                    );
                }
            }
        }
    }
}

impl ProtocolDecoderExtractor for ApolloExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "graphql-apollo"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        for document in matching_documents(detection, corpus) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            let mut found = false;
            for line in text.lines() {
                for literal in document_string_literals(document, line) {
                    // The endpoint a document is posted to is only known at
                    // its call site (see the method-scoped resolver); a URL
                    // elsewhere in the file is not evidence of it.
                    for (kind, name) in graphql_operations(&literal) {
                        builder.add_operation(
                            "graphql-apollo",
                            detection,
                            ProtocolOperationIdentity::GraphQl {
                                endpoint_url: None,
                                operation_type: kind,
                                operation_name: name,
                            },
                            &document.path,
                        );
                        found = true;
                    }
                }
            }
            if !found {
                let stem = Path::new(&document.path)
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default();
                // Only Apollo-codegen operation classes follow the `*Query` /
                // `*Mutation` / `*Subscription` naming convention. A bare class name
                // (`R`, `ChuckerDatabase_Impl`, `HttpTransaction`, `di`) is NOT a
                // GraphQL operation — fabricating a `query <ClassName>` from every
                // matched document is the source of the garbage-operation noise, so
                // the catch-all is removed: no suffix match ⇒ no operation.
                let matched = if stem.ends_with("Mutation") {
                    Some((GraphQlOperationType::Mutation, "Mutation"))
                } else if stem.ends_with("Subscription") {
                    Some((GraphQlOperationType::Subscription, "Subscription"))
                } else if stem.ends_with("Query") {
                    Some((GraphQlOperationType::Query, "Query"))
                } else {
                    None
                };
                if let Some((kind, suffix)) = matched {
                    let name = stem.strip_suffix(suffix).unwrap_or(stem);
                    if !name.is_empty() {
                        builder.add_operation(
                            "graphql-apollo",
                            detection,
                            ProtocolOperationIdentity::GraphQl {
                                endpoint_url: absolute_urls(&text).into_iter().next(),
                                operation_type: kind,
                                operation_name: name.to_owned(),
                            },
                            &document.path,
                        );
                    }
                }
            }
        }
    }
}

impl ProtocolDecoderExtractor for OkHttpExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "okhttp"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        let documents = matching_documents(detection, corpus);
        let covered = extract_java_call_sites(
            detection,
            corpus,
            builder,
            &documents,
            HttpClient::OkHttp,
            "okhttp",
        );
        for (document, text) in fallback_documents(corpus, &documents, &covered) {
            for block in code_method_blocks(document, &text) {
                if !block.to_ascii_lowercase().contains("request$builder")
                    && !block.to_ascii_lowercase().contains(".url")
                    && !block.to_ascii_lowercase().contains("addpathsegment")
                {
                    continue;
                }
                let mut url = find_call_string(&block, ".url");
                let mut path_segments = Vec::new();
                let mut query_names = Vec::new();
                for line in block.lines() {
                    let lower = line.to_ascii_lowercase();
                    if lower.contains("addpathsegment") {
                        if let Some(value) = first_quoted(line) {
                            path_segments.push(value);
                        }
                    }
                    if lower.contains("addqueryparameter") {
                        if let Some(value) = first_quoted(line) {
                            query_names.push(value);
                        }
                    }
                }
                let method = block_http_method(document, &block);
                if let Some(url_value) = url.take() {
                    let (base, mut path) = split_url(&url_value);
                    for segment in path_segments {
                        path.push('/');
                        path.push_str(&segment);
                    }
                    if path.is_empty() {
                        path.clear();
                        path.push('/');
                    }
                    builder.add_rest(
                        "okhttp",
                        detection,
                        &method,
                        &path,
                        PathTemplateOrigin::Inferred,
                        base,
                        &query_names,
                        &placeholders(&path),
                        &[],
                        &StaticBody::Absent,
                        &document.path,
                    );
                } else {
                    builder.partial(
                        &detection.library_id,
                        &document.path,
                        "OkHttp builder construction escaped bounded intra-procedural literal recovery",
                    );
                }
            }
        }
    }
}

/// Resolves hand-built HTTP call sites in decompiled Java one method at a
/// time and records one endpoint per resolved call site. Returns the classes
/// whose Java view was complete, so their smali view is not re-scanned by the
/// coarser fallback (which cannot bind a verb to its call site).
fn extract_java_call_sites(
    detection: &LibraryDetection,
    corpus: &SignatureCorpus,
    builder: &mut ModelBuilder,
    documents: &[&CorpusDocument],
    client: HttpClient,
    extractor_id: &str,
) -> BTreeSet<String> {
    let mut covered = BTreeSet::new();
    let mut constants = java_scope::ConstantIndex::new(corpus);
    let mut dtos = DtoIndex::new(corpus);
    for document in documents
        .iter()
        .filter(|document| document.source_kind == SourceKind::DecompiledSource)
    {
        let Some(text) = corpus.text_for(document) else {
            continue;
        };
        if !java_scope::decompilation_incomplete(&text) {
            if let Some(class) = java_scope::java_class_name(&document.path, &text) {
                covered.insert(class);
            }
        }
        let relevant = match client {
            HttpClient::OkHttp => text.contains("Builder"),
            HttpClient::UrlConnection => text.contains("openConnection"),
        };
        if !relevant {
            continue;
        }
        for site in java_scope::resolve_call_sites(document, &text, &mut constants) {
            if site.client() != client {
                continue;
            }
            if let CallSite::Resolved(call) = &site {
                builder.add_graphql_call(extractor_id, detection, call, &document.path);
            }
            match site {
                CallSite::Resolved(call) => builder.add_rest(
                    extractor_id,
                    detection,
                    &call.method,
                    &call.path,
                    PathTemplateOrigin::Inferred,
                    call.base_url,
                    &call.query_names,
                    &placeholders(&call.path),
                    &call.header_names,
                    &match &call.body {
                        Some(BodyRef::Keys(keys)) => StaticBody::from_keys(keys),
                        Some(BodyRef::Class { class, anchor }) => dtos.body(class, anchor),
                        None if call.has_body => StaticBody::Opaque,
                        None => StaticBody::Absent,
                    },
                    &document.path,
                ),
                CallSite::Unresolved {
                    method_name,
                    missing,
                    ..
                } => {
                    let what = match missing {
                        java_scope::Missing::Url => "request URL",
                        java_scope::Missing::Verb => "HTTP method",
                    };
                    builder.partial(
                        &detection.library_id,
                        &document.path,
                        &format!(
                            "{what} in method `{method_name}` is not recoverable inside that method"
                        ),
                    );
                }
            }
        }
    }
    covered
}

/// Non-Java documents still worth the coarse per-method scan: smali whose
/// class has no complete decompiled Java view, plus any other source kind.
/// Documents are loaded one at a time as the caller iterates.
fn fallback_documents<'a>(
    corpus: &'a SignatureCorpus,
    documents: &'a [&'a CorpusDocument],
    covered: &'a BTreeSet<String>,
) -> impl Iterator<Item = (&'a CorpusDocument, String)> + 'a {
    documents
        .iter()
        .filter(|document| document.source_kind != SourceKind::DecompiledSource)
        .filter_map(|document| {
            let text = corpus.text_for(document)?;
            if document.source_kind == SourceKind::Smali
                && java_scope::smali_outer_class_name(&text)
                    .is_some_and(|class| covered.contains(&class))
            {
                return None;
            }
            Some((*document, text))
        })
}

/// Method-granular blocks for any code view: jadx Java is segmented by its
/// brace structure, smali/Kotlin by their method markers.
fn code_method_blocks(document: &CorpusDocument, text: &str) -> Vec<String> {
    if document.source_kind == SourceKind::DecompiledSource {
        if let Some(methods) = java_scope::java_method_texts(text) {
            return methods;
        }
    }
    method_blocks(text)
}

/// The HTTP verb for a method block, read from the representation's own call
/// shape so a verb is only ever taken from the block it occurs in.
fn block_http_method(document: &CorpusDocument, block: &str) -> String {
    if document.source_kind == SourceKind::Smali {
        smali_http_method(block).unwrap_or_else(|| "GET".to_owned())
    } else {
        http_method_from_text(block)
    }
}

/// Binds a verb inside one smali method: `okhttp3` `Request$Builder` verb calls,
/// `Request$Builder->method(String, ...)` and
/// `HttpURLConnection->setRequestMethod(String)`, following the `const-string`
/// that feeds the argument register. A connection that writes a body with no
/// explicit verb is a POST.
fn smali_http_method(block: &str) -> Option<String> {
    let mut registers = BTreeMap::<String, String>::new();
    let mut verb = None;
    let mut writes_body = false;
    for line in block.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("const-string/jumbo ")
            .or_else(|| line.strip_prefix("const-string "))
        {
            if let (Some((register, _)), Some(value)) = (rest.split_once(','), first_quoted(rest)) {
                registers.insert(register.trim().to_owned(), value);
            }
            continue;
        }
        if !line.starts_with("invoke-") {
            continue;
        }
        let arguments = line
            .split_once('{')
            .and_then(|(_, rest)| rest.split_once('}'))
            .map(|(arguments, _)| {
                arguments
                    .split(',')
                    .map(|register| register.trim().to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let argument_literal = |index: usize| {
            arguments
                .get(index)
                .and_then(|register| registers.get(register))
                .map(|value| value.to_ascii_uppercase())
        };
        if line.contains("Lokhttp3/Request$Builder;->") {
            for candidate in ["get", "head", "post", "put", "patch", "delete"] {
                if line.contains(&format!("Lokhttp3/Request$Builder;->{candidate}("))
                    || line.contains(&format!("Lokhttp3/Request$Builder;->{candidate}$default("))
                {
                    verb = Some(candidate.to_ascii_uppercase());
                }
            }
            if line.contains("Lokhttp3/Request$Builder;->method(") {
                verb = argument_literal(1).or(verb);
            }
        }
        if line.contains("URLConnection;->setRequestMethod(") {
            verb = argument_literal(1).or(verb);
        }
        if line.contains("URLConnection;->setDoOutput(")
            || line.contains("URLConnection;->getOutputStream(")
        {
            writes_body = true;
        }
    }
    verb.or_else(|| writes_body.then(|| "POST".to_owned()))
}

impl ProtocolDecoderExtractor for VolleyExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "volley"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        for document in matching_documents(detection, corpus) {
            let Some(text) = corpus.text_for(document) else {
                continue;
            };
            for block in code_method_blocks(document, &text) {
                let lower = block.to_ascii_lowercase();
                if !lower.contains("stringrequest")
                    && !lower.contains("jsonobjectrequest")
                    && !lower.contains("jsonarrayrequest")
                {
                    continue;
                }
                let url = find_url_literal(&block);
                let queries = call_names(&block, "params.put");
                let headers = call_names(&block, "headers.put");
                if let Some(url) = url {
                    let (base, path) = split_url(&url);
                    builder.add_rest(
                        "volley",
                        detection,
                        &block_http_method(document, &block),
                        &path,
                        PathTemplateOrigin::Inferred,
                        base,
                        &queries,
                        &placeholders(&path),
                        &headers,
                        &StaticBody::Absent,
                        &document.path,
                    );
                } else {
                    builder.partial(
                        &detection.library_id,
                        &document.path,
                        "Volley request URL was constructed outside the bounded local analysis",
                    );
                }
            }
        }
    }
}

simple_id!(ApacheExtractor, "apache-httpclient");
impl ProtocolDecoderExtractor for HttpUrlConnectionExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "httpurlconnection"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        let documents = matching_documents(detection, corpus);
        let covered = extract_java_call_sites(
            detection,
            corpus,
            builder,
            &documents,
            HttpClient::UrlConnection,
            "httpurlconnection",
        );
        let fallback = fallback_documents(corpus, &documents, &covered);
        extract_simple_url_blocks(detection, builder, "httpurlconnection", fallback);
    }
}

simple_id!(WebViewExtractor, "webview-js-bridge");

impl ProtocolDecoderExtractor for RawSocketExtractor {
    fn protocol_decoder_id(&self) -> &'static str {
        "raw-sockets"
    }

    fn extract(
        &self,
        detection: &LibraryDetection,
        corpus: &SignatureCorpus,
        builder: &mut ModelBuilder,
    ) {
        for document in matching_documents(detection, corpus) {
            builder.partial(
                &detection.library_id,
                &document.path,
                "Raw socket protocol and endpoint reconstruction is deferred beyond bounded Phase 1.3 analysis",
            );
        }
    }
}

fn extract_simple_url_calls(
    detection: &LibraryDetection,
    corpus: &SignatureCorpus,
    builder: &mut ModelBuilder,
    extractor_id: &str,
) {
    let documents = matching_documents(detection, corpus)
        .into_iter()
        .filter_map(|document| Some((document, corpus.text_for(document)?)));
    extract_simple_url_blocks(detection, builder, extractor_id, documents);
}

fn extract_simple_url_blocks<'a>(
    detection: &LibraryDetection,
    builder: &mut ModelBuilder,
    extractor_id: &str,
    documents: impl IntoIterator<Item = (&'a CorpusDocument, String)>,
) {
    for (document, text) in documents {
        for block in code_method_blocks(document, &text) {
            let lower = block.to_ascii_lowercase();
            let relevant = match extractor_id {
                "apache-httpclient" => {
                    lower.contains("httpget(")
                        || lower.contains("httppost(")
                        || lower.contains("httpclient.execute")
                }
                "httpurlconnection" => {
                    lower.contains("openconnection") || lower.contains("httpurlconnection")
                }
                "webview-js-bridge" => {
                    lower.contains("loadurl") || lower.contains("evaluatejavascript")
                }
                _ => false,
            };
            if !relevant {
                continue;
            }
            if let Some(url) = find_url_literal(&block) {
                let (base, path) = split_url(&url);
                builder.add_rest(
                    extractor_id,
                    detection,
                    &block_http_method(document, &block),
                    &path,
                    PathTemplateOrigin::Inferred,
                    base,
                    &[],
                    &placeholders(&path),
                    &[],
                    &StaticBody::Absent,
                    &document.path,
                );
            } else {
                builder.partial(
                    &detection.library_id,
                    &document.path,
                    "URL construction escaped bounded intra-procedural literal recovery",
                );
            }
        }
    }
}

fn matching_documents<'a>(
    detection: &LibraryDetection,
    corpus: &'a SignatureCorpus,
) -> Vec<&'a CorpusDocument> {
    let paths = detection
        .evidence
        .iter()
        .map(|hit| PathBuf::from(&hit.path))
        .collect::<Vec<_>>();
    corpus
        .documents()
        .iter()
        .filter(|document| {
            let document_path = Path::new(&document.path);
            paths
                .iter()
                .any(|path| document_path == path || document_path.starts_with(path))
        })
        .collect()
}

fn method_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = Vec::new();
    let mut in_method = false;
    for line in text.lines() {
        if line.trim_start().starts_with(".method") || line.trim_start().starts_with("fun ") {
            if !current.is_empty() {
                blocks.push(current.join("\n"));
            }
            current.clear();
            in_method = true;
        }
        if in_method {
            current.push(line);
        }
        if line.trim_start().starts_with(".end method") {
            blocks.push(current.join("\n"));
            current.clear();
            in_method = false;
        }
    }
    if !current.is_empty() {
        blocks.push(current.join("\n"));
    }
    if blocks.is_empty() {
        vec![text.to_owned()]
    } else {
        blocks
    }
}

fn annotation_blocks(text: &str) -> Vec<(String, String)> {
    let lines = text.lines().collect::<Vec<_>>();
    let mut blocks = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].contains(".annotation") {
            index += 1;
            continue;
        }
        let annotation = annotation_name(lines[index]);
        let mut content = String::new();
        let mut end = index + 1;
        while end < lines.len() && !lines[end].contains(".end annotation") {
            content.push_str(lines[end]);
            content.push('\n');
            end += 1;
        }
        blocks.push((annotation, content));
        index = end.saturating_add(1);
    }
    blocks
}

fn annotation_name(line: &str) -> String {
    for prefix in ["retrofit2/http/", "io/ktor/resources/"] {
        if let Some(start) = line.find(prefix) {
            let value = &line[start + prefix.len()..];
            return value
                .split([';', ' ', '\t'])
                .next()
                .unwrap_or_default()
                .to_owned();
        }
    }
    String::new()
}

fn first_quoted(text: &str) -> Option<String> {
    string_literals(text).into_iter().next()
}

fn string_literals(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        if in_string {
            if escaped {
                current.push(match character {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    other => other,
                });
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                values.push(current.clone());
                current.clear();
                in_string = false;
            } else {
                current.push(character);
            }
        } else if character == '"' {
            in_string = true;
        }
    }
    values
}

fn document_string_literals(document: &CorpusDocument, text: &str) -> Vec<String> {
    let mut values = match document.source_kind {
        // DEX is a binary container. Quoted-string parsing over a lossy
        // UTF-8 rendering can join unrelated bytes into enormous false
        // literals; printable-string extraction is the bounded binary-safe
        // representation for this source kind.
        SourceKind::Dex => printable_strings(text),
        // Resources/assets may be binary (including compiled resources).
        // Only parse quoted literals when the bounded rendering contains no
        // NUL/control bytes; text resources remain fully eligible.
        SourceKind::ResourcesOrAssets if has_binary_controls(text) => Vec::new(),
        SourceKind::Smali | SourceKind::DecompiledSource | SourceKind::ResourcesOrAssets => {
            string_literals(text)
        }
    };
    values.sort();
    values.dedup();
    values
}

fn has_binary_controls(text: &str) -> bool {
    text.chars().any(|character| {
        character == '\0' || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    })
}

fn printable_strings(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if character.is_ascii_graphic() || character == ' ' {
            current.push(character);
        } else if current.len() >= 4 {
            values.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.len() >= 4 {
        values.push(current);
    }
    values
}

fn find_call_string(text: &str, call: &str) -> Option<String> {
    text.lines()
        .find(|line| {
            line.to_ascii_lowercase()
                .contains(&call.to_ascii_lowercase())
        })
        .and_then(first_quoted)
}

fn find_url_literal(text: &str) -> Option<String> {
    string_literals(text).into_iter().find(|value| {
        value.starts_with("http://") || value.starts_with("https://") || value.starts_with('/')
    })
}

fn absolute_urls(text: &str) -> Vec<String> {
    string_literals(text)
        .into_iter()
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
        .collect()
}

fn split_url(url: &str) -> (Option<String>, String) {
    if let Some(scheme) = url.find("://") {
        let authority_start = scheme + 3;
        let path_start = url[authority_start..]
            .find('/')
            .map_or(url.len(), |offset| authority_start + offset);
        let base = url[..path_start].to_owned();
        let path = if path_start == url.len() {
            "/".to_owned()
        } else {
            url[path_start..]
                .split(['?', '#'])
                .next()
                .unwrap_or("/")
                .to_owned()
        };
        (Some(base), normalize_path(&path))
    } else {
        (None, normalize_path(url))
    }
}

fn normalize_path(path: &str) -> String {
    let mut path = path.trim().to_owned();
    if path.is_empty() {
        path.push('/');
    }
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    path.split(['?', '#']).next().unwrap_or("/").to_owned()
}

fn placeholders(path: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut remaining = path;
    while let Some(start) = remaining.find('{') {
        let tail = &remaining[start + 1..];
        let Some(end) = tail.find('}') else {
            break;
        };
        let name = &tail[..end];
        if !name.is_empty() {
            names.push(name.to_owned());
        }
        remaining = &tail[end + 1..];
    }
    names
}

fn http_methods(text: &str) -> Vec<String> {
    let methods = ["get", "post", "put", "patch", "delete", "head"];
    let mut found = methods
        .iter()
        .filter(|method| {
            text.to_ascii_lowercase()
                .contains(&format!("client.{method}("))
        })
        .map(|method| (*method).to_ascii_uppercase())
        .collect::<Vec<_>>();
    if found.is_empty() {
        found.push("GET".to_owned());
    }
    found
}

fn http_method_from_text(text: &str) -> String {
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
        if text
            .to_ascii_uppercase()
            .contains(&format!("METHOD.{method}"))
            || text
                .to_ascii_uppercase()
                .contains(&format!(".{}(", method.to_ascii_lowercase()))
            || text
                .to_ascii_uppercase()
                .contains(&format!("HTTP_{method}"))
        {
            return method.to_owned();
        }
    }
    "GET".to_owned()
}

fn call_names(text: &str, call: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .contains(&call.to_ascii_lowercase())
        })
        .filter_map(first_quoted)
        .collect()
}

fn grpc_path(line: &str) -> Option<(String, String)> {
    string_literals(line)
        .into_iter()
        .find_map(|value| parse_grpc_full_method_name(&value))
}

/// Parses a gRPC full method name literal of the exact canonical form
/// `/package.Service/Method`.
///
/// The previous parser accepted any `/x/y` string literal via `rsplit_once('/')`,
/// so an ordinary REST path literal such as `/api/v1/users` or `/health/check`
/// was fabricated into a phantom gRPC operation in the surface — a fidelity/honesty
/// defect. gRPC full method names have a strict shape the parser now enforces:
/// exactly one interior `/`, a package-qualified (dot-containing) proto service
/// identifier before it, and a bare proto identifier method after it. This also
/// rejects over-read binary literals whose method segment carries trailing junk
/// (a non-identifier byte fails the method check).
fn parse_grpc_full_method_name(value: &str) -> Option<(String, String)> {
    // The shared path parser (the one dynamic capture reads live calls with)
    // enforces the shape; a literal in code must also be package-qualified,
    // since a bare `/api/health`-like pair is far likelier a REST path.
    let (service, method) = apiaxess_api_model::parse_grpc_method_path(value)?;
    service.contains('.').then_some((service, method))
}

/// A single Protocol Buffers identifier: an ASCII letter or `_`, then ASCII
/// alphanumerics or `_`.
fn is_proto_identifier(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// A dot-separated path of proto identifiers (`package.sub.Service`).
fn is_dotted_proto_identifier(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(is_proto_identifier)
}

/// Validates and orients a candidate gRPC (service, method) pair captured from a
/// `generateFullMethodName` call. A real gRPC service is package-qualified
/// (`pkg.Service`) and the method is a bare proto identifier (`SendEvent`). Returns
/// the correctly-ordered pair when exactly one side is dotted-qualified and the
/// other is a bare identifier — fixing swapped captures — and `None` for anything
/// else (Kotlin synthetics like `$lambda$0`, member names, whitespace tokens), so
/// decompiler noise never becomes a phantom gRPC operation.
fn orient_grpc_pair(a: &str, b: &str) -> Option<(String, String)> {
    let a = a.trim();
    let b = b.trim();
    let a_service = is_dotted_proto_identifier(a) && a.contains('.');
    let b_service = is_dotted_proto_identifier(b) && b.contains('.');
    match (a_service, b_service) {
        (true, false) if is_proto_identifier(b) => Some((a.to_owned(), b.to_owned())),
        (false, true) if is_proto_identifier(a) => Some((b.to_owned(), a.to_owned())),
        _ => None,
    }
}

/// Whether `unbound` is a GraphQL operation with no known endpoint URL that
/// names the same operation (type and name) as `other`.
fn same_graphql_operation_unbound(
    unbound: &ProtocolOperationIdentity,
    other: &ProtocolOperationIdentity,
) -> bool {
    match (unbound, other) {
        (
            ProtocolOperationIdentity::GraphQl {
                endpoint_url: None,
                operation_type: unbound_type,
                operation_name: unbound_name,
            },
            ProtocolOperationIdentity::GraphQl {
                operation_type,
                operation_name,
                ..
            },
        ) => unbound_type == operation_type && unbound_name == operation_name,
        _ => false,
    }
}

/// The named operations of a GraphQL document literal. Anonymous operations
/// carry no name to key an operation on, so they are not emitted.
fn graphql_operations(value: &str) -> Vec<(GraphQlOperationType, String)> {
    apiaxess_api_model::parse_graphql_operations(value)
        .into_iter()
        .filter_map(|header| Some((header.operation_type, header.name?)))
        .collect()
}

fn classify_string(value: &str) -> Option<LooseFindingKind> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return None;
    }
    // Decompiler/parse noise (e.g. the Compose `LinkAnnotation.Url(` artifact) is
    // never a real endpoint under any classification. Reject it uniformly here so
    // it cannot slip through the relative-path or query branches below — the
    // http(s) branch previously guarded it, but a bare `/…` path did not.
    if is_url_extraction_artifact(value) {
        return None;
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        if !valid_http_url(value) {
            return None;
        }
        let (_, path) = split_url(value);
        return Some(if path == "/" {
            LooseFindingKind::BaseUrl
        } else {
            LooseFindingKind::Url
        });
    }
    if value.starts_with('/') && value.len() > 1 {
        return is_uri_path(value).then_some(LooseFindingKind::Path);
    }
    if let Some((key, _)) = value.split_once('=') {
        if is_query_key(key) {
            return Some(LooseFindingKind::QueryKey);
        }
    }
    if is_domain_candidate(value) {
        return Some(LooseFindingKind::Domain);
    }
    let lower = value.to_ascii_lowercase();
    if lower == "authorization"
        || lower == "content-type"
        || lower == "accept"
        || lower == "user-agent"
        || (lower.starts_with("x-") && is_header_name(value))
    {
        return Some(LooseFindingKind::Header);
    }
    None
}

fn valid_http_url(value: &str) -> bool {
    let Some(authority_and_path) = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return false;
    }
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host)
        .trim_matches(['[', ']'])
        .split(':')
        .next()
        .unwrap_or_default();
    !host.is_empty()
        && (host == "localhost"
            || host.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-')
            }))
}

fn is_uri_path(value: &str) -> bool {
    value.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                '/' | '.'
                    | '_'
                    | '-'
                    | '~'
                    | ':'
                    | '@'
                    | '!'
                    | '$'
                    | '&'
                    | '\''
                    | '('
                    | ')'
                    | '*'
                    | '+'
                    | ','
                    | ';'
                    | '='
                    | '%'
                    | '{'
                    | '}'
            )
    })
}

fn is_query_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        })
}

fn is_domain_candidate(value: &str) -> bool {
    value.len() < 256
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn is_header_name(value: &str) -> bool {
    value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn unique_names(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .filter(|value| !value.is_empty() && seen.insert((*value).clone()))
        .cloned()
        .collect()
}

fn safe_token(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn deferred_diagnostic(detection: &LibraryDetection) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "library_id".to_owned(),
        DiagnosticValue::String(detection.library_id.clone()),
    );
    context.insert(
        "protocol_decoder_id".to_owned(),
        DiagnosticValue::String(detection.protocol_decoder_id.clone()),
    );
    EXTRACTION_DECODER_DEFERRED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::{
        StaticStringCandidate, classify_string, extract, is_documentation_host, is_non_http_path,
        is_url_extraction_artifact, loose_noise_reason, obfuscated_retrofit_routes,
        orient_grpc_pair,
    };
    use apiaxess_api_model::LooseFindingKind;
    use apiaxess_artifact_intake::{
        ArtifactFormat, DexAccess, InstallableApk, NormalizedUnpackedArtifact, ProtectionMetadata,
        StructuralOutput, index_static_archive,
    };
    use apiaxess_network_routing::NetworkingRouter;
    use std::{
        fmt::Write,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn filesystem_paths_are_rejected_as_endpoints() {
        // The Openly garbage: sysfs/procfs and app-storage paths misread as HTTP.
        assert!(is_non_http_path("/sys/devices/system/cpu/"));
        assert!(is_non_http_path("/proc/self/status"));
        assert!(is_non_http_path("/dev/urandom"));
        assert!(is_non_http_path("/data/data/com.example/files"));
        assert!(is_non_http_path("/system/bin/sh"));
        assert!(is_non_http_path("/storage/emulated/0/Download"));
        assert!(is_non_http_path("/sdcard/DCIM"));
        assert!(is_non_http_path("Lcom/example/Foo;"));
    }

    #[test]
    fn real_api_paths_are_not_mistaken_for_filesystem() {
        // Requirement: preserve real signal. API routes that merely share a first
        // word with a filesystem root must survive.
        assert!(!is_non_http_path("/v1/matches"));
        assert!(!is_non_http_path("/data/users")); // an app resource, not /data/data/
        assert!(!is_non_http_path("/system/status")); // an app resource, not /system/bin
        assert!(!is_non_http_path("/api/v2/devices"));
        assert!(!is_non_http_path("/.well-known/openid-configuration"));
        assert!(!is_non_http_path("/users/{id}/profile"));
    }

    #[test]
    fn string_literal_artifacts_are_rejected_as_endpoints() {
        // The Openly-debug garbage: header names, format strings, log lines, code
        // comments, and toString() shrapnel misread as endpoints.
        assert!(is_non_http_path("/Authorization"));
        assert!(is_non_http_path("/Host"));
        assert!(is_non_http_path("/Accept-Type"));
        assert!(is_non_http_path("/WebSocket"));
        assert!(is_non_http_path("/https"));
        assert!(is_non_http_path("https://%s/%s/%s"));
        assert!(is_non_http_path("/%s"));
        assert!(is_non_http_path("/A connection to"));
        assert!(is_non_http_path("/Use LinkAnnotatation.Url(url) instead"));
        assert!(is_non_http_path("/-->"));
        assert!(is_non_http_path("/Response{protocol="));
    }

    #[test]
    fn grpc_pair_validates_orients_and_rejects_garbage() {
        // Correctly ordered.
        assert_eq!(
            orient_grpc_pair("gpt.EventService", "SendEvent"),
            Some(("gpt.EventService".to_owned(), "SendEvent".to_owned()))
        );
        // Swapped capture is corrected.
        assert_eq!(
            orient_grpc_pair("SendEvent", "gpt.EventService"),
            Some(("gpt.EventService".to_owned(), "SendEvent".to_owned()))
        );
        // Kotlin synthetics / member names / whitespace tokens are rejected.
        assert_eq!(
            orient_grpc_pair(
                " gameRepository_delegate$lambda$0",
                " gameRepository_delegate$lambda$1"
            ),
            None
        );
        assert_eq!(
            orient_grpc_pair(
                " generatePendingIntentRequestCode",
                "$getALPHANUMERIC_ALPHABET$annotations"
            ),
            None
        );
        // Two dotted or two bare ⇒ ambiguous ⇒ rejected.
        assert_eq!(orient_grpc_pair("a.B", "c.D"), None);
        assert_eq!(orient_grpc_pair("Send", "Event"), None);
    }

    #[test]
    fn real_paths_survive_the_artifact_filter() {
        // Percent-encoding, templates, and ordinary single-segment roots must stay.
        assert!(!is_non_http_path("/search/%20results")); // real %XX escape
        assert!(!is_non_http_path("/users/{id}")); // Retrofit template
        assert!(!is_non_http_path("/videos")); // common noun root, not a header
        assert!(!is_non_http_path("/login"));
        assert!(!is_non_http_path("/auth/otp/send"));
    }

    #[test]
    fn linkannotation_url_artifact_is_rejected() {
        // The consistent Compose decompiler artifact must not become a finding.
        assert_eq!(
            classify_string("https://host.example/LinkAnnotation.Url(url="),
            None
        );
        assert!(is_url_extraction_artifact(
            "https://host.example/LinkAnnotation.Url(url="
        ));
        // Over-captured adjacent source text (space/quote) is rejected too.
        assert_eq!(classify_string("https://a.example/x path"), None);
        assert_eq!(classify_string("https://a.example/x\"code"), None);
        // A clean URL still classifies, including legitimate parens in a path.
        assert_eq!(
            classify_string("https://api.example.com/"),
            Some(LooseFindingKind::BaseUrl)
        );
        assert_eq!(
            classify_string("https://api.example.com/v1/items(3)"),
            Some(LooseFindingKind::Url)
        );
    }

    #[test]
    fn documentation_hosts_are_distinguished_from_api_hosts() {
        assert!(is_documentation_host("github.com"));
        assert!(is_documentation_host("raw.githubusercontent.com"));
        assert!(is_documentation_host("www.w3.org"));
        assert!(is_documentation_host("schemas.android.com"));
        assert!(is_documentation_host("developer.myapp.io"));
        assert!(is_documentation_host("example.com")); // RFC 2606 placeholder
        assert!(!is_documentation_host("api.myapp.io"));
        assert!(!is_documentation_host("gateway.myapp.io"));
        // A real API host, not documentation, even from Google.
        assert!(!is_documentation_host("www.googleapis.com"));
    }

    fn artifact(source: &str) -> NormalizedUnpackedArtifact {
        artifact_files(&[("Network.smali", source)])
    }

    /// A normalized artifact whose smali root holds the given files.
    fn artifact_files(files: &[(&str, &str)]) -> NormalizedUnpackedArtifact {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-extraction-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let smali = root.join("smali");
        let resources = root.join("res");
        let assets = root.join("assets");
        fs::create_dir_all(&smali).expect("smali directory");
        fs::create_dir_all(&resources).expect("resources directory");
        fs::create_dir_all(&assets).expect("assets directory");
        for (relative, source) in files {
            let path = smali.join(relative);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("fixture directory");
            fs::write(path, source).expect("fixture source");
        }
        NormalizedUnpackedArtifact {
            schema_version: 1,
            target_type_id: "android.apk".to_owned(),
            workspace_root: root.display().to_string(),
            input_format: ArtifactFormat::Apk,
            raw_archives: Vec::new(),
            static_archives: Vec::new(),
            installable_apks: vec![InstallableApk {
                id: "base".to_owned(),
                path: root.join("base.apk").display().to_string(),
                is_base: true,
            }],
            structural_outputs: vec![StructuralOutput {
                apk_id: "base".to_owned(),
                manifest: root.join("AndroidManifest.xml").display().to_string(),
                smali_roots: vec![smali.display().to_string()],
                resource_root: resources.display().to_string(),
                asset_root: assets.display().to_string(),
            }],
            dex_access: DexAccess {
                dex_files: Vec::new(),
                parser_handoff: "test".to_owned(),
                capabilities: Vec::new(),
            },
            decompiled_source_roots: Vec::new(),
            protection: ProtectionMetadata {
                detector: "test".to_owned(),
                detector_version: None,
                distribution_posture: "test".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn a_retrofit_body_data_class_resolves_to_its_serialized_fields() {
        use apiaxess_api_model::{ObjectOpenness, SchemaShape};
        let service = ".class public interface abstract Lcom/example/net/AccountApi;\n\
             .super Ljava/lang/Object;\n\
             .method public abstract signUp(Lcom/example/net/model/SignUp;)Lretrofit2/Call;\n\
             .param p1    # Lcom/example/net/model/SignUp;\n\
                 .annotation runtime Lretrofit2/http/Body;\n\
                 .end annotation\n\
             .end param\n\
             .annotation runtime Lretrofit2/http/POST;\n\
                 value = \"/v1/accounts\"\n\
             .end annotation\n\
             .end method\n";
        let dto = ".class public final Lcom/example/net/model/SignUp;\n\
             .super Ljava/lang/Object;\n\
             .field public static final Companion:Lcom/example/net/model/SignUp$Companion;\n\
             .field private final email:Ljava/lang/String;\n\
             .field private final displayName:Ljava/lang/String;\n\
                 .annotation runtime Lcom/google/gson/annotations/SerializedName;\n\
                     value = \"display_name\"\n\
                 .end annotation\n\
             .end field\n\
             .field private final age:I\n\
             .field private final transient session:Ljava/lang/Object;\n\
             .method public constructor <init>()V\n\
             .end method\n";
        let artifact = artifact_files(&[
            ("com/example/net/AccountApi.smali", service),
            ("com/example/net/model/SignUp.smali", dto),
        ]);
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid extraction model");
        let endpoint = report
            .document
            .surface
            .endpoints
            .iter()
            .find(|endpoint| endpoint.identity.path_template.as_str() == "/v1/accounts")
            .expect("body endpoint");
        let body = endpoint.request_body.as_ref().expect("request body");
        let SchemaShape::Object {
            properties,
            openness,
        } = &body.shape.selected_candidate().unwrap().value
        else {
            panic!("body resolves to an object");
        };
        let fields = properties
            .iter()
            .map(|property| {
                (
                    property.name.as_str().to_owned(),
                    property
                        .schema
                        .shape
                        .selected_candidate()
                        .unwrap()
                        .value
                        .clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            vec![
                ("email".to_owned(), SchemaShape::String { format: None }),
                (
                    "display_name".to_owned(),
                    SchemaShape::String { format: None }
                ),
                (
                    "age".to_owned(),
                    SchemaShape::Integer {
                        format: Some("int32".to_owned())
                    }
                ),
            ]
        );
        assert_eq!(*openness, ObjectOpenness::Closed);
        assert!(report.document.validate().is_ok());
    }

    #[test]
    fn retrofit_routes_resolve_against_their_own_base_like_retrofit_does() {
        assert_eq!(
            super::resolve_retrofit_route(Some("https://api.app.test/v2/"), "users/{id}"),
            (
                Some("https://api.app.test".to_owned()),
                "/v2/users/{id}".to_owned()
            )
        );
        assert_eq!(
            super::resolve_retrofit_route(Some("https://api.app.test/v2/"), "/status"),
            (
                Some("https://api.app.test".to_owned()),
                "/status".to_owned()
            )
        );
        assert_eq!(
            super::resolve_retrofit_route(Some("https://api.app.test/"), "https://other.test/x"),
            (Some("https://other.test".to_owned()), "/x".to_owned())
        );
        assert_eq!(
            super::resolve_retrofit_route(None, "users"),
            (None, "users".to_owned())
        );
    }

    #[test]
    fn retrofit_annotations_write_valid_model_facts_and_fuse_base_url() {
        let artifact = artifact(
            ".method public getUser()V\n\
             .annotation runtime Lretrofit2/http/GET;\n\
                 value = \"/users/{id}\"\n\
             .end annotation\n\
             .annotation runtime Lretrofit2/http/Path;\n\
                 value = \"id\"\n\
             .end annotation\n\
             .annotation runtime Lretrofit2/http/Query;\n\
                 value = \"expand\"\n\
             .end annotation\n\
             .end method\n\
             const-string v0, \"https://api.example.test\"\n",
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid extraction model");
        let endpoint = &report.document.surface.endpoints[0];
        assert_eq!(endpoint.identity.method.as_str(), "GET");
        assert_eq!(endpoint.identity.path_template.as_str(), "/users/{id}");
        assert_eq!(endpoint.path_parameters[0].name.as_str(), "id");
        assert_eq!(endpoint.query_parameters[0].name.as_str(), "expand");
        assert_eq!(
            endpoint
                .base_url
                .as_ref()
                .unwrap()
                .selected_candidate()
                .unwrap()
                .value,
            "https://api.example.test"
        );
        assert!(
            endpoint
                .path_template
                .expected_recoverability_basis_points
                .unwrap()
                >= 9000
        );
        assert!(report.document.validate().is_ok());
    }

    #[test]
    fn obfuscated_java_retrofit_annotations_recover_tusky_route_shape() {
        let routes = obfuscated_retrofit_routes(
            r#"
            @ol.f("api/v1/accounts/{id}/statuses")
            Object A(@s("id") String id);

            @o("oauth/token")
            @ol.e
            Object B(@ol.c("code") String code);

            @h(hasBody = true, method = "DELETE", path = "api/v1/lists/{listId}/accounts")
            Object C(@s("listId") String listId);
            "#,
        );

        assert_eq!(
            routes,
            vec![
                ("GET".to_owned(), "api/v1/accounts/{id}/statuses".to_owned()),
                ("POST".to_owned(), "oauth/token".to_owned()),
                (
                    "DELETE".to_owned(),
                    "api/v1/lists/{listId}/accounts".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn loose_candidates_require_uri_like_shapes() {
        assert_eq!(
            classify_string("https://api.example.test/v1/feeds"),
            Some(LooseFindingKind::Url)
        );
        assert_eq!(
            classify_string("api.example.test"),
            Some(LooseFindingKind::Domain)
        );
        assert_eq!(
            classify_string("since=123"),
            Some(LooseFindingKind::QueryKey)
        );
        assert_eq!(classify_string("https://"), None);
        assert_eq!(classify_string("!Alg.Alias.Signature.ECDSAwithSHA1"), None);
        assert_eq!(classify_string("/ by zero"), None);
        assert_eq!(classify_string("!BlockGraphicsLayerModifier(block="), None);
    }

    #[test]
    fn jvm_descriptor_paths_are_filtered_without_rejecting_short_api_paths() {
        assert_eq!(
            loose_noise_reason(&StaticStringCandidate {
                kind: LooseFindingKind::Path,
                value: "/Ljava/lang/String;".to_owned(),
                path: "classes.dex".to_owned(),
            }),
            Some("jvm-descriptor")
        );
        assert_eq!(
            loose_noise_reason(&StaticStringCandidate {
                kind: LooseFindingKind::Path,
                value: "/v1/a".to_owned(),
                path: "classes.dex".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn packaged_noise_is_filtered_with_auditable_reason_and_code_signal_retained() {
        let artifact = artifact("const-string v0, \"/api/kept\"\n");
        let resource_root = std::path::Path::new(&artifact.structural_outputs[0].resource_root);
        fs::write(
            resource_root.join("bz.json"),
            "[\"https://catalog.example.test/feed\", \"catalog.example.test\"]",
        )
        .expect("resource fixture");

        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid extraction model");
        let values = report
            .document
            .surface
            .loose_findings
            .iter()
            .filter_map(|finding| finding.value.selected_candidate())
            .map(|candidate| candidate.value.as_str())
            .collect::<Vec<_>>();

        assert!(values.contains(&"/api/kept"));
        assert!(!values.contains(&"https://catalog.example.test/feed"));
        let filtered = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.id.as_ref() == "extraction.loose-findings-filtered")
            .expect("noise classification diagnostic");
        assert!(filtered.context.contains_key("reasons"));
        assert!(filtered.context.contains_key("examples"));

        assert_eq!(
            loose_noise_reason(&StaticStringCandidate {
                kind: LooseFindingKind::Url,
                value: "https://catalog.example.test/feed".to_owned(),
                path: "base.apk!/res/bz.json".to_owned(),
            }),
            Some("packaged-resource-data")
        );
        assert_eq!(
            loose_noise_reason(&StaticStringCandidate {
                kind: LooseFindingKind::Url,
                value: "https://api.example.test/v1/users".to_owned(),
                path: "base.apk!/assets/api.json".to_owned(),
            }),
            None
        );
    }

    #[test]
    fn packaged_catalogue_volume_does_not_become_loose_finding_volume() {
        let artifact = artifact("const-string v0, \"/api/kept\"\n");
        let resource_root = std::path::Path::new(&artifact.structural_outputs[0].resource_root);
        let catalog = (0..5_000)
            .map(|index| format!("\"https://catalog-{index}.example.test/feed\""))
            .collect::<Vec<_>>()
            .join(",");
        fs::write(resource_root.join("catalog.json"), catalog).expect("resource fixture");

        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid extraction model");

        assert_eq!(report.document.surface.loose_findings.len(), 1);
        assert!(report.timing.loose_finding_filtering_millis < 2_000);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "extraction.loose-findings-filtered")
        );
    }

    #[test]
    #[ignore = "requires the existing Windows-normalized Feeder workspace"]
    fn real_feeder_probe_preserves_endpoints_and_reduces_packaged_noise() {
        if std::env::var_os("APIAXESS_PHASE_8_7_REAL").is_none() {
            return;
        }
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root");
        let fixture = workspace.join("fixtures/capstone/feeder-2.22.0-4050.apk");
        let intake = workspace.join("tmp/phase-8.4.1-feeder-intake/intake-1787837677");
        let apktool = intake.join("unpacked/base/apktool");
        let jadx = intake.join("unpacked/base/jadx");
        assert!(
            fixture.is_file() && apktool.is_dir() && jadx.is_dir(),
            "Phase 8.7 real probe requires the existing Feeder intake workspace"
        );

        let mut artifact = artifact("");
        artifact.installable_apks[0].path = fixture.display().to_string();
        artifact.static_archives = vec![index_static_archive(&fixture).expect("index Feeder")];
        artifact.structural_outputs[0] = StructuralOutput {
            apk_id: "base".to_owned(),
            manifest: apktool.join("AndroidManifest.xml").display().to_string(),
            smali_roots: vec![apktool.join("smali").display().to_string()],
            resource_root: apktool.join("res").display().to_string(),
            asset_root: apktool.join("assets").display().to_string(),
        };
        artifact.decompiled_source_roots = vec![jadx.join("sources").display().to_string()];

        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid Feeder extraction");
        println!(
            "phase_8_7_real_feeder endpoints={} loose_findings={} filtered={:?} timing={:?}",
            report.document.surface.endpoints.len(),
            report.document.surface.loose_findings.len(),
            report.diagnostics.iter().find(|diagnostic| {
                diagnostic.id.as_ref() == "extraction.loose-findings-filtered"
            }),
            report.timing
        );
        assert_eq!(report.document.surface.endpoints.len(), 12);
        assert!(report.document.surface.loose_findings.len() < 2_000);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "extraction.loose-findings-filtered")
        );
    }

    #[test]
    #[ignore = "requires the existing Windows-normalized PlayRoom workspace"]
    fn real_playroom_probe_keeps_signal_while_reducing_packaged_metadata() {
        if std::env::var_os("APIAXESS_PHASE_8_7_REAL").is_none() {
            return;
        }
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("workspace root");
        let fixture = workspace.join("target/PlayRoom.apk");
        let intake = workspace.join("tmp/phase-8.4-playroom-intake/intake-1787835804");
        let apktool = intake.join("unpacked/base/apktool");
        let jadx = intake.join("unpacked/base/jadx");
        assert!(
            fixture.is_file() && apktool.is_dir() && jadx.is_dir(),
            "Phase 8.7 real probe requires the existing PlayRoom intake workspace"
        );

        let mut artifact = artifact("");
        artifact.installable_apks[0].path = fixture.display().to_string();
        artifact.static_archives = vec![index_static_archive(&fixture).expect("index PlayRoom")];
        artifact.structural_outputs[0] = StructuralOutput {
            apk_id: "base".to_owned(),
            manifest: apktool.join("AndroidManifest.xml").display().to_string(),
            smali_roots: vec![
                apktool.join("smali").display().to_string(),
                apktool.join("smali_classes2").display().to_string(),
                apktool.join("smali_classes3").display().to_string(),
            ],
            resource_root: apktool.join("res").display().to_string(),
            asset_root: apktool.join("assets").display().to_string(),
        };
        artifact.decompiled_source_roots = vec![jadx.join("sources").display().to_string()];

        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid PlayRoom extraction");
        println!(
            "phase_8_7_real_playroom endpoints={} loose_findings={} timing={:?}",
            report.document.surface.endpoints.len(),
            report.document.surface.loose_findings.len(),
            report.timing
        );
        assert_eq!(report.document.surface.endpoints.len(), 4);
        assert!(report.document.surface.loose_findings.len() < 4_296);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "extraction.loose-findings-filtered")
        );
    }

    #[test]
    fn grpc_and_graphql_keep_native_operation_identities() {
        let artifact = artifact(
            "generateFullMethodName(\"demo.Users\", \"GetUser\")\n\
             const-string v0, \"query GetUser { user { id } }\"\n\
             Lcom/apollographql/apollo/ApolloClient;\n",
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid operation model");
        assert!(
            report
                .document
                .surface
                .protocol_operations
                .iter()
                .any(|operation| matches!(
                    operation.identity,
                    apiaxess_api_model::ProtocolOperationIdentity::Grpc { .. }
                ))
        );
        assert!(
            report
                .document
                .surface
                .protocol_operations
                .iter()
                .any(|operation| matches!(
                    operation.identity,
                    apiaxess_api_model::ProtocolOperationIdentity::GraphQl { .. }
                ))
        );
    }

    #[test]
    fn grpc_full_method_name_parser_rejects_rest_paths() {
        // Canonical gRPC full method names are accepted.
        assert_eq!(
            super::parse_grpc_full_method_name("/demo.Users/GetUser"),
            Some(("demo.Users".to_owned(), "GetUser".to_owned()))
        );
        assert_eq!(
            super::parse_grpc_full_method_name("/a.b.C/Do"),
            Some(("a.b.C".to_owned(), "Do".to_owned()))
        );
        // Ordinary REST path literals must NOT be misread as gRPC operations.
        for rest in [
            "/api/v1/users",         // multiple segments
            "/health/check",         // no package dot
            "/users/{id}",           // non-identifier method
            "/demo.Users/Get/extra", // trailing segment
            "/demo.Users/Get User",  // whitespace in method
            "demo.Users/Get",        // no leading slash
            "/.Users/Get",           // empty service segment
        ] {
            assert_eq!(
                super::parse_grpc_full_method_name(rest),
                None,
                "REST-shaped literal must not be parsed as gRPC: {rest}"
            );
        }
    }

    #[test]
    fn grpc_extractor_does_not_fabricate_operations_from_rest_path_literals() {
        // A gRPC-detected class that also carries a plain REST path literal must
        // not manufacture a phantom gRPC operation from that literal.
        let artifact = artifact(
            "Lio/grpc/MethodDescriptor;\n\
             const-string v0, \"/api/v1/users\"\n\
             const-string v1, \"/health/check\"\n",
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("valid extraction");
        assert!(
            !report
                .document
                .surface
                .protocol_operations
                .iter()
                .any(|operation| matches!(
                    operation.identity,
                    apiaxess_api_model::ProtocolOperationIdentity::Grpc { .. }
                )),
            "REST path literals must not become phantom gRPC operations"
        );
    }

    #[test]
    fn unresolved_okhttp_builder_is_a_partial_finding_not_a_guess() {
        let artifact = artifact(
            "Lokhttp3/Request$Builder;\n\
             invoke-virtual {v0}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)\n",
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("partial extraction remains valid");
        assert!(
            report
                .partial_recoveries
                .iter()
                .any(|partial| partial.library_id == "okhttp")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "extraction.partial-recovery")
        );
        assert!(report.document.surface.endpoints.is_empty());
    }

    #[test]
    fn large_string_pool_stays_bounded_during_coalescing_and_validation() {
        let mut source = String::new();
        for index in 0..20_000 {
            writeln!(
                source,
                ".const-string v0, \"https://api.example.test/resource/{index}\""
            )
            .expect("write synthetic large corpus");
        }
        let artifact = artifact(&source);
        let routed = NetworkingRouter::default().route(&artifact);
        let report = extract(&artifact, &routed).expect("large extraction remains valid");

        assert_eq!(report.document.surface.endpoints.len(), 0);
        assert_eq!(report.document.surface.loose_findings.len(), 20_000);
        assert!(
            report.timing.loose_finding_deduplication_millis < 2_000,
            "loose-finding coalescing regressed: {:?}",
            report.timing
        );
        assert!(
            report.timing.finalization_millis < 10_000,
            "large model validation regressed: {:?}",
            report.timing
        );
        assert!(report.document.validate().is_ok());
    }
}
