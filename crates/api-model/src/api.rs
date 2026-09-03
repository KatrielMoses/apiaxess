//! Canonical API surface, endpoint identity, parameters, and authentication.

use std::collections::BTreeSet;

use apiaxess_diagnostics::Diagnostic;
use serde::{Deserialize, Serialize};

use crate::{
    error::{ModelError, ModelResult},
    fact::{Fact, FieldClass, ResolutionPolicy},
    ids::{HttpMethod, ParameterName, PathTemplate},
    provenance::ProvenanceRegistry,
    schema::{RequirednessAssertion, SchemaSlot, validate_requiredness},
};

/// Complete canonical API surface for one analyzed artifact/project state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSurface {
    /// Normalized evidence graph shared by every fact.
    pub provenance: ProvenanceRegistry,
    /// Endpoint inventory. Identity uniqueness is validated on load/save.
    pub endpoints: Vec<Endpoint>,
    /// Non-REST operations such as gRPC methods and GraphQL operations.
    #[serde(default)]
    pub protocol_operations: Vec<ProtocolOperation>,
    /// Static candidates that could not be structurally bound to an operation.
    #[serde(default)]
    pub loose_findings: Vec<LooseFinding>,
    /// Reusable signer artifacts emitted by Phase 4.4.
    #[serde(default)]
    pub signers: Vec<crate::signer::SignerArtifact>,
}

/// Stable endpoint key: method plus template, and nothing else.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointIdentity {
    /// Normalized HTTP method.
    pub method: HttpMethod,
    /// Declared or inferred path template without query/fragment.
    pub path_template: PathTemplate,
}

/// One endpoint and its independently evidenced metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Canonical lookup identity.
    pub identity: EndpointIdentity,
    /// Optional statically resolved base URL candidate.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<Fact<String>>,
    /// Evidence that the endpoint exists. The value has no absent variant.
    pub presence: Fact<PresenceAssertion>,
    /// Candidate templates and declared/inferred origin.
    pub path_template: Fact<PathTemplateAssertion>,
    /// Query inventory; names do not affect endpoint identity.
    pub query_parameters: Vec<QueryParameter>,
    /// Path-parameter inventory; names do not affect endpoint identity.
    #[serde(default)]
    pub path_parameters: Vec<PathParameter>,
    /// Header inventory; names do not affect endpoint identity.
    pub headers: Vec<HeaderParameter>,
    /// Authentication candidates when any source speaks about authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Fact<AuthenticationScheme>>,
    /// Request-body schema when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<SchemaSlot>,
    /// Response schemas keyed by selector.
    pub responses: Vec<ResponseBody>,
    /// Observable pagination conventions such as page, cursor, or Link.
    #[serde(default)]
    pub pagination_signals: Vec<Fact<PaginationSignal>>,
}

/// Positive-only presence assertion. Silence can never manufacture absence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceAssertion {
    /// A source asserts or confirms existence.
    Present,
}

/// How a route template entered the model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathTemplateAssertion {
    /// Template value.
    pub template: PathTemplate,
    /// Declared route table or fallback inference.
    pub origin: PathTemplateOrigin,
}

/// Source basis for a path template.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathTemplateOrigin {
    /// Extracted from a static route declaration/table.
    Declared,
    /// Inferred as a fallback for a route static analysis missed.
    Inferred,
}

/// Query parameter metadata belonging to one endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParameter {
    /// Parameter name, unique within the endpoint.
    pub name: ParameterName,
    /// Positive-only evidence that this query parameter exists.
    pub presence: Fact<PresenceAssertion>,
    /// Candidate and unified parameter shapes.
    pub schema: SchemaSlot,
    /// Static declaration or dynamic observation tally.
    pub requiredness: Fact<RequirednessAssertion>,
}

/// Header metadata belonging to an endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderParameter {
    /// Header name.
    pub name: ParameterName,
    /// Positive-only evidence that this header exists.
    pub presence: Fact<PresenceAssertion>,
    /// Candidate and unified header value shape.
    pub schema: SchemaSlot,
}

/// Path parameter metadata belonging to an endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathParameter {
    /// Parameter name.
    pub name: ParameterName,
    /// Positive-only evidence that this path parameter exists.
    pub presence: Fact<PresenceAssertion>,
    /// Candidate and unified path-parameter shape.
    pub schema: SchemaSlot,
}

/// A non-REST operation identity preserved in its native protocol shape.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum ProtocolOperationIdentity {
    /// gRPC generated service method identity.
    Grpc {
        /// Fully-qualified protobuf service name.
        service: String,
        /// Method name within the service.
        method: String,
    },
    /// GraphQL operation over one endpoint.
    GraphQl {
        /// Single GraphQL endpoint URL when statically known.
        endpoint_url: Option<String>,
        /// Query, mutation, or subscription.
        operation_type: GraphQlOperationType,
        /// Generated operation name.
        operation_name: String,
    },
}

/// GraphQL operation kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphQlOperationType {
    /// GraphQL query.
    Query,
    /// GraphQL mutation.
    Mutation,
    /// GraphQL subscription.
    Subscription,
}

/// One gRPC or GraphQL operation with independently evidenced schemas.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolOperation {
    /// Native protocol identity.
    pub identity: ProtocolOperationIdentity,
    /// Evidence that the operation exists.
    pub presence: Fact<PresenceAssertion>,
    /// Request/input schema when descriptors or generated types expose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<SchemaSlot>,
    /// Response/output schema when descriptors or generated types expose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<SchemaSlot>,
}

/// Kind of an unbound static string candidate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LooseFindingKind {
    /// Absolute URL or URL-like literal.
    Url,
    /// Base URL candidate.
    BaseUrl,
    /// Domain or host candidate.
    Domain,
    /// Relative path candidate.
    Path,
    /// Query-key candidate.
    QueryKey,
    /// Header-name candidate.
    Header,
}

/// A string candidate retained in the canonical model without endpoint binding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LooseFinding {
    /// Candidate category.
    pub kind: LooseFindingKind,
    /// Evidence-preserving candidate value.
    pub value: Fact<String>,
}

/// Static knowledge state for one detected library or boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticKnowledgeStatus {
    /// Static evidence is expected to be near-complete and no partial marker
    /// was emitted for this library.
    HighConfidence,
    /// Static evidence exists but bounded analysis recorded a limitation.
    Partial,
    /// A known static gap was identified, such as deferred raw sockets.
    KnownMissing,
    /// No absence assertion was made; static analysis is silent here.
    Silent,
}

/// Machine-readable reason for a static-to-dynamic handoff.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticBoundaryReason {
    /// Endpoint or payload composition escaped bounded static analysis.
    RuntimeAssembly,
    /// Commercial protection encrypted or renamed the relevant map.
    CommercialObfuscation,
    /// Networking logic is in native code outside Phase 1.
    NativeLogic,
    /// Raw socket interpretation is explicitly deferred.
    RawSocketDeferred,
    /// Networking was detected but no structural API finding was recovered.
    UnidentifiedNetworking,
    /// A supported detector was present but static analysis was silent.
    StaticSilence,
}

/// One explicit static-to-dynamic focus marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicHandoff {
    /// Stable marker ID within the static pass.
    pub id: String,
    /// Library identity when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_id: Option<String>,
    /// Static location or structural focus for dynamic capture.
    pub location: String,
    /// Machine-readable handoff reason.
    pub reason: StaticBoundaryReason,
    /// Human-readable explanation retained for integration and presentation.
    pub detail: String,
    /// Whether static was silent rather than an explicit absence assertion.
    pub static_silence: bool,
}

/// Per-library static coverage accounting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryCoverage {
    /// Stable routed library identity.
    pub library_id: String,
    /// Protection-adjusted expectation from Phase 1.2.
    pub expected_recoverability_basis_points: u16,
    /// Static status after normalization.
    pub status: StaticKnowledgeStatus,
    /// Number of canonical REST endpoints contributed by this extractor.
    pub endpoint_count: usize,
    /// Number of canonical native operations contributed by this extractor.
    pub operation_count: usize,
    /// Number of explicit bounded partial findings.
    pub partial_count: usize,
}

/// Honest target-level coverage signal; this is not an API confidence score.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCoverage {
    /// Weighted recoverability denominator for detected libraries.
    pub expected_basis_points: u64,
    /// Weighted amount statically carried into the canonical view.
    pub covered_basis_points: u64,
    /// Explicit method used to calculate the signal.
    pub methodology: String,
    /// Per-library accounting retained without flattening.
    pub libraries: Vec<LibraryCoverage>,
}

/// Honest accounting for one dynamic-capture run.
///
/// This is deliberately a summary rather than a second API surface: dynamic
/// candidates are retained on the same facts as static candidates, while this
/// record tells consumers which identities were actually exercised.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicCaptureSummary {
    /// Dynamic-capture summary schema version.
    pub schema_version: u32,
    /// Capture run identifier from the provenance activity.
    pub run_id: String,
    /// Number of durable flows considered by the extractor.
    pub flow_count: usize,
    /// Number of flows with a structured endpoint fact.
    pub structured_flow_count: usize,
    /// Number of endpoint identities inferred without a static template.
    pub inferred_endpoint_count: usize,
    /// Identities with dynamic ground-truth in this run.
    pub observed_endpoints: Vec<EndpointIdentity>,
    /// Static identities not exercised by this run.
    pub static_only_endpoints: Vec<EndpointIdentity>,
    /// Handoff markers satisfied by an observed identity.
    pub resolved_handoffs: Vec<String>,
    /// Handoff markers still open after this run.
    pub open_handoffs: Vec<String>,
    /// Minimum sample count used when assessing dynamic requiredness.
    pub minimum_dynamic_samples: u64,
    /// Diagnostics emitted while extracting or committing the run.
    pub diagnostics: Vec<Diagnostic>,
}

impl DynamicCaptureSummary {
    pub(crate) fn validate(&self) -> crate::error::ModelResult<()> {
        if self.schema_version == 0 || self.run_id.trim().is_empty() {
            return Err(crate::error::ModelError::invariant(
                "dynamic_capture",
                "schema version and run ID must be non-empty",
            ));
        }
        if self.minimum_dynamic_samples == 0 {
            return Err(crate::error::ModelError::invariant(
                "dynamic_capture.minimum_dynamic_samples",
                "must be non-zero",
            ));
        }
        let mut identities = BTreeSet::new();
        for identity in &self.observed_endpoints {
            if !identities.insert(identity) {
                return Err(crate::error::ModelError::invariant(
                    "dynamic_capture.observed_endpoints",
                    "endpoint identities must be unique",
                ));
            }
        }
        let mut handoffs = BTreeSet::new();
        for id in self.resolved_handoffs.iter().chain(&self.open_handoffs) {
            if id.trim().is_empty() || !handoffs.insert(id) {
                return Err(crate::error::ModelError::invariant(
                    "dynamic_capture.handoffs",
                    "handoff IDs must be non-empty and unique",
                ));
            }
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            diagnostic.validate().map_err(|error| {
                crate::error::ModelError::invariant(
                    format!("dynamic_capture.diagnostics[{index}]"),
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }
}

/// Phase 1.4 static-pass honesty layer persisted with the API document.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticPassSummary {
    /// Static-pass handoff schema version.
    pub schema_version: u32,
    /// Coverage signal for this specific target.
    pub coverage: StaticCoverage,
    /// Explicit dynamic focus points and known static boundaries.
    pub dynamic_handoffs: Vec<DynamicHandoff>,
    /// Diagnostics emitted from the same boundary accounting.
    pub diagnostics: Vec<Diagnostic>,
}

impl StaticPassSummary {
    pub(crate) fn validate(&self) -> crate::error::ModelResult<()> {
        if self.schema_version == 0 {
            return Err(crate::error::ModelError::invariant(
                "static_pass.schema_version",
                "must be non-zero",
            ));
        }
        if self.coverage.covered_basis_points > self.coverage.expected_basis_points
            && self.coverage.expected_basis_points != 0
        {
            return Err(crate::error::ModelError::invariant(
                "static_pass.coverage.covered_basis_points",
                "covered basis points must not exceed the expected denominator",
            ));
        }
        let mut ids = BTreeSet::new();
        for (index, handoff) in self.dynamic_handoffs.iter().enumerate() {
            if handoff.id.trim().is_empty() || !ids.insert(&handoff.id) {
                return Err(crate::error::ModelError::invariant(
                    format!("static_pass.dynamic_handoffs[{index}].id"),
                    "handoff IDs must be non-empty and unique",
                ));
            }
            if handoff.location.trim().is_empty() || handoff.detail.trim().is_empty() {
                return Err(crate::error::ModelError::invariant(
                    format!("static_pass.dynamic_handoffs[{index}]"),
                    "handoff location and detail must be non-empty",
                ));
            }
            if handoff.static_silence && handoff.reason != StaticBoundaryReason::StaticSilence {
                return Err(crate::error::ModelError::invariant(
                    format!("static_pass.dynamic_handoffs[{index}].static_silence"),
                    "static silence must use the static-silence boundary reason",
                ));
            }
        }
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            diagnostic.validate().map_err(|error| {
                crate::error::ModelError::invariant(
                    format!("static_pass.diagnostics[{index}]"),
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }
}

/// Authentication scheme independent of `OpenAPI`'s publishing representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum AuthenticationScheme {
    /// Evidence indicates no authentication on this endpoint.
    None,
    /// HTTP Basic authentication.
    Basic,
    /// Bearer token authentication.
    Bearer {
        /// Optional observed token format hint.
        token_format: Option<String>,
    },
    /// API key supplied at a named location.
    ApiKey {
        /// Header or query location.
        location: ApiKeyLocation,
        /// Header/query name.
        name: ParameterName,
    },
    /// OAuth 2 flow identifiers without adopting `OpenAPI`'s schema.
    OAuth2 {
        /// Observed or declared flow names.
        flows: Vec<String>,
    },
    /// Extensible scheme token for nonstandard mechanisms.
    Custom {
        /// Stable scheme name.
        scheme: String,
    },
}

/// API-key transport location.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyLocation {
    /// HTTP header.
    Header,
    /// Query parameter.
    Query,
}

/// Pagination convention observed on an endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationSignal {
    /// Page-number query parameter.
    Page,
    /// Page-size/limit query parameter.
    PageSize,
    /// Offset query parameter.
    Offset,
    /// Cursor query parameter.
    Cursor,
    /// RFC 8288-style response Link header.
    LinkHeader,
}

/// One response schema selected by an exact status or status class.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseBody {
    /// Exact/class/default status selector.
    pub selector: ResponseSelector,
    /// Positive-only evidence that this response selector exists.
    pub presence: Fact<PresenceAssertion>,
    /// Candidate response-body schema.
    pub body: SchemaSlot,
}

/// Response status selector independent of `OpenAPI` keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "kind",
    content = "value"
)]
pub enum ResponseSelector {
    /// Exact HTTP response status.
    Exact(u16),
    /// Response family from 1 through 5.
    Class(u8),
    /// Fallback response.
    Default,
}

impl ApiSurface {
    pub(crate) fn validate(&self) -> ModelResult<()> {
        self.provenance.validate()?;
        let entity_ids: BTreeSet<_> = self
            .provenance
            .entities
            .iter()
            .map(|entity| &entity.id)
            .collect();
        let mut identities = BTreeSet::new();
        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if !identities.insert(&endpoint.identity) {
                return Err(ModelError::invariant(
                    format!("endpoints[{index}].identity"),
                    "endpoint method + path-template identities must be unique",
                ));
            }
            endpoint.validate(&self.provenance, &format!("endpoints[{index}]"))?;
        }
        let mut operation_identities = BTreeSet::new();
        for (index, operation) in self.protocol_operations.iter().enumerate() {
            if !operation_identities.insert(&operation.identity) {
                return Err(ModelError::invariant(
                    format!("protocol_operations[{index}].identity"),
                    "protocol operation identities must be unique",
                ));
            }
            operation.validate(&self.provenance, &format!("protocol_operations[{index}]"))?;
        }
        for (index, finding) in self.loose_findings.iter().enumerate() {
            if finding.value.field_class != FieldClass::Scalar
                || finding.value.resolution.policy != ResolutionPolicy::Explicit
            {
                return Err(ModelError::invariant(
                    format!("loose_findings[{index}].value"),
                    "loose findings must use the scalar/explicit fact policy",
                ));
            }
            finding.value.validate(
                &self.provenance,
                &format!("loose_findings[{index}].value"),
                Some(&entity_ids),
            )?;
        }
        let mut signer_ids = BTreeSet::new();
        for (index, signer) in self.signers.iter().enumerate() {
            signer.validate(&format!("signers[{index}]"))?;
            if !signer_ids.insert(&signer.signer_id) {
                return Err(ModelError::invariant(
                    format!("signers[{index}].signer_id"),
                    "signer IDs must be unique",
                ));
            }
        }
        Ok(())
    }
}

impl Endpoint {
    #[allow(clippy::too_many_lines)]
    fn validate(&self, provenance: &ProvenanceRegistry, path: &str) -> ModelResult<()> {
        validate_presence(&self.presence, provenance, &format!("{path}.presence"))?;

        if self.path_template.field_class != FieldClass::PathTemplate
            || self.path_template.resolution.policy != ResolutionPolicy::DeclaredBeforeInferred
        {
            return Err(ModelError::invariant(
                format!("{path}.path_template"),
                "path templates must use the path-template field class and declared-first policy",
            ));
        }
        self.path_template
            .validate(provenance, &format!("{path}.path_template"), None)?;
        for (index, candidate) in self.path_template.candidates.iter().enumerate() {
            if candidate.value.origin == PathTemplateOrigin::Declared
                && !provenance
                    .leaf_entities(&candidate.evidence)?
                    .iter()
                    .any(|entity| {
                        entity.source_type == crate::provenance::SourceType::StaticAnalysis
                    })
            {
                return Err(ModelError::invariant(
                    format!("{path}.path_template.candidates[{index}].evidence"),
                    "declared templates must trace to static evidence",
                ));
            }
        }
        let selected_template = &self
            .path_template
            .selected_candidate()
            .expect("selected candidate was validated")
            .value;
        if selected_template.template != self.identity.path_template {
            return Err(ModelError::invariant(
                format!("{path}.identity.path_template"),
                "identity template must equal the selected template candidate",
            ));
        }
        if self.path_template.resolution.policy == ResolutionPolicy::DeclaredBeforeInferred
            && self
                .path_template
                .candidates
                .iter()
                .any(|candidate| candidate.value.origin == PathTemplateOrigin::Declared)
            && selected_template.origin != PathTemplateOrigin::Declared
        {
            return Err(ModelError::invariant(
                format!("{path}.path_template.resolution.selected"),
                "a declared template must be selected before an inferred template",
            ));
        }

        let mut parameter_names = BTreeSet::new();
        for (index, parameter) in self.query_parameters.iter().enumerate() {
            if !parameter_names.insert(&parameter.name) {
                return Err(ModelError::invariant(
                    format!("{path}.query_parameters[{index}].name"),
                    "query-parameter names must be unique within an endpoint",
                ));
            }
            parameter.validate(provenance, &format!("{path}.query_parameters[{index}]"))?;
        }
        let mut path_parameter_names = BTreeSet::new();
        for (index, parameter) in self.path_parameters.iter().enumerate() {
            if !path_parameter_names.insert(&parameter.name) {
                return Err(ModelError::invariant(
                    format!("{path}.path_parameters[{index}].name"),
                    "path-parameter names must be unique within an endpoint",
                ));
            }
            validate_presence(
                &parameter.presence,
                provenance,
                &format!("{path}.path_parameters[{index}].presence"),
            )?;
            parameter.schema.validate(
                provenance,
                &format!("{path}.path_parameters[{index}].schema"),
            )?;
        }
        let mut header_names = BTreeSet::new();
        for (index, header) in self.headers.iter().enumerate() {
            if !header_names.insert(&header.name) {
                return Err(ModelError::invariant(
                    format!("{path}.headers[{index}].name"),
                    "header names must be unique within an endpoint",
                ));
            }
            validate_presence(
                &header.presence,
                provenance,
                &format!("{path}.headers[{index}].presence"),
            )?;
            header
                .schema
                .validate(provenance, &format!("{path}.headers[{index}].schema"))?;
        }

        if let Some(authentication) = &self.authentication {
            if authentication.field_class != FieldClass::Authentication
                || authentication.resolution.policy != ResolutionPolicy::DynamicAuthoritative
            {
                return Err(ModelError::invariant(
                    format!("{path}.authentication"),
                    "authentication must use its field class and dynamic-authoritative policy",
                ));
            }
            authentication.validate(provenance, &format!("{path}.authentication"), None)?;
            for (index, candidate) in authentication.candidates.iter().enumerate() {
                validate_authentication(
                    &candidate.value,
                    &format!("{path}.authentication.candidates[{index}].value"),
                )?;
            }
        }

        if let Some(base_url) = &self.base_url {
            if base_url.field_class != FieldClass::Scalar
                || base_url.resolution.policy != ResolutionPolicy::Explicit
            {
                return Err(ModelError::invariant(
                    format!("{path}.base_url"),
                    "base URLs must use the scalar/explicit fact policy",
                ));
            }
            base_url.validate(provenance, &format!("{path}.base_url"), None)?;
        }

        if let Some(request_body) = &self.request_body {
            request_body.validate(provenance, &format!("{path}.request_body"))?;
        }
        let mut selectors = BTreeSet::new();
        for (index, response) in self.responses.iter().enumerate() {
            if !selectors.insert(response.selector) {
                return Err(ModelError::invariant(
                    format!("{path}.responses[{index}].selector"),
                    "response selectors must be unique within an endpoint",
                ));
            }
            match response.selector {
                ResponseSelector::Exact(status) if !(100..=599).contains(&status) => {
                    return Err(ModelError::invariant(
                        format!("{path}.responses[{index}].selector"),
                        "exact HTTP response status must be between 100 and 599",
                    ));
                }
                ResponseSelector::Class(class) if !(1..=5).contains(&class) => {
                    return Err(ModelError::invariant(
                        format!("{path}.responses[{index}].selector"),
                        "HTTP response class must be between 1 and 5",
                    ));
                }
                _ => {}
            }
            validate_presence(
                &response.presence,
                provenance,
                &format!("{path}.responses[{index}].presence"),
            )?;
            response
                .body
                .validate(provenance, &format!("{path}.responses[{index}].body"))?;
        }
        for (index, signal) in self.pagination_signals.iter().enumerate() {
            if signal.field_class != FieldClass::Scalar
                || signal.resolution.policy != ResolutionPolicy::Explicit
            {
                return Err(ModelError::invariant(
                    format!("{path}.pagination_signals[{index}]"),
                    "pagination signals must use the scalar/explicit fact policy",
                ));
            }
            signal.validate(
                provenance,
                &format!("{path}.pagination_signals[{index}]"),
                None,
            )?;
        }
        Ok(())
    }
}

impl ProtocolOperation {
    fn validate(&self, provenance: &ProvenanceRegistry, path: &str) -> ModelResult<()> {
        validate_presence(&self.presence, provenance, &format!("{path}.presence"))?;
        if let Some(request) = &self.request_body {
            request.validate(provenance, &format!("{path}.request_body"))?;
        }
        if let Some(response) = &self.response_body {
            response.validate(provenance, &format!("{path}.response_body"))?;
        }
        Ok(())
    }
}

impl QueryParameter {
    fn validate(&self, provenance: &ProvenanceRegistry, path: &str) -> ModelResult<()> {
        validate_presence(&self.presence, provenance, &format!("{path}.presence"))?;
        self.schema
            .validate(provenance, &format!("{path}.schema"))?;
        validate_requiredness(
            &self.requiredness,
            provenance,
            &format!("{path}.requiredness"),
        )
    }
}

fn validate_presence(
    fact: &Fact<PresenceAssertion>,
    provenance: &ProvenanceRegistry,
    path: &str,
) -> ModelResult<()> {
    if fact.field_class != FieldClass::Presence
        || fact.resolution.policy != ResolutionPolicy::StaticCompleteDynamicConfirm
    {
        return Err(ModelError::invariant(
            path,
            "presence must use its field class and static-complete/dynamic-confirm policy",
        ));
    }
    fact.validate(provenance, path, None)
}

fn validate_authentication(scheme: &AuthenticationScheme, path: &str) -> ModelResult<()> {
    match scheme {
        AuthenticationScheme::OAuth2 { flows } if flows.is_empty() => Err(ModelError::invariant(
            path,
            "OAuth2 evidence must retain at least one flow identifier",
        )),
        AuthenticationScheme::OAuth2 { flows }
            if flows.iter().any(|flow| flow.trim().is_empty()) =>
        {
            Err(ModelError::invariant(
                path,
                "OAuth2 flow identifiers must not be blank",
            ))
        }
        AuthenticationScheme::Custom { scheme } if scheme.trim().is_empty() => Err(
            ModelError::invariant(path, "custom authentication scheme must not be blank"),
        ),
        _ => Ok(()),
    }
}
