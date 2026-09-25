//! Canonical, evidence-preserving representation of a reverse-engineered API.
//!
//! This crate is deliberately independent of `OpenAPI`, HAR, Postman, analysis
//! tools, plugin transports, sessions, and GUI DTOs. It provides only the phase
//! 0.2 model, invariants, merge semantics, derived confidence, and durable JSON.

pub mod api;
pub mod confidence;
pub mod document;
pub mod error;
pub mod fact;
pub mod ids;
pub mod provenance;
pub mod schema;
pub mod signer;
pub mod unified;

pub use api::{
    ApiKeyLocation, ApiSurface, AuthenticationScheme, DynamicCaptureSummary, DynamicHandoff,
    Endpoint, EndpointIdentity, GraphQlOperationType, HeaderParameter, LibraryCoverage,
    LooseFinding, LooseFindingKind, PaginationSignal, PathParameter, PathTemplateAssertion,
    PathTemplateOrigin, PresenceAssertion, ProtocolOperation, ProtocolOperationIdentity,
    QueryParameter, ResponseBody, ResponseSelector, StaticBoundaryReason, StaticCoverage,
    StaticKnowledgeStatus, StaticPassSummary, normalize_host,
};
pub use confidence::{
    CONFIDENCE_SCHEMA_VERSION, ConfidenceSummary, CoveragePicture, FactConfidence,
    HandoffResolution, MergeCounts,
};
pub use document::{ApiDocument, CURRENT_FORMAT_VERSION};
pub use error::{ModelError, ModelResult};
pub use fact::{
    ConfidenceAssessment, Fact, FactCandidate, FieldClass, MergeInput, MergeRecord, MergeRelation,
    Resolution, ResolutionPolicy,
};
pub use ids::{
    ActivityId, AgentId, CandidateId, EntityId, HttpMethod, ParameterName, PathTemplate, RunId,
};
pub use provenance::{
    Activity, Agent, AgentKind, Entity, EntityKind, ProvenanceRegistry, SourceType,
};
pub use schema::{
    ObjectOpenness, RequirednessAssertion, RequirednessAssessment, SamplePayload,
    SchemaObservation, SchemaProperty, SchemaShape, SchemaSlot,
};
pub use signer::{
    CanonicalizationOperation, CanonicalizationStep, SIGNER_IR_SCHEMA_VERSION, SignedComponent,
    SignerAlternative, SignerArtifact, SignerFixture, SignerInterface, SignerKeySource, SignerMode,
    SignerOutput, SignerPrimitive, SignerProvenance, SignerRequest, SignerRuntime, SignerScheme,
};
pub use unified::{
    HostParty, SignerBinding, SignerTarget, UNIFIED_SURFACE_SCHEMA_VERSION, UnifiedApiSurface,
    UnifiedEndpoint,
};

#[cfg(test)]
mod tests;
