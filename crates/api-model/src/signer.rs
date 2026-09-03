//! Portable signer IR carried by the canonical API model.

use serde::{Deserialize, Serialize};

use crate::{
    error::{ModelError, ModelResult},
    provenance::SourceType,
};

/// Current signer IR schema version.
pub const SIGNER_IR_SCHEMA_VERSION: u32 = 1;

/// Honest signer reproducibility mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerMode {
    /// Exact reusable signing logic and credential boundary are available.
    Reproducible,
    /// A ranked candidate exists but requires review or more evidence.
    PartialHypothesis,
    /// A primitive was observed without recoverable canonicalization.
    ObservedOnly,
    /// Reproduction must call the original app/device runtime.
    DeviceOracle,
}

/// Known scheme or an explicitly retained custom scheme label.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerScheme {
    /// AWS Signature Version 4.
    AwsSigV4,
    /// OAuth 1.0 HMAC.
    OAuth1Hmac,
    /// JSON Web Signature.
    JwtJws,
    /// HTTP Message Signatures / RFC 9421.
    HttpMessageSignatures,
    /// Custom single-message HMAC.
    CustomHmac,
    /// Public-key request signature.
    PublicKeyRequestSignature,
    /// Bespoke or not-yet-recognized scheme.
    Unrecognized {
        /// Retained label for a scheme that has not been normalized.
        label: String,
    },
}

/// Request component covered by the signer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignedComponent {
    /// HTTP method.
    Method,
    /// Path.
    Path,
    /// Query string or parameters.
    Query,
    /// One or more headers.
    Headers,
    /// Request body bytes.
    Body,
    /// Runtime timestamp.
    Timestamp,
    /// Runtime nonce.
    Nonce,
}

/// Ordered operation in the canonicalization pipeline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum CanonicalizationOperation {
    /// Read a request component.
    Field {
        /// Request field or derived value read by the operation.
        name: String,
    },
    /// Uppercase the current value.
    Uppercase,
    /// RFC percent encode the current value.
    UrlEncode,
    /// Form encode the current value.
    FormEncode,
    /// Sort key/value pairs.
    Sort,
    /// Join values with a literal delimiter.
    Join {
        /// Bytes placed between the values being joined.
        delimiter: Vec<u8>,
    },
    /// Insert a literal byte sequence.
    Literal {
        /// Constant bytes inserted into the canonical form.
        bytes: Vec<u8>,
    },
    /// Hash the current value.
    Hash {
        /// Digest algorithm applied to the current value.
        algorithm: String,
    },
    /// Apply a named HMAC/KDF stage.
    Hmac {
        /// HMAC or key-derivation algorithm applied at this stage.
        algorithm: String,
    },
    /// Base64 encode the current value.
    Base64,
    /// `Base64URL` encode the current value.
    Base64Url,
    /// Hex encode the current value.
    Hex,
    /// Apply a recognized scheme template step.
    Template {
        /// Recognized scheme template step being applied.
        name: String,
    },
}

/// One documented canonicalization operation with its provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalizationStep {
    /// Ordered operation.
    pub operation: CanonicalizationOperation,
    /// Human-readable explanation.
    pub description: String,
    /// Evidence origin.
    pub source_type: SourceType,
}

/// Cryptographic primitive used for the final signature.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerPrimitive {
    /// HMAC with a named hash.
    Hmac {
        /// Hash function used by the HMAC primitive.
        hash: String,
    },
    /// RSA signature with a named hash/padding family.
    Rsa {
        /// RSA signature and padding algorithm.
        algorithm: String,
    },
    /// ECDSA signature with a named hash.
    Ecdsa {
        /// ECDSA signature algorithm and hash combination.
        algorithm: String,
    },
    /// Digest-only observation.
    Digest {
        /// Digest algorithm observed without a signing operation.
        algorithm: String,
    },
    /// Primitive could not be normalized further.
    Unknown {
        /// Original algorithm label retained when normalization is unavailable.
        algorithm: String,
    },
}

/// Credential boundary; no key bytes are representable here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignerKeySource {
    /// Secret is resolved from a caller-supplied credential provider.
    CredentialReference {
        /// Stable secret reference, never the secret value.
        secret_ref: String,
        /// Optional external provider name/reference.
        provider: Option<String>,
    },
    /// Signing remains inside the original runtime/device.
    DeviceOracle {
        /// Callback identifier generated by the instrumentation boundary.
        callback_id: String,
        /// Why the key cannot be exported.
        reason: String,
    },
    /// External signer/provider owns the key operation.
    ExternalProvider {
        /// Stable reference for the external signing provider.
        provider_ref: String,
    },
}

/// Signature bytes and their request-wire placement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerOutput {
    /// Output encoding.
    pub encoding: String,
    /// Header, query, body, or other wire location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_location: Option<String>,
    /// Prefix placed before encoded signature bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Suffix placed after encoded signature bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suffix: Option<String>,
    /// Optional truncation length observed on the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation: Option<usize>,
}

/// Runtime values needed at sign time.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerRuntime {
    /// Timestamp format, such as epoch seconds or RFC3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_format: Option<String>,
    /// Nonce source contract, such as random or monotonic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_source: Option<String>,
    /// Replay validity window, when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_window_seconds: Option<u64>,
}

/// Request shape consumed by the generated sign interface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerRequest {
    /// Method expression.
    pub method: String,
    /// Path expression.
    pub path: String,
    /// Query pairs.
    pub query: Vec<(String, String)>,
    /// Header pairs.
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// Fixture supporting a signer artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerFixture {
    /// Source capture identifier.
    pub capture_id: String,
    /// Whether the fixture was held out during inference.
    pub held_out: bool,
    /// Request used by the fixture.
    pub request: SignerRequest,
    /// Canonical bytes supporting the candidate.
    pub canonical_bytes: Vec<u8>,
    /// Observed output bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Vec<u8>>,
    /// Whether held-out replay matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_match: Option<bool>,
}

/// Ranked alternative retained for a partial signer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerAlternative {
    /// Candidate identifier.
    pub hypothesis_id: String,
    /// Candidate confidence.
    pub confidence: f64,
    /// Candidate operations.
    pub canonicalization_steps: Vec<CanonicalizationStep>,
    /// Candidate supporting fixtures.
    pub fixtures: Vec<SignerFixture>,
}

/// Language-neutral sign interface for Phase 6 SDK generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerInterface {
    /// Stable operation name.
    pub operation: String,
    /// Request type name in the generated SDK.
    pub request_type: String,
    /// Credential provider parameter type.
    pub credential_provider_type: String,
    /// Clock parameter type.
    pub clock_type: String,
    /// Nonce source parameter type.
    pub nonce_source_type: String,
    /// Return type containing the signed request and trace.
    pub return_type: String,
    /// Provenance/diagnostic trace type.
    pub trace_type: String,
    /// Device callback type for device-oracle mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_oracle_callback_type: Option<String>,
}

impl Default for SignerInterface {
    fn default() -> Self {
        Self {
            operation: "sign".to_owned(),
            request_type: "SignerRequest".to_owned(),
            credential_provider_type: "CredentialProvider".to_owned(),
            clock_type: "Clock".to_owned(),
            nonce_source_type: "NonceSource".to_owned(),
            return_type: "SignedRequest".to_owned(),
            trace_type: "SignerTrace".to_owned(),
            device_oracle_callback_type: None,
        }
    }
}

/// Provenance attached to the signer fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerProvenance {
    /// Static, dynamic, or fusion origin.
    pub source_type: SourceType,
    /// Capture or activity identifiers.
    pub evidence_ids: Vec<String>,
    /// Human-readable evidence summary.
    pub detail: String,
}

/// Reusable signer artifact carried with an API surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerArtifact {
    /// Signer IR schema version.
    pub schema_version: u32,
    /// Stable artifact identifier.
    pub signer_id: String,
    /// Scheme identity.
    pub scheme: SignerScheme,
    /// Honest reproducibility mode, serialized as `signer_mode`.
    #[serde(rename = "signer_mode")]
    pub signer_mode: SignerMode,
    /// Bounded confidence score.
    pub confidence: f64,
    /// Request components covered by the signature.
    pub coverage: Vec<SignedComponent>,
    /// Ordered canonicalization operations.
    pub canonicalization_steps: Vec<CanonicalizationStep>,
    /// Final primitive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primitive: Option<SignerPrimitive>,
    /// Credential/device boundary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<SignerKeySource>,
    /// Output encoding and wire placement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<SignerOutput>,
    /// Runtime timestamp/nonce behavior.
    pub runtime: SignerRuntime,
    /// Primary and alternative supporting fixtures.
    pub fixtures: Vec<SignerFixture>,
    /// Ranked alternatives retained for review.
    pub ranked_alternatives: Vec<SignerAlternative>,
    /// Phase 6 interface contract.
    pub interface: SignerInterface,
    /// Reproduction prose suitable for generated SDK metadata.
    pub reproduction: String,
    /// Evidence provenance.
    pub provenance: Vec<SignerProvenance>,
}

impl SignerArtifact {
    /// Validates signer mode/confidence invariants at the model boundary.
    pub(crate) fn validate(&self, path: &str) -> ModelResult<()> {
        if self.schema_version != SIGNER_IR_SCHEMA_VERSION {
            return Err(ModelError::invariant(
                format!("{path}.schema_version"),
                "unsupported signer IR schema version",
            ));
        }
        if self.signer_id.trim().is_empty() {
            return Err(ModelError::invariant(
                format!("{path}.signer_id"),
                "signer ID must not be blank",
            ));
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(ModelError::invariant(
                format!("{path}.confidence"),
                "signer confidence must be finite and between 0 and 1",
            ));
        }
        if self.provenance.is_empty()
            || self
                .provenance
                .iter()
                .any(|provenance| provenance.detail.trim().is_empty())
        {
            return Err(ModelError::invariant(
                format!("{path}.provenance"),
                "signers must retain non-empty evidence provenance",
            ));
        }
        if self.signer_mode == SignerMode::DeviceOracle
            && !matches!(self.key_source, Some(SignerKeySource::DeviceOracle { .. }))
        {
            return Err(ModelError::invariant(
                format!("{path}.key_source"),
                "device-oracle signers must retain a device callback reference",
            ));
        }
        Ok(())
    }
}
