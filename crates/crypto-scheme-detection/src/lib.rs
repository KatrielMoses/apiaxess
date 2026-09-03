//! Phase 4.2: recognize known signing schemes before generic inference.
//!
//! Each scheme is a sibling implementation of `SchemeTemplate`. The detector
//! evaluates every registered template and never selects through a scheme
//! specific central switch.

use std::collections::BTreeMap;

use apiaxess_api_model::provenance::SourceType;
use apiaxess_crypto_capture::{CryptoCaptureRecord, KeyObservation};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use serde::{Deserialize, Serialize};

mod templates;
pub use templates::builtin_templates;

/// Current Phase 4.2 detection-result schema.
pub const SCHEME_DETECTION_SCHEMA_VERSION: u32 = 1;

/// Static indicators supplied by the Phase 1 analysis boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticSigningIndicators {
    /// Package names associated with the analyzed application.
    pub package_names: Vec<String>,
    /// String constants that may identify signing behavior.
    pub string_constants: Vec<String>,
    /// Literals already classified as signing-related by static analysis.
    pub signing_literals: Vec<String>,
}

/// One captured request and all Phase 4.1 operations attributed to it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningEvidence {
    /// Request identifier for correlating evidence with captured traffic.
    pub request_id: Option<String>,
    /// Network flow identifier associated with the request.
    pub flow_id: Option<u64>,
    /// HTTP method observed for the request.
    pub method: Option<String>,
    /// Request path observed for the request.
    pub path: Option<String>,
    /// Header name/value pairs available to scheme templates.
    pub headers: Vec<(String, String)>,
    /// Query parameter name/value pairs available to scheme templates.
    pub query: Vec<(String, String)>,
    /// Request body bytes, when captured.
    pub body: Option<Vec<u8>>,
    /// Static-analysis markers attributed to the application.
    pub static_indicators: StaticSigningIndicators,
    /// Completed crypto operations attributed to this request.
    pub crypto_operations: Vec<CryptoCaptureRecord>,
    /// Keystore and key-derivation observations attributed to this request.
    pub key_observations: Vec<KeyObservation>,
}

impl SigningEvidence {
    /// Returns a case-insensitive header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Returns true if any static indicator contains a marker.
    #[must_use]
    pub fn static_contains(&self, marker: &str) -> bool {
        self.static_indicators
            .package_names
            .iter()
            .chain(self.static_indicators.string_constants.iter())
            .chain(self.static_indicators.signing_literals.iter())
            .any(|value| contains_ci(value, marker))
    }

    /// Returns all request-visible values, including query values.
    #[must_use]
    pub fn visible_values(&self) -> Vec<&str> {
        self.headers
            .iter()
            .map(|(_, value)| value.as_str())
            .chain(self.query.iter().map(|(_, value)| value.as_str()))
            .collect()
    }
}

/// Known canonicalization/reproduction shortcut handed to Phase 4.3.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReproductionShortcut {
    /// AWS Signature Version 4 canonicalization and key-derivation template.
    AwsSigV4,
    /// OAuth 1.0 HMAC normalization and signing template.
    OAuth1Hmac,
    /// JSON Web Signature three-segment encoding template.
    JwtJws,
    /// HTTP Message Signatures / RFC 9421 template.
    HttpMessageSignatures,
    /// Generic HMAC path requiring further Phase 4.3 inference.
    CustomHmac,
    /// Public-key request signature with observed output shape.
    PublicKeyRequestSignature {
        /// Algorithm label reported by the captured primitive.
        algorithm: Option<String>,
        /// Shape or encoding of the observed signature bytes.
        output_shape: String,
    },
}

impl ReproductionShortcut {
    /// Returns the ordered canonicalization/reproduction steps that Phase 4.3
    /// should use as its starting hypothesis.
    #[must_use]
    pub fn canonicalization_steps(&self) -> &'static [&'static str] {
        match self {
            Self::AwsSigV4 => &[
                "canonical_request",
                "string_to_sign",
                "hmac_aws4_date",
                "hmac_region",
                "hmac_service",
                "hmac_terminator",
            ],
            Self::OAuth1Hmac => &["rfc5849_normalize_parameters", "rfc5849_base_string"],
            Self::JwtJws => &["base64url_header", "dot", "base64url_payload"],
            Self::HttpMessageSignatures => &[
                "ordered_covered_components",
                "signature_params",
                "component_serialization",
            ],
            Self::CustomHmac => &["generic_hmac_message_requires_phase_4_3_inference"],
            Self::PublicKeyRequestSignature { .. } => &[
                "request_message_requires_phase_4_3_inference",
                "observed_signature_encoding",
            ],
        }
    }
}

/// One matched marker with source provenance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndicatorMatch {
    /// Stable identifier for the matched indicator.
    pub id: String,
    /// Evidence boundary that supplied the indicator.
    pub source_type: SourceType,
    /// Human-readable explanation of the match.
    pub detail: String,
    /// Contribution of this indicator to candidate confidence.
    pub weight: f64,
}

/// A candidate produced by one scheme template.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemeCandidate {
    /// Stable identifier of the proposed signing scheme.
    pub scheme_id: String,
    /// Display name of the proposed scheme.
    pub name: String,
    /// Bounded confidence score computed from the indicators.
    pub confidence: f64,
    /// Evidence retained to explain the candidate score.
    pub indicators: Vec<IndicatorMatch>,
    /// Starting point for reproducing the candidate scheme.
    pub reproduction: ReproductionShortcut,
}

impl SchemeCandidate {
    /// Recomputes the bounded score from retained indicator weights.
    #[must_use]
    pub fn recompute_confidence(&self) -> f64 {
        self.indicators
            .iter()
            .map(|indicator| indicator.weight)
            .sum::<f64>()
            .min(1.0)
    }
}

/// Final detector outcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DetectionOutcome {
    /// One candidate exceeded the recognition threshold with sufficient margin.
    Recognized {
        /// Selected scheme candidate and its supporting evidence.
        identification: SchemeCandidate,
    },
    /// Multiple candidates remain too close to select honestly.
    Ambiguous {
        /// Candidates within the configured ambiguity margin.
        candidates: Vec<SchemeCandidate>,
    },
    /// No candidate reached the recognition threshold.
    Unrecognized {
        /// Ranked candidates retained for later analysis.
        candidates: Vec<SchemeCandidate>,
    },
}

/// Durable result tied to the request that supplied the evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemeDetection {
    /// Schema version used to serialize this result.
    pub schema_version: u32,
    /// Request identifier that supplied the evidence.
    pub request_id: Option<String>,
    /// Network flow identifier that supplied the evidence.
    pub flow_id: Option<u64>,
    /// Recognized, ambiguous, or unrecognized detector outcome.
    pub result: DetectionOutcome,
    /// Structured diagnostic explaining the detector outcome.
    pub diagnostic: Diagnostic,
}

/// One declarative/template detector.
pub trait SchemeTemplate: Send + Sync {
    /// Returns the stable identifier serialized for this template.
    fn id(&self) -> &'static str;
    /// Returns the human-readable name shown for this template.
    fn name(&self) -> &'static str;
    /// Evaluates request evidence and returns a candidate when indicators match.
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate>;
}

/// Extensible registry of sibling scheme templates.
pub struct SchemeRegistry {
    templates: Vec<Box<dyn SchemeTemplate>>,
}

impl Default for SchemeRegistry {
    fn default() -> Self {
        Self {
            templates: builtin_templates(),
        }
    }
}

impl SchemeRegistry {
    /// Creates an empty registry for plugin/community templates.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            templates: Vec::new(),
        }
    }

    /// Adds one sibling template without changing detector logic.
    pub fn register(&mut self, template: Box<dyn SchemeTemplate>) {
        self.templates.push(template);
    }

    /// Number of registered templates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Whether no templates are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

/// Recognition thresholds and template registry.
pub struct SchemeDetector {
    registry: SchemeRegistry,
    recognition_threshold: f64,
    ambiguity_delta: f64,
}

impl Default for SchemeDetector {
    fn default() -> Self {
        Self {
            registry: SchemeRegistry::default(),
            recognition_threshold: 0.62,
            ambiguity_delta: 0.08,
        }
    }
}

impl SchemeDetector {
    /// Creates a detector from a community/plugin registry.
    #[must_use]
    pub fn new(registry: SchemeRegistry) -> Self {
        Self {
            registry,
            ..Self::default()
        }
    }

    /// Sets the minimum confidence required for recognition.
    #[must_use]
    pub fn with_recognition_threshold(mut self, threshold: f64) -> Self {
        self.recognition_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Detects a scheme and emits an outcome diagnostic.
    #[must_use]
    pub fn detect(&self, evidence: &SigningEvidence) -> SchemeDetection {
        let mut candidates: Vec<_> = self
            .registry
            .templates
            .iter()
            .filter_map(|template| template.evaluate(evidence))
            .collect();
        candidates.sort_by(|left, right| right.confidence.total_cmp(&left.confidence));
        let result = if let Some(top) = candidates
            .first()
            .cloned()
            .filter(|candidate| candidate.confidence >= self.recognition_threshold)
        {
            if candidates.get(1).is_some_and(|next| {
                next.confidence >= self.recognition_threshold
                    && top.confidence - next.confidence <= self.ambiguity_delta
            }) {
                DetectionOutcome::Ambiguous {
                    candidates: candidates
                        .into_iter()
                        .filter(|candidate| {
                            candidate.confidence >= self.recognition_threshold
                                && top.confidence - candidate.confidence <= self.ambiguity_delta
                        })
                        .collect(),
                }
            } else {
                DetectionOutcome::Recognized {
                    identification: top,
                }
            }
        } else {
            DetectionOutcome::Unrecognized { candidates }
        };
        let diagnostic = outcome_diagnostic(evidence, &result);
        SchemeDetection {
            schema_version: SCHEME_DETECTION_SCHEMA_VERSION,
            request_id: evidence.request_id.clone(),
            flow_id: evidence.flow_id,
            result,
            diagnostic,
        }
    }
}

fn outcome_diagnostic(evidence: &SigningEvidence, result: &DetectionOutcome) -> Diagnostic {
    let (definition, scheme, confidence, candidates) = match result {
        DetectionOutcome::Recognized { identification } => (
            catalogue::CRYPTO_SCHEME_RECOGNIZED,
            Some(identification.scheme_id.clone()),
            Some(identification.confidence),
            vec![identification.scheme_id.clone()],
        ),
        DetectionOutcome::Ambiguous { candidates } => (
            catalogue::CRYPTO_SCHEME_AMBIGUOUS,
            None,
            candidates.first().map(|candidate| candidate.confidence),
            candidates
                .iter()
                .map(|candidate| candidate.scheme_id.clone())
                .collect(),
        ),
        DetectionOutcome::Unrecognized { candidates } => (
            catalogue::CRYPTO_SCHEME_UNRECOGNIZED,
            None,
            candidates.first().map(|candidate| candidate.confidence),
            candidates
                .iter()
                .map(|candidate| candidate.scheme_id.clone())
                .collect(),
        ),
    };
    let mut context = DiagnosticContext::new();
    if let Some(request_id) = &evidence.request_id {
        context.insert(
            "request_id".to_owned(),
            DiagnosticValue::String(request_id.clone()),
        );
    }
    if let Some(flow_id) = evidence.flow_id {
        context.insert(
            "flow_id".to_owned(),
            DiagnosticValue::Integer(i64::try_from(flow_id).unwrap_or(i64::MAX)),
        );
    }
    if let Some(scheme) = scheme {
        context.insert("scheme_id".to_owned(), DiagnosticValue::String(scheme));
    }
    if let Some(confidence) = confidence {
        context.insert(
            "confidence".to_owned(),
            DiagnosticValue::String(format!("{confidence:.3}")),
        );
    }
    context.insert(
        "candidate_schemes".to_owned(),
        DiagnosticValue::StringList(candidates),
    );
    definition.instantiate(context)
}

/// Creates one provenance-bearing marker.
#[must_use]
pub(crate) fn indicator(
    id: &str,
    source_type: SourceType,
    detail: impl Into<String>,
    weight: f64,
) -> IndicatorMatch {
    IndicatorMatch {
        id: id.to_owned(),
        source_type,
        detail: detail.into(),
        weight,
    }
}

/// Creates a normalized candidate from template-local indicators.
#[must_use]
pub(crate) fn candidate(
    template: &dyn SchemeTemplate,
    indicators: Vec<IndicatorMatch>,
    reproduction: ReproductionShortcut,
) -> Option<SchemeCandidate> {
    if indicators.is_empty() {
        return None;
    }
    let confidence = indicators
        .iter()
        .map(|indicator| indicator.weight)
        .sum::<f64>()
        .min(1.0);
    Some(SchemeCandidate {
        scheme_id: template.id().to_owned(),
        name: template.name().to_owned(),
        confidence,
        indicators,
        reproduction,
    })
}

/// Case-insensitive token search.
#[must_use]
pub(crate) fn contains_ci(value: &str, marker: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&marker.to_ascii_lowercase())
}

/// Returns whether a header or query name exists.
#[must_use]
pub(crate) fn has_name(evidence: &SigningEvidence, name: &str) -> bool {
    evidence
        .headers
        .iter()
        .chain(evidence.query.iter())
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

/// Returns whether any HMAC operation is present.
#[must_use]
pub(crate) fn has_hmac(evidence: &SigningEvidence) -> bool {
    evidence.crypto_operations.iter().any(|operation| {
        operation
            .algorithm
            .as_deref()
            .is_some_and(|algorithm| contains_ci(algorithm, "hmac"))
    })
}

/// Returns whether an operation has the requested algorithm marker.
#[must_use]
pub(crate) fn has_algorithm(evidence: &SigningEvidence, marker: &str) -> bool {
    evidence.crypto_operations.iter().any(|operation| {
        operation
            .algorithm
            .as_deref()
            .is_some_and(|algorithm| contains_ci(algorithm, marker))
    })
}

/// Detects a three-segment Base64URL-looking request value.
#[must_use]
pub(crate) fn has_jwt_value(evidence: &SigningEvidence) -> bool {
    evidence
        .visible_values()
        .iter()
        .flat_map(|value| value.split_whitespace())
        .any(|token| {
            let segments: Vec<_> = token.split('.').collect();
            segments.len() == 3
                && segments.iter().all(|segment| {
                    !segment.is_empty()
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'=')
                        })
                })
        })
}

/// Detects a DER-like or fixed-length public-key output.
#[must_use]
pub(crate) fn public_key_shape(evidence: &SigningEvidence) -> Option<String> {
    evidence.crypto_operations.iter().find_map(|operation| {
        if !matches!(
            operation.primitive,
            apiaxess_crypto_capture::Primitive::Signature
        ) {
            return None;
        }
        let output = operation.primitive_output.as_ref()?;
        if output.first() == Some(&0x30) {
            Some("der".to_owned())
        } else if matches!(output.len(), 64 | 96 | 128 | 256 | 384 | 512) {
            Some("fixed_length".to_owned())
        } else {
            Some("unknown".to_owned())
        }
    })
}

/// Groups matched indicators by source type for integrations.
#[must_use]
pub fn provenance_summary(detection: &SchemeDetection) -> BTreeMap<String, Vec<String>> {
    let candidates: Vec<&SchemeCandidate> = match &detection.result {
        DetectionOutcome::Recognized { identification } => vec![identification],
        DetectionOutcome::Ambiguous { candidates }
        | DetectionOutcome::Unrecognized { candidates } => candidates.iter().collect(),
    };
    let mut summary = BTreeMap::new();
    for candidate in candidates {
        for indicator in &candidate.indicators {
            summary
                .entry(format!("{:?}", indicator.source_type).to_ascii_lowercase())
                .or_insert_with(Vec::new)
                .push(format!("{}: {}", indicator.id, indicator.detail));
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_crypto_capture::{KeyCapture, KeyExportability, Primitive};

    fn hmac(operation_id: &str, algorithm: &str) -> CryptoCaptureRecord {
        CryptoCaptureRecord {
            schema_version: 1,
            operation_id: operation_id.to_owned(),
            primitive: Primitive::Mac,
            algorithm: Some(algorithm.to_owned()),
            provider: Some("Conscrypt".to_owned()),
            key: KeyCapture {
                exportability: KeyExportability::Exportable,
                ..KeyCapture::default()
            },
            updates: Vec::new(),
            accumulated_message: b"message".to_vec(),
            primitive_output: Some(vec![1; 32]),
            update_outputs: Vec::new(),
            wire_output: Vec::new(),
            stacks: Vec::new(),
            thread_id: Some(1),
            request_id: Some("flow:1".to_owned()),
            flow_id: Some(1),
            reused_after_finalize: false,
        }
    }

    #[test]
    fn sigv4_uses_static_and_runtime_evidence() {
        let evidence = SigningEvidence {
            request_id: Some("req-1".to_owned()),
            flow_id: Some(1),
            headers: vec![
                ("Authorization".to_owned(), "AWS4-HMAC-SHA256 Credential=a/20260822/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc".to_owned()),
                ("x-amz-date".to_owned(), "20260822T000000Z".to_owned()),
            ],
            static_indicators: StaticSigningIndicators {
                string_constants: vec!["AWS4-HMAC-SHA256".to_owned()],
                ..StaticSigningIndicators::default()
            },
            crypto_operations: vec![
                hmac("h1", "HmacSHA256"),
                hmac("h2", "HmacSHA256"),
                hmac("h3", "HmacSHA256"),
                hmac("h4", "HmacSHA256"),
            ],
            ..SigningEvidence::default()
        };
        let result = SchemeDetector::default().detect(&evidence);
        assert!(
            matches!(&result.result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "aws-sigv4" && identification.confidence > 0.8)
        );
        assert_eq!(result.diagnostic.id.as_ref(), "crypto.scheme-recognized");
        assert!(provenance_summary(&result).contains_key("staticanalysis"));
    }

    #[test]
    fn jwt_uses_three_segments_and_hmac_evidence() {
        let evidence = SigningEvidence {
            headers: vec![(
                "Authorization".to_owned(),
                "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig-_".to_owned(),
            )],
            crypto_operations: vec![hmac("jwt", "HmacSHA256")],
            ..SigningEvidence::default()
        };
        let result = SchemeDetector::default().detect(&evidence);
        assert!(
            matches!(result.result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "jwt-jws")
        );
    }

    #[test]
    fn bare_hmac_is_honestly_unrecognized() {
        let evidence = SigningEvidence {
            crypto_operations: vec![hmac("h", "HmacSHA256")],
            ..SigningEvidence::default()
        };
        let result = SchemeDetector::default().detect(&evidence);
        assert!(matches!(
            result.result,
            DetectionOutcome::Unrecognized { .. }
        ));
        assert_eq!(result.diagnostic.id.as_ref(), "crypto.scheme-unrecognized");
    }

    #[test]
    fn oauth_rfc9421_custom_hmac_and_public_key_templates_match() {
        let oauth = SigningEvidence {
            headers: vec![
                ("Authorization".to_owned(), "OAuth oauth_nonce=\"n\", oauth_timestamp=\"1\", oauth_signature_method=\"HMAC-SHA1\"".to_owned()),
                ("oauth_nonce".to_owned(), "n".to_owned()),
                ("oauth_timestamp".to_owned(), "1".to_owned()),
            ],
            crypto_operations: vec![hmac("oauth", "HmacSHA1")],
            ..SigningEvidence::default()
        };
        assert!(
            matches!(SchemeDetector::default().detect(&oauth).result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "oauth1-hmac")
        );

        let rfc9421 = SigningEvidence {
            headers: vec![
                (
                    "Signature-Input".to_owned(),
                    "sig1=(\"@method\" \"@authority\" \"content-digest\");created=1".to_owned(),
                ),
                ("Signature".to_owned(), "sig1=:abc:".to_owned()),
            ],
            ..SigningEvidence::default()
        };
        assert!(
            matches!(SchemeDetector::default().detect(&rfc9421).result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "http-message-signatures-rfc9421")
        );

        let custom = SigningEvidence {
            headers: vec![
                ("X-Api-Signature".to_owned(), "deadbeef".to_owned()),
                ("X-Timestamp".to_owned(), "1".to_owned()),
            ],
            crypto_operations: vec![hmac("custom", "HmacSHA256")],
            ..SigningEvidence::default()
        };
        assert!(
            matches!(SchemeDetector::default().detect(&custom).result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "custom-hmac-header")
        );

        let mut public = hmac("public", "SHA256withRSA");
        public.primitive = Primitive::Signature;
        public.primitive_output = Some(vec![0x30, 0x10, 1, 2]);
        let public_evidence = SigningEvidence {
            headers: vec![("X-Signature".to_owned(), "DER".to_owned())],
            crypto_operations: vec![public],
            ..SigningEvidence::default()
        };
        assert!(
            matches!(SchemeDetector::default().detect(&public_evidence).result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "rsa-ecdsa-request-signature")
        );
    }

    #[test]
    fn community_template_is_a_registry_addition() {
        struct Community;
        impl SchemeTemplate for Community {
            fn id(&self) -> &'static str {
                "community-example"
            }
            fn name(&self) -> &'static str {
                "Community example"
            }
            fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
                if evidence.static_contains("community-signature") {
                    candidate(
                        self,
                        vec![indicator(
                            "community-literal",
                            SourceType::StaticAnalysis,
                            "static marker",
                            0.9,
                        )],
                        ReproductionShortcut::CustomHmac,
                    )
                } else {
                    None
                }
            }
        }
        let mut registry = SchemeRegistry::empty();
        registry.register(Box::new(Community));
        let evidence = SigningEvidence {
            static_indicators: StaticSigningIndicators {
                string_constants: vec!["community-signature".to_owned()],
                ..StaticSigningIndicators::default()
            },
            ..SigningEvidence::default()
        };
        let result = SchemeDetector::new(registry).detect(&evidence);
        assert!(
            matches!(result.result, DetectionOutcome::Recognized { identification } if identification.scheme_id == "community-example")
        );
    }
}
