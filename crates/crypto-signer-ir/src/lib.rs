//! Phase 4.4: emit the reusable signer IR without embedding secrets.

use apiaxess_api_model::provenance::SourceType;
use apiaxess_api_model::{
    ApiSurface, CanonicalizationOperation, CanonicalizationStep, SIGNER_IR_SCHEMA_VERSION,
    SignedComponent, SignerAlternative, SignerArtifact, SignerFixture, SignerInterface,
    SignerKeySource, SignerMode, SignerOutput, SignerPrimitive, SignerProvenance, SignerRequest,
    SignerRuntime, SignerScheme,
};
use apiaxess_crypto_canonicalization::{
    CanonicalSource, CanonicalizationFixture, CanonicalizationHypothesis,
    CanonicalizationInference, InferenceOutcome, ValueEncoding,
};
use apiaxess_crypto_capture::{CryptoCaptureRecord, KeyExportability, Primitive};
use apiaxess_crypto_scheme_detection::ReproductionShortcut;
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use serde::{Deserialize, Serialize};

/// Credential reference supplied by the caller at sign time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialReference {
    /// Stable secret identifier; never the secret value.
    pub secret_ref: String,
    /// Optional external credential provider.
    pub provider: Option<String>,
}

/// Inputs needed to turn 4.3 evidence into a signer artifact.
#[derive(Clone, Debug)]
pub struct SignerEmissionInput {
    /// Stable artifact identifier.
    pub signer_id: String,
    /// Recognized Phase 4.2 scheme, if any.
    pub scheme_shortcut: Option<ReproductionShortcut>,
    /// Phase 4.3 inference result.
    pub inference: CanonicalizationInference,
    /// Representative Phase 4.1 primitive/key/output observation.
    pub representative_operation: Option<CryptoCaptureRecord>,
    /// Credential reference used for exportable-key modes.
    pub credential: Option<CredentialReference>,
    /// Device callback ID for non-exportable or white-box signing.
    pub device_oracle_callback_id: Option<String>,
    /// Explicit white-box/runtime-only reason, if known.
    pub device_oracle_reason: Option<String>,
    /// Runtime values observed by capture or supplied by the integration.
    pub runtime: SignerRuntime,
    /// Optional prefix observed before the wire signature.
    pub wire_prefix: Option<String>,
    /// Optional suffix observed after the wire signature.
    pub wire_suffix: Option<String>,
}

/// Emission result. Blocked inference produces no artifact; observed-only is
/// still a durable artifact because it records the primitive honestly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerEmission {
    /// Artifact when enough evidence exists to emit an honest mode.
    pub artifact: Option<SignerArtifact>,
    /// Diagnostic-legible emission state.
    pub diagnostic: Diagnostic,
}

/// Emits the language-neutral signer IR consumed by Phase 6.
#[derive(Clone, Debug, Default)]
pub struct SignerEmitter;

impl SignerEmitter {
    /// Packages inference, primitive metadata, credential boundary, fixtures,
    /// and the generated-SDK sign interface into a reusable artifact.
    #[must_use]
    pub fn emit(&self, input: &SignerEmissionInput) -> SignerEmission {
        let (inference_mode, hypotheses, reason) = match &input.inference.outcome {
            InferenceOutcome::Reproducible { hypotheses } => {
                (SignerMode::Reproducible, hypotheses.clone(), None)
            }
            InferenceOutcome::PartialHypothesis { hypotheses, reason } => (
                SignerMode::PartialHypothesis,
                hypotheses.clone(),
                Some(reason.clone()),
            ),
            InferenceOutcome::ObservedOnly { reason, .. } => {
                (SignerMode::ObservedOnly, Vec::new(), Some(reason.clone()))
            }
            InferenceOutcome::Blocked { reason } => {
                return SignerEmission {
                    artifact: None,
                    diagnostic: emission_diagnostic(
                        None,
                        SignerMode::ObservedOnly,
                        0.0,
                        &input.signer_id,
                        reason,
                    ),
                };
            }
        };

        let device_reason = device_oracle_reason(input);
        let device_mode = device_reason.is_some();
        let missing_credential = inference_mode == SignerMode::Reproducible
            && input.credential.is_none()
            && !device_mode;
        let mode = if device_mode {
            SignerMode::DeviceOracle
        } else if missing_credential {
            SignerMode::PartialHypothesis
        } else {
            inference_mode
        };
        let top = hypotheses.first();
        let confidence = top.map_or(0.0, |hypothesis| hypothesis.confidence);
        let scheme = input.scheme_shortcut.as_ref().map_or_else(
            || SignerScheme::Unrecognized {
                label: "custom_or_unrecognized".to_owned(),
            },
            shortcut_scheme,
        );
        let key_source = if let Some(reason) = device_reason.clone() {
            Some(SignerKeySource::DeviceOracle {
                callback_id: input
                    .device_oracle_callback_id
                    .clone()
                    .unwrap_or_else(|| "original-runtime".to_owned()),
                reason,
            })
        } else {
            input
                .credential
                .as_ref()
                .map(|credential| SignerKeySource::CredentialReference {
                    secret_ref: credential.secret_ref.clone(),
                    provider: credential.provider.clone(),
                })
        };
        let canonicalization_steps = top.map_or_else(Vec::new, hypothesis_steps);
        let coverage = top.map_or_else(Vec::new, hypothesis_coverage);
        let ranked_alternatives = hypotheses
            .iter()
            .map(|hypothesis| SignerAlternative {
                hypothesis_id: hypothesis.hypothesis_id.clone(),
                confidence: hypothesis.confidence,
                canonicalization_steps: hypothesis_steps(hypothesis),
                fixtures: hypothesis.fixtures.iter().map(fixture).collect(),
            })
            .collect::<Vec<_>>();
        let fixtures = top.map_or_else(Vec::new, |hypothesis| {
            hypothesis.fixtures.iter().map(fixture).collect()
        });
        let primitive = input
            .representative_operation
            .as_ref()
            .map(primitive_from_operation);
        let output = input
            .representative_operation
            .as_ref()
            .map(|operation| output_from_operation(operation, input));
        let interface = interface_for_mode(mode, input.device_oracle_callback_id.is_some());
        let reproduction = reproduction_text(mode);
        let mut provenance = vec![SignerProvenance {
            source_type: SourceType::Fusion,
            evidence_ids: input
                .inference
                .training_capture_ids
                .iter()
                .chain(input.inference.held_out_capture_ids.iter())
                .cloned()
                .collect(),
            detail: "Signer IR emitted from Phase 4.1 primitive evidence and Phase 4.3 canonicalization inference.".to_owned(),
        }];
        if device_mode {
            provenance.push(SignerProvenance {
                source_type: SourceType::DynamicCapture,
                evidence_ids: input.inference.training_capture_ids.clone(),
                detail:
                    "Key exportability or white-box behavior requires the original runtime/device."
                        .to_owned(),
            });
        }
        let artifact = SignerArtifact {
            schema_version: SIGNER_IR_SCHEMA_VERSION,
            signer_id: input.signer_id.clone(),
            scheme,
            signer_mode: mode,
            confidence,
            coverage,
            canonicalization_steps,
            primitive,
            key_source,
            output,
            runtime: input.runtime.clone(),
            fixtures,
            ranked_alternatives,
            interface,
            reproduction,
            provenance,
        };
        let diagnostic_reason = reason.unwrap_or_else(|| {
            if missing_credential {
                "A credential reference is required before a reproducible signer can be used."
                    .to_owned()
            } else {
                "Signer artifact emitted.".to_owned()
            }
        });
        SignerEmission {
            diagnostic: emission_diagnostic(
                Some(&artifact),
                mode,
                confidence,
                &input.signer_id,
                &diagnostic_reason,
            ),
            artifact: Some(artifact),
        }
    }

    /// Emits and persists an honest artifact as a first-class API-model signer.
    #[must_use]
    pub fn emit_into_surface(
        &self,
        surface: &mut ApiSurface,
        input: &SignerEmissionInput,
    ) -> SignerEmission {
        let emission = self.emit(input);
        if let Some(artifact) = &emission.artifact {
            surface.signers.push(artifact.clone());
        }
        emission
    }
}

fn shortcut_scheme(shortcut: &ReproductionShortcut) -> SignerScheme {
    match shortcut {
        ReproductionShortcut::AwsSigV4 => SignerScheme::AwsSigV4,
        ReproductionShortcut::OAuth1Hmac => SignerScheme::OAuth1Hmac,
        ReproductionShortcut::JwtJws => SignerScheme::JwtJws,
        ReproductionShortcut::HttpMessageSignatures => SignerScheme::HttpMessageSignatures,
        ReproductionShortcut::CustomHmac => SignerScheme::CustomHmac,
        ReproductionShortcut::PublicKeyRequestSignature { .. } => {
            SignerScheme::PublicKeyRequestSignature
        }
    }
}

fn device_oracle_reason(input: &SignerEmissionInput) -> Option<String> {
    if let Some(reason) = input
        .device_oracle_reason
        .as_deref()
        .filter(|reason| !reason.trim().is_empty())
    {
        return Some(reason.to_owned());
    }
    if input.device_oracle_callback_id.is_some() {
        return Some("An explicit device-oracle callback was supplied.".to_owned());
    }
    let operation = input.representative_operation.as_ref()?;
    if operation.key.exportability == KeyExportability::NonExportable {
        return Some(
            "The signing key is non-exportable (for example, Keystore/hardware-backed).".to_owned(),
        );
    }
    if operation.key.hardware_backed == Some(true) {
        return Some(
            "The signing key is hardware-backed and must remain in the original runtime."
                .to_owned(),
        );
    }
    None
}

fn primitive_from_operation(operation: &CryptoCaptureRecord) -> SignerPrimitive {
    let algorithm = operation
        .algorithm
        .clone()
        .unwrap_or_else(|| "unknown".to_owned());
    let lower = algorithm.to_ascii_lowercase();
    match operation.primitive {
        Primitive::Mac => SignerPrimitive::Hmac {
            hash: algorithm
                .strip_prefix("Hmac")
                .unwrap_or(&algorithm)
                .to_owned(),
        },
        Primitive::Signature if lower.contains("rsa") => SignerPrimitive::Rsa { algorithm },
        Primitive::Signature if lower.contains("ecdsa") || lower.contains("ec") => {
            SignerPrimitive::Ecdsa { algorithm }
        }
        Primitive::Signature => SignerPrimitive::Unknown { algorithm },
        Primitive::MessageDigest => SignerPrimitive::Digest { algorithm },
        _ => SignerPrimitive::Unknown { algorithm },
    }
}

fn output_from_operation(
    operation: &CryptoCaptureRecord,
    input: &SignerEmissionInput,
) -> SignerOutput {
    let observation = operation.wire_output.first();
    SignerOutput {
        encoding: observation
            .and_then(|observation| observation.encoding.clone())
            .unwrap_or_else(|| "raw".to_owned()),
        wire_location: observation.and_then(|observation| observation.location.clone()),
        prefix: input.wire_prefix.clone(),
        suffix: input.wire_suffix.clone(),
        truncation: observation.and_then(|observation| {
            operation
                .primitive_output
                .as_ref()
                .filter(|output| observation.bytes.len() < output.len())
                .map(|_| observation.bytes.len())
        }),
    }
}

fn hypothesis_steps(hypothesis: &CanonicalizationHypothesis) -> Vec<CanonicalizationStep> {
    let mut steps = Vec::new();
    if let Some(shortcut) = &hypothesis.scheme_shortcut {
        for name in shortcut.canonicalization_steps() {
            steps.push(CanonicalizationStep {
                operation: CanonicalizationOperation::Template {
                    name: (*name).to_owned(),
                },
                description: format!("Phase 4.2 template step: {name}"),
                source_type: SourceType::Fusion,
            });
        }
    }
    for component in &hypothesis.components {
        let (operation, description) = match &component.source {
            CanonicalSource::Method => (
                CanonicalizationOperation::Field {
                    name: "method".to_owned(),
                },
                "Read HTTP method".to_owned(),
            ),
            CanonicalSource::Path => (
                CanonicalizationOperation::Field {
                    name: "path".to_owned(),
                },
                "Read request path".to_owned(),
            ),
            CanonicalSource::Query => (
                CanonicalizationOperation::Field {
                    name: "query".to_owned(),
                },
                "Read query in captured order".to_owned(),
            ),
            CanonicalSource::SortedQuery => (
                CanonicalizationOperation::Sort,
                "Sort query key/value pairs".to_owned(),
            ),
            CanonicalSource::Headers => (
                CanonicalizationOperation::Field {
                    name: "headers".to_owned(),
                },
                "Read headers in captured order".to_owned(),
            ),
            CanonicalSource::SortedHeaders => {
                (CanonicalizationOperation::Sort, "Sort headers".to_owned())
            }
            CanonicalSource::Body => (
                CanonicalizationOperation::Field {
                    name: "body".to_owned(),
                },
                "Read body bytes".to_owned(),
            ),
            CanonicalSource::Timestamp => (
                CanonicalizationOperation::Field {
                    name: "timestamp".to_owned(),
                },
                "Read runtime timestamp".to_owned(),
            ),
            CanonicalSource::Nonce => (
                CanonicalizationOperation::Field {
                    name: "nonce".to_owned(),
                },
                "Read runtime nonce".to_owned(),
            ),
            CanonicalSource::Literal(bytes) => (
                CanonicalizationOperation::Literal {
                    bytes: bytes.clone(),
                },
                "Insert observed literal bytes".to_owned(),
            ),
        };
        steps.push(CanonicalizationStep {
            operation,
            description,
            source_type: SourceType::DynamicCapture,
        });
        if let Some(operation) = encoding_operation(&component.encoding) {
            steps.push(CanonicalizationStep {
                operation,
                description: "Apply observed field encoding".to_owned(),
                source_type: SourceType::DynamicCapture,
            });
        }
    }
    if !hypothesis.delimiter.is_empty() {
        steps.push(CanonicalizationStep {
            operation: CanonicalizationOperation::Join {
                delimiter: hypothesis.delimiter.clone(),
            },
            description: "Join ordered components with the observed delimiter".to_owned(),
            source_type: SourceType::DynamicCapture,
        });
    }
    steps
}

fn encoding_operation(encoding: &ValueEncoding) -> Option<CanonicalizationOperation> {
    match encoding {
        ValueEncoding::Raw => None,
        ValueEncoding::PercentEncoded => Some(CanonicalizationOperation::UrlEncode),
        ValueEncoding::FormEncoded => Some(CanonicalizationOperation::FormEncode),
        ValueEncoding::HexLower => Some(CanonicalizationOperation::Hex),
        ValueEncoding::Base64 => Some(CanonicalizationOperation::Base64),
        ValueEncoding::Base64Url => Some(CanonicalizationOperation::Base64Url),
    }
}

fn hypothesis_coverage(hypothesis: &CanonicalizationHypothesis) -> Vec<SignedComponent> {
    let mut coverage = Vec::new();
    for component in &hypothesis.components {
        let value = match component.source {
            CanonicalSource::Method => Some(SignedComponent::Method),
            CanonicalSource::Path => Some(SignedComponent::Path),
            CanonicalSource::Query | CanonicalSource::SortedQuery => Some(SignedComponent::Query),
            CanonicalSource::Headers | CanonicalSource::SortedHeaders => {
                Some(SignedComponent::Headers)
            }
            CanonicalSource::Body => Some(SignedComponent::Body),
            CanonicalSource::Timestamp => Some(SignedComponent::Timestamp),
            CanonicalSource::Nonce => Some(SignedComponent::Nonce),
            CanonicalSource::Literal(_) => None,
        };
        if let Some(value) = value {
            if !coverage.contains(&value) {
                coverage.push(value);
            }
        }
    }
    coverage
}

fn fixture(fixture: &CanonicalizationFixture) -> SignerFixture {
    SignerFixture {
        capture_id: fixture.capture_id.clone(),
        held_out: fixture.held_out,
        request: SignerRequest {
            method: fixture.request.method.clone(),
            path: fixture.request.path.clone(),
            query: fixture.request.query.clone(),
            headers: fixture.request.headers.clone(),
            body: fixture.request.body.clone(),
        },
        canonical_bytes: fixture.canonical_bytes.clone(),
        output: fixture.observed_output.clone(),
        replay_match: fixture.replay_match,
    }
}

fn interface_for_mode(mode: SignerMode, has_callback: bool) -> SignerInterface {
    let mut interface = SignerInterface::default();
    if mode == SignerMode::DeviceOracle || has_callback {
        interface.device_oracle_callback_type = Some("DeviceSignerOracle".to_owned());
    }
    interface
}

fn reproduction_text(mode: SignerMode) -> String {
    match mode {
        SignerMode::Reproducible => "pure signer".to_owned(),
        SignerMode::PartialHypothesis => "ranked hypothesis; requires human review".to_owned(),
        SignerMode::ObservedOnly => "primitive observed; canonicalization not recovered".to_owned(),
        SignerMode::DeviceOracle => "requires original runtime".to_owned(),
    }
}

fn emission_diagnostic(
    artifact: Option<&SignerArtifact>,
    mode: SignerMode,
    confidence: f64,
    signer_id: &str,
    reason: &str,
) -> Diagnostic {
    let definition = match (artifact.is_some(), mode) {
        (false, _) => catalogue::CRYPTO_SIGNER_NOT_RECOVERABLE,
        (true, SignerMode::Reproducible) => catalogue::CRYPTO_SIGNER_EMITTED,
        (true, SignerMode::PartialHypothesis) => catalogue::CRYPTO_SIGNER_NEEDS_REVIEW,
        (true, SignerMode::DeviceOracle) => catalogue::CRYPTO_SIGNER_DEVICE_ORACLE,
        (true, SignerMode::ObservedOnly) => catalogue::CRYPTO_SIGNER_NOT_RECOVERABLE,
    };
    let mut context = DiagnosticContext::new();
    context.insert(
        "signer_id".to_owned(),
        DiagnosticValue::String(signer_id.to_owned()),
    );
    context.insert(
        "mode".to_owned(),
        DiagnosticValue::String(format_mode(mode)),
    );
    context.insert(
        "confidence".to_owned(),
        DiagnosticValue::String(format!("{confidence:.3}")),
    );
    context.insert(
        "reason".to_owned(),
        DiagnosticValue::String(reason.to_owned()),
    );
    definition.instantiate(context)
}

fn format_mode(mode: SignerMode) -> String {
    match mode {
        SignerMode::Reproducible => "reproducible",
        SignerMode::PartialHypothesis => "partial_hypothesis",
        SignerMode::ObservedOnly => "observed_only",
        SignerMode::DeviceOracle => "device_oracle",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_crypto_canonicalization::{
        CanonicalizationCapture, CanonicalizationInferer, InferenceInput, RequestSnapshot,
    };
    use apiaxess_crypto_capture::{KeyCapture, Primitive, UpdateChunk};

    fn operation(exportability: KeyExportability) -> CryptoCaptureRecord {
        CryptoCaptureRecord {
            schema_version: 1,
            operation_id: "op-1".to_owned(),
            primitive: Primitive::Mac,
            algorithm: Some("HmacSHA256".to_owned()),
            provider: None,
            key: KeyCapture {
                exportability,
                ..KeyCapture::default()
            },
            updates: vec![UpdateChunk {
                method: "update".to_owned(),
                bytes: b"GET/a".to_vec(),
                source_offset: None,
                source_length: None,
                byte_buffer: false,
            }],
            accumulated_message: b"GET/a".to_vec(),
            primitive_output: Some(b"signature".to_vec()),
            update_outputs: Vec::new(),
            wire_output: Vec::new(),
            stacks: Vec::new(),
            thread_id: None,
            request_id: Some("one".to_owned()),
            flow_id: Some(1),
            reused_after_finalize: false,
        }
    }

    fn inference(operation: CryptoCaptureRecord) -> CanonicalizationInference {
        let capture = CanonicalizationCapture {
            capture_id: "one".to_owned(),
            request: RequestSnapshot {
                request_id: Some("one".to_owned()),
                flow_id: Some(1),
                method: "GET".to_owned(),
                path: "/a".to_owned(),
                ..RequestSnapshot::default()
            },
            operation,
        };
        CanonicalizationInferer::default().infer(
            &InferenceInput {
                training_captures: vec![capture],
                ..InferenceInput::default()
            },
            None,
        )
    }

    #[test]
    fn reproducible_artifact_contains_no_secret_and_interface() {
        let operation = operation(KeyExportability::Exportable);
        let inference = inference(operation.clone());
        let input = SignerEmissionInput {
            signer_id: "signer:test".to_owned(),
            scheme_shortcut: Some(ReproductionShortcut::CustomHmac),
            inference,
            representative_operation: Some(operation),
            credential: Some(CredentialReference {
                secret_ref: "credential://api-key".to_owned(),
                provider: Some("vault".to_owned()),
            }),
            device_oracle_callback_id: None,
            device_oracle_reason: None,
            runtime: SignerRuntime::default(),
            wire_prefix: Some("sig=".to_owned()),
            wire_suffix: None,
        };
        let emitted = SignerEmitter.emit(&input);
        let artifact = emitted.artifact.expect("artifact");
        assert_eq!(artifact.signer_mode, SignerMode::PartialHypothesis);
        assert_eq!(
            artifact.key_source,
            Some(SignerKeySource::CredentialReference {
                secret_ref: "credential://api-key".to_owned(),
                provider: Some("vault".to_owned()),
            })
        );
        assert_eq!(artifact.interface.operation, "sign");
        assert_eq!(
            artifact
                .output
                .as_ref()
                .and_then(|output| output.prefix.as_deref()),
            Some("sig=")
        );
        let serialized = serde_json::to_string(&artifact).unwrap();
        assert!(serialized.contains("credential://api-key"));
        assert!(!serialized.contains("encoded"));
    }

    #[test]
    fn non_exportable_key_forces_device_oracle() {
        let operation = operation(KeyExportability::NonExportable);
        let input = SignerEmissionInput {
            signer_id: "signer:device".to_owned(),
            scheme_shortcut: None,
            inference: inference(operation.clone()),
            representative_operation: Some(operation),
            credential: Some(CredentialReference {
                secret_ref: "credential://must-not-be-used".to_owned(),
                provider: None,
            }),
            device_oracle_callback_id: Some("device-callback-1".to_owned()),
            device_oracle_reason: None,
            runtime: SignerRuntime::default(),
            wire_prefix: None,
            wire_suffix: None,
        };
        let artifact = SignerEmitter.emit(&input).artifact.expect("artifact");
        assert_eq!(artifact.signer_mode, SignerMode::DeviceOracle);
        assert_eq!(artifact.reproduction, "requires original runtime");
        assert!(matches!(
            artifact.key_source,
            Some(SignerKeySource::DeviceOracle { .. })
        ));
    }

    #[test]
    fn blocked_inference_does_not_emit_a_fake_signer() {
        let input = SignerEmissionInput {
            signer_id: "signer:blocked".to_owned(),
            scheme_shortcut: None,
            inference: CanonicalizationInferer::default().infer(
                &InferenceInput {
                    blocked_reason: Some("anti-hooking".to_owned()),
                    ..InferenceInput::default()
                },
                None,
            ),
            representative_operation: None,
            credential: None,
            device_oracle_callback_id: None,
            device_oracle_reason: None,
            runtime: SignerRuntime::default(),
            wire_prefix: None,
            wire_suffix: None,
        };
        let emitted = SignerEmitter.emit(&input);
        assert!(emitted.artifact.is_none());
        assert_eq!(
            emitted.diagnostic.id.as_ref(),
            "crypto.signer-not-recoverable"
        );
    }
}
