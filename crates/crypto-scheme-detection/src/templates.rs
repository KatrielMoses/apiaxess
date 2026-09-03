//! Built-in Phase 4.2 sibling templates.

use apiaxess_api_model::provenance::SourceType;
use apiaxess_crypto_capture::Primitive;

use crate::{
    ReproductionShortcut, SchemeCandidate, SchemeTemplate, SigningEvidence, candidate, contains_ci,
    has_algorithm, has_hmac, has_jwt_value, has_name, indicator, public_key_shape,
};

/// Returns the built-in templates. Adding a scheme means adding one sibling
/// implementation and registering it here; matching remains generic.
#[must_use]
pub fn builtin_templates() -> Vec<Box<dyn SchemeTemplate>> {
    vec![
        Box::new(AwsSigV4),
        Box::new(OAuth1),
        Box::new(JwtJws),
        Box::new(HttpMessageSignatures),
        Box::new(CustomHmac),
        Box::new(PublicKeyRequestSignature),
    ]
}

struct AwsSigV4;
struct OAuth1;
struct JwtJws;
struct HttpMessageSignatures;
struct CustomHmac;
struct PublicKeyRequestSignature;

fn static_hit(
    evidence: &SigningEvidence,
    marker: &str,
    id: &str,
    weight: f64,
) -> Option<crate::IndicatorMatch> {
    evidence.static_contains(marker).then(|| {
        indicator(
            id,
            SourceType::StaticAnalysis,
            format!("static marker contains {marker}"),
            weight,
        )
    })
}

fn runtime_hit(
    condition: bool,
    id: &str,
    detail: impl Into<String>,
    weight: f64,
) -> Option<crate::IndicatorMatch> {
    condition.then(|| indicator(id, SourceType::DynamicCapture, detail, weight))
}

fn wire_encoding(evidence: &SigningEvidence, names: &[&str]) -> bool {
    evidence
        .crypto_operations
        .iter()
        .flat_map(|operation| operation.wire_output.iter())
        .any(|wire| {
            wire.encoding.as_deref().is_some_and(|encoding| {
                names.iter().any(|name| encoding.eq_ignore_ascii_case(name))
            })
        })
}

fn hmac_count(evidence: &SigningEvidence) -> usize {
    evidence
        .crypto_operations
        .iter()
        .filter(|operation| {
            operation
                .algorithm
                .as_deref()
                .is_some_and(|algorithm| contains_ci(algorithm, "hmac"))
        })
        .count()
}

fn has_signature_primitive(evidence: &SigningEvidence) -> bool {
    evidence
        .crypto_operations
        .iter()
        .any(|operation| operation.primitive == Primitive::Signature)
}

impl SchemeTemplate for AwsSigV4 {
    fn id(&self) -> &'static str {
        "aws-sigv4"
    }
    fn name(&self) -> &'static str {
        "AWS Signature Version 4"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let authorization = evidence.header("Authorization").unwrap_or_default();
        let auth = contains_ci(authorization, "AWS4-HMAC-SHA256");
        let canonical_fields = contains_ci(authorization, "Credential=")
            && contains_ci(authorization, "SignedHeaders=")
            && contains_ci(authorization, "Signature=");
        let chain = hmac_count(evidence) >= 4
            || evidence
                .key_observations
                .iter()
                .any(|observation| contains_ci(&observation.path, "secret_key"));
        let mut matches = Vec::new();
        if let Some(hit) = static_hit(evidence, "AWS4-HMAC-SHA256", "aws4-static-algorithm", 0.15) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            auth,
            "aws4-authorization",
            "Authorization uses AWS4-HMAC-SHA256",
            0.30,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            has_name(evidence, "x-amz-date"),
            "aws4-amz-date",
            "x-amz-date is present",
            0.20,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            canonical_fields,
            "aws4-authorization-fields",
            "Credential, SignedHeaders, and Signature are present",
            0.15,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            chain,
            "aws4-hmac-chain",
            format!(
                "{} HMAC operations or derived-key evidence",
                hmac_count(evidence)
            ),
            0.25,
        ) {
            matches.push(hit);
        }
        candidate(self, matches, ReproductionShortcut::AwsSigV4)
    }
}

impl SchemeTemplate for OAuth1 {
    fn id(&self) -> &'static str {
        "oauth1-hmac"
    }
    fn name(&self) -> &'static str {
        "OAuth 1.0 HMAC"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let authorization = evidence.header("Authorization").unwrap_or_default();
        let oauth_header = authorization
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("oauth ");
        let oauth_fields = ["oauth_nonce", "oauth_timestamp", "oauth_signature_method"]
            .iter()
            .filter(|name| has_name(evidence, name))
            .count();
        let oauth_algorithm =
            has_algorithm(evidence, "HmacSHA1") || has_algorithm(evidence, "HmacSHA256");
        let encoded = wire_encoding(evidence, &["url_encode", "percent_encode"]);
        let mut matches = Vec::new();
        if let Some(hit) = static_hit(evidence, "oauth_nonce", "oauth-static-fields", 0.12) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            oauth_header,
            "oauth-authorization",
            "Authorization uses the OAuth scheme",
            0.28,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            oauth_fields >= 2,
            "oauth-request-fields",
            format!("{oauth_fields} OAuth request fields are present"),
            0.25,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            oauth_algorithm,
            "oauth-hmac-algorithm",
            "HMAC-SHA1 or HMAC-SHA256 was captured",
            0.20,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            encoded,
            "oauth-percent-encoding",
            "URL/percent encoding was observed",
            0.15,
        ) {
            matches.push(hit);
        }
        candidate(self, matches, ReproductionShortcut::OAuth1Hmac)
    }
}

impl SchemeTemplate for JwtJws {
    fn id(&self) -> &'static str {
        "jwt-jws"
    }
    fn name(&self) -> &'static str {
        "JWT / JWS"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let jwt = has_jwt_value(evidence);
        let signing_input = evidence.crypto_operations.iter().any(|operation| {
            operation
                .accumulated_message
                .iter()
                .fold(0_usize, |count, byte| {
                    count.saturating_add(usize::from(*byte == b'.'))
                })
                == 1
        });
        let algorithm = has_hmac(evidence)
            || has_algorithm(evidence, "RSA")
            || has_algorithm(evidence, "ECDSA");
        let encoded = wire_encoding(evidence, &["base64url"]);
        let mut matches = Vec::new();
        if let Some(hit) = runtime_hit(
            jwt,
            "jws-three-segments",
            "A request value has three Base64URL-looking segments",
            0.40,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            signing_input,
            "jws-signing-input",
            "The captured message has encoded-header dot encoded-payload shape",
            0.22,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            algorithm,
            "jws-crypto-algorithm",
            "HMAC or public-key signing primitive was captured",
            0.25,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            encoded,
            "jws-base64url-output",
            "Base64URL wire output was observed",
            0.15,
        ) {
            matches.push(hit);
        }
        candidate(self, matches, ReproductionShortcut::JwtJws)
    }
}

impl SchemeTemplate for HttpMessageSignatures {
    fn id(&self) -> &'static str {
        "http-message-signatures-rfc9421"
    }
    fn name(&self) -> &'static str {
        "HTTP Message Signatures (RFC 9421)"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let signature_input = evidence
            .header("Signature-Input")
            .or_else(|| evidence.header("signature-input"));
        let signature = evidence
            .header("Signature")
            .or_else(|| evidence.header("signature"));
        let params = signature_input.is_some_and(|value| contains_ci(value, "@signature-params"));
        let covered = signature_input.is_some_and(|value| {
            ["@method", "@target-uri", "@authority", "content-digest"]
                .iter()
                .any(|marker| contains_ci(value, marker))
        });
        let mut matches = Vec::new();
        if let Some(hit) = static_hit(evidence, "Signature-Input", "rfc9421-static-header", 0.12) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            signature_input.is_some(),
            "rfc9421-signature-input",
            "Signature-Input is present",
            0.28,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            signature.is_some(),
            "rfc9421-signature",
            "Signature is present",
            0.12,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            params,
            "rfc9421-signature-params",
            "@signature-params is covered",
            0.25,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            covered,
            "rfc9421-covered-components",
            "HTTP covered components are ordered in Signature-Input",
            0.23,
        ) {
            matches.push(hit);
        }
        candidate(self, matches, ReproductionShortcut::HttpMessageSignatures)
    }
}

impl SchemeTemplate for CustomHmac {
    fn id(&self) -> &'static str {
        "custom-hmac-header"
    }
    fn name(&self) -> &'static str {
        "Custom HMAC request header"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let custom_header = ["X-Signature", "X-Api-Signature", "X-Request-Signature"]
            .iter()
            .find(|name| evidence.header(name).is_some());
        let timestamp_or_nonce = has_name(evidence, "timestamp")
            || has_name(evidence, "x-timestamp")
            || has_name(evidence, "nonce")
            || has_name(evidence, "x-nonce");
        let encoding = wire_encoding(evidence, &["hex", "base64", "base64url"]);
        let mut matches = Vec::new();
        if let Some(name) = custom_header {
            matches.push(indicator(
                "custom-signature-header",
                SourceType::DynamicCapture,
                format!("{name} is present"),
                0.28,
            ));
        }
        if let Some(hit) = runtime_hit(
            timestamp_or_nonce,
            "custom-freshness-field",
            "timestamp or nonce is present",
            0.20,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            has_hmac(evidence) && hmac_count(evidence) == 1,
            "custom-single-hmac",
            "one HMAC operation is correlated to the request",
            0.30,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            encoding,
            "custom-output-encoding",
            "hex or Base64 wire encoding was observed",
            0.15,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = static_hit(
            evidence,
            "x-signature",
            "custom signature header is present in static indicators",
            0.12,
        ) {
            matches.push(hit);
        }
        candidate(self, matches, ReproductionShortcut::CustomHmac)
    }
}

impl SchemeTemplate for PublicKeyRequestSignature {
    fn id(&self) -> &'static str {
        "rsa-ecdsa-request-signature"
    }
    fn name(&self) -> &'static str {
        "RSA/ECDSA request signature"
    }
    fn evaluate(&self, evidence: &SigningEvidence) -> Option<SchemeCandidate> {
        let algorithm = evidence.crypto_operations.iter().find_map(|operation| {
            operation
                .algorithm
                .as_deref()
                .filter(|value| contains_ci(value, "RSA") || contains_ci(value, "ECDSA"))
                .map(str::to_owned)
        });
        let shape = public_key_shape(evidence);
        let signature_header = evidence.header("Signature").is_some()
            || evidence.header("X-Signature").is_some()
            || evidence.header("X-Api-Signature").is_some();
        let hardware = evidence.crypto_operations.iter().any(|operation| {
            operation.key.hardware_backed == Some(true)
                || operation.key.exportability
                    == apiaxess_crypto_capture::KeyExportability::NonExportable
        });
        let mut matches = Vec::new();
        if let Some(algorithm) = &algorithm {
            matches.push(indicator(
                "public-key-algorithm",
                SourceType::DynamicCapture,
                format!("captured {algorithm}"),
                0.34,
            ));
        }
        if let Some(hit) = runtime_hit(
            has_signature_primitive(evidence),
            "signature-primitive",
            "java.security.Signature operation was captured",
            0.22,
        ) {
            matches.push(hit);
        }
        if let Some(shape) = &shape {
            matches.push(indicator(
                "signature-output-shape",
                SourceType::DynamicCapture,
                format!("observed {shape} output"),
                0.20,
            ));
        }
        if let Some(hit) = runtime_hit(
            signature_header,
            "public-key-wire-placement",
            "signature is placed in a request header",
            0.14,
        ) {
            matches.push(hit);
        }
        if let Some(hit) = runtime_hit(
            hardware,
            "keystore-bound-key",
            "key is hardware-backed or non-exportable",
            0.10,
        ) {
            matches.push(hit);
        }
        candidate(
            self,
            matches,
            ReproductionShortcut::PublicKeyRequestSignature {
                algorithm,
                output_shape: shape.unwrap_or_else(|| "unknown".to_owned()),
            },
        )
    }
}
