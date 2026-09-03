//! Secure credential handling for login-gated crawls.
//!
//! Security contract (this is what earns operator trust):
//! - Credential values live only in memory, wrapped in [`Secret`], and are
//!   zeroized on drop. Nothing is ever written to disk, session files, or config.
//! - Injected values are registered with a [`CredentialRedactor`] *before* they
//!   are typed into the app, so the login request the proxy captures is scrubbed
//!   before it lands in the durable store, the assembled surface, or any export.
//! - [`Secret`]'s `Debug` never renders the value, so it cannot leak into logs,
//!   diagnostics, or error messages.
//!
//! Redaction is deliberately *precise*: only the exact values the operator
//! supplied (and their URL/form/JSON-encoded forms) are scrubbed. Legitimately
//! captured bearer tokens and cookies from other flows are part of the API
//! surface and are left intact — over-redacting them would defeat the tool.

use std::sync::RwLock;

use apiaxess_workbench_store::{FlowCapture, FlowRedactor};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const PLACEHOLDER: &[u8] = b"[apiaxess-redacted-credential]";

/// A credential value held only in memory and zeroized when dropped.
///
/// Never persisted, never logged (its `Debug`/`Display` are redacted), never
/// serialized.
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wraps a value as a zeroize-on-drop secret.
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Wraps a string value as a secret.
    #[must_use]
    pub fn from_text(value: &str) -> Self {
        Self::new(value.as_bytes().to_vec())
    }

    /// Raw bytes, for injection into the app only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lossy string view, for injection via `input text` only.
    #[must_use]
    pub fn reveal(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Secret([redacted])")
    }
}

/// Semantic role of a login field, surfaced to the operator so they know what
/// to supply. Deliberately generic — apps use varied schemas.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Username / handle / account id.
    Username,
    /// Password.
    Password,
    /// Email address.
    Email,
    /// Phone number.
    Phone,
    /// Numeric PIN.
    Pin,
    /// One-time code delivered out-of-band (SMS/authenticator).
    Otp,
    /// Unclassified text field on the login screen.
    Generic,
}

impl CredentialKind {
    /// Whether values of this kind are sensitive (must be redacted/masked).
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(self, Self::Password | Self::Pin | Self::Otp)
    }
}

/// One field the crawler detected on a login/OTP screen.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialField {
    /// Stable key (resource-id when present, else a synthesized index).
    pub name: String,
    /// Human-readable hint (hint text / content-desc / label) for the operator.
    pub label: String,
    /// Inferred semantic role.
    pub kind: CredentialKind,
    /// Whether this field's value is sensitive and must be masked in the prompt.
    pub secret: bool,
}

/// Why the crawler is asking for credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPromptReason {
    /// The crawler stalled at a sign-in screen.
    LoginGate,
    /// An OTP/verification-code field is blocking progress.
    Otp,
}

/// A request for credentials the crawler sends to the [`CredentialProvider`].
///
/// Serializable so it can be pushed to the GUI over telemetry. It never carries
/// any secret value — only the *shape* of what is needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    /// Package under crawl.
    pub package: String,
    /// Short description of the screen (activity + detected hints).
    pub screen_summary: String,
    /// Fields the operator should fill.
    pub fields: Vec<CredentialField>,
    /// Why the prompt is being raised.
    pub reason: CredentialPromptReason,
}

/// The operator's answer: field name → secret value. Held in memory only.
#[derive(Clone, Debug, Default)]
pub struct CredentialAnswer {
    /// Values keyed by [`CredentialField::name`].
    pub values: Vec<(String, Secret)>,
}

impl CredentialAnswer {
    /// Looks up a supplied value by field name.
    #[must_use]
    pub fn get(&self, field: &str) -> Option<&Secret> {
        self.values
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, secret)| secret)
    }

    /// Whether any non-empty value was supplied.
    #[must_use]
    pub fn has_values(&self) -> bool {
        self.values.iter().any(|(_, secret)| !secret.is_empty())
    }
}

/// Pre-run decision from the operator before the dynamic crawl starts.
pub enum PreRunDecision {
    /// The operator supplied credentials up front.
    FeedNow(CredentialAnswer),
    /// Skip the dynamic crawl entirely for this run.
    Skip,
    /// Crawl anyway; prompt live if a login gate is hit.
    TryAnyway,
}

/// Mid-crawl decision when a login gate is detected.
pub enum CredentialDecision {
    /// The operator supplied credentials for the detected fields.
    Provide(CredentialAnswer),
    /// Continue crawling without signing in (post-auth surface stays unreached).
    Continue,
}

/// Bridge the crawler uses to obtain credentials from the operator.
///
/// Implementations route to the GUI (a live prompt over the control/telemetry
/// sockets) or, in tests, to a canned responder. The crawler itself never
/// originates credential values.
pub trait CredentialProvider: Send {
    /// Asked once before the crawl: does the app require sign-in?
    fn pre_run(&mut self, package: &str) -> PreRunDecision;
    /// Asked when the crawler stalls at a sign-in screen.
    fn on_login_gate(&mut self, request: &CredentialRequest) -> CredentialDecision;
    /// Asked when an OTP field blocks progress; the operator enters the code
    /// they received on their real device. `None` means continue without it.
    fn on_otp(&mut self, request: &CredentialRequest) -> Option<Secret>;
}

/// Redacts the exact injected credential values from captured flows.
///
/// Shared as `Arc<CredentialRedactor>` by the crawler (which [`register`]s each
/// value just before typing it) and installed on the traffic store + live
/// workbench as an [`Arc<dyn FlowRedactor>`] so every persisted/surfaced flow is
/// scrubbed.
///
/// [`register`]: CredentialRedactor::register
#[derive(Default)]
pub struct CredentialRedactor {
    /// Byte variants (raw + encodings) to scrub, each zeroized on drop.
    variants: RwLock<Vec<Zeroizing<Vec<u8>>>>,
    /// Count of distinct secrets registered (for honest telemetry — never values).
    registered: RwLock<usize>,
}

impl CredentialRedactor {
    /// Creates an empty redactor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a secret so it (and its URL/form/JSON-encoded forms) will be
    /// scrubbed from every subsequently captured flow.
    ///
    /// Call this *before* typing the value into the app so no capture window
    /// exists where the raw value could be persisted.
    pub fn register(&self, secret: &Secret) {
        if secret.is_empty() {
            return;
        }
        let raw = secret.as_bytes().to_vec();
        let mut new_variants = vec![
            percent_encode(&raw, false),
            percent_encode(&raw, true),
            json_escape(&raw),
            raw,
        ];
        new_variants.sort();
        new_variants.dedup();
        if let Ok(mut variants) = self.variants.write() {
            for variant in new_variants {
                if !variant.is_empty() && !variants.iter().any(|existing| **existing == variant) {
                    variants.push(Zeroizing::new(variant));
                }
            }
            // Longest-first so an encoded superset is replaced before a raw
            // subset, keeping redaction total.
            variants.sort_by_key(|variant| std::cmp::Reverse(variant.len()));
        }
        if let Ok(mut registered) = self.registered.write() {
            *registered += 1;
        }
    }

    /// Number of distinct credential values registered (never the values).
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.registered.read().map(|count| *count).unwrap_or(0)
    }

    /// Whether any value is registered.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.variants
            .read()
            .map(|variants| !variants.is_empty())
            .unwrap_or(false)
    }
}

impl FlowRedactor for CredentialRedactor {
    fn redact(&self, flow: &mut FlowCapture) {
        let Ok(variants) = self.variants.read() else {
            return;
        };
        if variants.is_empty() {
            return;
        }
        for variant in variants.iter() {
            redact_opt_string(&mut flow.url, variant);
            redact_opt_string(&mut flow.path, variant);
            for (_, value) in &mut flow.request_headers {
                redact_string(value, variant);
            }
            for (_, value) in &mut flow.response_headers {
                redact_string(value, variant);
            }
            redact_opt_bytes(&mut flow.request_body, variant);
            redact_opt_bytes(&mut flow.response_body, variant);
        }
    }
}

fn redact_opt_string(field: &mut Option<String>, needle: &[u8]) {
    if let Some(value) = field {
        redact_string(value, needle);
    }
}

fn redact_string(value: &mut String, needle: &[u8]) {
    let bytes = value.as_bytes();
    if !contains(bytes, needle) {
        return;
    }
    let replaced = replace_bytes(bytes, needle);
    *value = String::from_utf8_lossy(&replaced).into_owned();
}

fn redact_opt_bytes(field: &mut Option<Vec<u8>>, needle: &[u8]) {
    if let Some(value) = field {
        if contains(value, needle) {
            *value = replace_bytes(value, needle);
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn replace_bytes(haystack: &[u8], needle: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut index = 0;
    while index < haystack.len() {
        if index + needle.len() <= haystack.len() && &haystack[index..index + needle.len()] == needle
        {
            out.extend_from_slice(PLACEHOLDER);
            index += needle.len();
        } else {
            out.push(haystack[index]);
            index += 1;
        }
    }
    out
}

/// RFC 3986 component percent-encoding. `space_as_plus` selects the
/// `application/x-www-form-urlencoded` variant (space → `+`).
fn percent_encode(value: &[u8], space_as_plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for &byte in value {
        let unreserved = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(byte);
        } else if byte == b' ' && space_as_plus {
            out.push(b'+');
        } else {
            out.push(b'%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0f));
        }
    }
    out
}

const fn hex_upper(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + (nibble - 10),
    }
}

/// JSON string-escaping (without surrounding quotes), matching how a value
/// appears inside a JSON request body.
fn json_escape(value: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(value);
    let mut out = Vec::with_capacity(value.len());
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut buffer = [0_u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_session::ScopeDisposition;
    use chrono::Utc;

    fn flow_with(url: &str, request_body: &[u8], headers: Vec<(String, String)>) -> FlowCapture {
        FlowCapture {
            id: 1,
            captured_at: Utc::now(),
            protocol: "http/1.1".to_owned(),
            method: Some("POST".to_owned()),
            host: Some("api.example.test".to_owned()),
            url: Some(url.to_owned()),
            path: Some("/login".to_owned()),
            status: Some(200),
            duration_ms: Some(5),
            request_headers: headers,
            response_headers: Vec::new(),
            request_body: Some(request_body.to_vec()),
            response_body: None,
            scope: ScopeDisposition::InScope,
            provenance: "test".to_owned(),
        }
    }

    #[test]
    fn secret_debug_never_reveals_value() {
        let secret = Secret::from_text("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");
    }

    #[test]
    fn redacts_raw_value_in_body_and_header() {
        let redactor = CredentialRedactor::new();
        redactor.register(&Secret::from_text("hunter2"));
        let mut flow = flow_with(
            "https://api.example.test/login",
            b"{\"user\":\"alice\",\"password\":\"hunter2\"}",
            vec![("x-auth".to_owned(), "hunter2".to_owned())],
        );
        redactor.redact(&mut flow);
        let body = String::from_utf8(flow.request_body.unwrap()).unwrap();
        assert!(!body.contains("hunter2"), "raw password must be scrubbed");
        assert!(body.contains("[apiaxess-redacted-credential]"));
        assert!(!flow.request_headers[0].1.contains("hunter2"));
    }

    #[test]
    fn redacts_url_encoded_and_form_encoded_and_query_variants() {
        let redactor = CredentialRedactor::new();
        redactor.register(&Secret::from_text("p@ss w0rd"));
        // Query with percent-encoding, and form body with '+' for space.
        let mut flow = flow_with(
            "https://api.example.test/login?pw=p%40ss%20w0rd",
            b"pw=p%40ss+w0rd&u=alice",
            Vec::new(),
        );
        redactor.redact(&mut flow);
        assert!(!flow.url.as_ref().unwrap().contains("p%40ss%20w0rd"));
        let body = String::from_utf8(flow.request_body.unwrap()).unwrap();
        assert!(!body.contains("p%40ss+w0rd"), "form-encoded value must be scrubbed: {body}");
    }

    #[test]
    fn redacts_json_escaped_value() {
        let redactor = CredentialRedactor::new();
        redactor.register(&Secret::from_text("a\"b\\c"));
        let mut flow = flow_with(
            "https://api.example.test/login",
            br#"{"password":"a\"b\\c"}"#,
            Vec::new(),
        );
        redactor.redact(&mut flow);
        let body = String::from_utf8(flow.request_body.unwrap()).unwrap();
        assert!(!body.contains(r#"a\"b\\c"#), "json-escaped value must be scrubbed: {body}");
    }

    #[test]
    fn leaves_unrelated_auth_tokens_intact() {
        // Precise redaction: a bearer token that is NOT the injected secret is
        // legitimate API surface and must survive.
        let redactor = CredentialRedactor::new();
        redactor.register(&Secret::from_text("hunter2"));
        let mut flow = flow_with(
            "https://api.example.test/data",
            b"{}",
            vec![("authorization".to_owned(), "Bearer abc.def.ghi".to_owned())],
        );
        redactor.redact(&mut flow);
        assert_eq!(flow.request_headers[0].1, "Bearer abc.def.ghi");
    }

    #[test]
    fn no_registered_values_is_a_noop() {
        let redactor = CredentialRedactor::new();
        let mut flow = flow_with("https://x/y", b"secret-looking", Vec::new());
        redactor.redact(&mut flow);
        assert_eq!(flow.request_body.unwrap(), b"secret-looking");
        assert_eq!(redactor.registered_count(), 0);
    }
}
