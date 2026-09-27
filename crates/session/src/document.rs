//! Versioned, invariant-checked durable session JSON.

use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        SESSION_FORMAT_UNSUPPORTED, SESSION_INVARIANT_FAILED, SESSION_JSON_INVALID,
        SESSION_UNKNOWN_FIELDS,
    },
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Session;

/// Current durable session JSON format version.
pub const CURRENT_SESSION_FORMAT_VERSION: u32 = 1;

/// Durable envelope for a complete session aggregate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionDocument {
    /// On-disk format version, independent from product and nested model versions.
    pub format_version: u32,
    /// Time this immutable document snapshot was created.
    pub serialized_at: DateTime<Utc>,
    /// Complete session aggregate.
    pub session: Session,
}

impl SessionDocument {
    /// Wraps a session in the current durable format.
    #[must_use]
    pub const fn new(session: Session, serialized_at: DateTime<Utc>) -> Self {
        Self {
            format_version: CURRENT_SESSION_FORMAT_VERSION,
            serialized_at,
            session,
        }
    }

    /// Validates the envelope and every recursive session/model invariant.
    ///
    /// # Errors
    ///
    /// Returns a canonical version or invariant diagnostic.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        if self.format_version != CURRENT_SESSION_FORMAT_VERSION {
            return Err(unsupported_format(self.format_version));
        }
        self.session.validate()?;
        if self.serialized_at < self.session.updated_at() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "path".to_owned(),
                DiagnosticValue::String("serialized_at".to_owned()),
            );
            context.insert(
                "reason".to_owned(),
                DiagnosticValue::String(
                    "document snapshot time must not precede the last session mutation".to_owned(),
                ),
            );
            return Err(SESSION_INVARIANT_FAILED.instantiate(context));
        }
        Ok(())
    }

    /// Serializes an invariant-valid complete session as compact UTF-8 JSON,
    /// the form written to disk (pretty-printing roughly doubled the file).
    ///
    /// # Errors
    ///
    /// Returns a canonical diagnostic rather than persisting invalid or lossy state.
    pub fn to_json(&self) -> Result<Vec<u8>, Diagnostic> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|error| json_diagnostic(&error))
    }

    /// Serializes an invariant-valid complete session as pretty UTF-8 JSON.
    ///
    /// # Errors
    ///
    /// Returns a canonical diagnostic rather than persisting invalid or lossy state.
    pub fn to_json_pretty(&self) -> Result<Vec<u8>, Diagnostic> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(|error| json_diagnostic(&error))
    }

    /// Loads JSON, rejects unsupported versions/unknown fields, then validates recursively.
    ///
    /// # Errors
    ///
    /// Returns a structured what/why/fix diagnostic for every anticipated load failure.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Diagnostic> {
        let raw_value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| json_diagnostic(&error))?;
        // Valid JSON that is not a session at all (an export, a HAR) is named
        // for what it is, rather than reported as broken session JSON.
        if !(raw_value.get("format_version").is_some() && raw_value.get("session").is_some()) {
            return Err(not_a_session(&raw_value));
        }
        if let Some(found) = raw_value
            .get("format_version")
            .and_then(serde_json::Value::as_u64)
        {
            if found != u64::from(CURRENT_SESSION_FORMAT_VERSION) {
                let found = u32::try_from(found).unwrap_or(u32::MAX);
                return Err(unsupported_format(found));
            }
        }

        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let mut ignored_fields = Vec::new();
        let document: Self = serde_ignored::deserialize(&mut deserializer, |path| {
            ignored_fields.push(path.to_string());
        })
        .map_err(|error| {
            if error.to_string().contains("unknown field") {
                unknown_fields(vec![error.to_string()])
            } else {
                json_diagnostic(&error)
            }
        })?;
        if !ignored_fields.is_empty() {
            return Err(unknown_fields(ignored_fields));
        }

        let canonical_value =
            serde_json::to_value(&document).map_err(|error| json_diagnostic(&error))?;
        collect_extra_fields(&raw_value, &canonical_value, "$", &mut ignored_fields);
        if !ignored_fields.is_empty() {
            return Err(unknown_fields(ignored_fields));
        }
        document.validate()?;
        Ok(document)
    }
}

fn unsupported_format(found: u32) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "found_version".to_owned(),
        DiagnosticValue::Integer(i64::from(found)),
    );
    context.insert(
        "supported_version".to_owned(),
        DiagnosticValue::Integer(i64::from(CURRENT_SESSION_FORMAT_VERSION)),
    );
    let mut diagnostic = SESSION_FORMAT_UNSUPPORTED.instantiate(context);
    diagnostic.why = format!(
        "The session artifact is format version {found}; this build reads only version {CURRENT_SESSION_FORMAT_VERSION}{}.",
        if found > CURRENT_SESSION_FORMAT_VERSION {
            " (it was written by a newer APIaxess)"
        } else {
            " (it was written by an older APIaxess)"
        }
    )
    .into_boxed_str();
    diagnostic
}

/// A JSON document that is not a session artifact, named by what it looks like.
fn not_a_session(value: &serde_json::Value) -> Diagnostic {
    let looks_like = if value.get("openapi").is_some() || value.get("swagger").is_some() {
        "an OpenAPI document (an APIaxess export)"
    } else if value
        .get("log")
        .and_then(|log| log.get("entries"))
        .is_some()
    {
        "a HAR traffic file (import it from Live traffic → Import HAR instead)"
    } else if value.get("info").is_some() && value.get("item").is_some() {
        "a Postman collection (an APIaxess export)"
    } else {
        "some other JSON document"
    };
    let mut diagnostic = SESSION_JSON_INVALID.instantiate(DiagnosticContext::new());
    diagnostic.what = "This file is not an APIaxess session.".into();
    diagnostic.why = format!(
        "It is valid JSON, but it has no session record: it looks like {looks_like}. A session artifact is a session.json written by Save (session format version {CURRENT_SESSION_FORMAT_VERSION})."
    )
    .into();
    diagnostic.fix = "Choose a session.json from a session folder (pick one from Recent sessions, or Browse to it), then open it.".into();
    diagnostic
}

fn json_diagnostic(error: &serde_json::Error) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "json_error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    context.insert(
        "line".to_owned(),
        DiagnosticValue::Integer(i64::try_from(error.line()).unwrap_or(i64::MAX)),
    );
    context.insert(
        "column".to_owned(),
        DiagnosticValue::Integer(i64::try_from(error.column()).unwrap_or(i64::MAX)),
    );
    let mut diagnostic = SESSION_JSON_INVALID.instantiate(context);
    // Put the location where the operator reads it, not only in the context.
    diagnostic.why = format!(
        "The file is not valid JSON at line {}, column {}: {error}.",
        error.line(),
        error.column()
    )
    .into();
    diagnostic
}

fn unknown_fields(fields: Vec<String>) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("fields".to_owned(), DiagnosticValue::StringList(fields));
    SESSION_UNKNOWN_FIELDS.instantiate(context)
}

fn collect_extra_fields(
    raw: &serde_json::Value,
    canonical: &serde_json::Value,
    path: &str,
    extras: &mut Vec<String>,
) {
    match (raw, canonical) {
        (serde_json::Value::Object(raw), serde_json::Value::Object(canonical)) => {
            for (key, value) in raw {
                let child_path = format!("{path}.{key}");
                if let Some(canonical_value) = canonical.get(key) {
                    collect_extra_fields(value, canonical_value, &child_path, extras);
                } else {
                    extras.push(child_path);
                }
            }
        }
        (serde_json::Value::Array(raw), serde_json::Value::Array(canonical)) => {
            for (index, (value, canonical_value)) in raw.iter().zip(canonical).enumerate() {
                collect_extra_fields(value, canonical_value, &format!("{path}[{index}]"), extras);
            }
        }
        _ => {}
    }
}
