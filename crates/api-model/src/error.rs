//! Model validation and serialization failures.

use thiserror::Error;

/// A failure to construct, validate, load, or save a canonical model.
#[derive(Debug, Error)]
pub enum ModelError {
    /// An identifier or domain string violates its lexical invariant.
    #[error("invalid {kind} `{value}`: {reason}")]
    InvalidValue {
        /// Kind of value being validated.
        kind: &'static str,
        /// Rejected value.
        value: String,
        /// Human-readable invariant.
        reason: &'static str,
    },
    /// A structural invariant failed at a model path.
    #[error("model invariant failed at {path}: {reason}")]
    Invariant {
        /// Dotted/indexed path to the invalid value.
        path: String,
        /// Human-readable invariant.
        reason: String,
    },
    /// The durable document format is not supported by this reader.
    #[error("unsupported model format version {found}; expected {expected}")]
    UnsupportedFormat {
        /// Version found on disk.
        found: u32,
        /// Version supported by this crate.
        expected: u32,
    },
    /// JSON encoding or decoding failed.
    #[error("model JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    /// Fields would have been ignored by serde, which would lose evidence.
    #[error("model contains unknown field(s): {fields:?}")]
    UnknownFields {
        /// Full serde paths to rejected fields.
        fields: Vec<String>,
    },
}

impl ModelError {
    pub(crate) fn invariant(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invariant {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

/// Result type local to canonical-model operations.
pub type ModelResult<T> = Result<T, ModelError>;
