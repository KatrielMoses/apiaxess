//! Versioned, invariant-checked durable model serialization.

use serde::{Deserialize, Serialize};

use crate::{
    api::ApiSurface,
    error::{ModelError, ModelResult},
};

/// Current durable JSON format version.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Versioned durable envelope for an API surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiDocument {
    /// On-disk format version, independent from the product version.
    pub format_version: u32,
    /// Canonical evidence-preserving API surface.
    pub surface: ApiSurface,
    /// Normalized Phase 1 static-pass honesty handoff, when a static pass has
    /// been committed to this document.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_pass: Option<crate::api::StaticPassSummary>,
    /// Honest coverage and handoff feedback for the latest dynamic run.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_capture: Option<crate::api::DynamicCaptureSummary>,
    /// Recomputable Phase 5.2 confidence, handoff, and coverage accounting.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<crate::confidence::ConfidenceSummary>,
    /// Durable Phase 5.3 unified surface consumed by artifact generators.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unified_surface: Option<crate::unified::UnifiedApiSurface>,
}

impl ApiDocument {
    /// Wraps a surface in the current durable format.
    #[must_use]
    pub const fn new(surface: ApiSurface) -> Self {
        Self {
            format_version: CURRENT_FORMAT_VERSION,
            surface,
            static_pass: None,
            dynamic_capture: None,
            confidence: None,
            unified_surface: None,
        }
    }

    /// Attaches a validated static-pass summary to this document.
    #[must_use]
    pub fn with_static_pass(mut self, static_pass: crate::api::StaticPassSummary) -> Self {
        self.static_pass = Some(static_pass);
        self
    }

    /// Attaches a Phase 5.3 unified surface to this document.
    #[must_use]
    pub fn with_unified_surface(
        mut self,
        unified_surface: crate::unified::UnifiedApiSurface,
    ) -> Self {
        self.unified_surface = Some(unified_surface);
        self
    }

    /// Validates the version and every recursive model invariant.
    ///
    /// # Errors
    ///
    /// Returns the precise unsupported-version or invariant failure.
    pub fn validate(&self) -> ModelResult<()> {
        if self.format_version != CURRENT_FORMAT_VERSION {
            return Err(ModelError::UnsupportedFormat {
                found: self.format_version,
                expected: CURRENT_FORMAT_VERSION,
            });
        }
        self.surface.validate().and_then(|()| {
            self.static_pass
                .as_ref()
                .map_or(Ok(()), crate::api::StaticPassSummary::validate)
                .and_then(|()| {
                    self.dynamic_capture
                        .as_ref()
                        .map_or(Ok(()), crate::api::DynamicCaptureSummary::validate)
                        .and_then(|()| {
                            self.confidence.as_ref().map_or(Ok(()), |confidence| {
                                confidence.validate(&self.surface.provenance)
                            })
                        })
                        .and_then(|()| {
                            self.unified_surface
                                .as_ref()
                                .map_or(Ok(()), crate::unified::UnifiedApiSurface::validate)
                        })
                })
        })
    }

    /// Serializes an invariant-valid document as pretty UTF-8 JSON.
    ///
    /// # Errors
    ///
    /// Fails rather than persisting an invalid or lossy document.
    pub fn to_json_pretty(&self) -> ModelResult<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Loads UTF-8 JSON and validates version and recursive invariants.
    ///
    /// Unknown fields are rejected to prevent silent evidence loss by an older
    /// reader. Format migrations will be explicit in a future version.
    ///
    /// # Errors
    ///
    /// Returns JSON, version, or invariant failures.
    pub fn from_json(bytes: &[u8]) -> ModelResult<Self> {
        let raw_value: serde_json::Value = serde_json::from_slice(bytes)?;
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let mut ignored_fields = Vec::new();
        let document: Self = serde_ignored::deserialize(&mut deserializer, |path| {
            ignored_fields.push(path.to_string());
        })?;
        if !ignored_fields.is_empty() {
            return Err(ModelError::UnknownFields {
                fields: ignored_fields,
            });
        }
        let canonical_value = serde_json::to_value(&document)?;
        collect_extra_fields(&raw_value, &canonical_value, "$", &mut ignored_fields);
        if !ignored_fields.is_empty() {
            return Err(ModelError::UnknownFields {
                fields: ignored_fields,
            });
        }
        document.validate()?;
        Ok(document)
    }
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
