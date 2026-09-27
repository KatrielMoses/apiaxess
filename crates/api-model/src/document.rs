//! Versioned, invariant-checked durable model serialization.

use serde::{Deserialize, Serialize};

use crate::{
    api::ApiSurface,
    error::{ModelError, ModelResult},
};

/// Current durable JSON format version.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Versioned durable envelope for an API surface.
///
/// Serialized through [`StoredDocument`]: the unified surface's copy of the
/// document's own `surface` and `confidence` is written once, not twice.
#[derive(Clone, Debug, PartialEq)]
pub struct ApiDocument {
    /// On-disk format version, independent from the product version.
    pub format_version: u32,
    /// Canonical evidence-preserving API surface.
    pub surface: ApiSurface,
    /// Normalized Phase 1 static-pass honesty handoff, when a static pass has
    /// been committed to this document.
    pub static_pass: Option<crate::api::StaticPassSummary>,
    /// Honest coverage and handoff feedback for the latest dynamic run.
    pub dynamic_capture: Option<crate::api::DynamicCaptureSummary>,
    /// Recomputable Phase 5.2 confidence, handoff, and coverage accounting.
    pub confidence: Option<crate::confidence::ConfidenceSummary>,
    /// Durable Phase 5.3 unified surface consumed by artifact generators.
    pub unified_surface: Option<crate::unified::UnifiedApiSurface>,
}

/// The durable JSON shape of an [`ApiDocument`]. Identical to the document's
/// fields, except that the embedded unified surface omits `surface` and
/// `confidence` when they are the document's own (they always are after an
/// assembly), which halved every session artifact. Older documents, which
/// carry both copies, load unchanged.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDocument {
    format_version: u32,
    surface: ApiSurface,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    static_pass: Option<crate::api::StaticPassSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dynamic_capture: Option<crate::api::DynamicCaptureSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<crate::confidence::ConfidenceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unified_surface: Option<StoredUnifiedSurface>,
}

/// [`crate::unified::UnifiedApiSurface`] as stored inside a document.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredUnifiedSurface {
    schema_version: u32,
    assembly_run_id: String,
    assembled_at: chrono::DateTime<chrono::Utc>,
    /// Absent when equal to the document's `surface`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    surface: Option<ApiSurface>,
    /// Absent when equal to the document's `confidence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confidence: Option<crate::confidence::ConfidenceSummary>,
    endpoints: Vec<crate::unified::UnifiedEndpoint>,
    signer_bindings: Vec<crate::unified::SignerBinding>,
    diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
}

impl Serialize for ApiDocument {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let unified_surface = self
            .unified_surface
            .as_ref()
            .map(|unified| StoredUnifiedSurface {
                schema_version: unified.schema_version,
                assembly_run_id: unified.assembly_run_id.clone(),
                assembled_at: unified.assembled_at,
                surface: (unified.surface != self.surface).then(|| unified.surface.clone()),
                confidence: (self.confidence.as_ref() != Some(&unified.confidence))
                    .then(|| unified.confidence.clone()),
                endpoints: unified.endpoints.clone(),
                signer_bindings: unified.signer_bindings.clone(),
                diagnostics: unified.diagnostics.clone(),
            });
        StoredDocument {
            format_version: self.format_version,
            surface: self.surface.clone(),
            static_pass: self.static_pass.clone(),
            dynamic_capture: self.dynamic_capture.clone(),
            confidence: self.confidence.clone(),
            unified_surface,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApiDocument {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let stored = StoredDocument::deserialize(deserializer)?;
        let unified_surface = match stored.unified_surface {
            None => None,
            Some(unified) => {
                let confidence = match unified.confidence {
                    Some(confidence) => confidence,
                    None => stored.confidence.clone().ok_or_else(|| {
                        serde::de::Error::custom(
                            "unified_surface omits confidence but the document has none",
                        )
                    })?,
                };
                Some(crate::unified::UnifiedApiSurface {
                    schema_version: unified.schema_version,
                    assembly_run_id: unified.assembly_run_id,
                    assembled_at: unified.assembled_at,
                    surface: unified.surface.unwrap_or_else(|| stored.surface.clone()),
                    confidence,
                    endpoints: unified.endpoints,
                    signer_bindings: unified.signer_bindings,
                    diagnostics: unified.diagnostics,
                })
            }
        };
        Ok(Self {
            format_version: stored.format_version,
            surface: stored.surface,
            static_pass: stored.static_pass,
            dynamic_capture: stored.dynamic_capture,
            confidence: stored.confidence,
            unified_surface,
        })
    }
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

    /// Drops provenance nothing refers to any more: entities, activities and
    /// agents of earlier runs whose facts were retracted or re-derived (each
    /// live re-fuse of web capture used to leave its whole evidence graph
    /// behind). Returns how many records were removed.
    ///
    /// Reachability is conservative: every string anywhere else in the
    /// document is treated as a potential reference, and whatever a kept
    /// record links to (`derived_from`, `generated_by`, `attributed_to`, an
    /// activity's `agent`) is kept too. A referenced record is never dropped.
    pub fn prune_unreferenced_provenance(&mut self) -> usize {
        use std::collections::BTreeSet;
        fn collect(value: &serde_json::Value, into: &mut BTreeSet<String>) {
            match value {
                serde_json::Value::String(text) => {
                    into.insert(text.clone());
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        collect(item, into);
                    }
                }
                serde_json::Value::Object(map) => {
                    for item in map.values() {
                        collect(item, into);
                    }
                }
                _ => {}
            }
        }
        let registry = std::mem::take(&mut self.surface.provenance);
        let mut referenced = BTreeSet::new();
        if let Ok(value) = serde_json::to_value(&*self) {
            collect(&value, &mut referenced);
        }
        self.surface.provenance = registry;
        let before = self.surface.provenance.entities.len()
            + self.surface.provenance.activities.len()
            + self.surface.provenance.agents.len();

        // Entities: referenced ones, closed over `derived_from`.
        let mut kept: BTreeSet<String> = self
            .surface
            .provenance
            .entities
            .iter()
            .filter(|entity| referenced.contains(entity.id.as_str()))
            .map(|entity| entity.id.as_str().to_owned())
            .collect();
        loop {
            let grown: Vec<String> = self
                .surface
                .provenance
                .entities
                .iter()
                .filter(|entity| kept.contains(entity.id.as_str()))
                .flat_map(|entity| entity.derived_from.iter().map(|id| id.as_str().to_owned()))
                .filter(|id| !kept.contains(id))
                .collect();
            if grown.is_empty() {
                break;
            }
            kept.extend(grown);
        }
        self.surface
            .provenance
            .entities
            .retain(|entity| kept.contains(entity.id.as_str()));

        // Activities and agents: referenced directly, or by what is kept.
        let mut activities: BTreeSet<String> = referenced.clone();
        let mut agents: BTreeSet<String> = referenced;
        for entity in &self.surface.provenance.entities {
            activities.insert(entity.generated_by.as_str().to_owned());
            agents.insert(entity.attributed_to.as_str().to_owned());
        }
        self.surface
            .provenance
            .activities
            .retain(|activity| activities.contains(activity.id.as_str()));
        for activity in &self.surface.provenance.activities {
            agents.insert(activity.agent.as_str().to_owned());
        }
        self.surface
            .provenance
            .agents
            .retain(|agent| agents.contains(agent.id.as_str()));

        before
            - self.surface.provenance.entities.len()
            - self.surface.provenance.activities.len()
            - self.surface.provenance.agents.len()
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
