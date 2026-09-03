//! Session-scoped Phase 6 artifact export.
//!
//! The emitters remain the source of truth for each artifact format. This
//! module supplies the product boundary: it selects a completed session
//! surface, writes the generated files, preserves large evidence in a
//! sidecar, and records the export in the canonical session audit trail.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

use apiaxess_api_model::UnifiedApiSurface;
use apiaxess_collections_emitter::CollectionsEmitter;
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_openapi_emitter::OpenApiEmitter;
use apiaxess_python_sdk_emitter::PythonSdkEmitter;
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AuditActor,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::SessionRuntime;

/// One user-selectable artifact format.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// `OpenAPI` 3.1 JSON document.
    OpenApi,
    /// Generated Python `httpx` package directory.
    Sdk,
    /// Postman Collection v2.1 JSON document.
    Postman,
    /// HAR 1.2 captured-traffic interchange document.
    Har,
}

impl ExportFormat {
    /// Parses a CLI/API format name.
    ///
    /// # Errors
    ///
    /// Returns the unsupported format name when it is not recognized.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openapi" | "openapi-3.1" => Ok(Self::OpenApi),
            "sdk" | "python" | "python-sdk" => Ok(Self::Sdk),
            "postman" | "collection" => Ok(Self::Postman),
            "har" => Ok(Self::Har),
            other => Err(format!(
                "unsupported export format `{other}`; use openapi, sdk, postman, har, or all"
            )),
        }
    }

    /// Returns the stable CLI/API name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenApi => "openapi",
            Self::Sdk => "sdk",
            Self::Postman => "postman",
            Self::Har => "har",
        }
    }
}

/// Export selection and destination.
#[derive(Clone, Debug)]
pub struct ExportConfig {
    /// Formats to emit. At least one format is required.
    pub formats: BTreeSet<ExportFormat>,
    /// Directory receiving artifacts and the evidence sidecar.
    pub output_dir: PathBuf,
}

impl ExportConfig {
    /// Creates a validated export configuration.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no output directory or format was supplied.
    pub fn new(
        output_dir: impl Into<PathBuf>,
        formats: impl IntoIterator<Item = ExportFormat>,
    ) -> Result<Self, Diagnostic> {
        let output_dir = output_dir.into();
        let formats = formats.into_iter().collect::<BTreeSet<_>>();
        if output_dir.as_os_str().is_empty() || formats.is_empty() {
            return Err(catalogue::EXPORT_INVALID_REQUEST.instantiate(DiagnosticContext::new()));
        }
        Ok(Self {
            formats,
            output_dir,
        })
    }

    /// Creates a configuration from CLI/API names, expanding `all`.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when a format name or output directory is invalid.
    pub fn from_names(
        output_dir: impl Into<PathBuf>,
        names: impl IntoIterator<Item = String>,
    ) -> Result<Self, Diagnostic> {
        let mut formats = BTreeSet::new();
        for name in names {
            if name.eq_ignore_ascii_case("all") {
                formats.extend([
                    ExportFormat::OpenApi,
                    ExportFormat::Sdk,
                    ExportFormat::Postman,
                    ExportFormat::Har,
                ]);
            } else {
                let format = ExportFormat::parse(&name).map_err(|detail| {
                    let mut context = DiagnosticContext::new();
                    context.insert("format".to_owned(), DiagnosticValue::String(name.clone()));
                    context.insert("detail".to_owned(), DiagnosticValue::String(detail));
                    catalogue::EXPORT_INVALID_REQUEST.instantiate(context)
                })?;
                formats.insert(format);
            }
        }
        Self::new(output_dir, formats)
    }
}

/// One written artifact or generated SDK file set.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedArtifact {
    /// Logical format emitted.
    pub format: ExportFormat,
    /// Paths written below the requested output directory.
    pub paths: Vec<String>,
    /// Total bytes written for this format.
    pub bytes: u64,
}

/// Result of one session export.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReport {
    /// Session that supplied the unified surface.
    pub session_id: String,
    /// Destination directory.
    pub output_dir: String,
    /// Files emitted by format.
    pub artifacts: Vec<ExportedArtifact>,
    /// Retained-evidence sidecar referenced by primary artifacts.
    pub evidence_sidecar: String,
    /// Non-fatal emitter and interchange diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

struct PendingArtifact {
    format: ExportFormat,
    relative_path: PathBuf,
    bytes: Vec<u8>,
    sidecar: bool,
}

/// Exports selected artifacts from the active session's completed surface.
///
/// Large retained evidence is written once to `apiaxess-evidence.json`; the
/// primary `OpenAPI` document carries counts and a sidecar reference rather than
/// inlining tens of thousands of findings and diagnostics.
///
/// # Errors
///
/// Returns structured diagnostics when the session has no completed surface,
/// an emitter rejects the surface, or an output write fails.
#[allow(clippy::too_many_lines)]
pub fn export_session_artifacts(
    runtime: &SessionRuntime,
    config: &ExportConfig,
) -> Result<ExportReport, Vec<Diagnostic>> {
    let session = runtime
        .session_snapshot()
        .map_err(|diagnostic| vec![diagnostic])?;
    let session_id = session.id().as_str().to_owned();
    let Some(surface) = session.api_document().unified_surface.clone() else {
        let diagnostics =
            vec![catalogue::EXPORT_SURFACE_NOT_READY.instantiate(DiagnosticContext::new())];
        return finish_export_failure(runtime, &session_id, config, diagnostics);
    };

    let mut pending = Vec::new();
    let mut diagnostics = Vec::new();
    if config.formats.contains(&ExportFormat::OpenApi) {
        let emission = OpenApiEmitter::default()
            .emit(&surface)
            .map_err(|errors| emitter_failure(ExportFormat::OpenApi, errors));
        match emission {
            Ok(emission) => {
                diagnostics.extend(emission.diagnostics);
                let bytes = match serde_json::to_vec_pretty(&emission.document) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return finish_export_failure(
                            runtime,
                            &session_id,
                            config,
                            vec![write_failure("openapi.json", &error.to_string())],
                        );
                    }
                };
                pending.push(PendingArtifact {
                    format: ExportFormat::OpenApi,
                    relative_path: PathBuf::from("openapi.json"),
                    bytes,
                    sidecar: false,
                });
            }
            Err(errors) => return finish_export_failure(runtime, &session_id, config, errors),
        }
    }
    if config.formats.contains(&ExportFormat::Sdk) {
        match PythonSdkEmitter::default().generate(&surface) {
            Ok(sdk) => {
                diagnostics.extend(sdk.diagnostics);
                for (path, contents) in sdk.files {
                    pending.push(PendingArtifact {
                        format: ExportFormat::Sdk,
                        relative_path: PathBuf::from("python-sdk").join(path),
                        bytes: contents.into_bytes(),
                        sidecar: false,
                    });
                }
            }
            Err(errors) => {
                return finish_export_failure(
                    runtime,
                    &session_id,
                    config,
                    emitter_failure(ExportFormat::Sdk, errors),
                );
            }
        }
    }
    let collections = CollectionsEmitter::default();
    if config.formats.contains(&ExportFormat::Postman) {
        match collections.emit_collection(&surface) {
            Ok(emission) => {
                diagnostics.extend(emission.diagnostics);
                pending.push(PendingArtifact {
                    format: ExportFormat::Postman,
                    relative_path: PathBuf::from("postman.collection.json"),
                    bytes: emission.json.into_bytes(),
                    sidecar: false,
                });
            }
            Err(errors) => {
                return finish_export_failure(
                    runtime,
                    &session_id,
                    config,
                    emitter_failure(ExportFormat::Postman, errors),
                );
            }
        }
    }
    if config.formats.contains(&ExportFormat::Har) {
        match runtime.store().summaries() {
            Ok(summaries) if !summaries.is_empty() => match runtime.store().export_har() {
                Ok(bytes) => pending.push(PendingArtifact {
                    format: ExportFormat::Har,
                    relative_path: PathBuf::from("traffic.har.json"),
                    bytes,
                    sidecar: false,
                }),
                Err(error) => {
                    return finish_export_failure(runtime, &session_id, config, vec![error]);
                }
            },
            Ok(_) => match collections.emit_har(&surface) {
                Ok(emission) => {
                    diagnostics.extend(emission.diagnostics);
                    pending.push(PendingArtifact {
                        format: ExportFormat::Har,
                        relative_path: PathBuf::from("traffic.har.json"),
                        bytes: emission.json.into_bytes(),
                        sidecar: false,
                    });
                }
                Err(errors) => {
                    return finish_export_failure(
                        runtime,
                        &session_id,
                        config,
                        emitter_failure(ExportFormat::Har, errors),
                    );
                }
            },
            Err(error) => return finish_export_failure(runtime, &session_id, config, vec![error]),
        }
    }

    let evidence_bytes = match evidence_sidecar(&surface, &diagnostics) {
        Ok(bytes) => bytes,
        Err(error) => {
            return finish_export_failure(
                runtime,
                &session_id,
                config,
                vec![write_failure("apiaxess-evidence.json", &error.to_string())],
            );
        }
    };
    pending.push(PendingArtifact {
        format: ExportFormat::OpenApi,
        relative_path: PathBuf::from("apiaxess-evidence.json"),
        bytes: evidence_bytes,
        sidecar: true,
    });

    let mut artifact_map = BTreeSet::new();
    for artifact in &pending {
        if let Err(error) =
            write_artifact(&config.output_dir, &artifact.relative_path, &artifact.bytes)
        {
            diagnostics.push(error.clone());
            return finish_export_failure(runtime, &session_id, config, diagnostics);
        }
        if !artifact.sidecar {
            artifact_map.insert(artifact.format);
        }
    }

    let mut artifacts = Vec::new();
    for format in artifact_map {
        let entries = pending
            .iter()
            .filter(|artifact| artifact.format == format && !artifact.sidecar);
        let mut paths = Vec::new();
        let mut bytes = 0_u64;
        for entry in entries {
            paths.push(entry.relative_path.display().to_string());
            bytes = bytes.saturating_add(entry.bytes.len() as u64);
        }
        artifacts.push(ExportedArtifact {
            format,
            paths,
            bytes,
        });
    }
    record_export_action(
        runtime,
        &session_id,
        config,
        ActionOutcome::Completed,
        &diagnostics,
    )
    .map_err(|error| vec![error])?;
    Ok(ExportReport {
        session_id,
        output_dir: config.output_dir.display().to_string(),
        artifacts,
        evidence_sidecar: "apiaxess-evidence.json".to_owned(),
        diagnostics,
    })
}

fn evidence_sidecar(
    surface: &UnifiedApiSurface,
    export_diagnostics: &[Diagnostic],
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec_pretty(&json!({
        "schema_version": 1,
        "description": "APIxess retained evidence sidecar; primary artifacts reference this file instead of inlining high-volume evidence.",
        "coverage": surface.confidence.coverage,
        "handoffs": surface.confidence.handoffs,
        "provenance": surface.surface.provenance,
        "facts": surface.confidence.facts,
        "loose_findings": surface.surface.loose_findings,
        "signers": surface.surface.signers,
        "signer_bindings": surface.signer_bindings,
        "diagnostics": surface.diagnostics,
        "export_diagnostics": export_diagnostics
    }))
}

fn write_artifact(output_dir: &Path, relative_path: &Path, bytes: &[u8]) -> Result<(), Diagnostic> {
    let path = output_dir.join(relative_path);
    fs::create_dir_all(path.parent().unwrap_or(output_dir))
        .map_err(|error| write_failure(&path.display().to_string(), &error.to_string()))?;
    fs::write(&path, bytes)
        .map_err(|error| write_failure(&path.display().to_string(), &error.to_string()))
}

fn emitter_failure(format: ExportFormat, errors: Vec<Diagnostic>) -> Vec<Diagnostic> {
    let mut context = DiagnosticContext::new();
    context.insert(
        "format".to_owned(),
        DiagnosticValue::String(format.as_str().to_owned()),
    );
    let mut diagnostics = vec![catalogue::EXPORT_EMITTER_FAILED.instantiate(context)];
    diagnostics.extend(errors);
    diagnostics
}

fn write_failure(path: &str, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("path".to_owned(), DiagnosticValue::String(path.to_owned()));
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::EXPORT_WRITE_FAILED.instantiate(context)
}

fn finish_export_failure(
    runtime: &SessionRuntime,
    session_id: &str,
    config: &ExportConfig,
    diagnostics: Vec<Diagnostic>,
) -> Result<ExportReport, Vec<Diagnostic>> {
    match record_export_action(
        runtime,
        session_id,
        config,
        ActionOutcome::Failed,
        &diagnostics,
    ) {
        Ok(()) => Err(diagnostics),
        Err(error) => {
            let mut diagnostics = diagnostics;
            diagnostics.push(error);
            Err(diagnostics)
        }
    }
}

fn record_export_action(
    runtime: &SessionRuntime,
    session_id: &str,
    config: &ExportConfig,
    outcome: ActionOutcome,
    diagnostics: &[Diagnostic],
) -> Result<(), Diagnostic> {
    let mut session = runtime.session_snapshot()?;
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let base_id = format!("artifact.export:{timestamp}");
    let mut id = base_id.clone();
    let mut suffix = 0_u32;
    while session.audit_trail().iter().any(|record| record.id == id) {
        suffix = suffix.saturating_add(1);
        id = format!("{base_id}:{suffix}");
    }
    let format_names = config
        .formats
        .iter()
        .map(|format| format.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    session.record_action(ActionRecordInput {
        id,
        occurred_at: Utc::now(),
        actor: AuditActor::Engine,
        action: ActionDescriptor {
            kind: "artifact.export".to_owned(),
            summary: format!("Exported {format_names} artifacts for session {session_id}"),
        },
        target: ActionTarget::SessionTarget,
        outcome,
        diagnostics: diagnostics.to_vec(),
    })?;
    runtime.replace_session(session)?;
    runtime.save().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_selection_expands_all_and_rejects_unknown_names() {
        let config = ExportConfig::from_names("exports", vec!["all".to_owned(), "sdk".to_owned()])
            .expect("formats");
        assert_eq!(config.formats.len(), 4);
        assert!(ExportConfig::from_names("exports", vec!["wat".to_owned()]).is_err());
    }
}
