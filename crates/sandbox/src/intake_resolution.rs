//! Resolve normalized Android intake results into an install operation.
//!
//! This module sits after target-specific artifact intake and before the
//! runtime-specific install command. Format recognition and installer-error
//! handling are sibling strategy objects, so adding a new artifact family or
//! installer signal does not require changing the sandbox control contract.

use std::{path::PathBuf, sync::Arc, time::Duration};

use apiaxess_artifact_intake::{ArtifactFormat, NormalizedUnpackedArtifact};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};

use crate::{SandboxCommandOutput, SandboxControl};

/// One planned install operation selected by a resolution strategy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallPlan {
    /// Install one universal or standalone APK directly.
    Single {
        /// Normalized APK identifier.
        id: String,
        /// Local path to the APK.
        path: PathBuf,
    },
    /// Install a complete base-plus-split set together.
    SplitSet {
        /// Normalized APK identifiers in install order.
        ids: Vec<String>,
        /// Local APK paths in install order.
        paths: Vec<PathBuf>,
    },
}

impl InstallPlan {
    fn ids(&self) -> Vec<String> {
        match self {
            Self::Single { id, .. } => vec![id.clone()],
            Self::SplitSet { ids, .. } => ids.clone(),
        }
    }
}

/// Extensible artifact-to-install-plan strategy.
pub trait IntakeResolutionStrategy: Send + Sync {
    /// Stable strategy identifier surfaced in the outcome.
    fn id(&self) -> &'static str;
    /// Returns a plan when this strategy recognizes the normalized artifact.
    fn plan(&self, artifact: &NormalizedUnpackedArtifact) -> Option<InstallPlan>;
}

/// Resolves more than one normalized APK as a split set.
#[derive(Debug, Default, Clone, Copy)]
pub struct SplitSetStrategy;

impl IntakeResolutionStrategy for SplitSetStrategy {
    fn id(&self) -> &'static str {
        "install-multiple-splits"
    }

    fn plan(&self, artifact: &NormalizedUnpackedArtifact) -> Option<InstallPlan> {
        (artifact.installable_apks.len() > 1).then(|| InstallPlan::SplitSet {
            ids: artifact
                .installable_apks
                .iter()
                .map(|apk| apk.id.clone())
                .collect(),
            paths: artifact
                .installable_apks
                .iter()
                .map(|apk| PathBuf::from(&apk.path))
                .collect(),
        })
    }
}

/// Resolves one normalized APK as a direct universal/standalone install.
#[derive(Debug, Default, Clone, Copy)]
pub struct SingleApkStrategy;

impl IntakeResolutionStrategy for SingleApkStrategy {
    fn id(&self) -> &'static str {
        "install-single-apk"
    }

    fn plan(&self, artifact: &NormalizedUnpackedArtifact) -> Option<InstallPlan> {
        (artifact.installable_apks.len() == 1).then(|| {
            let apk = &artifact.installable_apks[0];
            InstallPlan::Single {
                id: apk.id.clone(),
                path: PathBuf::from(&apk.path),
            }
        })
    }
}

/// Normalized installer failure signal passed to error strategies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallerFailureSignal {
    /// Stable installer code extracted from bounded output.
    pub code: String,
}

impl InstallerFailureSignal {
    fn from_output(output: &SandboxCommandOutput) -> Self {
        let code = output
            .stderr
            .lines()
            .chain(output.stdout.lines())
            .flat_map(str::split_whitespace)
            .map(|token| {
                token.trim_matches(|character: char| {
                    !character.is_ascii_alphanumeric() && character != '_'
                })
            })
            .find(|token| {
                token.starts_with("INSTALL_FAILED_") || token.starts_with("INSTALL_PARSE_FAILED_")
            })
            .unwrap_or("INSTALLER_UNKNOWN")
            .to_owned();
        Self { code }
    }
}

/// Extensible installer-signal-to-diagnostic strategy.
pub trait InstallerErrorStrategy: Send + Sync {
    /// Stable strategy identifier.
    fn id(&self) -> &'static str;
    /// Translates a signal, or returns None for the next sibling strategy.
    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic>;
}

#[derive(Debug, Default, Clone, Copy)]
struct MissingSplitStrategy;

impl InstallerErrorStrategy for MissingSplitStrategy {
    fn id(&self) -> &'static str {
        "missing-split"
    }

    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        (signal.code == "INSTALL_FAILED_MISSING_SPLIT").then(|| {
            let definition = if artifact.installable_apks.len() > 1 {
                catalogue::INTAKE_SPLIT_SET_INCOMPLETE
            } else {
                catalogue::INTAKE_BASE_ONLY_SPLITS_MISSING
            };
            instantiate(definition, artifact, "missing-split")
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct AbiStrategy;

impl InstallerErrorStrategy for AbiStrategy {
    fn id(&self) -> &'static str {
        "abi-mismatch"
    }

    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        (signal.code == "INSTALL_FAILED_NO_MATCHING_ABIS")
            .then(|| instantiate(catalogue::INTAKE_NO_MATCHING_ABI, artifact, "abi-mismatch"))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ApiLevelStrategy;

impl InstallerErrorStrategy for ApiLevelStrategy {
    fn id(&self) -> &'static str {
        "android-api-level"
    }

    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        matches!(
            signal.code.as_str(),
            "INSTALL_FAILED_OLDER_SDK" | "INSTALL_FAILED_NEWER_SDK"
        )
        .then(|| {
            instantiate(
                catalogue::INTAKE_ANDROID_API_TOO_OLD,
                artifact,
                "android-api-level",
            )
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct SignatureStrategy;

impl InstallerErrorStrategy for SignatureStrategy {
    fn id(&self) -> &'static str {
        "signature-verification"
    }

    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        let signature_failure = signal.code.contains("SIGNATURE")
            || signal.code.contains("CERTIFICATE")
            || matches!(
                signal.code.as_str(),
                "INSTALL_FAILED_UPDATE_INCOMPATIBLE"
                    | "INSTALL_PARSE_FAILED_NO_CERTIFICATES"
                    | "INSTALL_FAILED_VERIFICATION_FAILURE"
                    | "INSTALL_FAILED_VERSION_DOWNGRADE"
            );
        signature_failure.then(|| {
            instantiate(
                catalogue::INTAKE_SIGNATURE_INVALID,
                artifact,
                "signature-verification",
            )
        })
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct StorageStrategy;

impl InstallerErrorStrategy for StorageStrategy {
    fn id(&self) -> &'static str {
        "storage"
    }

    fn diagnose(
        &self,
        signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        (signal.code == "INSTALL_FAILED_INSUFFICIENT_STORAGE")
            .then(|| instantiate(catalogue::INTAKE_STORAGE_INSUFFICIENT, artifact, "storage"))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct GenericInstallStrategy;

impl InstallerErrorStrategy for GenericInstallStrategy {
    fn id(&self) -> &'static str {
        "generic-installer-failure"
    }

    fn diagnose(
        &self,
        _signal: &InstallerFailureSignal,
        artifact: &NormalizedUnpackedArtifact,
    ) -> Option<Diagnostic> {
        Some(instantiate(
            catalogue::INTAKE_INSTALL_FAILED,
            artifact,
            "generic-installer-failure",
        ))
    }
}

/// User-visible result of resolving and installing one normalized artifact.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IntakeResolutionOutcome {
    /// Format identified from artifact contents.
    pub recognized_format: ArtifactFormat,
    /// Strategy that performed the install.
    pub strategy_id: String,
    /// Normalized APK identifiers installed by the strategy.
    pub installed_apks: Vec<String>,
    /// Legible summary of what the brain did.
    pub summary: String,
    /// Non-blocking intake diagnostics retained for the caller.
    pub diagnostics: Vec<Diagnostic>,
}

/// The Phase 3.1.3 resolve-or-diagnose brain.
pub struct IntakeResolutionBrain {
    strategies: Vec<Arc<dyn IntakeResolutionStrategy>>,
    error_strategies: Vec<Arc<dyn InstallerErrorStrategy>>,
}

impl Default for IntakeResolutionBrain {
    fn default() -> Self {
        Self {
            strategies: vec![Arc::new(SplitSetStrategy), Arc::new(SingleApkStrategy)],
            error_strategies: vec![
                Arc::new(MissingSplitStrategy),
                Arc::new(AbiStrategy),
                Arc::new(ApiLevelStrategy),
                Arc::new(SignatureStrategy),
                Arc::new(StorageStrategy),
                Arc::new(GenericInstallStrategy),
            ],
        }
    }
}

impl IntakeResolutionBrain {
    /// Creates a brain with the built-in strategies.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a sibling artifact resolution strategy with highest priority.
    pub fn add_strategy(&mut self, strategy: Arc<dyn IntakeResolutionStrategy>) {
        self.strategies.insert(0, strategy);
    }

    /// Adds a sibling installer-error strategy with highest priority.
    pub fn add_error_strategy(&mut self, strategy: Arc<dyn InstallerErrorStrategy>) {
        self.error_strategies.insert(0, strategy);
    }

    /// Resolves, installs, or emits a precise diagnostic for a normalized artifact.
    pub fn resolve(
        &self,
        artifact: &NormalizedUnpackedArtifact,
        control: &dyn SandboxControl,
        timeout: Duration,
    ) -> Result<IntakeResolutionOutcome, Vec<Diagnostic>> {
        if let Err(reason) = artifact.validate() {
            return Err(vec![instantiate_with_reason(
                catalogue::INTAKE_RESOLUTION_UNAVAILABLE,
                artifact,
                "invalid-normalized-artifact",
                reason,
            )]);
        }
        let Some((strategy_id, plan)) = self
            .strategies
            .iter()
            .find_map(|strategy| strategy.plan(artifact).map(|plan| (strategy.id(), plan)))
        else {
            return Err(vec![instantiate(
                catalogue::INTAKE_RESOLUTION_UNAVAILABLE,
                artifact,
                "no-install-strategy",
            )]);
        };
        let installed_ids = plan.ids();
        let result = match &plan {
            InstallPlan::Single { path, .. } => control.install_apk(path, timeout),
            InstallPlan::SplitSet { paths, .. } => control.install_apks(paths, timeout),
        };
        let output = match result {
            Ok(output) => output,
            Err(diagnostic) => return Err(vec![diagnostic]),
        };
        if output.exit_code != Some(0) {
            let signal = InstallerFailureSignal::from_output(&output);
            let diagnostic = self
                .error_strategies
                .iter()
                .find_map(|strategy| strategy.diagnose(&signal, artifact))
                .unwrap_or_else(|| {
                    instantiate(
                        catalogue::INTAKE_INSTALL_FAILED,
                        artifact,
                        "unmapped-installer-failure",
                    )
                });
            return Err(vec![diagnostic]);
        }
        let summary = match &plan {
            InstallPlan::Single { .. } => format!(
                "detected {}, installed one universal/standalone APK",
                format_format(artifact.input_format)
            ),
            InstallPlan::SplitSet { paths, .. } => format!(
                "detected {}, installed {} APK splits",
                format_format(artifact.input_format),
                paths.len()
            ),
        };
        Ok(IntakeResolutionOutcome {
            recognized_format: artifact.input_format,
            strategy_id: strategy_id.to_owned(),
            installed_apks: installed_ids,
            summary,
            diagnostics: artifact.diagnostics.clone(),
        })
    }
}

fn format_format(format: ArtifactFormat) -> String {
    format!("{format:?}").to_ascii_lowercase()
}

fn instantiate(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    artifact: &NormalizedUnpackedArtifact,
    strategy: &str,
) -> Diagnostic {
    instantiate_with_reason(definition, artifact, strategy, String::new())
}

fn instantiate_with_reason(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    artifact: &NormalizedUnpackedArtifact,
    strategy: &str,
    reason: String,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "recognized_format".to_owned(),
        DiagnosticValue::String(format_format(artifact.input_format)),
    );
    context.insert(
        "strategy".to_owned(),
        DiagnosticValue::String(strategy.to_owned()),
    );
    context.insert(
        "installable_apk_count".to_owned(),
        DiagnosticValue::Integer(
            i64::try_from(artifact.installable_apks.len()).unwrap_or(i64::MAX),
        ),
    );
    if !reason.is_empty() {
        context.insert("reason".to_owned(), DiagnosticValue::String(reason));
    }
    definition.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_artifact_intake::{
        ComponentProvenance, DexAccess, InstallableApk, NORMALIZED_ARTIFACT_SCHEMA_VERSION,
        ProtectionMetadata, RawArchive, StructuralOutput,
    };

    fn artifact(format: ArtifactFormat, count: usize) -> NormalizedUnpackedArtifact {
        let installable_apks = (0..count)
            .map(|index| InstallableApk {
                id: if index == 0 {
                    "base".to_owned()
                } else {
                    format!("split-{index}")
                },
                path: format!("/tmp/apk-{index}.apk"),
                is_base: index == 0,
            })
            .collect::<Vec<_>>();
        NormalizedUnpackedArtifact {
            schema_version: NORMALIZED_ARTIFACT_SCHEMA_VERSION,
            target_type_id: "android.apk".to_owned(),
            workspace_root: "/tmp/workspace".to_owned(),
            input_format: format,
            raw_archives: vec![RawArchive {
                format,
                path: "/tmp/input".to_owned(),
                entries: Vec::new(),
            }],
            static_archives: Vec::new(),
            structural_outputs: installable_apks
                .iter()
                .map(|apk| StructuralOutput {
                    apk_id: apk.id.clone(),
                    manifest: "/tmp/manifest".to_owned(),
                    smali_roots: vec!["/tmp/smali".to_owned()],
                    resource_root: "/tmp/res".to_owned(),
                    asset_root: "/tmp/assets".to_owned(),
                })
                .collect(),
            installable_apks,
            dex_access: DexAccess {
                dex_files: vec!["/tmp/classes.dex".to_owned()],
                parser_handoff: "fixture".to_owned(),
                capabilities: vec!["strings".to_owned()],
            },
            decompiled_source_roots: (0..count).map(|_| "/tmp/jadx".to_owned()).collect(),
            protection: ProtectionMetadata {
                detector: "fixture".to_owned(),
                detector_version: None,
                distribution_posture: "fixture".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance: vec![ComponentProvenance {
                component: apiaxess_artifact_intake::ArtifactComponent::RawArchive,
                source_tool: "fixture".to_owned(),
                source_version: None,
                recorded_at_unix_seconds: 0,
                output_root: "/tmp".to_owned(),
            }],
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn strategies_choose_single_and_split_plans_without_a_format_switch() {
        let single = artifact(ArtifactFormat::Apk, 1);
        let split = artifact(ArtifactFormat::Apkm, 3);
        assert_eq!(
            SingleApkStrategy.plan(&single).map(|_| "single"),
            Some("single")
        );
        assert_eq!(
            SplitSetStrategy.plan(&split).map(|_| "split"),
            Some("split")
        );
    }

    #[test]
    fn installer_signal_extraction_uses_a_stable_signal() {
        let output = SandboxCommandOutput {
            stdout: "Failure [INSTALL_FAILED_MISSING_SPLIT: details]".to_owned(),
            stderr: String::new(),
            exit_code: Some(1),
        };
        assert_eq!(
            InstallerFailureSignal::from_output(&output).code,
            "INSTALL_FAILED_MISSING_SPLIT"
        );
    }

    #[test]
    fn missing_split_is_translated_to_a_precise_base_only_diagnostic() {
        let signal = InstallerFailureSignal {
            code: "INSTALL_FAILED_MISSING_SPLIT".to_owned(),
        };
        let diagnostic = MissingSplitStrategy
            .diagnose(&signal, &artifact(ArtifactFormat::Apk, 1))
            .expect("missing split should be diagnosed");
        assert_eq!(diagnostic.id.as_ref(), "intake.base-only-splits-missing");
        assert!(!diagnostic.why.contains("INSTALL_FAILED_MISSING_SPLIT"));
    }

    #[test]
    fn missing_split_after_full_set_install_is_not_misreported_as_base_only() {
        let signal = InstallerFailureSignal {
            code: "INSTALL_FAILED_MISSING_SPLIT".to_owned(),
        };
        let diagnostic = MissingSplitStrategy
            .diagnose(&signal, &artifact(ArtifactFormat::ZipSplits, 3))
            .expect("split mismatch should be diagnosed");
        assert_eq!(diagnostic.id.as_ref(), "intake.split-set-incomplete");
    }
}
