//! Versioned detection-evasion infrastructure.
//!
//! Stealth is deliberately independent from `pinning` and
//! `instrumentation`: it describes and deploys versioned root-hiding,
//! integrity-fix, Frida-concealment, and emulator-fingerprint artifacts, but
//! it does not contain pinning specs or signing-recovery hooks.

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::ExternalToolRunner;
use serde::{Deserialize, Serialize};

use crate::{SandboxCleanup, SandboxControl, SandboxLease};

/// Stealth infrastructure schema version.
pub const STEALTH_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// Standard evasion component family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StealthComponent {
    /// Hide root and common management artifacts.
    RootHiding,
    /// Apply session-scoped integrity/attestation fixes.
    IntegrityFix,
    /// Conceal Frida paths, names, strings, and ports.
    FridaConcealment,
    /// Reduce emulator-fingerprint signals.
    EmulatorFingerprintMitigation,
}

impl StealthComponent {
    fn label(self) -> &'static str {
        match self {
            Self::RootHiding => "root hiding",
            Self::IntegrityFix => "integrity/attestation fix",
            Self::FridaConcealment => "Frida concealment",
            Self::EmulatorFingerprintMitigation => "emulator fingerprint mitigation",
        }
    }
}

/// Session-scoped artifact command description.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthArtifact {
    /// Component family.
    pub component: StealthComponent,
    /// Versioned host artifact path.
    pub host_path: PathBuf,
    /// Session-only runtime path.
    pub remote_path: String,
    /// Arguments after the remote executable path.
    pub install_arguments: Vec<String>,
    /// Runtime cleanup command, before removing the artifact.
    pub cleanup_arguments: Vec<String>,
}

/// Version/provenance record for a stealth bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthBundle {
    /// Bundle schema version.
    pub schema_version: u32,
    /// Stable infrastructure bundle ID.
    pub bundle_id: String,
    /// Tooling generation/version visible to maintenance and audit.
    pub version: String,
    /// Release timestamp or source revision.
    pub published_at: String,
    /// Source/provenance description.
    pub provenance: String,
    /// Components carried by this bundle.
    pub components: Vec<StealthComponent>,
    /// Artifacts and lifecycle commands.
    pub artifacts: Vec<StealthArtifact>,
    /// Concealed runtime identity passed to the Frida substrate.
    pub launch_overrides: StealthLaunchOverrides,
}

impl StealthBundle {
    /// Validates maintenance metadata and component/artifact consistency.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        if self.schema_version != STEALTH_BUNDLE_SCHEMA_VERSION
            || self.bundle_id.trim().is_empty()
            || self.version.trim().is_empty()
            || self.published_at.trim().is_empty()
            || self.provenance.trim().is_empty()
            || self.components.is_empty()
        {
            return Err(diag(
                catalogue::STEALTH_BUNDLE_INVALID,
                "bundle",
                format!("invalid versioned bundle metadata for `{}`", self.bundle_id),
            ));
        }
        for artifact in &self.artifacts {
            if !self.components.contains(&artifact.component) {
                return Err(diag(
                    catalogue::STEALTH_BUNDLE_INVALID,
                    "component",
                    format!(
                        "artifact is not declared in bundle components: {:?}",
                        artifact.component
                    ),
                ));
            }
            if artifact.remote_path.trim().is_empty()
                || artifact.remote_path.chars().any(|character| {
                    character.is_whitespace()
                        || matches!(character, ';' | '|' | '&' | '$' | '`' | '<' | '>')
                })
            {
                return Err(diag(
                    catalogue::STEALTH_BUNDLE_INVALID,
                    "remote_path",
                    artifact.remote_path.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Concealed identity supplied to the independent Frida substrate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthLaunchOverrides {
    /// Concealed device server path.
    pub server_remote_path: String,
    /// Concealed Gadget library name.
    pub gadget_library_name: String,
    /// Optional non-default Frida transport port.
    pub frida_port: Option<u16>,
}

impl Default for StealthLaunchOverrides {
    fn default() -> Self {
        Self {
            server_remote_path: "/data/local/tmp/.fs-session/frida-server".to_owned(),
            gadget_library_name: "libfs-runtime.so".to_owned(),
            frida_port: None,
        }
    }
}

/// Detection signal supplied by static/runtime target analysis.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionBoundary {
    /// Hardened RASP terminates during early instrumentation.
    HardenedRasp,
    /// Hardware-backed attestation is outside software integrity fixes.
    HardwareAttestation,
    /// Custom anti-Frida behavior is outside standard concealment.
    CustomAntiFrida,
}

/// Target signals used to decide whether standard stealth is honest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthTargetProfile {
    /// Whether the runtime is an emulator.
    pub emulator: bool,
    /// Observed detection markers.
    pub signals: Vec<String>,
    /// Explicit boundaries from Phase 3.3 or later detectors.
    pub boundaries: Vec<DetectionBoundary>,
}

/// Planned standard stealth operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthPlan {
    /// Bundle provenance.
    pub bundle_id: String,
    /// Bundle version.
    pub bundle_version: String,
    /// Components to deploy.
    pub components: Vec<StealthComponent>,
    /// Approximate standard coverage target in basis points.
    pub coverage_basis_points: u16,
    /// True when a known boundary prevents an automation claim.
    pub blocked_by_boundary: bool,
    /// Plan diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Plans the versioned ~97% standard evasion layer.
#[must_use]
pub fn plan_stealth(bundle: &StealthBundle, target: &StealthTargetProfile) -> StealthPlan {
    let diagnostics = target
        .boundaries
        .first()
        .map(|boundary| {
            vec![diag(
                catalogue::STEALTH_DETECTION_BOUNDARY,
                "boundary",
                format!("{boundary:?}: standard evasion exhausted"),
            )]
        })
        .unwrap_or_default();
    StealthPlan {
        bundle_id: bundle.bundle_id.clone(),
        bundle_version: bundle.version.clone(),
        components: bundle.components.clone(),
        coverage_basis_points: 9_700,
        blocked_by_boundary: !diagnostics.is_empty(),
        diagnostics,
    }
}

/// A live session-scoped stealth deployment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StealthSessionInfo {
    /// Selected plan.
    pub plan: StealthPlan,
    /// Maintenance-visible provenance.
    pub provenance: String,
    /// Launch overrides for the independent instrumentation substrate.
    pub launch_overrides: StealthLaunchOverrides,
}

/// Deploys versioned stealth artifacts and attaches cleanup to the lease.
pub fn deploy_stealth(
    lease: &mut SandboxLease,
    _runner: Arc<dyn ExternalToolRunner>,
    bundle: &StealthBundle,
    target: &StealthTargetProfile,
) -> Result<StealthSessionInfo, Vec<Diagnostic>> {
    if let Err(error) = bundle.validate() {
        return Err(vec![error]);
    }
    let plan = plan_stealth(bundle, target);
    if plan.blocked_by_boundary {
        return Err(plan.diagnostics);
    }
    let control = lease.control();
    let mut cleanup = StealthCleanup {
        control: Arc::clone(&control),
        artifacts: Vec::new(),
    };
    for artifact in &bundle.artifacts {
        let bytes = match fs::read(&artifact.host_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                let mut errors = vec![component_diag(
                    artifact.component,
                    format!("{}: {error}", artifact.host_path.display()),
                )];
                errors.extend(cleanup.cleanup().err().unwrap_or_default());
                return Err(errors);
            }
        };
        if let Err(error) = control.put(&bytes, &artifact.remote_path, Duration::from_secs(30)) {
            let mut errors = vec![component_diag(artifact.component, error.to_string())];
            errors.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(errors);
        }
        cleanup.artifacts.push(artifact.clone());
        let chmod = control.shell(
            &[
                "chmod".to_owned(),
                "0755".to_owned(),
                artifact.remote_path.clone(),
            ],
            Duration::from_secs(20),
        );
        if let Err(error) = require_success(chmod, artifact.component, "chmod") {
            let mut errors = vec![error];
            errors.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(errors);
        }
        let mut command = vec![artifact.remote_path.clone()];
        command.extend(artifact.install_arguments.clone());
        let launch = control.shell(&command, Duration::from_secs(45));
        if let Err(error) = require_success(launch, artifact.component, "activate") {
            let mut errors = vec![error];
            errors.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(errors);
        }
    }
    lease.add_cleanup(Box::new(cleanup));
    Ok(StealthSessionInfo {
        plan,
        provenance: bundle.provenance.clone(),
        launch_overrides: bundle.launch_overrides.clone(),
    })
}

struct StealthCleanup {
    control: Arc<dyn SandboxControl>,
    artifacts: Vec<StealthArtifact>,
}

impl SandboxCleanup for StealthCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut errors = Vec::new();
        while let Some(artifact) = self.artifacts.pop() {
            if !artifact.cleanup_arguments.is_empty() {
                let output = self
                    .control
                    .shell(&artifact.cleanup_arguments, Duration::from_secs(30));
                if let Err(error) = require_success(output, artifact.component, "deactivate") {
                    errors.push(error);
                }
            }
            if let Err(error) = self
                .control
                .remove(&artifact.remote_path, Duration::from_secs(20))
            {
                errors.push(diag(
                    catalogue::STEALTH_TEARDOWN_FAILED,
                    "artifact",
                    format!("{}: {error}", artifact.remote_path),
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn require_success(
    result: Result<crate::SandboxCommandOutput, Diagnostic>,
    component: StealthComponent,
    operation: &str,
) -> Result<(), Diagnostic> {
    match result {
        Ok(output) if output.exit_code == Some(0) => Ok(()),
        Ok(output) => Err(component_diag(
            component,
            format!("{operation}: {}", output.stderr),
        )),
        Err(error) => Err(component_diag(component, format!("{operation}: {error}"))),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn component_diag(component: StealthComponent, value: String) -> Diagnostic {
    let definition = match component {
        StealthComponent::RootHiding => catalogue::STEALTH_ROOT_HIDING_FAILED,
        StealthComponent::IntegrityFix => catalogue::STEALTH_INTEGRITY_FIX_FAILED,
        StealthComponent::FridaConcealment => catalogue::STEALTH_FRIDA_CONCEALMENT_FAILED,
        StealthComponent::EmulatorFingerprintMitigation => {
            catalogue::STEALTH_EMULATOR_FINGERPRINT_FAILED
        }
    };
    diag(
        definition,
        "component",
        format!("{}: {value}", component.label()),
    )
}

fn diag(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    key: &str,
    value: String,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String("sandbox.stealth".to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value));
    definition.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> StealthBundle {
        StealthBundle {
            schema_version: STEALTH_BUNDLE_SCHEMA_VERSION,
            bundle_id: "standard-evasion".to_owned(),
            version: "2026.08".to_owned(),
            published_at: "2026-08-19".to_owned(),
            provenance: "reviewed-equivalent-bundle".to_owned(),
            components: vec![
                StealthComponent::RootHiding,
                StealthComponent::IntegrityFix,
                StealthComponent::FridaConcealment,
                StealthComponent::EmulatorFingerprintMitigation,
            ],
            artifacts: Vec::new(),
            launch_overrides: StealthLaunchOverrides::default(),
        }
    }

    #[test]
    fn bundle_version_and_provenance_are_visible_in_plan() {
        let target = StealthTargetProfile {
            emulator: true,
            signals: Vec::new(),
            boundaries: Vec::new(),
        };
        let plan = plan_stealth(&bundle(), &target);
        assert_eq!(plan.bundle_version, "2026.08");
        assert_eq!(plan.coverage_basis_points, 9_700);
        assert!(!plan.blocked_by_boundary);
    }

    #[test]
    fn hard_boundary_is_diagnosed_before_deployment() {
        let target = StealthTargetProfile {
            emulator: false,
            signals: vec!["custom anti-Frida".to_owned()],
            boundaries: vec![DetectionBoundary::CustomAntiFrida],
        };
        let plan = plan_stealth(&bundle(), &target);
        assert!(plan.blocked_by_boundary);
        assert_eq!(
            plan.diagnostics[0].id.as_ref(),
            "stealth.detection-boundary"
        );
        assert!(plan.diagnostics[0].fix.contains("Manual"));
    }

    #[test]
    fn invalid_bundle_cannot_claim_standard_coverage() {
        let mut invalid = bundle();
        invalid.version.clear();
        assert_eq!(
            invalid.validate().unwrap_err().id.as_ref(),
            "stealth.bundle-invalid"
        );
    }
}
