//! Product analysis-pipeline orchestration.
//!
//! This module is the composition-root runner for the already-defined phase
//! handoffs. It owns ordering, session commits, progress, and diagnostics; the
//! individual phase crates continue to own their analysis behavior.

use std::{
    fmt,
    fmt::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use apiaxess_api_model::{RunId, SignerBinding, UnifiedApiSurface};
use apiaxess_app_crawler::{
    AppCrawler, CrawlConfig, CrawlReport, CredentialAnswer, CredentialDecision, CredentialKind,
    CredentialPromptReason, CredentialProvider, CredentialRedactor, CredentialRequest,
    PreRunDecision, Secret,
};
use apiaxess_artifact_intake::NormalizedUnpackedArtifact;
use apiaxess_confidence::ConfidenceConfig;
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        PIPELINE_COMPLETED, PIPELINE_DYNAMIC_BYPASS, PIPELINE_DYNAMIC_CRAWL,
        PIPELINE_DYNAMIC_SKIPPED, PIPELINE_SIGNING_SKIPPED, PIPELINE_STAGE_FAILED,
    },
};
use apiaxess_external_tools::ProcessToolRunner;
use apiaxess_fusion::FusionConfig;
use apiaxess_sandbox::{
    SandboxTier,
    traffic::{CaTrustConfig, L3Mechanism, L3RoutingConfig, SandboxTrafficSession},
};
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AnalysisPipelineState,
    AuditActor, SessionLifecycle,
};
use apiaxess_static_pass::StaticPassReport;
use apiaxess_target_apk::{ApkIntakeConfig, ApkTarget, cleanup_intake_workspace};
use apiaxess_unified_surface::{UnifiedSurfaceConfig, UnifiedSurfaceReport};
use apiaxess_workbench_proxy::{CredentialPrompt, CredentialPromptField};
use apiaxess_workbench_proxy::{FlowObserver, FlowOrigin, LiveWorkbench, ProxyCore, SessionCa};
use chrono::{DateTime, Utc};
use tokio::runtime::Runtime;

use crate::SessionRuntime;

/// Ordered stages owned by the product pipeline.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    /// Resolve and normalize the input artifact.
    Intake,
    /// Route networking implementations, extract bounded facts, and normalize honesty.
    Static,
    /// Optionally extract facts from durable captured traffic.
    Dynamic,
    /// Optionally recover signer artifacts from runtime crypto evidence.
    Signing,
    /// Merge retained static and dynamic candidates.
    Fusion,
    /// Recompute confidence and resolve handoffs.
    Confidence,
    /// Assemble the durable unified API surface.
    Surface,
    /// Terminal successful state.
    Completed,
}

impl PipelineStage {
    /// Stable serialized identifier for this stage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intake => "intake",
            Self::Static => "static",
            Self::Dynamic => "dynamic",
            Self::Signing => "signing",
            Self::Fusion => "fusion",
            Self::Confidence => "confidence",
            Self::Surface => "surface",
            Self::Completed => "completed",
        }
    }
}

/// Terminal or in-progress state of one pipeline run.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineRunStatus {
    /// A stage is executing or has produced an intermediate commit.
    Running,
    /// The unified surface was committed successfully.
    Completed,
    /// A stage failed and the failure was retained in the session.
    Failed,
}

impl PipelineRunStatus {
    /// Stable serialized identifier for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Progress event emitted by the engine and retained by the session.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PipelineProgress {
    /// Stable analysis run identifier.
    pub run_id: String,
    /// Current stage.
    pub stage: PipelineStage,
    /// Current run status.
    pub status: PipelineRunStatus,
    /// Progress in basis points, from zero through ten thousand.
    pub progress_basis_points: u16,
    /// Human-readable stage detail.
    pub message: String,
    /// Diagnostics emitted so far or by this transition.
    pub diagnostics: Vec<Diagnostic>,
    /// Whether dynamic facts were incorporated.
    pub dynamic_ran: bool,
    /// Last transition time.
    pub updated_at: DateTime<Utc>,
}

/// Callback used by a caller that wants live progress notifications.
pub type PipelineProgressCallback = Arc<dyn Fn(PipelineProgress) + Send + Sync>;

/// Configuration for one APK analysis run.
pub struct PipelineConfig {
    /// Input APK/APKM/APKS/AAB path.
    pub artifact_path: PathBuf,
    /// Stable run identifier shared by phase configurations.
    pub run_id: String,
    /// Whether to consume available session traffic for dynamic enrichment.
    pub dynamic_requested: bool,
    /// APK intake and external-tool configuration.
    pub intake: ApkIntakeConfig,
    /// Explicit signer bindings for Phase 5.3 assembly.
    pub signer_bindings: Vec<SignerBinding>,
    /// Optional live progress callback.
    pub progress_callback: Option<PipelineProgressCallback>,
    /// Session-scoped live workbench used to raise live credential prompts to
    /// the GUI during a dynamic crawl. Absent for headless/CLI runs.
    pub interaction: Option<Arc<LiveWorkbench>>,
    /// Credentials the operator supplied up front (pre-run "feed now"), keyed by
    /// field name or canonical kind. Held in memory only; never logged or saved.
    pub staged_credentials: Vec<(String, Secret)>,
}

impl fmt::Debug for PipelineConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipelineConfig")
            .field("artifact_path", &self.artifact_path)
            .field("run_id", &self.run_id)
            .field("dynamic_requested", &self.dynamic_requested)
            .field("intake", &self.intake)
            .field("signer_bindings", &self.signer_bindings)
            .field("progress_callback", &self.progress_callback.is_some())
            .field("interaction", &self.interaction.is_some())
            // Never render staged credential values — only their count.
            .field("staged_credentials", &self.staged_credentials.len())
            .finish()
    }
}

impl PipelineConfig {
    /// Creates a static-only-by-default run with a fresh stable run ID.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic only if the generated run ID cannot satisfy the
    /// API-model identifier invariant.
    pub fn new(artifact_path: impl Into<PathBuf>) -> Result<Self, Diagnostic> {
        let run_id = fresh_pipeline_run_id()?;
        Ok(Self {
            artifact_path: artifact_path.into(),
            run_id,
            dynamic_requested: false,
            intake: ApkIntakeConfig::default(),
            signer_bindings: Vec::new(),
            progress_callback: None,
            interaction: None,
            staged_credentials: Vec::new(),
        })
    }

    /// Attaches the session-scoped live workbench so the dynamic crawl can raise
    /// live credential prompts to the GUI.
    #[must_use]
    pub fn with_interaction(mut self, interaction: Arc<LiveWorkbench>) -> Self {
        self.interaction = Some(interaction);
        self
    }

    /// Supplies operator credentials up front for a login-gated crawl. Values
    /// are held in memory only.
    #[must_use]
    pub fn with_staged_credentials(mut self, credentials: Vec<(String, Secret)>) -> Self {
        self.staged_credentials = credentials;
        self
    }

    /// Replaces the generated run ID for deterministic integrations or tests.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the supplied ID is not a valid model run ID.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Result<Self, Diagnostic> {
        let run_id = run_id.into();
        RunId::new(run_id.clone()).map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert("run_id".to_owned(), DiagnosticValue::String(run_id.clone()));
            context.insert(
                "error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            PIPELINE_STAGE_FAILED.instantiate(context)
        })?;
        self.run_id = run_id;
        Ok(self)
    }

    /// Requests optional dynamic enrichment from available session traffic.
    #[must_use]
    pub const fn with_dynamic_capture(mut self, requested: bool) -> Self {
        self.dynamic_requested = requested;
        self
    }

    /// Installs an APK intake configuration.
    #[must_use]
    pub fn with_intake_config(mut self, intake: ApkIntakeConfig) -> Self {
        self.intake = intake;
        self
    }

    /// Sets the disposable normalized-intake workspace root.
    #[must_use]
    pub fn with_intake_output_root(mut self, output_root: impl Into<PathBuf>) -> Self {
        self.intake.output_root = output_root.into();
        self
    }

    /// Installs explicit signer bindings for unified-surface assembly.
    #[must_use]
    pub fn with_signer_bindings(mut self, bindings: Vec<SignerBinding>) -> Self {
        self.signer_bindings = bindings;
        self
    }

    /// Installs a live progress callback.
    #[must_use]
    pub fn with_progress_callback(
        mut self,
        callback: impl Fn(PipelineProgress) + Send + Sync + 'static,
    ) -> Self {
        self.progress_callback = Some(Arc::new(callback));
        self
    }
}

/// Successful result of an assembled product analysis run.
#[derive(Clone, Debug)]
pub struct PipelineReport {
    /// Stable analysis run identifier.
    pub run_id: String,
    /// Input artifact used by the run.
    pub artifact_path: PathBuf,
    /// Final durable API document committed to the session.
    pub document: apiaxess_api_model::ApiDocument,
    /// Standalone unified surface projection.
    pub unified_surface: UnifiedApiSurface,
    /// All non-fatal diagnostics emitted by the run.
    pub diagnostics: Vec<Diagnostic>,
    /// Final progress state.
    pub progress: PipelineProgress,
    /// Whether dynamic facts were incorporated.
    pub dynamic_ran: bool,
    /// Normalized intake output retained for inspection and later stages.
    pub normalized_artifact: NormalizedUnpackedArtifact,
}

/// Failure from one pipeline stage after the failure has been persisted.
#[derive(Clone, Debug)]
pub struct PipelineFailure {
    /// Stage that failed.
    pub stage: PipelineStage,
    /// Structured diagnostics, including the stage wrapper and root cause(s).
    pub diagnostics: Box<[Diagnostic]>,
    /// Last durable progress state.
    pub progress: Box<PipelineProgress>,
}

impl fmt::Display for PipelineFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "analysis pipeline failed at {}",
            self.stage.as_str()
        )
    }
}

impl std::error::Error for PipelineFailure {}

/// Run-scoped owner of the intake stage's unpacked scratch workspace.
///
/// Intake persists its normalized workspace (smali/jadx/dex) under the configured
/// output root because later stages read from it; intake's own guard only removes
/// it on intake *failure*. Nothing, however, removed it once a run finished, so it
/// accumulated across runs and eventually filled the disk — which then surfaced as
/// a cryptic emulator `boot-failed`. This guard binds that scratch to the lifetime
/// of a single [`run_pipeline`] call: it is removed on drop, whether the run
/// completes or bails out early from a later stage.
struct IntakeScratchGuard {
    output_root: PathBuf,
    workspace_root: String,
}

impl IntakeScratchGuard {
    fn new(output_root: PathBuf, workspace_root: String) -> Self {
        Self {
            output_root,
            workspace_root,
        }
    }
}

impl Drop for IntakeScratchGuard {
    fn drop(&mut self) {
        // Best-effort teardown: the workspace is a direct child of the configured
        // output root (the shared cleanup enforces that bound), and a failure to
        // remove it must not mask the pipeline's own result. A leftover directory
        // is at worst re-cleaned by the next run's guard rather than accumulating.
        let _ = cleanup_intake_workspace(&self.output_root, &self.workspace_root);
    }
}

/// Runs the real product pipeline inside the active durable session.
///
/// # Errors
///
/// Returns the stage and structured diagnostics when a pipeline stage cannot
/// complete. The failure state remains durable in the session.
#[allow(clippy::too_many_lines, clippy::unnecessary_mut_passed)]
pub fn run_pipeline(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
) -> Result<PipelineReport, Box<PipelineFailure>> {
    let session = runtime.session_snapshot().map_err(|diagnostic| {
        initial_failure(runtime, config, PipelineStage::Intake, vec![diagnostic])
    })?;
    if session.lifecycle() != SessionLifecycle::Active {
        return Err(initial_failure(
            runtime,
            config,
            PipelineStage::Intake,
            vec![PIPELINE_STAGE_FAILED.instantiate(stage_context(
                PipelineStage::Intake,
                "an active session is required before analysis can begin",
            ))],
        ));
    }

    let mut diagnostics = Vec::new();
    let mut dynamic_ran = false;
    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Intake,
        0,
        "Starting artifact intake",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        initial_failure(runtime, config, PipelineStage::Intake, vec![diagnostic])
    })?;

    let target = ApkTarget::new(
        Arc::new(apiaxess_external_tools::ProcessToolRunner),
        config.intake.clone(),
    );
    let normalized = match target.intake(&config.artifact_path) {
        Ok(artifact) => artifact,
        Err(failure) => {
            return Err(fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Intake,
                vec![failure.diagnostic],
                dynamic_ran,
            ));
        }
    };
    // Intake succeeded, so its own failure-only guard has been disarmed and the
    // unpacked workspace now persists under the configured output root. That
    // scratch (smali/jadx/dex) is consumed by the static and dynamic stages
    // below, so it must survive for the whole run — but it must NOT outlive the
    // run and accumulate across runs (the leak that silently filled the disk and
    // surfaced later as a cryptic emulator `boot-failed`). This run-scoped guard
    // removes it on drop, i.e. when `run_pipeline` returns down any path — the
    // success path at the end, or any early-return failure from a later stage.
    let _intake_scratch = IntakeScratchGuard::new(
        config.intake.output_root.clone(),
        normalized.workspace_root.clone(),
    );
    diagnostics.extend(normalized.diagnostics.clone());
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Intake,
        1_000,
        "Artifact normalized",
        dynamic_ran,
    )?;

    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Static,
        1_000,
        "Running static routing and extraction",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Static,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    let routed = apiaxess_network_routing::NetworkingRouter::default().route(&normalized);
    diagnostics.extend(routed.diagnostics.clone());
    let extraction = match apiaxess_network_extraction::extract(&normalized, &routed) {
        Ok(report) => report,
        Err(failure) => {
            return Err(fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Static,
                vec![failure.diagnostic],
                dynamic_ran,
            ));
        }
    };
    diagnostics.extend(extraction.diagnostics.clone());
    let static_report = match apiaxess_static_pass::normalize(&normalized, &routed, &extraction) {
        Ok(report) => report,
        Err(failure) => {
            return Err(fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Static,
                vec![failure.diagnostic],
                dynamic_ran,
            ));
        }
    };
    diagnostics.extend(static_report.diagnostics.clone());
    commit_document(runtime, &static_report).map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Static,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Static,
        4_500,
        "Static model committed with explicit handoffs",
        dynamic_ran,
    )?;

    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Dynamic,
        4_500,
        "Evaluating optional dynamic capture",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Dynamic,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    if config.dynamic_requested {
        // Wire the tier→backend factory into the live pipeline. Select the
        // bundled, owned dynamic backend from functional host-capability
        // evidence — honoring the accelerated/software speed choice from
        // capability detection — and surface the honest planner diagnostics
        // (`sandbox.runtime-selected` plus `sandbox.{accelerated,software}-mode-
        // active`). On a host without the separately-downloaded analysis runtime
        // the backend preflight reports `sandbox.analysis-runtime-missing`, an
        // actionable what/why/fix, and the stage degrades gracefully instead of
        // failing the analysis.
        let selection = apiaxess_sandbox::DynamicBackendFactory::detect(Arc::new(
            apiaxess_external_tools::ProcessToolRunner,
        ))
        .select();
        diagnostics.extend(selection.diagnostics.clone());
        let plan = selection.backend.preflight();
        let runtime_available = plan.is_runnable();
        diagnostics.extend(plan.diagnostics.clone());
        if runtime_available {
            // The analysis runtime is installed: invoke the bundled emulator
            // backend — boot the owned Android image and install the target.
            // Capture fresh traffic through the session proxy. A live sandbox
            // failure degrades honestly here rather than aborting the analysis.
            match drive_bundled_dynamic(runtime, selection.backend.as_ref(), &normalized, config) {
                Ok(info_diagnostics) => diagnostics.extend(info_diagnostics),
                Err(stage_diagnostics) => diagnostics.extend(stage_diagnostics),
            }
        }
        // Fold whatever durable traffic exists — freshly captured on a
        // runtime-equipped host, or pre-existing web/proxy traffic — into the
        // model, so dynamic facts reach fusion through the live pipeline.
        let has_traffic = runtime
            .store()
            .summaries()
            .is_ok_and(|summaries| !summaries.is_empty());
        if has_traffic {
            let dynamic_config = apiaxess_dynamic_capture::DynamicCaptureConfig::new(format!(
                "{}:dynamic",
                config.run_id
            ))
            .map_err(|diagnostic| {
                fail(
                    runtime,
                    config,
                    &mut diagnostics,
                    PipelineStage::Dynamic,
                    vec![diagnostic],
                    dynamic_ran,
                )
            })?;
            let mut session = runtime.session_snapshot().map_err(|diagnostic| {
                fail(
                    runtime,
                    config,
                    &mut diagnostics,
                    PipelineStage::Dynamic,
                    vec![diagnostic],
                    dynamic_ran,
                )
            })?;
            match apiaxess_dynamic_capture::capture_into_session(
                &mut session,
                &runtime.store(),
                &dynamic_config,
                Utc::now(),
            ) {
                Ok(report) => {
                    dynamic_ran = true;
                    diagnostics.extend(report.diagnostics);
                    runtime.replace_session(session).map_err(|diagnostic| {
                        fail(
                            runtime,
                            config,
                            &mut diagnostics,
                            PipelineStage::Dynamic,
                            vec![diagnostic],
                            dynamic_ran,
                        )
                    })?;
                    runtime.save().map_err(|diagnostic| {
                        fail(
                            runtime,
                            config,
                            &mut diagnostics,
                            PipelineStage::Dynamic,
                            vec![diagnostic],
                            dynamic_ran,
                        )
                    })?;
                }
                Err(stage_diagnostics) => {
                    return Err(fail(
                        runtime,
                        config,
                        &mut diagnostics,
                        PipelineStage::Dynamic,
                        stage_diagnostics,
                        dynamic_ran,
                    ));
                }
            }
        } else {
            let mut diagnostic = PIPELINE_DYNAMIC_SKIPPED.instantiate(DiagnosticContext::new());
            diagnostic.why = if runtime_available {
                "Dynamic analysis invoked the bundled emulator and the autonomous app crawler, but no durable captured traffic was available to enrich the static model. The app may make no network calls on the reached screens, or its traffic sits behind a sign-in wall that was not crossed.".into()
            } else {
                "Dynamic analysis was requested, but the bundled analysis runtime is not installed on this host (see sandbox.analysis-runtime-missing); no durable traffic was available to fold in.".into()
            };
            diagnostics.push(diagnostic);
        }
    } else {
        let mut diagnostic = PIPELINE_DYNAMIC_SKIPPED.instantiate(DiagnosticContext::new());
        diagnostic.why = "The caller selected the honest static-only pipeline path; dynamic enrichment was not requested.".into();
        diagnostics.push(diagnostic);
    }
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Dynamic,
        6_000,
        if dynamic_ran {
            "Dynamic facts committed"
        } else {
            "Dynamic stage skipped honestly"
        },
        dynamic_ran,
    )?;

    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Signing,
        6_000,
        "Evaluating signing recovery applicability",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Signing,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    let mut signing_skipped = PIPELINE_SIGNING_SKIPPED.instantiate(DiagnosticContext::new());
    signing_skipped.context.insert(
        "run_id".to_owned(),
        DiagnosticValue::String(config.run_id.clone()),
    );
    diagnostics.push(signing_skipped);
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Signing,
        7_000,
        "No Phase 4 runtime crypto evidence was supplied",
        dynamic_ran,
    )?;

    let document = runtime
        .session_snapshot()
        .map_err(|diagnostic| {
            fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Fusion,
                vec![diagnostic],
                dynamic_ran,
            )
        })?
        .api_document()
        .clone();
    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Fusion,
        7_000,
        "Fusing retained static and dynamic facts",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Fusion,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    let fusion_config =
        FusionConfig::new(format!("{}:fusion", config.run_id)).map_err(|diagnostic| {
            fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Fusion,
                vec![diagnostic],
                dynamic_ran,
            )
        })?;
    let fused = apiaxess_fusion::fuse_document(&document, &fusion_config, Utc::now()).map_err(
        |stage_diagnostics| {
            fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Fusion,
                stage_diagnostics,
                dynamic_ran,
            )
        },
    )?;
    diagnostics.extend(fused.diagnostics.clone());
    commit_api_document(runtime, fused.document.clone()).map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Fusion,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Fusion,
        8_200,
        "Fused model committed",
        dynamic_ran,
    )?;

    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Confidence,
        8_200,
        "Recomputing confidence and handoffs",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Confidence,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    let confidence_config = ConfidenceConfig::new(format!("{}:confidence", config.run_id))
        .map_err(|diagnostic| {
            fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Confidence,
                vec![diagnostic],
                dynamic_ran,
            )
        })?;
    let confidence = apiaxess_confidence::recompute_document(
        &runtime
            .session_snapshot()
            .map_err(|diagnostic| {
                fail(
                    runtime,
                    config,
                    &mut diagnostics,
                    PipelineStage::Confidence,
                    vec![diagnostic],
                    dynamic_ran,
                )
            })?
            .api_document()
            .clone(),
        &confidence_config,
        Utc::now(),
    )
    .map_err(|stage_diagnostics| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Confidence,
            stage_diagnostics,
            dynamic_ran,
        )
    })?;
    diagnostics.extend(confidence.diagnostics.clone());
    commit_api_document(runtime, confidence.document.clone()).map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Confidence,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Confidence,
        9_200,
        "Confidence and handoffs committed",
        dynamic_ran,
    )?;

    announce(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Surface,
        9_200,
        "Assembling unified API surface",
        dynamic_ran,
    )
    .map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Surface,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    let mut surface_config = UnifiedSurfaceConfig::new(format!("{}:surface", config.run_id))
        .map_err(|diagnostic| {
            fail(
                runtime,
                config,
                &mut diagnostics,
                PipelineStage::Surface,
                vec![diagnostic],
                dynamic_ran,
            )
        })?;
    surface_config
        .signer_bindings
        .clone_from(&config.signer_bindings);
    let surface = assemble(
        &runtime
            .session_snapshot()
            .map_err(|diagnostic| {
                fail(
                    runtime,
                    config,
                    &mut diagnostics,
                    PipelineStage::Surface,
                    vec![diagnostic],
                    dynamic_ran,
                )
            })?
            .api_document()
            .clone(),
        &surface_config,
    )
    .map_err(|stage_diagnostics| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Surface,
            stage_diagnostics,
            dynamic_ran,
        )
    })?;
    diagnostics.extend(surface.diagnostics.clone());
    commit_api_document(runtime, surface.document.clone()).map_err(|diagnostic| {
        fail(
            runtime,
            config,
            &mut diagnostics,
            PipelineStage::Surface,
            vec![diagnostic],
            dynamic_ran,
        )
    })?;
    diagnostics.push(PIPELINE_COMPLETED.instantiate(DiagnosticContext::new()));
    let progress = complete(
        runtime,
        config,
        &mut diagnostics,
        PipelineStage::Completed,
        10_000,
        "Unified API surface committed",
        dynamic_ran,
    )?;

    Ok(PipelineReport {
        run_id: config.run_id.clone(),
        artifact_path: config.artifact_path.clone(),
        document: surface.document,
        unified_surface: surface.unified,
        diagnostics,
        progress,
        dynamic_ran,
        normalized_artifact: normalized,
    })
}

/// Invokes the selected bundled dynamic backend for a live pipeline run.
///
/// Boots the owned emulator, installs the target, and captures the traffic the
/// autonomous crawler provokes by methodically driving the app's UI. Login gates
/// are crossed with operator-supplied, in-memory-only, redacted-from-capture
/// credentials. The emulator is always torn down, even on failure.
///
/// Returns informational diagnostics (the honest crawl-coverage summary) on
/// success, or hard-failure diagnostics on error.
#[allow(clippy::too_many_lines)]
fn drive_bundled_dynamic(
    runtime: &SessionRuntime,
    backend: &dyn apiaxess_sandbox::SandboxBackend,
    normalized: &NormalizedUnpackedArtifact,
    config: &PipelineConfig,
) -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
    let session = runtime
        .session_snapshot()
        .map_err(|diagnostic| vec![diagnostic])?;
    let session_id = session.id().as_str().to_owned();
    let mut request =
        apiaxess_sandbox::SandboxStartRequest::new(session_id, format!("lease:{}", config.run_id));
    request.readiness_timeout = Duration::from_secs(300);
    let mut lease = backend.start(&request)?;
    lease.resolve_and_install(normalized, Duration::from_secs(180))?;

    let package_name = package_name_from_artifact(normalized)?;

    // If the target enforces certificate pinning, bypass it before the capture
    // window so its traffic reaches the proxy. Plain apps skip the lane. On a
    // build without the frida-embedded variant (or if a lane fails) this reports
    // honestly rather than capturing nothing silently.
    let bypass_diagnostics = maybe_bypass_pinning(
        &mut lease,
        normalized,
        &package_name,
        session.id().as_str(),
        &request.lease_id,
    );

    // Arm the credential redactor on the durable store BEFORE any crawl begins.
    // Setting it here guarantees no capture window exists in which an injected
    // credential could reach disk unredacted, regardless of capture path.
    let redactor = Arc::new(CredentialRedactor::new());
    runtime
        .store()
        .set_redactor(Arc::clone(&redactor) as Arc<dyn apiaxess_workbench_store::FlowRedactor>);

    let observer = Arc::new(LiveWorkbench::new());
    observer.attach_store(runtime.store());
    // Surface every host the sandboxed app is observed contacting. An APK
    // engagement declares no allowed network targets (the operator cannot know the
    // app's backend hosts up front), so classifying captured flows against a
    // declared scope would discard all of them and fuse nothing. But the crawled
    // app itself made every captured, decrypted call, so an observed hit *is* the
    // honesty guarantee — no filler can enter, because nothing was fabricated.
    // Admit them all: first-party backend and third-party SDK/telemetry alike are
    // real pentest surface (a third-party weakness the app depends on is a valid
    // finding). First-vs-third-party is a downstream *label*, not a capture filter.
    observer.set_engagement_scope(session.engagement_scope().clone());
    observer.set_admit_all_observed(true);
    observer.set_provenance(format!("pipeline.{}.bundled-dynamic", config.run_id));
    let observer_for_proxy: Arc<dyn FlowObserver> = observer;
    let ca = SessionCa::generate().map_err(|error| vec![error])?;
    let lease_id = request.lease_id.clone();

    // The credential provider bridges the crawler to the GUI's live prompt over
    // the session-scoped workbench (instance A), and carries any pre-run creds.
    let staged = staged_answer(config);
    let provider: Box<dyn CredentialProvider> = Box::new(PipelineCredentialProvider {
        interaction: config.interaction.clone(),
        staged,
        prompt_timeout: Duration::from_secs(300),
    });
    let crawl_config = CrawlConfig::new(package_name.clone());
    let interaction = config.interaction.clone();
    let crawl_redactor = Arc::clone(&redactor);
    // The durable store, so the drain below can watch for late-arriving flows.
    let drain_store = runtime.store();

    // The pipeline runs inside a Tokio runtime; run the whole async capture plus
    // the (synchronous, blocking) crawl on a dedicated OS thread that has no
    // ambient runtime, so `block_on` is always valid.
    let capture = std::thread::spawn(move || -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
        let capture_runtime = Runtime::new().map_err(|error| {
            vec![dynamic_stage_diagnostic(format!(
                "could not create capture runtime: {error}"
            ))]
        })?;
        let traffic = capture_runtime.block_on(SandboxTrafficSession::start(
            ProxyCore::new(),
            lease,
            &session,
            ca,
            observer_for_proxy,
            L3RoutingConfig {
                proxy_host: "10.0.2.2".to_owned(),
                proxy_port: 0,
                redirect_port: 0,
                mechanism: L3Mechanism::Iptables,
                lease_id: lease_id.clone(),
            },
            CaTrustConfig::for_tier(SandboxTier::BundledEmulator, &lease_id),
            Arc::new(ProcessToolRunner),
            None,
        ))?;

        let Some(control) = traffic.control() else {
            let _ = capture_runtime.block_on(traffic.teardown());
            return Err(vec![dynamic_stage_diagnostic(
                "capture session has no sandbox control".to_owned(),
            )]);
        };
        // Drive the app. The crawler borrows the control transport for its whole
        // run; it is dropped before teardown consumes the traffic session.
        let report = {
            let mut crawler =
                AppCrawler::new(control.as_ref(), crawl_config, provider, crawl_redactor);
            crawler.run()
        };
        drop(control);
        // Idle-detect drain: keep the capture window open while new flows are
        // still arriving, so a slow app's post-auth initialization (calls that can
        // fire 6–8s after sign-in, with no further UI interaction) is captured
        // rather than cut off by a fixed short window. Stops after a quiet gap, or
        // at a hard cap so a chatty background poller can't hold the pipeline open.
        idle_drain(&drain_store);
        let teardown = capture_runtime.block_on(traffic.teardown());

        let report_diagnostic = crawl_report_diagnostic(&report);
        // Surface the honest coverage summary live to the GUI when connected.
        if let Some(live) = &interaction {
            live.publish_diagnostic(report_diagnostic.clone());
        }
        if let Err(teardown_diagnostics) = teardown {
            let mut diagnostics = vec![report_diagnostic];
            diagnostics.extend(teardown_diagnostics);
            return Err(diagnostics);
        }
        Ok(vec![report_diagnostic])
    });
    // The capture outcome: the labeled summary of every host the app was observed
    // hitting, or the honest "no calls — needs in-app setup, use the client" note
    // when none. Read from the store after capture. Informational — never blocks.
    let host_summary = observed_host_summary(runtime, &package_name);
    // Merge the bypass notes (informational, computed before capture) with the
    // capture outcome so both reach the pipeline diagnostics.
    match capture.join() {
        Ok(Ok(mut info)) => {
            let mut all = bypass_diagnostics;
            all.append(&mut info);
            all.push(host_summary);
            Ok(all)
        }
        Ok(Err(mut errors)) => {
            let mut all = bypass_diagnostics;
            all.append(&mut errors);
            all.push(host_summary);
            Err(all)
        }
        Err(_) => {
            let mut all = bypass_diagnostics;
            all.push(dynamic_stage_diagnostic(
                "the dynamic capture thread panicked".to_owned(),
            ));
            Err(all)
        }
    }
}

/// Holds the capture window open until traffic goes quiet, so late post-auth
/// initialization calls are captured without guessing a fixed window length.
///
/// Polls the durable store's flow count: every time the count grows, the quiet
/// timer resets; the drain ends after `IDLE_STOP` of no new flows, or at the
/// `MAX` hard cap (a background poller that never goes quiet must not stall the
/// pipeline). `MIN` guarantees at least a short settle even on an instantly-quiet
/// app.
fn idle_drain(store: &apiaxess_workbench_store::TrafficStore) {
    let flow_count = |store: &apiaxess_workbench_store::TrafficStore| {
        store.summaries().map(|summaries| summaries.len()).ok()
    };
    let started = Instant::now();
    let mut last_count = flow_count(store).unwrap_or(0);
    let mut last_change = Instant::now();
    loop {
        std::thread::sleep(DRAIN_POLL);
        if let Some(count) = flow_count(store) {
            if count != last_count {
                last_count = count;
                last_change = Instant::now();
            }
        }
        if drain_should_stop(started.elapsed(), last_change.elapsed()) {
            break;
        }
    }
}

const DRAIN_POLL: Duration = Duration::from_millis(1000);
const DRAIN_IDLE_STOP: Duration = Duration::from_secs(6);
const DRAIN_MIN: Duration = Duration::from_secs(3);
const DRAIN_MAX: Duration = Duration::from_secs(30);

/// Whether the idle drain should end: at the hard cap regardless, or once a
/// minimum settle has passed and traffic has been quiet for the idle gap.
fn drain_should_stop(elapsed: Duration, since_last_flow: Duration) -> bool {
    elapsed >= DRAIN_MAX || (elapsed >= DRAIN_MIN && since_last_flow >= DRAIN_IDLE_STOP)
}

/// Bypasses certificate pinning when the target enforces it, before capture.
///
/// Returns informational diagnostics describing the decision and outcome. When
/// pinning is present but the bypass is unavailable (e.g. the base build without
/// the frida-embedded variant) or fails, the honest capability/failure
/// diagnostics are included so the run reports "pinning present, bypass
/// unavailable/failed" rather than silently capturing nothing.
fn maybe_bypass_pinning(
    lease: &mut apiaxess_sandbox::SandboxLease,
    normalized: &NormalizedUnpackedArtifact,
    package_name: &str,
    session_id: &str,
    lease_id: &str,
) -> Vec<Diagnostic> {
    use apiaxess_sandbox::pinning::{
        BypassRequest, BypassTechniqueRegistry, TargetInventory, apply_bypass, assess_pinning,
    };

    let assessment = assess_pinning(normalized);
    if !assessment.present {
        if assessment.truncated {
            // The bounded scan hit its cap before completing, so "no pinning" is
            // not certain. Say so rather than silently treating the app as plain —
            // a missed deep pin literal would leave a pinned app capturing nothing.
            return vec![bypass_note(
                "No certificate-pinning signals found, but the bounded bytecode/resource scan was truncated before completing; pinning cannot be ruled out. If capture yields no flows from a suspected-pinned app, treat pinning as possible.".to_owned(),
            )];
        }
        return vec![bypass_note(
            "No certificate-pinning signals detected; bypass lane not engaged (plain traffic reaches the proxy directly).".to_owned(),
        )];
    }
    let evidence = assessment.evidence.join("; ");
    let rooted = probe_rooted(lease);
    let inventory = TargetInventory::from_normalized(package_name, normalized, rooted);
    let mut request = BypassRequest::new(session_id.to_owned(), lease_id.to_owned(), inventory);
    // Resolve the Frida lane's device-side server from the bundled analysis
    // runtime. `BypassToolchain::default()` leaves this as a bare `frida-server`
    // that never resolves on a clean host, so without this the frida-embedded
    // lane fails its deploy even though the binary ships with the product.
    request.toolchain.frida_server_path = apiaxess_sandbox::bundled_frida_server_path();
    let registry = BypassTechniqueRegistry::builtins();
    let runner: Arc<dyn apiaxess_external_tools::ExternalToolRunner> = Arc::new(ProcessToolRunner);
    match apply_bypass(lease, &request, &registry, &runner) {
        Ok(outcome) => vec![bypass_note(format!(
            "Certificate pinning detected ({evidence}); bypass applied via the {:?} lane — techniques: [{}]. Frida server started: {}.",
            outcome.plan.lane,
            outcome.applied_technique_ids.join(", "),
            outcome.frida_server_started,
        ))],
        Err(mut diagnostics) => {
            let mut notes = vec![bypass_note(format!(
                "Certificate pinning detected ({evidence}) but the bypass lane is unavailable or failed; traffic from pinned endpoints may not be captured. See the accompanying diagnostic(s)."
            ))];
            notes.append(&mut diagnostics);
            notes
        }
    }
}

/// Best-effort root probe used to select the Frida vs. patch bypass lane.
///
/// The bundled AOSP emulator is a `userdebug` build, so root is available via
/// `adb root` (the same escalation the CA-overlay step performs later). We
/// actively escalate here — not just observe the current uid — so a rootable
/// runtime selects the primary Frida lane instead of falling back to the no-root
/// patch-and-resign lane (which needs a resign toolchain the product does not
/// bundle).
fn probe_rooted(lease: &apiaxess_sandbox::SandboxLease) -> bool {
    let control = lease.control();
    let is_root = |output: &apiaxess_sandbox::SandboxCommandOutput| {
        output.exit_code == Some(0) && output.stdout.contains("uid=0")
    };
    let check = || {
        control
            .shell(&["id".to_owned()], Duration::from_secs(10))
            .as_ref()
            .is_ok_and(is_root)
    };
    if check() {
        return true;
    }
    // Escalate the transport to root (restarts adbd as root on a userdebug
    // build), then re-check. Ignore the command result: a production build that
    // refuses `adb root` simply stays unrooted and the check below reports it.
    let _ = control.command(&["root".to_owned()], Duration::from_secs(30));
    if check() {
        return true;
    }
    control
        .shell(
            &["su".to_owned(), "-c".to_owned(), "id".to_owned()],
            Duration::from_secs(10),
        )
        .as_ref()
        .is_ok_and(is_root)
}

/// Informational (Info-severity) bypass note carried in the pipeline diagnostics.
fn bypass_note(detail: String) -> Diagnostic {
    let mut diagnostic = PIPELINE_DYNAMIC_BYPASS.instantiate(DiagnosticContext::new());
    diagnostic.why = detail.into();
    diagnostic
}

/// Builds the pre-run credential answer from staged config values, if any.
fn staged_answer(config: &PipelineConfig) -> Option<CredentialAnswer> {
    if config.staged_credentials.is_empty() {
        return None;
    }
    let values = config
        .staged_credentials
        .iter()
        .map(|(name, secret)| (name.clone(), secret.clone()))
        .collect();
    Some(CredentialAnswer { values })
}

/// Builds the informational, honest crawl-coverage diagnostic (never a % claim).
fn crawl_report_diagnostic(report: &CrawlReport) -> Diagnostic {
    let mut diagnostic = PIPELINE_DYNAMIC_CRAWL.instantiate(DiagnosticContext::new());
    let notes = if report.notes.is_empty() {
        String::new()
    } else {
        format!(" Notes: {}", report.notes.join(" | "))
    };
    diagnostic.why = format!("{}.{notes}", report.summary_line()).into();
    diagnostic
}

/// Bridges the crawler's credential requests to the GUI's live prompt channel.
struct PipelineCredentialProvider {
    interaction: Option<Arc<LiveWorkbench>>,
    staged: Option<CredentialAnswer>,
    prompt_timeout: Duration,
}

impl PipelineCredentialProvider {
    fn ask(&self, request: &CredentialRequest) -> Option<CredentialAnswer> {
        let live = self.interaction.as_ref()?;
        let prompt = CredentialPrompt {
            id: live.next_prompt_id(),
            package: request.package.clone(),
            screen_summary: request.screen_summary.clone(),
            reason: match request.reason {
                CredentialPromptReason::LoginGate => "login_gate".to_owned(),
                CredentialPromptReason::Otp => "otp".to_owned(),
            },
            fields: request
                .fields
                .iter()
                .map(|field| CredentialPromptField {
                    name: field.name.clone(),
                    label: field.label.clone(),
                    kind: kind_key(field.kind).to_owned(),
                    secret: field.secret,
                })
                .collect(),
        };
        let answer = live.request_credential_prompt(prompt, self.prompt_timeout)?;
        if answer.skip {
            return None;
        }
        Some(CredentialAnswer {
            values: answer
                .values
                .into_iter()
                .map(|(name, value)| (name, Secret::from_text(&value)))
                .collect(),
        })
    }
}

impl CredentialProvider for PipelineCredentialProvider {
    fn pre_run(&mut self, _package: &str) -> PreRunDecision {
        // The pre-run choice is made in the GUI before the run; here we only act
        // on staged credentials (Skip is expressed GUI-side by not running dynamic).
        match self.staged.take() {
            Some(answer) if answer.has_values() => PreRunDecision::FeedNow(answer),
            _ => PreRunDecision::TryAnyway,
        }
    }

    fn on_login_gate(&mut self, request: &CredentialRequest) -> CredentialDecision {
        match self.ask(request) {
            Some(answer) if answer.has_values() => CredentialDecision::Provide(answer),
            _ => CredentialDecision::Continue,
        }
    }

    fn on_otp(&mut self, request: &CredentialRequest) -> Option<Secret> {
        self.ask(request)
            .and_then(|answer| answer.values.into_iter().next().map(|(_, secret)| secret))
    }
}

const fn kind_key(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Username => "username",
        CredentialKind::Password => "password",
        CredentialKind::Email => "email",
        CredentialKind::Phone => "phone",
        CredentialKind::Pin => "pin",
        CredentialKind::Otp => "otp",
        CredentialKind::Generic => "generic",
    }
}

fn package_name_from_artifact(
    artifact: &NormalizedUnpackedArtifact,
) -> Result<String, Vec<Diagnostic>> {
    let manifest = artifact
        .structural_outputs
        .iter()
        .find(|output| output.apk_id == "base")
        .or_else(|| artifact.structural_outputs.first())
        .ok_or_else(|| {
            vec![dynamic_stage_diagnostic(
                "normalized artifact has no manifest".to_owned(),
            )]
        })?;
    let manifest_xml = std::fs::read_to_string(&manifest.manifest).map_err(|error| {
        vec![dynamic_stage_diagnostic(format!(
            "could not read decoded manifest: {error}"
        ))]
    })?;
    manifest_package_name(&manifest_xml).ok_or_else(|| {
        vec![dynamic_stage_diagnostic(
            "decoded manifest has no package attribute".to_owned(),
        )]
    })
}

fn manifest_package_name(manifest_xml: &str) -> Option<String> {
    let manifest = manifest_xml.find("<manifest")?;
    let element_end = manifest_xml[manifest..].find('>')? + manifest;
    let element = &manifest_xml[manifest..element_end];
    for quote in ['\"', '\''] {
        let marker = format!("package={quote}");
        if let Some(start) = element.find(&marker) {
            let value_start = start + marker.len();
            if let Some(value_end) = element[value_start..].find(quote) {
                let value = element[value_start..value_start + value_end].trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

#[allow(clippy::needless_pass_by_value)] // Ergonomic call sites pass owned format!(...) results.
fn dynamic_stage_diagnostic(detail: String) -> Diagnostic {
    PIPELINE_STAGE_FAILED.instantiate(stage_context(PipelineStage::Dynamic, &detail))
}

fn assemble(
    document: &apiaxess_api_model::ApiDocument,
    config: &UnifiedSurfaceConfig,
) -> Result<UnifiedSurfaceReport, Vec<Diagnostic>> {
    apiaxess_unified_surface::assemble_document(document, config, Utc::now())
}

/// First- vs third-party classification of a host the app was observed hitting.
///
/// This is an honest *label*, never a capture filter — every observed host is
/// surfaced regardless. First-party is decided by affinity between the host's
/// registrable-domain labels and the app's own package tokens; a curated set of
/// well-known SDK/analytics/tracker domains marks the obvious third parties. A
/// host that matches neither signal is left unclassified rather than guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostParty {
    FirstParty,
    ThirdParty,
    Unclassified,
}

/// Well-known third-party SDK / analytics / tracker / payment host suffixes. A
/// host ending in one of these is external to the app's own backend. The list is
/// a labeling aid, not exhaustive — an unrecognized host is left unclassified.
const THIRD_PARTY_SUFFIXES: &[&str] = &[
    "facebook.com",
    "fbcdn.net",
    "graph.facebook.com",
    "google.com",
    "googleapis.com",
    "google-analytics.com",
    "googletagmanager.com",
    "gstatic.com",
    "doubleclick.net",
    "crashlytics.com",
    "app-measurement.com",
    "firebaseio.com",
    "firebaseinstallations.googleapis.com",
    "clarity.ms",
    "appsflyer.com",
    "adjust.com",
    "branch.io",
    "sentry.io",
    "bugsnag.com",
    "mixpanel.com",
    "amplitude.com",
    "segment.io",
    "segment.com",
    "onesignal.com",
    "cloudflareinsights.com",
    "razorpay.com",
    "juspay.in",
    "cashfree.com",
    "phonepe.com",
    "paytm.in",
];

/// Classifies one observed host relative to the app package.
fn classify_host_party(host: &str, package: &str) -> HostParty {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if THIRD_PARTY_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return HostParty::ThirdParty;
    }
    // Package tokens (`live.tamasha.playroom` → tamasha, playroom) matched against
    // the host's own labels flags the app's own backend (`api.tamasha.live`).
    let host_labels: Vec<&str> = host.split('.').collect();
    let affinity = package
        .split('.')
        .filter(|token| token.len() >= 4 && !GENERIC_PACKAGE_TOKENS.contains(token))
        .any(|token| host_labels.contains(&token));
    if affinity {
        HostParty::FirstParty
    } else {
        HostParty::Unclassified
    }
}

/// Package name segments too generic to signal first-party affinity.
const GENERIC_PACKAGE_TOKENS: &[&str] = &[
    "com", "org", "net", "app", "apps", "android", "mobile", "www", "io", "co", "the",
];

/// Builds the honest, labeled summary of every host the app was observed hitting.
///
/// Read from the durable store after capture so it reflects exactly what was
/// captured. Every host appears; first-/third-party is a label so the tester can
/// distinguish the app's own backend from the SDKs and trackers it depends on.
fn observed_host_summary(runtime: &SessionRuntime, package: &str) -> Diagnostic {
    let hosts: Vec<String> = runtime.store().summaries().map_or_else(
        |_| Vec::new(),
        |summaries| {
            let mut hosts: Vec<String> = summaries
                .into_iter()
                .filter(|flow| flow.origin == FlowOrigin::Capture)
                .filter_map(|flow| flow.host)
                .collect();
            hosts.sort();
            hosts.dedup();
            hosts
        },
    );
    // No calls captured: this is the Breezy-class honest-empty. The autonomous
    // crawler reached the app but no backend call fired — almost always because
    // the app needs in-app setup it can't complete (a city/location, a selection,
    // or an account step). Say so plainly and point to the right tool.
    if hosts.is_empty() {
        let mut diagnostic = PIPELINE_DYNAMIC_CRAWL.instantiate(DiagnosticContext::new());
        diagnostic.why = "No API calls were captured. The app most likely requires in-app setup the autonomous crawler could not complete — e.g. choosing a location/city, making a selection, or an account step it lacks credentials for. Apps like this are best driven manually: install the APIaxess client APK on a device and interact with the app yourself while it captures live.".into();
        return diagnostic;
    }
    let mut first = Vec::new();
    let mut third = Vec::new();
    let mut other = Vec::new();
    for host in hosts {
        match classify_host_party(&host, package) {
            HostParty::FirstParty => first.push(host),
            HostParty::ThirdParty => third.push(host),
            HostParty::Unclassified => other.push(host),
        }
    }
    let render = |label: &str, hosts: &[String]| {
        if hosts.is_empty() {
            String::new()
        } else {
            format!(" {label}: {}.", hosts.join(", "))
        }
    };
    let detail = format!(
        "Surfaced every host the app was observed contacting ({} first-party / {} third-party / {} unclassified).{}{}{}",
        first.len(),
        third.len(),
        other.len(),
        render("First-party", &first),
        render("Third-party (SDK/analytics/tracker)", &third),
        render("Unclassified", &other),
    );
    let mut diagnostic = PIPELINE_DYNAMIC_CRAWL.instantiate(DiagnosticContext::new());
    diagnostic.why = detail.into();
    diagnostic
}

fn commit_api_document(
    runtime: &SessionRuntime,
    document: apiaxess_api_model::ApiDocument,
) -> Result<(), Diagnostic> {
    let mut session = runtime.session_snapshot()?;
    session.commit_api_document(document, Utc::now())?;
    runtime.replace_session(session)?;
    runtime.save().map(|_| ())
}

fn commit_document(runtime: &SessionRuntime, report: &StaticPassReport) -> Result<(), Diagnostic> {
    let mut session = runtime.session_snapshot()?;
    apiaxess_static_pass::commit(&mut session, report, Utc::now())?;
    runtime.replace_session(session)?;
    runtime.save().map(|_| ())
}

fn announce(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    diagnostics: &[Diagnostic],
    stage: PipelineStage,
    progress_basis_points: u16,
    message: &str,
    dynamic_ran: bool,
) -> Result<(), Diagnostic> {
    let progress = transition(
        config,
        stage,
        PipelineRunStatus::Running,
        progress_basis_points,
        message,
        diagnostics.to_owned(),
        dynamic_ran,
    );
    persist_progress(runtime, config, &progress)
}

fn complete(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    #[allow(clippy::ptr_arg)] diagnostics: &mut Vec<Diagnostic>,
    stage: PipelineStage,
    progress_basis_points: u16,
    message: &str,
    dynamic_ran: bool,
) -> Result<PipelineProgress, Box<PipelineFailure>> {
    let progress = transition(
        config,
        stage,
        if stage == PipelineStage::Completed {
            PipelineRunStatus::Completed
        } else {
            PipelineRunStatus::Running
        },
        progress_basis_points,
        message,
        diagnostics.clone(),
        dynamic_ran,
    );
    persist_audited_progress(runtime, config, &progress, ActionOutcome::Completed).map_err(
        |diagnostic| {
            fail(
                runtime,
                config,
                diagnostics,
                stage,
                vec![diagnostic],
                dynamic_ran,
            )
        },
    )?;
    Ok(progress)
}

#[allow(clippy::needless_pass_by_value, clippy::unnecessary_box_returns)]
fn fail(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    diagnostics: &mut Vec<Diagnostic>,
    stage: PipelineStage,
    stage_diagnostics: Vec<Diagnostic>,
    dynamic_ran: bool,
) -> Box<PipelineFailure> {
    diagnostics.extend(stage_diagnostics.clone());
    let mut wrapper = PIPELINE_STAGE_FAILED.instantiate(stage_context(
        stage,
        "see the retained stage diagnostics for the root cause",
    ));
    wrapper.context.insert(
        "diagnostic_ids".to_owned(),
        DiagnosticValue::StringList(
            stage_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.id.to_string())
                .collect(),
        ),
    );
    diagnostics.push(wrapper);
    let progress = transition(
        config,
        stage,
        PipelineRunStatus::Failed,
        progress_for(stage),
        "Pipeline stage failed",
        diagnostics.clone(),
        dynamic_ran,
    );
    let persist_result =
        persist_audited_progress(runtime, config, &progress, ActionOutcome::Failed);
    if let Err(diagnostic) = persist_result {
        diagnostics.push(diagnostic);
    }
    Box::new(PipelineFailure {
        stage,
        diagnostics: diagnostics.clone().into_boxed_slice(),
        progress: Box::new(progress),
    })
}

#[allow(clippy::unnecessary_box_returns)]
fn initial_failure(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    stage: PipelineStage,
    diagnostics: Vec<Diagnostic>,
) -> Box<PipelineFailure> {
    let mut accumulated = diagnostics;
    fail(runtime, config, &mut accumulated, stage, Vec::new(), false)
}

fn transition(
    config: &PipelineConfig,
    stage: PipelineStage,
    status: PipelineRunStatus,
    progress_basis_points: u16,
    message: &str,
    diagnostics: Vec<Diagnostic>,
    dynamic_ran: bool,
) -> PipelineProgress {
    PipelineProgress {
        run_id: config.run_id.clone(),
        stage,
        status,
        progress_basis_points,
        message: message.to_owned(),
        diagnostics,
        dynamic_ran,
        updated_at: Utc::now(),
    }
}

fn persist_progress(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    progress: &PipelineProgress,
) -> Result<(), Diagnostic> {
    let mut session = runtime.session_snapshot()?;
    session
        .set_analysis_pipeline_state(state_from_progress(config, progress), progress.updated_at)?;
    runtime.replace_session(session)?;
    emit(config, progress);
    Ok(())
}

fn persist_audited_progress(
    runtime: &SessionRuntime,
    config: &PipelineConfig,
    progress: &PipelineProgress,
    outcome: ActionOutcome,
) -> Result<(), Diagnostic> {
    let mut session = runtime.session_snapshot()?;
    session
        .set_analysis_pipeline_state(state_from_progress(config, progress), progress.updated_at)?;
    session.record_action(ActionRecordInput {
        id: format!(
            "analysis.pipeline:{}:{}",
            config.run_id,
            progress.stage.as_str()
        ),
        occurred_at: progress.updated_at,
        actor: AuditActor::Engine,
        action: ActionDescriptor {
            kind: format!("analysis.pipeline.{}", progress.stage.as_str()),
            summary: progress.message.clone(),
        },
        target: ActionTarget::SessionTarget,
        outcome,
        diagnostics: if outcome == ActionOutcome::Failed {
            progress.diagnostics.clone()
        } else {
            Vec::new()
        },
    })?;
    runtime.replace_session(session)?;
    emit(config, progress);
    Ok(())
}

fn state_from_progress(
    config: &PipelineConfig,
    progress: &PipelineProgress,
) -> AnalysisPipelineState {
    AnalysisPipelineState {
        schema_version: 1,
        run_id: config.run_id.clone(),
        artifact_path: config.artifact_path.display().to_string(),
        stage: progress.stage.as_str().to_owned(),
        status: progress.status.as_str().to_owned(),
        progress_basis_points: progress.progress_basis_points,
        dynamic_requested: config.dynamic_requested,
        dynamic_ran: progress.dynamic_ran,
        diagnostics: progress.diagnostics.clone(),
        updated_at: progress.updated_at,
    }
}

fn emit(config: &PipelineConfig, progress: &PipelineProgress) {
    if let Some(callback) = &config.progress_callback {
        callback(progress.clone());
    }
}

fn stage_context(stage: PipelineStage, detail: &str) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "stage".to_owned(),
        DiagnosticValue::String(stage.as_str().to_owned()),
    );
    context.insert(
        "detail".to_owned(),
        DiagnosticValue::String(detail.to_owned()),
    );
    context
}

fn progress_for(stage: PipelineStage) -> u16 {
    match stage {
        PipelineStage::Intake => 0,
        PipelineStage::Static => 1_000,
        PipelineStage::Dynamic => 4_500,
        PipelineStage::Signing => 6_000,
        PipelineStage::Fusion => 7_000,
        PipelineStage::Confidence => 8_200,
        PipelineStage::Surface => 9_200,
        PipelineStage::Completed => 10_000,
    }
}

fn fresh_pipeline_run_id() -> Result<String, Diagnostic> {
    let mut bytes = [0_u8; 12];
    if getrandom::fill(&mut bytes).is_err() {
        let fallback = Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_le_bytes();
        let length = bytes.len();
        bytes.copy_from_slice(&fallback[..length]);
    }
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut token, "{byte:02x}");
    }
    let run_id = format!("pipeline:{token}");
    RunId::new(run_id.clone()).map_err(|error| {
        let mut context = DiagnosticContext::new();
        context.insert("run_id".to_owned(), DiagnosticValue::String(run_id.clone()));
        context.insert(
            "error".to_owned(),
            DiagnosticValue::String(error.to_string()),
        );
        PIPELINE_STAGE_FAILED.instantiate(context)
    })?;
    Ok(run_id)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn intake_scratch_guard_removes_the_workspace_when_the_run_ends() {
        let output_root = std::env::temp_dir().join(format!(
            "apiaxess-pipeline-scratch-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let workspace = output_root.join("intake-run");
        fs::create_dir_all(workspace.join("unpacked")).expect("create scratch");
        fs::write(workspace.join("unpacked").join("smali"), b"x").expect("write scratch");
        assert!(workspace.exists());

        {
            let _guard =
                IntakeScratchGuard::new(output_root.clone(), workspace.display().to_string());
            // The scratch persists for the lifetime of the run (guard in scope).
            assert!(workspace.exists(), "scratch must survive during the run");
        }
        // Dropping the guard at run teardown removes the per-run scratch, so it
        // cannot accumulate across runs and eventually fill the disk.
        assert!(!workspace.exists(), "scratch must be gone after the run");
        assert!(
            output_root.exists(),
            "the shared output root is preserved for reuse"
        );
        fs::remove_dir_all(&output_root).expect("remove fixture root");
    }

    #[test]
    fn config_generates_valid_run_ids_and_explicit_static_mode() {
        let config = PipelineConfig::new("feeder.apk").expect("config");
        assert!(config.run_id.starts_with("pipeline:"));
        assert!(!config.dynamic_requested);
        assert_eq!(PipelineStage::Surface.as_str(), "surface");
    }

    #[test]
    fn dynamic_capture_flag_is_honored_and_opt_in() {
        let config = PipelineConfig::new("feeder.apk")
            .expect("config")
            .with_dynamic_capture(true);
        assert!(config.dynamic_requested);
    }

    #[test]
    fn drain_stops_on_quiet_after_min_and_at_hard_cap() {
        use std::time::Duration;
        // Still-noisy (traffic within the idle gap) before the cap: keep draining.
        assert!(!drain_should_stop(
            Duration::from_secs(5),
            Duration::from_secs(1)
        ));
        // Quiet for the idle gap, past the minimum settle: stop.
        assert!(drain_should_stop(
            Duration::from_secs(10),
            Duration::from_secs(6)
        ));
        // Quiet but still inside the minimum settle: keep going (guards a slow
        // app whose first call hasn't landed yet).
        assert!(!drain_should_stop(
            Duration::from_secs(2),
            Duration::from_secs(6)
        ));
        // Hard cap reached even though traffic is still flowing: stop.
        assert!(drain_should_stop(
            Duration::from_secs(30),
            Duration::from_millis(0)
        ));
    }

    #[test]
    fn host_party_flags_the_apps_own_backend_first_party() {
        // Package tokens (tamasha, playroom) matched against the host's labels flag
        // the app's own backend, even though the TLD differs from the package's.
        assert_eq!(
            classify_host_party("api.tamasha.live", "live.tamasha.playroom"),
            HostParty::FirstParty
        );
        assert_eq!(
            classify_host_party("cdn.playroom.io", "live.tamasha.playroom"),
            HostParty::FirstParty
        );
    }

    #[test]
    fn host_party_flags_known_sdks_third_party() {
        // Known SDK / analytics / payment hosts are third-party regardless of package.
        for host in [
            "graph.facebook.com",
            "app-measurement.com",
            "settings.crashlytics.com",
            "api.razorpay.com",
            "assets.juspay.in",
            "www.clarity.ms",
        ] {
            assert_eq!(
                classify_host_party(host, "live.tamasha.playroom"),
                HostParty::ThirdParty,
                "{host} should be third-party"
            );
        }
    }

    #[test]
    fn host_party_leaves_unrecognized_hosts_unclassified() {
        // Not a known SDK and no package affinity → left unclassified, not guessed.
        assert_eq!(
            classify_host_party("edge.some-cdn.io", "live.tamasha.playroom"),
            HostParty::Unclassified
        );
        // Generic package tokens (com, app) never manufacture first-party affinity.
        assert_eq!(
            classify_host_party("app.example-tracker.net", "com.app.thing"),
            HostParty::Unclassified
        );
    }

    #[test]
    fn manifest_package_name_reads_the_root_manifest_attribute() {
        assert_eq!(
            manifest_package_name(
                r#"<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.capture"><application /></manifest>"#,
            ),
            Some("com.example.capture".to_owned())
        );
        assert_eq!(
            manifest_package_name(
                "<manifest package='com.example.single-quote'><application /></manifest>"
            ),
            Some("com.example.single-quote".to_owned())
        );
    }

    #[test]
    fn manifest_package_name_does_not_infer_a_missing_package() {
        assert_eq!(
            manifest_package_name("<manifest><application /></manifest>"),
            None
        );
    }

    #[test]
    fn dynamic_stage_selects_the_bundled_tier_with_honest_capability_diagnostics() {
        // The engine's dynamic stage drives the tier→backend factory (this same
        // call) to select a backend. On a no-virtualization host it must choose
        // the zero-config bundled emulator and carry the honest software-mode
        // diagnostic — exactly what the pipeline extends into its output.
        use apiaxess_host_capabilities::{CapabilityAvailability, CapabilityObservation};
        let capabilities = apiaxess_host_capabilities::HostCapabilityReport {
            observations: vec![CapabilityObservation {
                capability_id: apiaxess_host_capabilities::CAPABILITY_AVD_ACCELERATION.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence: "no virtualization in this fixture".to_owned(),
                remediation: "enable host virtualization for the accelerated path".to_owned(),
                fallback_tier: None,
            }],
        };
        let selection = apiaxess_sandbox::DynamicBackendFactory::new(
            Arc::new(apiaxess_external_tools::ProcessToolRunner),
            capabilities,
        )
        .select();
        assert_eq!(
            selection.tier,
            apiaxess_sandbox::SandboxTier::BundledEmulator
        );
        assert_eq!(
            selection.acceleration,
            apiaxess_sandbox::AccelerationMode::Software
        );
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.software-mode-active"),
            "the pipeline must be able to surface the honest software-mode fallback"
        );
    }

    /// Profiles a persisted high-volume static document without rerunning APK
    /// intake. This is an opt-in probe for reproducing downstream regressions.
    #[test]
    #[ignore = "requires APIAXESS_PROFILE_SESSION_ARTIFACT pointing to a persisted session"]
    fn profile_downstream_pipeline_from_session_artifact() {
        let path = std::env::var("APIAXESS_PROFILE_SESSION_ARTIFACT")
            .expect("set APIAXESS_PROFILE_SESSION_ARTIFACT");
        let document = apiaxess_session::SessionDocument::from_json(
            &fs::read(path).expect("read session artifact"),
        )
        .expect("valid session artifact");
        let mut source = document.session.api_document().clone();
        // A completed session also stores the derived confidence and unified
        // projections. Remove those projections from this downstream probe so
        // it measures the static/fused source path rather than revalidating a
        // prior 27k-diagnostic surface before fusion.
        source.confidence = None;
        source.unified_surface = None;

        let started = Instant::now();
        let fused = apiaxess_fusion::fuse_document(
            &source,
            &FusionConfig::new("run:profile-fusion").expect("fusion config"),
            Utc::now(),
        )
        .expect("fusion");
        eprintln!(
            "[pipeline-profile] fusion total_ms={} endpoints={} protocol_operations={} loose_findings={} merged_facts={}",
            started.elapsed().as_millis(),
            fused.document.surface.endpoints.len(),
            fused.document.surface.protocol_operations.len(),
            fused.document.surface.loose_findings.len(),
            fused.merged_fact_count
        );

        let started = Instant::now();
        let confidence = apiaxess_confidence::recompute_document(
            &fused.document,
            &ConfidenceConfig::new("run:profile-confidence").expect("confidence config"),
            Utc::now(),
        )
        .expect("confidence");
        eprintln!(
            "[pipeline-profile] confidence total_ms={} facts={} handoffs={}",
            started.elapsed().as_millis(),
            confidence.summary.facts.len(),
            confidence.summary.handoffs.len()
        );

        let started = Instant::now();
        let surface = apiaxess_unified_surface::assemble_document(
            &confidence.document,
            &UnifiedSurfaceConfig::new("run:profile-surface").expect("surface config"),
            Utc::now(),
        )
        .expect("surface");
        eprintln!(
            "[pipeline-profile] surface total_ms={} endpoints={} diagnostics={}",
            started.elapsed().as_millis(),
            surface.unified.endpoints.len(),
            surface.unified.diagnostics.len()
        );
    }
}
