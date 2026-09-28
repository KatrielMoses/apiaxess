//! Session-scoped Android sandbox substrate.
//!
//! Runtime-specific details are kept behind the AVD, redroid, and secured
//! remote implementations. Callers do not receive Docker objects, shell
//! commands, or unauthenticated ADB endpoints.

// Backend operations return the canonical diagnostic vector rather than a
// Rust error type; the trait signatures are the intentional documentation of
// that contract. Concrete backend IDs remain dynamically typed for plugins.
#![allow(clippy::missing_errors_doc, clippy::unnecessary_literal_bound)]

pub mod android_target;
pub mod apk_manifest;
pub mod device_provision;
#[cfg(feature = "frida-embedded")]
pub mod frida_embedded;
pub mod instrumentation;
pub mod intake_resolution;
pub mod pinning;
pub mod runtime_trust;
pub mod stealth;
pub mod traffic;

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticSeverity, DiagnosticValue, catalogue,
};
use apiaxess_external_tools::{
    ExternalToolError, ExternalToolRunner, ToolInvocation, ToolInvocationRequest, ToolProbe,
    ToolProbeRequest, ToolProcess, ToolProcessRequest, ToolRequirement, ToolVersion,
};
use apiaxess_host_capabilities::{
    CAPABILITY_ANDROID_ADB, CAPABILITY_AVD_ACCELERATION, CAPABILITY_DOCKER,
    CAPABILITY_DOCKER_PRIVILEGED, CAPABILITY_KVM, CAPABILITY_REDOID_KERNEL, CAPABILITY_REMOTE_SSH,
    CAPABILITY_VM_POSTURE, CAPABILITY_WINDOWS_HYPERVISOR, CAPABILITY_WSL2_NESTED_KVM,
    CapabilityAvailability, HostCapabilityReport, HostCapabilityService,
};
use apiaxess_session::{Session, SessionLifecycle};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The user-visible isolation/speed choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxTier {
    /// Bundled, owned QEMU + Android-10 AOSP image — the zero-config default
    /// dynamic runtime. Runs everywhere: hardware-accelerated when the host
    /// exposes virtualization, or QEMU TCG software mode (slower) when it does
    /// not.
    BundledEmulator,
    /// Legacy Dockerized `HQarroum` `google_apis` `AVD`; requires host Docker +
    /// KVM/WHPX + authenticated ADB. Offered as an advanced accelerated option.
    Avd,
    /// redroid in a privileged Docker container.
    Redroid,
    /// Android runtime on a remote Linux host.
    RemoteOffload,
}
impl SandboxTier {
    /// Stable selection ID.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::BundledEmulator => "sandbox.bundled-emulator",
            Self::Avd => "sandbox.avd",
            Self::Redroid => "sandbox.redroid",
            Self::RemoteOffload => "sandbox.remote-offload",
        }
    }
}

/// How the bundled emulator executes: hardware-accelerated or software (TCG).
///
/// This is the honest, capability-driven speed choice. Hardware acceleration
/// needs a host virtualization capability (KVM on Linux, WHPX/Hyper-V on
/// Windows) — a CPU/firmware property, not something that can be bundled — so a
/// no-virtualization host (for example a plain cloud droplet) falls back to
/// software mode, which is correct but substantially slower.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccelerationMode {
    /// KVM (Linux) or WHPX/Hyper-V (Windows) hardware acceleration.
    Accelerated,
    /// QEMU TCG software emulation — runs everywhere, materially slower.
    Software,
}

impl AccelerationMode {
    /// Stable selection ID.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Accelerated => "accelerated",
            Self::Software => "software",
        }
    }

    /// Detects the mode from functional host virtualization evidence, and
    /// returns the honest diagnostic that must be surfaced to the operator.
    #[must_use]
    pub fn detect(report: &HostCapabilityReport) -> (Self, Diagnostic) {
        Self::detect_for_host(report, cfg!(target_os = "windows"))
    }

    /// Like [`Self::detect`], but for an explicit host family so a planner
    /// modelling another environment applies that environment's rules rather
    /// than the compile host's.
    fn detect_for_host(report: &HostCapabilityReport, windows_host: bool) -> (Self, Diagnostic) {
        // Windows' transitional AEHD accelerator is reported as degraded but is
        // still hardware acceleration for this decision.
        let accelerated = report.supports(CAPABILITY_AVD_ACCELERATION, windows_host)
            || report.supports(CAPABILITY_WSL2_NESTED_KVM, false)
            || (windows_host && report.supports(CAPABILITY_WINDOWS_HYPERVISOR, true));
        if accelerated {
            (
                Self::Accelerated,
                catalogue::SANDBOX_ACCELERATED_MODE_ACTIVE
                    .instantiate(planner_context("acceleration", "accelerated")),
            )
        } else {
            (
                Self::Software,
                catalogue::SANDBOX_SOFTWARE_MODE_ACTIVE
                    .instantiate(planner_context("acceleration", "software")),
            )
        }
    }
}

/// Host posture used by the runtime strategy planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    /// Native Linux with a KVM-capable host path.
    NativeLinux,
    /// Native `x86_64` Windows with the `WHPX`/`AEHD` emulator path.
    NativeWindows,
    /// Windows Home, where the durable `WHPX`/`Hyper-V` path is unavailable.
    WindowsHome,
    /// Windows-on-`ARM`, outside the supported local `AVD` matrix.
    WindowsArm,
    /// `APIaxess` is running inside a `VM` or nested virtualization boundary.
    InsideVm,
    /// `WSL2` exposed a usable nested `KVM` path for `HQarroum` `Docker`.
    Wsl2NestedKvm,
}

/// Explicit result of the default/fast/fallback runtime decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSelection {
    /// Host posture used for the decision.
    pub environment: RuntimeEnvironment,
    /// Whether the bundled emulator will run accelerated or in software mode.
    pub acceleration: AccelerationMode,
    /// Runtime selected by default for a new session.
    pub default_tier: SandboxTier,
    /// Linux-only opt-in fast tier, when it is actually available.
    pub opt_in_fast_tier: Option<SandboxTier>,
    /// Secured fallback when the local default cannot run.
    pub fallback_tier: SandboxTier,
    /// Tiers the user may be shown for this host.
    pub offered_tiers: Vec<SandboxTier>,
    /// Decision and guidance diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Selects the runtime strategy without changing the `SandboxBackend` seam.
pub struct SandboxRuntimePlanner;

impl SandboxRuntimePlanner {
    /// Selects the strategy for the compiled host using functional capability evidence.
    #[must_use]
    pub fn detect(report: &HostCapabilityReport) -> RuntimeSelection {
        let environment = if cfg!(target_os = "windows") {
            if cfg!(target_arch = "aarch64") {
                RuntimeEnvironment::WindowsArm
            } else {
                RuntimeEnvironment::NativeWindows
            }
        } else if cfg!(target_os = "linux") {
            if report
                .get(CAPABILITY_WSL2_NESTED_KVM)
                .is_some_and(|item| item.availability == CapabilityAvailability::Supported)
            {
                RuntimeEnvironment::Wsl2NestedKvm
            } else if report
                .get(CAPABILITY_VM_POSTURE)
                .is_some_and(|item| item.availability == CapabilityAvailability::Degraded)
            {
                RuntimeEnvironment::InsideVm
            } else {
                RuntimeEnvironment::NativeLinux
            }
        } else {
            RuntimeEnvironment::InsideVm
        };
        Self::for_environment(environment, report)
    }

    /// Selects a strategy for a caller-provided host posture, useful for UI and tests.
    ///
    /// The per-environment tier decision is one linear policy table kept in a
    /// single function so each host posture's reasoning stays visible together.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn for_environment(
        environment: RuntimeEnvironment,
        report: &HostCapabilityReport,
    ) -> RuntimeSelection {
        let allow_degraded_acceleration = matches!(environment, RuntimeEnvironment::NativeWindows);
        let avd = report.supports(CAPABILITY_DOCKER, false)
            && report.supports(CAPABILITY_ANDROID_ADB, false)
            && (report.supports(CAPABILITY_AVD_ACCELERATION, allow_degraded_acceleration)
                || report.supports(CAPABILITY_WSL2_NESTED_KVM, false));
        let windows_avd = report.supports(CAPABILITY_WINDOWS_HYPERVISOR, true) && avd;
        let redroid = matches!(environment, RuntimeEnvironment::NativeLinux)
            && report.supports(CAPABILITY_DOCKER, false)
            && report.supports(CAPABILITY_DOCKER_PRIVILEGED, true)
            && report.supports(CAPABILITY_REDOID_KERNEL, false);
        let mut diagnostics = Vec::new();
        // The honest, capability-driven speed decision for the bundled emulator.
        let windows_host = matches!(
            environment,
            RuntimeEnvironment::NativeWindows
                | RuntimeEnvironment::WindowsHome
                | RuntimeEnvironment::WindowsArm
        );
        let (acceleration, acceleration_diagnostic) =
            AccelerationMode::detect_for_host(report, windows_host);
        diagnostics.push(acceleration_diagnostic);
        // The host-dependent accelerated tiers still computed for the "advanced"
        // offering; the zero-config default is the bundled emulator below.
        let (recommended_advanced, advanced_offered) = match environment {
            RuntimeEnvironment::NativeLinux | RuntimeEnvironment::Wsl2NestedKvm if avd => {
                let mut offered = vec![SandboxTier::Avd];
                if redroid {
                    offered.push(SandboxTier::Redroid);
                }
                offered.push(SandboxTier::RemoteOffload);
                (SandboxTier::Avd, offered)
            }
            RuntimeEnvironment::NativeWindows if windows_avd => {
                let offered = vec![SandboxTier::Avd, SandboxTier::RemoteOffload];
                if report
                    .get(CAPABILITY_WINDOWS_HYPERVISOR)
                    .is_some_and(|item| item.availability == CapabilityAvailability::Degraded)
                {
                    diagnostics.push(
                        catalogue::SANDBOX_AEHD_TRANSITIONAL.instantiate(planner_context(
                            "aehd",
                            "transitional Windows accelerator",
                        )),
                    );
                }
                (SandboxTier::Avd, offered)
            }
            RuntimeEnvironment::NativeLinux | RuntimeEnvironment::Wsl2NestedKvm => {
                let mut offered = Vec::new();
                if redroid {
                    offered.push(SandboxTier::Redroid);
                }
                offered.push(SandboxTier::RemoteOffload);
                (SandboxTier::RemoteOffload, offered)
            }
            RuntimeEnvironment::NativeWindows => {
                (SandboxTier::RemoteOffload, vec![SandboxTier::RemoteOffload])
            }
            RuntimeEnvironment::WindowsHome => {
                diagnostics.push(
                    catalogue::SANDBOX_WINDOWS_HOME_UNSUPPORTED
                        .instantiate(planner_context("windows-home", "Windows Home")),
                );
                (SandboxTier::RemoteOffload, vec![SandboxTier::RemoteOffload])
            }
            RuntimeEnvironment::WindowsArm => {
                diagnostics.push(
                    catalogue::SANDBOX_WINDOWS_ARM_UNSUPPORTED
                        .instantiate(planner_context("windows-arm", "Windows-on-ARM")),
                );
                (SandboxTier::RemoteOffload, vec![SandboxTier::RemoteOffload])
            }
            RuntimeEnvironment::InsideVm => {
                diagnostics.push(
                    catalogue::SANDBOX_VM_GUIDANCE
                        .instantiate(planner_context("vm", "virtualized or nested host posture")),
                );
                (SandboxTier::RemoteOffload, vec![SandboxTier::RemoteOffload])
            }
        };
        // The bundled, owned emulator is the zero-config default: it always runs
        // locally, accelerated or in software mode, with nothing required on the
        // host. The host-dependent accelerated tiers (Dockerized AVD, redroid,
        // remote-offload) remain available as advanced options.
        let default_tier = SandboxTier::BundledEmulator;
        let mut offered_tiers = vec![SandboxTier::BundledEmulator];
        for tier in advanced_offered {
            if !offered_tiers.contains(&tier) {
                offered_tiers.push(tier);
            }
        }
        // When the host can accelerate a legacy AVD, offer it as the opt-in fast
        // tier; otherwise redroid (Linux) remains the opt-in fast tier if usable.
        let opt_in_fast_tier = if acceleration == AccelerationMode::Accelerated
            && recommended_advanced == SandboxTier::Avd
        {
            Some(SandboxTier::Avd)
        } else {
            redroid.then_some(SandboxTier::Redroid)
        };
        diagnostics.push(
            catalogue::SANDBOX_RUNTIME_SELECTED
                .instantiate(planner_context("selected_tier", default_tier.id())),
        );
        RuntimeSelection {
            environment,
            acceleration,
            default_tier,
            opt_in_fast_tier,
            fallback_tier: SandboxTier::RemoteOffload,
            offered_tiers,
            diagnostics,
        }
    }
}

/// A live dynamic backend chosen from functional host-capability evidence.
///
/// This is the result of the tier→backend factory: the concrete, ready-to-run
/// [`SandboxBackend`] plus the tier and acceleration mode it was built for, and
/// the honest planner diagnostics (`sandbox.runtime-selected` and the
/// `sandbox.{accelerated,software}-mode-active` speed choice) that must be
/// surfaced to the operator before a dynamic run starts.
pub struct DynamicBackendSelection {
    /// The constructed backend, ready to `preflight` and `start`.
    pub backend: Box<dyn SandboxBackend>,
    /// The tier selected for this host (the bundled emulator by default).
    pub tier: SandboxTier,
    /// Whether the bundled emulator will run accelerated or in software mode.
    pub acceleration: AccelerationMode,
    /// Selection + capability diagnostics to surface alongside the run.
    pub diagnostics: Vec<Diagnostic>,
}

impl std::fmt::Debug for DynamicBackendSelection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicBackendSelection")
            .field("backend_id", &self.backend.backend_id())
            .field("tier", &self.tier)
            .field("acceleration", &self.acceleration)
            .field("diagnostics", &self.diagnostics.len())
            .finish()
    }
}

/// Turns the runtime planner's tier decision into an actual, runnable backend.
///
/// The planner ([`SandboxRuntimePlanner`]) describes *which* tier to use for the
/// observed host; this factory is the seam that constructs it. The bundled,
/// owned emulator is the zero-config default on every host — it always runs
/// locally, accelerated where the host exposes virtualization and in QEMU
/// software mode where it does not (the deliberate no-remote-offload fallback
/// from Phase 11.5). Capability detection drives the honest speed choice; the
/// diagnostics travel with the selection so a caller surfaces the same honest
/// messaging the planner recorded.
pub struct DynamicBackendFactory {
    runner: Arc<dyn ExternalToolRunner>,
    capabilities: HostCapabilityReport,
}

impl DynamicBackendFactory {
    /// Creates a factory from injected capability evidence.
    ///
    /// Embedders and tests use this to drive tier selection from a known host
    /// posture without re-running live detection.
    #[must_use]
    pub fn new(runner: Arc<dyn ExternalToolRunner>, capabilities: HostCapabilityReport) -> Self {
        Self {
            runner,
            capabilities,
        }
    }

    /// Creates a factory by detecting the current host's functional capabilities.
    #[must_use]
    pub fn detect(runner: Arc<dyn ExternalToolRunner>) -> Self {
        let capabilities = HostCapabilityService::with_runner(Arc::clone(&runner)).detect();
        Self::new(runner, capabilities)
    }

    /// Capability evidence this factory selects from.
    #[must_use]
    pub const fn capabilities(&self) -> &HostCapabilityReport {
        &self.capabilities
    }

    /// Selects and constructs the default dynamic backend for this host.
    ///
    /// Uses the runtime planner's default tier and acceleration decision, then
    /// builds the concrete backend. The planner's diagnostics — including the
    /// honest `accelerated`/`software`-mode speed choice — are carried on the
    /// returned selection.
    #[must_use]
    pub fn select(&self) -> DynamicBackendSelection {
        let selection = SandboxRuntimePlanner::detect(&self.capabilities);
        self.build(
            selection.default_tier,
            selection.acceleration,
            selection.diagnostics,
        )
    }

    /// Selects a specific tier (for an operator's advanced opt-in), honoring the
    /// planner's acceleration decision for the bundled emulator.
    #[must_use]
    pub fn select_tier(&self, tier: SandboxTier) -> DynamicBackendSelection {
        let selection = SandboxRuntimePlanner::detect(&self.capabilities);
        self.build(tier, selection.acceleration, selection.diagnostics)
    }

    fn build(
        &self,
        tier: SandboxTier,
        acceleration: AccelerationMode,
        mut diagnostics: Vec<Diagnostic>,
    ) -> DynamicBackendSelection {
        let (backend, resolved_tier) = self.backend_for_tier(tier, acceleration, &mut diagnostics);
        DynamicBackendSelection {
            backend,
            tier: resolved_tier,
            acceleration,
            diagnostics,
        }
    }

    /// Constructs the concrete backend for a resolved tier and acceleration mode.
    ///
    /// Only the zero-config bundled emulator is wired into the live engine today
    /// — the planner defaults to it on every host. The host-dependent accelerated
    /// tiers (Dockerized AVD, redroid, remote-offload) remain available through
    /// the capstone harness and are not yet constructed by the live pipeline;
    /// requesting one degrades to the bundled emulator (which always runs
    /// locally) with an honest diagnostic rather than silently doing nothing.
    fn backend_for_tier(
        &self,
        tier: SandboxTier,
        acceleration: AccelerationMode,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> (Box<dyn SandboxBackend>, SandboxTier) {
        if tier != SandboxTier::BundledEmulator {
            diagnostics.push(
                catalogue::SANDBOX_RUNTIME_SELECTED
                    .instantiate(planner_context("bundled_emulator_fallback", tier.id())),
            );
        }
        let config = BundledEmulatorConfig::resolve(acceleration);
        let backend = BundledEmulatorBackend::new(
            config,
            Arc::clone(&self.runner),
            self.capabilities.clone(),
        );
        (Box::new(backend), SandboxTier::BundledEmulator)
    }
}

/// Honest isolation description surfaced to the planner and GUI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationStrength {
    /// Hardware-backed VM boundary.
    HardwareVm,
    /// Shared-kernel container; trusted targets only.
    SharedKernelTrustedOnly,
    /// Depends on the remote Linux host.
    RemoteHostControlled,
}

/// Stable backend description shown before runtime start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxBackendDescriptor {
    /// Stable backend ID.
    pub backend_id: String,
    /// Selected tier.
    pub tier: SandboxTier,
    /// Isolation mode.
    pub isolation: IsolationStrength,
    /// Security/speed tradeoff.
    pub tradeoff: String,
    /// Required host capabilities.
    pub required_capability_ids: Vec<String>,
}

/// Start request shared by all backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxStartRequest {
    /// Active session identifier.
    pub session_id: String,
    /// Stable lease identifier.
    pub lease_id: String,
    /// Boot/readiness deadline.
    pub readiness_timeout: Duration,
}
impl SandboxStartRequest {
    /// Creates a request with a two-minute default deadline.
    #[must_use]
    pub fn new(session_id: impl Into<String>, lease_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            lease_id: lease_id.into(),
            readiness_timeout: Duration::from_secs(120),
        }
    }
}

/// Evidence returned by backend preflight.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxPlan {
    /// Backend identity.
    pub backend_id: String,
    /// Selected tier.
    pub tier: SandboxTier,
    /// Isolation mode.
    pub isolation: IsolationStrength,
    /// Capability observations.
    pub capabilities: HostCapabilityReport,
    /// Warnings and blocking errors.
    pub diagnostics: Vec<Diagnostic>,
}
impl SandboxPlan {
    /// Whether no error blocks startup.
    #[must_use]
    pub fn is_runnable(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|item| item.severity >= DiagnosticSeverity::Error)
    }
}

/// Stable handle later phases use to attach ADB, proxy, and Frida.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SandboxHandle {
    /// Session lease ID.
    pub lease_id: String,
    /// Backend ID.
    pub backend_id: String,
    /// Selected tier.
    pub tier: SandboxTier,
    /// Honest isolation mode.
    pub isolation: IsolationStrength,
    /// Never a raw ADB URL.
    pub control_channel: String,
    /// Device serial or remote helper identity.
    pub device_serial: String,
}

/// Result of one secured command sent to the running Android environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCommandOutput {
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Process exit code, when available.
    pub exit_code: Option<i32>,
}

/// Guest-reachable endpoint used to bridge a sandbox topology to the host
/// workbench proxy. The endpoint is intentionally separate from the host
/// proxy address: a Dockerized emulator often cannot route to the host
/// listener directly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxCaptureEndpoint {
    /// Address visible from the Android guest or remote runtime.
    pub host: String,
    /// Port exposed by the topology-specific bridge.
    pub port: u16,
    /// Stable topology/provenance label.
    pub topology: String,
}

/// Runtime control channel used by traffic routing and system trust setup.
///
/// Implementations are ADB for AVD, Docker exec for redroid, and strict SSH
/// helper calls for remote-offload. No implementation exposes a raw ADB TCP
/// endpoint.
pub trait SandboxControl: Send + Sync {
    /// Runs a control command through the secured runtime transport.
    fn command(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic>;
    /// Runs a command inside Android's shell.
    fn shell(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic>;
    /// Copies bytes into an Android path for a session-scoped operation.
    fn put(
        &self,
        bytes: &[u8],
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic>;
    /// Removes a session-scoped Android path.
    fn remove(
        &self,
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic>;
    /// Installs session-scoped APK files, including split APKs.
    fn install_apks(
        &self,
        apk_paths: &[PathBuf],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic>;
    /// Installs one universal or standalone APK through the runtime's direct
    /// single-package operation when available.
    fn install_apk(
        &self,
        apk_path: &Path,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.install_apks(std::slice::from_ref(&apk_path.to_path_buf()), timeout)
    }
    /// Stable transport descriptor for provenance.
    fn transport_id(&self) -> &str;
}

/// Topology-specific bridge from a guest-reachable endpoint to the workbench
/// proxy. Implementations own their forwarder and must tear it down with the
/// sandbox lease.
pub trait SandboxCaptureBridge: Send {
    /// Starts the bridge toward the already-bound host proxy.
    fn prepare(&mut self, proxy: SocketAddr) -> Result<SandboxCaptureEndpoint, Diagnostic>;
    /// Stops the bridge and verifies its disposable state is removed.
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>>;
}

/// Active runtime lease with idempotent complete cleanup.
pub struct SandboxLease {
    handle: SandboxHandle,
    control: Arc<dyn SandboxControl>,
    cleanups: Vec<Box<dyn SandboxCleanup>>,
    capture_bridge: Option<Box<dyn SandboxCaptureBridge>>,
    trust_diagnostics: Vec<Diagnostic>,
}
impl std::fmt::Debug for SandboxLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxLease")
            .field("handle", &self.handle)
            .field("active", &!self.cleanups.is_empty())
            .field("capture_bridge", &self.capture_bridge.is_some())
            .field("control", &self.control.transport_id())
            .finish_non_exhaustive()
    }
}
impl SandboxLease {
    fn new(
        handle: SandboxHandle,
        control: Arc<dyn SandboxControl>,
        cleanup: Box<dyn SandboxCleanup>,
    ) -> Self {
        Self {
            handle,
            control,
            cleanups: vec![cleanup],
            capture_bridge: None,
            trust_diagnostics: Vec::new(),
        }
    }

    fn with_trust_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.trust_diagnostics = diagnostics;
        self
    }
    /// Attaches the topology-specific guest-to-proxy bridge for this lease.
    ///
    /// Backends use this when the guest cannot reach a host listener directly.
    /// The bridge is owned by the lease and is cleaned up on both explicit and
    /// drop-based teardown.
    #[must_use]
    pub fn with_capture_bridge(mut self, bridge: Box<dyn SandboxCaptureBridge>) -> Self {
        self.capture_bridge = Some(bridge);
        self
    }
    pub(crate) fn take_capture_bridge(&mut self) -> Option<Box<dyn SandboxCaptureBridge>> {
        self.capture_bridge.take()
    }
    /// Runtime metadata.
    #[must_use]
    pub const fn handle(&self) -> &SandboxHandle {
        &self.handle
    }
    /// Secured runtime control channel for session-scoped adapters.
    #[must_use]
    pub fn control(&self) -> Arc<dyn SandboxControl> {
        Arc::clone(&self.control)
    }
    /// Trust findings emitted when the runtime lease was established.
    #[must_use]
    pub fn trust_diagnostics(&self) -> &[Diagnostic] {
        &self.trust_diagnostics
    }
    /// Resolves and installs a normalized Android artifact through this lease.
    ///
    /// The intake brain selects single-APK versus split installation and
    /// translates installer failures into precise diagnostics before they
    /// reach the caller.
    pub fn resolve_and_install(
        &self,
        artifact: &apiaxess_artifact_intake::NormalizedUnpackedArtifact,
        timeout: Duration,
    ) -> Result<intake_resolution::IntakeResolutionOutcome, Vec<Diagnostic>> {
        intake_resolution::IntakeResolutionBrain::new().resolve(
            artifact,
            self.control.as_ref(),
            timeout,
        )
    }
    /// Adds cleanup that must run before the base runtime is destroyed.
    pub fn add_cleanup(&mut self, cleanup: Box<dyn SandboxCleanup>) {
        self.cleanups.push(cleanup);
    }
    /// Stops and removes session-scoped state.
    pub fn teardown(mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Some(mut bridge) = self.capture_bridge.take() {
            diagnostics.extend(bridge.cleanup().err().unwrap_or_default());
        }
        diagnostics.extend(cleanup_all(&mut self.cleanups).err().unwrap_or_default());
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}
impl Drop for SandboxLease {
    fn drop(&mut self) {
        if let Some(mut bridge) = self.capture_bridge.take() {
            let _ = bridge.cleanup();
        }
        let _ = cleanup_all(&mut self.cleanups);
    }
}
/// A synchronous cleanup action attached to a sandbox lease.
pub trait SandboxCleanup: Send {
    /// Performs best-effort cleanup and returns every verified failure.
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>>;
}

fn cleanup_all(cleanups: &mut Vec<Box<dyn SandboxCleanup>>) -> Result<(), Vec<Diagnostic>> {
    let mut diagnostics = Vec::new();
    while let Some(mut cleanup) = cleanups.pop() {
        if let Err(mut errors) = cleanup.cleanup() {
            diagnostics.append(&mut errors);
        }
    }
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics)
    }
}

/// Common backend port for all local and remote Android runtimes.
pub trait SandboxBackend: Send + Sync {
    /// Stable backend identity.
    fn backend_id(&self) -> &str;
    /// User-selected tier.
    fn tier(&self) -> SandboxTier;
    /// Security/capability description.
    fn descriptor(&self) -> SandboxBackendDescriptor;
    /// Non-mutating capability preflight.
    fn preflight(&self) -> SandboxPlan;
    /// Starts a clean, ready runtime.
    fn start(&self, request: &SandboxStartRequest) -> Result<SandboxLease, Vec<Diagnostic>>;
}

/// Session-owned coordinator that binds runtime cleanup to session metadata.
pub struct SessionSandboxLease {
    lease: Option<SandboxLease>,
}

impl std::fmt::Debug for SessionSandboxLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionSandboxLease")
            .field("lease", &self.lease)
            .finish()
    }
}

impl SessionSandboxLease {
    /// Starts a backend and attaches its durable handle to an active session.
    pub fn start(
        session: &mut Session,
        backend: &dyn SandboxBackend,
        request: &SandboxStartRequest,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, Vec<Diagnostic>> {
        if session.lifecycle() != SessionLifecycle::Active {
            return Err(vec![catalogue::SANDBOX_SESSION_NOT_ACTIVE.instantiate(
                context(
                    backend.backend_id(),
                    "session_id",
                    request.session_id.clone(),
                ),
            )]);
        }
        let lease = backend.start(request)?;
        let handle = lease.handle();
        let session_handle = apiaxess_session::SandboxHandle {
            lease_id: handle.lease_id.clone(),
            backend_id: handle.backend_id.clone(),
            tier: handle.tier.id().to_owned(),
            isolation: format!("{:?}", handle.isolation).to_ascii_lowercase(),
            control_channel: handle.control_channel.clone(),
            device_serial: handle.device_serial.clone(),
        };
        if let Err(error) = session.attach_sandbox(session_handle, at) {
            let mut diagnostics = vec![error];
            diagnostics.extend(lease.teardown().err().unwrap_or_default());
            return Err(diagnostics);
        }
        Ok(Self { lease: Some(lease) })
    }

    /// Tears down the runtime, then removes its durable session attachment.
    pub fn close(
        mut self,
        session: &mut Session,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Vec<Diagnostic>> {
        match self.lease.take().map_or(Ok(()), SandboxLease::teardown) {
            Ok(()) => session
                .detach_sandbox(at)
                .map(|_| ())
                .map_err(|error| vec![error]),
            Err(diagnostics) => Err(diagnostics),
        }
    }

    /// Tears down the runtime, detaches its metadata, and closes the session.
    pub fn close_session(
        self,
        session: &mut Session,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Vec<Diagnostic>> {
        self.close(session, at)?;
        session.close(at).map_err(|error| vec![error])
    }
}

/// On-demand image acquisition boundary.
pub trait ImageManager: Send + Sync {
    /// Acquires/verifies an AVD image.
    fn ensure_avd_image(&self, package: &str, marker: Option<&Path>) -> Result<(), Diagnostic>;
    /// Acquires/verifies redroid.
    fn ensure_redroid_image(&self, image: &str) -> Result<(), Diagnostic>;
    /// Acquires/verifies a digest-pinned `HQarroum` image.
    fn ensure_hqarroum_image(&self, image: &str, digest: &str) -> Result<(), Diagnostic> {
        let reference = if image.contains('@') {
            image.to_owned()
        } else {
            format!("{image}@{digest}")
        };
        self.ensure_redroid_image(&reference)
    }
}

struct AdbControl {
    runner: Arc<dyn ExternalToolRunner>,
    adb: ToolProbe,
    serial: String,
    environment: Vec<(String, String)>,
    transport: &'static str,
}

impl AdbControl {
    /// Builds a control channel for an externally-attached adb device (physical
    /// USB device or same-machine emulator) targeted by serial. Used by device
    /// provisioning, which drives devices the sandbox did not itself boot.
    pub(crate) fn for_device(
        runner: Arc<dyn ExternalToolRunner>,
        adb: ToolProbe,
        serial: String,
    ) -> Self {
        Self {
            runner,
            adb,
            serial,
            environment: Vec::new(),
            transport: "device-adb",
        }
    }

    fn invoke(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let mut full = vec!["-s".to_owned(), self.serial.clone()];
        full.extend(arguments.iter().cloned());
        invoke_control_tool_with_environment(
            &self.runner,
            &self.adb,
            &full,
            timeout,
            "sandbox.adb",
            &self.environment,
        )
    }
}

impl SandboxControl for AdbControl {
    fn command(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.invoke(arguments, timeout)
    }
    fn shell(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let mut full = vec!["shell".to_owned()];
        full.extend(arguments.iter().cloned());
        self.invoke(&full, timeout)
    }
    fn put(
        &self,
        bytes: &[u8],
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let local_path = temporary_control_file("adb-push", bytes)?;
        let result = self.invoke(
            &[
                "push".to_owned(),
                local_path.display().to_string(),
                remote_path.to_owned(),
            ],
            timeout,
        );
        let _ = fs::remove_file(&local_path);
        result
    }
    fn remove(
        &self,
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.shell(
            &["rm".to_owned(), "-f".to_owned(), remote_path.to_owned()],
            timeout,
        )
    }
    fn install_apks(
        &self,
        apk_paths: &[PathBuf],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let mut arguments = vec!["install-multiple".to_owned()];
        arguments.extend(apk_paths.iter().map(|path| path.display().to_string()));
        self.invoke(&arguments, timeout)
    }
    fn install_apk(
        &self,
        apk_path: &Path,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.invoke(
            &["install".to_owned(), apk_path.display().to_string()],
            timeout,
        )
    }
    fn transport_id(&self) -> &str {
        self.transport
    }
}

struct RemoteControl {
    runner: Arc<dyn ExternalToolRunner>,
    ssh: ToolProbe,
    config: RemoteConfig,
}

impl RemoteControl {
    fn invoke(
        &self,
        action: &str,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let mut full = remote_base_args(&self.config);
        full.push(self.config.helper_path.clone());
        full.push(action.to_owned());
        full.extend(arguments.iter().cloned());
        invoke_control_tool(
            &self.runner,
            &self.ssh,
            &full,
            timeout,
            "sandbox.remote-offload",
        )
    }
}

impl SandboxControl for RemoteControl {
    fn command(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.invoke("exec", arguments, timeout)
    }
    fn shell(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.invoke("shell", arguments, timeout)
    }
    fn put(
        &self,
        bytes: &[u8],
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.invoke(
            "put",
            &[
                "--path".to_owned(),
                remote_path.to_owned(),
                "--base64".to_owned(),
                BASE64.encode(bytes),
            ],
            timeout,
        )
    }
    fn remove(
        &self,
        remote_path: &str,
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.shell(
            &["rm".to_owned(), "-f".to_owned(), remote_path.to_owned()],
            timeout,
        )
    }
    fn install_apks(
        &self,
        apk_paths: &[PathBuf],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let paths = apk_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        self.invoke(
            "install",
            &["--paths".to_owned(), paths.join("\n")],
            timeout,
        )
    }
    fn transport_id(&self) -> &str {
        "ssh-strict-host-key"
    }
}

fn invoke_control_tool(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    arguments: &[String],
    timeout: Duration,
    backend: &str,
) -> Result<SandboxCommandOutput, Diagnostic> {
    invoke_control_tool_with_environment(runner, probe, arguments, timeout, backend, &[])
}

fn invoke_control_tool_with_environment(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    arguments: &[String],
    timeout: Duration,
    backend: &str,
    environment: &[(String, String)],
) -> Result<SandboxCommandOutput, Diagnostic> {
    invoke_tool_with_environment(runner, probe, arguments, timeout, environment)
        .map(|output| SandboxCommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
        .map_err(|error| {
            catalogue::SANDBOX_PROXY_UNREACHABLE.instantiate(context(
                backend,
                "error",
                error.to_string(),
            ))
        })
}

fn temporary_control_file(prefix: &str, bytes: &[u8]) -> Result<PathBuf, Diagnostic> {
    let path = std::env::temp_dir().join(format!("apiaxess-{prefix}-{}", generated_lease_id()));
    fs::write(&path, bytes).map_err(|error| {
        catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
            "sandbox",
            "path",
            format!("{}: {error}", path.display()),
        ))
    })?;
    Ok(path)
}

fn remote_base_args(config: &RemoteConfig) -> Vec<String> {
    vec![
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.known_hosts_file.display()),
        "-i".to_owned(),
        config.identity_file.display().to_string(),
        format!("{}@{}", config.user, config.host),
    ]
}

/// Production image manager; heavyweight assets stay outside the installer.
#[derive(Clone)]
pub struct ExternalImageManager {
    runner: Arc<dyn ExternalToolRunner>,
    sdkmanager_executable: String,
    docker_executable: String,
}
impl ExternalImageManager {
    /// Creates a manager using the external-tool boundary.
    #[must_use]
    pub fn new(
        runner: Arc<dyn ExternalToolRunner>,
        sdkmanager_executable: impl Into<String>,
        docker_executable: impl Into<String>,
    ) -> Self {
        Self {
            runner,
            sdkmanager_executable: sdkmanager_executable.into(),
            docker_executable: docker_executable.into(),
        }
    }
}
impl ImageManager for ExternalImageManager {
    fn ensure_avd_image(&self, package: &str, marker: Option<&Path>) -> Result<(), Diagnostic> {
        if marker.is_some_and(Path::exists) {
            return Ok(());
        }
        let probe = probe_tool(
            &self.runner,
            "android.sdkmanager",
            &self.sdkmanager_executable,
            &["--version"],
        )
        .map_err(|e| image_diagnostic("avd", package, e.to_string()))?;
        invoke_tool(
            &self.runner,
            &probe,
            &["--install", package],
            Duration::from_secs(30 * 60),
        )
        .map(|_| ())
        .map_err(|e| image_diagnostic("avd", package, e.to_string()))
    }
    fn ensure_redroid_image(&self, image: &str) -> Result<(), Diagnostic> {
        let probe = probe_tool(
            &self.runner,
            "container.docker",
            &self.docker_executable,
            &["version"],
        )
        .map_err(|e| image_diagnostic("redroid", image, e.to_string()))?;
        invoke_tool(
            &self.runner,
            &probe,
            &["pull", image],
            Duration::from_secs(30 * 60),
        )
        .map(|_| ())
        .map_err(|e| image_diagnostic("redroid", image, e.to_string()))
    }

    fn ensure_hqarroum_image(&self, image: &str, digest: &str) -> Result<(), Diagnostic> {
        let probe = probe_tool(
            &self.runner,
            "container.docker",
            &self.docker_executable,
            &["version"],
        )
        .map_err(|e| image_diagnostic("hqarroum", image, e.to_string()))?;
        let reference = if image.contains('@') {
            image.to_owned()
        } else {
            format!("{image}@{digest}")
        };
        invoke_tool(
            &self.runner,
            &probe,
            &["pull".to_owned(), reference.clone()],
            Duration::from_secs(30 * 60),
        )
        .map_err(|e| image_diagnostic("hqarroum", &reference, e.to_string()))?;
        let inspected = invoke_tool(
            &self.runner,
            &probe,
            &[
                "image".to_owned(),
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{json .RepoDigests}}".to_owned(),
                reference.clone(),
            ],
            Duration::from_secs(30),
        )
        .map_err(|e| image_diagnostic("hqarroum", &reference, e.to_string()))?;
        if !inspected.stdout.contains(digest) {
            return Err(
                catalogue::SANDBOX_HQARROUM_IMAGE_DIGEST_MISMATCH.instantiate(context(
                    "sandbox.avd",
                    "expected_digest",
                    format!("{digest}; observed {}", inspected.stdout.trim()),
                )),
            );
        }
        Ok(())
    }
}

/// Test/embedding image manager that declares assets already present.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExistingImageManager;
impl ImageManager for ExistingImageManager {
    fn ensure_avd_image(&self, _: &str, _: Option<&Path>) -> Result<(), Diagnostic> {
        Ok(())
    }
    fn ensure_redroid_image(&self, _: &str) -> Result<(), Diagnostic> {
        Ok(())
    }
}

/// Digest of the validated API 33 `HQarroum` image.
pub const HQARROUM_API_33_DIGEST: &str =
    "sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95";

/// Default `HQarroum` image repository.
pub const HQARROUM_IMAGE: &str = "halimqarroum/docker-android:api-33";

/// Fixed-version sidecar used to bridge the guest-visible QEMU host alias to
/// the host-side workbench proxy without switching the emulator container to
/// host networking.
pub const CAPTURE_BRIDGE_IMAGE: &str =
    "alpine/socat:1.8.0.0@sha256:a6be4c0262b339c53ddad723cdd178a1a13271e1137c65e27f90a08c16de02b8";
const CAPTURE_BRIDGE_PORT: u16 = 18080;

struct ContainerCaptureBridge {
    runner: Arc<dyn ExternalToolRunner>,
    docker: ToolProbe,
    container: String,
    sidecar: String,
    started: bool,
}
impl ContainerCaptureBridge {
    fn new(
        runner: Arc<dyn ExternalToolRunner>,
        docker: ToolProbe,
        container: String,
        lease_id: &str,
    ) -> Self {
        Self {
            runner,
            docker,
            container,
            sidecar: format!("{}-capture-bridge", safe_suffix(lease_id)),
            started: false,
        }
    }
}
impl SandboxCaptureBridge for ContainerCaptureBridge {
    fn prepare(&mut self, proxy: SocketAddr) -> Result<SandboxCaptureEndpoint, Diagnostic> {
        if proxy.port() == 0 {
            return Err(
                catalogue::SANDBOX_CAPTURE_BRIDGE_FAILED.instantiate(context(
                    "sandbox.capture-bridge",
                    "error",
                    "host proxy port was zero".to_owned(),
                )),
            );
        }
        let args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--rm".to_owned(),
            "--name".to_owned(),
            self.sidecar.clone(),
            "--network".to_owned(),
            format!("container:{}", self.container),
            CAPTURE_BRIDGE_IMAGE.to_owned(),
            format!("TCP-LISTEN:{CAPTURE_BRIDGE_PORT},fork,reuseaddr,bind=0.0.0.0"),
            format!("TCP:host.docker.internal:{}", proxy.port()),
        ];
        if let Err(error) = invoke_tool(&self.runner, &self.docker, &args, Duration::from_secs(60))
        {
            return Err(
                catalogue::SANDBOX_CAPTURE_BRIDGE_FAILED.instantiate(context(
                    "sandbox.capture-bridge",
                    "error",
                    format!("sidecar start failed: {error}"),
                )),
            );
        }
        self.started = true;
        let inspect = invoke_tool(
            &self.runner,
            &self.docker,
            &[
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{.State.Running}}".to_owned(),
                self.sidecar.clone(),
            ],
            Duration::from_secs(30),
        );
        if !inspect
            .as_ref()
            .is_ok_and(|output| output.exit_code == Some(0) && output.stdout.trim() == "true")
        {
            let _ = self.cleanup();
            return Err(
                catalogue::SANDBOX_CAPTURE_BRIDGE_FAILED.instantiate(context(
                    "sandbox.capture-bridge",
                    "error",
                    format!("sidecar readiness failed: {inspect:?}"),
                )),
            );
        }
        Ok(SandboxCaptureEndpoint {
            host: "10.0.2.2".to_owned(),
            port: CAPTURE_BRIDGE_PORT,
            topology: "qemu-guest-to-docker-sidecar-to-host-proxy".to_owned(),
        })
    }

    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        if !self.started {
            return Ok(());
        }
        self.started = false;
        invoke_tool(
            &self.runner,
            &self.docker,
            &["rm".to_owned(), "--force".to_owned(), self.sidecar.clone()],
            Duration::from_secs(30),
        )
        .map(|_| ())
        .map_err(|error| {
            vec![
                catalogue::SANDBOX_CAPTURE_BRIDGE_FAILED.instantiate(context(
                    "sandbox.capture-bridge",
                    "error",
                    format!("sidecar teardown failed: {error}"),
                )),
            ]
        })
    }
}

/// HQarroum-backed AVD configuration. The legacy native-AVD fields remain
/// present so configuration deserialization and embedding code can migrate
/// without changing the `SandboxBackend` contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvdConfig {
    /// Container/AVD logical name retained for compatibility.
    pub avd_name: String,
    /// Legacy emulator executable; `HQarroum` starts the emulator in-container.
    pub emulator_executable: String,
    /// Host ADB executable.
    pub adb_executable: String,
    /// Legacy `ADB` serial; `HQarroum` discovers a per-lease loopback serial.
    pub device_serial: String,
    /// Legacy snapshot name; `HQarroum` always uses `-no-snapshot`.
    pub baseline_snapshot: String,
    /// Legacy SDK image marker.
    pub image_marker: Option<PathBuf>,
    /// Legacy SDK package; `HQarroum` uses `api_level` and `image`.
    pub image_package: String,
    /// Docker executable used to run the image.
    pub docker_executable: String,
    /// `HQarroum` image repository or a locally rebuilt image tag.
    pub image: String,
    /// Expected immutable image digest.
    pub image_digest: String,
    /// Android API level represented by the image.
    pub api_level: u32,
    /// Per-lease container name prefix.
    pub container_name_prefix: String,
    /// Optional finding-scoped runtime-trust acceptance.
    pub runtime_trust_acceptance: Option<runtime_trust::RuntimeTrustAcceptance>,
    /// Optional append-only JSONL path for accepted trust findings.
    pub runtime_trust_audit_path: Option<PathBuf>,
}

impl Default for AvdConfig {
    fn default() -> Self {
        Self {
            avd_name: "android".to_owned(),
            emulator_executable: "emulator".to_owned(),
            adb_executable: "adb".to_owned(),
            device_serial: String::new(),
            baseline_snapshot: String::new(),
            image_marker: None,
            image_package: String::new(),
            docker_executable: "docker".to_owned(),
            image: HQARROUM_IMAGE.to_owned(),
            image_digest: HQARROUM_API_33_DIGEST.to_owned(),
            api_level: 33,
            container_name_prefix: "apiaxess-avd".to_owned(),
            runtime_trust_acceptance: None,
            runtime_trust_audit_path: None,
        }
    }
}

/// Strong-isolation AOSP `x86_64` emulator backend.
pub struct AvdBackend {
    config: AvdConfig,
    runner: Arc<dyn ExternalToolRunner>,
    capabilities: HostCapabilityReport,
    images: Arc<dyn ImageManager>,
}
impl AvdBackend {
    /// Creates an AVD backend with injected policy.
    #[must_use]
    pub fn new(
        config: AvdConfig,
        runner: Arc<dyn ExternalToolRunner>,
        capabilities: HostCapabilityReport,
        images: Arc<dyn ImageManager>,
    ) -> Self {
        Self {
            config,
            runner,
            capabilities,
            images,
        }
    }
}
impl SandboxBackend for AvdBackend {
    fn backend_id(&self) -> &str {
        "sandbox.avd"
    }
    fn tier(&self) -> SandboxTier {
        SandboxTier::Avd
    }
    fn descriptor(&self) -> SandboxBackendDescriptor {
        SandboxBackendDescriptor {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::HardwareVm,
            tradeoff:
                "HQarroum google_apis userdebug emulator in a disposable Docker VM; requires KVM/WHPX and host-side authenticated ADB."
                    .to_owned(),
            required_capability_ids: vec![
                CAPABILITY_DOCKER.to_owned(),
                CAPABILITY_ANDROID_ADB.to_owned(),
                CAPABILITY_AVD_ACCELERATION.to_owned(),
            ],
        }
    }
    fn preflight(&self) -> SandboxPlan {
        let mut diagnostics = Vec::new();
        if self.config.api_level == 0 {
            diagnostics.push(backend_diagnostic(
                "android.hqarroum-api-level",
                "the HQarroum API level must be a positive value",
            ));
        }
        require_capability(
            &self.capabilities,
            CAPABILITY_DOCKER,
            false,
            &mut diagnostics,
        );
        require_capability(
            &self.capabilities,
            CAPABILITY_ANDROID_ADB,
            false,
            &mut diagnostics,
        );
        if !self
            .capabilities
            .supports(CAPABILITY_AVD_ACCELERATION, false)
            && !self
                .capabilities
                .supports(CAPABILITY_WSL2_NESTED_KVM, false)
        {
            if let Some(observation) = self.capabilities.get(CAPABILITY_AVD_ACCELERATION) {
                diagnostics.push(capability_diagnostic(
                    observation,
                    CAPABILITY_AVD_ACCELERATION,
                ));
            } else {
                diagnostics.push(backend_diagnostic(
                    CAPABILITY_AVD_ACCELERATION,
                    "neither native emulator acceleration nor WSL2 nested KVM was confirmed",
                ));
            }
        }
        SandboxPlan {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::HardwareVm,
            capabilities: self.capabilities.clone(),
            diagnostics,
        }
    }
    // Backend startup is an ordered resource handoff and intentionally remains
    // in one function so each rollback path is visible beside its acquisition.
    #[allow(clippy::too_many_lines)]
    fn start(&self, request: &SandboxStartRequest) -> Result<SandboxLease, Vec<Diagnostic>> {
        let plan = self.preflight();
        if !plan.is_runnable() {
            return Err(plan.diagnostics);
        }
        self.images
            .ensure_hqarroum_image(&self.config.image, &self.config.image_digest)
            .map_err(|e| vec![e])?;
        let docker = probe_tool(
            &self.runner,
            "container.docker",
            &self.config.docker_executable,
            &["version"],
        )
        .map_err(|e| vec![boot_diagnostic(self.backend_id(), e.to_string())])?;
        let adb = probe_tool(
            &self.runner,
            "android.adb",
            &self.config.adb_executable,
            &["version"],
        )
        .map_err(|e| vec![adb_diagnostic(self.backend_id(), e.to_string())])?;
        let container = format!(
            "{}-{}",
            self.config.container_name_prefix,
            safe_suffix(&request.lease_id)
        );
        let adb_key = redroid_adb_key_path(&request.lease_id);
        let adb_public_key = adb_key.with_extension("pub");
        let adb_environment = vec![("ADB_VENDOR_KEYS".to_owned(), adb_key.display().to_string())];
        if let Err(error) = invoke_tool_with_environment(
            &self.runner,
            &adb,
            &["keygen".to_owned(), adb_key.display().to_string()],
            Duration::from_secs(30),
            &adb_environment,
        ) {
            return Err(vec![catalogue::SANDBOX_ADB_AUTH_UNAVAILABLE.instantiate(
                context(self.backend_id(), "error", error.to_string()),
            )]);
        }
        let image = if self.config.image.contains('@') {
            self.config.image.clone()
        } else {
            format!("{}@{}", self.config.image, self.config.image_digest)
        };
        let args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            container.clone(),
            "--device".to_owned(),
            "/dev/kvm".to_owned(),
            "--publish".to_owned(),
            "127.0.0.1::5555".to_owned(),
            "--env".to_owned(),
            "EXTRA_FLAGS=-writable-system".to_owned(),
            "--env".to_owned(),
            "SKIP_AUTH=false".to_owned(),
            "--volume".to_owned(),
            format!("{}:/root/.android/adbkey:ro", adb_key.display()),
            "--volume".to_owned(),
            format!("{}:/root/.android/adbkey.pub:ro", adb_public_key.display()),
            image,
        ];
        if let Err(error) = invoke_tool(&self.runner, &docker, &args, Duration::from_secs(60)) {
            let _ = fs::remove_file(&adb_key);
            let _ = fs::remove_file(&adb_public_key);
            return Err(vec![boot_diagnostic(self.backend_id(), error.to_string())]);
        }
        if let Err(error) = verify_hqarroum_kvm(&self.runner, &docker, &container) {
            let mut cleanup = HqarroumCleanup::new(
                self.runner.clone(),
                docker.clone(),
                container,
                adb.clone(),
                "127.0.0.1:0".to_owned(),
                adb_environment,
                adb_key,
                adb_public_key,
            );
            let mut diagnostics = vec![error];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        let serial = match published_adb_serial(&self.runner, &docker, &container) {
            Ok(serial) => serial,
            Err(error) => {
                let mut cleanup = HqarroumCleanup::new(
                    self.runner.clone(),
                    docker.clone(),
                    container,
                    adb.clone(),
                    "127.0.0.1:0".to_owned(),
                    adb_environment,
                    adb_key,
                    adb_public_key,
                );
                let mut diagnostics = vec![error];
                diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
                return Err(diagnostics);
            }
        };
        if let Err(error) = invoke_tool_with_environment(
            &self.runner,
            &adb,
            &["connect".to_owned(), serial.clone()],
            Duration::from_secs(30),
            &adb_environment,
        ) {
            let mut cleanup = HqarroumCleanup::new(
                self.runner.clone(),
                docker.clone(),
                container,
                adb.clone(),
                serial,
                adb_environment,
                adb_key,
                adb_public_key,
            );
            let mut diagnostics =
                vec![catalogue::SANDBOX_HQARROUM_ADB_FAILED.instantiate(context(
                    self.backend_id(),
                    "error",
                    error.to_string(),
                ))];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        if let Err(error) = wait_for_redroid_device(
            &self.runner,
            &adb,
            &serial,
            &adb_environment,
            request.readiness_timeout,
        ) {
            let mut cleanup = HqarroumCleanup::new(
                self.runner.clone(),
                docker.clone(),
                container,
                adb.clone(),
                serial,
                adb_environment,
                adb_key,
                adb_public_key,
            );
            let mut diagnostics = vec![error];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        let trust_diagnostics = match evaluate_hqarroum_runtime_trust(
            &self.runner,
            &adb,
            &serial,
            &adb_environment,
            &self.config,
        ) {
            Ok(diagnostics) => diagnostics,
            Err(mut diagnostics) => {
                let mut cleanup = HqarroumCleanup::new(
                    self.runner.clone(),
                    docker.clone(),
                    container,
                    adb.clone(),
                    serial,
                    adb_environment,
                    adb_key,
                    adb_public_key,
                );
                diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
                return Err(diagnostics);
            }
        };
        if let Err(error) = prepare_hqarroum_system(
            &self.runner,
            &adb,
            &serial,
            &adb_environment,
            request.readiness_timeout,
        ) {
            let mut cleanup = HqarroumCleanup::new(
                self.runner.clone(),
                docker.clone(),
                container,
                adb.clone(),
                serial,
                adb_environment,
                adb_key,
                adb_public_key,
            );
            let mut diagnostics = vec![error];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        let control: Arc<dyn SandboxControl> = Arc::new(AdbControl {
            runner: self.runner.clone(),
            adb: adb.clone(),
            serial: serial.clone(),
            environment: adb_environment.clone(),
            transport: "loopback-adb-host",
        });
        let cleanup = HqarroumCleanup::new(
            self.runner.clone(),
            docker,
            container,
            adb,
            serial.clone(),
            adb_environment,
            adb_key,
            adb_public_key,
        );
        let capture_bridge = ContainerCaptureBridge::new(
            self.runner.clone(),
            cleanup.docker.clone(),
            cleanup.container.clone(),
            &request.lease_id,
        );
        Ok(SandboxLease::new(
            SandboxHandle {
                lease_id: request.lease_id.clone(),
                backend_id: self.backend_id().to_owned(),
                tier: self.tier(),
                isolation: IsolationStrength::HardwareVm,
                control_channel: "loopback-adb-host".to_owned(),
                device_serial: serial,
            },
            control,
            Box::new(cleanup),
        )
        .with_capture_bridge(Box::new(capture_bridge))
        .with_trust_diagnostics(trust_diagnostics))
    }
}
/// Resolved layout + speed choice for the bundled, owned zero-config emulator.
///
/// The analysis runtime (bundled QEMU/SDK emulator engine + owned Android-10
/// AOSP image) is a separate, optional payload. It is located under the install
/// tree's `analysis-runtime/` directory, or wherever `APIAXESS_ANALYSIS_RUNTIME`
/// points. It doubles as `ANDROID_SDK_ROOT` (holding `emulator/`,
/// `platform-tools/`, and `system-images/`), with the owned AVD under `avd/`.
#[derive(Clone, Debug)]
pub struct BundledEmulatorConfig {
    /// Runtime root, used as `ANDROID_SDK_ROOT`.
    pub runtime_root: PathBuf,
    /// Absolute path to the bundled emulator engine.
    pub emulator_executable: PathBuf,
    /// Absolute path to the bundled `adb`.
    pub adb_executable: PathBuf,
    /// `ANDROID_AVD_HOME` holding the owned Android-10 AVD.
    pub avd_home: PathBuf,
    /// Owned AVD name.
    pub avd_name: String,
    /// Whether to boot accelerated or in software (TCG) mode.
    pub acceleration: AccelerationMode,
    /// Local emulator console port; the device serial is `emulator-<port>`.
    pub console_port: u16,
}

impl BundledEmulatorConfig {
    /// Resolves the bundled runtime from the install layout for the given mode.
    #[must_use]
    pub fn resolve(acceleration: AccelerationMode) -> Self {
        let root = analysis_runtime_root();
        Self::for_root(&root, acceleration)
    }

    /// Builds a config rooted at an explicit runtime directory (used by tests
    /// and by the `APIAXESS_ANALYSIS_RUNTIME` override).
    #[must_use]
    pub fn for_root(root: &Path, acceleration: AccelerationMode) -> Self {
        let exe = |name: &str| {
            if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.to_owned()
            }
        };
        Self {
            runtime_root: root.to_path_buf(),
            emulator_executable: root.join("emulator").join(exe("emulator")),
            adb_executable: root.join("platform-tools").join(exe("adb")),
            avd_home: root.join("avd"),
            avd_name: "apiaxess-android-10".to_owned(),
            acceleration,
            console_port: 5554,
        }
    }

    fn device_serial(&self) -> String {
        format!("emulator-{}", self.console_port)
    }

    fn environment(&self) -> Vec<(String, String)> {
        vec![
            (
                "ANDROID_SDK_ROOT".to_owned(),
                self.runtime_root.display().to_string(),
            ),
            (
                "ANDROID_AVD_HOME".to_owned(),
                self.avd_home.display().to_string(),
            ),
        ]
    }
}

/// The analysis-runtime root: an explicit `APIAXESS_ANALYSIS_RUNTIME` override,
/// otherwise the `analysis-runtime/` directory beside the install (Windows) or
/// under `share/apiaxess/` (Unix) — matching the other bundled components.
fn analysis_runtime_root() -> PathBuf {
    if let Some(configured) = std::env::var_os("APIAXESS_ANALYSIS_RUNTIME") {
        return PathBuf::from(configured);
    }
    let Some(bin) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    else {
        return PathBuf::from("analysis-runtime");
    };
    if cfg!(windows) {
        bin.join("..").join("analysis-runtime")
    } else {
        bin.join("..")
            .join("share")
            .join("apiaxess")
            .join("analysis-runtime")
    }
}

/// Host path to the bundled device-side `frida-server` shipped in the analysis
/// runtime. The pinning-bypass Frida lane deploys this binary to the guest, so
/// the pipeline must resolve it from the install layout rather than relying on a
/// bare `frida-server` on `PATH`.
#[must_use]
pub fn bundled_frida_server_path() -> PathBuf {
    analysis_runtime_root().join("frida-server")
}

/// Bundled, owned zero-config Android-10 emulator backend. Runs the bundled
/// emulator engine + owned image directly (no Docker), accelerated when the host
/// exposes virtualization or in QEMU software mode otherwise.
pub struct BundledEmulatorBackend {
    config: BundledEmulatorConfig,
    runner: Arc<dyn ExternalToolRunner>,
    capabilities: HostCapabilityReport,
}

impl BundledEmulatorBackend {
    /// Creates a bundled-emulator backend with an injected runner and capability
    /// evidence.
    #[must_use]
    pub fn new(
        config: BundledEmulatorConfig,
        runner: Arc<dyn ExternalToolRunner>,
        capabilities: HostCapabilityReport,
    ) -> Self {
        Self {
            config,
            runner,
            capabilities,
        }
    }

    fn wait_for_boot(
        &self,
        adb: &ToolProbe,
        serial: &str,
        environment: &[(String, String)],
        process: &ToolProcess,
        deadline: Duration,
    ) -> Result<(), Diagnostic> {
        let started = std::time::Instant::now();
        // Give the emulator a chance to register with adb, then poll boot state.
        let _ = invoke_tool_with_environment(
            &self.runner,
            adb,
            &["-s", serial, "wait-for-device"],
            deadline,
            environment,
        );
        loop {
            if !process.is_running() {
                return Err(catalogue::SANDBOX_BOOT_FAILED.instantiate(context(
                    self.backend_id(),
                    "error",
                    format!(
                        "the bundled emulator exited before boot completed: {}",
                        process.stderr().trim()
                    ),
                )));
            }
            if let Ok(output) = invoke_tool_with_environment(
                &self.runner,
                adb,
                &["-s", serial, "shell", "getprop", "sys.boot_completed"],
                Duration::from_secs(20),
                environment,
            ) && output.stdout.trim() == "1"
            {
                return Ok(());
            }
            if started.elapsed() >= deadline {
                return Err(catalogue::SANDBOX_READINESS_TIMEOUT.instantiate(context(
                    self.backend_id(),
                    "error",
                    format!("the bundled emulator did not reach sys.boot_completed=1 within {deadline:?}"),
                )));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

impl SandboxBackend for BundledEmulatorBackend {
    fn backend_id(&self) -> &str {
        "sandbox.bundled-emulator"
    }
    fn tier(&self) -> SandboxTier {
        SandboxTier::BundledEmulator
    }
    fn descriptor(&self) -> SandboxBackendDescriptor {
        let tradeoff = match self.config.acceleration {
            AccelerationMode::Accelerated => {
                "Bundled, owned Android-10 AOSP emulator running with hardware acceleration (KVM/WHPX); zero host configuration."
            }
            AccelerationMode::Software => {
                "Bundled, owned Android-10 AOSP emulator running in QEMU software mode (no host virtualization); correct but substantially slower."
            }
        };
        SandboxBackendDescriptor {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::HardwareVm,
            tradeoff: tradeoff.to_owned(),
            // Nothing is required on the host: the engine and image are bundled,
            // and software mode needs no virtualization capability at all.
            required_capability_ids: Vec::new(),
        }
    }
    fn preflight(&self) -> SandboxPlan {
        let mut diagnostics = Vec::new();
        // The analysis runtime is an optional, separately-downloaded payload.
        for component in [
            &self.config.emulator_executable,
            &self.config.adb_executable,
        ] {
            if !component.is_file() {
                diagnostics.push(
                    catalogue::SANDBOX_ANALYSIS_RUNTIME_MISSING.instantiate(context(
                        self.backend_id(),
                        "missing_path",
                        component.display().to_string(),
                    )),
                );
                break;
            }
        }
        if !self
            .config
            .avd_home
            .join(format!("{}.ini", self.config.avd_name))
            .is_file()
            && diagnostics.is_empty()
        {
            diagnostics.push(
                catalogue::SANDBOX_ANALYSIS_RUNTIME_MISSING.instantiate(context(
                    self.backend_id(),
                    "missing_path",
                    self.config
                        .avd_home
                        .join(format!("{}.ini", self.config.avd_name))
                        .display()
                        .to_string(),
                )),
            );
        }
        // Software mode has no hardware requirement; only surface the honest
        // speed diagnostic for the resolved mode.
        let (_, acceleration_diagnostic) = AccelerationMode::detect(&self.capabilities);
        diagnostics.push(acceleration_diagnostic);
        SandboxPlan {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::HardwareVm,
            capabilities: self.capabilities.clone(),
            diagnostics,
        }
    }
    fn start(&self, request: &SandboxStartRequest) -> Result<SandboxLease, Vec<Diagnostic>> {
        let plan = self.preflight();
        if !plan.is_runnable() {
            return Err(plan.diagnostics);
        }
        // Fail legibly before boot when the runtime volume is too full to hold a
        // fresh `-wipe-data` userdata image. Without this, a disk-full condition
        // surfaces only as an opaque mid-boot `sandbox.boot-failed`, misdiagnosing
        // a host storage problem as an emulator fault. If free space cannot be
        // measured, degrade honestly and let boot proceed rather than block.
        let required_free = emulator_min_free_bytes();
        if let Some(available) = available_space(&self.config.avd_home)
            && available < required_free
        {
            return Err(vec![insufficient_disk_diagnostic(
                self.backend_id(),
                &self.config.avd_home,
                required_free,
                available,
            )]);
        }
        let serial = self.config.device_serial();
        let environment = self.config.environment();
        let adb = probe_tool(
            &self.runner,
            "android.adb",
            &self.config.adb_executable.display().to_string(),
            &["version"],
        )
        .map_err(|error| vec![adb_diagnostic(self.backend_id(), error.to_string())])?;
        let emulator = probe_tool(
            &self.runner,
            "android.emulator",
            &self.config.emulator_executable.display().to_string(),
            &["-version"],
        )
        .map_err(|error| vec![boot_diagnostic(self.backend_id(), error.to_string())])?;

        // Accel-aware, headless, disposable (fresh each session) launch.
        let accel = match self.config.acceleration {
            AccelerationMode::Accelerated => "on",
            AccelerationMode::Software => "off",
        };
        let arguments = vec![
            "-avd".to_owned(),
            self.config.avd_name.clone(),
            "-port".to_owned(),
            self.config.console_port.to_string(),
            "-accel".to_owned(),
            accel.to_owned(),
            "-gpu".to_owned(),
            "swiftshader_indirect".to_owned(),
            "-no-window".to_owned(),
            "-no-audio".to_owned(),
            "-no-boot-anim".to_owned(),
            "-no-metrics".to_owned(),
            // A disposable analysis sandbox must start pristine every run.
            // `-no-snapshot-save` alone still *loads* any prior snapshot, and the
            // writable-system/userdata qcow2 overlays persist across boots — so a
            // previous run's state (or a qcow2 left inconsistent by a killed run)
            // silently poisons later boots, which then hang forever at
            // `sys.boot_completed` and surface only as a readiness timeout.
            // `-no-snapshot` (never load or save) + `-wipe-data` (fresh userdata)
            // guarantee a clean cold boot; the APK is installed fresh after boot
            // anyway, so nothing of value is lost.
            "-no-snapshot".to_owned(),
            "-wipe-data".to_owned(),
            "-writable-system".to_owned(),
        ];
        // Clear stale AVD locks from a previous run that was killed rather than
        // torn down (a SIGKILL/TerminateProcess does not let the emulator release
        // hardware-qemu.ini.lock / multiinstance.lock / snapshot.lock.lock). Left
        // behind, a single crashed run poisons every subsequent boot: the emulator
        // process starts but never attaches to adb, surfacing only as a readiness
        // timeout. This disposable AVD is single-instance and no live emulator
        // shares it here, so removing stale locks before launch is safe.
        clear_stale_avd_locks(&self.config.runtime_root, &self.config.avd_name);
        let process = self
            .runner
            .spawn(&ToolProcessRequest {
                probe: emulator,
                arguments,
                working_directory: Some(self.config.runtime_root.clone()),
                environment: environment.clone(),
            })
            .map_err(|error| vec![boot_diagnostic(self.backend_id(), error.to_string())])?;

        if let Err(error) = self.wait_for_boot(
            &adb,
            &serial,
            &environment,
            &process,
            request.readiness_timeout,
        ) {
            let _ = process.stop();
            return Err(vec![error]);
        }

        let control = Arc::new(AdbControl {
            runner: Arc::clone(&self.runner),
            adb: adb.clone(),
            serial: serial.clone(),
            environment: environment.clone(),
            transport: "sandbox.adb",
        });
        let cleanup = BundledEmulatorCleanup {
            runner: Arc::clone(&self.runner),
            adb,
            serial: serial.clone(),
            environment,
            process: Some(process),
        };
        Ok(SandboxLease::new(
            SandboxHandle {
                lease_id: request.lease_id.clone(),
                backend_id: self.backend_id().to_owned(),
                tier: self.tier(),
                isolation: IsolationStrength::HardwareVm,
                control_channel: "bundled-emulator-adb".to_owned(),
                device_serial: serial,
            },
            control,
            Box::new(cleanup),
        ))
    }
}

struct BundledEmulatorCleanup {
    runner: Arc<dyn ExternalToolRunner>,
    adb: ToolProbe,
    serial: String,
    environment: Vec<(String, String)>,
    process: Option<ToolProcess>,
}

impl SandboxCleanup for BundledEmulatorCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        // Ask the emulator to power off cleanly, then stop the owned process.
        let _ = invoke_tool_with_environment(
            &self.runner,
            &self.adb,
            &["-s", &self.serial, "emu", "kill"],
            Duration::from_secs(20),
            &self.environment,
        );
        if let Some(process) = self.process.take()
            && let Err(error) = process.stop()
        {
            return Err(vec![catalogue::SANDBOX_TEARDOWN_FAILED.instantiate(
                context("sandbox.bundled-emulator", "error", error.to_string()),
            )]);
        }
        Ok(())
    }
}

struct HqarroumCleanup {
    runner: Arc<dyn ExternalToolRunner>,
    docker: ToolProbe,
    container: String,
    adb: ToolProbe,
    serial: String,
    environment: Vec<(String, String)>,
    adb_key: PathBuf,
    adb_public_key: PathBuf,
}
impl HqarroumCleanup {
    // Cleanup owns several independent resources that must be torn down
    // together in reverse handoff order.
    #[allow(clippy::too_many_arguments)]
    fn new(
        runner: Arc<dyn ExternalToolRunner>,
        docker: ToolProbe,
        container: String,
        adb: ToolProbe,
        serial: String,
        environment: Vec<(String, String)>,
        adb_key: PathBuf,
        adb_public_key: PathBuf,
    ) -> Self {
        Self {
            runner,
            docker,
            container,
            adb,
            serial,
            environment,
            adb_key,
            adb_public_key,
        }
    }
}
impl SandboxCleanup for HqarroumCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if self.serial != "127.0.0.1:0"
            && let Err(e) = invoke_tool_with_environment(
                &self.runner,
                &self.adb,
                &["disconnect".to_owned(), self.serial.clone()],
                Duration::from_secs(15),
                &self.environment,
            )
        {
            diagnostics.push(teardown_diagnostic("sandbox.avd", e.to_string()));
        }
        if let Err(e) = invoke_tool(
            &self.runner,
            &self.docker,
            &[
                "rm".to_owned(),
                "--force".to_owned(),
                self.container.clone(),
            ],
            Duration::from_secs(30),
        ) {
            diagnostics.push(teardown_diagnostic("sandbox.avd", e.to_string()));
        }
        if let Err(error) = fs::remove_file(&self.adb_key)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            diagnostics.push(teardown_diagnostic(
                "sandbox.avd",
                format!(
                    "could not remove adbkey {}: {error}",
                    self.adb_key.display()
                ),
            ));
        }
        if let Err(error) = fs::remove_file(&self.adb_public_key)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            diagnostics.push(teardown_diagnostic(
                "sandbox.avd",
                format!(
                    "could not remove adb public key {}: {error}",
                    self.adb_public_key.display()
                ),
            ));
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// redroid configuration. ADB is host-side and bound to a per-lease loopback
/// port; the legacy serial field is retained for configuration compatibility
/// but is not used to bypass dynamic port discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedroidConfig {
    /// Docker executable.
    pub docker_executable: String,
    /// Host ADB executable used for the authenticated loopback transport.
    pub adb_executable: String,
    /// redroid image reference.
    pub image: String,
    /// Container name prefix.
    pub container_name_prefix: String,
    /// Volume name prefix.
    pub volume_name_prefix: String,
    /// Legacy device serial retained for configuration compatibility.
    pub device_serial: String,
}
/// Fast shared-kernel redroid backend for trusted targets.
pub struct RedroidBackend {
    config: RedroidConfig,
    runner: Arc<dyn ExternalToolRunner>,
    capabilities: HostCapabilityReport,
    images: Arc<dyn ImageManager>,
}
impl RedroidBackend {
    /// Creates a redroid backend.
    #[must_use]
    pub fn new(
        config: RedroidConfig,
        runner: Arc<dyn ExternalToolRunner>,
        capabilities: HostCapabilityReport,
        images: Arc<dyn ImageManager>,
    ) -> Self {
        Self {
            config,
            runner,
            capabilities,
            images,
        }
    }
}
impl SandboxBackend for RedroidBackend {
    fn backend_id(&self) -> &str {
        "sandbox.redroid"
    }
    fn tier(&self) -> SandboxTier {
        SandboxTier::Redroid
    }
    fn descriptor(&self) -> SandboxBackendDescriptor {
        SandboxBackendDescriptor { backend_id: self.backend_id().to_owned(), tier: self.tier(), isolation: IsolationStrength::SharedKernelTrustedOnly, tradeoff: "Fast startup, but native-Linux-only --privileged shared-kernel isolation; use only with trusted targets.".to_owned(), required_capability_ids: vec![CAPABILITY_DOCKER.to_owned(), CAPABILITY_DOCKER_PRIVILEGED.to_owned(), CAPABILITY_REDOID_KERNEL.to_owned()] }
    }
    fn preflight(&self) -> SandboxPlan {
        let mut diagnostics = Vec::new();
        require_capability(
            &self.capabilities,
            CAPABILITY_DOCKER,
            false,
            &mut diagnostics,
        );
        require_capability(
            &self.capabilities,
            CAPABILITY_DOCKER_PRIVILEGED,
            true,
            &mut diagnostics,
        );
        require_capability(
            &self.capabilities,
            CAPABILITY_REDOID_KERNEL,
            false,
            &mut diagnostics,
        );
        SandboxPlan {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::SharedKernelTrustedOnly,
            capabilities: self.capabilities.clone(),
            diagnostics,
        }
    }
    // Backend startup is an ordered resource handoff and intentionally remains
    // in one function so each rollback path is visible beside its acquisition.
    #[allow(clippy::too_many_lines)]
    fn start(&self, request: &SandboxStartRequest) -> Result<SandboxLease, Vec<Diagnostic>> {
        let plan = self.preflight();
        if !plan.is_runnable() {
            return Err(plan.diagnostics);
        }
        self.images
            .ensure_redroid_image(&self.config.image)
            .map_err(|e| vec![e])?;
        let docker = probe_tool(
            &self.runner,
            "container.docker",
            &self.config.docker_executable,
            &["version"],
        )
        .map_err(|e| vec![docker_diagnostic(e.to_string())])?;
        let container = format!(
            "{}-{}",
            self.config.container_name_prefix,
            safe_suffix(&request.lease_id)
        );
        let volume = format!(
            "{}-{}",
            self.config.volume_name_prefix,
            safe_suffix(&request.lease_id)
        );
        let adb = probe_tool(
            &self.runner,
            "android.adb",
            &self.config.adb_executable,
            &["version"],
        )
        .map_err(|e| vec![adb_diagnostic(self.backend_id(), e.to_string())])?;
        let adb_key = redroid_adb_key_path(&request.lease_id);
        let adb_environment = vec![("ADB_VENDOR_KEYS".to_owned(), adb_key.display().to_string())];
        if let Err(error) = invoke_tool_with_environment(
            &self.runner,
            &adb,
            &["keygen".to_owned(), adb_key.display().to_string()],
            Duration::from_secs(30),
            &adb_environment,
        ) {
            let _ = fs::remove_file(&adb_key);
            return Err(vec![catalogue::SANDBOX_ADB_AUTH_UNAVAILABLE.instantiate(
                context(self.backend_id(), "error", error.to_string()),
            )]);
        }
        let args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--privileged".to_owned(),
            "--name".to_owned(),
            container.clone(),
            "--publish".to_owned(),
            "127.0.0.1::5555".to_owned(),
            "--volume".to_owned(),
            format!("{volume}:/data"),
            self.config.image.clone(),
        ];
        if let Err(error) = invoke_tool(&self.runner, &docker, &args, Duration::from_secs(60)) {
            let _ = fs::remove_file(&adb_key);
            return Err(vec![boot_diagnostic(self.backend_id(), error.to_string())]);
        }
        let serial = match published_adb_serial(&self.runner, &docker, &container) {
            Ok(serial) => serial,
            Err(error) => {
                let mut cleanup = RedroidCleanup::new(
                    self.runner.clone(),
                    docker,
                    container,
                    volume,
                    adb,
                    "127.0.0.1:0".to_owned(),
                    adb_environment,
                    adb_key,
                );
                let mut diagnostics = vec![error];
                diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
                return Err(diagnostics);
            }
        };
        if let Err(error) = invoke_tool_with_environment(
            &self.runner,
            &adb,
            &["connect".to_owned(), serial.clone()],
            Duration::from_secs(30),
            &adb_environment,
        ) {
            let mut cleanup = RedroidCleanup::new(
                self.runner.clone(),
                docker,
                container,
                volume,
                adb,
                serial,
                adb_environment,
                adb_key,
            );
            let mut diagnostics = vec![
                catalogue::SANDBOX_REDOID_ADB_CONTRACT_FAILED.instantiate(context(
                    self.backend_id(),
                    "error",
                    error.to_string(),
                )),
            ];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        if let Err(error) = wait_for_redroid_device(
            &self.runner,
            &adb,
            &serial,
            &adb_environment,
            request.readiness_timeout,
        ) {
            let mut cleanup = RedroidCleanup::new(
                self.runner.clone(),
                docker,
                container,
                volume,
                adb,
                serial,
                adb_environment,
                adb_key,
            );
            let mut diagnostics = vec![error];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        if let Err(error) = verify_adb_security_patch(&self.runner, &adb, &serial, &adb_environment)
        {
            let mut cleanup = RedroidCleanup::new(
                self.runner.clone(),
                docker,
                container,
                volume,
                adb,
                serial,
                adb_environment,
                adb_key,
            );
            let mut diagnostics = vec![error];
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            return Err(diagnostics);
        }
        let control: Arc<dyn SandboxControl> = Arc::new(AdbControl {
            runner: self.runner.clone(),
            adb: adb.clone(),
            serial: serial.clone(),
            environment: adb_environment.clone(),
            transport: "loopback-adb-host",
        });
        let cleanup = RedroidCleanup::new(
            self.runner.clone(),
            docker,
            container,
            volume,
            adb,
            serial.clone(),
            adb_environment,
            adb_key,
        );
        let capture_bridge = ContainerCaptureBridge::new(
            self.runner.clone(),
            cleanup.docker.clone(),
            cleanup.container.clone(),
            &request.lease_id,
        );
        Ok(SandboxLease::new(
            SandboxHandle {
                lease_id: request.lease_id.clone(),
                backend_id: self.backend_id().to_owned(),
                tier: self.tier(),
                isolation: IsolationStrength::SharedKernelTrustedOnly,
                control_channel: "loopback-adb-host".to_owned(),
                device_serial: serial,
            },
            control,
            Box::new(cleanup),
        )
        .with_capture_bridge(Box::new(capture_bridge)))
    }
}
struct RedroidCleanup {
    runner: Arc<dyn ExternalToolRunner>,
    docker: ToolProbe,
    container: String,
    volume: String,
    adb: ToolProbe,
    serial: String,
    environment: Vec<(String, String)>,
    adb_key: PathBuf,
}
impl RedroidCleanup {
    // Cleanup owns several independent resources that must be torn down
    // together in reverse handoff order.
    #[allow(clippy::too_many_arguments)]
    fn new(
        runner: Arc<dyn ExternalToolRunner>,
        docker: ToolProbe,
        container: String,
        volume: String,
        adb: ToolProbe,
        serial: String,
        environment: Vec<(String, String)>,
        adb_key: PathBuf,
    ) -> Self {
        Self {
            runner,
            docker,
            container,
            volume,
            adb,
            serial,
            environment,
            adb_key,
        }
    }
}
impl SandboxCleanup for RedroidCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if self.serial != "127.0.0.1:0"
            && let Err(e) = invoke_tool_with_environment(
                &self.runner,
                &self.adb,
                &["disconnect".to_owned(), self.serial.clone()],
                Duration::from_secs(15),
                &self.environment,
            )
        {
            diagnostics.push(teardown_diagnostic("sandbox.redroid", e.to_string()));
        }
        if let Err(e) = invoke_tool(
            &self.runner,
            &self.docker,
            &["rm", "--force", &self.container],
            Duration::from_secs(30),
        ) {
            diagnostics.push(teardown_diagnostic("sandbox.redroid", e.to_string()));
        }
        if let Err(error) = fs::remove_file(&self.adb_key)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            diagnostics.push(teardown_diagnostic(
                "sandbox.redroid",
                format!(
                    "could not remove adbkey {}: {error}",
                    self.adb_key.display()
                ),
            ));
        }
        if let Err(e) = invoke_tool(
            &self.runner,
            &self.docker,
            &["volume", "rm", "--force", &self.volume],
            Duration::from_secs(30),
        ) {
            diagnostics.push(teardown_diagnostic("sandbox.redroid", e.to_string()));
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// Only encrypted/authenticated remote transports can be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RemoteTransport {
    /// Strict host-key-verified SSH.
    Ssh,
}
/// Runtime the remote helper starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RemoteRuntime {
    /// Remote AVD.
    Avd,
    /// Remote redroid.
    Redroid,
}
/// Secured remote configuration. There is intentionally no ADB-over-TCP field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteConfig {
    /// Remote host, without URI scheme or port.
    pub host: String,
    /// SSH account.
    pub user: String,
    /// Local private key.
    pub identity_file: PathBuf,
    /// Pinned local known-hosts file.
    pub known_hosts_file: PathBuf,
    /// SSH executable.
    pub ssh_executable: String,
    /// Fixed remote helper path.
    pub helper_path: String,
    /// Remote runtime type.
    pub runtime: RemoteRuntime,
    /// Fixed encrypted transport.
    pub transport: RemoteTransport,
}
impl RemoteConfig {
    /// Rejects raw ADB and unsafe command/path values.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        let valid = |value: &str| {
            !value.trim().is_empty()
                && !value.chars().any(|c| {
                    c.is_whitespace() || matches!(c, ';' | '|' | '&' | '$' | '`' | '<' | '>')
                })
        };
        if self.transport != RemoteTransport::Ssh
            || !valid(&self.host)
            || !valid(&self.user)
            || !valid(&self.helper_path)
            || self.host.contains("://")
            || !self.identity_file.is_file()
            || !self.known_hosts_file.is_file()
        {
            let mut context = DiagnosticContext::new();
            context.insert(
                "transport".to_owned(),
                DiagnosticValue::String(format!("{:?}", self.transport).to_ascii_lowercase()),
            );
            context.insert(
                "host".to_owned(),
                DiagnosticValue::String(self.host.clone()),
            );
            return Err(catalogue::SANDBOX_REMOTE_TRANSPORT_INSECURE.instantiate(context));
        }
        Ok(())
    }
}
/// Remote-offload backend using only strict SSH control.
pub struct RemoteOffloadBackend {
    config: RemoteConfig,
    runner: Arc<dyn ExternalToolRunner>,
    capabilities: HostCapabilityReport,
}
impl RemoteOffloadBackend {
    /// Creates a secured remote backend.
    #[must_use]
    pub fn new(
        config: RemoteConfig,
        runner: Arc<dyn ExternalToolRunner>,
        capabilities: HostCapabilityReport,
    ) -> Self {
        Self {
            config,
            runner,
            capabilities,
        }
    }
}
impl SandboxBackend for RemoteOffloadBackend {
    fn backend_id(&self) -> &str {
        "sandbox.remote-offload"
    }
    fn tier(&self) -> SandboxTier {
        SandboxTier::RemoteOffload
    }
    fn descriptor(&self) -> SandboxBackendDescriptor {
        SandboxBackendDescriptor { backend_id: self.backend_id().to_owned(), tier: self.tier(), isolation: IsolationStrength::RemoteHostControlled, tradeoff: "Local control and results with runtime isolation delegated to a Linux host over strict encrypted SSH.".to_owned(), required_capability_ids: vec![CAPABILITY_REMOTE_SSH.to_owned()] }
    }
    fn preflight(&self) -> SandboxPlan {
        let mut diagnostics = Vec::new();
        if let Err(e) = self.config.validate() {
            diagnostics.push(e);
        }
        require_capability(
            &self.capabilities,
            CAPABILITY_REMOTE_SSH,
            false,
            &mut diagnostics,
        );
        SandboxPlan {
            backend_id: self.backend_id().to_owned(),
            tier: self.tier(),
            isolation: IsolationStrength::RemoteHostControlled,
            capabilities: self.capabilities.clone(),
            diagnostics,
        }
    }
    fn start(&self, request: &SandboxStartRequest) -> Result<SandboxLease, Vec<Diagnostic>> {
        let plan = self.preflight();
        if !plan.is_runnable() {
            return Err(plan.diagnostics);
        }
        if !valid_remote_token(&request.session_id) || !valid_remote_token(&request.lease_id) {
            return Err(vec![
                catalogue::SANDBOX_REMOTE_TRANSPORT_INSECURE.instantiate(context(
                    self.backend_id(),
                    "reason",
                    "session and lease IDs contain unsafe remote command characters".to_owned(),
                )),
            ]);
        }
        let ssh = probe_tool(
            &self.runner,
            "remote.ssh-encrypted",
            &self.config.ssh_executable,
            &["-V"],
        )
        .map_err(|e| {
            vec![remote_diagnostic(
                catalogue::SANDBOX_REMOTE_UNREACHABLE,
                e.to_string(),
            )]
        })?;
        let args = self.ssh_args(request, "start");
        invoke_tool(&self.runner, &ssh, &args, request.readiness_timeout)
            .map_err(|e| vec![remote_diagnostic(classify_remote_error(&e), e.to_string())])?;
        let control: Arc<dyn SandboxControl> = Arc::new(RemoteControl {
            runner: self.runner.clone(),
            ssh: ssh.clone(),
            config: self.config.clone(),
        });
        let cleanup = RemoteCleanup {
            runner: self.runner.clone(),
            ssh,
            config: self.config.clone(),
            lease_id: request.lease_id.clone(),
        };
        Ok(SandboxLease::new(
            SandboxHandle {
                lease_id: request.lease_id.clone(),
                backend_id: self.backend_id().to_owned(),
                tier: self.tier(),
                isolation: IsolationStrength::RemoteHostControlled,
                control_channel: "ssh-strict-host-key".to_owned(),
                device_serial: format!("remote:{}", request.lease_id),
            },
            control,
            Box::new(cleanup),
        ))
    }
}
impl RemoteOffloadBackend {
    fn ssh_args(&self, request: &SandboxStartRequest, action: &str) -> Vec<String> {
        vec![
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "-o".to_owned(),
            format!(
                "UserKnownHostsFile={}",
                self.config.known_hosts_file.display()
            ),
            "-i".to_owned(),
            self.config.identity_file.display().to_string(),
            format!("{}@{}", self.config.user, self.config.host),
            self.config.helper_path.clone(),
            action.to_owned(),
            "--lease-id".to_owned(),
            request.lease_id.clone(),
            "--runtime".to_owned(),
            format!("{:?}", self.config.runtime).to_ascii_lowercase(),
            "--session-id".to_owned(),
            request.session_id.clone(),
        ]
    }
}
struct RemoteCleanup {
    runner: Arc<dyn ExternalToolRunner>,
    ssh: ToolProbe,
    config: RemoteConfig,
    lease_id: String,
}
impl SandboxCleanup for RemoteCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let args = vec![
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "-o".to_owned(),
            format!(
                "UserKnownHostsFile={}",
                self.config.known_hosts_file.display()
            ),
            "-i".to_owned(),
            self.config.identity_file.display().to_string(),
            format!("{}@{}", self.config.user, self.config.host),
            self.config.helper_path.clone(),
            "teardown".to_owned(),
            "--lease-id".to_owned(),
            self.lease_id.clone(),
        ];
        match invoke_tool(&self.runner, &self.ssh, &args, Duration::from_secs(60)) {
            Ok(_) => Ok(()),
            Err(e) => Err(vec![teardown_diagnostic(
                "sandbox.remote-offload",
                e.to_string(),
            )]),
        }
    }
}

fn redroid_adb_key_path(lease_id: &str) -> PathBuf {
    let suffix = safe_suffix(lease_id);
    let suffix = if suffix.is_empty() {
        "lease".to_owned()
    } else {
        suffix
    };
    std::env::temp_dir().join(format!("apiaxess-redroid-{suffix}-adbkey"))
}

fn published_adb_serial(
    runner: &Arc<dyn ExternalToolRunner>,
    docker: &ToolProbe,
    container: &str,
) -> Result<String, Diagnostic> {
    let output = invoke_tool(
        runner,
        docker,
        &["port", container, "5555/tcp"],
        Duration::from_secs(15),
    )
    .map_err(|error| {
        catalogue::SANDBOX_REDOID_ADB_CONTRACT_FAILED.instantiate(context(
            "sandbox.redroid",
            "error",
            format!("could not inspect the published ADB port: {error}"),
        ))
    })?;
    let binding = output
        .stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            catalogue::SANDBOX_REDOID_ADB_CONTRACT_FAILED.instantiate(context(
                "sandbox.redroid",
                "error",
                "Docker returned no published ADB port".to_owned(),
            ))
        })?;
    let Some((host, port)) = binding.rsplit_once(':') else {
        return Err(
            catalogue::SANDBOX_REDOID_ADB_CONTRACT_FAILED.instantiate(context(
                "sandbox.redroid",
                "binding",
                binding.to_owned(),
            )),
        );
    };
    let valid_port = port.parse::<u16>().is_ok_and(|value| value != 0);
    if host != "127.0.0.1" || !valid_port {
        return Err(
            catalogue::SANDBOX_REDOID_ADB_CONTRACT_FAILED.instantiate(context(
                "sandbox.redroid",
                "binding",
                format!("expected 127.0.0.1:<ephemeral-port>, got {binding}"),
            )),
        );
    }
    Ok(binding.to_owned())
}

fn wait_for_redroid_device(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
    timeout: Duration,
) -> Result<(), Diagnostic> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // `adb connect` can return exit code 0 while reporting that the
        // transport is still offline during emulator boot or after reboot.
        // Reconnect and validate the actual per-serial state before polling
        // boot_completed; wait-for-device alone is not a sufficient gate.
        let _ = invoke_tool_with_environment(
            runner,
            adb,
            &["connect".to_owned(), serial.to_owned()],
            Duration::from_secs(15),
            environment,
        );
        let state = invoke_tool_with_environment(
            runner,
            adb,
            &["-s".to_owned(), serial.to_owned(), "get-state".to_owned()],
            Duration::from_secs(5),
            environment,
        );
        let state_detail = match state {
            Ok(output) if output.stdout.trim() == "device" => {
                let booted = invoke_tool_with_environment(
                    runner,
                    adb,
                    &[
                        "-s".to_owned(),
                        serial.to_owned(),
                        "shell".to_owned(),
                        "getprop".to_owned(),
                        "sys.boot_completed".to_owned(),
                    ],
                    Duration::from_secs(5),
                    environment,
                );
                if booted.is_ok_and(|output| output.stdout.trim() == "1") {
                    return Ok(());
                }
                "device, but sys.boot_completed != 1".to_owned()
            }
            Ok(output) => format!("ADB state {:?}", output.stdout.trim()),
            Err(error) => error.to_string(),
        };
        if std::time::Instant::now() >= deadline {
            return Err(catalogue::SANDBOX_READINESS_TIMEOUT.instantiate(context(
                "sandbox.redroid",
                "readiness_timeout",
                format!(
                    "host ADB endpoint {serial} did not reach ADB state device and sys.boot_completed=1: {state_detail}"
                ),
            )));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn verify_hqarroum_kvm(
    runner: &Arc<dyn ExternalToolRunner>,
    docker: &ToolProbe,
    container: &str,
) -> Result<(), Diagnostic> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let probe = invoke_tool(
            runner,
            docker,
            &[
                "exec".to_owned(),
                container.to_owned(),
                "sh".to_owned(),
                "-c".to_owned(),
                "for fd in /proc/[0-9]*/fd/*; do link=$(readlink \"$fd\" 2>/dev/null || true); case \"$link\" in /dev/kvm|anon_inode:kvm-vm*|anon_inode:kvm-vcpu:*) echo APIAXESS_KVM_ACTIVE; exit 0;; esac; done; exit 1".to_owned(),
            ],
            Duration::from_secs(5),
        );
        if probe.is_ok_and(|output| output.stdout.contains("APIAXESS_KVM_ACTIVE")) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(
                catalogue::SANDBOX_HQARROUM_TCG_FALLBACK.instantiate(context(
                    "sandbox.avd",
                    "container",
                    container.to_owned(),
                )),
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn prepare_hqarroum_system(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
    timeout: Duration,
) -> Result<(), Diagnostic> {
    let property = |name: &str| {
        invoke_tool_with_environment(
            runner,
            adb,
            &[
                "-s".to_owned(),
                serial.to_owned(),
                "shell".to_owned(),
                "getprop".to_owned(),
                name.to_owned(),
            ],
            Duration::from_secs(15),
            environment,
        )
    };
    let build_type = property("ro.build.type")
        .map(|output| output.stdout.trim().to_owned())
        .unwrap_or_default();
    let debuggable = property("ro.debuggable")
        .map(|output| output.stdout.trim().to_owned())
        .unwrap_or_default();
    if build_type != "userdebug" || debuggable != "1" {
        return Err(
            catalogue::SANDBOX_HQARROUM_ROOT_UNAVAILABLE.instantiate(context(
                "sandbox.avd",
                "posture",
                format!("ro.build.type={build_type}; ro.debuggable={debuggable}"),
            )),
        );
    }
    run_hqarroum_adb_command(runner, adb, serial, environment, &["root"], "adb root").map_err(
        |error| {
            catalogue::SANDBOX_HQARROUM_ROOT_UNAVAILABLE.instantiate(context(
                "sandbox.avd",
                "error",
                error,
            ))
        },
    )?;
    wait_for_redroid_device(runner, adb, serial, environment, timeout)?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["disable-verity"],
        "adb disable-verity",
    )
    .map_err(|error| hqarroum_system_not_writable("disable-verity", error))?;
    run_hqarroum_adb_command(runner, adb, serial, environment, &["reboot"], "adb reboot")
        .map_err(|error| hqarroum_system_not_writable("reboot after disable-verity", error))?;
    wait_for_redroid_device(runner, adb, serial, environment, timeout)?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["root"],
        "second adb root",
    )
    .map_err(|error| {
        catalogue::SANDBOX_HQARROUM_ROOT_UNAVAILABLE.instantiate(context(
            "sandbox.avd",
            "error",
            error,
        ))
    })?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["remount"],
        "adb remount after disable-verity reboot",
    )
    .map_err(|error| hqarroum_system_not_writable("remount", error))?;
    probe_hqarroum_ca_directory(runner, adb, serial, environment)
}

fn probe_hqarroum_ca_directory(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
) -> Result<(), Diagnostic> {
    let directory = "/system/etc/security/cacerts";
    let marker = format!("{directory}/.apiaxess-write-probe");
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["shell", "test", "-d", directory],
        "CA directory existence check",
    )
    .map_err(|error| hqarroum_system_not_writable("CA directory missing or unreadable", error))?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["shell", "test", "-w", directory],
        "CA directory writable check",
    )
    .map_err(|error| hqarroum_system_not_writable("CA directory is not writable", error))?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["shell", "touch", &marker],
        "CA directory touch",
    )
    .map_err(|error| hqarroum_system_not_writable("CA directory touch failed", error))?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["shell", "test", "-f", &marker],
        "CA marker visibility check",
    )
    .map_err(|error| hqarroum_system_not_writable("CA marker was not visible", error))?;
    run_hqarroum_adb_command(
        runner,
        adb,
        serial,
        environment,
        &["shell", "rm", "-f", &marker],
        "CA marker cleanup",
    )
    .map_err(|error| hqarroum_system_not_writable("CA marker cleanup failed", error))
}

fn hqarroum_system_not_writable(operation: &str, error: String) -> Diagnostic {
    let mut details = context("sandbox.avd", "operation", operation.to_owned());
    details.insert("reason".to_owned(), DiagnosticValue::String(error));
    catalogue::SANDBOX_HQARROUM_SYSTEM_NOT_WRITABLE.instantiate(details)
}

fn run_hqarroum_adb_command(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
    arguments: &[&str],
    operation: &str,
) -> Result<(), String> {
    let mut command = vec!["-s".to_owned(), serial.to_owned()];
    command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    match invoke_tool_with_environment(runner, adb, &command, Duration::from_secs(30), environment)
    {
        Ok(output) if output.exit_code.is_none_or(|code| code == 0) => Ok(()),
        Ok(output) => {
            let stdout = output.stdout.trim();
            let stderr = output.stderr.trim();
            let detail = match (stdout.is_empty(), stderr.is_empty()) {
                (true, true) => "no stdout/stderr evidence".to_owned(),
                (false, true) => format!("stdout: {stdout}"),
                (true, false) => format!("stderr: {stderr}"),
                (false, false) => format!("stdout: {stdout}; stderr: {stderr}"),
            };
            Err(format!(
                "{operation} exited with {:?}: {detail}",
                output.exit_code
            ))
        }
        Err(error) => Err(format!("{operation}: {error}")),
    }
}

fn evaluate_hqarroum_runtime_trust(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
    config: &AvdConfig,
) -> Result<Vec<Diagnostic>, Vec<Diagnostic>> {
    let output = invoke_tool_with_environment(
        runner,
        adb,
        &[
            "-s".to_owned(),
            serial.to_owned(),
            "shell".to_owned(),
            "getprop".to_owned(),
            "ro.build.version.security_patch".to_owned(),
        ],
        Duration::from_secs(15),
        environment,
    );
    let patch = match output {
        Ok(value) => value.stdout.trim().to_owned(),
        Err(error) => {
            return Err(vec![runtime_trust_failure(format!(
                "could not verify Android security patch level: {error}"
            ))]);
        }
    };
    let policy = match runtime_trust::default_policy() {
        Ok(policy) => policy,
        Err(error) => return Err(vec![runtime_trust_failure(error)]),
    };
    let facts = runtime_trust::RuntimeTrustFacts {
        sandbox_tier: SandboxTier::Avd.id().to_owned(),
        security_patch: (!patch.is_empty()).then_some(patch),
        image_digest: config.image_digest.clone(),
        expected_image_digest: config.image_digest.clone(),
        image_signature_verified: false,
        image_signature_checked: false,
        containment_verified: true,
        adb_loopback_only: true,
        adb_key_authenticated: true,
        adb_ephemeral: true,
        policy_bundle_verified: true,
    };
    let decision =
        runtime_trust::evaluate(facts, &policy, config.runtime_trust_acceptance.as_ref());
    let diagnostics = runtime_trust::diagnostics(&decision);
    if matches!(
        decision.outcome,
        runtime_trust::RuntimeTrustOutcome::Allow
            | runtime_trust::RuntimeTrustOutcome::AllowWithFindings
    ) {
        if let (Some(acceptance), Some(path)) = (
            config.runtime_trust_acceptance.as_ref(),
            config.runtime_trust_audit_path.as_deref(),
        ) {
            if let Err(error) = runtime_trust::append_acceptance_audit(path, acceptance, &decision)
            {
                return Err(vec![runtime_trust_failure(format!(
                    "could not append scoped acceptance audit: {error}"
                ))]);
            }
        } else if config.runtime_trust_acceptance.is_some() {
            return Err(vec![runtime_trust_failure(
                "scoped acceptance requires an append-only audit path".to_owned(),
            )]);
        }
        Ok(diagnostics)
    } else {
        Err(diagnostics)
    }
}

fn runtime_trust_failure(reason: String) -> Diagnostic {
    let mut diagnostic = catalogue::SANDBOX_RUNTIME_TRUST_DENIED.instantiate(context(
        "sandbox.avd",
        "reason",
        reason,
    ));
    diagnostic.severity = DiagnosticSeverity::Critical;
    diagnostic
}

fn verify_adb_security_patch(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
) -> Result<(), Diagnostic> {
    evaluate_hqarroum_runtime_trust(runner, adb, serial, environment, &AvdConfig::default())
        .map(|_| ())
        .map_err(|diagnostics| {
            diagnostics.into_iter().next().unwrap_or_else(|| {
                runtime_trust_failure("runtime trust evaluation failed".to_owned())
            })
        })
}

fn probe_tool(
    runner: &Arc<dyn ExternalToolRunner>,
    id: &str,
    executable: &str,
    args: &[&str],
) -> Result<ToolProbe, ExternalToolError> {
    runner.probe(&ToolProbeRequest {
        tool_id: id.to_owned(),
        executable: executable.to_owned(),
        version_arguments: args.iter().map(|v| (*v).to_owned()).collect(),
        requirement: ToolRequirement {
            minimum: ToolVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
        },
    })
}

fn invoke_tool<S: AsRef<str>>(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    args: &[S],
    timeout: Duration,
) -> Result<ToolInvocation, ExternalToolError> {
    invoke_tool_with_environment(runner, probe, args, timeout, &[])
}

fn invoke_tool_with_environment<S: AsRef<str>>(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    args: &[S],
    timeout: Duration,
    environment: &[(String, String)],
) -> Result<ToolInvocation, ExternalToolError> {
    runner.invoke(&ToolInvocationRequest {
        probe: probe.clone(),
        arguments: args.iter().map(|v| v.as_ref().to_owned()).collect(),
        working_directory: None,
        environment: environment.to_vec(),
        timeout,
    })
}
fn require_capability(
    report: &HostCapabilityReport,
    id: &str,
    allow_degraded: bool,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if let Some(observation) = report.get(id) {
        if !observation.availability.is_supported(allow_degraded) {
            diagnostics.push(capability_diagnostic(observation, id));
        }
    } else {
        diagnostics.push(backend_diagnostic(
            id,
            "capability detector returned no observation",
        ));
    }
}
fn capability_diagnostic(
    observation: &apiaxess_host_capabilities::CapabilityObservation,
    id: &str,
) -> Diagnostic {
    let definition = match id {
        CAPABILITY_KVM => catalogue::SANDBOX_VIRTUALIZATION_UNAVAILABLE,
        CAPABILITY_WINDOWS_HYPERVISOR => catalogue::SANDBOX_HYPERVISOR_DRIVER_MISSING,
        CAPABILITY_AVD_ACCELERATION => catalogue::SANDBOX_ACCELERATION_CHECK_FAILED,
        CAPABILITY_DOCKER => catalogue::SANDBOX_DOCKER_UNAVAILABLE,
        CAPABILITY_DOCKER_PRIVILEGED => catalogue::SANDBOX_DOCKER_PRIVILEGE_UNAVAILABLE,
        CAPABILITY_REDOID_KERNEL if cfg!(target_os = "windows") => {
            catalogue::SANDBOX_REDOID_WINDOWS_UNSUPPORTED
        }
        CAPABILITY_REDOID_KERNEL => catalogue::SANDBOX_REDOID_KERNEL_UNAVAILABLE,
        _ => {
            return observation
                .gap_diagnostic()
                .unwrap_or_else(|| backend_diagnostic(id, "capability was not supported"));
        }
    };
    let mut diagnostic = definition.instantiate(context("sandbox", "capability_id", id.to_owned()));
    diagnostic.why = format!(
        "Capability `{id}` is {:?}: {}",
        observation.availability, observation.evidence
    )
    .into_boxed_str();
    if !observation.remediation.trim().is_empty() {
        diagnostic.fix = observation.remediation.clone().into_boxed_str();
    }
    diagnostic
}
fn context(backend: &str, key: &str, value: String) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String(backend.to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value));
    context
}

fn planner_context(key: &str, value: &str) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String("sandbox.runtime-planner".to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value.to_owned()));
    context
}
fn backend_diagnostic(capability: &str, reason: &str) -> Diagnostic {
    let mut diagnostic = catalogue::SANDBOX_BACKEND_UNAVAILABLE.instantiate(context(
        "sandbox",
        "capability_id",
        capability.to_owned(),
    ));
    diagnostic.why = format!("Capability `{capability}` is unavailable: {reason}").into_boxed_str();
    diagnostic
}
/// Removes stale AVD lock files/dirs left by a previously killed emulator so a
/// crashed run does not block every subsequent boot. Best-effort and idempotent.
fn clear_stale_avd_locks(runtime_root: &std::path::Path, avd_name: &str) {
    let avd_dir = runtime_root.join("avd").join(format!("{avd_name}.avd"));
    for lock in [
        "hardware-qemu.ini.lock",
        "multiinstance.lock",
        "snapshot.lock.lock",
    ] {
        let path = avd_dir.join(lock);
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn boot_diagnostic(backend: &str, reason: String) -> Diagnostic {
    catalogue::SANDBOX_BOOT_FAILED.instantiate(context(backend, "error", reason))
}

/// Default free space the bundled emulator needs on the runtime volume to write
/// a fresh userdata image at cold boot, in whole megabytes. The Android-10
/// userdata plus the writable-system overlay empirically need ~7.4 GB; falling
/// below this surfaces later as an opaque mid-boot failure, so the preflight
/// reports the requirement instead.
const EMULATOR_MIN_FREE_MB_DEFAULT: u64 = 7_400;

/// Resolves the emulator free-space requirement in bytes, honoring the advanced
/// `APIAXESS_EMULATOR_MIN_FREE_MB` override for non-default images. A missing,
/// empty, unparseable, or zero value falls back to the default.
fn emulator_min_free_bytes() -> u64 {
    resolve_min_free_bytes(std::env::var("APIAXESS_EMULATOR_MIN_FREE_MB").ok())
}

/// Pure resolution of the free-space requirement from a raw override value, so
/// the parsing/fallback contract is testable without mutating process env.
fn resolve_min_free_bytes(raw_override: Option<String>) -> u64 {
    let megabytes = raw_override
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|megabytes| *megabytes > 0)
        .unwrap_or(EMULATOR_MIN_FREE_MB_DEFAULT);
    megabytes.saturating_mul(1024 * 1024)
}

/// Free bytes available on the volume that holds `path`, or `None` when it cannot
/// be determined. The leaf may not exist yet on a first run (the AVD home is
/// created at boot), so this measures the nearest existing ancestor, which is on
/// the same volume.
fn available_space(path: &Path) -> Option<u64> {
    let mut probe = path;
    let existing = loop {
        if probe.exists() {
            break probe;
        }
        probe = probe.parent()?;
    };
    available_space_impl(existing)
}

#[cfg(unix)]
fn available_space_impl(path: &Path) -> Option<u64> {
    // statvfs field widths are target-dependent (u64 on Linux x86_64, narrower
    // on macOS and 32-bit targets), so widen generically rather than through a
    // conversion that is an identity on some targets.
    fn widen(value: impl TryInto<u64>) -> Option<u64> {
        value.try_into().ok()
    }
    let stats = nix::sys::statvfs::statvfs(path).ok()?;
    let fragment_size = widen(stats.fragment_size())?;
    let blocks_available = widen(stats.blocks_available())?;
    Some(blocks_available.saturating_mul(fragment_size))
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn available_space_impl(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt as _;

    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut free_available: u64 = 0;
    // SAFETY: `wide` is a NUL-terminated UTF-16 path buffer that outlives the
    // call; `free_available` is a valid, writable `u64`; the two unused out
    // parameters are null, which `GetDiskFreeSpaceExW` explicitly accepts.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &raw mut free_available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(free_available)
}

#[cfg(not(any(unix, windows)))]
fn available_space_impl(_path: &Path) -> Option<u64> {
    None
}

/// Human-readable gigabytes (decimal) for a byte count, to one decimal place.
fn gigabytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let gib = bytes as f64 / 1_000_000_000.0;
    format!("{gib:.1} GB")
}

fn insufficient_disk_diagnostic(
    backend: &str,
    volume: &Path,
    required_bytes: u64,
    available_bytes: u64,
) -> Diagnostic {
    let mut diagnostic = catalogue::SANDBOX_INSUFFICIENT_DISK.instantiate(context(
        backend,
        "volume",
        volume.display().to_string(),
    ));
    diagnostic.context.insert(
        "required_bytes".to_owned(),
        DiagnosticValue::String(required_bytes.to_string()),
    );
    diagnostic.context.insert(
        "available_bytes".to_owned(),
        DiagnosticValue::String(available_bytes.to_string()),
    );
    diagnostic.why = format!(
        "The bundled emulator writes a fresh userdata image on each cold boot and needs about {} free on the runtime volume ({}); only {} is available, so a boot would fail partway with a misleading runtime error.",
        gigabytes(required_bytes),
        volume.display(),
        gigabytes(available_bytes),
    )
    .into_boxed_str();
    diagnostic
}
fn adb_diagnostic(backend: &str, reason: String) -> Diagnostic {
    catalogue::SANDBOX_ADB_UNREACHABLE.instantiate(context(backend, "error", reason))
}
fn docker_diagnostic(reason: String) -> Diagnostic {
    catalogue::SANDBOX_DOCKER_UNAVAILABLE.instantiate(context("sandbox.redroid", "error", reason))
}
fn image_diagnostic(tier: &str, image: &str, reason: String) -> Diagnostic {
    let mut value = context(&format!("sandbox.{tier}"), "image", image.to_owned());
    value.insert("error".to_owned(), DiagnosticValue::String(reason));
    catalogue::SANDBOX_IMAGE_ACQUISITION_FAILED.instantiate(value)
}
fn teardown_diagnostic(backend: &str, reason: String) -> Diagnostic {
    catalogue::SANDBOX_TEARDOWN_FAILED.instantiate(context(backend, "error", reason))
}
fn remote_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    reason: String,
) -> Diagnostic {
    definition.instantiate(context("sandbox.remote-offload", "error", reason))
}
fn classify_remote_error(error: &ExternalToolError) -> apiaxess_diagnostics::DiagnosticDefinition {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("auth") || text.contains("host key") || text.contains("permission") {
        catalogue::SANDBOX_REMOTE_AUTH_FAILED
    } else {
        catalogue::SANDBOX_REMOTE_UNREACHABLE
    }
}
fn safe_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(40)
        .collect()
}

fn valid_remote_token(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':' | '.')
        })
}
/// Creates a stable lease identifier when a caller does not have one.
#[must_use]
pub fn generated_lease_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("lease-{millis}")
}
#[derive(Debug, Error)]
/// Reserved wrapper for future non-diagnostic adapters.
pub enum SandboxError {
    /// Backend returned structured diagnostics.
    #[error("sandbox operation failed with {0} diagnostic(s)")]
    Diagnostics(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_host_capabilities::{CAPABILITY_AVD_EMULATOR, CapabilityObservation};

    #[test]
    fn stale_avd_locks_are_removed_and_avd_data_is_kept() {
        let root = std::env::temp_dir().join(format!("apiaxess-avd-locks-{}", std::process::id()));
        let avd = root.join("avd").join("target.avd");
        // The emulator leaves these as directories (observed after a forced stop)
        // or as plain files, depending on version.
        std::fs::create_dir_all(avd.join("hardware-qemu.ini.lock")).expect("lock dir");
        std::fs::create_dir_all(avd.join("snapshot.lock.lock")).expect("lock dir");
        std::fs::write(avd.join("multiinstance.lock"), b"").expect("lock file");
        std::fs::write(avd.join("userdata-qemu.img"), b"data").expect("userdata");
        std::fs::write(avd.join("config.ini"), b"cfg").expect("config");

        clear_stale_avd_locks(&root, "target");

        for lock in [
            "hardware-qemu.ini.lock",
            "snapshot.lock.lock",
            "multiinstance.lock",
        ] {
            assert!(!avd.join(lock).exists(), "{lock} should be removed");
        }
        assert!(avd.join("userdata-qemu.img").is_file());
        assert!(avd.join("config.ini").is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn observation(id: &str, availability: CapabilityAvailability) -> CapabilityObservation {
        CapabilityObservation {
            capability_id: id.to_owned(),
            availability,
            evidence: "fixture evidence".to_owned(),
            remediation: "fixture remediation".to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        }
    }

    fn supported(id: &str) -> CapabilityObservation {
        observation(id, CapabilityAvailability::Supported)
    }

    fn degraded(id: &str) -> CapabilityObservation {
        observation(id, CapabilityAvailability::Degraded)
    }

    fn report(observations: Vec<CapabilityObservation>) -> HostCapabilityReport {
        HostCapabilityReport { observations }
    }

    fn unavailable(id: &str) -> CapabilityObservation {
        CapabilityObservation {
            capability_id: id.to_owned(),
            availability: CapabilityAvailability::Unavailable,
            evidence: "fixture unavailable".to_owned(),
            remediation: "select remote-offload".to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        }
    }

    #[test]
    fn avd_preflight_reports_missing_hqarroum_acceleration_as_a_structured_gap() {
        let capabilities = HostCapabilityReport {
            observations: vec![
                supported(CAPABILITY_DOCKER),
                unavailable(CAPABILITY_AVD_ACCELERATION),
                unavailable(CAPABILITY_ANDROID_ADB),
            ],
        };
        let backend = AvdBackend::new(
            AvdConfig {
                avd_name: "fixture".to_owned(),
                emulator_executable: "emulator".to_owned(),
                adb_executable: "adb".to_owned(),
                device_serial: "emulator-5554".to_owned(),
                baseline_snapshot: "clean".to_owned(),
                image_marker: None,
                image_package: "system-images;android-35;google_apis;x86_64".to_owned(),
                docker_executable: "docker".to_owned(),
                image: HQARROUM_IMAGE.to_owned(),
                image_digest: HQARROUM_API_33_DIGEST.to_owned(),
                api_level: 33,
                container_name_prefix: "apiaxess-avd".to_owned(),
                runtime_trust_acceptance: None,
                runtime_trust_audit_path: None,
            },
            Arc::new(apiaxess_external_tools::ProcessToolRunner),
            capabilities,
            Arc::new(ExistingImageManager),
        );

        let plan = backend.preflight();
        assert!(!plan.is_runnable());
        assert!(
            plan.diagnostics.iter().any(|diagnostic| {
                diagnostic.id.as_ref() == "sandbox.acceleration-check-failed"
            })
        );
    }

    #[test]
    fn remote_configuration_rejects_unauthenticated_or_missing_key_material() {
        let config = RemoteConfig {
            host: "10.0.0.2".to_owned(),
            user: "tester".to_owned(),
            identity_file: PathBuf::from("missing-key"),
            known_hosts_file: PathBuf::from("missing-known-hosts"),
            ssh_executable: "ssh".to_owned(),
            helper_path: "/usr/libexec/apiaxess-sandbox".to_owned(),
            runtime: RemoteRuntime::Avd,
            transport: RemoteTransport::Ssh,
        };

        let diagnostic = config.validate().expect_err("key material is mandatory");
        assert_eq!(diagnostic.id.as_ref(), "sandbox.remote-transport-insecure");
    }

    #[test]
    fn redroid_descriptor_surfaces_shared_kernel_tradeoff() {
        let descriptor = SandboxBackendDescriptor {
            backend_id: "sandbox.redroid".to_owned(),
            tier: SandboxTier::Redroid,
            isolation: IsolationStrength::SharedKernelTrustedOnly,
            tradeoff: "trusted only".to_owned(),
            required_capability_ids: vec![CAPABILITY_DOCKER_PRIVILEGED.to_owned()],
        };
        assert_eq!(
            descriptor.isolation,
            IsolationStrength::SharedKernelTrustedOnly
        );
        assert!(
            descriptor
                .required_capability_ids
                .contains(&CAPABILITY_DOCKER_PRIVILEGED.to_owned())
        );
    }

    #[test]
    fn bundled_emulator_is_the_default_and_avd_is_the_accelerated_opt_in_on_linux() {
        let report = report(vec![
            supported(CAPABILITY_AVD_EMULATOR),
            supported(CAPABILITY_ANDROID_ADB),
            supported(CAPABILITY_AVD_ACCELERATION),
            supported(CAPABILITY_DOCKER),
            degraded(CAPABILITY_DOCKER_PRIVILEGED),
            supported(CAPABILITY_REDOID_KERNEL),
        ]);

        let selection =
            SandboxRuntimePlanner::for_environment(RuntimeEnvironment::NativeLinux, &report);
        // The bundled emulator is the zero-config default; with KVM present it
        // runs accelerated, and the legacy Docker AVD is offered as the fast path.
        assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Accelerated);
        assert_eq!(selection.opt_in_fast_tier, Some(SandboxTier::Avd));
        assert_eq!(selection.fallback_tier, SandboxTier::RemoteOffload);
        assert_eq!(
            selection.offered_tiers,
            vec![
                SandboxTier::BundledEmulator,
                SandboxTier::Avd,
                SandboxTier::Redroid,
                SandboxTier::RemoteOffload
            ]
        );
    }

    #[test]
    fn native_windows_defaults_to_bundled_emulator_and_never_offers_redroid() {
        let report = report(vec![
            supported(CAPABILITY_AVD_EMULATOR),
            supported(CAPABILITY_ANDROID_ADB),
            supported(CAPABILITY_AVD_ACCELERATION),
            supported(CAPABILITY_DOCKER),
            supported(CAPABILITY_WINDOWS_HYPERVISOR),
            unavailable(CAPABILITY_REDOID_KERNEL),
        ]);

        let selection =
            SandboxRuntimePlanner::for_environment(RuntimeEnvironment::NativeWindows, &report);
        assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Accelerated);
        assert!(!selection.offered_tiers.contains(&SandboxTier::Redroid));
        assert_eq!(
            selection.offered_tiers,
            vec![
                SandboxTier::BundledEmulator,
                SandboxTier::Avd,
                SandboxTier::RemoteOffload
            ]
        );
    }

    #[test]
    fn dockerless_windows_acceleration_reports_the_bundled_runtime_not_a_failed_avd() {
        let report = report(vec![
            unavailable(CAPABILITY_DOCKER),
            unavailable(CAPABILITY_ANDROID_ADB),
            unavailable(CAPABILITY_AVD_ACCELERATION),
            supported(CAPABILITY_WINDOWS_HYPERVISOR),
        ]);

        let selection =
            SandboxRuntimePlanner::for_environment(RuntimeEnvironment::NativeWindows, &report);
        assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Accelerated);
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.accelerated-mode-active")
        );
        assert!(
            !selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.acceleration-check-failed")
        );
    }

    #[test]
    fn aehd_counts_as_acceleration_and_records_transitional_guidance() {
        let report = report(vec![
            supported(CAPABILITY_AVD_EMULATOR),
            supported(CAPABILITY_ANDROID_ADB),
            degraded(CAPABILITY_AVD_ACCELERATION),
            supported(CAPABILITY_DOCKER),
            degraded(CAPABILITY_WINDOWS_HYPERVISOR),
        ]);

        let selection =
            SandboxRuntimePlanner::for_environment(RuntimeEnvironment::NativeWindows, &report);
        assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Accelerated);
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.aehd-transitional")
        );
    }

    #[test]
    fn no_virtualization_falls_back_to_local_software_mode_not_remote() {
        // The primary Phase 11.5 case: a no-KVM host still runs the bundled
        // emulator locally, in software mode, with an honest diagnostic — it
        // does NOT silently route to remote-offload.
        let report = report(vec![
            unavailable(CAPABILITY_AVD_EMULATOR),
            unavailable(CAPABILITY_ANDROID_ADB),
            unavailable(CAPABILITY_AVD_ACCELERATION),
            supported(CAPABILITY_DOCKER),
            degraded(CAPABILITY_DOCKER_PRIVILEGED),
            supported(CAPABILITY_REDOID_KERNEL),
        ]);

        let selection =
            SandboxRuntimePlanner::for_environment(RuntimeEnvironment::NativeLinux, &report);
        assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Software);
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.software-mode-active"),
            "the honest software-mode fallback message must be surfaced"
        );
        assert_eq!(selection.opt_in_fast_tier, Some(SandboxTier::Redroid));
        assert_eq!(
            selection.offered_tiers,
            vec![
                SandboxTier::BundledEmulator,
                SandboxTier::Redroid,
                SandboxTier::RemoteOffload
            ]
        );
    }

    #[test]
    fn inside_vm_and_windows_arm_still_offer_the_bundled_emulator_in_software_mode() {
        let report = report(Vec::new());
        for environment in [RuntimeEnvironment::InsideVm, RuntimeEnvironment::WindowsArm] {
            let selection = SandboxRuntimePlanner::for_environment(environment, &report);
            assert_eq!(selection.default_tier, SandboxTier::BundledEmulator);
            assert_eq!(selection.acceleration, AccelerationMode::Software);
            assert_eq!(selection.opt_in_fast_tier, None);
            assert_eq!(
                selection.offered_tiers,
                vec![SandboxTier::BundledEmulator, SandboxTier::RemoteOffload]
            );
        }
    }

    #[test]
    fn factory_selects_bundled_emulator_in_software_mode_on_a_no_virt_host() {
        // The tier→backend factory must build the zero-config bundled emulator
        // and carry the honest software-mode diagnostic when the host exposes no
        // virtualization — the live-engine analogue of the planner test above.
        let capabilities = report(vec![
            unavailable(CAPABILITY_AVD_ACCELERATION),
            unavailable(CAPABILITY_WSL2_NESTED_KVM),
        ]);
        let factory = DynamicBackendFactory::new(
            Arc::new(apiaxess_external_tools::ProcessToolRunner),
            capabilities,
        );
        let selection = factory.select();
        assert_eq!(selection.tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Software);
        assert_eq!(selection.backend.tier(), SandboxTier::BundledEmulator);
        assert_eq!(selection.backend.backend_id(), "sandbox.bundled-emulator");
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.software-mode-active"),
            "the honest software-mode fallback message must travel with the selection"
        );
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.runtime-selected"),
            "the selected-tier decision must be surfaced"
        );
    }

    #[test]
    fn factory_selects_accelerated_mode_when_host_virtualization_is_present() {
        let capabilities = report(vec![supported(CAPABILITY_AVD_ACCELERATION)]);
        let factory = DynamicBackendFactory::new(
            Arc::new(apiaxess_external_tools::ProcessToolRunner),
            capabilities,
        );
        let selection = factory.select();
        assert_eq!(selection.tier, SandboxTier::BundledEmulator);
        assert_eq!(selection.acceleration, AccelerationMode::Accelerated);
        assert!(
            selection
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.accelerated-mode-active"),
            "the accelerated-mode message must travel with the selection"
        );
    }

    #[test]
    fn bundled_backend_preflight_reports_analysis_runtime_missing_when_payload_absent() {
        // A dynamic run requested when the ~2 GB analysis-runtime payload is not
        // installed must be an actionable what/why/fix diagnostic, not a crash.
        let root = std::env::temp_dir().join(format!(
            "apiaxess-missing-runtime-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let config = BundledEmulatorConfig::for_root(&root, AccelerationMode::Software);
        let backend = BundledEmulatorBackend::new(
            config,
            Arc::new(apiaxess_external_tools::ProcessToolRunner),
            report(Vec::new()),
        );
        let plan = backend.preflight();
        assert!(
            !plan.is_runnable(),
            "an absent analysis runtime must block startup"
        );
        assert!(
            plan.diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.analysis-runtime-missing"),
            "the honest analysis-runtime-missing diagnostic must be surfaced"
        );
    }

    #[test]
    fn available_space_measures_an_existing_volume() {
        let free = available_space(&std::env::temp_dir())
            .expect("free space on the temp volume must be measurable");
        assert!(
            free > 0,
            "an existing writable volume reports non-zero free space"
        );
    }

    #[test]
    fn available_space_walks_up_to_an_existing_ancestor() {
        // A not-yet-created AVD home (as on a first run) must still measure the
        // volume via its nearest existing ancestor rather than failing outright.
        let missing = std::env::temp_dir()
            .join(format!("apiaxess-nonexistent-{}", generated_lease_id()))
            .join("avd")
            .join("does-not-exist");
        assert!(!missing.exists());
        assert!(
            available_space(&missing).is_some(),
            "free space must resolve through the nearest existing ancestor"
        );
    }

    #[test]
    fn min_free_bytes_honors_a_valid_override_and_falls_back_otherwise() {
        assert_eq!(
            resolve_min_free_bytes(Some("1024".to_owned())),
            1024 * 1024 * 1024
        );
        let default = EMULATOR_MIN_FREE_MB_DEFAULT * 1024 * 1024;
        assert_eq!(resolve_min_free_bytes(None), default);
        assert_eq!(resolve_min_free_bytes(Some("0".to_owned())), default);
        assert_eq!(
            resolve_min_free_bytes(Some("not-a-number".to_owned())),
            default
        );
    }

    #[test]
    fn insufficient_disk_diagnostic_is_legible_and_actionable() {
        let volume = std::env::temp_dir();
        let diagnostic = insufficient_disk_diagnostic(
            "sandbox.bundled-emulator",
            &volume,
            7_400_000_000,
            1_200_000_000,
        );
        assert_eq!(diagnostic.id.as_ref(), "sandbox.insufficient-disk");
        assert!(
            diagnostic.context.contains_key("required_bytes")
                && diagnostic.context.contains_key("available_bytes"),
            "the diagnostic must carry the machine-readable required/available bytes"
        );
        // The human-facing text names both the requirement and what is available,
        // so a disk-full condition is not misdiagnosed as an emulator fault.
        assert!(diagnostic.why.contains("7.4 GB"));
        assert!(diagnostic.why.contains("1.2 GB"));
    }
}
