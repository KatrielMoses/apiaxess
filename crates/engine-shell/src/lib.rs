//! Core orchestration shell.
//!
//! The recovered-API domain model is supplied by `apiaxess-api-model`. Analysis
//! orchestration remains absent. This crate can see the canonical model and
//! plugin-host facade, never concrete target or brain implementations.

mod browser;
mod export;
mod pipeline;
mod session_runtime;

pub use export::{
    ExportConfig, ExportFormat, ExportReport, ExportedArtifact, export_session_artifacts,
};
pub use pipeline::{
    PipelineConfig, PipelineFailure, PipelineProgress, PipelineProgressCallback, PipelineReport,
    PipelineRunStatus, PipelineStage, run_pipeline,
};
pub use session_runtime::{SessionRuntime, SessionStatus, fresh_session_id};

/// In-memory, zeroize-on-drop credential value used to stage operator-supplied
/// sign-in credentials for a dynamic crawl.
pub use apiaxess_app_crawler::Secret;

/// Canonical API-surface model consumed and produced by engine orchestration.
pub use apiaxess_api_model as api_model;
/// Canonical structured diagnostic framework used by every engine boundary.
pub use apiaxess_diagnostics as diagnostics;
/// Dynamic Phase-3.5 capture extractor.
pub use apiaxess_dynamic_capture as dynamic_capture;
/// Re-exported so the local API can construct a device pinning-bypass request
/// (Phase C4) for [`Engine::bypass_pinning_on_device`] without depending on the
/// sandbox crate directly.
pub use apiaxess_sandbox::pinning::{BypassRequest as DeviceBypassRequestSpec, TargetInventory};
/// Canonical session aggregate consumed by future feature orchestration.
pub use apiaxess_session as session;

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use apiaxess_confidence::ConfidenceConfig;
use apiaxess_external_tools::ManagedProcessCommand;
use apiaxess_plugin_host::PluginHost;
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AllowedNetworkTarget,
    AuditActor, EngagementScope, HostMatch, Session, TargetIdentifier, TargetIdentity,
};
use apiaxess_workbench_proxy::{
    BackendHealth, BrowserKind, BrowserTrustController, BrowserTrustStatus, FuzzerWorkbench,
    LiveWorkbench, OriginTaggingSender, ResendSender, ResendWorkbench, SessionCa,
};
use apiaxess_workbench_store::TrafficStore;
use apiaxess_workbench_store::{
    DelayPolicy, FlowOrigin, FuzzerAttackType, FuzzerConfig, FuzzerMatchFilter,
    FuzzerPositionLocation, GrepConfig, PayloadPosition, PayloadSet, PayloadSource, RedirectPolicy,
    ResendRequest, RetryPolicy,
};
use serde::Serialize;

use browser::{BrowserChild, bootstrap_cdp, spawn_browser};

/// Minimal engine handle shared with transport adapters.
#[derive(Clone, Debug)]
pub struct Engine {
    _plugin_host: Arc<PluginHost>,
    live_workbench: Arc<LiveWorkbench>,
    resend: Arc<ResendWorkbench>,
    fuzzer: Arc<FuzzerWorkbench>,
    browser_trust: Arc<BrowserTrustController>,
    session_ca: Arc<RwLock<Option<SessionCa>>>,
    browser_launch: Arc<std::sync::Mutex<Option<ActiveBrowserLaunch>>>,
    proxy_address: Arc<RwLock<Option<std::net::SocketAddr>>>,
    session_runtime: Arc<RwLock<Option<Arc<SessionRuntime>>>>,
    proxy_health: Arc<RwLock<Option<BackendHealth>>>,
    /// Devices provisioned this session (Phase C5). Retained so the installed
    /// system-CA/tunnel state can be torn down on shutdown rather than leaking.
    provisioned_devices:
        Arc<std::sync::Mutex<Vec<apiaxess_sandbox::device_provision::ProvisionedDevice>>>,
    /// The GUI Android target booted this session (Phase D1), if any. Retained so
    /// the emulator process is stopped on shutdown rather than left running.
    android_target:
        Arc<std::sync::Mutex<Option<apiaxess_sandbox::android_target::BootedAndroidTarget>>>,
    /// The loopback ws-scrcpy screen stream for the GUI Android target (Phase D2),
    /// if running. Retained so the Node process is stopped on shutdown; the engine
    /// reverse-proxies its port behind the workbench gate — never reachable directly.
    android_stream:
        Arc<std::sync::Mutex<Option<apiaxess_sandbox::android_target::AndroidTargetStream>>>,
    /// Live lifecycle of the GUI Android target (Phase D3), polled by the workbench
    /// panel for per-step progress and honest failures.
    android_status: Arc<RwLock<AndroidTargetStatus>>,
    /// Guards against a second concurrent launch while one is in flight.
    android_launching: Arc<AtomicBool>,
    /// Static analysis of the APK installed onto the Android target, keyed by
    /// the session it was installed in, so Fuse can fuse it with the live drive.
    android_static: Arc<std::sync::Mutex<Option<(String, AndroidStaticAnalysis)>>>,
    /// The id of the active discovery job (see [`Engine::start_discovery`]),
    /// while one is running. Single-flighted: a second run is refused until this
    /// one finishes or is cancelled, so no un-cancellable ffuf orphan is ever
    /// left probing the target after the UI reports STOPPED.
    active_discovery: Arc<std::sync::Mutex<Option<String>>>,
}

/// Outcome of launching the GUI Android target add-on (Phase D1): the booted,
/// first-boot-provisioned target the operator will stream (D2) and drive (D3).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTargetLaunchReport {
    /// adb serial of the booted target (`emulator-<port>`).
    pub serial: String,
    /// The ws-scrcpy port Phase D2 will stream over.
    pub ws_scrcpy_port: u16,
    /// Detected Android API level of the target image.
    pub android_sdk: u32,
    /// Whether the first-party client APK was installed on first boot.
    pub client_apk_installed: bool,
    /// Whether the device-side frida-server is running.
    pub frida_server_started: bool,
    /// Whether the loopback ws-scrcpy screen stream started (Phase D2). The engine
    /// reverse-proxies it behind the workbench gate; D3 wires the view.
    pub streaming: bool,
    /// The device-wide proxy the target's traffic is captured through, when
    /// capture routing is active.
    pub capture_proxy: Option<String>,
    /// Why capture routing is not active, when it was attempted and failed.
    pub capture_issue: Option<String>,
    /// Ordered step diagnostics (info plus any non-fatal warnings).
    pub diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
}

/// The live phase of the GUI Android target (Phase D3), for the workbench panel to
/// render legible per-step progress and honest failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AndroidTargetPhase {
    /// No target has been launched (or one was stopped).
    Idle,
    /// The AVD is booting headless.
    Booting,
    /// First-boot C2/C5 provisioning is running (client APK, CA, frida-server).
    Provisioning,
    /// The loopback ws-scrcpy screen stream is starting.
    Streaming,
    /// The target is booted, provisioned, and (if available) streaming.
    Ready,
    /// The launch failed; `diagnostics` carries the actionable what/why/fix.
    Error,
}

/// A captured WebSocket connection with its first-/third-party label.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WsConnectionView {
    /// The connection as persisted.
    #[serde(flatten)]
    pub connection: apiaxess_workbench_store::WsConnectionRecord,
    /// First- or third-party, when classifiable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub party: Option<apiaxess_api_model::HostParty>,
}

/// The outcome of importing a HAR into the active session.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarImportReport {
    /// Flows imported.
    pub imported: usize,
    /// The scope derived from the HAR, when the session had none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_scope: Option<HarDerivedScope>,
}

/// A scope derived from an imported HAR's own hosts.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarDerivedScope {
    /// Hosts put in scope, each as an exact-host rule.
    pub hosts: Vec<String>,
    /// The HAR's other hosts, left out of scope as third-party.
    pub excluded_hosts: Vec<String>,
}

/// Static analysis of the APK installed onto the Android target.
#[derive(Clone, Debug)]
enum AndroidStaticAnalysis {
    Running,
    Ready(Box<apiaxess_api_model::ApiDocument>),
    Failed(String),
}

/// The Android target panel's view of that static analysis.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidStaticAnalysisStatus {
    /// `running`, `ready`, or `failed`.
    pub state: &'static str,
    /// Endpoints the static pass recovered, when ready.
    pub endpoint_count: Option<usize>,
    /// Why it failed, when it did.
    pub message: Option<String>,
}

/// A snapshot of the GUI Android target's lifecycle for the workbench panel.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent status flags, not a state enum.
pub struct AndroidTargetStatus {
    /// The current phase.
    pub phase: AndroidTargetPhase,
    /// A short, operator-facing status line for the current phase.
    pub message: String,
    /// Whether the add-on payload is installed at all (drives the "download it"
    /// empty state).
    pub addon_present: bool,
    /// adb serial of the booted target, once booting has started.
    pub serial: Option<String>,
    /// The ws-scrcpy port the authenticated view is reverse-proxied from, when
    /// streaming.
    pub ws_scrcpy_port: Option<u16>,
    /// Whether the loopback screen stream is running.
    pub streaming: bool,
    /// Whether the first-party client APK was installed on first boot.
    pub client_apk_installed: bool,
    /// Whether the device-side frida-server is running.
    pub frida_server_started: bool,
    /// Detected Android API level, once provisioning has read it.
    pub android_sdk: Option<u32>,
    /// The device-wide proxy the target's app traffic is routed through to the
    /// workbench MITM (`127.0.0.1:<port>`), when capture is active.
    pub capture_proxy: Option<String>,
    /// Why the target's traffic is not being captured, when routing was
    /// attempted and failed. `None` with no `capture_proxy` means not yet set up.
    pub capture_issue: Option<String>,
    /// Static analysis of the installed APK, fused with the live drive on Fuse.
    pub static_analysis: Option<AndroidStaticAnalysisStatus>,
    /// Package of the APK installed onto the target from this panel, which
    /// "Open app" launches. Cleared when the target stops or relaunches.
    pub installed_package: Option<String>,
    /// File name of that APK, for the panel's installed state.
    pub installed_apk: Option<String>,
    /// Why the installed APK's package could not be read (the install itself
    /// succeeded), so the panel can explain a missing "Open app".
    pub install_note: Option<String>,
    /// The latest step diagnostics (info, warnings, or the failure on `Error`).
    pub diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
}

impl Default for AndroidTargetStatus {
    fn default() -> Self {
        Self {
            phase: AndroidTargetPhase::Idle,
            message: "No Android target is running.".to_owned(),
            addon_present: false,
            serial: None,
            ws_scrcpy_port: None,
            streaming: false,
            client_apk_installed: false,
            frida_server_started: false,
            android_sdk: None,
            capture_proxy: None,
            capture_issue: None,
            static_analysis: None,
            installed_package: None,
            installed_apk: None,
            install_note: None,
            diagnostics: Vec::new(),
        }
    }
}

/// Discovery operation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryKind {
    /// Probe candidate subdomains.
    Subdomain,
    /// Probe candidate URL paths.
    Directory,
}

/// Estimate shown before an active discovery run.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryEstimate {
    /// Session web target.
    pub target: String,
    /// Selected wordlist name.
    pub wordlist: String,
    /// Number of requests.
    pub request_count: usize,
    /// Calibrated requests per second.
    pub rate_per_second: u32,
    /// Estimated duration in seconds.
    pub estimated_seconds: u64,
    /// Human-readable duration.
    pub estimated_label: String,
}

/// Real, widely-used wordlists bundled with the application (curated from
/// `SecLists` and the APIaxess-curated `large` list). They are shipped in the
/// binary so discovery works offline; anything else can be supplied by upload.
const LARGE_WORDLIST: &str = include_str!("wordlists/large.txt");
const COMMON_WORDLIST: &str = include_str!("wordlists/common.txt");
const RAFT_SMALL_DIRECTORIES: &str = include_str!("wordlists/raft-small-directories.txt");
const API_ENDPOINTS_WORDLIST: &str = include_str!("wordlists/api-endpoints.txt");
const SUBDOMAINS_TOP_5000: &str = include_str!("wordlists/subdomains-top5000.txt");
const SUBDOMAINS_TOP_20000: &str = include_str!("wordlists/subdomains-top20000.txt");

/// One bundled wordlist's catalogue entry, surfaced to the GUI so the operator
/// picks by real name rather than an opaque "small/medium/large".
#[derive(Clone, serde::Serialize)]
pub struct WordlistInfo {
    /// Stable id sent back on a discovery request.
    pub id: String,
    /// Human name shown in the picker.
    pub label: String,
    /// "directory" or "subdomain" — which discovery type it suits.
    pub kind: String,
    /// Number of entries (so the request-count estimate is honest up front).
    pub count: usize,
    /// Provenance/source of the list.
    pub source: String,
}

/// Parses a bundled wordlist file, dropping blank lines and `#` comments.
fn parse_wordlist(contents: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter(|line| seen.insert(line.to_owned()))
        .map(str::to_owned)
        .collect()
}

/// Every bundled wordlist keyed by id, with the raw content.
fn bundled_wordlist_sources() -> &'static [(&'static str, &'static str, &'static str, &'static str)]
{
    // (id, label, kind, raw)
    &[
        ("quick", "Quick sample (8)", "directory", ""),
        ("common", "SecLists common.txt", "directory", COMMON_WORDLIST),
        ("raft-small-directories", "SecLists raft-small-directories", "directory", RAFT_SMALL_DIRECTORIES),
        ("api-endpoints", "SecLists api-endpoints", "directory", API_ENDPOINTS_WORDLIST),
        ("large", "APIaxess curated", "directory", LARGE_WORDLIST),
        ("subdomains-top-5000", "SecLists subdomains top 5000", "subdomain", SUBDOMAINS_TOP_5000),
        ("subdomains-top-20000", "SecLists subdomains top 20000", "subdomain", SUBDOMAINS_TOP_20000),
    ]
}

/// The wordlist picker catalogue for the GUI.
#[must_use]
pub fn bundled_wordlist_catalogue() -> Vec<WordlistInfo> {
    bundled_wordlist_sources()
        .iter()
        .map(|(id, label, kind, raw)| {
            let count = if *id == "quick" { 8 } else { parse_wordlist(raw).len() };
            WordlistInfo {
                id: (*id).to_owned(),
                label: (*label).to_owned(),
                kind: (*kind).to_owned(),
                count,
                source: if *id == "large" { "APIaxess".to_owned() } else if *id == "quick" { "built-in".to_owned() } else { "SecLists".to_owned() },
            }
        })
        .collect()
}

/// Wordlists shipped with the application. `quick` and the legacy `small`/`medium`
/// are tiny built-ins; every other id resolves a bundled SecLists/curated file.
pub fn bundled_wordlist(name: &str) -> Option<Vec<String>> {
    match name {
        "small" | "quick" => Some(
            ["www", "api", "app", "dev", "staging", "admin", "v1", "health"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        "medium" => Some(
            [
                "www", "api", "app", "admin", "auth", "dev", "test", "staging", "cdn", "static",
                "assets", "internal", "portal", "login", "health", "docs", "v1", "v2",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        ),
        other => bundled_wordlist_sources()
            .iter()
            .find(|(id, _, _, raw)| *id == other && !raw.is_empty())
            .map(|(_, _, _, raw)| parse_wordlist(raw))
            .filter(|values| !values.is_empty()),
    }
}

impl Engine {
    /// Creates the engine shell without analysis behavior.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _plugin_host: Arc::new(PluginHost::new()),
            live_workbench: Arc::new(LiveWorkbench::new()),
            resend: Arc::new(ResendWorkbench::new()),
            fuzzer: Arc::new(FuzzerWorkbench::new()),
            browser_trust: Arc::new(BrowserTrustController::new()),
            session_ca: Arc::new(RwLock::new(None)),
            browser_launch: Arc::new(std::sync::Mutex::new(None)),
            proxy_address: Arc::new(RwLock::new(None)),
            session_runtime: Arc::new(RwLock::new(None)),
            proxy_health: Arc::new(RwLock::new(None)),
            provisioned_devices: Arc::new(std::sync::Mutex::new(Vec::new())),
            android_target: Arc::new(std::sync::Mutex::new(None)),
            android_stream: Arc::new(std::sync::Mutex::new(None)),
            android_status: Arc::new(RwLock::new(AndroidTargetStatus::default())),
            android_launching: Arc::new(AtomicBool::new(false)),
            android_static: Arc::new(std::sync::Mutex::new(None)),
            active_discovery: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Returns the session-scoped live traffic and intercept surface.
    #[must_use]
    pub fn live_workbench(&self) -> Arc<LiveWorkbench> {
        Arc::clone(&self.live_workbench)
    }

    /// Attaches the active session's durable traffic runtime store.
    pub fn attach_traffic_store(&self, store: &Arc<TrafficStore>) {
        self.live_workbench.attach_store(Arc::clone(store));
        if let Err(diagnostic) = self.resend.attach_store(Arc::clone(store)) {
            self.live_workbench.publish_diagnostic(diagnostic);
        }
        if let Err(diagnostic) = self.fuzzer.attach_store(Arc::clone(store)) {
            self.live_workbench.publish_diagnostic(diagnostic);
        }
    }

    /// Attaches the single session/store pair used by the assembled product.
    ///
    /// The workbench surfaces are rehydrated from the same store immediately,
    /// so API save/open/new operations cannot diverge from live state.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the session snapshot or engine state lock is
    /// unavailable.
    pub fn attach_session_runtime(
        &self,
        runtime: Arc<SessionRuntime>,
    ) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        runtime.ensure_baseline()?;
        let session = runtime.session_snapshot()?;
        self.set_engagement_scope(session.engagement_scope().clone());
        self.attach_traffic_store(&runtime.store());
        self.session_runtime
            .write()
            .map_err(|_| {
                apiaxess_diagnostics::catalogue::PROXY_SESSION_SAVE_FAILED
                    .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
            })?
            .replace(runtime);
        Ok(())
    }

    /// Returns the active product session status.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if no session is attached or durable state cannot
    /// be read.
    pub fn session_status(&self) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime.status()
    }

    /// Saves the active product session to its canonical artifact.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if no session is attached or serialization/write
    /// fails.
    pub fn save_session(&self) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime.save()
    }

    /// Returns the canonical audit trail for the active session.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if no session is attached or the session lock is
    /// unavailable.
    pub fn session_audit(
        &self,
    ) -> Result<Vec<apiaxess_session::AuditRecord>, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime.audit_trail()
    }

    /// Returns the active session's durable API document.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if no session is attached or its lock is unavailable.
    pub fn session_document(
        &self,
    ) -> Result<apiaxess_api_model::ApiDocument, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime
            .session_snapshot()
            .map(|session| session.api_document().clone())
    }

    /// Returns the active session's durable unified surface, when assembled.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if no session is attached or its lock is unavailable.
    pub fn session_surface(
        &self,
    ) -> Result<Option<apiaxess_api_model::UnifiedApiSurface>, apiaxess_diagnostics::Diagnostic>
    {
        self.session_document()
            .map(|document| document.unified_surface)
    }

    /// Exports selected Phase 6 artifacts from the active session surface.
    ///
    /// The export is recorded as a session-scoped action and the generated
    /// files are written below the requested output directory.
    ///
    /// # Errors
    ///
    /// Returns structured diagnostics when no active session exists, no
    /// completed surface is available, emission fails, or a write/audit
    /// operation fails.
    pub fn export_session_artifacts(
        &self,
        config: &ExportConfig,
    ) -> Result<ExportReport, Vec<apiaxess_diagnostics::Diagnostic>> {
        let runtime = self
            .session_runtime()
            .map_err(|diagnostic| vec![diagnostic])?
            .ok_or_else(|| {
                vec![
                    apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                        .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
                ]
            })?;
        export_session_artifacts(&runtime, config)
    }

    /// Returns the canonical engagement scope for workbench classification.
    ///
    /// # Errors
    ///
    /// Returns a scope-not-set diagnostic when no session is attached.
    pub fn session_scope(&self) -> Result<EngagementScope, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_SCOPE_NOT_SET
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime
            .session_snapshot()
            .map(|session| session.engagement_scope().clone())
    }

    /// Updates the session's declared scope and records that declaration.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the scope is invalid, the session is inactive,
    /// or the updated session cannot be persisted.
    pub fn update_session_scope(
        &self,
        scope: EngagementScope,
    ) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        self.apply_session_scope(
            scope,
            AuditActor::User,
            "session.scope.update",
            "Updated the declared engagement scope".to_owned(),
        )
    }

    /// Declares `scope` on the session, audits it as `kind` by `actor`, and
    /// re-classifies stored traffic against it.
    fn apply_session_scope(
        &self,
        scope: EngagementScope,
        actor: AuditActor,
        kind: &str,
        summary: String,
    ) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        let now = chrono::Utc::now();
        let mut session = runtime.session_snapshot()?;
        session.update_engagement_scope(scope, now)?;
        let action_id = format!(
            "{kind}:{}",
            fresh_session_id()?.as_str().trim_start_matches("session:")
        );
        session.record_action(ActionRecordInput {
            id: action_id,
            occurred_at: now,
            actor,
            action: ActionDescriptor {
                kind: kind.to_owned(),
                summary,
            },
            target: ActionTarget::SessionTarget,
            outcome: ActionOutcome::Completed,
            diagnostics: Vec::new(),
        })?;
        runtime.replace_session(session)?;
        self.set_engagement_scope(runtime.session_snapshot()?.engagement_scope().clone());
        // Traffic captured before this scope existed (or before a host was added)
        // was classified against the old scope; re-classify it now so it reaches
        // fusion instead of being silently excluded.
        self.live_workbench.promote_stored_flows_into_scope()?;
        runtime.save()
    }

    /// Opens and resumes a canonical session artifact into the product.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the artifact is missing, incompatible, or
    /// cannot be rehydrated.
    pub fn open_session(
        &self,
        artifact_path: &Path,
    ) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        let runtime = Arc::new(SessionRuntime::open(artifact_path, &session_store_root())?);
        self.attach_session_runtime(runtime)?;
        self.session_status()
    }

    /// Starts a fresh active session using the current scope and API document.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the current session cannot be saved or the new
    /// runtime store cannot be created.
    pub fn new_session(&self) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        self.new_session_with_scope(None)
    }

    /// Starts a fresh active session, optionally replacing the inherited scope.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the current session cannot be saved, the scope
    /// is invalid, or the new runtime store cannot be created.
    pub fn new_session_with_scope(
        &self,
        requested_scope: Option<EngagementScope>,
    ) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        let current = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        current.save()?;
        let previous = current.session_snapshot()?;
        let now = chrono::Utc::now();
        let mut session = Session::new(
            fresh_session_id()?,
            requested_scope.unwrap_or_else(|| previous.engagement_scope().clone()),
            previous.api_document().clone(),
            now,
        );
        session.activate(now)?;
        let store = Arc::new(TrafficStore::open(
            &session_store_root(),
            session.id().as_str(),
        )?);
        let artifact = store.root().join("session.json");
        self.attach_session_runtime(Arc::new(SessionRuntime::new(session, store, artifact)))?;
        self.session_status()
    }

    /// Estimates an active discovery run using the calibrated ffuf request rate.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the requested wordlist or active web target is
    /// unavailable.
    pub fn estimate_discovery(
        &self,
        _kind: DiscoveryKind,
        wordlist: &str,
        custom: Option<Vec<String>>,
    ) -> Result<DiscoveryEstimate, apiaxess_diagnostics::Diagnostic> {
        let values = custom
            .or_else(|| bundled_wordlist(wordlist))
            .ok_or_else(|| browser_diagnostic(apiaxess_diagnostics::catalogue::DISCOVERY_WORDLIST_UNKNOWN, "discovery wordlist was not found"))?;
        let target = self.web_target_origin()?;
        // Realistic default: end-to-end throughput through the routed proxy (and,
        // on the APK path, the emulator) to a real target is latency-bound at a
        // few req/s, not the tens/s an unrouted ffuf reaches. Live acceptance
        // observed ~3.5 req/s, so an earlier 20 req/s estimate was wildly
        // optimistic. Default to a conservative-but-honest 5 req/s; deployments
        // calibrate `APIAXESS_DISCOVERY_RATE` from their own acceptance runs, and
        // the run reports its actual achieved rate on completion.
        let rate = env::var("APIAXESS_DISCOVERY_RATE")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|rate| *rate > 0)
            .unwrap_or(5_u32);
        let seconds = (values.len() as u64).div_ceil(u64::from(rate));
        Ok(DiscoveryEstimate {
            target,
            wordlist: wordlist.to_owned(),
            request_count: values.len(),
            rate_per_second: rate,
            estimated_seconds: seconds,
            estimated_label: format_duration(seconds),
        })
    }

    /// Creates and launches one confirmed, auditable discovery run via ffuf.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the wordlist, session, confirmation, or
    /// discovery request configuration is invalid.
    #[allow(clippy::too_many_lines)]
    pub fn start_discovery(
        &self,
        kind: DiscoveryKind,
        wordlist: &str,
        custom: Option<Vec<String>>,
        confirmed: bool,
    ) -> Result<apiaxess_workbench_store::FuzzerJob, apiaxess_diagnostics::Diagnostic> {
        let values = custom
            .or_else(|| bundled_wordlist(wordlist))
            .ok_or_else(|| browser_diagnostic(apiaxess_diagnostics::catalogue::DISCOVERY_WORDLIST_UNKNOWN, "discovery wordlist was not found"))?;
        let estimate = self.estimate_discovery(kind, wordlist, Some(values.clone()))?;
        if !confirmed {
            return Err(browser_launch_diagnostic(&format!(
                "active discovery requires confirmation: {} requests against {} (estimated {})",
                estimate.request_count, estimate.target, estimate.estimated_label
            )));
        }
        // Single-flight: refuse a second run while one is active so a re-click
        // never spawns a concurrent ffuf that outlives the one the UI cancels.
        if let Some(active) = self.active_discovery_running() {
            return Err(discovery_diagnostic(
                apiaxess_diagnostics::catalogue::DISCOVERY_ALREADY_ACTIVE,
                &format!("active discovery job {active}"),
            ));
        }
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        let mut session = runtime.session_snapshot()?;
        let marker = match kind {
            DiscoveryKind::Subdomain => format!(
                "https://FUZZ.{}",
                estimate
                    .target
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
            ),
            DiscoveryKind::Directory => format!("{}/FUZZ", estimate.target.trim_end_matches('/')),
        };
        let start = marker.find("FUZZ").ok_or_else(|| {
            browser_launch_diagnostic("discovery request template could not place FUZZ")
        })?;
        let config = FuzzerConfig {
            base_request: ResendRequest {
                method: "GET".to_owned(),
                url: marker,
                headers: Vec::new(),
                body: None,
            },
            positions: vec![PayloadPosition {
                location: FuzzerPositionLocation::Url,
                header_name: None,
                start,
                end: start + 4,
                set_index: 0,
            }],
            payload_sets: vec![PayloadSet {
                name: wordlist.to_owned(),
                source: PayloadSource::SimpleList { values },
                processors: Vec::new(),
                url_encode_chars: None,
            }],
            attack_type: FuzzerAttackType::Sniper,
            match_filter: FuzzerMatchFilter::default(),
            grep: GrepConfig::default(),
            concurrency: 1,
            // Discovery paces via a fixed rate and keeps the ffuf-compatible
            // defaults (no-follow redirects, no retries) so it rides the fast tier.
            delay: DelayPolicy::Fixed {
                rate_per_second: estimate.rate_per_second,
            },
            retry: RetryPolicy::default(),
            redirect: RedirectPolicy::default(),
            connection_close: false,
            update_content_length: true,
            max_results: estimate.request_count,
            auth_preflight: None,
            sequence: Vec::new(),
            // Directory discovery auto-calibrates against a soft-404/catch-all so
            // a WAF/wildcard site that answers every path yields no fake hits.
            // Subdomain discovery is DNS-resolved and needs no calibration.
            auto_calibrate: matches!(kind, DiscoveryKind::Directory),
            internal: true,
        };
        let job = self.fuzzer.create(config)?;
        session.record_action(ActionRecordInput {
            id: format!("discovery:confirm:{}", job.id),
            occurred_at: chrono::Utc::now(),
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "web.discovery.confirm".to_owned(),
                summary: format!(
                    "Confirmed active {} discovery: {} requests against {} (estimated {})",
                    match kind {
                        DiscoveryKind::Subdomain => "subdomain",
                        DiscoveryKind::Directory => "directory",
                    },
                    estimate.request_count,
                    estimate.target,
                    estimate.estimated_label
                ),
            },
            target: ActionTarget::SessionTarget,
            outcome: ActionOutcome::Completed,
            diagnostics: Vec::new(),
        })?;
        self.fuzzer.launch_in_session(&job.id, &mut session)?;
        runtime.replace_session(session)?;
        runtime.save()?;
        if let Ok(mut active) = self.active_discovery.lock() {
            *active = Some(job.id.clone());
        }
        Ok(job)
    }

    /// The active discovery job id, if one is currently running or paused. A
    /// finished/stopped/cleared job returns `None` (and the slot is cleared).
    fn active_discovery_running(&self) -> Option<String> {
        let mut active = self.active_discovery.lock().ok()?;
        let id = active.clone()?;
        let live = matches!(
            self.fuzzer.get(&id).map(|job| job.state),
            Some(
                apiaxess_workbench_store::FuzzerJobState::Running
                    | apiaxess_workbench_store::FuzzerJobState::Paused
            )
        );
        if !live {
            *active = None;
        }
        live.then_some(id)
    }

    /// Cancels the active discovery run: stops the underlying ffuf/native job
    /// (killing its process) and clears the single-flight slot so a fresh run
    /// can start. Returns the stopped job, or an error when nothing is active.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no discovery run is active or the underlying
    /// job cannot be stopped.
    pub fn cancel_discovery(
        &self,
    ) -> Result<apiaxess_workbench_store::FuzzerJob, apiaxess_diagnostics::Diagnostic> {
        let id = self.active_discovery_running().ok_or_else(|| {
            discovery_diagnostic(
                apiaxess_diagnostics::catalogue::DISCOVERY_NONE_ACTIVE,
                "cancel requested with no active run",
            )
        })?;
        let stopped = self.fuzzer.stop(&id)?;
        if let Ok(mut active) = self.active_discovery.lock() {
            *active = None;
        }
        Ok(stopped)
    }

    /// Every WebSocket connection captured in this session, each labeled first-
    /// or third-party by the same structural classifier as the API surface.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no session is active or the store read fails.
    pub fn ws_connections(
        &self,
    ) -> Result<Vec<WsConnectionView>, apiaxess_diagnostics::Diagnostic> {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        let store = runtime.store();
        let connections = store.ws_connections()?;
        // Weight hosts by all captured traffic, HTTP and WebSocket alike.
        let mut weights = std::collections::BTreeMap::<String, usize>::new();
        for flow in store.summaries()? {
            if flow.origin == FlowOrigin::Capture {
                if let Some(host) = flow.host {
                    *weights.entry(host).or_default() += 1;
                }
            }
        }
        for connection in &connections {
            if let Some(host) = &connection.host {
                *weights.entry(host.clone()).or_default() += 1;
            }
        }
        let hints = first_party_hints(runtime.session_snapshot()?.engagement_scope());
        let parties = apiaxess_unified_surface::party::classify_hosts(&weights, &hints);
        Ok(connections
            .into_iter()
            .map(|connection| WsConnectionView {
                party: connection
                    .host
                    .as_ref()
                    .and_then(|host| parties.get(host).copied()),
                connection,
            })
            .collect())
    }

    /// Imports a HAR into the session's traffic. When the session has no scope
    /// declared, one is derived from the HAR first (see
    /// [`Self::derive_scope_from_har`]) so the imported traffic is in scope and
    /// fuses, instead of every flow being silently excluded as undetermined.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the HAR is invalid, the derived scope cannot
    /// be declared, or the import fails.
    pub fn import_har(
        &self,
        bytes: &[u8],
    ) -> Result<HarImportReport, apiaxess_diagnostics::Diagnostic> {
        let derived_scope = match self.session_runtime()? {
            Some(runtime) => {
                let scope = runtime.session_snapshot()?.engagement_scope().clone();
                if scope.allowed_targets.is_empty() {
                    self.derive_scope_from_har(scope, bytes)?
                } else {
                    None
                }
            }
            None => None,
        };
        let imported = self.live_workbench.import_har(bytes, "har.import")?;
        Ok(HarImportReport {
            imported,
            derived_scope,
        })
    }

    /// Declares a scope from a HAR's own hosts, as exact-host rules: the hosts
    /// the structural classifier finds first-party (the dominant domain), or
    /// every HAR host when none dominates. Never wider than the HAR's hosts;
    /// the audit trail records it as derived, and the operator can narrow it.
    fn derive_scope_from_har(
        &self,
        mut scope: EngagementScope,
        bytes: &[u8],
    ) -> Result<Option<HarDerivedScope>, apiaxess_diagnostics::Diagnostic> {
        // Only hosts that form a valid scope rule are candidates.
        let rule = |host: &str| AllowedNetworkTarget {
            id: format!(
                "har:{}",
                host.chars()
                    .map(|ch| match ch {
                        'a'..='z' | '0'..='9' | '.' | '-' | '_' => ch,
                        _ => '-',
                    })
                    .collect::<String>()
            ),
            host: HostMatch::Exact {
                host: host.to_owned(),
            },
            ports: Vec::new(),
        };
        let weights = apiaxess_workbench_store::har_hosts(bytes)?
            .into_iter()
            .filter(|(host, _)| {
                EngagementScope {
                    allowed_targets: vec![rule(host)],
                    ..scope.clone()
                }
                .validate()
                .is_ok()
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if weights.is_empty() {
            return Ok(None);
        }
        let parties =
            apiaxess_unified_surface::party::classify_hosts(&weights, &first_party_hints(&scope));
        let (hosts, excluded_hosts): (Vec<_>, Vec<_>) = weights.keys().cloned().partition(|host| {
            parties.is_empty()
                || parties.get(host) == Some(&apiaxess_api_model::HostParty::FirstParty)
        });
        scope.allowed_targets = hosts.iter().map(|host| rule(host)).collect();
        self.apply_session_scope(
            scope,
            AuditActor::Engine,
            "session.scope.derive-from-har",
            format!(
                "No scope was declared: scoped to {} host(s) from the imported HAR ({})",
                hosts.len(),
                hosts.join(", ")
            ),
        )?;
        Ok(Some(HarDerivedScope {
            hosts,
            excluded_hosts,
        }))
    }

    /// One page of a WebSocket connection's messages, after `after` (sequence).
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no session is active or the store read fails.
    pub fn ws_messages(
        &self,
        connection_id: u64,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<apiaxess_workbench_store::WsMessageRecord>, apiaxess_diagnostics::Diagnostic>
    {
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        runtime.store().ws_messages(connection_id, after, limit)
    }

    /// Builds the observation-based web surface from all captured traffic and
    /// persists the resulting unified artifact. No APK/static claims are made.
    ///
    /// # Errors
    ///
    /// Returns the diagnostics collected when capture, confidence
    /// recomputation, assembly, or session persistence fails.
    pub fn fuse_web_capture(
        &self,
    ) -> Result<apiaxess_api_model::UnifiedApiSurface, Vec<apiaxess_diagnostics::Diagnostic>> {
        let runtime = self
            .session_runtime()
            .map_err(|error| vec![error])?
            .ok_or_else(|| {
                vec![
                    apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                        .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
                ]
            })?;
        let run_id = format!(
            "web:capture:{}",
            fresh_session_id()
                .map_err(|error| vec![error])?
                .as_str()
                .trim_start_matches("session:")
        );
        let mut session = runtime.session_snapshot().map_err(|error| vec![error])?;
        // An app driven on the Android target carries the static model of the APK
        // installed onto it: rebuild from that static document on every Fuse, so
        // its templates generalize the concrete observed paths and a previous
        // fuse's concrete endpoints never compete with them.
        let static_base = self.android_static_document(session.id().as_str());
        if let Some(document) = &static_base {
            session
                .commit_api_document((**document).clone(), chrono::Utc::now())
                .map_err(|error| vec![error])?;
        }
        let config = apiaxess_dynamic_capture::DynamicCaptureConfig::new(run_id.clone())
            .map_err(|error| vec![error])?;
        apiaxess_dynamic_capture::capture_into_session(
            &mut session,
            &runtime.store(),
            &config,
            chrono::Utc::now(),
        )?;
        if static_base.is_some() {
            let fusion_config = apiaxess_fusion::FusionConfig::new(format!("{run_id}:fusion"))
                .map_err(|error| vec![error])?;
            let fused = apiaxess_fusion::fuse_document(
                session.api_document(),
                &fusion_config,
                chrono::Utc::now(),
            )?;
            session
                .commit_api_document(fused.document, chrono::Utc::now())
                .map_err(|error| vec![error])?;
        }
        let confidence_config =
            ConfidenceConfig::new(format!("{run_id}:confidence")).map_err(|error| vec![error])?;
        let confidence = apiaxess_confidence::recompute_document(
            &session.api_document().clone(),
            &confidence_config,
            chrono::Utc::now(),
        )
        .map_err(|diagnostics| diagnostics.into_iter().collect::<Vec<_>>())?;
        let mut surface_config =
            apiaxess_unified_surface::UnifiedSurfaceConfig::new(format!("{run_id}:surface"))
                .map_err(|error| vec![error])?;
        surface_config.first_party = first_party_hints(session.engagement_scope());
        let surface = apiaxess_unified_surface::assemble_document(
            &confidence.document,
            &surface_config,
            chrono::Utc::now(),
        )?;
        session
            .commit_api_document(surface.document.clone(), chrono::Utc::now())
            .map_err(|error| vec![error])?;
        runtime
            .replace_session(session)
            .map_err(|error| vec![error])?;
        runtime.save().map_err(|error| vec![error])?;
        Ok(surface.unified)
    }

    /// Starts a durable web-target session after the user has explicitly
    /// affirmed that they are authorized to test the target.
    ///
    /// The target is deliberately represented through the same engagement
    /// scope and append-only audit trail used by APK and workbench sessions.
    /// Network activity remains advisory: requests outside this host are
    /// warned and recorded, never blocked.
    ///
    /// # Errors
    ///
    /// Returns a session diagnostic when the target, authorization affirmation,
    /// or durable session setup is invalid.
    pub fn start_web_session(
        &self,
        target: &str,
        authorization_affirmed: bool,
        artifact_path: Option<PathBuf>,
    ) -> Result<SessionStatus, apiaxess_diagnostics::Diagnostic> {
        if !authorization_affirmed {
            return Err(web_session_diagnostic(
                "authorization affirmation is required before starting a web-target session",
            ));
        }
        let web_target = WebTarget::parse(target)?;
        if let Some(current) = self.session_runtime()? {
            current.save()?;
        }
        let now = chrono::Utc::now();
        let session_id = fresh_session_id()?;
        let scope = EngagementScope {
            declared_at: now,
            target: TargetIdentity {
                target_type: "web.url".to_owned(),
                primary: TargetIdentifier {
                    kind: "url.origin".to_owned(),
                    value: web_target.origin.clone(),
                },
                aliases: vec![TargetIdentifier {
                    kind: "domain.host".to_owned(),
                    value: web_target.host.clone(),
                }],
            },
            allowed_targets: vec![AllowedNetworkTarget {
                id: "web.target-domain".to_owned(),
                host: HostMatch::Exact {
                    host: web_target.host.clone(),
                },
                ports: web_target.port.into_iter().collect(),
            }],
        };
        scope.validate()?;
        let mut session = Session::new(
            session_id,
            scope,
            apiaxess_api_model::ApiDocument::new(apiaxess_api_model::ApiSurface {
                provenance: apiaxess_api_model::ProvenanceRegistry::default(),
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            now,
        );
        session.activate(now)?;
        session.record_action(ActionRecordInput {
            id: format!(
                "web.authorization.affirm:{}",
                fresh_session_id()?.as_str().trim_start_matches("session:")
            ),
            occurred_at: now,
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "web.authorization.affirm".to_owned(),
                summary: format!(
                    "Affirmed authorization to test web target {}",
                    web_target.origin
                ),
            },
            target: ActionTarget::SessionTarget,
            outcome: ActionOutcome::Completed,
            diagnostics: Vec::new(),
        })?;
        let store = Arc::new(TrafficStore::open(
            &session_store_root(),
            session.id().as_str(),
        )?);
        let artifact = artifact_path.unwrap_or_else(|| store.root().join("session.json"));
        self.attach_session_runtime(Arc::new(SessionRuntime::new(session, store, artifact)))?;
        self.save_session()
    }

    /// Provides the runtime to the composition root for commit-before-exit.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the engine state lock is unavailable.
    pub fn session_runtime(
        &self,
    ) -> Result<Option<Arc<SessionRuntime>>, apiaxess_diagnostics::Diagnostic> {
        self.session_runtime
            .read()
            .map(|runtime| runtime.clone())
            .map_err(|_| {
                apiaxess_diagnostics::catalogue::PROXY_SESSION_SAVE_FAILED
                    .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
            })
    }

    /// Root containing hashed per-session `SQLite` directories.
    #[must_use]
    pub fn session_store_root() -> PathBuf {
        session_store_root()
    }

    /// Runs the product's typed APK analysis pipeline in the active session.
    ///
    /// The returned document and unified surface are also committed to the
    /// session before this method returns. Stage transitions are persisted and
    /// audited, so a caller can inspect progress after a long run or failure.
    ///
    /// # Errors
    ///
    /// Returns the stage and structured diagnostics when a pipeline stage
    /// cannot complete. The failure state remains durable in the session.
    pub fn run_pipeline(
        &self,
        config: &PipelineConfig,
    ) -> Result<PipelineReport, Box<PipelineFailure>> {
        let runtime = self
            .session_runtime()
            .map_err(|diagnostic| Box::new(pipeline_failure(config, diagnostic)))?
            .ok_or_else(|| {
                let diagnostic = apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                    .instantiate(apiaxess_diagnostics::DiagnosticContext::new());
                Box::new(pipeline_failure(config, diagnostic))
            })?;
        run_pipeline(&runtime, config)
    }

    /// Returns the session-scoped manual resend surface.
    #[must_use]
    pub fn resend(&self) -> Arc<ResendWorkbench> {
        Arc::clone(&self.resend)
    }

    /// Attaches the running routed proxy as the resend's send transport.
    ///
    /// Both tools send through the same proxy, which records every request as a
    /// flow. Each workbench gets an [`OriginTaggingSender`] so its traffic is
    /// tagged at the single write choke-point ([`FlowOrigin::Resend`] /
    /// [`FlowOrigin::Fuzz`]) and thereby excluded from the Live list and the
    /// fused API surface, while still recorded for the Resend history / Fuzz
    /// results views.
    pub fn attach_resend_sender(&self, sender: Arc<dyn ResendSender>) {
        self.resend.attach_sender(Arc::new(OriginTaggingSender::new(
            Arc::clone(&sender),
            FlowOrigin::Resend,
        )));
        self.fuzzer
            .attach_sender(Arc::new(OriginTaggingSender::new(sender, FlowOrigin::Fuzz)));
    }

    /// Applies the active session's advisory scope to every workbench sender.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        self.live_workbench.set_engagement_scope(scope.clone());
        self.resend.set_engagement_scope(scope.clone());
        self.fuzzer.set_engagement_scope(scope);
    }

    /// Supplies the active proxy listener used by stateless ffuf jobs.
    pub fn set_fuzzer_ffuf_proxy(&self, address: std::net::SocketAddr) {
        self.fuzzer.set_ffuf_proxy(address);
    }

    /// Binds browser trust provisioning to the active session CA.
    pub fn configure_browser_ca(&self, ca: SessionCa) {
        self.browser_trust.configure_ca(ca.clone());
        if let Ok(mut configured) = self.session_ca.write() {
            *configured = Some(ca);
        }
    }

    /// Returns the active session's interception CA, if one has been configured.
    ///
    /// The CA is per-session and ephemeral: it is set once at workbench startup
    /// and never persisted. Callers use it to read the root certificate PEM and
    /// its SHA-256 fingerprint (for device pairing); the signing key is never
    /// exposed by the returned handle without an explicit export.
    #[must_use]
    pub fn session_ca(&self) -> Option<SessionCa> {
        self.session_ca.read().ok().and_then(|ca| ca.clone())
    }

    /// Lists attached adb devices available for provisioning (Phase C2).
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the bundled adb cannot be probed or the device
    /// listing fails.
    pub fn detect_adb_devices(
        &self,
    ) -> Result<
        Vec<apiaxess_sandbox::device_provision::DetectedDevice>,
        apiaxess_diagnostics::Diagnostic,
    > {
        device_provisioner().detect_devices()
    }

    /// Provisions an attached adb device against the live session (Phase C2):
    /// establishes the adb-reverse tunnel to the running workbench proxy and
    /// installs the live session CA into the device's system trust store using
    /// the path appropriate to its Android version. Optionally starts the bundled
    /// frida-server (the hook for C4's per-app pinned bypass).
    ///
    /// # Errors
    ///
    /// Returns the provisioning diagnostics when no session CA or running proxy
    /// exists, or when any provisioning step fails.
    pub fn provision_adb_device(
        &self,
        serial: &str,
        start_frida_server: bool,
    ) -> Result<
        apiaxess_sandbox::device_provision::ProvisionedDevice,
        Vec<apiaxess_diagnostics::Diagnostic>,
    > {
        let ca = self.session_ca().ok_or_else(|| {
            vec![
                apiaxess_diagnostics::catalogue::PAIRING_CA_UNAVAILABLE
                    .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
            ]
        })?;
        let proxy = self
            .proxy_address
            .read()
            .ok()
            .and_then(|value| *value)
            .ok_or_else(|| {
                vec![
                    apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                        .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
                ]
            })?;
        let proxy_mapping = apiaxess_sandbox::device_provision::PortMapping {
            device_port: proxy.port(),
            host_port: proxy.port(),
        };
        let frida_server_path =
            start_frida_server.then(apiaxess_sandbox::bundled_frida_server_path);
        let options = apiaxess_sandbox::device_provision::ProvisionOptions {
            proxy: proxy_mapping,
            control: None,
            lease_id: fresh_session_id()
                .map_or_else(|_| "device".to_owned(), |id| id.as_str().to_owned()),
            start_frida_server,
            frida_server_path,
            // A user's own paired device keeps its settings; it captures through
            // the client app, not a device-wide proxy the workbench imposes.
            route_device_proxy: false,
        };
        device_provisioner().provision(serial, &ca, &options)
    }

    /// Establishes only the adb-reverse tunnel for a device (Phase C5 pairing arm).
    ///
    /// This is transport, not trust: it forwards the device's control + proxy
    /// loopback ports to the workbench so the device can present its pairing token,
    /// but installs no CA and grants no capability. The trust-granting provisioning
    /// runs only after the operator accepts (see [`Self::provision_device_retained`]).
    ///
    /// # Errors
    ///
    /// Returns the reverse-tunnel diagnostics when a mapping cannot be installed.
    pub fn arm_device_tunnel(
        &self,
        serial: &str,
        control_port: u16,
        proxy_port: u16,
    ) -> Result<(), Vec<apiaxess_diagnostics::Diagnostic>> {
        use apiaxess_sandbox::device_provision::PortMapping;
        let mappings = [
            PortMapping {
                device_port: control_port,
                host_port: control_port,
            },
            PortMapping {
                device_port: proxy_port,
                host_port: proxy_port,
            },
        ];
        device_provisioner().establish_tunnel(serial, &mappings)
    }

    /// Provisions a device (Phase C2) and retains the handle for the session so its
    /// installed system-CA/tunnel state is torn down on shutdown, not leaked.
    /// This is the trust-granting step the Phase C5 accept gate calls — it must not
    /// run without an explicit operator accept.
    ///
    /// # Errors
    ///
    /// Returns the provisioning diagnostics when any step fails.
    pub fn provision_device_retained(
        &self,
        serial: &str,
        start_frida_server: bool,
    ) -> Result<
        apiaxess_sandbox::device_provision::DeviceProvisionReport,
        Vec<apiaxess_diagnostics::Diagnostic>,
    > {
        let device = self.provision_adb_device(serial, start_frida_server)?;
        let report = device.report().clone();
        if let Ok(mut devices) = self.provisioned_devices.lock() {
            devices.push(device);
        }
        Ok(report)
    }

    /// Tears down every device provisioned this session, returning any teardown
    /// diagnostics. Called on workbench shutdown.
    #[must_use]
    pub fn teardown_provisioned_devices(&self) -> Vec<apiaxess_diagnostics::Diagnostic> {
        let devices = self
            .provisioned_devices
            .lock()
            .map(|mut devices| std::mem::take(&mut *devices))
            .unwrap_or_default();
        devices
            .into_iter()
            .filter_map(|device| device.teardown().err())
            .flatten()
            .collect()
    }

    /// Launches the GUI Android target add-on (Phase D1): resolves the downloaded
    /// payload, boots its slim no-GApps root-capable AOSP AVD headless
    /// (acceleration-aware, software-degraded when nested virtualization is
    /// unavailable), installs the first-party client APK on first boot, and runs
    /// the existing C2/C5 provisioning (the live session CA, the device-side
    /// frida-server, and the adb-reverse tunnel) over *this target's* bundled adb,
    /// not the analysis runtime's. The returned report carries the ws-scrcpy port
    /// Phase D2 will stream over. The booted target and its provisioned trust are
    /// retained for teardown on shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`apiaxess_diagnostics::catalogue::ANDROID_TARGET_MISSING`] when the
    /// add-on is not installed, [`apiaxess_diagnostics::catalogue::PAIRING_CA_UNAVAILABLE`]
    /// / [`apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE`] when no
    /// session CA or running proxy exists, or the boot/provisioning diagnostics on
    /// failure.
    pub fn launch_android_target(
        &self,
    ) -> Result<AndroidTargetLaunchReport, Vec<apiaxess_diagnostics::Diagnostic>> {
        self.set_android_phase(AndroidTargetPhase::Booting, "Booting the Android target…");
        let result = self.launch_android_target_inner();
        match &result {
            Ok(report) => self.mark_android_ready(report),
            Err(errors) => self.mark_android_error(errors),
        }
        // Release the launch guard so the panel can retry (begin_android_launch set
        // it; a direct caller that skipped begin just clears a false flag).
        self.android_launching.store(false, Ordering::Release);
        result
    }

    /// The blocking boot → provision → stream steps behind
    /// [`Self::launch_android_target`], updating the panel status as it progresses.
    #[allow(clippy::too_many_lines)] // A linear boot → provision → stream flow reads best whole.
    fn launch_android_target_inner(
        &self,
    ) -> Result<AndroidTargetLaunchReport, Vec<apiaxess_diagnostics::Diagnostic>> {
        use apiaxess_sandbox::android_target::AndroidTargetAddon;
        use apiaxess_sandbox::device_provision::{
            DeviceProvisioner, PortMapping, ProvisionOptions,
        };

        // 1. Resolve the optional, separately-downloaded add-on payload.
        let addon = AndroidTargetAddon::resolve().map_err(|diagnostic| vec![diagnostic])?;

        // 2. First-boot provisioning needs the live session CA + running proxy,
        //    exactly like the C2 device path.
        let ca = self.session_ca().ok_or_else(|| {
            vec![
                apiaxess_diagnostics::catalogue::PAIRING_CA_UNAVAILABLE
                    .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
            ]
        })?;
        let proxy = self
            .proxy_address
            .read()
            .ok()
            .and_then(|value| *value)
            .ok_or_else(|| {
                vec![
                    apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                        .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
                ]
            })?;

        // 3. Boot the AVD headless, acceleration-aware (honest software fallback).
        let runner: Arc<dyn apiaxess_external_tools::ExternalToolRunner> =
            Arc::new(apiaxess_external_tools::ProcessToolRunner);
        let acceleration = AndroidTargetAddon::detect_acceleration(Arc::clone(&runner));
        let booted = addon.boot(
            Arc::clone(&runner),
            acceleration,
            std::time::Duration::from_secs(300),
        )?;
        let serial = booted.serial().to_owned();
        let ws_scrcpy_port = booted.ws_scrcpy_port();
        let mut diagnostics = vec![
            apiaxess_diagnostics::catalogue::ANDROID_TARGET_BOOTED
                .instantiate(device_serial_context(&serial)),
        ];
        self.set_android_serial_phase(
            &serial,
            AndroidTargetPhase::Provisioning,
            "Installing the client app, session CA, and instrumentation…",
        );

        // 4. First-boot client APK install (idempotent). Non-fatal: the target is
        //    still bootable/streamable, but cannot pair until the client is present.
        let client_apk_installed = match booted.install_client_apk() {
            Ok(()) => addon.manifest().provisioning.install_client_apk,
            Err(mut errors) => {
                diagnostics.append(&mut errors);
                false
            }
        };

        // 5. Reuse the C2/C5 provisioner over THIS target's bundled adb.
        let start_frida_server = addon.manifest().provisioning.start_frida_server;
        let provisioner = DeviceProvisioner::new(
            Arc::clone(&runner),
            addon.adb_executable().display().to_string(),
        );
        let options = ProvisionOptions {
            proxy: PortMapping {
                device_port: proxy.port(),
                host_port: proxy.port(),
            },
            control: None,
            lease_id: fresh_session_id()
                .map_or_else(|_| "android-target".to_owned(), |id| id.as_str().to_owned()),
            start_frida_server,
            frida_server_path: start_frida_server.then(|| addon.frida_server_path()),
            // The managed emulator is the workbench's own device: route all of its
            // traffic through the MITM so a driven app is captured with no setup.
            route_device_proxy: true,
        };
        let device = match provisioner.provision(&serial, &ca, &options) {
            Ok(device) => device,
            Err(mut errors) => {
                diagnostics.append(&mut errors);
                // Do not leak the emulator process when provisioning fails.
                let _ = booted.stop();
                return Err(diagnostics);
            }
        };
        let provision_report = device.report().clone();

        // 5b. Start the loopback ws-scrcpy screen stream (Phase D2). Non-fatal: the
        //     target is fully provisioned and capturing traffic even if streaming
        //     is unavailable (an add-on assembled without ws-scrcpy/Node). The
        //     stream binds 127.0.0.1 only; the engine reverse-proxies it.
        self.set_android_phase(AndroidTargetPhase::Streaming, "Starting the screen stream…");
        let streaming = match booted.start_streaming() {
            Ok(stream) => {
                // A brief readiness wait so the first proxied request does not race
                // Node startup; best-effort, never fatal.
                let _ = stream.wait_ready(std::time::Duration::from_secs(15));
                if let Ok(mut slot) = self.android_stream.lock() {
                    if let Some(previous) = slot.take() {
                        let _ = previous.stop();
                    }
                    *slot = Some(stream);
                }
                diagnostics.push(
                    apiaxess_diagnostics::catalogue::ANDROID_STREAM_STARTED
                        .instantiate(device_serial_context(&serial)),
                );
                true
            }
            Err(mut errors) => {
                diagnostics.append(&mut errors);
                false
            }
        };

        // 6. Retain the provisioned trust and the booted emulator for teardown.
        if let Ok(mut devices) = self.provisioned_devices.lock() {
            devices.push(device);
        }
        if let Ok(mut slot) = self.android_target.lock() {
            if let Some(previous) = slot.take() {
                let _ = previous.stop();
            }
            *slot = Some(booted);
        }

        diagnostics.extend(provision_report.diagnostics.iter().cloned());
        diagnostics.push(
            apiaxess_diagnostics::catalogue::ANDROID_TARGET_READY
                .instantiate(device_serial_context(&serial)),
        );
        Ok(AndroidTargetLaunchReport {
            serial,
            ws_scrcpy_port,
            android_sdk: provision_report.android_sdk,
            client_apk_installed,
            frida_server_started: provision_report.frida_server_started,
            streaming,
            capture_proxy: provision_report.device_proxy.clone(),
            capture_issue: provision_report.capture_issue.clone(),
            diagnostics,
        })
    }

    /// The GUI Android target's running ws-scrcpy stream (Phase D2) as the
    /// reverse-proxy upstream: its loopback port and the base path it was started
    /// to serve under (`WS_SCRCPY_PATHNAME`, e.g. `/android-stream/`). `None` means
    /// no stream is active, so the Android view returns the honest
    /// `sandbox.android-stream-not-active` diagnostic.
    #[must_use]
    pub fn android_stream_upstream(&self) -> Option<(u16, String)> {
        // Advanced/dev override: point the reverse-proxy at an externally-run
        // ws-scrcpy (e.g. a manually started stream) without launching the add-on.
        // It is assumed to serve under the same base path the add-on uses unless
        // `APIAXESS_ANDROID_STREAM_BASE_PATH` says otherwise.
        if let Some(port) = std::env::var("APIAXESS_ANDROID_STREAM_PORT")
            .ok()
            .and_then(|value| value.trim().parse::<u16>().ok())
            .filter(|port| *port != 0)
        {
            let base_path = std::env::var("APIAXESS_ANDROID_STREAM_BASE_PATH")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "/android-stream/".to_owned());
            return Some((port, base_path));
        }
        let stream = self.android_stream.lock().ok()?;
        stream
            .as_ref()
            .filter(|stream| stream.is_running())
            .map(|stream| (stream.port(), stream.base_path().to_owned()))
    }

    /// Stops the GUI Android target booted this session (Phase D1) and its
    /// loopback ws-scrcpy stream (Phase D2), returning any teardown diagnostics.
    /// Called on workbench shutdown. The provisioned trust is torn down separately
    /// by [`Self::teardown_provisioned_devices`].
    #[must_use]
    pub fn teardown_android_target(&self) -> Vec<apiaxess_diagnostics::Diagnostic> {
        let mut diagnostics = Vec::new();
        // Stop the stream first so its Node process releases the loopback port
        // before the emulator it streams from goes away.
        let stream = self
            .android_stream
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(stream) = stream {
            diagnostics.extend(stream.stop().err().unwrap_or_default());
        }
        // Undo the target's provisioning (device proxy, CA trust, reverse tunnel)
        // while the emulator is still running: its settings persist across boots,
        // so a proxy left behind would outlive the tunnel it points at.
        let target_serial = self
            .android_status
            .read()
            .ok()
            .and_then(|status| status.serial.clone());
        if let Some(serial) = target_serial {
            let provisioned = self
                .provisioned_devices
                .lock()
                .map(|mut devices| {
                    let (target, others): (Vec<_>, Vec<_>) = std::mem::take(&mut *devices)
                        .into_iter()
                        .partition(|device| device.report().serial == serial);
                    *devices = others;
                    target
                })
                .unwrap_or_default();
            for device in provisioned {
                diagnostics.extend(device.teardown().err().unwrap_or_default());
            }
        }
        let target = self
            .android_target
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(target) = target {
            diagnostics.extend(target.stop().err().unwrap_or_default());
        }
        // Return the panel to its idle state and release the launch guard.
        if let Ok(mut status) = self.android_status.write() {
            *status = AndroidTargetStatus::default();
        }
        self.android_launching.store(false, Ordering::Release);
        diagnostics
    }

    /// The current lifecycle of the GUI Android target (Phase D3), for the workbench
    /// panel. `addon_present` is recomputed each read so a freshly installed add-on
    /// is reflected without a restart.
    #[must_use]
    pub fn android_target_status(&self) -> AndroidTargetStatus {
        let mut status = self
            .android_status
            .read()
            .ok()
            .map(|status| status.clone())
            .unwrap_or_default();
        status.addon_present = apiaxess_sandbox::android_target::AndroidTargetAddon::is_present();
        let session_id = self
            .session_runtime()
            .ok()
            .flatten()
            .and_then(|runtime| runtime.session_snapshot().ok())
            .map(|session| session.id().as_str().to_owned());
        status.static_analysis = self.android_static.lock().ok().and_then(|current| {
            let (id, state) = current.as_ref()?;
            if Some(id) != session_id.as_ref() {
                return None;
            }
            Some(match state {
                AndroidStaticAnalysis::Running => AndroidStaticAnalysisStatus {
                    state: "running",
                    endpoint_count: None,
                    message: None,
                },
                AndroidStaticAnalysis::Ready(document) => AndroidStaticAnalysisStatus {
                    state: "ready",
                    endpoint_count: Some(document.surface.endpoints.len()),
                    message: None,
                },
                AndroidStaticAnalysis::Failed(why) => AndroidStaticAnalysisStatus {
                    state: "failed",
                    endpoint_count: None,
                    message: Some(why.clone()),
                },
            })
        });
        status
    }

    /// Claims the single-launch guard and marks the target as booting, so the
    /// workbench panel's launch endpoint can kick the blocking launch onto a
    /// background thread and return immediately. Returns `false` when a launch is
    /// already in flight (the panel should just keep polling status).
    #[must_use]
    pub fn begin_android_launch(&self) -> bool {
        if self.android_launching.swap(true, Ordering::AcqRel) {
            return false;
        }
        self.set_android_phase(AndroidTargetPhase::Booting, "Booting the Android target…");
        true
    }

    /// Installs the user's target APK onto the running GUI Android target
    /// (`adb install -r`), the core "install the app I want to capture" step. The
    /// app is then driven via the embedded screen and its traffic flows to the
    /// workbench.
    ///
    /// # Errors
    ///
    /// Returns [`apiaxess_diagnostics::catalogue::ANDROID_TARGET_NOT_RUNNING`] when
    /// no target is running, or
    /// [`apiaxess_diagnostics::catalogue::ANDROID_TARGET_APK_INSTALL_FAILED`] when
    /// adb rejects the install.
    pub fn install_target_apk(
        &self,
        apk_path: &Path,
    ) -> Result<(), Vec<apiaxess_diagnostics::Diagnostic>> {
        self.install_target_apk_only(apk_path)?;
        self.record_installed_app(apk_path);
        self.start_android_static_analysis(apk_path);
        Ok(())
    }

    /// Records the just-installed APK's package (read from its compiled
    /// manifest) so the panel can show it and offer "Open app".
    fn record_installed_app(&self, apk_path: &Path) {
        let package = apiaxess_sandbox::apk_manifest::package_name(apk_path);
        if let Ok(mut status) = self.android_status.write() {
            status.installed_apk = apk_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            match package {
                Ok(package) => {
                    status.installed_package = Some(package);
                    status.install_note = None;
                }
                Err(why) => {
                    status.installed_package = None;
                    status.install_note = Some(format!(
                        "Installed, but its package name could not be read ({why}); open it from the device's app drawer."
                    ));
                }
            }
        }
    }

    /// Launches the app installed from the panel on the running target: resolves
    /// its launcher activity and starts it. Returns the started component.
    ///
    /// # Errors
    ///
    /// Returns [`apiaxess_diagnostics::catalogue::ANDROID_TARGET_NOT_RUNNING`] when
    /// no target is running, or
    /// [`apiaxess_diagnostics::catalogue::ANDROID_TARGET_APP_OPEN_FAILED`] when no
    /// app is recorded as installed, it has no launcher activity, or the device
    /// refuses to start it.
    pub fn open_target_app(&self) -> Result<String, Vec<apiaxess_diagnostics::Diagnostic>> {
        let package = self
            .android_status
            .read()
            .ok()
            .and_then(|status| status.installed_package.clone())
            .ok_or_else(|| {
                vec![app_open_failed(
                    "no app has been installed from this panel since the target launched",
                )]
            })?;
        let control = {
            let guard = self
                .android_target
                .lock()
                .map_err(|_| vec![android_target_not_running()])?;
            guard
                .as_ref()
                .ok_or_else(|| vec![android_target_not_running()])?
                .control()
        };
        let timeout = std::time::Duration::from_secs(20);
        let resolved = control
            .shell(
                &[
                    "cmd".to_owned(),
                    "package".to_owned(),
                    "resolve-activity".to_owned(),
                    "--brief".to_owned(),
                    "-c".to_owned(),
                    "android.intent.category.LAUNCHER".to_owned(),
                    package.clone(),
                ],
                timeout,
            )
            .map_err(|diagnostic| vec![diagnostic])?;
        let component = launcher_component(&resolved.stdout, &package).ok_or_else(|| {
            vec![app_open_failed(&format!(
                "{package} has no launcher activity to open"
            ))]
        })?;
        let started = control
            .shell(
                &[
                    "am".to_owned(),
                    "start".to_owned(),
                    "-n".to_owned(),
                    component.clone(),
                ],
                timeout,
            )
            .map_err(|diagnostic| vec![diagnostic])?;
        // `am start` exits 0 even for some failures and reports them on stdout.
        let refused = started.stdout.contains("Error") || started.stderr.contains("Error");
        if started.exit_code == Some(0) && !refused {
            Ok(component)
        } else {
            Err(vec![app_open_failed(&format!(
                "the device refused to start {component}: {}",
                format!("{} {}", started.stdout.trim(), started.stderr.trim()).trim()
            ))])
        }
    }

    /// Runs static analysis of the just-installed APK in the background, keyed
    /// to the current session, so a later Fuse can fuse it with the live drive.
    fn start_android_static_analysis(&self, apk_path: &Path) {
        let Some(session_id) = self
            .session_runtime()
            .ok()
            .flatten()
            .and_then(|runtime| runtime.session_snapshot().ok())
            .map(|session| session.id().as_str().to_owned())
        else {
            return;
        };
        let slot = Arc::clone(&self.android_static);
        if let Ok(mut current) = slot.lock() {
            *current = Some((session_id.clone(), AndroidStaticAnalysis::Running));
        }
        let apk = apk_path.to_path_buf();
        std::thread::spawn(move || {
            let outcome = match pipeline::static_document_for_apk(&apk) {
                Ok(document) => AndroidStaticAnalysis::Ready(Box::new(document)),
                Err(diagnostics) => AndroidStaticAnalysis::Failed(diagnostics.first().map_or_else(
                    || "static analysis failed".to_owned(),
                    |d| d.what.to_string(),
                )),
            };
            if let Ok(mut current) = slot.lock() {
                // A newer install (or session) superseded this run: keep it.
                if current.as_ref().is_some_and(|(id, state)| {
                    *id == session_id && matches!(state, AndroidStaticAnalysis::Running)
                }) {
                    *current = Some((session_id, outcome));
                }
            }
        });
    }

    /// The static document of the APK installed in `session_id`, when ready.
    fn android_static_document(
        &self,
        session_id: &str,
    ) -> Option<Box<apiaxess_api_model::ApiDocument>> {
        let current = self.android_static.lock().ok()?;
        match current.as_ref()? {
            (id, AndroidStaticAnalysis::Ready(document)) if id == session_id => {
                Some(document.clone())
            }
            _ => None,
        }
    }

    fn install_target_apk_only(
        &self,
        apk_path: &Path,
    ) -> Result<(), Vec<apiaxess_diagnostics::Diagnostic>> {
        let guard = self
            .android_target
            .lock()
            .map_err(|_| vec![android_target_not_running()])?;
        let Some(target) = guard.as_ref() else {
            return Err(vec![android_target_not_running()]);
        };
        let output = target
            .control()
            .install_apk(apk_path, std::time::Duration::from_secs(300))
            .map_err(|diagnostic| vec![diagnostic])?;
        if output.exit_code == Some(0) {
            Ok(())
        } else {
            Err(vec![
                apiaxess_diagnostics::catalogue::ANDROID_TARGET_APK_INSTALL_FAILED.instantiate(
                    apiaxess_diagnostics::DiagnosticContext::from_iter([(
                        "stderr".to_owned(),
                        apiaxess_diagnostics::DiagnosticValue::String(output.stderr),
                    )]),
                ),
            ])
        }
    }

    fn set_android_phase(&self, phase: AndroidTargetPhase, message: &str) {
        if let Ok(mut status) = self.android_status.write() {
            status.phase = phase;
            message.clone_into(&mut status.message);
            if phase == AndroidTargetPhase::Booting {
                // A fresh launch clears any prior run's terminal fields.
                status.diagnostics.clear();
                status.streaming = false;
                status.ws_scrcpy_port = None;
                status.installed_package = None;
                status.installed_apk = None;
                status.install_note = None;
            }
        }
    }

    fn set_android_serial_phase(&self, serial: &str, phase: AndroidTargetPhase, message: &str) {
        if let Ok(mut status) = self.android_status.write() {
            status.serial = Some(serial.to_owned());
            status.phase = phase;
            message.clone_into(&mut status.message);
        }
    }

    fn mark_android_ready(&self, report: &AndroidTargetLaunchReport) {
        if let Ok(mut status) = self.android_status.write() {
            status.phase = AndroidTargetPhase::Ready;
            status.message = if report.streaming {
                "The Android target is ready — install your target APK and drive it.".to_owned()
            } else {
                "The Android target is ready, but screen streaming is unavailable (reinstall the add-on's streaming components).".to_owned()
            };
            status.serial = Some(report.serial.clone());
            status.ws_scrcpy_port = report.streaming.then_some(report.ws_scrcpy_port);
            status.streaming = report.streaming;
            status.client_apk_installed = report.client_apk_installed;
            status.frida_server_started = report.frida_server_started;
            status.android_sdk = Some(report.android_sdk);
            status.capture_proxy.clone_from(&report.capture_proxy);
            status.capture_issue.clone_from(&report.capture_issue);
            status.diagnostics.clone_from(&report.diagnostics);
        }
    }

    fn mark_android_error(&self, errors: &[apiaxess_diagnostics::Diagnostic]) {
        use apiaxess_diagnostics::DiagnosticSeverity;
        if let Ok(mut status) = self.android_status.write() {
            status.phase = AndroidTargetPhase::Error;
            // Surface the actual failure, not a leading informational line. The
            // diagnostics vector can begin with progress notes (e.g. the headless
            // "booted, ready for provisioning" info) followed by the real error;
            // showing `first()` there made the ERROR badge read as success.
            let cause = errors
                .iter()
                .find(|diagnostic| {
                    matches!(
                        diagnostic.severity,
                        DiagnosticSeverity::Error | DiagnosticSeverity::Critical
                    )
                })
                .or_else(|| errors.first());
            status.message = cause.map_or_else(
                || "The Android target failed to launch.".to_owned(),
                |diagnostic| diagnostic.what.to_string(),
            );
            status.streaming = false;
            status.ws_scrcpy_port = None;
            status.diagnostics = errors.to_vec();
        }
    }

    /// Runs the certificate-pinning bypass against the user's chosen connected
    /// device (Phase C4), so a pinned app captured by the C3 client actually
    /// decrypts at the workbench.
    ///
    /// This re-points the existing, proven bypass lanes at an arbitrary device by
    /// its adb serial (not the bundled emulator): it verifies the serial is a
    /// connected, ready device, builds that device's control transport, tags the
    /// request with the serial + a distinct Frida host port, resolves the bundled
    /// frida-server, and reuses `apply_bypass_on_control`. The C2 frida-server on
    /// the device hosts instrumentation; the workbench attaches over the adb tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`catalogue::DEVICE_FRIDA_TARGET_NOT_FOUND`] when the serial is not a
    /// ready device, or the bypass diagnostics on failure — with
    /// [`catalogue::DEVICE_PINNING_UNBEATABLE`] prepended for the honest
    /// native/anti-instrumentation boundary cases.
    pub fn bypass_pinning_on_device(
        &self,
        serial: &str,
        request: &apiaxess_sandbox::pinning::BypassRequest,
    ) -> Result<
        (
            apiaxess_sandbox::pinning::BypassOutcome,
            apiaxess_sandbox::pinning::BypassSession,
        ),
        Vec<apiaxess_diagnostics::Diagnostic>,
    > {
        use apiaxess_sandbox::device_provision::DeviceState;

        let provisioner = device_provisioner();
        let ready = provisioner
            .detect_devices()
            .map_err(|error| vec![error])?
            .into_iter()
            .any(|device| device.serial == serial && device.state == DeviceState::Ready);
        if !ready {
            return Err(vec![
                apiaxess_diagnostics::catalogue::DEVICE_FRIDA_TARGET_NOT_FOUND
                    .instantiate(device_serial_context(serial)),
            ]);
        }
        let control = provisioner
            .control_for(serial)
            .map_err(|error| vec![error])?;

        // Tag the request with the target device + bundled frida-server.
        let mut request = request.clone();
        request.frida.device_serial = Some(serial.to_owned());
        if request.toolchain.frida_server_path == PathBuf::from("frida-server") {
            request.toolchain.frida_server_path = apiaxess_sandbox::bundled_frida_server_path();
        }

        let registry = apiaxess_sandbox::pinning::BypassTechniqueRegistry::builtins();
        let runner: Arc<dyn apiaxess_external_tools::ExternalToolRunner> =
            Arc::new(apiaxess_external_tools::ProcessToolRunner);
        apiaxess_sandbox::pinning::apply_bypass_on_control(&control, &request, &registry, &runner)
            .map_err(|mut diagnostics| {
                // Surface the honest device-facing boundary summary for the cases
                // the automated lanes cannot beat (Flutter/native BoringSSL,
                // anti-instrumentation), on top of the specific lane diagnostic.
                if diagnostics.iter().any(|diagnostic| {
                    matches!(
                        diagnostic.id.as_ref(),
                        "sandbox.bypass.escalation-boundary"
                            | "sandbox.bypass.framework-offset-miss"
                    )
                }) {
                    diagnostics.insert(
                        0,
                        apiaxess_diagnostics::catalogue::DEVICE_PINNING_UNBEATABLE
                            .instantiate(apiaxess_diagnostics::DiagnosticContext::new()),
                    );
                }
                diagnostics
            })
    }

    /// Records the live loopback proxy address used by dedicated browsers.
    pub fn set_proxy_address(&self, address: std::net::SocketAddr) {
        if let Ok(mut configured) = self.proxy_address.write() {
            *configured = Some(address);
        }
    }

    /// The bound workbench MITM proxy port, if the proxy is running. Used to build
    /// the pairing QR and to arm a device's reverse tunnel (Phase C5).
    #[must_use]
    pub fn proxy_port(&self) -> Option<u16> {
        self.proxy_address
            .read()
            .ok()
            .and_then(|address| *address)
            .map(|address| address.port())
    }

    /// Launches a disposable browser window through the active session proxy.
    ///
    /// The target comes from a web-target session; APK and generic workbench
    /// sessions are rejected rather than accidentally browsing an unrelated
    /// host. Browser profile trust is always provisioned before process spawn.
    ///
    /// # Errors
    ///
    /// Returns a launch, CDP, proxy, profile, or teardown diagnostic when
    /// the dedicated browser cannot be started safely.
    #[allow(clippy::too_many_lines)] // The launch order is a security boundary: validate, pin, spawn, then attach CDP.
    fn launch_browser(
        &self,
        browser: BrowserKind,
        executable: Option<PathBuf>,
    ) -> Result<BrowserLaunchStatus, apiaxess_diagnostics::Diagnostic> {
        self.reap_closed_browser()?;
        if self
            .browser_launch
            .lock()
            .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?
            .is_some()
        {
            return Err(browser_launch_diagnostic(
                "a dedicated browser is already running for this session",
            ));
        }
        // A declared web target is optional: if none is set the browser opens on
        // the APIaxess capture landing page (a brief in-browser primer) so the
        // operator can type any URL, and everything they browse is admitted for
        // capture (not discarded as out-of-scope). With a web session active it
        // opens on that target and keeps the target scope. The landing page is
        // written into the disposable profile below, once its path is known.
        let (mut target, open_landing) = if let Ok(origin) = self.web_target_origin() {
            (origin, false)
        } else {
            self.live_workbench().set_admit_all_observed(true);
            (String::new(), true)
        };
        let proxy = self
            .proxy_address
            .read()
            .ok()
            .and_then(|value| *value)
            .ok_or_else(|| {
                browser_launch_diagnostic(
                    "the session proxy is not running; start APIaxess with the web session open",
                )
            })?;
        let (profile, trust, firefox_trust) = match browser {
            BrowserKind::Firefox => {
                let trust = self.browser_trust.provision_firefox()?;
                let profile = trust.profile_directory.clone().ok_or_else(|| {
                    browser_launch_diagnostic(
                        "browser trust provisioning did not return a disposable profile",
                    )
                })?;
                (profile, trust, true)
            }
            BrowserKind::Chromium => (
                disposable_browser_profile()?,
                self.browser_trust.status(),
                false,
            ),
        };
        // Now that the profile directory exists, materialize the landing page and
        // point the (otherwise empty) target at it.
        if open_landing {
            target = write_capture_landing_page(&profile).unwrap_or_else(|_| "about:blank".to_owned());
        }
        let binary = match browser {
            BrowserKind::Firefox => {
                executable.unwrap_or_else(|| default_browser_executable(browser))
            }
            BrowserKind::Chromium => bundled_chromium_executable()?,
        };
        let mut command = ManagedProcessCommand::new(&binary);
        match browser {
            BrowserKind::Firefox => {
                configure_firefox_proxy(&profile, proxy)?;
                command.args(["-no-remote", "-profile"]);
                command.arg(&profile);
                command.arg(&target);
            }
            BrowserKind::Chromium => {
                command.args(chromium_launch_arguments(&profile, proxy));
                command.arg("about:blank");
            }
        }
        let mut child = spawn_browser(command).map_err(|error| {
            let diagnostic = browser_launch_diagnostic(&format!(
                "could not start {} at {}: {error}",
                browser_name(browser),
                binary.display()
            ));
            if firefox_trust {
                let _ = self.browser_trust.teardown();
            }
            let _ = fs::remove_dir_all(&profile);
            diagnostic
        })?;
        let pid = child.id();
        let debug_port = if browser == BrowserKind::Chromium {
            match bootstrap_cdp(&profile, &target) {
                Ok(port) => Some(port),
                Err(error) => {
                    let _ = child.kill();
                    let _ = fs::remove_dir_all(&profile);
                    return Err(browser_cdp_diagnostic(&error));
                }
            }
        } else {
            None
        };
        let mut active = self
            .browser_launch
            .lock()
            .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?;
        *active = Some(ActiveBrowserLaunch {
            browser,
            child,
            target: target.clone(),
            profile: profile.clone(),
            firefox_trust,
            debug_port,
        });
        Ok(BrowserLaunchStatus {
            running: true,
            browser: Some(browser),
            target: Some(target),
            pid: Some(pid),
            trust,
            cdp_connected: browser == BrowserKind::Firefox || debug_port.is_some(),
            debug_port,
        })
    }

    /// Launches the owned bundled Chromium capture browser.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the bundled Chromium runtime is missing, the
    /// disposable profile cannot be prepared, or the browser process or its CDP
    /// endpoint cannot be started.
    pub fn launch_bundled_chromium(
        &self,
    ) -> Result<BrowserLaunchStatus, apiaxess_diagnostics::Diagnostic> {
        self.launch_browser(BrowserKind::Chromium, None)
    }

    /// Stops the dedicated browser and removes its disposable profile trust.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic when the process boundary, trust record,
    /// or disposable profile cannot be fully removed.
    pub fn stop_browser(&self) -> Result<BrowserLaunchStatus, apiaxess_diagnostics::Diagnostic> {
        let active = self
            .browser_launch
            .lock()
            .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?
            .take();
        if let Some(mut active) = active {
            if active
                .child
                .try_wait()
                .map_err(|error| browser_teardown_diagnostic(&error.to_string()))?
                .is_none()
            {
                active
                    .child
                    .kill()
                    .map_err(|error| browser_teardown_diagnostic(&error.to_string()))?;
            }
            if active.firefox_trust {
                self.browser_trust
                    .teardown()
                    .map_err(|error| browser_teardown_diagnostic(&error.to_string()))?;
            } else {
                fs::remove_dir_all(&active.profile).map_err(|error| {
                    browser_teardown_diagnostic(&format!(
                        "could not remove disposable Chromium profile: {error}"
                    ))
                })?;
            }
        }
        self.browser_trust.teardown()?;
        Ok(BrowserLaunchStatus::stopped(self.browser_trust.status()))
    }

    /// Returns browser status, cleaning profile trust after a user closes the
    /// dedicated browser window directly.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic when automatic cleanup cannot be verified.
    pub fn browser_launch_status(
        &self,
    ) -> Result<BrowserLaunchStatus, apiaxess_diagnostics::Diagnostic> {
        self.reap_closed_browser()?;
        let active = self
            .browser_launch
            .lock()
            .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?;
        Ok(active.as_ref().map_or_else(
            || BrowserLaunchStatus::stopped(self.browser_trust.status()),
            |active| BrowserLaunchStatus {
                running: true,
                browser: Some(active.browser),
                target: Some(active.target.clone()),
                pid: Some(active.child.id()),
                trust: self.browser_trust.status(),
                cdp_connected: active.debug_port.is_some(),
                debug_port: active.debug_port,
            },
        ))
    }

    fn reap_closed_browser(&self) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        let exited = {
            let mut active = self
                .browser_launch
                .lock()
                .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?;
            active
                .as_mut()
                .is_some_and(|launch| launch.child.try_wait().ok().flatten().is_some())
        };
        if exited {
            let active = self
                .browser_launch
                .lock()
                .map_err(|_| browser_launch_diagnostic("browser launch state is unavailable"))?
                .take();
            if let Some(active) = active {
                if active.firefox_trust {
                    self.browser_trust.teardown()?;
                } else {
                    fs::remove_dir_all(active.profile).map_err(|error| {
                        browser_teardown_diagnostic(&format!(
                            "could not remove disposable Chromium profile: {error}"
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }

    fn web_target_origin(&self) -> Result<String, apiaxess_diagnostics::Diagnostic> {
        let scope = self.session_scope()?;
        if scope.target.target_type != "web.url" {
            return Err(browser_diagnostic(
                apiaxess_diagnostics::catalogue::WEB_TARGET_REQUIRED,
                "the active session is not a web-target session",
            ));
        }
        Ok(scope.target.primary.value)
    }

    /// Stores the latest session proxy capability health for API/GUI clients.
    pub fn set_proxy_health(&self, health: BackendHealth) {
        if let Ok(mut current) = self.proxy_health.write() {
            *current = Some(health);
        }
    }

    /// Returns the latest session proxy capability health, if the proxy has
    /// completed startup probing.
    #[must_use]
    pub fn proxy_health(&self) -> Option<BackendHealth> {
        self.proxy_health
            .read()
            .ok()
            .and_then(|health| health.clone())
    }

    /// Tears down the session's isolated browser trust profile.
    ///
    /// # Errors
    ///
    /// Returns a critical teardown diagnostic if the exact NSS entry or
    /// ephemeral profile cannot be removed.
    pub fn teardown_browser_trust(&self) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        self.stop_browser().map(|_| ())
    }

    /// Returns the session-scoped fuzzer surface.
    #[must_use]
    pub fn fuzzer(&self) -> Arc<FuzzerWorkbench> {
        Arc::clone(&self.fuzzer)
    }
}

#[derive(Debug)]
struct ActiveBrowserLaunch {
    browser: BrowserKind,
    child: BrowserChild,
    target: String,
    profile: PathBuf,
    firefox_trust: bool,
    debug_port: Option<u16>,
}

/// Status for the disposable externally launched browser.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserLaunchStatus {
    /// Whether the browser process is still running.
    pub running: bool,
    /// Browser family when an instance is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserKind>,
    /// Session web target opened in the browser.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Process ID when a browser is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Disposable trust/profile state.
    pub trust: BrowserTrustStatus,
    /// Whether the browser was reached through its loopback CDP endpoint.
    pub cdp_connected: bool,
    /// Ephemeral loopback CDP port, when Chromium is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_port: Option<u16>,
}

impl BrowserLaunchStatus {
    fn stopped(trust: BrowserTrustStatus) -> Self {
        Self {
            running: false,
            browser: None,
            target: None,
            pid: None,
            trust,
            cdp_connected: false,
            debug_port: None,
        }
    }
}

fn default_browser_executable(browser: BrowserKind) -> PathBuf {
    match browser {
        BrowserKind::Firefox => env::var_os("APIAXESS_FIREFOX").map_or_else(
            || {
                PathBuf::from(if cfg!(windows) {
                    "firefox.exe"
                } else {
                    "firefox"
                })
            },
            PathBuf::from,
        ),
        BrowserKind::Chromium => env::var_os("APIAXESS_CHROMIUM").map_or_else(
            || {
                PathBuf::from(if cfg!(windows) {
                    "chromium.exe"
                } else {
                    "chromium"
                })
            },
            PathBuf::from,
        ),
    }
}

/// True when the process has no graphical display to open a browser window on
/// (a headless server/VM). On such hosts the capture browser must run headless
/// or it cannot create a window, so it never renders or navigates and captures
/// no traffic. Only consulted on Unix; Windows always has a desktop compositor.
fn no_graphical_display() -> bool {
    cfg!(unix) && env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none()
}

fn chromium_launch_arguments(profile: &Path, proxy: std::net::SocketAddr) -> Vec<String> {
    let mut arguments = Vec::new();
    // Headless-server hosts (e.g. the Linux `serve` deployment with no X/Wayland)
    // have no display for a browser window; without `--headless` Chromium fails
    // to start the renderer, so the target never loads and 0 flows are captured.
    // A host with a display keeps the proven windowed path (Windows web capture).
    if no_graphical_display() {
        arguments.push("--headless=new".to_owned());
        arguments.push("--disable-gpu".to_owned());
        arguments.push("--no-sandbox".to_owned());
    }
    arguments.extend([
        format!("--user-data-dir={}", profile.display()),
        "--ignore-certificate-errors".to_owned(),
        format!("--proxy-server=http://{proxy}"),
        "--proxy-bypass-list=<-loopback>".to_owned(),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        "--disable-background-networking".to_owned(),
        "--disable-default-apps".to_owned(),
        "--no-pings".to_owned(),
        "--disable-extensions".to_owned(),
        "--disable-breakpad".to_owned(),
        "--disable-crash-reporter".to_owned(),
        "--disk-cache-size=0".to_owned(),
        "--media-cache-size=0".to_owned(),
        "--disable-notifications".to_owned(),
        "--disable-speech-api".to_owned(),
        "--disable-file-system".to_owned(),
        "--disable-presentation-api".to_owned(),
        "--disable-permissions-api".to_owned(),
        "--disable-media-session-api".to_owned(),
        "--no-experiments".to_owned(),
        "--no-events".to_owned(),
        "--disable-features=ChromeWhatsNewUI,HttpsUpgrades,ImageServiceObserveSyncDownloadStatus,LensOverlay,RenderDocument,SessionRestoreInfobar,TrackingProtection3pcd".to_owned(),
        "--remote-debugging-port=0".to_owned(),
        "--new-window".to_owned(),
    ]);
    arguments
}

fn bundled_chromium_executable() -> Result<PathBuf, apiaxess_diagnostics::Diagnostic> {
    let executable = env::current_exe().map_err(|error| {
        browser_launch_diagnostic(&format!(
            "could not locate the APIaxess installation: {error}"
        ))
    })?;
    let install_bin = executable.parent().ok_or_else(|| {
        browser_launch_diagnostic("could not locate the APIaxess installation directory")
    })?;
    let candidate = if cfg!(windows) {
        install_bin
            .join("..")
            .join("runtime")
            .join("chromium")
            .join("chrome.exe")
    } else {
        install_bin
            .join("..")
            .join("share")
            .join("apiaxess")
            .join("chromium")
            .join("chrome")
    };
    let candidate = candidate.canonicalize().map_err(|_| browser_launch_diagnostic("the bundled APIaxess Chromium binary is missing; reinstall APIaxess so its verified browser runtime is present"))?;
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(browser_launch_diagnostic(
            "the bundled APIaxess Chromium path is not an executable file",
        ))
    }
}

/// Pre-run availability of one bundled tool at the path its resolver expects.
///
/// Surfacing this turns "learn a tool is missing by watching a run fail" into a
/// visible pre-run fact for the settings screen.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundledToolStatus {
    /// Stable tool label (matches the install-integrity component labels).
    pub label: String,
    /// Workflow group: `static`, `discovery`, `browser`, or `dynamic`.
    pub group: String,
    /// The absolute path the engine resolves for this tool.
    pub path: String,
    /// Whether the resolved path exists.
    pub present: bool,
    /// Whether an `APIAXESS_*` override is in effect for this tool.
    pub overridden: bool,
    /// Whether absence is expected by default (the analysis-runtime is a separate
    /// optional download, not part of the base install).
    pub optional: bool,
}

/// The expected bundled Chromium path (non-failing, for status display).
fn bundled_chromium_path() -> PathBuf {
    let name = if cfg!(windows) {
        "chrome.exe"
    } else {
        "chrome"
    };
    match env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    {
        Some(bin) if cfg!(windows) => bin.join("..").join("runtime").join("chromium").join(name),
        Some(bin) => bin
            .join("..")
            .join("share")
            .join("apiaxess")
            .join("chromium")
            .join(name),
        None => PathBuf::from(name),
    }
}

/// Gathers the pre-run availability of every bundled tool the product resolves by
/// absolute path, honoring operator overrides. Powers the settings tool-status
/// panel.
#[must_use]
pub fn bundled_tool_status() -> Vec<BundledToolStatus> {
    let mut statuses = Vec::new();

    // Static toolchain (java/apktool/jadx): the APK resolver's install-integrity
    // components carry the resolved bundled paths when not overridden.
    let toolchain = apiaxess_target_apk::resolve_default_toolchain();
    for component in &toolchain.bundled_components {
        statuses.push(BundledToolStatus {
            label: component.label.to_owned(),
            group: "static".to_owned(),
            path: component.path.display().to_string(),
            present: component.path.is_file(),
            overridden: false,
            optional: false,
        });
    }
    // An overridden static tool has no integrity component; surface it from env.
    for (label, key) in [
        ("java-runtime", "APIAXESS_JAVA"),
        ("apktool", "APIAXESS_APKTOOL"),
        ("jadx", "APIAXESS_JADX"),
    ] {
        if !statuses.iter().any(|status| status.label == label)
            && let Some(value) = env::var_os(key)
        {
            let path = PathBuf::from(value);
            statuses.push(BundledToolStatus {
                label: label.to_owned(),
                group: "static".to_owned(),
                present: path.exists(),
                path: path.display().to_string(),
                overridden: true,
                optional: false,
            });
        }
    }

    // ffuf (discovery).
    let (ffuf_path, ffuf_overridden) = apiaxess_workbench_proxy::resolved_ffuf();
    statuses.push(BundledToolStatus {
        label: "ffuf".to_owned(),
        group: "discovery".to_owned(),
        present: Path::new(&ffuf_path).is_file(),
        path: ffuf_path,
        overridden: ffuf_overridden,
        optional: false,
    });

    // Chromium (browser).
    let chromium = bundled_chromium_path();
    statuses.push(BundledToolStatus {
        label: "chromium".to_owned(),
        group: "browser".to_owned(),
        present: chromium.is_file(),
        path: chromium.display().to_string(),
        overridden: env::var_os("APIAXESS_CHROMIUM").is_some(),
        optional: false,
    });

    // Analysis runtime (dynamic) — the separate, optional ~2 GB payload.
    let runtime = apiaxess_sandbox::BundledEmulatorConfig::resolve(
        apiaxess_sandbox::AccelerationMode::Software,
    );
    statuses.push(BundledToolStatus {
        label: "analysis-runtime".to_owned(),
        group: "dynamic".to_owned(),
        present: runtime.emulator_executable.is_file(),
        path: runtime.runtime_root.display().to_string(),
        overridden: env::var_os("APIAXESS_ANALYSIS_RUNTIME").is_some(),
        optional: true,
    });

    // GUI Android target (Phase D1) — the separate, optional GUI-target add-on.
    let android_target_root = apiaxess_sandbox::android_target::android_target_root();
    statuses.push(BundledToolStatus {
        label: "android-target".to_owned(),
        group: "dynamic".to_owned(),
        present: apiaxess_sandbox::android_target::AndroidTargetAddon::is_present(),
        path: android_target_root.display().to_string(),
        overridden: env::var_os("APIAXESS_ANDROID_TARGET").is_some(),
        optional: true,
    });

    statuses
}

/// Diagnostic context carrying the target device serial.
fn device_serial_context(serial: &str) -> apiaxess_diagnostics::DiagnosticContext {
    let mut context = apiaxess_diagnostics::DiagnosticContext::new();
    context.insert(
        "device_serial".to_owned(),
        apiaxess_diagnostics::DiagnosticValue::String(serial.to_owned()),
    );
    context
}

/// The "no GUI Android target is running" diagnostic (Phase D3).
fn android_target_not_running() -> apiaxess_diagnostics::Diagnostic {
    apiaxess_diagnostics::catalogue::ANDROID_TARGET_NOT_RUNNING
        .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
}

fn app_open_failed(reason: &str) -> apiaxess_diagnostics::Diagnostic {
    apiaxess_diagnostics::catalogue::ANDROID_TARGET_APP_OPEN_FAILED.instantiate(
        apiaxess_diagnostics::DiagnosticContext::from_iter([(
            "reason".to_owned(),
            apiaxess_diagnostics::DiagnosticValue::String(reason.to_owned()),
        )]),
    )
}

/// The `package/Activity` component `cmd package resolve-activity --brief`
/// printed for `package`, if it resolved one. The brief output ends with the
/// component line; "No activity found" (or anything else) means none.
fn launcher_component(output: &str, package: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .rev()
        .find(|line| !line.is_empty())
        .filter(|line| {
            line.split_once('/').is_some_and(|(owner, activity)| {
                owner == package && !activity.is_empty() && !activity.contains(char::is_whitespace)
            })
        })
        .map(str::to_owned)
}

/// Builds a device provisioner over the bundled platform-tools `adb`.
fn device_provisioner() -> apiaxess_sandbox::device_provision::DeviceProvisioner {
    let runtime = apiaxess_sandbox::BundledEmulatorConfig::resolve(
        apiaxess_sandbox::AccelerationMode::Software,
    );
    apiaxess_sandbox::device_provision::DeviceProvisioner::new(
        Arc::new(apiaxess_external_tools::ProcessToolRunner),
        runtime.adb_executable.display().to_string(),
    )
}

/// The `APIaxess` capture landing page — a brief in-browser primer shown when the
/// browser is launched without a declared target. Self-contained (inline CSS),
/// dark-branded, and deliberately short: what this browser is, that its traffic
/// is captured, and where to view it.
const CAPTURE_LANDING_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>APIaxess capture browser</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#0d0d0d;color:#f0f0f0;font:16px/1.6 -apple-system,Segoe UI,Roboto,Arial,sans-serif;display:flex;align-items:center;justify-content:center;padding:32px}
.card{width:min(640px,100%)}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px}
.brand .mark{color:#2d7ff9;font-size:22px;line-height:1}
.brand .name{font-weight:700;letter-spacing:.03em;font-size:20px}
.brand .tag{margin-left:auto;font-size:12px;color:#b0b0b0;border:1px solid #262626;border-radius:4px;padding:3px 8px}
h1{font-size:26px;margin:0 0 8px}
.lede{color:#b0b0b0;margin:0 0 28px}
ol{margin:0;padding:0;list-style:none;counter-reset:step}
li{position:relative;padding:14px 0 14px 44px;border-top:1px solid #1a1a1a;counter-increment:step}
li::before{content:counter(step);position:absolute;left:0;top:12px;width:28px;height:28px;border-radius:50%;background:#1a1a1a;color:#2d7ff9;font-weight:700;font-size:13px;display:flex;align-items:center;justify-content:center}
li b{color:#f0f0f0}
.hint{margin-top:24px;font-size:13px;color:#8a8a8a}
kbd{background:#1a1a1a;border:1px solid #3d3d3d;border-radius:4px;padding:1px 6px;font-size:12px;font-family:ui-monospace,Consolas,monospace}
</style></head>
<body><main class="card">
<div class="brand"><span class="mark">&#9670;</span><span class="name">APIaxess</span><span class="tag">Capture browser</span></div>
<h1>You're browsing through APIaxess</h1>
<p class="lede">Every request this browser makes &mdash; including HTTPS &mdash; is intercepted and recorded for analysis. The blue marker in the corner of every page is how you know a page was opened here.</p>
<ol>
<li><b>Browse anything.</b> Type any URL in the address bar above, or paste a link. No target needs to be declared first.</li>
<li><b>Traffic is captured automatically.</b> Requests flow through the APIaxess proxy and appear as they happen &mdash; nothing else to switch on.</li>
<li><b>Review it in the app.</b> Switch to APIaxess &rarr; <b>Workbench</b> &rarr; <b>Live&nbsp;traffic</b> to inspect requests and responses.</li>
<li><b>Act on a request.</b> Right&#8209;click any captured request to <b>Resend</b> or <b>Fuzz</b> it, or add its domain to scope.</li>
</ol>
<p class="hint">Tip: this is a disposable session &mdash; profile data is discarded when the browser is stopped. Captured flows stay in your APIaxess session.</p>
</main></body></html>
"#;

/// Writes the capture landing page into the disposable profile and returns a
/// `file://` URL pointing at it.
fn write_capture_landing_page(profile: &Path) -> std::io::Result<String> {
    let path = profile.join("apiaxess-welcome.html");
    fs::write(&path, CAPTURE_LANDING_HTML)?;
    Ok(file_url(&path))
}

/// Builds a `file://` URL from an absolute path: forward slashes, and the few
/// characters that must not appear raw in a URL percent-encoded.
fn file_url(path: &Path) -> String {
    let text = path.to_string_lossy().replace('\\', "/");
    let mut encoded = String::from("file:///");
    for ch in text.trim_start_matches('/').chars() {
        match ch {
            ' ' => encoded.push_str("%20"),
            '#' => encoded.push_str("%23"),
            '?' => encoded.push_str("%3F"),
            '%' => encoded.push_str("%25"),
            _ => encoded.push(ch),
        }
    }
    encoded
}

fn disposable_browser_profile() -> Result<PathBuf, apiaxess_diagnostics::Diagnostic> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let profile = env::temp_dir().join(format!("apiaxess-chromium-{nonce}"));
    fs::create_dir(&profile).map_err(|error| {
        browser_launch_diagnostic(&format!(
            "could not create the disposable Chromium profile: {error}"
        ))
    })?;
    Ok(profile)
}

fn configure_firefox_proxy(
    profile: &Path,
    proxy: std::net::SocketAddr,
) -> Result<(), apiaxess_diagnostics::Diagnostic> {
    let prefs = format!(
        "user_pref(\"network.proxy.type\", 1);\nuser_pref(\"network.proxy.http\", \"{}\");\nuser_pref(\"network.proxy.http_port\", {});\nuser_pref(\"network.proxy.ssl\", \"{}\");\nuser_pref(\"network.proxy.ssl_port\", {});\nuser_pref(\"network.proxy.no_proxies_on\", \"\");\n",
        proxy.ip(),
        proxy.port(),
        proxy.ip(),
        proxy.port()
    );
    fs::write(profile.join("user.js"), prefs).map_err(|error| {
        browser_launch_diagnostic(&format!(
            "could not configure the disposable Firefox profile: {error}"
        ))
    })
}

fn browser_name(browser: BrowserKind) -> &'static str {
    match browser {
        BrowserKind::Firefox => "Firefox",
        BrowserKind::Chromium => "Chromium",
    }
}

fn discovery_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    reason: &str,
) -> apiaxess_diagnostics::Diagnostic {
    browser_diagnostic(definition, reason)
}

fn browser_launch_diagnostic(reason: &str) -> apiaxess_diagnostics::Diagnostic {
    browser_diagnostic(
        apiaxess_diagnostics::catalogue::PROXY_BUNDLED_BROWSER_LAUNCH_FAILURE,
        reason,
    )
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("~{seconds}s")
    } else if seconds < 3_600 {
        format!("~{}m", seconds.div_ceil(60))
    } else {
        format!("~{}h {}m", seconds / 3_600, (seconds % 3_600).div_ceil(60))
    }
}

fn browser_cdp_diagnostic(reason: &str) -> apiaxess_diagnostics::Diagnostic {
    let mut diagnostic = browser_diagnostic(
        apiaxess_diagnostics::catalogue::PROXY_CDP_CONNECT_FAILURE,
        reason,
    );
    diagnostic.why = format!("{} Reason: {reason}", diagnostic.why).into();
    diagnostic
}

fn browser_teardown_diagnostic(reason: &str) -> apiaxess_diagnostics::Diagnostic {
    browser_diagnostic(
        apiaxess_diagnostics::catalogue::PROXY_TEARDOWN_INCOMPLETE,
        reason,
    )
}

fn browser_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    reason: &str,
) -> apiaxess_diagnostics::Diagnostic {
    let mut context = apiaxess_diagnostics::DiagnosticContext::new();
    context.insert(
        "reason".to_owned(),
        apiaxess_diagnostics::DiagnosticValue::String(reason.to_owned()),
    );
    definition.instantiate(context)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WebTarget {
    origin: String,
    host: String,
    port: Option<u16>,
}

impl WebTarget {
    fn parse(value: &str) -> Result<Self, apiaxess_diagnostics::Diagnostic> {
        let value = value.trim();
        let with_scheme = if value.contains("://") {
            value.to_owned()
        } else {
            format!("https://{value}")
        };
        let (scheme, authority_and_path) = with_scheme
            .split_once("://")
            .ok_or_else(|| web_session_diagnostic("target must be a domain or http(s) URL"))?;
        if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
            return Err(web_session_diagnostic(
                "target URL scheme must be http or https",
            ));
        }
        let authority = authority_and_path
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(web_session_diagnostic(
                "target must contain a hostname without credentials",
            ));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| {
                        web_session_diagnostic("target URL port must be a non-zero integer")
                    })?;
                (host, Some(port))
            }
            _ => (authority, None),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.chars().any(char::is_whitespace) || host.contains(['/', ':']) {
            return Err(web_session_diagnostic("target hostname is invalid"));
        }
        let authority = port.map_or_else(|| host.clone(), |port| format!("{host}:{port}"));
        Ok(Self {
            origin: format!("{}://{}", scheme.to_ascii_lowercase(), authority),
            host,
            port,
        })
    }
}

fn web_session_diagnostic(reason: &str) -> apiaxess_diagnostics::Diagnostic {
    let mut context = apiaxess_diagnostics::DiagnosticContext::new();
    context.insert(
        "reason".to_owned(),
        apiaxess_diagnostics::DiagnosticValue::String(reason.to_owned()),
    );
    let mut diagnostic =
        apiaxess_diagnostics::catalogue::SESSION_INVARIANT_FAILED.instantiate(context);
    diagnostic.what = "Web session could not be started".into();
    diagnostic.why = reason.into();
    diagnostic.fix = "Provide a valid domain or HTTP(S) URL and explicitly affirm authorization for that target.".into();
    diagnostic
}

fn session_store_root() -> PathBuf {
    if let Some(configured) = env::var_os("APIAXESS_WORKBENCH_STORE_DIR") {
        return PathBuf::from(configured);
    }
    durable_data_root().join("apiaxess").join("workbench")
}

/// Returns a durable, per-user application-data directory for session state.
///
/// Sessions are the product's durability promise, so the default must survive
/// reboots and Windows' periodic `%TEMP%` cleanup. The platform-native data
/// directory is derived from standard environment variables (no extra
/// dependency); `env::temp_dir()` is a last resort only when none are set,
/// which effectively never happens on a real desktop session.
fn durable_data_root() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local);
        }
        if let Some(appdata) = env::var_os("APPDATA") {
            return PathBuf::from(appdata);
        }
        if let Some(profile) = env::var_os("USERPROFILE") {
            return PathBuf::from(profile).join("AppData").join("Local");
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg);
        }
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home).join(".local").join("share");
        }
    }
    env::temp_dir()
}

fn pipeline_failure(
    config: &PipelineConfig,
    diagnostic: apiaxess_diagnostics::Diagnostic,
) -> PipelineFailure {
    PipelineFailure {
        stage: PipelineStage::Intake,
        diagnostics: vec![diagnostic.clone()].into_boxed_slice(),
        progress: Box::new(PipelineProgress {
            run_id: config.run_id.clone(),
            stage: PipelineStage::Intake,
            status: PipelineRunStatus::Failed,
            progress_basis_points: 0,
            message: "No active session runtime is attached".to_owned(),
            diagnostics: vec![diagnostic],
            dynamic_ran: false,
            updated_at: chrono::Utc::now(),
        }),
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// What identifies the session target's own backend: a web target's own
/// origin/host, or an APK's package name. Scope rules are not used, because
/// they can include third parties the target was authorized to reach.
fn first_party_hints(
    scope: &apiaxess_session::EngagementScope,
) -> apiaxess_unified_surface::FirstPartyHints {
    let identifiers = std::iter::once(&scope.target.primary)
        .chain(&scope.target.aliases)
        .collect::<Vec<_>>();
    let value_of = |kinds: &[&str]| {
        identifiers
            .iter()
            .filter(|identifier| kinds.contains(&identifier.kind.as_str()))
            .map(|identifier| identifier.value.clone())
            .collect::<Vec<_>>()
    };
    apiaxess_unified_surface::FirstPartyHints {
        app_package: value_of(&["android.package"]).into_iter().next(),
        first_party_hosts: value_of(&["url.origin", "domain.host"]),
    }
}

#[cfg(test)]
mod tests {
    use super::{bundled_wordlist, chromium_launch_arguments};
    use std::{net::SocketAddr, path::Path};

    #[test]
    fn large_wordlist_is_real_curated_content_not_synthetic_placeholders() {
        let large = bundled_wordlist("large").expect("large wordlist is bundled");
        // Must be materially larger than medium so the choice is meaningful.
        let medium = bundled_wordlist("medium").expect("medium wordlist is bundled");
        assert!(
            large.len() > medium.len() * 4,
            "large ({}) should dwarf medium ({})",
            large.len(),
            medium.len()
        );
        // Real, deduplicated, comment/blank-free tokens.
        assert!(large.iter().all(|entry| !entry.is_empty()));
        assert!(large.iter().all(|entry| !entry.starts_with('#')));
        let unique: std::collections::BTreeSet<_> = large.iter().collect();
        assert_eq!(unique.len(), large.len(), "entries must be unique");
        // Must contain genuinely common hosts, and none of the old synthetic
        // `candidate-N` placeholders that could never match a real target.
        assert!(large.iter().any(|entry| entry == "admin"));
        assert!(large.iter().any(|entry| entry == "graphql"));
        assert!(!large.iter().any(|entry| entry.starts_with("candidate-")));
    }

    #[test]
    fn unknown_wordlist_names_are_rejected() {
        assert!(bundled_wordlist("gigantic").is_none());
    }

    #[test]
    fn chromium_uses_burps_disposable_blanket_trust_profile() {
        let arguments = chromium_launch_arguments(
            Path::new("C:\\temp\\apiaxess-chromium"),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        );

        assert!(
            arguments
                .iter()
                .any(|arg| arg == "--ignore-certificate-errors")
        );
        assert!(
            !arguments
                .iter()
                .any(|arg| arg.starts_with("--ignore-certificate-errors-spki-list"))
        );
        assert!(
            arguments
                .iter()
                .any(|arg| arg == "--user-data-dir=C:\\temp\\apiaxess-chromium")
        );
        assert!(
            arguments
                .iter()
                .any(|arg| arg == "--proxy-server=http://127.0.0.1:8080")
        );
        assert!(
            arguments
                .iter()
                .any(|arg| arg == "--proxy-bypass-list=<-loopback>")
        );
    }

    /// An engine with a fresh session attached, scoped to `hosts` (none: the
    /// session has no declared scope, as before a target is declared).
    fn engine_with_session(hosts: &[&str]) -> super::Engine {
        use apiaxess_session::{
            AllowedNetworkTarget, EngagementScope, HostMatch, Session, SessionId, TargetIdentifier,
            TargetIdentity,
        };
        let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        let root = std::env::temp_dir().join(format!("apiaxess-engine-test-{nanos}"));
        let now = chrono::Utc::now();
        let session_id = SessionId::new(format!("session:engine-test-{nanos}")).expect("id");
        let scope = EngagementScope {
            declared_at: now,
            target: TargetIdentity {
                target_type: "local-workbench".to_owned(),
                primary: TargetIdentifier {
                    kind: "session.id".to_owned(),
                    value: session_id.as_str().to_owned(),
                },
                aliases: Vec::new(),
            },
            allowed_targets: hosts
                .iter()
                .map(|host| AllowedNetworkTarget {
                    id: format!("test:{host}"),
                    host: HostMatch::Exact {
                        host: (*host).to_owned(),
                    },
                    ports: Vec::new(),
                })
                .collect(),
        };
        let mut session = Session::new(
            session_id,
            scope,
            apiaxess_api_model::ApiDocument::new(apiaxess_api_model::ApiSurface {
                provenance: apiaxess_api_model::ProvenanceRegistry::default(),
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            now,
        );
        session.activate(now).expect("activate");
        let store = std::sync::Arc::new(
            apiaxess_workbench_store::TrafficStore::open(&root, session.id().as_str())
                .expect("store"),
        );
        let engine = super::Engine::new();
        engine
            .attach_session_runtime(std::sync::Arc::new(super::SessionRuntime::new(
                session,
                store,
                root.join("session.json"),
            )))
            .expect("attach");
        engine
    }

    fn har(entries: &[(&str, &str)]) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(method, url)| {
                serde_json::json!({
                    "request": {"method": method, "url": url, "headers": []},
                    "response": {"status": 200, "headers": [
                        {"name": "content-type", "value": "application/json"}
                    ], "content": {"text": "{\"ok\":true}", "mimeType": "application/json"}}
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&serde_json::json!({"log": {"entries": entries}})).expect("har")
    }

    fn stored_scopes(engine: &super::Engine) -> Vec<(String, apiaxess_session::ScopeDisposition)> {
        let runtime = engine.session_runtime().expect("runtime").expect("session");
        runtime
            .store()
            .summaries()
            .expect("summaries")
            .into_iter()
            .map(|flow| (flow.host.unwrap_or_default(), flow.scope))
            .collect()
    }

    #[test]
    fn a_har_imported_without_a_scope_is_scoped_to_its_own_first_party_hosts_and_fuses() {
        let engine = engine_with_session(&[]);
        let report = engine
            .import_har(&har(&[
                ("GET", "https://app.example.test/v1/items"),
                ("GET", "https://app.example.test:8443/v1/items/7"),
                ("POST", "https://api.example.test/v1/orders"),
                ("GET", "https://cdn.tracker.test/pixel.gif"),
            ]))
            .expect("import");
        assert_eq!(report.imported, 4);
        let derived = report.derived_scope.expect("a scope was derived");
        assert_eq!(derived.hosts, vec!["api.example.test", "app.example.test"]);
        assert_eq!(derived.excluded_hosts, vec!["cdn.tracker.test"]);
        // Exactly the HAR's own first-party hosts: exact rules, never wider.
        let scope = engine.session_scope().expect("scope");
        assert!(scope.allowed_targets.iter().all(|rule| matches!(
            &rule.host,
            apiaxess_session::HostMatch::Exact { host } if derived.hosts.contains(host)
        )));
        assert_eq!(scope.allowed_targets.len(), 2);
        for (host, disposition) in stored_scopes(&engine) {
            let expected = if host == "cdn.tracker.test" {
                apiaxess_session::ScopeDisposition::OutsideDeclaredScope
            } else {
                apiaxess_session::ScopeDisposition::InScope
            };
            assert_eq!(disposition, expected, "{host}");
        }
        // Recorded in the audit trail as derived, not as an operator action.
        let audit = engine.session_audit().expect("audit");
        assert!(audit.iter().any(|record| {
            serde_json::to_string(record)
                .expect("record")
                .contains("session.scope.derive-from-har")
        }));
        // Import a HAR, fuse, get a surface.
        let surface = engine.fuse_web_capture().expect("fuse");
        let mut endpoints = surface
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.endpoint.identity.host.clone().unwrap_or_default(),
                    endpoint.endpoint.identity.path_template.as_str().to_owned(),
                )
            })
            .collect::<Vec<_>>();
        endpoints.sort();
        assert_eq!(
            endpoints,
            vec![
                ("api.example.test".to_owned(), "/v1/orders".to_owned()),
                ("app.example.test".to_owned(), "/v1/items".to_owned()),
                // A non-default port is part of an endpoint's host identity.
                (
                    "app.example.test:8443".to_owned(),
                    "/v1/items/{id}".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_har_imported_into_a_scoped_session_leaves_the_scope_alone() {
        let engine = engine_with_session(&["app.example.test"]);
        let before = engine.session_scope().expect("scope");
        let report = engine
            .import_har(&har(&[
                ("GET", "https://app.example.test/v1/items"),
                ("GET", "https://other.example.test/v1/items"),
            ]))
            .expect("import");
        assert_eq!(report.imported, 2);
        assert!(report.derived_scope.is_none());
        assert_eq!(engine.session_scope().expect("scope"), before);
        let mut scopes = stored_scopes(&engine);
        scopes.sort_by(|left, right| left.0.cmp(&right.0));
        assert_eq!(
            scopes,
            vec![
                (
                    "app.example.test".to_owned(),
                    apiaxess_session::ScopeDisposition::InScope
                ),
                (
                    "other.example.test".to_owned(),
                    apiaxess_session::ScopeDisposition::OutsideDeclaredScope
                ),
            ]
        );
    }

    #[test]
    fn web_fuse_lifts_graphql_operations_and_grpc_calls_from_captured_traffic() {
        let engine = engine_with_session(&["api.example.test"]);
        let runtime = engine.session_runtime().expect("runtime").expect("session");
        let store = runtime.store();
        let captured = |method: &str, path: &str, content_type: &str, body: &[u8]| {
            apiaxess_workbench_store::FlowCapture {
                id: store.allocate_flow_id(),
                captured_at: chrono::Utc::now(),
                protocol: "h2".to_owned(),
                method: Some(method.to_owned()),
                host: Some("api.example.test".to_owned()),
                url: Some(format!("https://api.example.test{path}")),
                path: Some(path.to_owned()),
                status: Some(200),
                duration_ms: Some(3),
                request_headers: vec![("content-type".to_owned(), content_type.to_owned())],
                response_headers: vec![("content-type".to_owned(), content_type.to_owned())],
                request_body: Some(body.to_vec()),
                response_body: None,
                scope: apiaxess_session::ScopeDisposition::InScope,
                provenance: "proxy.observer".to_owned(),
                origin: apiaxess_workbench_store::FlowOrigin::Capture,
            }
        };
        store
            .upsert(&captured(
                "POST",
                "/graphql",
                "application/json",
                br#"{"operationName":"AddToCart","query":"mutation AddToCart($sku: ID!) { addToCart(sku: $sku) { id } }"}"#,
            ))
            .expect("graphql flow");
        store
            .upsert(&captured(
                "POST",
                "/shop.v1.CartService/Checkout",
                "application/grpc",
                &[0, 0, 0, 0, 2, 8, 1],
            ))
            .expect("grpc flow");
        let surface = engine.fuse_web_capture().expect("fuse");
        let operations = surface
            .surface
            .protocol_operations
            .iter()
            .map(|operation| operation.identity.clone())
            .collect::<Vec<_>>();
        assert!(
            operations.contains(&apiaxess_api_model::ProtocolOperationIdentity::GraphQl {
                endpoint_url: Some("https://api.example.test/graphql".to_owned()),
                operation_type: apiaxess_api_model::GraphQlOperationType::Mutation,
                operation_name: "AddToCart".to_owned(),
            })
        );
        assert!(
            operations.contains(&apiaxess_api_model::ProtocolOperationIdentity::Grpc {
                service: "shop.v1.CartService".to_owned(),
                method: "Checkout".to_owned(),
            })
        );
        // The gRPC call is not also an opaque REST POST.
        assert!(
            surface.endpoints.iter().all(|endpoint| endpoint
                .endpoint
                .identity
                .path_template
                .as_str()
                != "/shop.v1.CartService/Checkout")
        );
    }

    #[test]
    fn android_target_status_starts_idle() {
        let engine = super::Engine::new();
        let status = engine.android_target_status();
        assert_eq!(status.phase, super::AndroidTargetPhase::Idle);
        assert!(!status.streaming);
        assert!(status.ws_scrcpy_port.is_none());
    }

    #[test]
    fn android_launch_guard_is_single_flight_and_marks_booting() {
        let engine = super::Engine::new();
        assert!(
            engine.begin_android_launch(),
            "the first launch claims the guard"
        );
        assert_eq!(
            engine.android_target_status().phase,
            super::AndroidTargetPhase::Booting
        );
        assert!(
            !engine.begin_android_launch(),
            "a second concurrent launch is refused while one is in flight"
        );
    }

    #[test]
    fn mark_android_error_surfaces_the_failure_not_a_leading_info_note() {
        use apiaxess_diagnostics::{DiagnosticContext, catalogue};
        let engine = super::Engine::new();
        // Mirrors a real failed launch: a progress info note ("booted, ready for
        // provisioning") ahead of the actual error (no system CA trust). The
        // ERROR badge must read the error, never the reassuring info line.
        let booted = catalogue::ANDROID_TARGET_BOOTED.instantiate(DiagnosticContext::new());
        let failure =
            catalogue::SANDBOX_CA_SYSTEM_STORE_UNAVAILABLE.instantiate(DiagnosticContext::new());
        engine.mark_android_error(&[booted, failure.clone()]);
        let status = engine.android_target_status();
        assert_eq!(status.phase, super::AndroidTargetPhase::Error);
        assert_eq!(status.message, failure.what.to_string());
        assert_ne!(status.message, "The GUI Android target booted headless and is ready for provisioning.");
    }

    #[test]
    fn launcher_component_is_read_from_resolve_activity_output() {
        let output = "priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false\n\
                      pro.mailaccess.reference/.MainActivity\n";
        assert_eq!(
            super::launcher_component(output, "pro.mailaccess.reference").as_deref(),
            Some("pro.mailaccess.reference/.MainActivity")
        );
        assert_eq!(
            super::launcher_component("No activity found\n", "pro.mailaccess.reference"),
            None
        );
        // A component for a different package is not this app's launcher.
        assert_eq!(
            super::launcher_component(
                "com.android.launcher3/.Launcher\n",
                "pro.mailaccess.reference"
            ),
            None
        );
        assert_eq!(
            super::launcher_component("", "pro.mailaccess.reference"),
            None
        );
    }

    #[test]
    fn open_app_before_any_install_is_actionable() {
        let engine = super::Engine::new();
        let error = engine.open_target_app().expect_err("nothing installed");
        assert_eq!(
            error[0].id.as_ref(),
            "sandbox.android-target-app-open-failed"
        );
    }

    #[test]
    fn install_target_apk_without_a_running_target_is_actionable() {
        let engine = super::Engine::new();
        let error = engine
            .install_target_apk(Path::new("target.apk"))
            .expect_err("no target is running");
        assert_eq!(error[0].id.as_ref(), "sandbox.android-target-not-running");
    }
}
