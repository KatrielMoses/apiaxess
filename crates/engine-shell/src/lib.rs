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
/// Canonical session aggregate consumed by future feature orchestration.
pub use apiaxess_session as session;

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use apiaxess_confidence::ConfidenceConfig;
use apiaxess_external_tools::ManagedProcessCommand;
use apiaxess_plugin_host::PluginHost;
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AllowedNetworkTarget,
    AuditActor, EngagementScope, HostMatch, Session, TargetIdentifier, TargetIdentity,
};
use apiaxess_workbench_proxy::{
    BackendHealth, BrowserKind, BrowserTrustController, BrowserTrustStatus, IntruderWorkbench,
    LiveWorkbench, RepeaterSender, RepeaterWorkbench, SessionCa,
};
use apiaxess_workbench_store::TrafficStore;
use apiaxess_workbench_store::{
    IntruderAttackType, IntruderConfig, IntruderMatchFilter, IntruderPositionLocation,
    PayloadPosition, PayloadSet, RepeaterRequest,
};
use serde::Serialize;

use browser::{BrowserChild, bootstrap_cdp, spawn_browser};

/// Minimal engine handle shared with transport adapters.
#[derive(Clone, Debug)]
pub struct Engine {
    _plugin_host: Arc<PluginHost>,
    live_workbench: Arc<LiveWorkbench>,
    repeater: Arc<RepeaterWorkbench>,
    intruder: Arc<IntruderWorkbench>,
    browser_trust: Arc<BrowserTrustController>,
    session_ca: Arc<RwLock<Option<SessionCa>>>,
    browser_launch: Arc<std::sync::Mutex<Option<ActiveBrowserLaunch>>>,
    proxy_address: Arc<RwLock<Option<std::net::SocketAddr>>>,
    session_runtime: Arc<RwLock<Option<Arc<SessionRuntime>>>>,
    proxy_health: Arc<RwLock<Option<BackendHealth>>>,
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

/// Real, curated "large" discovery wordlist bundled with the application.
///
/// Hand-curated candidates common to production web and API deployments; every
/// entry is a host/route a real target can plausibly expose. This replaces an
/// earlier synthetic generator whose 500 `candidate-N` strings could never
/// match anything but were presented as a co-equal choice.
const LARGE_WORDLIST: &str = include_str!("wordlists/large.txt");

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

/// Wordlists shipped with the application, intentionally small and useful by default.
pub fn bundled_wordlist(name: &str) -> Option<Vec<String>> {
    if name == "large" {
        let values = parse_wordlist(LARGE_WORDLIST);
        return (!values.is_empty()).then_some(values);
    }
    let values = match name {
        "small" => vec![
            "www", "api", "app", "dev", "staging", "admin", "v1", "health",
        ],
        "medium" => vec![
            "www", "api", "app", "admin", "auth", "dev", "test", "staging", "cdn", "static",
            "assets", "internal", "portal", "login", "health", "docs", "v1", "v2",
        ],
        _ => return None,
    };
    Some(values.into_iter().map(str::to_owned).collect())
}

impl Engine {
    /// Creates the engine shell without analysis behavior.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _plugin_host: Arc::new(PluginHost::new()),
            live_workbench: Arc::new(LiveWorkbench::new()),
            repeater: Arc::new(RepeaterWorkbench::new()),
            intruder: Arc::new(IntruderWorkbench::new()),
            browser_trust: Arc::new(BrowserTrustController::new()),
            session_ca: Arc::new(RwLock::new(None)),
            browser_launch: Arc::new(std::sync::Mutex::new(None)),
            proxy_address: Arc::new(RwLock::new(None)),
            session_runtime: Arc::new(RwLock::new(None)),
            proxy_health: Arc::new(RwLock::new(None)),
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
        if let Err(diagnostic) = self.repeater.attach_store(Arc::clone(store)) {
            self.live_workbench.publish_diagnostic(diagnostic);
        }
        if let Err(diagnostic) = self.intruder.attach_store(Arc::clone(store)) {
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
        let runtime = self.session_runtime()?.ok_or_else(|| {
            apiaxess_diagnostics::catalogue::PROXY_SESSION_NOT_ACTIVE
                .instantiate(apiaxess_diagnostics::DiagnosticContext::new())
        })?;
        let now = chrono::Utc::now();
        let mut session = runtime.session_snapshot()?;
        session.update_engagement_scope(scope, now)?;
        let action_id = format!(
            "session.scope.update:{}",
            fresh_session_id()?.as_str().trim_start_matches("session:")
        );
        session.record_action(ActionRecordInput {
            id: action_id,
            occurred_at: now,
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "session.scope.update".to_owned(),
                summary: "Updated the declared engagement scope".to_owned(),
            },
            target: ActionTarget::SessionTarget,
            outcome: ActionOutcome::Completed,
            diagnostics: Vec::new(),
        })?;
        runtime.replace_session(session)?;
        self.set_engagement_scope(runtime.session_snapshot()?.engagement_scope().clone());
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
            .ok_or_else(|| browser_launch_diagnostic("discovery wordlist was not found"))?;
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
    pub fn start_discovery(
        &self,
        kind: DiscoveryKind,
        wordlist: &str,
        custom: Option<Vec<String>>,
        confirmed: bool,
    ) -> Result<apiaxess_workbench_store::IntruderJob, apiaxess_diagnostics::Diagnostic> {
        let values = custom
            .or_else(|| bundled_wordlist(wordlist))
            .ok_or_else(|| browser_launch_diagnostic("discovery wordlist was not found"))?;
        let estimate = self.estimate_discovery(kind, wordlist, Some(values.clone()))?;
        if !confirmed {
            return Err(browser_launch_diagnostic(&format!(
                "active discovery requires confirmation: {} requests against {} (estimated {})",
                estimate.request_count, estimate.target, estimate.estimated_label
            )));
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
        let config = IntruderConfig {
            base_request: RepeaterRequest {
                method: "GET".to_owned(),
                url: marker,
                headers: Vec::new(),
                body: None,
            },
            positions: vec![PayloadPosition {
                location: IntruderPositionLocation::Url,
                header_name: None,
                start,
                end: start + 4,
                set_index: 0,
            }],
            payload_sets: vec![PayloadSet {
                name: wordlist.to_owned(),
                values,
            }],
            attack_type: IntruderAttackType::Sniper,
            match_filter: IntruderMatchFilter::default(),
            concurrency: 1,
            rate_per_second: estimate.rate_per_second,
            max_results: estimate.request_count,
            auth_preflight: None,
            sequence: Vec::new(),
            // Directory discovery auto-calibrates against a soft-404/catch-all so
            // a WAF/wildcard site that answers every path yields no fake hits.
            // Subdomain discovery is DNS-resolved and needs no calibration.
            auto_calibrate: matches!(kind, DiscoveryKind::Directory),
        };
        let job = self.intruder.create(config)?;
        // Keep the discovery template as a durable repeater context immediately;
        // completed hits can then be edited/sent through the same workbench
        // without a separate export/import step.
        let _ = self
            .repeater
            .create(job.config.base_request.clone(), None)?;
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
        self.intruder.launch_in_session(&job.id, &mut session)?;
        runtime.replace_session(session)?;
        runtime.save()?;
        Ok(job)
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
        let config = apiaxess_dynamic_capture::DynamicCaptureConfig::new(run_id.clone())
            .map_err(|error| vec![error])?;
        apiaxess_dynamic_capture::capture_into_session(
            &mut session,
            &runtime.store(),
            &config,
            chrono::Utc::now(),
        )?;
        let confidence_config =
            ConfidenceConfig::new(format!("{run_id}:confidence")).map_err(|error| vec![error])?;
        let confidence = apiaxess_confidence::recompute_document(
            &session.api_document().clone(),
            &confidence_config,
            chrono::Utc::now(),
        )
        .map_err(|diagnostics| diagnostics.into_iter().collect::<Vec<_>>())?;
        let surface_config =
            apiaxess_unified_surface::UnifiedSurfaceConfig::new(format!("{run_id}:surface"))
                .map_err(|error| vec![error])?;
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

    /// Returns the session-scoped manual repeater surface.
    #[must_use]
    pub fn repeater(&self) -> Arc<RepeaterWorkbench> {
        Arc::clone(&self.repeater)
    }

    /// Attaches the running routed proxy as the repeater's send transport.
    pub fn attach_repeater_sender(&self, sender: Arc<dyn RepeaterSender>) {
        self.repeater.attach_sender(Arc::clone(&sender));
        self.intruder.attach_sender(sender);
    }

    /// Applies the active session's advisory scope to every workbench sender.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        self.live_workbench.set_engagement_scope(scope.clone());
        self.repeater.set_engagement_scope(scope.clone());
        self.intruder.set_engagement_scope(scope);
    }

    /// Supplies the active proxy listener used by stateless ffuf jobs.
    pub fn set_intruder_ffuf_proxy(&self, address: std::net::SocketAddr) {
        self.intruder.set_ffuf_proxy(address);
    }

    /// Binds browser trust provisioning to the active session CA.
    pub fn configure_browser_ca(&self, ca: SessionCa) {
        self.browser_trust.configure_ca(ca.clone());
        if let Ok(mut configured) = self.session_ca.write() {
            *configured = Some(ca);
        }
    }

    /// Records the live loopback proxy address used by dedicated browsers.
    pub fn set_proxy_address(&self, address: std::net::SocketAddr) {
        if let Ok(mut configured) = self.proxy_address.write() {
            *configured = Some(address);
        }
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
        let target = self.web_target_origin()?;
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
            return Err(browser_launch_diagnostic(
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

    /// Returns the session-scoped intruder surface.
    #[must_use]
    pub fn intruder(&self) -> Arc<IntruderWorkbench> {
        Arc::clone(&self.intruder)
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
    cfg!(unix)
        && env::var_os("DISPLAY").is_none()
        && env::var_os("WAYLAND_DISPLAY").is_none()
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

    statuses
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
}
