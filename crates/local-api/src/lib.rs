//! Loopback HTTP/WebSocket transport and static GUI asset serving.

mod pairing;
mod settings;
mod stream_proxy;

pub use settings::persisted_env_overrides;

use pairing::{DevicePairingRegistry, PairingOutcome, PendingPairingRegistry};

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use apiaxess_diagnostics::{DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_engine_shell::{
    Engine, ExportConfig, PipelineConfig, PipelineProgress, PipelineRunStatus, PipelineStage,
};
use apiaxess_session::EngagementScope;
use apiaxess_workbench_proxy::{
    FlowDetail, FlowSummary, InterceptDecision, LiveWorkbench, ResendRequest,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, Query, State, WebSocketUpgrade},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ORIGIN},
    },
    response::{IntoResponse, Response},
    routing::{any_service, get},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

/// Creates the local API router on the default engine port.
///
/// # Errors
///
/// Returns an I/O error when the built GUI entry point is unavailable.
pub fn router(engine: Engine, gui_directory: &Path) -> io::Result<Router> {
    router_with_port(engine, gui_directory, 7_777)
}

/// Creates the local API router with an explicit expected loopback port.
///
/// The port is part of the WebSocket Origin contract. The caller must bind the
/// returned router to the same port.
///
/// # Errors
///
/// Returns an I/O error when the built GUI entry point is unavailable.
#[allow(clippy::too_many_lines)] // A flat, auditable route table reads better than split builders.
pub fn router_with_port(engine: Engine, gui_directory: &Path, port: u16) -> io::Result<Router> {
    let index = gui_directory.join("index.html");
    index.metadata()?;
    // Cache policy for the packaged GUI, so a rebuilt bundle is picked up without a
    // manual hard-refresh. Vite fingerprints everything under `/assets/` by content
    // hash, so those are safe to cache forever (immutable). `index.html` and every
    // other non-fingerprinted static file (fonts, favicons) must revalidate on each
    // load (`no-cache` = revalidate, a 304 is fine) so a new build's new asset
    // hashes are always requested. Applied as thin response-header layers over the
    // static services rather than per-file special-casing.
    let hashed_assets = any_service(ServeDir::new(gui_directory.join("assets"))).layer(
        SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        ),
    );
    let gui_assets =
        any_service(ServeDir::new(gui_directory).not_found_service(ServeFile::new(index))).layer(
            SetResponseHeaderLayer::overriding(CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        );
    let state = ApiState {
        engine,
        expected_origin: Arc::from(format!("http://127.0.0.1:{port}")),
        pipeline_runs: PipelineRegistry::default(),
        pairing: DevicePairingRegistry::default(),
        pending_pairing: PendingPairingRegistry::default(),
        gui_port: port,
    };

    Ok(Router::new()
        .route("/api/v1/system/status", get(system_status))
        .route("/api/v1/pick-file", axum::routing::post(pick_file))
        .route(
            "/api/v1/settings",
            get(get_settings).put(update_settings_handler),
        )
        .route("/api/v1/pairing/ca", get(pairing_ca))
        .route(
            "/api/v1/pairing/token",
            axum::routing::post(mint_pairing_token),
        )
        .route(
            "/api/v1/pairing/exchange",
            axum::routing::post(exchange_pairing_token),
        )
        .route(
            "/api/v1/pairing/exchange/{request_id}",
            get(poll_pairing_exchange),
        )
        .route("/api/v1/pairing/devices", get(pairing_devices))
        .route("/api/v1/pairing/arm", axum::routing::post(arm_pairing))
        .route("/api/v1/pairing/pending", get(list_pending_pairing))
        .route(
            "/api/v1/pairing/pending/{request_id}/accept",
            axum::routing::post(accept_pairing),
        )
        .route(
            "/api/v1/pairing/pending/{request_id}/decline",
            axum::routing::post(decline_pairing),
        )
        .route(
            "/api/v1/pairing/devices/{serial}/bypass",
            axum::routing::post(bypass_device),
        )
        .route("/api/v1/session", get(session_status))
        .route(
            "/api/v1/session/scope",
            get(session_scope).put(update_session_scope),
        )
        .route("/api/v1/session/audit", get(session_audit))
        .route("/api/v1/session/new", axum::routing::post(new_session))
        .route(
            "/api/v1/session/web",
            axum::routing::post(start_web_session),
        )
        .route("/api/v1/session/open", axum::routing::post(open_session))
        .route("/api/v1/session/save", axum::routing::post(save_session))
        .route(
            "/api/v1/discovery/estimate",
            axum::routing::post(discovery_estimate),
        )
        .route("/api/v1/discovery/run", axum::routing::post(discovery_run))
        .route(
            "/api/v1/discovery/wordlists",
            axum::routing::get(discovery_wordlists),
        )
        .route("/api/v1/web/fuse", axum::routing::post(fuse_web_capture))
        .route(
            "/api/v1/pipeline",
            get(current_pipeline_status).post(start_pipeline),
        )
        .route("/api/v1/pipeline/{run_id}", get(pipeline_status))
        .route("/api/v1/pipeline/{run_id}/surface", get(pipeline_surface))
        .route(
            "/api/v1/pipeline/{run_id}/surface-summary",
            get(pipeline_surface_summary),
        )
        .route("/api/v1/surface", get(current_surface))
        .route("/api/v1/export", axum::routing::post(export_artifacts))
        .route("/api/v1/workbench/session", get(workbench_session))
        .route("/api/v1/workbench/health", get(workbench_health))
        .route("/api/v1/workbench/diagnostics", get(workbench_diagnostics))
        .route(
            "/api/v1/workbench/browser",
            get(browser_launch_status)
                .post(launch_browser)
                .delete(stop_browser),
        )
        .route("/api/v1/workbench/flows", get(list_flows))
        .route("/api/v1/workbench/flows/{flow_id}", get(get_flow))
        .route("/api/v1/workbench/intercept/pending", get(pending_flows))
        .route("/api/v1/workbench/har", get(export_har).post(import_har))
        .route(
            "/api/v1/workbench/resend",
            get(list_resend).post(create_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}",
            get(get_resend).put(update_resend).delete(delete_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}/send",
            axum::routing::post(send_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}/cancel",
            axum::routing::post(cancel_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}/name",
            axum::routing::put(rename_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}/derive/{revision}",
            axum::routing::post(derive_resend),
        )
        .route(
            "/api/v1/workbench/resend/{context_id}/follow/{revision}",
            axum::routing::post(follow_resend),
        )
        .route(
            "/api/v1/workbench/fuzzer",
            get(list_fuzzer).post(create_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/preview",
            axum::routing::post(preview_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/payload-lists",
            get(list_payload_lists),
        )
        .route(
            "/api/v1/workbench/fuzzer/payload-lists/{list_id}",
            get(get_payload_list),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}",
            get(get_fuzzer).delete(delete_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}/start",
            axum::routing::post(start_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}/pause",
            axum::routing::post(pause_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}/resume",
            axum::routing::post(resume_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}/stop",
            axum::routing::post(stop_fuzzer),
        )
        .route(
            "/api/v1/workbench/fuzzer/{job_id}/results/{ordinal}/comment",
            axum::routing::post(comment_fuzzer_result),
        )
        .route("/api/v1/workbench/ws/control", get(control_ws))
        .route("/api/v1/workbench/ws/telemetry", get(telemetry_ws))
        .route(
            "/api/v1/workbench/ws/device/control",
            get(device_control_ws),
        )
        // Phase D3: the workbench Android target panel — one-click launch, status
        // polling, install-your-APK, and stop. All operator-gated.
        .route("/api/v1/android-target/status", get(android_target_status))
        .route(
            "/api/v1/android-target/launch",
            axum::routing::post(launch_android_target),
        )
        .route(
            "/api/v1/android-target/install-apk",
            axum::routing::post(install_target_apk),
        )
        .route(
            "/api/v1/android-target/stop",
            axum::routing::post(stop_android_target),
        )
        // Phase D2: the authenticated reverse-proxy for the GUI Android target's
        // ws-scrcpy screen stream (HTTP + WebSocket upgrade). ws-scrcpy is bound to
        // loopback and never reachable directly; this is the only door to it.
        // Three patterns: the bare base, the base with a trailing slash (the URL the
        // embedded iframe loads and ws-scrcpy serves its app from — axum's `{*rest}`
        // wildcard does not match an empty trailing segment), and everything below it.
        .route(
            "/android-stream",
            axum::routing::any(stream_proxy::stream_proxy),
        )
        .route(
            "/android-stream/",
            axum::routing::any(stream_proxy::stream_proxy),
        )
        .route(
            "/android-stream/{*rest}",
            axum::routing::any(stream_proxy::stream_proxy),
        )
        // Fingerprinted assets get the long-lived immutable policy; index.html and
        // any other static file fall through to the `no-cache` fallback below.
        .nest_service("/assets", hashed_assets)
        .fallback_service(gui_assets)
        .with_state(state))
}

#[derive(Clone)]
struct ApiState {
    engine: Engine,
    expected_origin: Arc<str>,
    pipeline_runs: PipelineRegistry,
    pairing: DevicePairingRegistry,
    /// Devices awaiting the operator accept/decline gate (Phase C5).
    pending_pairing: PendingPairingRegistry,
    /// The GUI/control loopback port this router is bound to; carried into the
    /// pairing QR and used to arm a device's control-channel reverse tunnel.
    gui_port: u16,
}

#[derive(Clone, Default)]
struct PipelineRegistry {
    runs: Arc<Mutex<BTreeMap<String, PipelineRunEntry>>>,
}

#[derive(Clone)]
struct PipelineRunEntry {
    progress: PipelineProgress,
    diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
    artifact_path: PathBuf,
    surface: Option<apiaxess_api_model::UnifiedApiSurface>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PipelineRunResponse {
    run_id: String,
    artifact_path: String,
    stage: PipelineStage,
    status: PipelineRunStatus,
    progress_basis_points: u16,
    message: String,
    diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
    dynamic_ran: bool,
    updated_at: chrono::DateTime<chrono::Utc>,
    surface_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SurfaceSummaryResponse {
    schema_version: u32,
    assembly_run_id: String,
    endpoints: Vec<SurfaceEndpointSummary>,
    coverage: SurfaceCoverageSummary,
    signer_count: usize,
    diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SurfaceEndpointSummary {
    method: String,
    path_template: String,
    /// Resolved base URL, when statically recovered — the host the GUI labels
    /// first- vs third-party so the tester can tell the app's own API from the
    /// SDK/tracker hosts it also talks to.
    #[serde(skip_serializing_if = "Option::is_none")]
    base_url: Option<String>,
    /// `confirmed` when at least one of the endpoint's facts was observed in
    /// dynamic capture (the app was actually seen hitting it), else
    /// `static_inferred` — a static candidate not observed being hit (e.g. a
    /// bundled SDK's configured base URL). Lets the GUI mark inferred candidates
    /// distinctly from confirmed surface so neither is presented as the other.
    evidence_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum_fact_confidence: Option<f64>,
    signer_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct SurfaceCoverageSummary {
    endpoint_count: u64,
    confirmed_endpoint_count: u64,
    inferred_endpoint_count: u64,
    static_only_endpoint_count: u64,
    open_handoff_count: u64,
    resolved_handoff_count: u64,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StartPipelineRequest {
    artifact_path: String,
    run_id: Option<String>,
    dynamic: Option<bool>,
    static_only: Option<bool>,
    session_path: Option<String>,
    scope: Option<EngagementScope>,
    intake_output_root: Option<String>,
    /// Pre-run "feed credentials now" values for a login-gated crawl. Held in
    /// memory only for the run, wrapped as zeroize-on-drop secrets immediately,
    /// never logged or persisted.
    credentials: Option<Vec<CredentialInput>>,
}

/// One operator-supplied credential, keyed by field name or canonical kind
/// (`username`, `password`, `email`, `otp`, ...).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialInput {
    key: String,
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ExportRequest {
    format: Option<String>,
    formats: Option<Vec<String>>,
    output_dir: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemStatus {
    api_version: &'static str,
    service: &'static str,
    state: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkbenchSession {
    auth_token: String,
    intercept_enabled: bool,
    telemetry_capacity: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkbenchHealth {
    proxy_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<apiaxess_workbench_proxy::BackendHealth>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenSessionRequest {
    path: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct NewSessionRequest {
    scope: Option<EngagementScope>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryRequest {
    kind: apiaxess_engine_shell::DiscoveryKind,
    wordlist: String,
    custom: Option<Vec<String>>,
    confirmed: Option<bool>,
}

/// Explicit one-time acknowledgement required before creating a web-target
/// session. The acknowledgement is retained as a canonical audit record.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartWebSessionRequest {
    target: String,
    authorization_affirmed: bool,
    artifact_path: Option<String>,
}

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

/// Response for `POST /api/v1/pairing/token`: the one-time pairing token the
/// operator hands to a device (the C5 QR encodes this), the fingerprint of the
/// CA the device must pin, and the pairing token's expiry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingTokenResponse {
    pairing_token: String,
    expires_at_ms: u64,
    ca_fingerprint_sha256: String,
}

/// Request body for `POST /api/v1/pairing/exchange`: the one-time pairing token a
/// device presents, plus a friendly name for the operator's accept prompt.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairingExchangeRequest {
    pairing_token: String,
    #[serde(default)]
    device_name: Option<String>,
}

/// Response for `POST /api/v1/pairing/exchange`: the device is now awaiting the
/// operator's accept/decline. It polls the request id for the outcome (Phase C5).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingExchangeAck {
    request_id: String,
    status: &'static str,
}

/// Response for `GET /api/v1/pairing/exchange/{request_id}`: the operator decision.
/// On `accepted` it carries the per-session bearer token; nothing before that.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingPollResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
}

/// Request body for `POST /api/v1/pairing/arm` (operator): the adb serial to arm
/// pairing for. The minted token is bound to it so accepting provisions it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArmPairingRequest {
    #[serde(default)]
    serial: Option<String>,
}

/// Everything the QR encodes so a device can connect and pin the workbench —
/// host/port, the one-time pairing token, and the CA SHA-256 fingerprint. Its JSON
/// (camelCase) is exactly what the QR carries and what the client parses.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingQrPayload {
    host: String,
    control_port: u16,
    proxy_port: u16,
    pairing_token: String,
    ca_fingerprint_sha256: String,
    expires_at_ms: u64,
}

/// One attached device the operator can arm pairing for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PairingDeviceView {
    serial: String,
    state: String,
    description: String,
}

/// One device awaiting the operator's accept/decline decision.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingPairingView {
    id: String,
    device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    requested_ago_ms: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlMessage {
    SetIntercept {
        enabled: bool,
        timeout_ms: Option<u64>,
    },
    SetHostFilter {
        hosts: Option<Vec<String>>,
    },
    Decide {
        flow_id: u64,
        action: String,
        method: Option<String>,
        headers: Option<Vec<(String, String)>>,
        body: Option<Vec<u8>>,
    },
    /// Answers a live credential prompt. `values` carries the operator's inputs
    /// for the prompt's fields; they are held in memory only and never logged.
    AnswerPrompt {
        id: u64,
        #[serde(default)]
        skip: bool,
        #[serde(default)]
        values: Vec<(String, String)>,
    },
    Ping,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ControlReply {
    Ready,
    Accepted {
        flow_id: u64,
    },
    Rejected {
        diagnostic: apiaxess_diagnostics::Diagnostic,
    },
    Pong,
}

async fn system_status(State(_state): State<ApiState>) -> Json<SystemStatus> {
    Json(SystemStatus {
        api_version: "v1",
        service: "APIaxess",
        state: "ready",
    })
}

/// Result of the native "Browse…" file picker.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PickFileResponse {
    /// Whether a native picker is available on this platform.
    available: bool,
    /// The full path the operator selected, or `null` if they cancelled.
    path: Option<String>,
}

/// Opens a native OS file dialog and returns the selected artifact's full path.
///
/// The web GUI's `<input type="file">` exposes only a filename, never a path the
/// engine can read from disk. On the desktop this endpoint opens the platform's
/// own file dialog (which yields a real path) so "Browse…" fills the field
/// directly. It is a local, single-operator, side-effectful action, so the modal
/// runs on a blocking thread. Platforms without a bundled native picker report
/// `available: false`, and the GUI falls back to the filename input.
async fn pick_file(State(_state): State<ApiState>) -> Json<PickFileResponse> {
    #[cfg(windows)]
    {
        let path = tokio::task::spawn_blocking(|| {
            let mut dialog = rfd::FileDialog::new()
                .set_title("Select an Android package")
                .add_filter("Android package", &["apk", "apks", "xapk", "aab"])
                .add_filter("All files", &["*"]);
            // Own the dialog to the current foreground window (the app the user
            // just clicked "Browse" in) so it opens on top and focused, not behind
            // the window where they'd have to hunt for it in the taskbar. Without
            // an owner an unparented dialog from this server process can open
            // behind the app. The Win32 handle is fetched via a tiny helper crate
            // that isolates the required unsafe (this workspace forbids unsafe).
            if let Some(parent) = apiaxess_native_dialog::foreground_window() {
                dialog = dialog.set_parent(&parent);
            }
            dialog.pick_file()
        })
        .await
        .ok()
        .flatten();
        Json(PickFileResponse {
            available: true,
            path: path.map(|path| path.display().to_string()),
        })
    }
    #[cfg(not(windows))]
    {
        Json(PickFileResponse {
            available: false,
            path: None,
        })
    }
}

async fn get_settings(State(_state): State<ApiState>) -> Json<settings::SettingsView> {
    Json(settings::settings_view())
}

async fn update_settings_handler(
    State(_state): State<ApiState>,
    Json(update): Json<settings::SettingsUpdate>,
) -> Result<Json<settings::SettingsView>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    settings::update_settings(update).map_err(|error| {
        let mut diagnostic =
            catalogue::SESSION_INVARIANT_FAILED.instantiate(DiagnosticContext::new());
        diagnostic.what = "The settings change could not be saved".into();
        diagnostic.why = error.into_boxed_str();
        diagnostic.fix = "Correct the value and try again.".into();
        (StatusCode::BAD_REQUEST, Json(diagnostic))
    })?;
    Ok(Json(settings::settings_view()))
}

async fn session_status(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .session_status()
        .map(Json)
        .map_err(session_response)
}

async fn session_scope(
    State(state): State<ApiState>,
) -> Result<Json<EngagementScope>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    state
        .engine
        .session_scope()
        .map(Json)
        .map_err(session_response)
}

async fn update_session_scope(
    State(state): State<ApiState>,
    Json(scope): Json<EngagementScope>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .update_session_scope(scope)
        .map(Json)
        .map_err(session_response)
}

async fn session_audit(
    State(state): State<ApiState>,
) -> Result<
    Json<Vec<apiaxess_session::AuditRecord>>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .session_audit()
        .map(Json)
        .map_err(session_response)
}

async fn new_session(
    State(state): State<ApiState>,
    input: Option<Json<NewSessionRequest>>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .new_session_with_scope(input.and_then(|input| input.0.scope))
        .map(Json)
        .map_err(session_response)
}

async fn start_web_session(
    State(state): State<ApiState>,
    Json(input): Json<StartWebSessionRequest>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .start_web_session(
            &input.target,
            input.authorization_affirmed,
            input.artifact_path.map(PathBuf::from),
        )
        .map(Json)
        .map_err(session_response)
}

async fn open_session(
    State(state): State<ApiState>,
    Json(input): Json<OpenSessionRequest>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .open_session(std::path::Path::new(&input.path))
        .map(Json)
        .map_err(session_response)
}

async fn save_session(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_engine_shell::SessionStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .save_session()
        .map(Json)
        .map_err(session_response)
}

async fn discovery_estimate(
    State(state): State<ApiState>,
    Json(input): Json<DiscoveryRequest>,
) -> Result<
    Json<apiaxess_engine_shell::DiscoveryEstimate>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .estimate_discovery(input.kind, &input.wordlist, input.custom)
        .map(Json)
        .map_err(session_response)
}

async fn discovery_run(
    State(state): State<ApiState>,
    Json(input): Json<DiscoveryRequest>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .start_discovery(
            input.kind,
            &input.wordlist,
            input.custom,
            input.confirmed.unwrap_or(false),
        )
        .map(Json)
        .map_err(session_response)
}

/// The bundled wordlist catalogue for the discovery picker (names, kinds, counts).
async fn discovery_wordlists() -> Json<Vec<apiaxess_engine_shell::WordlistInfo>> {
    Json(apiaxess_engine_shell::bundled_wordlist_catalogue())
}

async fn fuse_web_capture(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_api_model::UnifiedApiSurface>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuse_web_capture()
        .map(Json)
        .map_err(|diagnostics| {
            session_response(diagnostics.into_iter().next().unwrap_or_else(|| {
                catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new())
            }))
        })
}

fn session_response(
    diagnostic: apiaxess_diagnostics::Diagnostic,
) -> (StatusCode, Json<apiaxess_diagnostics::Diagnostic>) {
    let status = match diagnostic.id.as_ref() {
        "proxy.session-artifact-not-found" => StatusCode::NOT_FOUND,
        "persistence.session-format-unsupported" | "persistence.session-json-invalid" => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(diagnostic))
}

#[allow(clippy::too_many_lines)]
async fn start_pipeline(
    State(state): State<ApiState>,
    input: Option<Json<StartPipelineRequest>>,
) -> Result<
    (StatusCode, Json<PipelineRunResponse>),
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let input = input
        .ok_or_else(|| {
            pipeline_response(
                catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()),
            )
        })?
        .0;
    if let Some(path) = input.session_path.as_deref() {
        state
            .engine
            .open_session(Path::new(path))
            .map_err(session_response)?;
    }
    if let Some(scope) = input.scope {
        state
            .engine
            .update_session_scope(scope)
            .map_err(session_response)?;
    }
    let artifact_path = PathBuf::from(input.artifact_path);
    let mut config = PipelineConfig::new(artifact_path.clone()).map_err(pipeline_response)?;
    if let Some(run_id) = input.run_id {
        config = config.with_run_id(run_id).map_err(pipeline_response)?;
    }
    let dynamic_requested = input.dynamic.unwrap_or(false) && !input.static_only.unwrap_or(false);
    config = config.with_dynamic_capture(dynamic_requested);
    if let Some(output_root) = input.intake_output_root {
        config = config.with_intake_output_root(output_root);
    }
    if dynamic_requested {
        // Route the dynamic crawl's live credential prompts through the
        // session-scoped workbench the GUI sockets are subscribed to.
        config = config.with_interaction(state.engine.live_workbench());
        // Stage pre-run "feed now" credentials as zeroize-on-drop secrets. They
        // live only in this run's config, are wrapped immediately, and the raw
        // request Strings are dropped at the end of this scope.
        if let Some(credentials) = input.credentials {
            let staged = credentials
                .into_iter()
                .map(|credential| {
                    (
                        credential.key,
                        apiaxess_engine_shell::Secret::from_text(&credential.value),
                    )
                })
                .collect::<Vec<_>>();
            if !staged.is_empty() {
                config = config.with_staged_credentials(staged);
            }
        }
    }
    let run_id = config.run_id.clone();
    let initial = PipelineProgress {
        run_id: run_id.clone(),
        stage: PipelineStage::Intake,
        status: PipelineRunStatus::Running,
        progress_basis_points: 0,
        message: "Pipeline queued".to_owned(),
        diagnostics: Vec::new(),
        dynamic_ran: false,
        updated_at: chrono::Utc::now(),
    };
    state
        .pipeline_runs
        .insert(PipelineRunEntry {
            progress: initial.clone(),
            diagnostics: Vec::new(),
            artifact_path: artifact_path.clone(),
            surface: None,
        })
        .map_err(pipeline_response)?;

    let engine = state.engine.clone();
    let registry = state.pipeline_runs.clone();
    let callback_registry = registry.clone();
    config = config.with_progress_callback(move |progress| {
        let _ = callback_registry.update_progress(progress);
    });
    let queued_progress = initial.clone();
    let worker_registry = registry.clone();
    tokio::spawn(async move {
        let worker = tokio::task::spawn_blocking(move || {
            let result = engine.run_pipeline(&config);
            match result {
                Ok(report) => worker_registry.finish(
                    &run_id,
                    report.progress,
                    report.diagnostics,
                    Some(report.unified_surface),
                ),
                Err(failure) => worker_registry.finish(
                    &run_id,
                    *failure.progress,
                    failure.diagnostics.into_vec(),
                    None,
                ),
            }
        });
        if let Err(join_error) = worker.await {
            let mut context = DiagnosticContext::new();
            context.insert(
                "run_id".to_owned(),
                DiagnosticValue::String(queued_progress.run_id.clone()),
            );
            context.insert(
                "error".to_owned(),
                DiagnosticValue::String(join_error.to_string()),
            );
            let diagnostic = catalogue::PIPELINE_STAGE_FAILED.instantiate(context);
            let mut failed = queued_progress;
            failed.status = PipelineRunStatus::Failed;
            "Pipeline worker stopped unexpectedly".clone_into(&mut failed.message);
            failed.diagnostics = vec![diagnostic.clone()];
            let failed_run_id = failed.run_id.clone();
            let _ = registry.finish(&failed_run_id, failed, vec![diagnostic], None);
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(PipelineRunResponse::from_entry(&PipelineRunEntry {
            progress: initial,
            diagnostics: Vec::new(),
            artifact_path,
            surface: None,
        })),
    ))
}

async fn current_pipeline_status(
    State(state): State<ApiState>,
) -> Result<Json<PipelineRunResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let status = state.engine.session_status().map_err(session_response)?;
    let run_id = status
        .analysis_pipeline
        .as_ref()
        .map(|pipeline| pipeline.run_id.clone())
        .ok_or_else(|| {
            pipeline_response(
                catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
            )
        })?;
    pipeline_status_for(&state, &run_id)
}

async fn pipeline_status(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<PipelineRunResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    pipeline_status_for(&state, &run_id)
}

fn pipeline_status_for(
    state: &ApiState,
    run_id: &str,
) -> Result<Json<PipelineRunResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    if let Some(entry) = state.pipeline_runs.get(run_id).map_err(pipeline_response)? {
        return Ok(Json(PipelineRunResponse::from_entry(&entry)));
    }
    let status = state.engine.session_status().map_err(session_response)?;
    let Some(pipeline) = status.analysis_pipeline else {
        return Err(pipeline_response(
            catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
        ));
    };
    if pipeline.run_id != run_id {
        return Err(pipeline_response(
            catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
        ));
    }
    let progress = PipelineProgress {
        run_id: pipeline.run_id,
        stage: pipeline_stage(&pipeline.stage),
        status: pipeline_status_value(&pipeline.status),
        progress_basis_points: pipeline.progress_basis_points,
        message: format!("Persisted pipeline state: {}", pipeline.stage),
        diagnostics: pipeline.diagnostics.clone(),
        dynamic_ran: pipeline.dynamic_ran,
        updated_at: pipeline.updated_at,
    };
    Ok(Json(PipelineRunResponse::from_entry(&PipelineRunEntry {
        progress,
        diagnostics: pipeline.diagnostics,
        artifact_path: PathBuf::from(pipeline.artifact_path),
        surface: state.engine.session_surface().map_err(session_response)?,
    })))
}

async fn pipeline_surface(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_api_model::UnifiedApiSurface>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let entry = state
        .pipeline_runs
        .get(&run_id)
        .map_err(pipeline_response)?;
    let surface = if let Some(entry) = entry {
        entry.surface
    } else {
        let status = state.engine.session_status().map_err(session_response)?;
        let Some(pipeline) = status.analysis_pipeline else {
            return Err(pipeline_response(
                catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
            ));
        };
        if pipeline.run_id != run_id {
            return Err(pipeline_response(
                catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
            ));
        }
        state.engine.session_surface().map_err(session_response)?
    };
    if let Some(surface) = surface {
        return Ok(Json(surface));
    }
    Err(pipeline_response(
        catalogue::PIPELINE_SURFACE_NOT_READY.instantiate(DiagnosticContext::new()),
    ))
}

async fn pipeline_surface_summary(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<SurfaceSummaryResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let entry = state
        .pipeline_runs
        .get(&run_id)
        .map_err(pipeline_response)?;
    let surface = if let Some(entry) = entry {
        entry.surface
    } else {
        let status = state.engine.session_status().map_err(session_response)?;
        let Some(pipeline) = status.analysis_pipeline else {
            return Err(pipeline_response(
                catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
            ));
        };
        if pipeline.run_id != run_id {
            return Err(pipeline_response(
                catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
            ));
        }
        state.engine.session_surface().map_err(session_response)?
    };
    surface
        .map(|surface| Json(surface_summary(&surface)))
        .ok_or_else(|| {
            pipeline_response(
                catalogue::PIPELINE_SURFACE_NOT_READY.instantiate(DiagnosticContext::new()),
            )
        })
}

fn surface_summary(surface: &apiaxess_api_model::UnifiedApiSurface) -> SurfaceSummaryResponse {
    SurfaceSummaryResponse {
        schema_version: surface.schema_version,
        assembly_run_id: surface.assembly_run_id.clone(),
        endpoints: surface
            .endpoints
            .iter()
            .map(|endpoint| SurfaceEndpointSummary {
                method: serialize_model_string(&endpoint.endpoint.identity.method),
                path_template: serialize_model_string(&endpoint.endpoint.identity.path_template),
                base_url: endpoint
                    .endpoint
                    .base_url
                    .as_ref()
                    .and_then(|fact| fact.selected_candidate())
                    .map(|candidate| candidate.value.clone()),
                evidence_source: if endpoint.fact_confidence.iter().any(|fact| {
                    fact.sources
                        .contains(&apiaxess_api_model::SourceType::DynamicCapture)
                }) {
                    "confirmed"
                } else {
                    "static_inferred"
                },
                minimum_fact_confidence: endpoint
                    .fact_confidence
                    .iter()
                    .map(|fact| fact.score)
                    .reduce(f64::min),
                signer_count: endpoint.signers.len(),
            })
            .collect(),
        coverage: SurfaceCoverageSummary {
            endpoint_count: surface.confidence.coverage.endpoint_count,
            confirmed_endpoint_count: surface.confidence.coverage.confirmed_endpoint_count,
            inferred_endpoint_count: surface.confidence.coverage.inferred_endpoint_count,
            static_only_endpoint_count: surface.confidence.coverage.static_only_endpoint_count,
            open_handoff_count: surface.confidence.coverage.open_handoff_count,
            resolved_handoff_count: surface.confidence.coverage.resolved_handoff_count,
        },
        signer_count: surface.surface.signers.len(),
        diagnostics: apiaxess_diagnostics::bounded_status_diagnostics(&surface.diagnostics, 8, 100),
    }
}

fn serialize_model_string<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

async fn current_surface(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_api_model::UnifiedApiSurface>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .session_surface()
        .map_err(session_response)?
        .map(Json)
        .ok_or_else(|| {
            pipeline_response(
                catalogue::PIPELINE_SURFACE_NOT_READY.instantiate(DiagnosticContext::new()),
            )
        })
}

#[allow(clippy::too_many_lines)]
async fn export_artifacts(
    State(state): State<ApiState>,
    input: Option<Json<ExportRequest>>,
) -> Result<
    Json<apiaxess_engine_shell::ExportReport>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let input = input
        .ok_or_else(|| {
            export_response(vec![
                catalogue::EXPORT_INVALID_REQUEST.instantiate(DiagnosticContext::new()),
            ])
        })?
        .0;
    let output_dir = input.output_dir.ok_or_else(|| {
        export_response(vec![
            catalogue::EXPORT_INVALID_REQUEST.instantiate(DiagnosticContext::new()),
        ])
    })?;
    let mut names = input.formats.unwrap_or_default();
    if let Some(format) = input.format {
        names.push(format);
    }
    if names.is_empty() {
        names.push("all".to_owned());
    }
    let config = ExportConfig::from_names(output_dir, names)
        .map_err(|diagnostics| export_response(vec![diagnostics]))?;
    state
        .engine
        .export_session_artifacts(&config)
        .map(Json)
        .map_err(export_response)
}

fn export_response(
    mut diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
) -> (StatusCode, Json<apiaxess_diagnostics::Diagnostic>) {
    let diagnostic = diagnostics
        .drain(..)
        .next()
        .unwrap_or_else(|| catalogue::EXPORT_INVALID_REQUEST.instantiate(DiagnosticContext::new()));
    let status = match diagnostic.id.as_ref() {
        "export.surface-not-ready" => StatusCode::CONFLICT,
        "export.invalid-request" => StatusCode::BAD_REQUEST,
        "export.emitter-failed" | "export.write-failed" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(diagnostic))
}

fn pipeline_stage(stage: &str) -> PipelineStage {
    match stage {
        "static" => PipelineStage::Static,
        "dynamic" => PipelineStage::Dynamic,
        "signing" => PipelineStage::Signing,
        "fusion" => PipelineStage::Fusion,
        "confidence" => PipelineStage::Confidence,
        "surface" => PipelineStage::Surface,
        "completed" => PipelineStage::Completed,
        _ => PipelineStage::Intake,
    }
}

fn pipeline_status_value(status: &str) -> PipelineRunStatus {
    match status {
        "completed" => PipelineRunStatus::Completed,
        "failed" => PipelineRunStatus::Failed,
        _ => PipelineRunStatus::Running,
    }
}

fn pipeline_response(
    diagnostic: apiaxess_diagnostics::Diagnostic,
) -> (StatusCode, Json<apiaxess_diagnostics::Diagnostic>) {
    let status = match diagnostic.id.as_ref() {
        "pipeline.run-not-found" => StatusCode::NOT_FOUND,
        "pipeline.surface-not-ready" => StatusCode::CONFLICT,
        "pipeline.stage-failed" => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(diagnostic))
}

impl PipelineRunResponse {
    fn from_entry(entry: &PipelineRunEntry) -> Self {
        Self {
            run_id: entry.progress.run_id.clone(),
            artifact_path: entry.artifact_path.display().to_string(),
            stage: entry.progress.stage,
            status: entry.progress.status,
            progress_basis_points: entry.progress.progress_basis_points,
            message: entry.progress.message.clone(),
            diagnostics: apiaxess_diagnostics::bounded_status_diagnostics(
                &entry.diagnostics,
                8,
                100,
            ),
            dynamic_ran: entry.progress.dynamic_ran,
            updated_at: entry.progress.updated_at,
            surface_available: entry.surface.is_some(),
        }
    }
}

impl PipelineRegistry {
    fn insert(&self, entry: PipelineRunEntry) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()))?;
        if runs
            .get(&entry.progress.run_id)
            .is_some_and(|existing| existing.progress.status == PipelineRunStatus::Running)
        {
            return Err(catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()));
        }
        runs.insert(entry.progress.run_id.clone(), entry);
        Ok(())
    }

    fn update_progress(
        &self,
        progress: PipelineProgress,
    ) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()))?;
        if let Some(entry) = runs.get_mut(&progress.run_id) {
            entry.diagnostics.clone_from(&progress.diagnostics);
            entry.progress = progress;
        }
        Ok(())
    }

    fn finish(
        &self,
        run_id: &str,
        progress: PipelineProgress,
        diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
        surface: Option<apiaxess_api_model::UnifiedApiSurface>,
    ) -> Result<(), apiaxess_diagnostics::Diagnostic> {
        let mut runs = self
            .runs
            .lock()
            .map_err(|_| catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()))?;
        if let Some(entry) = runs.get_mut(run_id) {
            entry.progress = progress;
            entry.diagnostics = diagnostics;
            entry.surface = surface;
        }
        Ok(())
    }

    fn get(
        &self,
        run_id: &str,
    ) -> Result<Option<PipelineRunEntry>, apiaxess_diagnostics::Diagnostic> {
        self.runs
            .lock()
            .map_err(|_| catalogue::PIPELINE_STAGE_FAILED.instantiate(DiagnosticContext::new()))
            .map(|runs| runs.get(run_id).cloned())
    }
}

async fn workbench_session(State(state): State<ApiState>) -> Json<WorkbenchSession> {
    let live = state.engine.live_workbench();
    Json(WorkbenchSession {
        auth_token: live.auth_token().to_owned(),
        intercept_enabled: live.intercept_controller().is_enabled(),
        telemetry_capacity: 256,
    })
}

/// Returns the latest proxy capability snapshot for the GUI status surface.
async fn workbench_health(State(state): State<ApiState>) -> Json<WorkbenchHealth> {
    Json(WorkbenchHealth {
        proxy_running: state.engine.proxy_health().is_some(),
        backend: state.engine.proxy_health(),
    })
}

async fn workbench_diagnostics(
    State(state): State<ApiState>,
) -> Json<Vec<apiaxess_diagnostics::Diagnostic>> {
    Json(state.engine.live_workbench().diagnostics())
}

async fn browser_launch_status(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_engine_shell::BrowserLaunchStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .browser_launch_status()
        .map(Json)
        .map_err(storage_response)
}

async fn launch_browser(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_engine_shell::BrowserLaunchStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .launch_bundled_chromium()
        .map(Json)
        .map_err(storage_response)
}

async fn stop_browser(
    State(state): State<ApiState>,
) -> Result<
    Json<apiaxess_engine_shell::BrowserLaunchStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .stop_browser()
        .map(Json)
        .map_err(storage_response)
}

async fn list_flows(
    State(state): State<ApiState>,
) -> Result<Json<Vec<FlowSummary>>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    live.durable_summaries()
        .map(|flows| Json(flows.unwrap_or_else(|| live.recent_summaries())))
        .map_err(storage_response)
}

async fn get_flow(
    State(state): State<ApiState>,
    AxumPath(flow_id): AxumPath<u64>,
) -> Result<Json<FlowDetail>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    live.durable_flow(flow_id)
        .map_err(storage_response)?
        .or_else(|| live.flow(flow_id))
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
            )
        })
}

fn storage_response(
    diagnostic: apiaxess_diagnostics::Diagnostic,
) -> (StatusCode, Json<apiaxess_diagnostics::Diagnostic>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(diagnostic))
}

async fn pending_flows(State(state): State<ApiState>) -> Json<Vec<u64>> {
    Json(
        state
            .engine
            .live_workbench()
            .intercept_controller()
            .pending_ids(),
    )
}

async fn export_har(
    State(state): State<ApiState>,
) -> Result<
    ([(axum::http::HeaderName, &'static str); 1], Vec<u8>),
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .live_workbench()
        .export_har()
        .map(|bytes| {
            (
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                bytes,
            )
        })
        .map_err(storage_response)
}

async fn import_har(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<usize>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    state
        .engine
        .live_workbench()
        .import_har(&body, "har.import")
        .map(Json)
        .map_err(storage_response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateResend {
    flow_id: Option<u64>,
    request: Option<ResendRequest>,
}

async fn list_resend(
    State(state): State<ApiState>,
) -> Json<Vec<apiaxess_workbench_store::ResendContext>> {
    Json(state.engine.resend().list())
}

async fn create_resend(
    State(state): State<ApiState>,
    Json(input): Json<CreateResend>,
) -> Result<
    Json<apiaxess_workbench_store::ResendContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let resend = state.engine.resend();
    let context = if let Some(flow_id) = input.flow_id {
        let flow = state
            .engine
            .live_workbench()
            .durable_flow(flow_id)
            .map_err(storage_response)?
            .or_else(|| state.engine.live_workbench().flow(flow_id))
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
                )
            })?;
        resend.create_from_flow(&flow)
    } else if let Some(request) = input.request {
        resend.create(request, None)
    } else {
        return Err(storage_response(
            catalogue::PROXY_RESEND_REQUEST_FAILED.instantiate(DiagnosticContext::new()),
        ));
    }
    .map_err(storage_response)?;
    Ok(Json(context))
}

async fn get_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::ResendContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .resend()
        .get(&context_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
            )
        })
}

async fn delete_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    state
        .engine
        .resend()
        .remove(&context_id)
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(storage_response)
}

async fn update_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
    Json(request): Json<ResendRequest>,
) -> Result<
    Json<apiaxess_workbench_store::ResendContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .resend()
        .update_request(&context_id, request)
        .map(Json)
        .map_err(storage_response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendQuery {
    /// Seconds to wait for a response (default 30, clamped to 1–300).
    #[serde(default)]
    timeout_secs: Option<u64>,
}

impl SendQuery {
    fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout_secs.map(std::time::Duration::from_secs)
    }
}

async fn send_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
    Query(query): Query<SendQuery>,
) -> Result<
    Json<apiaxess_workbench_proxy::ResendSendResult>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let runtime = state
        .engine
        .session_runtime()
        .map_err(session_response)?
        .ok_or_else(|| {
            session_response(
                catalogue::PROXY_SESSION_NOT_ACTIVE.instantiate(DiagnosticContext::new()),
            )
        })?;
    let mut session = runtime.session_snapshot().map_err(session_response)?;
    let result = state
        .engine
        .resend()
        .send_in_session(&context_id, query.timeout(), &mut session)
        .await
        .map_err(storage_response)?;
    runtime.replace_session(session).map_err(session_response)?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FollowQuery {
    /// Carry cookies (request `Cookie` + response `Set-Cookie`) to the next hop.
    #[serde(default = "follow_cookies_default")]
    cookies: bool,
    /// Seconds to wait for a response (default 30, clamped to 1–300).
    #[serde(default)]
    timeout_secs: Option<u64>,
}

const fn follow_cookies_default() -> bool {
    true
}

/// Follows one redirect hop from a past revision's `3xx`, appending the hop as
/// a new revision (the editable draft is untouched).
async fn follow_resend(
    State(state): State<ApiState>,
    AxumPath((context_id, revision)): AxumPath<(String, u64)>,
    Query(query): Query<FollowQuery>,
) -> Result<
    Json<apiaxess_workbench_proxy::ResendSendResult>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let runtime = state
        .engine
        .session_runtime()
        .map_err(session_response)?
        .ok_or_else(|| {
            session_response(
                catalogue::PROXY_SESSION_NOT_ACTIVE.instantiate(DiagnosticContext::new()),
            )
        })?;
    let mut session = runtime.session_snapshot().map_err(session_response)?;
    let result = state
        .engine
        .resend()
        .follow_in_session(
            &context_id,
            revision,
            query.cookies,
            query.timeout_secs.map(std::time::Duration::from_secs),
            &mut session,
        )
        .await
        .map_err(storage_response)?;
    runtime.replace_session(session).map_err(session_response)?;
    Ok(Json(result))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelOutcome {
    /// Whether a send was in flight (and is now recorded as cancelled).
    cancelled: bool,
}

/// Cancels an item's in-flight send or follow; the pending send request then
/// returns with a cancelled revision.
async fn cancel_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
) -> Json<CancelOutcome> {
    Json(CancelOutcome {
        cancelled: state.engine.resend().cancel(&context_id),
    })
}

#[derive(Deserialize)]
struct RenameResend {
    /// New name; null or blank clears it.
    name: Option<String>,
}

async fn rename_resend(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
    Json(input): Json<RenameResend>,
) -> Result<
    Json<apiaxess_workbench_store::ResendContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .resend()
        .set_name(&context_id, input.name.as_deref())
        .map(Json)
        .map_err(storage_response)
}

async fn derive_resend(
    State(state): State<ApiState>,
    AxumPath((context_id, revision)): AxumPath<(String, u64)>,
) -> Result<
    Json<apiaxess_workbench_store::ResendContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .resend()
        .derive(&context_id, revision)
        .map(Json)
        .map_err(storage_response)
}

async fn list_fuzzer(
    State(state): State<ApiState>,
) -> Json<Vec<apiaxess_workbench_store::FuzzerJob>> {
    Json(state.engine.fuzzer().list())
}

async fn create_fuzzer(
    State(state): State<ApiState>,
    Json(config): Json<apiaxess_workbench_store::FuzzerConfig>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .create(config)
        .map(Json)
        .map_err(storage_response)
}

/// Returns the honest pre-run request-count estimate for a draft configuration,
/// so the GUI count preview shares the payload engine's cardinality math rather
/// than reimplementing it. Requires no persisted job.
async fn preview_fuzzer(
    Json(config): Json<apiaxess_workbench_store::FuzzerConfig>,
) -> Json<apiaxess_workbench_proxy::RequestCountPreview> {
    Json(apiaxess_workbench_proxy::preview_request_count(&config))
}

/// Lists the bundled predefined payload lists ("Add from list").
async fn list_payload_lists() -> Json<Vec<apiaxess_workbench_proxy::PayloadListInfo>> {
    Json(apiaxess_workbench_proxy::bundled_payload_lists())
}

/// Returns one bundled payload list's values by id.
async fn get_payload_list(
    AxumPath(list_id): AxumPath<String>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    apiaxess_workbench_proxy::read_payload_list(&list_id)
        .map(Json)
        .map_err(storage_response)
}

async fn get_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .get(&job_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
            )
        })
}

async fn delete_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    state
        .engine
        .fuzzer()
        .remove(&job_id)
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(storage_response)
}

async fn start_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let runtime = state
        .engine
        .session_runtime()
        .map_err(session_response)?
        .ok_or_else(|| {
            session_response(
                catalogue::PROXY_SESSION_NOT_ACTIVE.instantiate(DiagnosticContext::new()),
            )
        })?;
    let mut session = runtime.session_snapshot().map_err(session_response)?;
    let fuzzer = state.engine.fuzzer();
    let job = fuzzer
        .launch_in_session(&job_id, &mut session)
        .map_err(storage_response)?;
    runtime.replace_session(session).map_err(session_response)?;

    let watcher_runtime = runtime;
    let watcher_fuzzer = fuzzer;
    let watcher_job_id = job_id.clone();
    let watcher_live = state.engine.live_workbench();
    tokio::spawn(async move {
        loop {
            let Some(current) = watcher_fuzzer.get(&watcher_job_id) else {
                watcher_live.publish_diagnostic(
                    catalogue::PROXY_SESSION_AUDIT_FAILED.instantiate(DiagnosticContext::new()),
                );
                return;
            };
            if matches!(
                current.state,
                apiaxess_workbench_store::FuzzerJobState::Completed
                    | apiaxess_workbench_store::FuzzerJobState::Failed
                    | apiaxess_workbench_store::FuzzerJobState::Stopped
            ) {
                let mut session = match watcher_runtime.session_snapshot() {
                    Ok(session) => session,
                    Err(diagnostic) => {
                        watcher_live.publish_diagnostic(diagnostic);
                        return;
                    }
                };
                for result in current.results {
                    let record_id = format!("fuzzer:{watcher_job_id}:{}", result.ordinal);
                    if session
                        .audit_trail()
                        .iter()
                        .any(|record| record.id == record_id)
                    {
                        continue;
                    }
                    if let Err(diagnostic) = watcher_fuzzer.record_result_in_session(
                        &watcher_job_id,
                        result.ordinal,
                        &mut session,
                    ) {
                        watcher_live.publish_diagnostic(diagnostic);
                        return;
                    }
                }
                if let Err(diagnostic) = watcher_runtime.replace_session(session) {
                    watcher_live.publish_diagnostic(diagnostic);
                } else if let Err(diagnostic) = watcher_runtime.save() {
                    watcher_live.publish_diagnostic(diagnostic);
                }
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    Ok(Json(job))
}

async fn pause_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .pause(&job_id)
        .map(Json)
        .map_err(storage_response)
}

async fn resume_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .resume(&job_id)
        .map(Json)
        .map_err(storage_response)
}

async fn stop_fuzzer(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .stop(&job_id)
        .map(Json)
        .map_err(storage_response)
}

/// Request body for annotating a fuzzer result row.
#[derive(serde::Deserialize)]
struct FuzzerCommentRequest {
    #[serde(default)]
    comment: Option<String>,
}

/// Sets (or clears with an empty/absent value) the user comment on a result row.
async fn comment_fuzzer_result(
    State(state): State<ApiState>,
    AxumPath((job_id, ordinal)): AxumPath<(String, u64)>,
    Json(body): Json<FuzzerCommentRequest>,
) -> Result<
    Json<apiaxess_workbench_store::FuzzerJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .fuzzer()
        .set_result_comment(&job_id, ordinal, body.comment)
        .map(Json)
        .map_err(storage_response)
}

/// Serves the current session's root CA in PEM form.
///
/// This endpoint is intentionally public: it serves a public certificate, never
/// a private key. A device pulls the live session CA here at pairing/connect
/// time, so it never trusts a stale certificate. The trust anchor for the device
/// is the CA SHA-256 fingerprint delivered out-of-band by the pairing token
/// response (and, in C5, pinned in the QR); the device verifies the fetched PEM
/// against that fingerprint, which is also echoed in the `x-apiaxess-ca-fingerprint`
/// response header for convenience.
async fn pairing_ca(State(state): State<ApiState>) -> Response {
    let Some(ca) = state.engine.session_ca() else {
        let diagnostic = catalogue::PAIRING_CA_UNAVAILABLE.instantiate(DiagnosticContext::new());
        return (StatusCode::SERVICE_UNAVAILABLE, Json(diagnostic)).into_response();
    };
    let pem = ca.root_certificate_pem().to_owned();
    let fingerprint_header = HeaderValue::from_str(ca.fingerprint())
        .unwrap_or_else(|_| HeaderValue::from_static("unavailable"));
    (
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-pem-file"),
            ),
            (
                HeaderName::from_static("x-apiaxess-ca-fingerprint"),
                fingerprint_header,
            ),
        ],
        pem,
    )
        .into_response()
}

/// Mints a one-time device pairing token (operator action).
///
/// This is the operator-side of pairing: only the trusted workbench UI may mint a
/// token, so it is guarded by both the loopback `Origin` and the workbench session
/// token — exactly the pair the browser control channel requires. A cross-origin
/// device cannot reach this path, so it can never mint its own pairing token.
async fn mint_pairing_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<PairingTokenResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    let ca = state.engine.session_ca().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(catalogue::PAIRING_CA_UNAVAILABLE.instantiate(DiagnosticContext::new())),
        )
    })?;
    let issued = state.pairing.issue_pairing_token(None).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new())),
        )
    })?;
    Ok(Json(PairingTokenResponse {
        pairing_token: issued.token,
        expires_at_ms: issued.expires_at_ms,
        ca_fingerprint_sha256: ca.fingerprint().to_owned(),
    }))
}

/// Device-side of pairing (Phase C5): presents a one-time pairing token and enters
/// the accept/decline gate.
///
/// Deliberately *not* origin-gated — a device is cross-origin. The pairing token
/// (single-use, short-lived, and consumed here) proves the device holds a QR the
/// operator showed. Consuming it does NOT issue a session token: the device is
/// registered as a *pending* request and must wait for an explicit operator accept,
/// which it learns by polling the returned `requestId`. A device without a valid
/// token is rejected outright and never reaches the gate.
async fn exchange_pairing_token(
    State(state): State<ApiState>,
    Json(request): Json<PairingExchangeRequest>,
) -> Result<Json<PairingExchangeAck>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let claim = state
        .pairing
        .consume_pairing_token(&request.pairing_token)
        .ok_or_else(|| {
            let diagnostic =
                catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new());
            state
                .engine
                .live_workbench()
                .publish_diagnostic(diagnostic.clone());
            (StatusCode::UNAUTHORIZED, Json(diagnostic))
        })?;
    let device_name = request
        .device_name
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Unnamed device".to_owned());
    let request_id = state
        .pending_pairing
        .register(device_name, claim.serial)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new())),
            )
        })?;
    Ok(Json(PairingExchangeAck {
        request_id,
        status: "pending",
    }))
}

/// Device polls the operator's decision on its pending pairing request (Phase C5).
async fn poll_pairing_exchange(
    State(state): State<ApiState>,
    AxumPath(request_id): AxumPath<String>,
) -> Result<Json<PairingPollResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    match state.pending_pairing.poll(&request_id) {
        PairingOutcome::Pending => Ok(Json(PairingPollResponse {
            status: "pending",
            session_token: None,
            expires_at_ms: None,
        })),
        PairingOutcome::Accepted(token) => Ok(Json(PairingPollResponse {
            status: "accepted",
            session_token: Some(token.token),
            expires_at_ms: Some(token.expires_at_ms),
        })),
        PairingOutcome::Declined => Err((
            StatusCode::FORBIDDEN,
            Json(catalogue::DEVICE_PAIRING_DECLINED.instantiate(DiagnosticContext::new())),
        )),
        PairingOutcome::Unknown => Err((
            StatusCode::GONE,
            Json(catalogue::DEVICE_PAIRING_REQUEST_EXPIRED.instantiate(DiagnosticContext::new())),
        )),
    }
}

/// Lists attached adb devices the operator can arm pairing for (operator-gated).
async fn pairing_devices(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PairingDeviceView>>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    let devices = state
        .engine
        .detect_adb_devices()
        .map_err(|diagnostic| (StatusCode::INTERNAL_SERVER_ERROR, Json(diagnostic)))?;
    Ok(Json(
        devices
            .into_iter()
            .map(|device| PairingDeviceView {
                serial: device.serial,
                state: format!("{:?}", device.state),
                description: device.description,
            })
            .collect(),
    ))
}

/// Arms pairing for a device (operator-gated): establishes the reverse tunnel so
/// the device can reach the workbench, mints a one-time pairing token bound to the
/// device serial, and returns the QR payload. This is transport + a token only — no
/// trust is granted until the operator accepts the device's ensuing request.
async fn arm_pairing(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<ArmPairingRequest>,
) -> Result<Json<PairingQrPayload>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    let ca = state.engine.session_ca().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(catalogue::PAIRING_CA_UNAVAILABLE.instantiate(DiagnosticContext::new())),
        )
    })?;
    let proxy_port = state.engine.proxy_port().unwrap_or(8080);

    // Arm the transport for a specific detected device so it can reach the
    // workbench loopback to present its token. Skipped when no serial is given
    // (e.g. an already-tunnelled device pairing manually).
    if let Some(serial) = request.serial.as_deref() {
        state
            .engine
            .arm_device_tunnel(serial, state.gui_port, proxy_port)
            .map_err(|diagnostics| pairing_error(diagnostics, StatusCode::UNPROCESSABLE_ENTITY))?;
    }

    let issued = state
        .pairing
        .issue_pairing_token(request.serial)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new())),
            )
        })?;
    // The response body's JSON is exactly what the QR encodes and what the client
    // parses — the GUI reads it verbatim and renders the QR from it, so it must
    // stay the pure payload (no extra fields).
    Ok(Json(PairingQrPayload {
        host: "127.0.0.1".to_owned(),
        control_port: state.gui_port,
        proxy_port,
        pairing_token: issued.token,
        ca_fingerprint_sha256: ca.fingerprint().to_owned(),
        expires_at_ms: issued.expires_at_ms,
    }))
}

/// Lists devices awaiting the operator accept/decline decision (operator-gated).
async fn list_pending_pairing(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingPairingView>>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    Ok(Json(
        state
            .pending_pairing
            .list_pending()
            .into_iter()
            .map(|pending| PendingPairingView {
                id: pending.id,
                device_name: pending.device_name,
                serial: pending.serial,
                requested_ago_ms: pending.requested_ago_ms,
            })
            .collect(),
    ))
}

/// Accepts a pending device (operator-gated) — THE gate that wraps C2 provisioning.
///
/// This is the only path that runs `provision_adb_device`: on accept the workbench
/// provisions the armed device (system-CA install + optional frida) and issues the
/// session token the device is polling for. Nothing here runs without the operator
/// explicitly accepting, which closes the C2 "ungated provisioning" gap.
async fn accept_pairing(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(request_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;

    let serial = state
        .pending_pairing
        .serial_for_pending(&request_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(
                    catalogue::DEVICE_PAIRING_REQUEST_EXPIRED.instantiate(DiagnosticContext::new()),
                ),
            )
        })?;

    // The gated trust-granting provisioning. Provision + start frida-server so a
    // later pinned-app bypass (C4) can attach.
    if let Some(serial) = serial.as_deref() {
        state
            .engine
            .provision_device_retained(serial, true)
            .map_err(|diagnostics| {
                state.pending_pairing.decline(&request_id);
                pairing_error(diagnostics, StatusCode::UNPROCESSABLE_ENTITY)
            })?;
    }

    let session = state.pairing.issue_session_token().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new())),
        )
    })?;
    if state.pending_pairing.accept(&request_id, session) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::CONFLICT,
            Json(catalogue::DEVICE_PAIRING_REQUEST_EXPIRED.instantiate(DiagnosticContext::new())),
        ))
    }
}

/// Request body for `POST /api/v1/pairing/devices/{serial}/bypass`: the package of
/// the pinned app the C3 client is capturing on that device.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BypassDeviceRequest {
    package: String,
}

/// Response for the device pinning-bypass (Phase C4): the selected lane, the
/// techniques actually applied, and whether the device's frida-server is up.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BypassDeviceResponse {
    lane: String,
    frida_server_started: bool,
    applied_technique_ids: Vec<String>,
    reason: String,
}

/// Runs the certificate-pinning bypass (Phase C4) against a captured pinned app on
/// a paired device, by adb serial. Operator-gated. The device's C2 frida-server
/// hosts instrumentation; the workbench attaches over the adb tunnel and applies
/// the unpin techniques so the pinned app's HTTPS decrypts at the workbench.
async fn bypass_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(serial): AxumPath<String>,
    Json(body): Json<BypassDeviceRequest>,
) -> Result<Json<BypassDeviceResponse>, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;

    let target = apiaxess_engine_shell::TargetInventory {
        package_name: body.package.clone(),
        apks: Vec::new(),
        rooted_available: true,
        frameworks: Vec::new(),
        native_libraries: Vec::new(),
        build_fingerprint: None,
        escalation_boundaries: Vec::new(),
        evidence: Vec::new(),
    };
    let mut request = apiaxess_engine_shell::DeviceBypassRequestSpec::new(
        format!("device-bypass:{serial}"),
        format!("device-bypass:{serial}:{}", body.package),
        target,
    );
    // A paired physical/emulator device is instrumented in place, never patched.
    request.install_patched_app = false;

    match state.engine.bypass_pinning_on_device(&serial, &request) {
        Ok((outcome, session)) => {
            // The Frida session must outlive this request: dropping it unloads the
            // injected script and removes the unpin hooks, so the pinned app would
            // immediately pin again. Retain it for the workbench's lifetime so the
            // bypass stays active while the C3 client captures the app. (Cleanup
            // happens when the workbench process exits.)
            std::mem::forget(session);
            Ok(Json(BypassDeviceResponse {
                lane: format!("{:?}", outcome.plan.lane),
                frida_server_started: outcome.frida_server_started,
                applied_technique_ids: outcome.applied_technique_ids,
                reason: outcome.plan.reason,
            }))
        }
        Err(diagnostics) => Err(pairing_error(diagnostics, StatusCode::UNPROCESSABLE_ENTITY)),
    }
}

/// Declines a pending device (operator-gated). The device is told it was declined.
async fn decline_pairing(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(request_id): AxumPath<String>,
) -> Result<StatusCode, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    if state.pending_pairing.decline(&request_id) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(catalogue::DEVICE_PAIRING_REQUEST_EXPIRED.instantiate(DiagnosticContext::new())),
        ))
    }
}

/// Collapses a device-provisioning/tunnel diagnostic vector into one HTTP error.
fn pairing_error(
    diagnostics: Vec<apiaxess_diagnostics::Diagnostic>,
    status: StatusCode,
) -> (StatusCode, Json<apiaxess_diagnostics::Diagnostic>) {
    let diagnostic = diagnostics
        .into_iter()
        .next()
        .unwrap_or_else(|| catalogue::PAIRING_TOKEN_REJECTED.instantiate(DiagnosticContext::new()));
    (status, Json(diagnostic))
}

/// The GUI Android target's current lifecycle (Phase D3), polled by the panel.
async fn android_target_status(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<
    Json<apiaxess_engine_shell::AndroidTargetStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    Ok(Json(state.engine.android_target_status()))
}

/// Launches the GUI Android target (Phase D3). The blocking boot → provision →
/// stream runs on a background thread; this returns immediately with the (booting)
/// status the panel then polls. Idempotent while a launch is already in flight.
async fn launch_android_target(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<
    Json<apiaxess_engine_shell::AndroidTargetStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    if state.engine.begin_android_launch() {
        let engine = state.engine.clone();
        tokio::task::spawn_blocking(move || {
            let _ = engine.launch_android_target();
        });
    }
    Ok(Json(state.engine.android_target_status()))
}

/// Body for installing the user's target APK onto the running Android target.
#[derive(Deserialize)]
struct AndroidInstallRequest {
    /// Absolute path on this machine to the APK to install.
    path: String,
}

/// Installs the user's target APK onto the running GUI Android target (Phase D3).
async fn install_target_apk(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(request): Json<AndroidInstallRequest>,
) -> Result<StatusCode, (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    state
        .engine
        .install_target_apk(std::path::Path::new(&request.path))
        .map_err(|diagnostics| pairing_error(diagnostics, StatusCode::BAD_REQUEST))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Stops the running GUI Android target and its stream (Phase D3).
async fn stop_android_target(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<
    Json<apiaxess_engine_shell::AndroidTargetStatus>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let live = state.engine.live_workbench();
    require_operator(&state, &headers, &live)?;
    let _ = state.engine.teardown_android_target();
    Ok(Json(state.engine.android_target_status()))
}

/// Token-authenticated device control channel.
///
/// A device authenticates by the per-session bearer token it received from the
/// pairing exchange, presented as the `token` query parameter — not by `Origin`,
/// which a device cannot satisfy. This is the sole relaxation of the origin guard
/// and applies only to this token-gated device path; the browser/GUI/emulator
/// control paths (`/ws/control`) keep their exact origin+token behavior. Once
/// authenticated, the device drives the same `ControlMessage` protocol and the
/// same session-scoped [`control_loop`] the operator UI uses.
async fn device_control_ws(
    State(state): State<ApiState>,
    Query(query): Query<TokenQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let live = state.engine.live_workbench();
    if !state.pairing.validate_session_token(&query.token) {
        let diagnostic =
            catalogue::PAIRING_DEVICE_AUTH_REJECTED.instantiate(DiagnosticContext::new());
        live.publish_diagnostic(diagnostic.clone());
        return (StatusCode::UNAUTHORIZED, Json(diagnostic)).into_response();
    }
    upgrade
        .on_upgrade(move |socket| control_loop(socket, live))
        .into_response()
}

async fn control_ws(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let live = state.engine.live_workbench();
    if let Err(response) = authorize(&state, &headers, &query.token, &live) {
        return response.into_response();
    }
    upgrade
        .on_upgrade(move |socket| control_loop(socket, live))
        .into_response()
}

async fn telemetry_ws(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let live = state.engine.live_workbench();
    if let Err(response) = authorize(&state, &headers, &query.token, &live) {
        return response.into_response();
    }
    upgrade
        .on_upgrade(move |socket| telemetry_loop(socket, live))
        .into_response()
}

fn authorize(
    state: &ApiState,
    headers: &HeaderMap,
    token: &str,
    live: &LiveWorkbench,
) -> Result<(), (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if origin != state.expected_origin.as_ref() {
        let diagnostic =
            catalogue::PROXY_LIVE_ORIGIN_REJECTED.instantiate(DiagnosticContext::new());
        live.publish_diagnostic(diagnostic.clone());
        return Err((StatusCode::FORBIDDEN, Json(diagnostic)));
    }
    if token != live.auth_token() {
        let diagnostic = catalogue::PROXY_LIVE_AUTH_REJECTED.instantiate(DiagnosticContext::new());
        live.publish_diagnostic(diagnostic.clone());
        return Err((StatusCode::UNAUTHORIZED, Json(diagnostic)));
    }
    Ok(())
}

/// Authorizes an operator-only HTTP action (minting a device pairing token).
///
/// Requires the same trust pair as the browser control channel: the loopback
/// `Origin` and the workbench session token (here carried as an
/// `Authorization: Bearer` header). This keeps pairing-token minting exclusive to
/// the trusted local UI, so no cross-origin device or unrelated local caller can
/// bootstrap a pairing.
fn require_operator(
    state: &ApiState,
    headers: &HeaderMap,
    live: &LiveWorkbench,
) -> Result<(), (StatusCode, Json<apiaxess_diagnostics::Diagnostic>)> {
    // Browsers omit `Origin` on same-origin GETs (the operator GUI's device and
    // pending polls), so an absent Origin is legitimate same-origin traffic. Only
    // reject a *present* Origin that does not match; the mandatory bearer token
    // below is the real authenticator (a per-session token, not an ambient cookie,
    // so cross-site request forgery does not apply).
    if let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) {
        if origin != state.expected_origin.as_ref() {
            let diagnostic =
                catalogue::PROXY_LIVE_ORIGIN_REJECTED.instantiate(DiagnosticContext::new());
            live.publish_diagnostic(diagnostic.clone());
            return Err((StatusCode::FORBIDDEN, Json(diagnostic)));
        }
    }
    let token = bearer_token(headers).unwrap_or_default();
    if token != live.auth_token() {
        let diagnostic = catalogue::PROXY_LIVE_AUTH_REJECTED.instantiate(DiagnosticContext::new());
        live.publish_diagnostic(diagnostic.clone());
        return Err((StatusCode::UNAUTHORIZED, Json(diagnostic)));
    }
    Ok(())
}

/// Extracts a bearer token from the `Authorization` header, if present.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
}

#[allow(clippy::too_many_lines)]
async fn control_loop(mut socket: axum::extract::ws::WebSocket, live: Arc<LiveWorkbench>) {
    let _ = socket
        .send(axum::extract::ws::Message::Text(
            serde_json::to_string(&ControlReply::Ready)
                .expect("control ready serializes")
                .into(),
        ))
        .await;
    while let Some(Ok(message)) = socket.next().await {
        let axum::extract::ws::Message::Text(text) = message else {
            continue;
        };
        let reply = match serde_json::from_str::<ControlMessage>(&text) {
            Ok(ControlMessage::SetIntercept {
                enabled,
                timeout_ms,
            }) => {
                let controller = live.intercept_controller();
                controller.set_enabled(enabled);
                if let Some(timeout_ms) = timeout_ms {
                    controller.set_timeout(Duration::from_millis(timeout_ms));
                }
                ControlReply::Ready
            }
            Ok(ControlMessage::SetHostFilter { hosts }) => {
                live.intercept_controller().set_host_filter(hosts);
                ControlReply::Ready
            }
            Ok(ControlMessage::Decide {
                flow_id,
                action,
                method,
                headers,
                body,
            }) => {
                let decision = match action.as_str() {
                    "forward" => Some(InterceptDecision::Forward),
                    "drop" => Some(InterceptDecision::Drop),
                    "forward_modified" => Some(InterceptDecision::ForwardModified {
                        method: method.unwrap_or_default(),
                        headers: headers.unwrap_or_default(),
                        body: body.unwrap_or_default(),
                    }),
                    _ => None,
                };
                let accepted = decision
                    .is_some_and(|decision| live.intercept_controller().decide(flow_id, decision));
                if accepted {
                    ControlReply::Accepted { flow_id }
                } else {
                    let mut context = DiagnosticContext::new();
                    context.insert(
                        "flow_id".to_owned(),
                        DiagnosticValue::Integer(i64::try_from(flow_id).unwrap_or(i64::MAX)),
                    );
                    let diagnostic = catalogue::PROXY_LIVE_DESYNC.instantiate(context);
                    live.publish_diagnostic(diagnostic.clone());
                    ControlReply::Rejected { diagnostic }
                }
            }
            Ok(ControlMessage::AnswerPrompt { id, skip, values }) => {
                let answered = live.answer_credential_prompt(
                    id,
                    apiaxess_workbench_proxy::CredentialPromptAnswer { skip, values },
                );
                if answered {
                    ControlReply::Accepted { flow_id: id }
                } else {
                    let mut context = DiagnosticContext::new();
                    context.insert(
                        "prompt_id".to_owned(),
                        DiagnosticValue::Integer(i64::try_from(id).unwrap_or(i64::MAX)),
                    );
                    let diagnostic = catalogue::PROXY_LIVE_DESYNC.instantiate(context);
                    ControlReply::Rejected { diagnostic }
                }
            }
            Ok(ControlMessage::Ping) => ControlReply::Pong,
            Err(error) => {
                let mut context = DiagnosticContext::new();
                context.insert(
                    "error".to_owned(),
                    DiagnosticValue::String(error.to_string()),
                );
                let diagnostic = catalogue::PROXY_LIVE_TRANSPORT_FAILED.instantiate(context);
                live.publish_diagnostic(diagnostic.clone());
                ControlReply::Rejected { diagnostic }
            }
        };
        if socket
            .send(axum::extract::ws::Message::Text(
                serde_json::to_string(&reply)
                    .expect("control reply serializes")
                    .into(),
            ))
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn telemetry_loop(mut socket: axum::extract::ws::WebSocket, live: Arc<LiveWorkbench>) {
    let mut updates = live.subscribe();
    loop {
        let first = match tokio::time::timeout(Duration::from_millis(100), updates.recv()).await {
            Ok(Ok(update)) => update,
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(count))) => {
                let mut context = DiagnosticContext::new();
                context.insert(
                    "shed_updates".to_owned(),
                    DiagnosticValue::Integer(i64::try_from(count).unwrap_or(i64::MAX)),
                );
                let diagnostic = catalogue::PROXY_TELEMETRY_BACKPRESSURE.instantiate(context);
                apiaxess_workbench_proxy::live::LiveUpdate {
                    diagnostics: vec![diagnostic],
                    ..Default::default()
                }
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => break,
            Err(_) => continue,
        };
        let mut batch = first;
        for _ in 0..63 {
            let Ok(update) = updates.try_recv() else {
                break;
            };
            batch.flows.extend(update.flows);
            batch.diagnostics.extend(update.diagnostics);
            batch.prompts.extend(update.prompts);
        }
        if socket
            .send(axum::extract::ws::Message::Text(
                serde_json::to_string(&batch)
                    .expect("telemetry update serializes")
                    .into(),
            ))
            .await
            .is_err()
        {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scope() -> EngagementScope {
        EngagementScope {
            declared_at: chrono::Utc::now(),
            target: apiaxess_session::TargetIdentity {
                target_type: "android.apk".to_owned(),
                primary: apiaxess_session::TargetIdentifier {
                    kind: "artifact.path".to_owned(),
                    value: "missing.apk".to_owned(),
                },
                aliases: Vec::new(),
            },
            allowed_targets: Vec::new(),
        }
    }

    #[test]
    fn websocket_security_requires_exact_origin_and_session_token() {
        let state = ApiState {
            engine: Engine::new(),
            expected_origin: Arc::from("http://127.0.0.1:7777"),
            pipeline_runs: PipelineRegistry::default(),
            pairing: DevicePairingRegistry::default(),
            pending_pairing: PendingPairingRegistry::default(),
            gui_port: 7777,
        };
        let live = state.engine.live_workbench();
        let mut headers = HeaderMap::new();
        headers.insert(ORIGIN, "http://127.0.0.1:7777".parse().expect("origin"));
        assert!(authorize(&state, &headers, live.auth_token(), &live).is_ok());
        assert_eq!(
            authorize(&state, &headers, "wrong", &live)
                .expect_err("wrong token")
                .0,
            StatusCode::UNAUTHORIZED
        );
        headers.insert(ORIGIN, "http://localhost:7777".parse().expect("origin"));
        assert_eq!(
            authorize(&state, &headers, live.auth_token(), &live)
                .expect_err("wrong origin")
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // End-to-end pairing walkthrough reads best whole.
    async fn device_pairing_ca_and_token_exchange_mechanism() {
        use apiaxess_workbench_proxy::SessionCa;

        let engine = Engine::new();
        let state = ApiState {
            engine: engine.clone(),
            expected_origin: Arc::from("http://127.0.0.1:7777"),
            pipeline_runs: PipelineRegistry::default(),
            pairing: DevicePairingRegistry::default(),
            pending_pairing: PendingPairingRegistry::default(),
            gui_port: 7777,
        };

        // CA endpoint fails cleanly before the session CA is provisioned.
        let response = pairing_ca(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Provision the live session CA exactly as the workbench does at startup.
        let ca = SessionCa::generate().expect("session CA");
        engine.configure_browser_ca(ca.clone());

        // CA endpoint serves the live PEM and echoes the pinnable fingerprint.
        let response = pairing_ca(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let served_fingerprint = response
            .headers()
            .get("x-apiaxess-ca-fingerprint")
            .and_then(|value| value.to_str().ok())
            .expect("fingerprint header")
            .to_owned();
        assert_eq!(served_fingerprint, ca.fingerprint());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("ca body");
        let pem = String::from_utf8(body.to_vec()).expect("pem is utf-8");
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(pem, ca.root_certificate_pem());

        // A *present* cross-origin request is rejected (the origin guard). An
        // absent Origin is legitimate same-origin browser traffic, so the bearer
        // token below — not the Origin — is the real authenticator.
        let mut cross_origin = HeaderMap::new();
        cross_origin.insert(ORIGIN, "http://evil.example".parse().expect("origin"));
        cross_origin.insert(
            AUTHORIZATION,
            format!("Bearer {}", engine.live_workbench().auth_token())
                .parse()
                .expect("auth"),
        );
        assert_eq!(
            mint_pairing_token(State(state.clone()), cross_origin)
                .await
                .expect_err("cross-origin is rejected")
                .0,
            StatusCode::FORBIDDEN
        );

        // Without the workbench session token, minting is rejected — even with no
        // Origin header at all (a random local caller cannot mint).
        let anon = HeaderMap::new();
        assert_eq!(
            mint_pairing_token(State(state.clone()), anon)
                .await
                .expect_err("missing token is rejected")
                .0,
            StatusCode::UNAUTHORIZED
        );

        // A wrong token is rejected.
        let mut wrong_token = HeaderMap::new();
        wrong_token.insert(AUTHORIZATION, "Bearer wrong".parse().expect("auth"));
        assert_eq!(
            mint_pairing_token(State(state.clone()), wrong_token)
                .await
                .expect_err("wrong token is rejected")
                .0,
            StatusCode::UNAUTHORIZED
        );

        // The trusted operator UI mints a pairing token carrying the CA fingerprint.
        let auth_token = engine.live_workbench().auth_token().to_owned();
        let mut operator = HeaderMap::new();
        operator.insert(ORIGIN, "http://127.0.0.1:7777".parse().expect("origin"));
        operator.insert(
            AUTHORIZATION,
            format!("Bearer {auth_token}").parse().expect("auth"),
        );
        let Json(minted) = mint_pairing_token(State(state.clone()), operator)
            .await
            .expect("operator mints a pairing token");
        assert_eq!(minted.ca_fingerprint_sha256, ca.fingerprint());

        // A cross-origin device presents the pairing token — it does NOT get a
        // session token immediately (Phase C5); it enters the accept/decline gate.
        let Json(ack) = exchange_pairing_token(
            State(state.clone()),
            Json(PairingExchangeRequest {
                pairing_token: minted.pairing_token.clone(),
                device_name: Some("Test device".to_owned()),
            }),
        )
        .await
        .expect("device enters the pairing gate");
        assert_eq!(ack.status, "pending");

        // While pending, no session token exists.
        let Json(pending_poll) =
            poll_pairing_exchange(State(state.clone()), AxumPath(ack.request_id.clone()))
                .await
                .expect("poll pending");
        assert_eq!(pending_poll.status, "pending");
        assert!(pending_poll.session_token.is_none());

        // The operator accepts (this request has no serial, so no device
        // provisioning runs). Accept is operator-gated.
        let mut operator_accept = HeaderMap::new();
        operator_accept.insert(ORIGIN, "http://127.0.0.1:7777".parse().expect("origin"));
        operator_accept.insert(
            AUTHORIZATION,
            format!("Bearer {auth_token}").parse().expect("auth"),
        );
        accept_pairing(
            State(state.clone()),
            operator_accept,
            AxumPath(ack.request_id.clone()),
        )
        .await
        .expect("operator accepts the device");

        // The device now polls and receives its session token, which authenticates
        // the device control channel; a rogue device's forged token does not.
        let Json(accepted) =
            poll_pairing_exchange(State(state.clone()), AxumPath(ack.request_id.clone()))
                .await
                .expect("poll accepted");
        assert_eq!(accepted.status, "accepted");
        let session_token = accepted
            .session_token
            .expect("session token issued on accept");
        assert!(state.pairing.validate_session_token(&session_token));
        assert!(!state.pairing.validate_session_token("rogue-device-token"));

        // The one-time pairing token cannot be replayed by anyone.
        assert_eq!(
            exchange_pairing_token(
                State(state.clone()),
                Json(PairingExchangeRequest {
                    pairing_token: minted.pairing_token,
                    device_name: None,
                }),
            )
            .await
            .expect_err("replayed pairing token is rejected")
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn pairing_gate_requires_operator_accept_and_relays_decline() {
        let engine = Engine::new();
        let auth_token = engine.live_workbench().auth_token().to_owned();
        let state = ApiState {
            engine,
            expected_origin: Arc::from("http://127.0.0.1:7777"),
            pipeline_runs: PipelineRegistry::default(),
            pairing: DevicePairingRegistry::default(),
            pending_pairing: PendingPairingRegistry::default(),
            gui_port: 7777,
        };

        // A device presents a valid (serial-less) pairing token → pending.
        let token = state
            .pairing
            .issue_pairing_token(None)
            .expect("pairing token");
        let Json(ack) = exchange_pairing_token(
            State(state.clone()),
            Json(PairingExchangeRequest {
                pairing_token: token.token,
                device_name: None,
            }),
        )
        .await
        .expect("enters gate");

        // Accepting requires operator auth: an unauthenticated accept is refused,
        // so a rogue local caller cannot self-approve a device.
        assert!(
            accept_pairing(
                State(state.clone()),
                HeaderMap::new(),
                AxumPath(ack.request_id.clone()),
            )
            .await
            .is_err()
        );
        // The device is still pending — the failed accept changed nothing.
        let Json(still_pending) =
            poll_pairing_exchange(State(state.clone()), AxumPath(ack.request_id.clone()))
                .await
                .expect("still pending");
        assert_eq!(still_pending.status, "pending");

        // The operator declines → the device learns it was declined (403).
        let mut operator = HeaderMap::new();
        operator.insert(ORIGIN, "http://127.0.0.1:7777".parse().expect("origin"));
        operator.insert(
            AUTHORIZATION,
            format!("Bearer {auth_token}").parse().expect("auth"),
        );
        decline_pairing(
            State(state.clone()),
            operator,
            AxumPath(ack.request_id.clone()),
        )
        .await
        .expect("operator declines");
        assert_eq!(
            poll_pairing_exchange(State(state.clone()), AxumPath(ack.request_id))
                .await
                .expect_err("declined is surfaced")
                .0,
            StatusCode::FORBIDDEN,
        );
    }

    #[test]
    fn pipeline_diagnostics_map_to_actionable_http_statuses() {
        let not_found = pipeline_response(
            catalogue::PIPELINE_RUN_NOT_FOUND.instantiate(DiagnosticContext::new()),
        );
        assert_eq!(not_found.0, StatusCode::NOT_FOUND);
        let not_ready = pipeline_response(
            catalogue::PIPELINE_SURFACE_NOT_READY.instantiate(DiagnosticContext::new()),
        );
        assert_eq!(not_ready.0, StatusCode::CONFLICT);
    }

    #[test]
    fn export_diagnostics_map_to_actionable_http_statuses() {
        let not_ready = export_response(vec![
            catalogue::EXPORT_SURFACE_NOT_READY.instantiate(DiagnosticContext::new()),
        ]);
        assert_eq!(not_ready.0, StatusCode::CONFLICT);
        let invalid = export_response(vec![
            catalogue::EXPORT_INVALID_REQUEST.instantiate(DiagnosticContext::new()),
        ]);
        assert_eq!(invalid.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pipeline_start_is_queryable_and_retains_stage_diagnostics() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-local-api-pipeline-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let session_id = format!(
            "session:api-pipeline-test-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let session_id = apiaxess_session::SessionId::new(session_id).expect("session ID");
        let now = chrono::Utc::now();
        let mut session = apiaxess_session::Session::new(
            session_id,
            test_scope(),
            apiaxess_api_model::ApiDocument::new(apiaxess_api_model::ApiSurface {
                provenance: apiaxess_api_model::ProvenanceRegistry::default(),
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            now,
        );
        session.activate(now).expect("activate session");
        let store = Arc::new(
            apiaxess_workbench_store::TrafficStore::open(&root, session.id().as_str())
                .expect("open test store"),
        );
        let engine = Engine::new();
        engine
            .attach_session_runtime(Arc::new(apiaxess_engine_shell::SessionRuntime::new(
                session,
                store,
                root.join("session.json"),
            )))
            .expect("attach runtime");
        let state = ApiState {
            engine,
            expected_origin: Arc::from("http://127.0.0.1:7777"),
            pipeline_runs: PipelineRegistry::default(),
            pairing: DevicePairingRegistry::default(),
            pending_pairing: PendingPairingRegistry::default(),
            gui_port: 7777,
        };
        let (code, Json(queued)) = start_pipeline(
            State(state.clone()),
            Some(Json(StartPipelineRequest {
                artifact_path: root.join("missing.apk").display().to_string(),
                run_id: Some("pipeline:api-test-run".to_owned()),
                ..StartPipelineRequest::default()
            })),
        )
        .await
        .expect("queue pipeline");
        assert_eq!(code, StatusCode::ACCEPTED);
        assert_eq!(queued.run_id, "pipeline:api-test-run");

        let mut observed = None;
        for _ in 0..20 {
            if let Ok(Json(status)) = pipeline_status_for(&state, &queued.run_id) {
                if status.status == PipelineRunStatus::Failed {
                    observed = Some(status);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let status = observed.expect("failed intake becomes queryable");
        assert_eq!(status.stage, PipelineStage::Intake);
        assert!(!status.diagnostics.is_empty());
    }

    /// The packaged GUI must be served with cache headers that survive a rebuild:
    /// `index.html` (and non-fingerprinted static files) revalidate every load so a
    /// new build's asset hashes are picked up without a hard-refresh, while Vite's
    /// content-hashed `/assets/*` files are cached hard (immutable).
    #[tokio::test]
    async fn gui_static_serving_sets_cache_control_by_path() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = std::env::temp_dir().join(format!(
            "apiaxess-gui-cache-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("assets")).expect("assets dir");
        std::fs::create_dir_all(dir.join("fonts")).expect("fonts dir");
        std::fs::write(
            dir.join("index.html"),
            b"<!doctype html><script src=\"/assets/index-abc123.js\"></script>",
        )
        .expect("index");
        std::fs::write(dir.join("assets/index-abc123.js"), b"console.log(1)").expect("asset");
        std::fs::write(dir.join("fonts/archivo-latin.woff2"), b"font").expect("font");

        let router = router_with_port(Engine::new(), &dir, 7777).expect("router");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = reqwest::Client::new();
        let cache_control = |response: &reqwest::Response| {
            response
                .headers()
                .get(reqwest::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };

        // index.html revalidates every load.
        let index = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("GET /");
        assert_eq!(index.status(), reqwest::StatusCode::OK);
        assert_eq!(cache_control(&index).as_deref(), Some("no-cache"));
        assert!(
            index
                .text()
                .await
                .expect("body")
                .contains("index-abc123.js"),
            "the served index references the current asset hash"
        );

        // Fingerprinted assets are cached hard and served correctly.
        let asset = client
            .get(format!("http://{addr}/assets/index-abc123.js"))
            .send()
            .await
            .expect("GET asset");
        assert_eq!(asset.status(), reqwest::StatusCode::OK);
        assert_eq!(
            cache_control(&asset).as_deref(),
            Some("public, max-age=31536000, immutable")
        );

        // Non-fingerprinted static files (fonts) revalidate like index.html.
        let font = client
            .get(format!("http://{addr}/fonts/archivo-latin.woff2"))
            .send()
            .await
            .expect("GET font");
        assert_eq!(font.status(), reqwest::StatusCode::OK);
        assert_eq!(cache_control(&font).as_deref(), Some("no-cache"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
