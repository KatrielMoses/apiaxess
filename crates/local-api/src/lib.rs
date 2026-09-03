//! Loopback HTTP/WebSocket transport and static GUI asset serving.

mod settings;

pub use settings::persisted_env_overrides;

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
    FlowDetail, FlowSummary, InterceptDecision, LiveWorkbench, RepeaterRequest,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as AxumPath, Query, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode, header::ORIGIN},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tower_http::services::{ServeDir, ServeFile};

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
pub fn router_with_port(engine: Engine, gui_directory: &Path, port: u16) -> io::Result<Router> {
    let index = gui_directory.join("index.html");
    index.metadata()?;
    let gui_assets = ServeDir::new(gui_directory).not_found_service(ServeFile::new(index));
    let state = ApiState {
        engine,
        expected_origin: Arc::from(format!("http://127.0.0.1:{port}")),
        pipeline_runs: PipelineRegistry::default(),
    };

    Ok(Router::new()
        .route("/api/v1/system/status", get(system_status))
        .route(
            "/api/v1/settings",
            get(get_settings).put(update_settings_handler),
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
            "/api/v1/workbench/repeater",
            get(list_repeater).post(create_repeater),
        )
        .route(
            "/api/v1/workbench/repeater/{context_id}",
            get(get_repeater).put(update_repeater),
        )
        .route(
            "/api/v1/workbench/repeater/{context_id}/send",
            axum::routing::post(send_repeater),
        )
        .route(
            "/api/v1/workbench/repeater/{context_id}/derive/{revision}",
            axum::routing::post(derive_repeater),
        )
        .route(
            "/api/v1/workbench/intruder",
            get(list_intruder).post(create_intruder),
        )
        .route("/api/v1/workbench/intruder/{job_id}", get(get_intruder))
        .route(
            "/api/v1/workbench/intruder/{job_id}/start",
            axum::routing::post(start_intruder),
        )
        .route(
            "/api/v1/workbench/intruder/{job_id}/pause",
            axum::routing::post(pause_intruder),
        )
        .route(
            "/api/v1/workbench/intruder/{job_id}/resume",
            axum::routing::post(resume_intruder),
        )
        .route(
            "/api/v1/workbench/intruder/{job_id}/stop",
            axum::routing::post(stop_intruder),
        )
        .route("/api/v1/workbench/ws/control", get(control_ws))
        .route("/api/v1/workbench/ws/telemetry", get(telemetry_ws))
        .fallback_service(gui_assets)
        .with_state(state))
}

#[derive(Clone)]
struct ApiState {
    engine: Engine,
    expected_origin: Arc<str>,
    pipeline_runs: PipelineRegistry,
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
    Json<apiaxess_workbench_store::IntruderJob>,
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
                    (credential.key, apiaxess_engine_shell::Secret::from_text(&credential.value))
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
            diagnostics: apiaxess_diagnostics::bounded_status_diagnostics(&entry.diagnostics, 8, 100),
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
struct CreateRepeater {
    flow_id: Option<u64>,
    request: Option<RepeaterRequest>,
}

async fn list_repeater(
    State(state): State<ApiState>,
) -> Json<Vec<apiaxess_workbench_store::RepeaterContext>> {
    Json(state.engine.repeater().list())
}

async fn create_repeater(
    State(state): State<ApiState>,
    Json(input): Json<CreateRepeater>,
) -> Result<
    Json<apiaxess_workbench_store::RepeaterContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    let repeater = state.engine.repeater();
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
        repeater.create_from_flow(&flow)
    } else if let Some(request) = input.request {
        repeater.create(request, None)
    } else {
        return Err(storage_response(
            catalogue::PROXY_REPEATER_REQUEST_FAILED.instantiate(DiagnosticContext::new()),
        ));
    }
    .map_err(storage_response)?;
    Ok(Json(context))
}

async fn get_repeater(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::RepeaterContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .repeater()
        .get(&context_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
            )
        })
}

async fn update_repeater(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
    Json(request): Json<RepeaterRequest>,
) -> Result<
    Json<apiaxess_workbench_store::RepeaterContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .repeater()
        .update_request(&context_id, request)
        .map(Json)
        .map_err(storage_response)
}

async fn send_repeater(
    State(state): State<ApiState>,
    AxumPath(context_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_proxy::RepeaterSendResult>,
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
        .repeater()
        .send_in_session(&context_id, &mut session)
        .await
        .map_err(storage_response)?;
    runtime.replace_session(session).map_err(session_response)?;
    Ok(Json(result))
}

async fn derive_repeater(
    State(state): State<ApiState>,
    AxumPath((context_id, revision)): AxumPath<(String, u64)>,
) -> Result<
    Json<apiaxess_workbench_store::RepeaterContext>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .repeater()
        .derive(&context_id, revision)
        .map(Json)
        .map_err(storage_response)
}

async fn list_intruder(
    State(state): State<ApiState>,
) -> Json<Vec<apiaxess_workbench_store::IntruderJob>> {
    Json(state.engine.intruder().list())
}

async fn create_intruder(
    State(state): State<ApiState>,
    Json(config): Json<apiaxess_workbench_store::IntruderConfig>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .intruder()
        .create(config)
        .map(Json)
        .map_err(storage_response)
}

async fn get_intruder(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .intruder()
        .get(&job_id)
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(catalogue::PROXY_LIVE_DESYNC.instantiate(DiagnosticContext::new())),
            )
        })
}

async fn start_intruder(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
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
    let intruder = state.engine.intruder();
    let job = intruder
        .launch_in_session(&job_id, &mut session)
        .map_err(storage_response)?;
    runtime.replace_session(session).map_err(session_response)?;

    let watcher_runtime = runtime;
    let watcher_intruder = intruder;
    let watcher_job_id = job_id.clone();
    let watcher_live = state.engine.live_workbench();
    tokio::spawn(async move {
        loop {
            let Some(current) = watcher_intruder.get(&watcher_job_id) else {
                watcher_live.publish_diagnostic(
                    catalogue::PROXY_SESSION_AUDIT_FAILED.instantiate(DiagnosticContext::new()),
                );
                return;
            };
            if matches!(
                current.state,
                apiaxess_workbench_store::IntruderJobState::Completed
                    | apiaxess_workbench_store::IntruderJobState::Failed
                    | apiaxess_workbench_store::IntruderJobState::Stopped
            ) {
                let mut session = match watcher_runtime.session_snapshot() {
                    Ok(session) => session,
                    Err(diagnostic) => {
                        watcher_live.publish_diagnostic(diagnostic);
                        return;
                    }
                };
                for result in current.results {
                    let record_id = format!("intruder:{watcher_job_id}:{}", result.ordinal);
                    if session
                        .audit_trail()
                        .iter()
                        .any(|record| record.id == record_id)
                    {
                        continue;
                    }
                    if let Err(diagnostic) = watcher_intruder.record_result_in_session(
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

async fn pause_intruder(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .intruder()
        .pause(&job_id)
        .map(Json)
        .map_err(storage_response)
}

async fn resume_intruder(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .intruder()
        .resume(&job_id)
        .map(Json)
        .map_err(storage_response)
}

async fn stop_intruder(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
) -> Result<
    Json<apiaxess_workbench_store::IntruderJob>,
    (StatusCode, Json<apiaxess_diagnostics::Diagnostic>),
> {
    state
        .engine
        .intruder()
        .stop(&job_id)
        .map(Json)
        .map_err(storage_response)
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
}
