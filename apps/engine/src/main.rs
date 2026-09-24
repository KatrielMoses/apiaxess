//! Native `APIaxess` composition root.

use std::{
    collections::HashSet,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use apiaxess_api_model::{ApiDocument, ApiSurface, ProvenanceRegistry};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_engine_shell::SessionRuntime;
use apiaxess_engine_shell::{Engine, ExportConfig};
use apiaxess_session::{
    AllowedNetworkTarget, EngagementScope, HostMatch, Session, SessionId, SessionLifecycle,
    TargetIdentifier, TargetIdentity,
};
use apiaxess_workbench_proxy::{
    CaStateLog, ProxyCore, ProxyResendSender, SessionCa, SystemCaInstall, SystemStorePurger,
};
use apiaxess_workbench_store::TrafficStore;
use chrono::Utc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const DEFAULT_GUI_ADDRESS: &str = "127.0.0.1:7777";
const DEFAULT_PROXY_ADDRESS: &str = "127.0.0.1:8080";
const SESSION_CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);

struct CheckpointTask(Option<tokio::task::JoinHandle<()>>);

impl CheckpointTask {
    fn start(engine: Engine) -> Self {
        Self(Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(SESSION_CHECKPOINT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let runtime = match engine.session_runtime() {
                    Ok(Some(runtime)) => runtime,
                    Ok(None) => continue,
                    Err(diagnostic) => {
                        engine.live_workbench().publish_diagnostic(diagnostic);
                        continue;
                    }
                };
                if let Err(diagnostic) = runtime.checkpoint_if_dirty() {
                    engine.live_workbench().publish_diagnostic(diagnostic);
                }
            }
        })))
    }

    async fn stop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for CheckpointTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Apply persisted operator settings to the environment before the async
    // runtime (and any worker threads) exists, so every existing `APIAXESS_*`
    // consumer honors them with no change.
    apply_persisted_settings();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

/// Applies saved operator settings to this process's environment. An environment
/// variable already set (an external override) is never replaced.
#[allow(unsafe_code)] // The one audited env mutation, before any thread is spawned.
fn apply_persisted_settings() {
    for (key, value) in apiaxess_local_api::persisted_env_overrides() {
        // Safety: this runs from `main` before the Tokio runtime and its worker
        // threads are created, so no other thread can read the environment
        // concurrently. `persisted_env_overrides` already skips keys present in
        // the environment, preserving any external override.
        unsafe {
            std::env::set_var(&key, &value);
        }
    }
}

#[allow(clippy::too_many_lines)] // Keep the top-level CLI dispatch linear so command errors retain their exact context.
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--purge-cas")
    {
        let state_path = arguments
            .get(1)
            .map_or_else(default_ca_state_path, PathBuf::from);
        purge_cas(&state_path)?;
        return Ok(());
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "analyze")
    {
        return run_analyze_cli(&arguments[1..]);
    }
    if arguments.first().is_some_and(|argument| argument == "web") {
        return run_web_cli(&arguments[1..]);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "browse")
    {
        return run_browse_cli(&arguments[1..]).await;
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "discover")
    {
        return run_discover_cli(&arguments[1..]).await;
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "inspect")
    {
        return run_inspect_cli(&arguments[1..]);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "export")
    {
        return run_export_cli(&arguments[1..]);
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "serve")
    {
        return run_serve(&arguments[1..]).await;
    }
    if arguments
        .first()
        .is_some_and(|argument| argument == "--help" || argument == "-h")
    {
        print_cli_help();
        return Ok(());
    }
    let startup_artifact = startup_artifact(&arguments)?;
    init_tracing();
    // The default (no-subcommand) invocation is the loopback workbench server the
    // native shell and the browser launch mode both drive. `serve` is the
    // first-class headless variant with explicit port/host control.
    let gui_address = loopback_address("APIAXESS_GUI_ADDRESS", DEFAULT_GUI_ADDRESS)?;
    let proxy_address = loopback_address("APIAXESS_PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS)?;
    serve_workbench(gui_address, proxy_address, startup_artifact, false).await
}

/// Installs the tracing subscriber once for a server invocation.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

/// Runs the engine and serves the GUI + API until an interrupt (Ctrl-C) triggers
/// graceful shutdown. Shared by the default native/browser path and the headless
/// `serve` command; `announce_access` prints the operator-facing access banner
/// used by the headless deployment mode.
async fn serve_workbench(
    gui_address: SocketAddr,
    proxy_address: SocketAddr,
    startup_artifact: Option<PathBuf>,
    announce_access: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let gui_directory = gui_directory();
    let engine = Engine::new();
    let listener = tokio::net::TcpListener::bind(gui_address).await?;
    let bound_gui_address = listener.local_addr()?;
    let application = apiaxess_local_api::router_with_port(
        engine.clone(),
        &gui_directory,
        bound_gui_address.port(),
    )?;
    let startup_engine = engine.clone();
    let runtime = match WorkbenchRuntime::start_with_artifact(
        engine,
        proxy_address,
        startup_artifact,
    )
    .await
    {
        Ok(runtime) => runtime,
        Err(diagnostic) => {
            report_startup_diagnostic(&diagnostic);
            startup_engine
                .live_workbench()
                .publish_diagnostic(diagnostic.clone());
            let serve_result = axum::serve(listener, application)
                .with_graceful_shutdown(shutdown_signal())
                .await;
            serve_result?;
            return Err(Box::new(diagnostic) as Box<dyn std::error::Error>);
        }
    };

    info!(
        gui_address = %bound_gui_address,
        proxy_address = %runtime.proxy_address,
        ca_fingerprint = %runtime.ca.fingerprint(),
        store = %runtime.store.database_path().display(),
        gui_directory = %gui_directory.display(),
        "APIaxess workbench is ready"
    );
    if announce_access {
        print_access_banner(bound_gui_address);
    }
    let serve_result = axum::serve(listener, application)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let shutdown_result = runtime.shutdown().await;
    serve_result?;
    if let Err(diagnostic) = shutdown_result {
        report_startup_diagnostic(&diagnostic);
        return Err(Box::new(diagnostic) as Box<dyn std::error::Error>);
    }

    Ok(())
}

#[derive(Debug, Default)]
struct AnalyzeOptions {
    artifact_path: Option<PathBuf>,
    session_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    intake_output_root: Option<PathBuf>,
    scope_json: Option<String>,
    allow_targets: Vec<String>,
    session_id: Option<String>,
    staged_credentials: Vec<(String, String)>,
    dynamic: bool,
    json: bool,
    help: bool,
}

#[derive(Debug, Default)]
struct ExportOptions {
    session_path: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    formats: Vec<String>,
    json: bool,
    help: bool,
}

#[derive(Debug, Default)]
struct WebOptions {
    target: Option<String>,
    output_path: Option<PathBuf>,
    authorize: bool,
    json: bool,
    help: bool,
}

#[derive(Debug)]
struct BrowseOptions {
    session_path: PathBuf,
}

fn print_cli_help() {
    println!(
        "Export: apiaxess export <session> --format <openapi|sdk|postman|har|all> --out <dir> [--json]"
    );
    println!(
        "APIaxess\n\nCommands:\n  apiaxess                                    Launch the local workbench (loopback UI)\n  apiaxess serve [--port <n>] [--host <addr>] Run headless: serve the UI on a port until Ctrl-C\n  apiaxess analyze <apk> [options]\n  apiaxess web <domain-or-url> --authorize [options]\n  apiaxess inspect <session> [--json]\n\nWeb options:\n  --authorize               Affirm that you are authorized to test this target (required)\n  --output <path>           Persist the web session artifact at this path\n  --json                    Print the started session status as JSON\n\nAnalyze options:\n  --static-only             Run the static pipeline only (default)\n  --dynamic                 Request dynamic enrichment when session evidence exists\n  --session <path>          Resume an existing session artifact\n  --output <path>           Persist a new session artifact at this path\n  --scope <json|@file>      Declare the complete session EngagementScope\n  --allow-target <host>     Add an allowed host rule (repeatable)\n  --staged-credential <kind=value>  Pre-stage a login credential for the crawler,\n                            keyed by field kind (phone, otp, password, pin, email,\n                            username). Repeatable. e.g. --staged-credential phone=8888888888\n  --session-id <id>         Set the ID for a new session\n  --intake-output <dir>     Store normalized intake output below this directory\n  --json                    Print the unified surface as JSON\n  -h, --help                Show this help\n\nAPK analysis uses APIaxess's bundled Java runtime, apktool, and jadx by\ndefault, so nothing is required on the host. Advanced overrides:\nAPIAXESS_JAVA, APIAXESS_APKTOOL, APIAXESS_JADX (a .jar value runs through the\nbundled runtime; anything else is treated as a self-contained launcher)."
    );
}

#[derive(Debug, Default)]
struct ServeOptions {
    host: Option<String>,
    port: Option<u16>,
    help: bool,
}

/// Runs the first-class headless server: engine + GUI on a port, no native
/// window and no browser launched, until Ctrl-C. This is the VM/server
/// deployment mode.
async fn run_serve(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_serve_options(arguments)?;
    if options.help {
        print_serve_help();
        return Ok(());
    }
    init_tracing();
    let (gui_address, exposed) = serve_bind_address(options.host.as_deref(), options.port)?;
    let proxy_address = loopback_address("APIAXESS_PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS)?;
    if exposed {
        eprintln!(
            "WARNING: binding {gui_address} exposes the APIaxess workbench beyond loopback. \
             This is a deliberate choice you must secure (firewall/VPN); prefer an SSH tunnel \
             for remote access."
        );
    }
    serve_workbench(gui_address, proxy_address, None, true).await
}

fn parse_serve_options(arguments: &[String]) -> Result<ServeOptions, Box<dyn std::error::Error>> {
    let mut options = ServeOptions::default();
    let mut iterator = arguments.iter();
    while let Some(argument) = iterator.next() {
        match argument.as_str() {
            "--port" => {
                let value = iterator.next().ok_or("--port requires a value")?;
                options.port = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| format!("invalid --port value: {value}"))?,
                );
            }
            "--host" => {
                options.host = Some(iterator.next().ok_or("--host requires a value")?.clone());
            }
            "--help" | "-h" => options.help = true,
            other => return Err(format!("unknown serve option: {other}").into()),
        }
    }
    Ok(options)
}

/// Resolves the serve bind address from explicit flags, then the
/// `APIAXESS_GUI_ADDRESS` env, then the loopback default. Returns whether the
/// resolved address is a deliberate non-loopback exposure.
fn serve_bind_address(
    host: Option<&str>,
    port: Option<u16>,
) -> Result<(SocketAddr, bool), Box<dyn std::error::Error>> {
    let default_address: SocketAddr = env::var("APIAXESS_GUI_ADDRESS")
        .ok()
        .and_then(|address| address.parse().ok())
        .unwrap_or_else(|| {
            DEFAULT_GUI_ADDRESS
                .parse()
                .expect("the default GUI address is a valid socket address")
        });
    let ip: IpAddr = match host {
        Some(host) => host
            .parse()
            .map_err(|_| format!("invalid --host address (expected an IP): {host}"))?,
        None => default_address.ip(),
    };
    let port = port.unwrap_or_else(|| default_address.port());
    let address = SocketAddr::new(ip, port);
    Ok((address, !ip.is_loopback()))
}

fn print_access_banner(address: SocketAddr) {
    let url = format!("http://127.0.0.1:{}/", address.port());
    println!();
    println!("  APIaxess is serving the workbench at:");
    println!("      {url}");
    if !address.ip().is_loopback() {
        println!("  Bound to {address} — reachable from other hosts.");
        println!("  For full live functionality from a remote host, prefer an SSH tunnel so the");
        println!("  browser origin stays loopback (the live control/telemetry require it).");
    }
    println!("  Open that URL in your browser. Press Ctrl-C to stop.");
    println!();
}

fn print_serve_help() {
    println!(
        "Serve: apiaxess serve [--port <n>] [--host <addr>]\n\n  Runs the engine and serves the workbench GUI + API on a port until Ctrl-C —\n  headless: no native window, no browser launched. Open the printed URL in your\n  browser (locally, or remotely via an SSH tunnel). Binds loopback by default;\n  --host exposes it beyond loopback as a deliberate operator choice you must\n  secure yourself. --port defaults to 7777 (or APIAXESS_GUI_ADDRESS)."
    );
}

fn run_web_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_web_options(arguments)?;
    if options.help {
        return Ok(());
    }
    let target = options
        .target
        .ok_or_else(|| "web requires a domain or URL".to_owned())?;
    if !options.authorize {
        return Err("web sessions require --authorize: you must affirm that you are authorized to test this target".into());
    }
    let engine = Engine::new();
    let status = engine
        .start_web_session(&target, true, options.output_path)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Web session started for {target}");
        println!("session: {}", status.session_id);
        println!("session artifact: {}", status.artifact_path);
        println!("scope: {}", status.scope.target.primary.value);
        println!("authorization: affirmed and recorded in the session audit trail");
    }
    Ok(())
}

async fn run_browse_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_browse_options(arguments)?;
    let engine = Engine::new();
    let runtime = WorkbenchRuntime::start_with_artifact(
        engine.clone(),
        loopback_address("APIAXESS_PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS)?,
        Some(options.session_path),
    )
    .await
    .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    let launched = match engine.launch_bundled_chromium() {
        Ok(launched) => launched,
        Err(diagnostic) => {
            let error = cli_diagnostic_error(&diagnostic);
            let _ = runtime.shutdown().await;
            return Err(Box::new(error));
        }
    };
    println!(
        "Opened Bundled Chromium for {}; close the browser window to finish capture.",
        launched.target.as_deref().unwrap_or("the web target")
    );
    while engine
        .browser_launch_status()
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?
        .running
    {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    runtime
        .shutdown()
        .await
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    Ok(())
}

async fn run_discover_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = None;
    let mut kind = apiaxess_engine_shell::DiscoveryKind::Directory;
    let mut wordlist = "small".to_owned();
    let mut confirmed = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--type" => {
                index += 1;
                kind = match arguments.get(index).map(String::as_str) {
                    Some("subdomain") => apiaxess_engine_shell::DiscoveryKind::Subdomain,
                    Some("directory") => apiaxess_engine_shell::DiscoveryKind::Directory,
                    _ => return Err("--type accepts subdomain or directory".into()),
                };
            }
            "--wordlist" => {
                index += 1;
                wordlist.clone_from(arguments.get(index).ok_or("--wordlist requires a name")?);
            }
            "--confirm" => confirmed = true,
            value if value.starts_with('-') => {
                return Err(format!("unknown discover option: {value}").into());
            }
            value if session.is_none() => session = Some(PathBuf::from(value)),
            _ => return Err("discover accepts one session artifact path".into()),
        }
        index += 1;
    }
    let engine = Engine::new();
    let runtime = WorkbenchRuntime::start_with_artifact(
        engine.clone(),
        loopback_address("APIAXESS_PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS)?,
        Some(session.ok_or("discover requires a session artifact path")?),
    )
    .await
    .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    let estimate = engine
        .estimate_discovery(kind, &wordlist, None)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    println!(
        "Discovery target={} requests={} estimate={} ({} req/s). Authorization is required before active probing.",
        estimate.target, estimate.request_count, estimate.estimated_label, estimate.rate_per_second
    );
    if !confirmed {
        runtime
            .shutdown()
            .await
            .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
        return Ok(());
    }
    let job = engine
        .start_discovery(kind, &wordlist, None, true)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    println!("Discovery started: {}", job.id);
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let state = engine.fuzzer().get(&job.id).map(|job| job.state);
        if matches!(
            state,
            Some(
                apiaxess_workbench_store::FuzzerJobState::Completed
                    | apiaxess_workbench_store::FuzzerJobState::Failed
                    | apiaxess_workbench_store::FuzzerJobState::Stopped
            ) | None
        ) {
            break;
        }
    }
    runtime
        .shutdown()
        .await
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    Ok(())
}

fn parse_browse_options(arguments: &[String]) -> Result<BrowseOptions, Box<dyn std::error::Error>> {
    let mut session_path = None;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "--browser" | "--executable" => return Err("browse always uses the bundled Chromium; browser selection and external executables are no longer supported".into()),
            _ if argument.starts_with('-') => {
                return Err(format!("unknown browse option: {argument}").into());
            }
            _ if session_path.is_none() => session_path = Some(PathBuf::from(argument)),
            _ => return Err("browse accepts exactly one session artifact path".into()),
        }
        index += 1;
    }
    Ok(BrowseOptions {
        session_path: session_path.ok_or("browse requires a web session artifact path")?,
    })
}

fn parse_web_options(arguments: &[String]) -> Result<WebOptions, Box<dyn std::error::Error>> {
    let mut options = WebOptions::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let value = |index: &mut usize, name: &str| -> Result<String, Box<dyn std::error::Error>> {
            *index += 1;
            arguments.get(*index).cloned().ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} requires a value"),
                )) as Box<dyn std::error::Error>
            })
        };
        match argument.as_str() {
            "--authorize" => options.authorize = true,
            "--output" => options.output_path = Some(PathBuf::from(value(&mut index, argument)?)),
            "--json" => options.json = true,
            "--help" | "-h" => {
                println!(
                    "Usage: apiaxess web <domain-or-url> --authorize [--output <session.json>] [--json]"
                );
                options.help = true;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown web option: {argument}").into());
            }
            _ if options.target.is_none() => options.target = Some(argument.clone()),
            _ => return Err("web accepts exactly one domain or URL".into()),
        }
        index += 1;
    }
    Ok(options)
}

fn run_inspect_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut path = None;
    let mut json = false;
    for argument in arguments {
        match argument.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("Usage: apiaxess inspect <session.json> [--json]");
                return Ok(());
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown inspect option: {argument}").into());
            }
            _ if path.is_none() => path = Some(PathBuf::from(argument)),
            _ => return Err("inspect accepts exactly one session artifact path".into()),
        }
    }
    let path = path.ok_or_else(|| "inspect requires a session artifact path".to_owned())?;
    let engine = Engine::new();
    engine
        .open_session(&path)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    let surface = engine
        .session_surface()
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?
        .ok_or_else(|| {
            let diagnostic =
                catalogue::PIPELINE_SURFACE_NOT_READY.instantiate(DiagnosticContext::new());
            cli_diagnostic_error(&diagnostic)
        })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&surface)?);
    } else {
        print_surface_summary(&engine, &surface)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_export_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_export_options(arguments)?;
    if options.help {
        return Ok(());
    }
    let session_path = options
        .session_path
        .ok_or_else(|| "export requires a session artifact path".to_owned())?;
    let output_dir = options
        .output_dir
        .ok_or_else(|| "export requires --out <directory>".to_owned())?;
    let names = if options.formats.is_empty() {
        vec!["all".to_owned()]
    } else {
        options.formats
    };
    let config = ExportConfig::from_names(output_dir, names)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    let engine = Engine::new();
    engine
        .open_session(&session_path)
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    let report = match engine.export_session_artifacts(&config) {
        Ok(report) => report,
        Err(diagnostics) => {
            for diagnostic in &diagnostics {
                print_cli_diagnostic(diagnostic);
            }
            return Err(Box::new(std::io::Error::other("artifact export failed")));
        }
    };
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("session: {}", report.session_id);
        println!("export directory: {}", report.output_dir);
        for artifact in &report.artifacts {
            println!(
                "{}: {} bytes ({})",
                artifact.format.as_str(),
                artifact.bytes,
                artifact.paths.join(", ")
            );
        }
        for diagnostic in &report.diagnostics {
            print_cli_diagnostic(diagnostic);
        }
    }
    Ok(())
}

fn parse_export_options(arguments: &[String]) -> Result<ExportOptions, Box<dyn std::error::Error>> {
    let mut options = ExportOptions::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let value = |index: &mut usize, name: &str| -> Result<String, Box<dyn std::error::Error>> {
            *index += 1;
            arguments.get(*index).cloned().ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} requires a value"),
                )) as Box<dyn std::error::Error>
            })
        };
        match argument.as_str() {
            "--format" => options.formats.push(value(&mut index, argument)?),
            "--out" | "--output" => {
                options.output_dir = Some(PathBuf::from(value(&mut index, argument)?));
            }
            "--json" => options.json = true,
            "--help" | "-h" => {
                println!(
                    "Usage: apiaxess export <session.json> --format <openapi|sdk|postman|har|all> --out <dir> [--json]"
                );
                options.help = true;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown export option: {argument}").into());
            }
            _ if options.session_path.is_none() => {
                options.session_path = Some(PathBuf::from(argument));
            }
            _ => return Err("export accepts exactly one session artifact path".into()),
        }
        index += 1;
    }
    Ok(options)
}

#[allow(clippy::too_many_lines)]
fn run_analyze_cli(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_analyze_options(arguments)?;
    if options.help {
        return Ok(());
    }
    let artifact_path = options
        .artifact_path
        .clone()
        .ok_or_else(|| "analyze requires an APK path".to_owned())?;
    let engine = Engine::new();

    if let Some(session_path) = options.session_path.as_deref() {
        engine
            .open_session(session_path)
            .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
        if let Some(scope) = options.scope_json.as_deref() {
            let scope = parse_scope(scope)?;
            engine
                .update_session_scope(scope)
                .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
        } else if !options.allow_targets.is_empty() {
            let mut scope = engine
                .session_scope()
                .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
            scope.allowed_targets = parse_allowed_targets(&options.allow_targets);
            scope.declared_at = Utc::now();
            engine
                .update_session_scope(scope)
                .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
        }
    } else {
        let session_id = options
            .session_id
            .as_deref()
            .map_or_else(apiaxess_engine_shell::fresh_session_id, |value| {
                SessionId::new(value.to_owned())
            })?;
        let scope = options.scope_json.as_deref().map_or_else(
            || {
                Ok::<_, Box<dyn std::error::Error>>(EngagementScope {
                    declared_at: Utc::now(),
                    target: TargetIdentity {
                        target_type: "android.apk".to_owned(),
                        primary: TargetIdentifier {
                            kind: "artifact.path".to_owned(),
                            value: artifact_path.display().to_string(),
                        },
                        aliases: Vec::new(),
                    },
                    allowed_targets: if options.allow_targets.is_empty() {
                        allowed_targets()
                    } else {
                        parse_allowed_targets(&options.allow_targets)
                    },
                })
            },
            parse_scope,
        )?;
        scope.validate()?;
        let mut session = Session::new(
            session_id,
            scope,
            ApiDocument::new(ApiSurface {
                provenance: ProvenanceRegistry::default(),
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            Utc::now(),
        );
        session.activate(Utc::now())?;
        let store = Arc::new(
            TrafficStore::open(&Engine::session_store_root(), session.id().as_str())
                .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?,
        );
        let artifact = options
            .output_path
            .clone()
            .unwrap_or_else(|| store.root().join("session.json"));
        engine.attach_session_runtime(Arc::new(SessionRuntime::new(session, store, artifact)))?;
    }
    let _checkpoint_task = CheckpointTask::start(engine.clone());

    let mut config = apiaxess_engine_shell::PipelineConfig::new(artifact_path.clone())?
        .with_dynamic_capture(options.dynamic);
    // The intake toolchain defaults to the bundled, host-independent runtime +
    // apktool + jadx, resolved by absolute path from the install layout. The
    // advanced `APIAXESS_JAVA`/`APIAXESS_APKTOOL`/`APIAXESS_JADX` overrides are
    // honored inside that resolution, so nothing is required on the host.
    let intake = apiaxess_target_apk::ApkIntakeConfig::default();
    config = config.with_intake_config(intake);
    if let Some(root) = options.intake_output_root {
        config = config.with_intake_output_root(root);
    }
    if !options.staged_credentials.is_empty() {
        let staged = options
            .staged_credentials
            .into_iter()
            .map(|(name, secret)| (name, apiaxess_engine_shell::Secret::from_text(&secret)))
            .collect();
        config = config.with_staged_credentials(staged);
    }
    let json_progress = options.json;
    let printed_diagnostics = Arc::new(Mutex::new(HashSet::<String>::new()));
    let diagnostic_cursor = Arc::clone(&printed_diagnostics);
    config = config.with_progress_callback(move |progress| {
        if !json_progress {
            eprintln!(
                "pipeline stage={} status={} progress={}bp: {}",
                progress.stage.as_str(),
                progress.status.as_str(),
                progress.progress_basis_points,
                progress.message
            );
            if let Ok(mut seen) = diagnostic_cursor.lock() {
                for diagnostic in &progress.diagnostics {
                    if seen.insert(diagnostic.id.to_string()) {
                        print_cli_diagnostic(diagnostic);
                    }
                }
            }
        }
    });

    let report = match engine.run_pipeline(&config) {
        Ok(report) => report,
        Err(failure) => {
            for diagnostic in &failure.diagnostics {
                print_cli_diagnostic(diagnostic);
            }
            return Err(Box::new(std::io::Error::other(failure.to_string())));
        }
    };
    engine
        .save_session()
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report.unified_surface)?);
    } else {
        print_surface_summary(&engine, &report.unified_surface)?;
    }
    Ok(())
}

fn parse_analyze_options(
    arguments: &[String],
) -> Result<AnalyzeOptions, Box<dyn std::error::Error>> {
    let mut options = AnalyzeOptions::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        let value = |index: &mut usize, name: &str| -> Result<String, Box<dyn std::error::Error>> {
            *index += 1;
            arguments.get(*index).cloned().ok_or_else(|| {
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} requires a value"),
                )) as Box<dyn std::error::Error>
            })
        };
        match argument.as_str() {
            "--static-only" => options.dynamic = false,
            "--dynamic" => options.dynamic = true,
            "--json" => options.json = true,
            "--help" | "-h" => {
                print_cli_help();
                options.help = true;
            }
            "--session" => options.session_path = Some(PathBuf::from(value(&mut index, argument)?)),
            "--output" => options.output_path = Some(PathBuf::from(value(&mut index, argument)?)),
            "--intake-output" => {
                options.intake_output_root = Some(PathBuf::from(value(&mut index, argument)?));
            }
            "--scope" => options.scope_json = Some(value(&mut index, argument)?),
            "--allow-target" => options.allow_targets.push(value(&mut index, argument)?),
            "--staged-credential" => {
                let raw = value(&mut index, argument)?;
                let (name, secret) = raw.split_once('=').ok_or_else(|| {
                    format!("--staged-credential expects name=value, got '{raw}'")
                })?;
                options
                    .staged_credentials
                    .push((name.to_owned(), secret.to_owned()));
            }
            "--session-id" => options.session_id = Some(value(&mut index, argument)?),
            _ if argument.starts_with('-') => {
                return Err(format!("unknown analyze option: {argument}").into());
            }
            _ if options.artifact_path.is_none() => {
                options.artifact_path = Some(PathBuf::from(argument));
            }
            _ => return Err("analyze accepts exactly one APK path".into()),
        }
        index += 1;
    }
    Ok(options)
}

fn parse_scope(value: &str) -> Result<EngagementScope, Box<dyn std::error::Error>> {
    let json = value.strip_prefix('@').map_or_else(
        || Ok(value.to_owned()),
        |path| {
            fs::read_to_string(path).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        },
    )?;
    serde_json::from_str(&json).map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
}

fn parse_allowed_targets(values: &[String]) -> Vec<AllowedNetworkTarget> {
    values
        .iter()
        .map(String::as_str)
        .filter(|target| !target.trim().is_empty())
        .enumerate()
        .map(|(index, target)| {
            let target = target.trim();
            let host = target.strip_prefix("*.").map_or_else(
                || HostMatch::Exact {
                    host: target.to_ascii_lowercase(),
                },
                |domain| HostMatch::DomainSuffix {
                    domain: domain.to_ascii_lowercase(),
                },
            );
            AllowedNetworkTarget {
                id: format!("cli.allowed-{index}"),
                host,
                ports: Vec::new(),
            }
        })
        .collect()
}

fn print_surface_summary(
    engine: &Engine,
    surface: &apiaxess_api_model::UnifiedApiSurface,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = engine
        .session_status()
        .map_err(|diagnostic| cli_diagnostic_error(&diagnostic))?;
    println!("session: {}", status.session_id);
    println!("session artifact: {}", status.artifact_path);
    println!(
        "pipeline: {} ({})",
        surface.assembly_run_id,
        status
            .analysis_pipeline
            .as_ref()
            .map_or("completed", |pipeline| pipeline.status.as_str())
    );
    println!("endpoints: {}", surface.surface.endpoints.len());
    println!(
        "protocol operations: {}",
        surface.surface.protocol_operations.len()
    );
    println!("loose findings: {}", surface.surface.loose_findings.len());
    println!("signers: {}", surface.surface.signers.len());
    println!(
        "coverage: {} endpoints, {} confirmed, {} inferred, {} static-only; handoffs {} open / {} total",
        surface.confidence.coverage.endpoint_count,
        surface.confidence.coverage.confirmed_endpoint_count,
        surface.confidence.coverage.inferred_endpoint_count,
        surface.confidence.coverage.static_only_endpoint_count,
        surface.confidence.coverage.open_handoff_count,
        surface.confidence.coverage.handoff_count
    );
    println!("diagnostics: {}", surface.diagnostics.len());
    Ok(())
}

fn print_cli_diagnostic(diagnostic: &Diagnostic) {
    eprintln!(
        "diagnostic [{} / {:?}] what={} why={} fix={}",
        diagnostic.id,
        diagnostic.severity,
        compact_cli_text(&diagnostic.what),
        compact_cli_text(&diagnostic.why),
        compact_cli_text(&diagnostic.fix)
    );
}

fn compact_cli_text(value: &str) -> String {
    const MAX_LENGTH: usize = 600;
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if value.len() <= MAX_LENGTH {
        return value;
    }
    let mut compact = value;
    compact.truncate(MAX_LENGTH);
    compact.push_str("...");
    compact
}

fn cli_diagnostic_error(diagnostic: &Diagnostic) -> std::io::Error {
    print_cli_diagnostic(diagnostic);
    diagnostic_error(diagnostic)
}

struct WorkbenchRuntime {
    engine: Engine,
    proxy: ProxyCore,
    proxy_address: SocketAddr,
    ca: SessionCa,
    store: Arc<TrafficStore>,
    session_runtime: Arc<SessionRuntime>,
    checkpoint_task: CheckpointTask,
}

impl WorkbenchRuntime {
    async fn start_with_artifact(
        engine: Engine,
        proxy_address: SocketAddr,
        artifact_path: Option<PathBuf>,
    ) -> Result<Self, Diagnostic> {
        Self::start_with_proxy_and_artifact(engine, proxy_address, ProxyCore::new(), artifact_path)
            .await
    }

    async fn start_with_proxy_and_artifact(
        engine: Engine,
        proxy_address: SocketAddr,
        proxy: ProxyCore,
        artifact_path: Option<PathBuf>,
    ) -> Result<Self, Diagnostic> {
        let now = Utc::now();
        let session_runtime = if let Some(path) = artifact_path {
            Arc::new(SessionRuntime::open(&path, &Engine::session_store_root())?)
        } else {
            let mut session = runtime_session(now)?;
            if session.lifecycle() == SessionLifecycle::Created {
                session.activate(now)?;
            }
            let store = runtime_store(&session)?;
            let artifact = store.root().join("session.json");
            Arc::new(SessionRuntime::new(session, store, artifact))
        };
        Self::start_with_runtime(engine, proxy_address, proxy, session_runtime).await
    }

    #[cfg(test)]
    async fn start_with_components(
        engine: Engine,
        proxy_address: SocketAddr,
        proxy: ProxyCore,
        mut session: Session,
        store: Arc<TrafficStore>,
        artifact_path: Option<PathBuf>,
        now: chrono::DateTime<Utc>,
    ) -> Result<Self, Diagnostic> {
        if session.lifecycle() == SessionLifecycle::Created {
            session.activate(now)?;
        }
        let artifact_path = artifact_path.unwrap_or_else(|| store.root().join("session.json"));
        let session_runtime = Arc::new(SessionRuntime::new(
            session,
            Arc::clone(&store),
            artifact_path,
        ));
        Self::start_with_runtime(engine, proxy_address, proxy, session_runtime).await
    }

    async fn start_with_runtime(
        engine: Engine,
        proxy_address: SocketAddr,
        mut proxy: ProxyCore,
        session_runtime: Arc<SessionRuntime>,
    ) -> Result<Self, Diagnostic> {
        let store = session_runtime.store();
        engine.attach_session_runtime(Arc::clone(&session_runtime))?;
        let checkpoint_task = CheckpointTask::start(engine.clone());
        let session = session_runtime.session_snapshot()?;

        let ca = SessionCa::generate()?;
        engine.configure_browser_ca(ca.clone());
        let live = engine.live_workbench();
        let bound_address = proxy
            .start_with_intercept(
                &session,
                proxy_address,
                ca.clone(),
                live.clone(),
                live.intercept_controller(),
            )
            .await?;
        // The proxy is the embedded hudsucker backend (compiled in), so its
        // health is always available; no external backend to probe or report.
        engine.set_proxy_health(proxy.health().await);
        engine.set_proxy_address(bound_address);
        let sender = Arc::new(ProxyResendSender::new(bound_address, ca.clone()));
        engine.attach_resend_sender(sender);
        engine.set_fuzzer_ffuf_proxy(bound_address);

        Ok(Self {
            engine,
            proxy,
            proxy_address: bound_address,
            ca,
            store,
            session_runtime,
            checkpoint_task,
        })
    }

    async fn shutdown(mut self) -> Result<(), Diagnostic> {
        self.checkpoint_task.stop().await;
        // Revert any device provisioning done via the C5 accept gate (removes the
        // installed session CA + reverse tunnels) before the rest of teardown.
        for diagnostic in self.engine.teardown_provisioned_devices() {
            report_startup_diagnostic(&diagnostic);
        }
        // Stop the GUI Android target emulator (Phase D1) if one was launched this
        // session, so its process is not left running after shutdown.
        for diagnostic in self.engine.teardown_android_target() {
            report_startup_diagnostic(&diagnostic);
        }
        let trust_result = self.engine.teardown_browser_trust();
        let proxy_result = self.proxy.shutdown().await;
        let save_result = self.session_runtime.save();
        self.engine.live_workbench().close();
        let session_result = self.session_runtime.close();
        trust_result?;
        proxy_result?;
        save_result?;
        session_result
    }
}

fn runtime_store(session: &Session) -> Result<Arc<TrafficStore>, Diagnostic> {
    // The live workbench session is a real session (session.json + audit trail),
    // so it must land in the same durable per-user data root as resumed sessions
    // — surviving reboots and Windows' periodic %TEMP% cleanup — not env::temp_dir.
    // `Engine::session_store_root()` honors APIAXESS_WORKBENCH_STORE_DIR first.
    let root = Engine::session_store_root();
    let session_root = TrafficStore::session_root(&root, session.id().as_str());
    if env::var_os("APIAXESS_SESSION_ID").is_some() && session_root.exists() {
        let mut context = DiagnosticContext::new();
        context.insert(
            "session_id".to_owned(),
            DiagnosticValue::String(session.id().as_str().to_owned()),
        );
        context.insert(
            "store_path".to_owned(),
            DiagnosticValue::String(session_root.display().to_string()),
        );
        return Err(catalogue::PROXY_SESSION_ID_COLLISION.instantiate(context));
    }
    TrafficStore::open(&root, session.id().as_str()).map(Arc::new)
}

fn runtime_session(now: chrono::DateTime<Utc>) -> Result<Session, Diagnostic> {
    let session_id = env::var("APIAXESS_SESSION_ID").map_or_else(
        |_| apiaxess_engine_shell::fresh_session_id().map(|id| id.as_str().to_owned()),
        Ok,
    )?;
    let session_id = SessionId::new(session_id)?;
    let target_type =
        env::var("APIAXESS_TARGET_TYPE").unwrap_or_else(|_| "local-workbench".to_owned());
    let target_value =
        env::var("APIAXESS_TARGET_ID").unwrap_or_else(|_| session_id.as_str().to_owned());
    new_runtime_session(
        session_id,
        target_type,
        target_value,
        allowed_targets(),
        now,
    )
}

fn startup_artifact(arguments: &[String]) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    let cli_path = arguments
        .iter()
        .position(|argument| argument == "--open" || argument == "open")
        .map(|index| {
            arguments
                .get(index + 1)
                .map(PathBuf::from)
                .ok_or_else(|| "--open requires a session artifact path".to_owned())
        })
        .transpose()?;
    Ok(cli_path.or_else(|| env::var_os("APIAXESS_SESSION_FILE").map(PathBuf::from)))
}

fn new_runtime_session(
    session_id: SessionId,
    target_type: String,
    target_value: String,
    allowed_targets: Vec<AllowedNetworkTarget>,
    now: chrono::DateTime<Utc>,
) -> Result<Session, Diagnostic> {
    let scope = EngagementScope {
        declared_at: now,
        target: TargetIdentity {
            target_type,
            primary: TargetIdentifier {
                kind: "session.id".to_owned(),
                value: target_value,
            },
            aliases: Vec::new(),
        },
        allowed_targets,
    };
    scope.validate()?;
    Ok(Session::new(
        session_id,
        scope,
        ApiDocument::new(ApiSurface {
            provenance: ProvenanceRegistry::default(),
            endpoints: Vec::new(),
            protocol_operations: Vec::new(),
            loose_findings: Vec::new(),
            signers: Vec::new(),
        }),
        now,
    ))
}

fn allowed_targets() -> Vec<AllowedNetworkTarget> {
    env::var("APIAXESS_ALLOWED_TARGETS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .enumerate()
        .map(|(index, target)| {
            let host = target.strip_prefix("*.").map_or_else(
                || HostMatch::Exact {
                    host: target.to_ascii_lowercase(),
                },
                |domain| HostMatch::DomainSuffix {
                    domain: domain.to_ascii_lowercase(),
                },
            );
            AllowedNetworkTarget {
                id: format!("runtime.allowed-{index}"),
                host,
                ports: Vec::new(),
            }
        })
        .collect()
}

fn loopback_address(variable: &str, default: &str) -> Result<SocketAddr, Diagnostic> {
    let configured = env::var(variable).unwrap_or_else(|_| default.to_owned());
    let parsed = configured
        .parse::<SocketAddr>()
        .map_err(|error| address_diagnostic(variable, &configured, &error.to_string()))?;
    if !parsed.ip().is_loopback() {
        return Err(address_diagnostic(
            variable,
            &configured,
            "the address is not loopback",
        ));
    }
    Ok(parsed)
}

fn address_diagnostic(variable: &str, address: &str, reason: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "configuration".to_owned(),
        DiagnosticValue::String(variable.to_owned()),
    );
    context.insert(
        "address".to_owned(),
        DiagnosticValue::String(address.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(reason.to_owned()),
    );
    let mut diagnostic = catalogue::PROXY_BACKEND_START_FAILED.instantiate(context);
    diagnostic.why =
        format!("`{variable}` is not a valid loopback socket address: {reason}").into_boxed_str();
    diagnostic.fix = format!(
        "Set `{variable}` to a free loopback address such as `{default}` and restart APIaxess.",
        default = if variable == "APIAXESS_GUI_ADDRESS" {
            DEFAULT_GUI_ADDRESS
        } else {
            DEFAULT_PROXY_ADDRESS
        }
    )
    .into_boxed_str();
    diagnostic
}

fn report_startup_diagnostic(diagnostic: &Diagnostic) {
    error!(
        diagnostic_id = %diagnostic.id,
        what = %diagnostic.what,
        why = %diagnostic.why,
        fix = %diagnostic.fix,
        context = ?diagnostic.context,
        "workbench startup or shutdown failed"
    );
}

fn default_ca_state_path() -> PathBuf {
    env::var_os("APIAXESS_CA_STATE_LOG").map_or_else(
        || env::temp_dir().join("apiaxess-ca-state.json"),
        PathBuf::from,
    )
}

fn purge_cas(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = CaStateLog::load(path).map_err(|diagnostic| diagnostic_error(&diagnostic))?;
    let removed_system = state
        .purge_with(path, &FilesystemStorePurger)
        .map_err(|diagnostic| diagnostic_error(&diagnostic))?;
    let removed_browser = state
        .purge_browser_profiles(path)
        .map_err(|diagnostic| diagnostic_error(&diagnostic))?;
    println!(
        "purged {} APIaxess CA record(s) from {}",
        removed_system + removed_browser,
        path.display()
    );
    Ok(())
}

struct FilesystemStorePurger;

impl SystemStorePurger for FilesystemStorePurger {
    fn remove(&self, install: &SystemCaInstall) -> Result<(), Diagnostic> {
        let Some(path) = install.store_location.strip_prefix("file:") else {
            let mut context = DiagnosticContext::new();
            context.insert(
                "store_location".to_owned(),
                DiagnosticValue::String(install.store_location.clone()),
            );
            return Err(catalogue::PROXY_TRUST_PURGE_FAILED.instantiate(context));
        };
        fs::remove_file(path).map_err(|error| {
            let mut context = DiagnosticContext::new();
            context.insert("path".to_owned(), DiagnosticValue::String(path.to_owned()));
            context.insert(
                "error".to_owned(),
                DiagnosticValue::String(error.to_string()),
            );
            catalogue::PROXY_TRUST_PURGE_FAILED.instantiate(context)
        })
    }
}

fn diagnostic_error(diagnostic: &Diagnostic) -> std::io::Error {
    std::io::Error::other(diagnostic.to_string())
}

fn gui_directory() -> PathBuf {
    resolve_gui_directory(
        env::var_os("APIAXESS_GUI_DIR").map(PathBuf::from),
        env::current_exe().ok().as_deref(),
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../gui/dist"),
    )
}

fn resolve_gui_directory(
    configured: Option<PathBuf>,
    executable: Option<&Path>,
    development: &Path,
) -> PathBuf {
    if let Some(configured) = configured {
        return configured;
    }

    let installed = executable
        .and_then(Path::parent)
        .and_then(|binary_directory| {
            let portable = binary_directory.join("gui");
            if portable.join("index.html").is_file() {
                return Some(portable);
            }
            binary_directory
                .parent()
                .map(|install_root| install_root.join("share").join("apiaxess").join("gui"))
        })
        .filter(|candidate| candidate.join("index.html").is_file());
    installed.unwrap_or_else(|| development.to_path_buf())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use apiaxess_session::{
        ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AllowedNetworkTarget,
        AuditActor, HostMatch, SessionId,
    };
    use apiaxess_target_apk::ApkIntakeConfig;
    use apiaxess_workbench_proxy::{HudsuckerBackend, ProxyCore, ResendRequest};
    use apiaxess_workbench_store::{
        DelayPolicy, FuzzerAttackType, FuzzerConfig, FuzzerJobState, FuzzerMatchFilter,
        FuzzerPositionLocation, FuzzerSequenceStep, GrepConfig, PayloadPosition, PayloadSet,
        PayloadSource, RedirectPolicy, RetryPolicy, TrafficStore,
    };
    use chrono::Utc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        Engine, SessionRuntime, WorkbenchRuntime, new_runtime_session, parse_analyze_options,
        parse_export_options, resolve_gui_directory,
    };

    #[test]
    fn analyze_cli_parses_session_scope_and_output_options() {
        let arguments = [
            "fixtures/capstone/feeder-2.22.0-4050.apk",
            "--static-only",
            "--session",
            "session.json",
            "--output",
            "result.json",
            "--allow-target",
            "api.example.test",
            "--json",
        ]
        .map(str::to_owned);
        let options = parse_analyze_options(&arguments).expect("valid analyze options");
        assert_eq!(
            options.artifact_path.as_deref(),
            Some(Path::new("fixtures/capstone/feeder-2.22.0-4050.apk"))
        );
        assert_eq!(
            options.session_path.as_deref(),
            Some(Path::new("session.json"))
        );
        assert_eq!(
            options.output_path.as_deref(),
            Some(Path::new("result.json"))
        );
        assert_eq!(options.allow_targets, vec!["api.example.test"]);
        assert!(!options.dynamic);
        assert!(options.json);
    }

    #[test]
    fn export_cli_parses_multiple_formats_and_destination() {
        let arguments = [
            "session.json",
            "--format",
            "openapi",
            "--format",
            "sdk",
            "--out",
            "exports",
            "--json",
        ]
        .map(str::to_owned);
        let options = parse_export_options(&arguments).expect("valid export options");
        assert_eq!(
            options.session_path.as_deref(),
            Some(Path::new("session.json"))
        );
        assert_eq!(options.output_dir.as_deref(), Some(Path::new("exports")));
        assert_eq!(options.formats, vec!["openapi", "sdk"]);
        assert!(options.json);
    }

    #[test]
    fn packaged_gui_assets_are_resolved_relative_to_the_executable() {
        let root = temporary_path("packaged-gui");
        let binary = root.join("bin").join("apiaxess.exe");
        let installed_gui = root.join("share").join("apiaxess").join("gui");
        fs::create_dir_all(&installed_gui).expect("create installed GUI directory");
        fs::write(installed_gui.join("index.html"), b"installed").expect("write GUI entry point");

        let resolved = resolve_gui_directory(None, Some(&binary), Path::new("development-gui"));
        assert_eq!(resolved, installed_gui);

        fs::remove_dir_all(root).expect("remove packaged GUI fixture");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn assembled_runtime_connects_capture_store_resend_and_fuzzer() {
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream bind");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = upstream.accept().await.expect("upstream accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2_048];
                loop {
                    let read = socket.read(&mut buffer).await.expect("upstream read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .expect("upstream response");
            }
        });

        let store_root = temporary_path("assembled-runtime");
        let session_id = SessionId::new("session:assembled-runtime").expect("session ID");
        let now = Utc::now();
        let session = new_runtime_session(
            session_id.clone(),
            "local-workbench".to_owned(),
            session_id.as_str().to_owned(),
            vec![AllowedNetworkTarget {
                id: "test.loopback".to_owned(),
                host: HostMatch::Exact {
                    host: "127.0.0.1".to_owned(),
                },
                ports: Vec::new(),
            }],
            now,
        )
        .expect("runtime session");
        let store =
            Arc::new(TrafficStore::open(&store_root, session_id.as_str()).expect("traffic store"));
        let engine = Engine::new();
        let runtime = WorkbenchRuntime::start_with_components(
            engine.clone(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
            ProxyCore::with_backend(Box::new(HudsuckerBackend)),
            session,
            Arc::clone(&store),
            None,
            now,
        )
        .await
        .expect("assembled workbench starts");
        let proxy_address = runtime.proxy_address;
        let mut gui_capture_queue = engine.live_workbench().subscribe();

        let response = send_via_proxy(proxy_address, upstream_address, "/captured").await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
        let live_update = tokio::time::timeout(Duration::from_secs(2), gui_capture_queue.recv())
            .await
            .expect("GUI capture queue timeout")
            .expect("GUI capture queue remains open");
        assert_eq!(live_update.flows[0].id, 1);
        wait_for_flow_count(&store, 1).await;
        assert_eq!(engine.live_workbench().recent_summaries().len(), 1);
        let flow = engine
            .live_workbench()
            .durable_flow(1)
            .expect("durable flow query")
            .expect("captured flow");

        let resend = engine
            .resend()
            .create_from_flow(&flow)
            .expect("captured flow enters resend");
        let resend_request = ResendRequest {
            method: "GET".to_owned(),
            url: format!("http://{upstream_address}/repeated"),
            headers: Vec::new(),
            body: None,
        };
        engine
            .resend()
            .update_request(&resend.id, resend_request.clone())
            .expect("resend edit");
        let mut audited_session = runtime
            .session_runtime
            .session_snapshot()
            .expect("active session snapshot");
        let send_result = engine
            .resend()
            .send_in_session(&resend.id, &mut audited_session)
            .await
            .expect("resend sends through running proxy");
        runtime
            .session_runtime
            .replace_session(audited_session)
            .expect("persist resend audit state");
        assert_eq!(
            send_result
                .revision
                .response
                .as_ref()
                .map(|value| value.status),
            Some(200)
        );
        assert_eq!(
            store
                .resend_contexts()
                .expect("persisted resend contexts")[0]
                .history
                .len(),
            1
        );

        let mut fuzzer_request = resend_request;
        fuzzer_request.url = format!("http://{upstream_address}/fuzzer/FUZZ");
        let marker_start = fuzzer_request.url.find("FUZZ").expect("payload marker");
        let fuzzer = engine.fuzzer();
        let job = fuzzer
            .create(FuzzerConfig {
                base_request: fuzzer_request.clone(),
                positions: vec![PayloadPosition {
                    location: FuzzerPositionLocation::Url,
                    header_name: None,
                    start: marker_start,
                    end: marker_start + 4,
                    set_index: 0,
                }],
                payload_sets: vec![PayloadSet {
                    name: "fixture".to_owned(),
                    source: PayloadSource::SimpleList {
                        values: vec!["one".to_owned()],
                    },
                    processors: Vec::new(),
                    url_encode_chars: None,
                }],
                attack_type: FuzzerAttackType::Sniper,
                match_filter: FuzzerMatchFilter::default(),
                grep: GrepConfig::default(),
                concurrency: 1,
                delay: DelayPolicy::default(),
                retry: RetryPolicy::default(),
                redirect: RedirectPolicy::default(),
                connection_close: false,
                update_content_length: true,
                max_results: 1,
                auth_preflight: None,
                sequence: vec![FuzzerSequenceStep {
                    name: "send".to_owned(),
                    request: fuzzer_request,
                    extractors: Vec::new(),
                }],
                auto_calibrate: false,
            })
            .expect("fuzzer configuration");
        let mut audited_session = runtime
            .session_runtime
            .session_snapshot()
            .expect("active session snapshot");
        fuzzer
            .launch_in_session(&job.id, &mut audited_session)
            .expect("fuzzer launch");
        runtime
            .session_runtime
            .replace_session(audited_session)
            .expect("persist fuzzer launch audit state");
        let completed = wait_for_fuzzer(&fuzzer, &job.id).await;
        assert_eq!(completed.state, FuzzerJobState::Completed);
        assert_eq!(
            completed.results[0]
                .response
                .as_ref()
                .map(|response| response.status),
            Some(200)
        );
        assert_eq!(
            store.fuzzer_jobs().expect("persisted fuzzer jobs")[0]
                .results
                .len(),
            1
        );

        let mut audited_session = runtime
            .session_runtime
            .session_snapshot()
            .expect("active session snapshot");
        for result in &completed.results {
            fuzzer
                .record_result_in_session(&job.id, result.ordinal, &mut audited_session)
                .expect("record fuzzer audit result");
        }
        let outside_at = Utc::now();
        audited_session
            .record_action(ActionRecordInput {
                id: "test.outside-scope".to_owned(),
                occurred_at: outside_at,
                actor: AuditActor::User,
                action: ActionDescriptor {
                    kind: "workbench.test.outside-scope".to_owned(),
                    summary: "Recorded an out-of-scope test action".to_owned(),
                },
                target: ActionTarget::Network {
                    host: "outside.example.test".to_owned(),
                    port: None,
                },
                outcome: ActionOutcome::Completed,
                diagnostics: Vec::new(),
            })
            .expect("out-of-scope action remains auditable");
        let outside_record = audited_session
            .audit_trail()
            .last()
            .expect("outside-scope audit record");
        assert_eq!(
            outside_record.scope.disposition,
            apiaxess_session::ScopeDisposition::OutsideDeclaredScope
        );
        assert!(
            outside_record
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "scope.outside-declaration")
        );
        runtime
            .session_runtime
            .replace_session(audited_session)
            .expect("persist complete audit state");

        let artifact_path = PathBuf::from(
            runtime
                .session_runtime
                .status()
                .expect("runtime status")
                .artifact_path,
        );
        upstream_task.await.expect("upstream task");
        runtime.shutdown().await.expect("clean runtime shutdown");
        assert!(tokio::net::TcpListener::bind(proxy_address).await.is_ok());

        let resumed = SessionRuntime::open(&artifact_path, &store_root).expect("resume artifact");
        assert_eq!(resumed.session_id(), session_id.as_str());
        let resumed_engine = Engine::new();
        resumed_engine
            .attach_session_runtime(Arc::new(resumed))
            .expect("attach resumed session");
        assert_eq!(
            resumed_engine
                .live_workbench()
                .durable_summaries()
                .expect("resumed flow summaries")
                .expect("resumed store")
                .len(),
            3
        );
        assert_eq!(resumed_engine.resend().list().len(), 1);
        assert_eq!(resumed_engine.fuzzer().list().len(), 1);
        let audit = resumed_engine.session_audit().expect("resumed audit trail");
        assert!(
            audit
                .iter()
                .any(|record| record.action.kind == "workbench.resend.send")
        );
        assert!(
            audit
                .iter()
                .any(|record| record.action.kind == "workbench.fuzzer.launch")
        );
        assert!(
            audit
                .iter()
                .any(|record| record.action.kind == "workbench.fuzzer.send")
        );
        assert!(audit.iter().any(|record| {
            record.id == "test.outside-scope"
                && record.scope.disposition
                    == apiaxess_session::ScopeDisposition::OutsideDeclaredScope
                && record
                    .diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.id.as_ref() == "scope.outside-declaration")
        }));
        assert_eq!(
            resumed_engine
                .session_status()
                .expect("resumed status")
                .session_id,
            session_id.as_str()
        );
        drop(resumed_engine);
        drop(fuzzer);
        drop(engine);
        drop(store);
        fs::remove_dir_all(store_root).expect("remove test store");
    }

    #[test]
    #[ignore = "real Feeder static analysis is long-running and requires apktool/jadx"]
    fn assembled_product_runs_real_apk_through_the_durable_pipeline() {
        let fixture = env::var_os("APIAXESS_PIPELINE_FIXTURE")
            .map_or_else(
                || {
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../fixtures/capstone/feeder-2.22.0-4050.apk")
                },
                PathBuf::from,
            )
            .canonicalize()
            .expect("pipeline APK fixture");
        let root = temporary_path("assembled-pipeline");
        let store = Arc::new(
            TrafficStore::open(&root, "session:assembled-pipeline").expect("traffic store"),
        );
        let now = Utc::now();
        let mut session = new_runtime_session(
            SessionId::new("session:assembled-pipeline").expect("session ID"),
            "android.apk".to_owned(),
            "feeder-2.22.0-4050".to_owned(),
            Vec::new(),
            now,
        )
        .expect("runtime session");
        session.activate(now).expect("activate session");
        let artifact_path = store.root().join("session.json");
        let runtime = Arc::new(SessionRuntime::new(
            session,
            Arc::clone(&store),
            artifact_path.clone(),
        ));
        let engine = Engine::new();
        engine
            .attach_session_runtime(Arc::clone(&runtime))
            .expect("attach session runtime");

        // Uses the bundled, host-independent toolchain by default; a developer
        // running this ignored test can point at a staged install with the
        // APIAXESS_JAVA/APIAXESS_APKTOOL/APIAXESS_JADX overrides.
        let intake = ApkIntakeConfig {
            output_root: root.join("intake"),
            ..ApkIntakeConfig::default()
        };
        let config = apiaxess_engine_shell::PipelineConfig::new(fixture.clone())
            .expect("pipeline config")
            .with_run_id("pipeline:assembled-feeder")
            .expect("pipeline run ID")
            .with_intake_config(intake);
        let report = engine.run_pipeline(&config).expect("assembled pipeline");

        assert_eq!(
            report.progress.status,
            apiaxess_engine_shell::PipelineRunStatus::Completed
        );
        report
            .unified_surface
            .validate()
            .expect("unified surface validates");
        assert!(report.document.unified_surface.is_some());
        let saved = runtime.save().expect("save completed pipeline");
        assert_eq!(saved.analysis_pipeline.unwrap().status, "completed");
        let resumed = SessionRuntime::open(&artifact_path, &root).expect("resume pipeline");
        let resumed_session = resumed.session_snapshot().expect("resumed session");
        assert!(resumed_session.api_document().unified_surface.is_some());
        assert_eq!(
            resumed_session
                .analysis_pipeline_state()
                .expect("pipeline state")
                .status,
            "completed"
        );
        assert!(
            resumed
                .audit_trail()
                .expect("pipeline audit")
                .iter()
                .any(|record| record.action.kind == "analysis.pipeline.completed")
        );
        drop(resumed);
        drop(runtime);
        drop(engine);
        drop(store);
        fs::remove_dir_all(root).expect("remove assembled pipeline store");
    }

    async fn send_via_proxy(
        proxy_address: SocketAddr,
        upstream_address: SocketAddr,
        path: &str,
    ) -> Vec<u8> {
        let mut socket = tokio::net::TcpStream::connect(proxy_address)
            .await
            .expect("connect proxy");
        let request = format!(
            "GET http://{upstream_address}{path} HTTP/1.1\r\nHost: {upstream_address}\r\nConnection: close\r\n\r\n"
        );
        socket
            .write_all(request.as_bytes())
            .await
            .expect("write proxy request");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response))
            .await
            .expect("proxy response timeout")
            .expect("read proxy response");
        response
    }

    async fn wait_for_flow_count(store: &TrafficStore, minimum: usize) {
        for _ in 0..100 {
            if store.summaries().expect("flow summaries").len() >= minimum {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("traffic store did not reach {minimum} flow(s)");
    }

    async fn wait_for_fuzzer(
        fuzzer: &Arc<apiaxess_workbench_proxy::FuzzerWorkbench>,
        job_id: &str,
    ) -> apiaxess_workbench_store::FuzzerJob {
        for _ in 0..200 {
            let job = fuzzer.get(job_id).expect("fuzzer job");
            if matches!(
                job.state,
                FuzzerJobState::Completed | FuzzerJobState::Failed
            ) {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("fuzzer job did not complete");
    }

    fn temporary_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("apiaxess-{label}-{nonce}"))
    }
}
