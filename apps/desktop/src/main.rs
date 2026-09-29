//! `APIaxess` native desktop shell.
//!
//! A thin Tauri wrapper that gives the branded web GUI its own native window and
//! double-click launch. The frontend and backend are unchanged: this shell
//! starts the local engine (the same `apiaxess` binary, in its default
//! HTTP-server mode) as a managed child, waits for it to become ready, and points
//! a native webview at `http://127.0.0.1:<port>/` — the engine's own origin, so
//! the GUI's same-origin `/api/v1` calls and its exact-origin `WebSocket` auth keep
//! working. Closing the window stops the engine cleanly (the child runs inside a
//! Job Object / process group, so it can never be orphaned).
//!
//! On first launch a small chooser asks whether to open as a native desktop app
//! or in the user's browser; the choice is remembered (change it with `--choose`
//! or `APIAXESS_LAUNCH_MODE`). Browser mode starts the same engine, opens the
//! default browser at its URL, and keeps a small control window that stops the
//! engine when closed. The pure-headless server (no window, no browser) is
//! `apiaxess serve` in the engine itself.

// Release builds are GUI apps: no attached console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use apiaxess_external_tools::{ManagedProcess, ManagedProcessCommand};

/// Owns the engine child so it can be torn down when the app exits.
type EngineSlot = Arc<Mutex<Option<ManagedProcess>>>;

/// Set once the app itself is stopping the engine, so the supervisor never
/// mistakes a deliberate shutdown for a crash.
static ENGINE_STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Most restarts of a crashed engine within [`RESTART_WINDOW`] before giving
/// up (the GUI then shows its "engine stopped" state instead of a spinner).
const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(300);

/// How the shell presents the workbench.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum LaunchMode {
    /// The branded GUI in this app's own native window.
    Desktop,
    /// The engine plus the user's own browser; a small control window stays open.
    Browser,
}

impl LaunchMode {
    /// Parses a mode name from an env override or config value.
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "desktop" | "app" | "native" => Some(Self::Desktop),
            "browser" | "web" => Some(Self::Browser),
            _ => None,
        }
    }
}

/// The remembered launch choice, persisted between runs.
#[derive(serde::Serialize, serde::Deserialize)]
struct LaunchConfig {
    mode: LaunchMode,
}

fn main() {
    // Windows: guarantee a webview exists before we ever try to create a window,
    // so a machine without the WebView2 runtime installs it rather than showing a
    // blank window.
    #[cfg(windows)]
    ensure_webview2();

    // An update scheduled for when the last session ended, if the app did not
    // get to install it on the way out: install it now, before anything runs,
    // and come back as the new version.
    install_pending_update_and_exit();

    let force_choose = std::env::args()
        .skip(1)
        .any(|argument| argument == "--choose");
    let mode = resolve_launch_mode(force_choose);

    let gui_port = resolve_port("APIAXESS_GUI_ADDRESS");
    let proxy_port = resolve_port("APIAXESS_PROXY_ADDRESS");
    let engine_url = format!("http://127.0.0.1:{gui_port}/");

    let engine = match spawn_engine(gui_port, proxy_port) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("APIaxess: could not start the local engine: {error}");
            std::process::exit(1);
        }
    };
    let engine_slot: EngineSlot = Arc::new(Mutex::new(Some(engine)));
    {
        let supervised = Arc::clone(&engine_slot);
        std::thread::spawn(move || supervise_engine(&supervised, gui_port, proxy_port));
    }

    // Wait for the engine's readiness endpoint before showing the window, so the
    // first paint is the ready GUI, not a connection error.
    if !wait_for_ready(gui_port, Duration::from_secs(90)) {
        eprintln!("APIaxess: the local engine did not become ready in time.");
    }

    // Browser mode: open the user's default browser at the engine; the small
    // control window built below keeps the engine alive and stops it on close.
    if mode == LaunchMode::Browser
        && let Err(error) = open::that(&engine_url)
    {
        eprintln!(
            "APIaxess: could not open the browser automatically ({error}); open {engine_url} yourself."
        );
    }

    let setup_url = engine_url.clone();
    let exit_slot = Arc::clone(&engine_slot);
    let close_slot = Arc::clone(&engine_slot);
    tauri::Builder::default()
        // Stop the engine the moment the window is asked to close, so it is gone
        // immediately regardless of how long the webview itself takes to tear
        // down. The `Exit` handler below is the backstop for any other exit path.
        .on_window_event(move |_window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                stop_engine(&close_slot);
            }
        })
        .setup(move |app| {
            match mode {
                LaunchMode::Desktop => {
                    let url: tauri::Url = setup_url
                        .parse()
                        .expect("engine URL is a valid loopback URL");
                    tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(url))
                        .title("APIaxess")
                        .inner_size(1440.0, 920.0)
                        // The GUI's responsive ladder is designed down to a
                        // 360px viewport, so the window is free to go as narrow
                        // as an operator wants to dock it. The floor is only
                        // there to stop a resize that would clip the header.
                        .min_inner_size(480.0, 540.0)
                        // The webview paints white until the engine's first
                        // frame arrives; on the Ink ground that reads as a
                        // flash. Matching the window to the theme removes it.
                        .background_color(tauri::window::Color(0x0d, 0x0d, 0x0d, 0xff))
                        // Set the window/taskbar/title-bar icon explicitly to the
                        // identity-kit mark, so it never falls back to a generic
                        // placeholder regardless of how the exe resource is built.
                        .icon(app_window_icon()?)?
                        .build()?;
                }
                LaunchMode::Browser => {
                    let injected =
                        serde_json::to_string(&setup_url).unwrap_or_else(|_| "\"\"".to_owned());
                    tauri::WebviewWindowBuilder::new(
                        app,
                        "main",
                        tauri::WebviewUrl::App("control.html".into()),
                    )
                    .title("APIaxess — running in your browser")
                    .inner_size(540.0, 460.0)
                    .min_inner_size(380.0, 340.0)
                    .background_color(tauri::window::Color(0x0d, 0x0d, 0x0d, 0xff))
                    .icon(app_window_icon()?)?
                    .initialization_script(format!("window.__APIAXESS_URL__ = {injected};"))
                    .build()?;
                }
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the APIaxess desktop shell")
        .run(move |_handle, event| {
            if let tauri::RunEvent::Exit = event {
                stop_engine(&exit_slot);
                // "Install when this session ends": the session just did.
                install_deferred_update();
            }
        });
}

/// Starts the detached installer helper for a staged update (re-verifying the
/// MSI's SHA-256 first). It waits for this shell to exit, installs, and, when
/// `relaunch` is set, starts the new version reopening the handoff's session.
/// The handoff is consumed either way, so a failing install is tried once.
fn start_update_install(
    pending: &apiaxess_updater::InstallHandoff,
    relaunch: bool,
) -> std::io::Result<()> {
    let dir = apiaxess_updater::handoff::updates_dir();
    let executable = relaunch.then(std::env::current_exe).transpose()?;
    apiaxess_updater::handoff::launch_msi_installer(
        pending,
        std::process::id(),
        &dir,
        executable.as_deref(),
    )
}

/// On launch: installs a staged update left over from the last session and
/// exits (the helper relaunches the new version).
fn install_pending_update_and_exit() {
    if !cfg!(windows) {
        return;
    }
    let Some(pending) =
        apiaxess_updater::handoff::take_handoff(&apiaxess_updater::handoff::updates_dir())
    else {
        return;
    };
    match start_update_install(&pending, true) {
        Ok(()) => std::process::exit(0),
        Err(error) => report_update_failure(&pending.version, &error),
    }
}

/// On exit: installs an update scheduled for when the session ends. No
/// relaunch; the operator closed the app.
fn install_deferred_update() {
    if !cfg!(windows) {
        return;
    }
    let dir = apiaxess_updater::handoff::updates_dir();
    if !apiaxess_updater::handoff::read_handoff(&dir)
        .is_some_and(|pending| pending.when == apiaxess_updater::InstallWhen::Deferred)
    {
        return;
    }
    if let Some(pending) = apiaxess_updater::handoff::take_handoff(&dir)
        && let Err(error) = start_update_install(&pending, false)
    {
        report_update_failure(&pending.version, &error);
    }
}

/// Says why a staged update did not install; the app carries on as it is.
fn report_update_failure(version: &str, error: &std::io::Error) {
    eprintln!("APIaxess: the update to {version} was not installed: {error}");
    let _ = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title("APIaxess update")
        .set_description(format!(
            "The update to {version} was not installed:\n\n{error}\n\nAPIaxess will keep running the current version. You can download the update again from Settings."
        ))
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
}

/// The app's window icon — the identity-kit mark, embedded from the same PNG the
/// installer and bundle use, so the taskbar, title bar, and Alt-Tab all show the
/// real mark at a crisp size rather than any generic default.
fn app_window_icon() -> tauri::Result<tauri::image::Image<'static>> {
    tauri::image::Image::from_bytes(include_bytes!("../icons/128x128@2x.png"))
}

/// Determines the launch mode: an explicit env override wins, then the remembered
/// choice, then a first-run prompt (also forced by `--choose`) whose result is
/// remembered so the prompt does not recur.
fn resolve_launch_mode(force_choose: bool) -> LaunchMode {
    if let Some(value) = std::env::var_os("APIAXESS_LAUNCH_MODE")
        && let Some(mode) = value.to_str().and_then(LaunchMode::parse)
    {
        return mode;
    }
    if !force_choose && let Some(mode) = load_launch_mode() {
        return mode;
    }
    let chosen = prompt_launch_mode();
    save_launch_mode(chosen);
    chosen
}

/// Shows the small native launch chooser and returns the picked mode (defaulting
/// to the native desktop experience if the dialog is dismissed).
fn prompt_launch_mode() -> LaunchMode {
    let result = rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Info)
        .set_title("APIaxess")
        .set_description(
            "How would you like to open APIaxess?\n\n\
             •  Desktop app — its own native window\n\
             •  Open in browser — start the engine and use your browser\n\n\
             You can change this later with the --choose flag.",
        )
        .set_buttons(rfd::MessageButtons::OkCancelCustom(
            "Desktop app".to_owned(),
            "Open in browser".to_owned(),
        ))
        .show();
    match result {
        rfd::MessageDialogResult::Custom(label)
            if label.to_ascii_lowercase().contains("browser") =>
        {
            LaunchMode::Browser
        }
        _ => LaunchMode::Desktop,
    }
}

/// Path of the remembered launch-mode config, beside the engine's durable data.
fn launch_config_path() -> Option<PathBuf> {
    Some(apiaxess_install_layout::data_dir()?.join("launch-mode.json"))
}

/// Loads the remembered launch mode, if any.
fn load_launch_mode() -> Option<LaunchMode> {
    let bytes = std::fs::read(launch_config_path()?).ok()?;
    serde_json::from_slice::<LaunchConfig>(&bytes)
        .ok()
        .map(|config| config.mode)
}

/// Persists the launch mode so the chooser is not shown on every launch.
fn save_launch_mode(mode: LaunchMode) {
    let Some(path) = launch_config_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(&LaunchConfig { mode }) {
        let _ = std::fs::write(path, bytes);
    }
}

/// Watches the engine child and restarts it, on the same loopback ports, when
/// it exits on its own, so the window (which keeps reconnecting) recovers by
/// itself. Bounded, so an engine that cannot stay up is not respawned forever.
fn supervise_engine(slot: &EngineSlot, gui_port: u16, proxy_port: u16) {
    let mut restarts: Vec<Instant> = Vec::new();
    loop {
        std::thread::sleep(Duration::from_secs(1));
        if ENGINE_STOPPING.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let exited = match slot.lock() {
            Ok(mut guard) => match guard.as_mut() {
                Some(child) => child.try_wait().ok().flatten(),
                None => return,
            },
            Err(_) => return,
        };
        let Some(status) = exited else {
            continue;
        };
        if ENGINE_STOPPING.load(std::sync::atomic::Ordering::SeqCst) {
            continue;
        }
        // The operator chose "Restart and update": the engine saved the
        // session, staged the verified MSI, and exited on purpose.
        if status.code() == Some(apiaxess_updater::INSTALL_EXIT_CODE)
            && let Some(pending) =
                apiaxess_updater::handoff::take_handoff(&apiaxess_updater::handoff::updates_dir())
        {
            match start_update_install(&pending, true) {
                Ok(()) => {
                    ENGINE_STOPPING.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::process::exit(0);
                }
                Err(error) => report_update_failure(&pending.version, &error),
            }
        }
        restarts.retain(|at| at.elapsed() < RESTART_WINDOW);
        if restarts.len() >= MAX_RESTARTS {
            eprintln!("APIaxess: the local engine keeps stopping; not restarting it again.");
            return;
        }
        restarts.push(Instant::now());
        eprintln!("APIaxess: the local engine stopped unexpectedly; restarting it.");
        // Reopen the session it was running (up to its last save).
        let resume = session_to_resume();
        match spawn_engine_with(gui_port, proxy_port, resume.as_deref()) {
            Ok(child) => {
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(child);
                }
            }
            Err(error) => {
                eprintln!("APIaxess: could not restart the local engine: {error}");
                return;
            }
        }
    }
}

/// Terminates the engine child (and its process tree) if it is still running.
fn stop_engine(slot: &EngineSlot) {
    ENGINE_STOPPING.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut guard) = slot.lock()
        && let Some(mut child) = guard.take()
    {
        // A graceful stop first: the engine's own teardown reaps the capture
        // Chromium, which leads a process group the group kill cannot reach.
        let _ = child.terminate(ENGINE_STOP_GRACE);
    }
}

/// How long a stopping engine gets to tear down before it is killed.
const ENGINE_STOP_GRACE: Duration = Duration::from_secs(10);

/// Spawns the local engine in its default HTTP-server mode, bound to the chosen
/// loopback ports, inside the shared process boundary (Job Object on Windows,
/// process group on Unix) so it is torn down with this shell.
/// Per-launch file the engine writes the active session's artifact path to,
/// so a restarted engine can reopen that session.
fn active_session_pointer() -> PathBuf {
    std::env::temp_dir().join(format!(
        "apiaxess-active-session-{}.txt",
        std::process::id()
    ))
}

/// The session a crashed engine was running, if it saved one.
fn session_to_resume() -> Option<PathBuf> {
    let recorded = std::fs::read_to_string(active_session_pointer()).ok()?;
    let path = PathBuf::from(recorded.trim());
    path.is_file().then_some(path)
}

fn spawn_engine(gui_port: u16, proxy_port: u16) -> std::io::Result<ManagedProcess> {
    spawn_engine_with(gui_port, proxy_port, None)
}

fn spawn_engine_with(
    gui_port: u16,
    proxy_port: u16,
    resume: Option<&Path>,
) -> std::io::Result<ManagedProcess> {
    let binary = engine_binary();
    if !binary.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("engine binary not found at {}", binary.display()),
        ));
    }
    let mut command = ManagedProcessCommand::new(&binary);
    command.env("APIAXESS_GUI_ADDRESS", format!("127.0.0.1:{gui_port}"));
    command.env("APIAXESS_PROXY_ADDRESS", format!("127.0.0.1:{proxy_port}"));
    command.env("APIAXESS_ACTIVE_SESSION_POINTER", active_session_pointer());
    // Tells the engine an update install is this shell's to run (the engine
    // sits in this shell's Job Object and cannot outlive it).
    command.env("APIAXESS_DESKTOP_SHELL", "1");
    if let Some(session) = resume {
        command.env("APIAXESS_SESSION_FILE", session);
    }
    command.spawn()
}

/// Resolves the sibling engine binary from the installed layout (both the desktop
/// shell and the engine live in `bin/`), honoring an explicit override.
fn engine_binary() -> PathBuf {
    if let Some(configured) = std::env::var_os("APIAXESS_ENGINE_BIN") {
        return PathBuf::from(configured);
    }
    let name = if cfg!(windows) {
        "apiaxess.exe"
    } else {
        "apiaxess"
    };
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Resolves the port for a loopback address env var (`host:port`), honoring an
/// explicit non-zero port and otherwise reserving a free one. Lets an operator or
/// test pin ports while keeping zero-config the default.
fn resolve_port(env_key: &str) -> u16 {
    if let Some(value) = std::env::var_os(env_key)
        && let Some(port) = value
            .to_str()
            .and_then(|address| address.rsplit(':').next())
            .and_then(|port| port.parse::<u16>().ok())
        && port != 0
    {
        return port;
    }
    free_loopback_port()
}

/// Reserves a free loopback port by binding `:0` and reading the assigned port.
fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map_or(0, |address| address.port())
}

/// Polls the engine's readiness endpoint until it reports ready or the deadline
/// elapses.
fn wait_for_ready(port: u16, deadline: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < deadline {
        if engine_reports_ready(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// One readiness probe: a minimal HTTP GET of `/api/v1/system/status`, matching
/// the same endpoint the installed-product test and the GUI boot both poll.
fn engine_reports_ready(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = format!(
        "GET /api/v1/system/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.contains("\"state\":\"ready\"")
}

/// Ensures the Windows `WebView2` runtime is present, installing it from the
/// bundled Evergreen bootstrapper when it is not — so the app never opens to a
/// blank window on a machine that shipped without `WebView2`.
#[cfg(windows)]
fn ensure_webview2() {
    if webview2_runtime_present() {
        return;
    }
    let Some(bootstrapper) = bundled_webview2_bootstrapper() else {
        // Nothing bundled to install from; fall through and let Tauri surface its
        // own WebView2 guidance if the runtime really is absent.
        return;
    };
    let mut command = ManagedProcessCommand::new(&bootstrapper);
    command.arg("/silent");
    command.arg("/install");
    if let Ok(mut child) = command.spawn() {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(180) {
            match child.try_wait() {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    }
}

/// Detects the Evergreen `WebView2` runtime by its installed `msedgewebview2.exe`
/// under the per-machine or per-user `EdgeWebView\Application\<version>\` roots.
#[cfg(windows)]
fn webview2_runtime_present() -> bool {
    let application_roots = [
        std::env::var_os("ProgramFiles(x86)"),
        std::env::var_os("ProgramFiles"),
        std::env::var_os("LocalAppData"),
    ];
    for root in application_roots.into_iter().flatten() {
        let application = PathBuf::from(root)
            .join("Microsoft")
            .join("EdgeWebView")
            .join("Application");
        if let Ok(entries) = std::fs::read_dir(&application) {
            for entry in entries.flatten() {
                if entry.path().join("msedgewebview2.exe").is_file() {
                    return true;
                }
            }
        }
    }
    false
}

/// Resolves the bundled Evergreen bootstrapper staged next to the desktop shell.
#[cfg(windows)]
fn bundled_webview2_bootstrapper() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os("APIAXESS_WEBVIEW2_BOOTSTRAPPER") {
        let path = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    let candidate = std::env::current_exe()
        .ok()?
        .parent()?
        .join("MicrosoftEdgeWebview2Setup.exe");
    candidate.is_file().then_some(candidate)
}
