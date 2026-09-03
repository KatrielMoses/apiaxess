//! Hardened Frida instrumentation substrate for Phase 3.4 and later phases.
//!
//! This module intentionally knows nothing about certificate-pinning
//! techniques. It owns deployment, early process control, health evidence,
//! watchdog correlation, and session cleanup. Pinning and signing-recovery
//! payloads are callers of this substrate.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{
    ExternalToolRunner, ToolInvocationRequest, ToolProbe, ToolProbeRequest, ToolProcess,
    ToolProcessRequest, ToolRequirement, ToolVersion,
};

use crate::{SandboxCleanup, SandboxCommandOutput, SandboxControl, SandboxLease};

/// Whether the target is launched before hooks or attached after launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentationMode {
    /// Spawn-gated mode required for Application and native initialization.
    Spawn,
    /// Attach to an existing process by PID or package name.
    Attach {
        /// Optional process ID; `None` attaches by package name.
        pid: Option<u32>,
    },
}

/// Frida executable and session policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FridaSubstrateConfig {
    /// Host Frida CLI executable.
    pub frida_executable: String,
    /// Host Frida server binary.
    pub frida_server_path: PathBuf,
    /// Host Frida process-list executable.
    pub frida_ps_executable: String,
    /// Device path for the session server; callers may provide a concealed name.
    pub server_remote_path: String,
    /// Host address of the device-side frida-server to connect the embedded
    /// frida-core to explicitly (an `adb forward` endpoint), instead of relying
    /// on USB device enumeration — which mis-resolves a phantom device for an
    /// emulator on Linux. Standard `host:port` for `add_remote_device`.
    pub device_address: String,
    /// Time allowed for the initial substrate health gate.
    pub startup_timeout: Duration,
    /// Watchdog polling interval.
    pub watchdog_interval: Duration,
    /// Number of logcat lines inspected for crash correlation.
    pub logcat_lines: u32,
}

impl Default for FridaSubstrateConfig {
    fn default() -> Self {
        Self {
            frida_executable: "frida".to_owned(),
            frida_server_path: PathBuf::from("frida-server"),
            frida_ps_executable: "frida-ps".to_owned(),
            server_remote_path: "/data/local/tmp/.fs-session/frida-server".to_owned(),
            device_address: "127.0.0.1:27042".to_owned(),
            startup_timeout: Duration::from_secs(30),
            watchdog_interval: Duration::from_secs(2),
            logcat_lines: 200,
        }
    }
}

/// One substrate start/attach request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentationRequest {
    /// Active session ID.
    pub session_id: String,
    /// Active lease ID.
    pub lease_id: String,
    /// Android package name.
    pub package_name: String,
    /// Spawn or attach behavior.
    pub mode: InstrumentationMode,
    /// Payload script loaded at the earliest possible point.
    pub script: String,
    /// Parent for session-only host artifacts.
    pub workspace_root: Option<PathBuf>,
    /// Frida substrate configuration.
    pub config: FridaSubstrateConfig,
}

impl InstrumentationRequest {
    /// Creates a spawn-gated request with the standard early hooks.
    #[must_use]
    pub fn spawn(
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
        package_name: impl Into<String>,
        payload: impl Into<String>,
    ) -> Self {
        let package_name = package_name.into();
        Self {
            session_id: session_id.into(),
            lease_id: lease_id.into(),
            package_name: package_name.clone(),
            mode: InstrumentationMode::Spawn,
            script: generate_early_spawn_script(&package_name, &payload.into()),
            workspace_root: None,
            config: FridaSubstrateConfig::default(),
        }
    }

    /// Creates a spawn-gated request with the Phase 4.1 crypto payload.
    ///
    /// The payload is wrapped by the existing early substrate, so Java hooks
    /// and native module observation are installed before app initialization.
    #[must_use]
    pub fn spawn_crypto_capture(
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
        package_name: impl Into<String>,
    ) -> Self {
        let package_name = package_name.into();
        Self::spawn(
            session_id,
            lease_id,
            package_name.clone(),
            apiaxess_crypto_capture::frida_payload::generate(&package_name),
        )
    }
}

/// Health evidence collected from one substrate check.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct InstrumentationHealth {
    /// Frida server process and host IPC are healthy.
    pub server_ipc: bool,
    /// The target process is present.
    pub target_process: bool,
    /// Java class-loader probe succeeded.
    pub class_loader: bool,
    /// DEX enumeration probe succeeded.
    pub dex_resolution: bool,
    /// Script readiness marker was observed.
    pub script_ready: bool,
    /// Correlated crash text, if any.
    pub crash_evidence: Option<String>,
    /// Last check timestamp in monotonic milliseconds.
    pub checked_after_ms: u128,
}

impl InstrumentationHealth {
    /// Whether all substrate readiness gates are green.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.server_ipc
            && self.target_process
            && self.class_loader
            && self.dex_resolution
            && self.script_ready
            && self.crash_evidence.is_none()
    }
}

struct SubstrateState {
    control: Arc<dyn SandboxControl>,
    runner: Arc<dyn ExternalToolRunner>,
    frida: ToolProbe,
    frida_ps: ToolProbe,
    package_name: String,
    mode: InstrumentationMode,
    logcat_lines: u32,
    watchdog_interval: Duration,
    process: Mutex<Option<ToolProcess>>,
    auxiliary_processes: Mutex<Vec<ToolProcess>>,
    server_path: Mutex<Option<String>>,
    stop: AtomicBool,
    health: Mutex<InstrumentationHealth>,
    watchdog_diagnostics: Mutex<Vec<Diagnostic>>,
    watchdog: Mutex<Option<JoinHandle<()>>>,
    started_at: Instant,
}

/// A live, reusable Frida substrate session.
pub struct InstrumentationSession {
    state: Arc<SubstrateState>,
    workspace: PathBuf,
}

impl std::fmt::Debug for InstrumentationSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstrumentationSession")
            .field("package_name", &self.state.package_name)
            .field("mode", &self.state.mode)
            .field("workspace", &self.workspace)
            .field("health", &self.health())
            .finish()
    }
}

impl InstrumentationSession {
    /// Starts the server, launches/attaches the target, and passes the health gate.
    pub fn start(
        lease: &mut SandboxLease,
        runner: Arc<dyn ExternalToolRunner>,
        request: &InstrumentationRequest,
    ) -> Result<Self, Vec<Diagnostic>> {
        let workspace = session_workspace(request)?;
        let (frida, frida_ps) = probe_tools(&runner, request)?;
        let control = lease.control();
        let state = Arc::new(SubstrateState {
            control: Arc::clone(&control),
            runner,
            frida,
            frida_ps,
            package_name: request.package_name.clone(),
            mode: request.mode,
            logcat_lines: request.config.logcat_lines,
            watchdog_interval: request
                .config
                .watchdog_interval
                .max(Duration::from_millis(100)),
            process: Mutex::new(None),
            auxiliary_processes: Mutex::new(Vec::new()),
            server_path: Mutex::new(None),
            stop: AtomicBool::new(false),
            health: Mutex::new(InstrumentationHealth::default()),
            watchdog_diagnostics: Mutex::new(Vec::new()),
            watchdog: Mutex::new(None),
            started_at: Instant::now(),
        });
        if let Err(mut errors) = deploy_server(&state, &request.config) {
            errors.extend(cleanup_state(&state));
            let _ = fs::remove_dir_all(&workspace);
            return Err(errors);
        }
        let script_path = workspace.join("instrumentation.js");
        if let Err(error) = fs::write(&script_path, &request.script) {
            let mut errors = vec![diag(
                catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                "path",
                format!("{}: {error}", script_path.display()),
            )];
            errors.extend(cleanup_state(&state));
            let _ = fs::remove_dir_all(&workspace);
            return Err(errors);
        }
        if let Err(mut errors) = launch_target(&state, request, &script_path) {
            errors.extend(cleanup_state(&state));
            let _ = fs::remove_dir_all(&workspace);
            return Err(errors);
        }
        if let Err(errors) = wait_for_health(&state, request.config.startup_timeout) {
            let mut errors = errors;
            errors.extend(cleanup_state(&state));
            let _ = fs::remove_dir_all(&workspace);
            return Err(errors);
        }
        start_watchdog(&state);
        lease.add_cleanup(Box::new(InstrumentationCleanup {
            state: Arc::clone(&state),
            workspace: Some(workspace.clone()),
        }));
        Ok(Self { state, workspace })
    }

    /// Runs an immediate health check and returns structured failures.
    pub fn health_check(&self) -> Result<InstrumentationHealth, Vec<Diagnostic>> {
        check_health(&self.state)
    }

    /// Returns the last watchdog health snapshot.
    #[must_use]
    pub fn health(&self) -> InstrumentationHealth {
        self.state
            .health
            .lock()
            .map(|health| health.clone())
            .unwrap_or_default()
    }

    /// Drains diagnostics collected asynchronously by the watchdog.
    #[must_use]
    pub fn take_watchdog_diagnostics(&self) -> Vec<Diagnostic> {
        self.state
            .watchdog_diagnostics
            .lock()
            .map(|mut diagnostics| std::mem::take(&mut *diagnostics))
            .unwrap_or_default()
    }

    /// Loads a later-phase payload into the already-running target.
    pub fn load_payload(&self, payload: impl AsRef<Path>) -> Result<(), Vec<Diagnostic>> {
        let process = self
            .state
            .runner
            .spawn(&ToolProcessRequest {
                probe: self.state.frida.clone(),
                arguments: vec![
                    "-U".to_owned(),
                    "-n".to_owned(),
                    self.state.package_name.clone(),
                    "-l".to_owned(),
                    payload.as_ref().display().to_string(),
                ],
                working_directory: Some(self.workspace.clone()),
                environment: Vec::new(),
            })
            .map_err(|error| {
                vec![diag(
                    catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                    "payload",
                    error.to_string(),
                )]
            })?;
        if !process.is_running() {
            let _ = process.stop();
            return Err(vec![diag(
                catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                "payload",
                "Frida payload process exited immediately".to_owned(),
            )]);
        }
        self.state
            .auxiliary_processes
            .lock()
            .map_err(|_| {
                vec![diag(
                    catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                    "state",
                    "instrumentation process state lock was poisoned".to_owned(),
                )]
            })?
            .push(process);
        Ok(())
    }

    /// Requests teardown of the substrate and its session artifacts.
    pub fn teardown(self) -> Result<(), Vec<Diagnostic>> {
        let mut errors = cleanup_state(&self.state);
        if let Err(error) = remove_workspace(&self.workspace) {
            errors.push(diag(
                catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                "workspace",
                error,
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Generates the early hook wrapper used by spawn mode.
#[must_use]
pub fn generate_early_spawn_script(package_name: &str, payload: &str) -> String {
    format!(
        "'use strict';\n// APIaxess early substrate for {package_name}\nvar APIAXESS_SCRIPT_READY = false;\nfunction apiaxessNativeInit() {{ ['dlopen','android_dlopen_ext','SSL_CTX_new','SSL_do_handshake'].forEach(function(name) {{ try {{ var p = Module.findExportByName(null, name); if (p) Interceptor.attach(p, {{ onEnter: function() {{ console.log('APIAXESS_NATIVE_INIT:' + name); }} }}); }} catch (_) {{}} }}); }}\nfunction apiaxessApplicationReady() {{ try {{ Java.performNow(function() {{ var Application = Java.use('android.app.Application'); Application.onCreate.overloads.forEach(function(O) {{ var original = O.implementation; O.implementation = function() {{ console.log('APIAXESS_APPLICATION_ONCREATE'); return original.call(this); }}; }}); }}); }} catch (_) {{}} }}\nJava.perform(function() {{ apiaxessApplicationReady(); Java.enumerateLoadedClasses({{ onMatch: function(_) {{}}, onComplete: function() {{ APIAXESS_SCRIPT_READY = true; console.log('APIAXESS_CLASS_LOADER_OK'); console.log('APIAXESS_DEX_OK'); }} }}); }});\napiaxessNativeInit();\n{payload}\n"
    )
}

fn deploy_server(
    state: &Arc<SubstrateState>,
    config: &FridaSubstrateConfig,
) -> Result<(), Vec<Diagnostic>> {
    let bytes = fs::read(&config.frida_server_path).map_err(|error| {
        vec![diag(
            catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
            "host_path",
            format!("{}: {error}", config.frida_server_path.display()),
        )]
    })?;
    state
        .control
        .put(&bytes, &config.server_remote_path, Duration::from_secs(30))
        .map_err(|error| {
            vec![diag(
                catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
                "error",
                error.to_string(),
            )]
        })?;
    state
        .server_path
        .lock()
        .map_err(|_| {
            vec![diag(
                catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
                "state",
                "server state lock was poisoned".to_owned(),
            )]
        })?
        .replace(config.server_remote_path.clone());
    for command in [
        vec![
            "chmod".to_owned(),
            "0755".to_owned(),
            config.server_remote_path.clone(),
        ],
        vec![
            "sh".to_owned(),
            "-c".to_owned(),
            format!("{} >/dev/null 2>&1 &", config.server_remote_path),
        ],
    ] {
        let output = state
            .control
            .shell(&command, Duration::from_secs(30))
            .map_err(|error| {
                vec![diag(
                    catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
                    "operation",
                    error.to_string(),
                )]
            })?;
        if output.exit_code != Some(0) {
            return Err(vec![diag(
                catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
                "stderr",
                output.stderr,
            )]);
        }
    }
    let pid = state.control.shell(
        &["pidof".to_owned(), "frida-server".to_owned()],
        Duration::from_secs(15),
    );
    if !successful(&pid) {
        return Err(vec![diag(
            catalogue::INSTRUMENTATION_FRIDA_SERVER_DEPLOY_FAILED,
            "evidence",
            "frida-server did not report a live process".to_owned(),
        )]);
    }
    Ok(())
}

fn launch_target(
    state: &Arc<SubstrateState>,
    request: &InstrumentationRequest,
    script_path: &Path,
) -> Result<(), Vec<Diagnostic>> {
    let mut arguments = vec!["-U".to_owned()];
    match request.mode {
        InstrumentationMode::Spawn => {
            arguments.extend([
                "-f".to_owned(),
                request.package_name.clone(),
                "--no-pause".to_owned(),
            ]);
        }
        InstrumentationMode::Attach { pid: Some(pid) } => {
            arguments.extend(["-p".to_owned(), pid.to_string()]);
        }
        InstrumentationMode::Attach { pid: None } => {
            arguments.extend(["-n".to_owned(), request.package_name.clone()]);
        }
    }
    arguments.extend(["-l".to_owned(), script_path.display().to_string()]);
    let process = state
        .runner
        .spawn(&ToolProcessRequest {
            probe: state.frida.clone(),
            arguments,
            working_directory: script_path.parent().map(Path::to_path_buf),
            environment: Vec::new(),
        })
        .map_err(|error| {
            vec![diag(
                match request.mode {
                    InstrumentationMode::Spawn => catalogue::INSTRUMENTATION_SPAWN_GATE_FAILED,
                    InstrumentationMode::Attach { .. } => catalogue::INSTRUMENTATION_ATTACH_FAILED,
                },
                "error",
                error.to_string(),
            )]
        })?;
    if !process.is_running() {
        let _ = process.stop();
        return Err(vec![diag(
            match request.mode {
                InstrumentationMode::Spawn => catalogue::INSTRUMENTATION_SPAWN_GATE_FAILED,
                InstrumentationMode::Attach { .. } => catalogue::INSTRUMENTATION_ATTACH_FAILED,
            },
            "evidence",
            "Frida process exited immediately".to_owned(),
        )]);
    }
    state
        .process
        .lock()
        .map_err(|_| {
            vec![diag(
                catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                "state",
                "instrumentation process state lock was poisoned".to_owned(),
            )]
        })?
        .replace(process);
    Ok(())
}

fn wait_for_health(state: &Arc<SubstrateState>, timeout: Duration) -> Result<(), Vec<Diagnostic>> {
    let deadline = Instant::now() + timeout.max(Duration::from_secs(1));
    let mut last = Vec::new();
    while Instant::now() < deadline {
        match check_health(state) {
            Ok(health) if health.is_healthy() => return Ok(()),
            Ok(health) => {
                if let Some(crash) = health.crash_evidence {
                    return Err(vec![diag(
                        catalogue::INSTRUMENTATION_CRASH_CORRELATED,
                        "logcat",
                        crash,
                    )]);
                }
                last = vec![diag(
                    match state.mode {
                        InstrumentationMode::Spawn => catalogue::INSTRUMENTATION_SPAWN_GATE_FAILED,
                        InstrumentationMode::Attach { .. } => {
                            catalogue::INSTRUMENTATION_ATTACH_FAILED
                        }
                    },
                    "state",
                    format!("health gate incomplete: {health:?}"),
                )];
            }
            Err(errors) => last = errors,
        }
        thread::sleep(Duration::from_millis(200));
    }
    if last.is_empty() {
        last.push(diag(
            catalogue::INSTRUMENTATION_WATCHDOG_DEGRADED,
            "timeout",
            format!("health gate exceeded {timeout:?}"),
        ));
    }
    Err(last)
}

#[allow(clippy::too_many_lines)]
fn check_health(state: &Arc<SubstrateState>) -> Result<InstrumentationHealth, Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let server_pid = state.control.shell(
        &["pidof".to_owned(), "frida-server".to_owned()],
        Duration::from_secs(10),
    );
    let server_ipc = successful(&server_pid);
    if !server_ipc {
        errors.push(diag(
            catalogue::INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED,
            "server",
            "pidof frida-server failed".to_owned(),
        ));
    }
    let frida_ps = invoke(
        &state.runner,
        &state.frida_ps,
        &["-U".to_owned()],
        Duration::from_secs(15),
    );
    if !frida_ps
        .as_ref()
        .is_ok_and(|output| output.exit_code == Some(0))
    {
        errors.push(diag(
            catalogue::INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED,
            "ipc",
            frida_ps
                .err()
                .unwrap_or_else(|| "frida-ps returned a non-zero status".to_owned()),
        ));
    }
    let target_pid = state.control.shell(
        &["pidof".to_owned(), state.package_name.clone()],
        Duration::from_secs(10),
    );
    let target_process = successful(&target_pid);
    if !target_process {
        errors.push(diag(
            match state.mode {
                InstrumentationMode::Spawn => catalogue::INSTRUMENTATION_SPAWN_GATE_FAILED,
                InstrumentationMode::Attach { .. } => catalogue::INSTRUMENTATION_ATTACH_FAILED,
            },
            "target",
            state.package_name.clone(),
        ));
    }
    let probe = invoke(
        &state.runner,
        &state.frida,
        &[
            "-U".to_owned(),
            "-n".to_owned(),
            state.package_name.clone(),
            "-e".to_owned(),
            "Java.perform(function(){Java.enumerateLoadedClasses({onMatch:function(_){},onComplete:function(){console.log('APIAXESS_CLASS_LOADER_OK');console.log('APIAXESS_DEX_OK');}});});".to_owned(),
        ],
        Duration::from_secs(20),
    );
    let (class_loader, dex_resolution, script_ready) = match &probe {
        Ok(output) if output.exit_code == Some(0) => (
            output.stdout.contains("APIAXESS_CLASS_LOADER_OK"),
            output.stdout.contains("APIAXESS_DEX_OK"),
            output.stdout.contains("APIAXESS_") || output.stderr.contains("APIAXESS_"),
        ),
        _ => (false, false, false),
    };
    if !class_loader {
        errors.push(diag(
            catalogue::INSTRUMENTATION_CLASS_LOADER_FAILED,
            "probe",
            probe
                .as_ref()
                .map_or_else(Clone::clone, |output| output.stderr.clone()),
        ));
    }
    if !dex_resolution {
        errors.push(diag(
            catalogue::INSTRUMENTATION_DEX_RESOLUTION_FAILED,
            "probe",
            "loaded DEX marker was not observed".to_owned(),
        ));
    }
    let logcat = state.control.shell(
        &[
            "logcat".to_owned(),
            "-d".to_owned(),
            "-t".to_owned(),
            state.logcat_lines.to_string(),
        ],
        Duration::from_secs(15),
    );
    let crash_evidence = logcat.ok().and_then(|output| {
        output
            .stdout
            .lines()
            .filter(|line| line.contains(&state.package_name))
            .find(|line| {
                [
                    "FATAL EXCEPTION",
                    "Fatal signal",
                    "SIGSEGV",
                    "Abort message",
                ]
                .iter()
                .any(|marker| line.contains(marker))
            })
            .map(str::to_owned)
    });
    if let Some(crash) = &crash_evidence {
        errors.push(diag(
            catalogue::INSTRUMENTATION_CRASH_CORRELATED,
            "logcat",
            crash.clone(),
        ));
    }
    let health = InstrumentationHealth {
        server_ipc,
        target_process,
        class_loader,
        dex_resolution,
        script_ready,
        crash_evidence,
        checked_after_ms: state.started_at.elapsed().as_millis(),
    };
    if let Ok(mut current) = state.health.lock() {
        *current = health.clone();
    }
    if errors.is_empty() {
        Ok(health)
    } else {
        Err(errors)
    }
}

fn start_watchdog(state: &Arc<SubstrateState>) {
    let worker_state = Arc::clone(state);
    let handle = thread::spawn(move || {
        while !worker_state.stop.load(Ordering::Acquire) {
            if let Err(mut errors) = check_health(&worker_state) {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_WATCHDOG_DEGRADED,
                    "health",
                    format!("watchdog health failure for {}", worker_state.package_name),
                ));
                if let Ok(mut stored) = worker_state.watchdog_diagnostics.lock() {
                    stored.append(&mut errors);
                }
            }
            thread::sleep(worker_state.watchdog_interval);
        }
    });
    if let Ok(mut watchdog) = state.watchdog.lock() {
        *watchdog = Some(handle);
    }
}

struct InstrumentationCleanup {
    state: Arc<SubstrateState>,
    workspace: Option<PathBuf>,
}

impl SandboxCleanup for InstrumentationCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut errors = cleanup_state(&self.state);
        if let Some(workspace) = self.workspace.take() {
            if let Err(error) = remove_workspace(&workspace) {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "workspace",
                    error,
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

fn cleanup_state(state: &Arc<SubstrateState>) -> Vec<Diagnostic> {
    state.stop.store(true, Ordering::Release);
    let mut errors = Vec::new();
    if let Ok(mut watchdog) = state.watchdog.lock() {
        if let Some(handle) = watchdog.take() {
            if handle.join().is_err() {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "watchdog",
                    "watchdog thread did not join".to_owned(),
                ));
            }
        }
    }
    if let Ok(mut auxiliary) = state.auxiliary_processes.lock() {
        for process in auxiliary.drain(..) {
            if let Err(error) = process.stop() {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "payload",
                    error.to_string(),
                ));
            }
        }
    }
    if let Ok(mut process) = state.process.lock() {
        if let Some(process) = process.take() {
            if let Err(error) = process.stop() {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "frida",
                    error.to_string(),
                ));
            }
        }
    }
    if let Ok(mut server_path) = state.server_path.lock() {
        if let Some(path) = server_path.take() {
            if state
                .control
                .shell(
                    &["pkill".to_owned(), "-f".to_owned(), path.clone()],
                    Duration::from_secs(15),
                )
                .is_err()
            {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "server",
                    format!("could not stop server at {path}"),
                ));
            }
            if let Err(error) = state.control.remove(&path, Duration::from_secs(15)) {
                errors.push(diag(
                    catalogue::INSTRUMENTATION_TEARDOWN_FAILED,
                    "server_artifact",
                    error.to_string(),
                ));
            }
        }
    }
    errors
}

fn probe_tools(
    runner: &Arc<dyn ExternalToolRunner>,
    request: &InstrumentationRequest,
) -> Result<(ToolProbe, ToolProbe), Vec<Diagnostic>> {
    let frida = runner
        .probe(&ToolProbeRequest {
            tool_id: "instrumentation.frida-cli".to_owned(),
            executable: request.config.frida_executable.clone(),
            version_arguments: vec!["--version".to_owned()],
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        })
        .map_err(|error| {
            vec![diag(
                catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
                "frida_cli",
                error.to_string(),
            )]
        })?;
    let frida_ps = runner
        .probe(&ToolProbeRequest {
            tool_id: "instrumentation.frida-ps".to_owned(),
            executable: request.config.frida_ps_executable.clone(),
            version_arguments: vec!["--version".to_owned()],
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        })
        .map_err(|error| {
            vec![diag(
                catalogue::INSTRUMENTATION_FRIDA_SERVER_HEALTH_FAILED,
                "frida_ps",
                error.to_string(),
            )]
        })?;
    Ok((frida, frida_ps))
}

fn invoke(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    arguments: &[String],
    timeout: Duration,
) -> Result<SandboxCommandOutput, String> {
    runner
        .invoke(&ToolInvocationRequest {
            probe: probe.clone(),
            arguments: arguments.to_vec(),
            working_directory: None,
            environment: Vec::new(),
            timeout,
        })
        .map(|output| SandboxCommandOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
        .map_err(|error| error.to_string())
}

fn session_workspace(request: &InstrumentationRequest) -> Result<PathBuf, Vec<Diagnostic>> {
    let parent = request
        .workspace_root
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    let workspace = parent.join(format!(
        "apiaxess-instrumentation-{}",
        safe_token(&request.lease_id)
    ));
    fs::create_dir_all(&workspace).map_err(|error| {
        vec![diag(
            catalogue::INSTRUMENTATION_SCRIPT_LOAD_FAILED,
            "workspace",
            error.to_string(),
        )]
    })?;
    Ok(workspace)
}

fn remove_workspace(workspace: &Path) -> Result<(), String> {
    match fs::remove_dir_all(workspace) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: {error}", workspace.display())),
    }
}

fn successful(result: &Result<SandboxCommandOutput, Diagnostic>) -> bool {
    result
        .as_ref()
        .is_ok_and(|output| output.exit_code == Some(0))
}

fn diag(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    key: &str,
    value: String,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String("instrumentation.frida".to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value));
    definition.instantiate(context)
}

fn safe_token(value: &str) -> String {
    let value = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(48)
        .collect::<String>();
    if value.is_empty() {
        "session".to_owned()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_script_contains_application_and_native_initialization_gates() {
        let script = generate_early_spawn_script("com.example.target", "console.log('payload');");
        assert!(script.contains("APIAXESS_APPLICATION_ONCREATE"));
        assert!(script.contains("APIAXESS_NATIVE_INIT"));
        assert!(script.contains("APIAXESS_CLASS_LOADER_OK"));
        assert!(script.contains("SSL_CTX_new"));
        assert!(script.contains("console.log('payload');"));
    }

    #[test]
    fn health_requires_every_readiness_gate() {
        let mut health = InstrumentationHealth::default();
        assert!(!health.is_healthy());
        health.server_ipc = true;
        health.target_process = true;
        health.class_loader = true;
        health.dex_resolution = true;
        health.script_ready = true;
        assert!(health.is_healthy());
        health.crash_evidence = Some("Fatal signal".to_owned());
        assert!(!health.is_healthy());
    }
}
