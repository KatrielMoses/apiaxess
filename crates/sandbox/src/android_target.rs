//! Phase D1: the GUI-drivable Android target add-on.
//!
//! The GUI Android target is a slim, no-GApps, root-capable AOSP `x86_64` emulator
//! shipped as a separate, optional add-on (not part of the base install), the same
//! out-of-band, path-resolved model as the analysis runtime. A user installs the
//! add-on when they want a target they can drive by hand — installing their own
//! APK, completing logins and onboarding the autonomous crawler cannot — with
//! traffic flowing to the workbench.
//!
//! This module is the engine-side of the add-on: it resolves the payload by path,
//! reads the engine-facing manifest (`android-target-manifest.json`), boots the
//! owned AVD headless, and stages the first-boot client-APK install. The
//! trust-granting provisioning (live session CA + device-side frida-server + the
//! adb-reverse tunnel + pairing) is the existing C2/C5 flow in
//! [`crate::device_provision`], reused verbatim over this add-on's bundled `adb`,
//! not re-implemented here.
//!
//! It differs from [`crate::BundledEmulatorBackend`] (the analysis runtime) on
//! purpose: that target is headless, disposable (`-wipe-data`, `-no-snapshot`), and
//! driven autonomously. This one is a persistent GUI target — cold boot each
//! session for reliability, but userdata (the installed APK and any completed
//! login) survives across boots, so provisioning is applied on first boot rather
//! than baked into a snapshot.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use apiaxess_diagnostics::{Diagnostic, catalogue};
use apiaxess_external_tools::{ExternalToolRunner, ToolProbe, ToolProcess, ToolProcessRequest};
use serde::Deserialize;

use crate::{
    AccelerationMode, SandboxControl, clear_stale_avd_locks, context, invoke_tool_with_environment,
    probe_tool,
};

/// The engine-read manifest filename at the add-on payload root.
pub const MANIFEST_FILE: &str = "android-target-manifest.json";

const BACKEND_ID: &str = "sandbox.android-target";
/// How long `stop` lets the emulator exit on its own after `emu kill` before
/// force-stopping it (a clean exit releases the AVD's lock files).
const EMULATOR_EXIT_GRACE: Duration = Duration::from_secs(20);

/// First-boot provisioning switches recorded in the manifest.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTargetProvisioning {
    /// Install the first-party client APK on first boot.
    #[serde(default)]
    pub install_client_apk: bool,
    /// Install the live per-session CA into the system trust store (C2).
    #[serde(default)]
    pub install_session_ca: bool,
    /// Start the device-side frida-server (C2, the hook for a pinned-app bypass).
    #[serde(default)]
    pub start_frida_server: bool,
}

/// Payload-relative first-boot artifact paths recorded in the manifest.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTargetArtifacts {
    /// Payload-relative path to the staged client APK (may be absent if the
    /// add-on was assembled without it).
    #[serde(default)]
    pub client_apk: String,
    /// Payload-relative path to the device-side frida-server binary.
    #[serde(default)]
    pub frida_server: String,
}

/// Payload-relative locations of the bundled screen-streaming components
/// (Phase D2). ws-scrcpy runs on the bundled Node runtime, bound to loopback; the
/// engine is the only reachable listener and reverse-proxies it behind the
/// workbench gate.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTargetStreaming {
    /// Payload-relative directory holding the bundled Node runtime.
    #[serde(default)]
    pub node_dir: String,
    /// Payload-relative directory holding the pinned ws-scrcpy fork.
    #[serde(default)]
    pub ws_scrcpy_dir: String,
    /// ws-scrcpy entry point (JS), relative to `ws_scrcpy_dir`, run by Node.
    #[serde(default)]
    pub ws_scrcpy_entry: String,
    /// The base path the engine reverse-proxies the view under, and that the
    /// pinned fork is built to serve from (e.g. `/android-stream/`).
    #[serde(default = "default_stream_base_path")]
    pub base_path: String,
}

fn default_stream_base_path() -> String {
    "/android-stream/".to_owned()
}

/// The engine-facing add-on manifest (`android-target-manifest.json`), emitted by
/// `fetch-android-target.ps1` and read verbatim by the resolver.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AndroidTargetManifest {
    /// Manifest schema version.
    pub schema_version: u32,
    /// Stable add-on id (`android-target`).
    pub addon_id: String,
    /// Separately-versioned payload version.
    pub payload_version: String,
    /// Owned AVD name.
    pub avd_name: String,
    /// Payload-relative directory holding the emulator engine.
    pub emulator_dir: String,
    /// Payload-relative directory holding platform-tools (`adb`).
    pub platform_tools_dir: String,
    /// Payload-relative directory holding the owned AVD (`ANDROID_AVD_HOME`).
    pub avd_dir: String,
    /// Local emulator console port; the device serial is `emulator-<port>`.
    pub console_port: u16,
    /// RAM floor (MiB) applied at boot.
    #[serde(default = "default_ram_mib")]
    pub ram_mib: u32,
    /// The ws-scrcpy port Phase D2 will stream over.
    pub ws_scrcpy_port: u16,
    /// The fixed, "required" emulator arguments (headless boot profile). The
    /// dynamic `-avd`/`-port`/`-accel`/`-memory` are appended at boot.
    #[serde(default)]
    pub emulator_args: Vec<String>,
    /// First-boot provisioning switches.
    pub provisioning: AndroidTargetProvisioning,
    /// First-boot artifact paths.
    pub artifacts: AndroidTargetArtifacts,
    /// Bundled screen-streaming components (Phase D2). Absent on a payload
    /// assembled without streaming; the target still boots and captures traffic.
    #[serde(default)]
    pub streaming: Option<AndroidTargetStreaming>,
}

fn default_ram_mib() -> u32 {
    2048
}

/// A resolved GUI Android target add-on: its payload root plus the parsed manifest.
#[derive(Clone, Debug)]
pub struct AndroidTargetAddon {
    root: PathBuf,
    manifest: AndroidTargetManifest,
}

impl AndroidTargetAddon {
    /// Resolves the add-on from the install layout (or the
    /// `APIAXESS_ANDROID_TARGET` override).
    ///
    /// # Errors
    ///
    /// Returns [`catalogue::ANDROID_TARGET_MISSING`] when the payload/manifest is
    /// absent, or [`catalogue::ANDROID_TARGET_MANIFEST_INVALID`] when the manifest
    /// cannot be parsed.
    pub fn resolve() -> Result<Self, Diagnostic> {
        Self::resolve_at(&android_target_root())
    }

    /// Resolves the add-on rooted at an explicit directory (used by the override
    /// path and by tests).
    ///
    /// # Errors
    ///
    /// See [`Self::resolve`].
    pub fn resolve_at(root: &Path) -> Result<Self, Diagnostic> {
        let manifest_path = root.join(MANIFEST_FILE);
        if !manifest_path.is_file() {
            return Err(catalogue::ANDROID_TARGET_MISSING.instantiate(context(
                BACKEND_ID,
                "missing_path",
                manifest_path.display().to_string(),
            )));
        }
        let bytes = std::fs::read(&manifest_path).map_err(|error| {
            catalogue::ANDROID_TARGET_MANIFEST_INVALID.instantiate(context(
                BACKEND_ID,
                "error",
                format!("{}: {error}", manifest_path.display()),
            ))
        })?;
        let manifest: AndroidTargetManifest = serde_json::from_slice(&bytes).map_err(|error| {
            catalogue::ANDROID_TARGET_MANIFEST_INVALID.instantiate(context(
                BACKEND_ID,
                "error",
                format!("{}: {error}", manifest_path.display()),
            ))
        })?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
        })
    }

    /// Whether an add-on payload is installed at the resolved location. Cheap
    /// path-existence check for the settings/status panel — does not parse.
    #[must_use]
    pub fn is_present() -> bool {
        android_target_root().join(MANIFEST_FILE).is_file()
    }

    /// Detects the host's acceleration mode (WHPX/KVM vs. QEMU software) for a
    /// headless boot, so the launch path does not need to build a host-capability
    /// report itself.
    #[must_use]
    pub fn detect_acceleration(runner: Arc<dyn ExternalToolRunner>) -> AccelerationMode {
        let report =
            apiaxess_host_capabilities::HostCapabilityService::with_runner(runner).detect();
        AccelerationMode::detect(&report).0
    }

    /// The parsed manifest.
    #[must_use]
    pub fn manifest(&self) -> &AndroidTargetManifest {
        &self.manifest
    }

    /// The payload root (doubles as `ANDROID_SDK_ROOT`).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute path to the bundled emulator engine.
    #[must_use]
    pub fn emulator_executable(&self) -> PathBuf {
        self.root
            .join(&self.manifest.emulator_dir)
            .join(exe("emulator"))
    }

    /// Absolute path to the bundled `adb` (reused by the C2/C5 provisioner).
    #[must_use]
    pub fn adb_executable(&self) -> PathBuf {
        self.root
            .join(&self.manifest.platform_tools_dir)
            .join(exe("adb"))
    }

    /// `ANDROID_AVD_HOME` holding the owned AVD.
    #[must_use]
    pub fn avd_home(&self) -> PathBuf {
        self.root.join(&self.manifest.avd_dir)
    }

    /// Absolute path to the staged client APK (may not exist if unstaged).
    #[must_use]
    pub fn client_apk(&self) -> PathBuf {
        self.root.join(&self.manifest.artifacts.client_apk)
    }

    /// Absolute path to the device-side frida-server binary.
    #[must_use]
    pub fn frida_server_path(&self) -> PathBuf {
        self.root.join(&self.manifest.artifacts.frida_server)
    }

    /// The adb transport serial for the owned AVD (`emulator-<port>`).
    #[must_use]
    pub fn device_serial(&self) -> String {
        format!("emulator-{}", self.manifest.console_port)
    }

    /// The ws-scrcpy port Phase D2 will stream over.
    #[must_use]
    pub fn ws_scrcpy_port(&self) -> u16 {
        self.manifest.ws_scrcpy_port
    }

    /// The bundled streaming components, when the payload was assembled with them.
    #[must_use]
    pub fn streaming(&self) -> Option<&AndroidTargetStreaming> {
        self.manifest.streaming.as_ref()
    }

    /// Absolute path to the bundled Node runtime executable, when present.
    #[must_use]
    pub fn node_executable(&self) -> Option<PathBuf> {
        self.streaming()
            .map(|streaming| self.root.join(&streaming.node_dir).join(exe("node")))
    }

    /// Absolute path to the ws-scrcpy entry point, when present.
    #[must_use]
    pub fn ws_scrcpy_entry(&self) -> Option<PathBuf> {
        self.streaming().map(|streaming| {
            self.root
                .join(&streaming.ws_scrcpy_dir)
                .join(&streaming.ws_scrcpy_entry)
        })
    }

    /// Absolute path to the ws-scrcpy working directory, when present.
    #[must_use]
    pub fn ws_scrcpy_dir(&self) -> Option<PathBuf> {
        self.streaming()
            .map(|streaming| self.root.join(&streaming.ws_scrcpy_dir))
    }

    /// `ANDROID_SDK_ROOT` + `ANDROID_AVD_HOME` for emulator/adb invocations.
    #[must_use]
    pub fn environment(&self) -> Vec<(String, String)> {
        vec![
            (
                "ANDROID_SDK_ROOT".to_owned(),
                self.root.display().to_string(),
            ),
            (
                "ANDROID_AVD_HOME".to_owned(),
                self.avd_home().display().to_string(),
            ),
        ]
    }

    /// The headless boot command line: the manifest's fixed args plus the dynamic
    /// `-avd`/`-port`/`-accel`/`-memory`. A persistent GUI target — no `-wipe-data`
    /// (userdata survives across boots) and no quickboot snapshot save/load.
    #[must_use]
    pub fn boot_arguments(&self, acceleration: AccelerationMode) -> Vec<String> {
        let accel = match acceleration {
            AccelerationMode::Accelerated => "on",
            AccelerationMode::Software => "off",
        };
        let mut arguments = vec![
            "-avd".to_owned(),
            self.manifest.avd_name.clone(),
            "-port".to_owned(),
            self.manifest.console_port.to_string(),
            "-accel".to_owned(),
            accel.to_owned(),
            "-memory".to_owned(),
            self.manifest.ram_mib.to_string(),
        ];
        arguments.extend(self.manifest.emulator_args.iter().cloned());
        arguments
    }

    /// Honest preflight: the payload pieces the launch path needs. Empty when the
    /// add-on is bootable; otherwise the actionable missing-piece diagnostics.
    #[must_use]
    pub fn preflight(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        for component in [self.emulator_executable(), self.adb_executable()] {
            if !component.is_file() {
                diagnostics.push(catalogue::ANDROID_TARGET_MISSING.instantiate(context(
                    BACKEND_ID,
                    "missing_path",
                    component.display().to_string(),
                )));
            }
        }
        let avd_ini = self
            .avd_home()
            .join(format!("{}.ini", self.manifest.avd_name));
        if !avd_ini.is_file() {
            diagnostics.push(catalogue::ANDROID_TARGET_MISSING.instantiate(context(
                BACKEND_ID,
                "missing_path",
                avd_ini.display().to_string(),
            )));
        }
        if self.manifest.provisioning.install_client_apk && !self.client_apk().is_file() {
            diagnostics.push(
                catalogue::ANDROID_TARGET_CLIENT_APK_MISSING.instantiate(context(
                    BACKEND_ID,
                    "missing_path",
                    self.client_apk().display().to_string(),
                )),
            );
        }
        diagnostics
    }

    /// Boots the owned AVD headless and waits for `sys.boot_completed`. Returns a
    /// live handle owning the emulator process for first-boot provisioning.
    ///
    /// # Errors
    ///
    /// Returns the boot diagnostics when the payload is incomplete, the emulator
    /// cannot be spawned, or boot does not complete within `readiness_timeout`.
    pub fn boot(
        &self,
        runner: Arc<dyn ExternalToolRunner>,
        acceleration: AccelerationMode,
        readiness_timeout: Duration,
    ) -> Result<BootedAndroidTarget, Vec<Diagnostic>> {
        // Only the missing-payload preflight is fatal; a missing client APK is a
        // warning surfaced later by the install step, not a reason not to boot.
        let fatal: Vec<Diagnostic> = self
            .preflight()
            .into_iter()
            .filter(|diagnostic| {
                diagnostic.id.as_ref() != catalogue::ANDROID_TARGET_CLIENT_APK_MISSING.id
            })
            .collect();
        if !fatal.is_empty() {
            return Err(fatal);
        }

        let environment = self.environment();
        let serial = self.device_serial();
        let adb = probe_tool(
            &runner,
            "android.adb",
            &self.adb_executable().display().to_string(),
            &["version"],
        )
        .map_err(|error| vec![boot_failed(format!("adb could not be probed: {error}"))])?;
        let emulator = probe_tool(
            &runner,
            "android.emulator",
            &self.emulator_executable().display().to_string(),
            &["-version"],
        )
        .map_err(|error| {
            vec![boot_failed(format!(
                "emulator could not be probed: {error}"
            ))]
        })?;

        clear_stale_avd_locks(&self.root, &self.manifest.avd_name);
        let process = runner
            .spawn(&ToolProcessRequest {
                probe: emulator,
                arguments: self.boot_arguments(acceleration),
                working_directory: Some(self.root.clone()),
                environment: environment.clone(),
            })
            .map_err(|error| {
                vec![boot_failed(format!(
                    "emulator could not be spawned: {error}"
                ))]
            })?;

        if let Err(error) = wait_for_boot(
            &runner,
            &adb,
            &serial,
            &environment,
            &process,
            readiness_timeout,
        ) {
            let _ = process.stop();
            return Err(vec![error]);
        }

        Ok(BootedAndroidTarget {
            addon: self.clone(),
            runner,
            adb,
            serial,
            environment,
            process: Some(process),
        })
    }
}

/// A booted GUI Android target: owns the emulator process and exposes the
/// first-boot steps the launch path drives before handing off to C2/C5.
pub struct BootedAndroidTarget {
    addon: AndroidTargetAddon,
    runner: Arc<dyn ExternalToolRunner>,
    adb: ToolProbe,
    serial: String,
    environment: Vec<(String, String)>,
    process: Option<ToolProcess>,
}

impl std::fmt::Debug for BootedAndroidTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BootedAndroidTarget")
            .field("serial", &self.serial)
            .field("ws_scrcpy_port", &self.addon.ws_scrcpy_port())
            .finish_non_exhaustive()
    }
}

impl BootedAndroidTarget {
    /// The booted device's adb serial (`emulator-<port>`), for the C2/C5 provisioner.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// The resolved add-on (paths, manifest, ws-scrcpy port).
    #[must_use]
    pub fn addon(&self) -> &AndroidTargetAddon {
        &self.addon
    }

    /// The ws-scrcpy port Phase D2 will stream over.
    #[must_use]
    pub fn ws_scrcpy_port(&self) -> u16 {
        self.addon.ws_scrcpy_port()
    }

    /// Installs the first-party client APK on first boot (idempotent: `adb install
    /// -r` replaces). A no-op when the manifest does not request it.
    ///
    /// # Errors
    ///
    /// Returns [`catalogue::ANDROID_TARGET_CLIENT_APK_MISSING`] when the APK was
    /// not staged in the payload, or [`catalogue::ANDROID_TARGET_CLIENT_INSTALL_FAILED`]
    /// when adb rejects the install.
    pub fn install_client_apk(&self) -> Result<(), Vec<Diagnostic>> {
        if !self.addon.manifest.provisioning.install_client_apk {
            return Ok(());
        }
        let apk = self.addon.client_apk();
        if !apk.is_file() {
            return Err(vec![
                catalogue::ANDROID_TARGET_CLIENT_APK_MISSING.instantiate(context(
                    BACKEND_ID,
                    "missing_path",
                    apk.display().to_string(),
                )),
            ]);
        }
        let control = self.control();
        let output = control
            .install_apk(&apk, Duration::from_secs(180))
            .map_err(|diagnostic| vec![diagnostic])?;
        if output.exit_code == Some(0) {
            Ok(())
        } else {
            Err(vec![
                catalogue::ANDROID_TARGET_CLIENT_INSTALL_FAILED.instantiate(context(
                    BACKEND_ID,
                    "stderr",
                    output.stderr,
                )),
            ])
        }
    }

    /// Starts ws-scrcpy on the bundled Node runtime, bound to loopback only
    /// (Phase D2). ws-scrcpy has no built-in auth, so it is never the reachable
    /// surface: the engine reverse-proxies it behind the workbench gate. The
    /// emulator's scrcpy-server listens on the AVD's internal interface, so
    /// ws-scrcpy is preconfigured for its "proxy over adb" mode against this
    /// add-on's own adb — the user never sees the interface quirk.
    ///
    /// # Errors
    ///
    /// Returns [`catalogue::ANDROID_STREAM_UNAVAILABLE`] when the add-on does not
    /// include the Node runtime + ws-scrcpy, or when Node cannot be spawned.
    pub fn start_streaming(&self) -> Result<AndroidTargetStream, Vec<Diagnostic>> {
        let streaming = self.addon.streaming().ok_or_else(|| {
            vec![stream_unavailable(
                "the add-on does not include ws-scrcpy or the Node runtime".to_owned(),
            )]
        })?;
        let node = self
            .addon
            .node_executable()
            .filter(|path| path.is_file())
            .ok_or_else(|| {
                vec![stream_unavailable(
                    "the bundled Node runtime is not staged in the add-on".to_owned(),
                )]
            })?;
        let entry = self
            .addon
            .ws_scrcpy_entry()
            .filter(|path| path.is_file())
            .ok_or_else(|| {
                vec![stream_unavailable(
                    "the ws-scrcpy entry point is not staged in the add-on".to_owned(),
                )]
            })?;
        let working_directory = self.addon.ws_scrcpy_dir();
        let port = self.addon.ws_scrcpy_port();
        let probe = probe_tool(
            &self.runner,
            "node",
            &node.display().to_string(),
            &["--version"],
        )
        .map_err(|error| {
            vec![stream_unavailable(format!(
                "Node could not be probed: {error}"
            ))]
        })?;

        // ws-scrcpy binds loopback only, serves under the reverse-proxied base
        // path, and drives this add-on's own adb in "proxy over adb" interface mode
        // (the emulator quirk: scrcpy-server listens on the AVD's internal iface).
        let mut environment = self.addon.environment();
        environment.push(("WS_SCRCPY_HOST".to_owned(), "127.0.0.1".to_owned()));
        environment.push(("WS_SCRCPY_PORT".to_owned(), port.to_string()));
        environment.push(("WS_SCRCPY_PATHNAME".to_owned(), streaming.base_path.clone()));
        environment.push((
            "ADB".to_owned(),
            self.addon.adb_executable().display().to_string(),
        ));
        environment.push(("WS_SCRCPY_ADB_PROXY".to_owned(), "1".to_owned()));

        let process = self
            .runner
            .spawn(&ToolProcessRequest {
                probe,
                arguments: vec![entry.display().to_string()],
                working_directory,
                environment,
            })
            .map_err(|error| {
                vec![stream_unavailable(format!(
                    "ws-scrcpy could not be spawned: {error}"
                ))]
            })?;

        Ok(AndroidTargetStream {
            port,
            base_path: streaming.base_path.clone(),
            process: Some(process),
        })
    }

    /// A control channel over the booted target's adb serial, so the existing
    /// C2/C5 provisioner ([`crate::device_provision::DeviceProvisioner`]) runs
    /// against this exact device.
    #[must_use]
    pub fn control(&self) -> Arc<dyn SandboxControl> {
        Arc::new(crate::AdbControl::for_device(
            Arc::clone(&self.runner),
            self.adb.clone(),
            self.serial.clone(),
        ))
    }

    /// Powers the target off cleanly and stops the owned emulator process, then
    /// removes the AVD's lock files so the next launch boots without cleanup.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic when the process cannot be stopped.
    pub fn stop(mut self) -> Result<(), Vec<Diagnostic>> {
        let _ = invoke_tool_with_environment(
            &self.runner,
            &self.adb,
            &["-s", &self.serial, "emu", "kill"],
            Duration::from_secs(20),
            &self.environment,
        );
        if let Some(process) = self.process.take() {
            // Give the emulator time to exit on its own after `emu kill`, so it
            // releases its AVD locks itself; force-stopping it at once is what
            // leaves them behind. Force only if the grace period runs out.
            let deadline = Instant::now() + EMULATOR_EXIT_GRACE;
            while process.is_running() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(250));
            }
            if let Err(error) = process.stop() {
                return Err(vec![boot_failed(format!(
                    "the GUI Android target process could not be stopped: {error}"
                ))]);
            }
        }
        // The emulator is gone, so any lock left in the AVD directory is stale.
        clear_stale_avd_locks(&self.addon.root, &self.addon.manifest.avd_name);
        Ok(())
    }
}

/// A running ws-scrcpy stream bound to loopback (Phase D2). Owns the Node process
/// so it is stopped on teardown; the engine reverse-proxies its port behind the
/// workbench gate — it is never directly reachable.
pub struct AndroidTargetStream {
    port: u16,
    base_path: String,
    process: Option<ToolProcess>,
}

impl std::fmt::Debug for AndroidTargetStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AndroidTargetStream")
            .field("port", &self.port)
            .field("base_path", &self.base_path)
            .finish_non_exhaustive()
    }
}

impl AndroidTargetStream {
    /// The loopback port ws-scrcpy is bound to (the engine reverse-proxy upstream).
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The base path ws-scrcpy serves under and the engine proxies (`/android-stream/`).
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Whether the ws-scrcpy process is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.process.as_ref().is_some_and(ToolProcess::is_running)
    }

    /// Best-effort wait until ws-scrcpy accepts a loopback TCP connection, so the
    /// reverse-proxy's first forwarded request does not race the Node startup.
    /// Returns whether the port became reachable within `timeout`.
    #[must_use]
    pub fn wait_ready(&self, timeout: Duration) -> bool {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], self.port));
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !self.is_running() {
                return false;
            }
            if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }

    /// Stops the ws-scrcpy process.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the process cannot be stopped.
    pub fn stop(mut self) -> Result<(), Vec<Diagnostic>> {
        if let Some(process) = self.process.take()
            && let Err(error) = process.stop()
        {
            return Err(vec![stream_unavailable(format!(
                "the ws-scrcpy process could not be stopped: {error}"
            ))]);
        }
        Ok(())
    }
}

/// Polls `sys.boot_completed` until the AVD is up or the deadline elapses.
fn wait_for_boot(
    runner: &Arc<dyn ExternalToolRunner>,
    adb: &ToolProbe,
    serial: &str,
    environment: &[(String, String)],
    process: &ToolProcess,
    deadline: Duration,
) -> Result<(), Diagnostic> {
    let started = Instant::now();
    let _ = invoke_tool_with_environment(
        runner,
        adb,
        &["-s", serial, "wait-for-device"],
        deadline,
        environment,
    );
    loop {
        if !process.is_running() {
            return Err(catalogue::SANDBOX_BOOT_FAILED.instantiate(context(
                BACKEND_ID,
                "error",
                format!(
                    "the GUI Android target emulator exited before boot completed: {}",
                    process.stderr().trim()
                ),
            )));
        }
        if let Ok(output) = invoke_tool_with_environment(
            runner,
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
                BACKEND_ID,
                "error",
                format!(
                    "the GUI Android target did not reach sys.boot_completed=1 within {deadline:?}"
                ),
            )));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn boot_failed(detail: String) -> Diagnostic {
    catalogue::SANDBOX_BOOT_FAILED.instantiate(context(BACKEND_ID, "error", detail))
}

fn stream_unavailable(detail: String) -> Diagnostic {
    catalogue::ANDROID_STREAM_UNAVAILABLE.instantiate(context(BACKEND_ID, "error", detail))
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

/// The GUI Android target add-on root: an explicit `APIAXESS_ANDROID_TARGET`
/// override, otherwise the `android-target/` directory beside the install
/// (Windows) or under `share/apiaxess/` (Unix) — matching the other bundled
/// components and the analysis runtime.
#[must_use]
pub fn android_target_root() -> PathBuf {
    if let Some(configured) = std::env::var_os("APIAXESS_ANDROID_TARGET") {
        return PathBuf::from(configured);
    }
    let Some(bin) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    else {
        return PathBuf::from("android-target");
    };
    if cfg!(windows) {
        bin.join("..").join("android-target")
    } else {
        bin.join("..")
            .join("share")
            .join("apiaxess")
            .join("android-target")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique, empty scratch directory under the temp volume, matching the
    /// crate's `std::env::temp_dir()` test idiom (no `tempfile` dev-dep).
    struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            // A per-process counter, not just the clock: Windows' coarse clock
            // gave parallel tests the same timestamp, so they shared (and raced
            // on) one directory.
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "apiaxess-android-target-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).expect("create scratch dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write_manifest(&self, json: &str) {
            std::fs::write(self.path.join(MANIFEST_FILE), json).expect("write manifest");
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn sample_manifest_json(client_apk: &str) -> String {
        format!(
            r#"{{
                "schemaVersion": 1,
                "addonId": "android-target",
                "product": "APIaxess GUI Android target",
                "payloadVersion": "1.0.0-android13",
                "androidApiLevel": 33,
                "androidRelease": "13",
                "imageVariant": "default",
                "containsGms": false,
                "avdName": "apiaxess-android-target",
                "systemImage": "system-images;android-33;default;x86_64",
                "emulatorDir": "emulator",
                "platformToolsDir": "platform-tools",
                "avdDir": "avd",
                "consolePort": 5556,
                "ramMib": 2048,
                "wsScrcpyPort": 8000,
                "emulatorArgs": ["-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot"],
                "provisioning": {{
                    "installClientApk": true,
                    "installSessionCa": true,
                    "startFridaServer": true
                }},
                "artifacts": {{
                    "clientApk": "{client_apk}",
                    "fridaServer": "frida-server"
                }}
            }}"#
        )
    }

    #[test]
    fn parses_the_engine_manifest() {
        let manifest: AndroidTargetManifest =
            serde_json::from_str(&sample_manifest_json("artifacts/apiaxess-client.apk"))
                .expect("manifest parses");
        assert_eq!(manifest.addon_id, "android-target");
        assert_eq!(manifest.avd_name, "apiaxess-android-target");
        assert_eq!(manifest.console_port, 5556);
        assert_eq!(manifest.ws_scrcpy_port, 8000);
        assert_eq!(manifest.ram_mib, 2048);
        assert!(manifest.provisioning.install_session_ca);
        assert_eq!(manifest.artifacts.frida_server, "frida-server");
    }

    #[test]
    fn resolve_reads_paths_relative_to_the_root() {
        let dir = Scratch::new();
        dir.write_manifest(&sample_manifest_json("artifacts/apiaxess-client.apk"));

        let addon = AndroidTargetAddon::resolve_at(dir.path()).expect("resolves");
        assert_eq!(addon.device_serial(), "emulator-5556");
        assert_eq!(addon.ws_scrcpy_port(), 8000);
        assert_eq!(
            addon.emulator_executable(),
            dir.path().join("emulator").join(exe("emulator"))
        );
        assert_eq!(
            addon.adb_executable(),
            dir.path().join("platform-tools").join(exe("adb"))
        );
        assert_eq!(
            addon.client_apk(),
            dir.path().join("artifacts/apiaxess-client.apk")
        );
        assert_eq!(addon.frida_server_path(), dir.path().join("frida-server"));
    }

    #[test]
    fn missing_payload_reports_the_actionable_diagnostic() {
        let dir = Scratch::new();
        let error = AndroidTargetAddon::resolve_at(dir.path()).expect_err("no manifest");
        assert_eq!(error.id.as_ref(), catalogue::ANDROID_TARGET_MISSING.id);
    }

    #[test]
    fn malformed_manifest_reports_invalid_not_missing() {
        let dir = Scratch::new();
        std::fs::write(dir.path().join(MANIFEST_FILE), b"{ not valid json ").expect("write");
        let error = AndroidTargetAddon::resolve_at(dir.path()).expect_err("bad manifest");
        assert_eq!(
            error.id.as_ref(),
            catalogue::ANDROID_TARGET_MANIFEST_INVALID.id
        );
    }

    #[test]
    fn boot_arguments_are_headless_persistent_and_accel_aware() {
        let dir = Scratch::new();
        dir.write_manifest(&sample_manifest_json("artifacts/apiaxess-client.apk"));
        let addon = AndroidTargetAddon::resolve_at(dir.path()).expect("resolves");

        let accelerated = addon.boot_arguments(AccelerationMode::Accelerated);
        assert!(
            accelerated
                .windows(2)
                .any(|w| w == ["-avd", "apiaxess-android-target"])
        );
        assert!(accelerated.windows(2).any(|w| w == ["-port", "5556"]));
        assert!(accelerated.windows(2).any(|w| w == ["-accel", "on"]));
        assert!(accelerated.windows(2).any(|w| w == ["-memory", "2048"]));
        assert!(accelerated.iter().any(|a| a == "-no-window"));
        // A persistent GUI target: never wipe userdata, never quickboot-save.
        assert!(!accelerated.iter().any(|a| a == "-wipe-data"));

        let software = addon.boot_arguments(AccelerationMode::Software);
        assert!(software.windows(2).any(|w| w == ["-accel", "off"]));
    }

    #[test]
    fn preflight_flags_missing_engine_and_unstaged_client_apk() {
        let dir = Scratch::new();
        dir.write_manifest(&sample_manifest_json("artifacts/apiaxess-client.apk"));
        let addon = AndroidTargetAddon::resolve_at(dir.path()).expect("resolves");
        // Nothing staged: the engine binary and the client APK are both flagged.
        let preflight = addon.preflight();
        let ids: Vec<&str> = preflight.iter().map(|d| d.id.as_ref()).collect();
        assert!(ids.contains(&catalogue::ANDROID_TARGET_MISSING.id));
        assert!(ids.contains(&catalogue::ANDROID_TARGET_CLIENT_APK_MISSING.id));
    }

    #[test]
    fn manifest_without_streaming_resolves_with_no_stream_paths() {
        // A D1-era payload (no streaming block) parses; streaming is simply absent.
        let dir = Scratch::new();
        dir.write_manifest(&sample_manifest_json("artifacts/apiaxess-client.apk"));
        let addon = AndroidTargetAddon::resolve_at(dir.path()).expect("resolves");
        assert!(addon.streaming().is_none());
        assert!(addon.node_executable().is_none());
        assert!(addon.ws_scrcpy_entry().is_none());
    }

    #[test]
    fn manifest_with_streaming_resolves_the_node_and_ws_scrcpy_paths() {
        // The exact shape fetch-android-target.ps1 emits when streaming is staged.
        let json = r#"{
            "schemaVersion": 1,
            "addonId": "android-target",
            "payloadVersion": "1.0.0-android13",
            "avdName": "apiaxess-android-target",
            "systemImage": "system-images;android-33;default;x86_64",
            "emulatorDir": "emulator",
            "platformToolsDir": "platform-tools",
            "avdDir": "avd",
            "consolePort": 5556,
            "ramMib": 2048,
            "wsScrcpyPort": 8000,
            "emulatorArgs": ["-no-window"],
            "provisioning": { "installClientApk": true, "installSessionCa": true, "startFridaServer": true },
            "artifacts": { "clientApk": "artifacts/apiaxess-client.apk", "fridaServer": "frida-server" },
            "streaming": {
                "nodeDir": "node",
                "wsScrcpyDir": "ws-scrcpy",
                "wsScrcpyEntry": "dist/index.js",
                "basePath": "/android-stream/"
            }
        }"#;
        let dir = Scratch::new();
        dir.write_manifest(json);
        let addon = AndroidTargetAddon::resolve_at(dir.path()).expect("resolves");
        let streaming = addon.streaming().expect("streaming present");
        assert_eq!(streaming.base_path, "/android-stream/");
        assert_eq!(
            addon.node_executable().expect("node path"),
            dir.path().join("node").join(exe("node"))
        );
        assert_eq!(
            addon.ws_scrcpy_entry().expect("ws-scrcpy entry"),
            dir.path().join("ws-scrcpy").join("dist/index.js")
        );
        assert_eq!(
            addon.ws_scrcpy_dir().expect("ws-scrcpy dir"),
            dir.path().join("ws-scrcpy")
        );
    }
}
