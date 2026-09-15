//! Phase C2: adb device provisioning.
//!
//! Detects a connected rooted adb device (physical USB device or same-machine
//! emulator), establishes the adb-reverse tunnel so the device's loopback reaches
//! the workbench proxy over adb (no LAN exposure, no loopback-origin relaxation),
//! and installs the live session CA into the device's system trust store using the
//! path appropriate to the device's Android version:
//!
//! * Android <= 13 — the legacy `/system/etc/security/cacerts` writable-system path,
//!   reused verbatim from [`crate::traffic::provision_system_ca`].
//! * Android 14+ — the Conscrypt APEX bind-mount path (also in `traffic`).
//!
//! Version detection routes automatically. Optionally starts the bundled
//! frida-server for a later pinned-app bypass (C4 does the per-app targeting).
//!
//! Every step surfaces a legible what/why/fix diagnostic, and the returned
//! [`ProvisionedDevice`] tears the reverse tunnel and the CA trust back down.

use std::{path::PathBuf, sync::Arc, time::Duration};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{ExternalToolRunner, ToolProbe};
use apiaxess_workbench_proxy::SessionCa;
use serde::{Deserialize, Serialize};

use crate::{
    AdbControl, SandboxControl,
    traffic::{
        CaTrustConfig, CaTrustReceipt, TrustMechanism, detect_android_sdk, provision_system_ca,
        select_trust_mechanism,
    },
};

/// adb-reported state of an attached device.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Attached and authorized — ready to provision.
    Ready,
    /// Attached but the host key has not been authorized on the device.
    Unauthorized,
    /// Attached but offline (booting, sleeping, or a stale transport).
    Offline,
    /// Any other adb-reported state.
    Unknown,
}

impl DeviceState {
    fn parse(raw: &str) -> Self {
        match raw {
            "device" => Self::Ready,
            "unauthorized" => Self::Unauthorized,
            "offline" => Self::Offline,
            _ => Self::Unknown,
        }
    }
}

/// One attached adb device from `adb devices -l`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedDevice {
    /// adb transport serial (`emulator-5554`, a USB serial, or `host:port`).
    pub serial: String,
    /// adb-reported state.
    pub state: DeviceState,
    /// Human-readable descriptor (product/model), when adb reports one.
    pub description: String,
}

/// One `adb reverse` mapping: the device loopback port tunnels to the workbench
/// loopback port over the adb transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PortMapping {
    /// Port on the device's `127.0.0.1` the app connects to.
    pub device_port: u16,
    /// Port on the workbench host's `127.0.0.1` it reaches.
    pub host_port: u16,
}

/// Inputs for provisioning one device.
#[derive(Clone, Debug)]
pub struct ProvisionOptions {
    /// Reverse mapping for the workbench MITM proxy (the reused capture transport).
    pub proxy: PortMapping,
    /// Optional reverse mapping for the device control channel.
    pub control: Option<PortMapping>,
    /// Session-safe suffix for temporary device paths.
    pub lease_id: String,
    /// Whether to also start the bundled frida-server (hook for C4).
    pub start_frida_server: bool,
    /// Host path to the bundled frida-server binary; required when
    /// `start_frida_server` is set.
    pub frida_server_path: Option<PathBuf>,
}

/// Summary of what provisioning did, retained for the operator surface.
#[derive(Clone, Debug)]
pub struct DeviceProvisionReport {
    /// Provisioned device serial.
    pub serial: String,
    /// Detected Android API level.
    pub android_sdk: u32,
    /// Trust-install mechanism chosen for that API level.
    pub mechanism: TrustMechanism,
    /// Reverse mappings established over adb.
    pub reverse_mappings: Vec<PortMapping>,
    /// Whether the optional frida-server is running.
    pub frida_server_started: bool,
    /// Ordered step diagnostics (info and any non-fatal warnings).
    pub diagnostics: Vec<Diagnostic>,
}

/// A fully provisioned device, owning the state needed for exact teardown.
pub struct ProvisionedDevice {
    control: Arc<dyn SandboxControl>,
    trust: Option<CaTrustReceipt>,
    reverse_mappings: Vec<PortMapping>,
    report: DeviceProvisionReport,
}

impl std::fmt::Debug for ProvisionedDevice {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProvisionedDevice")
            .field("serial", &self.report.serial)
            .field("android_sdk", &self.report.android_sdk)
            .field("mechanism", &self.report.mechanism)
            .finish_non_exhaustive()
    }
}

impl ProvisionedDevice {
    /// Provisioning summary, including the ordered step diagnostics.
    #[must_use]
    pub fn report(&self) -> &DeviceProvisionReport {
        &self.report
    }

    /// Removes the session CA trust and the reverse tunnel, returning the device
    /// to its pre-provision state.
    ///
    /// # Errors
    ///
    /// Returns the trust/tunnel teardown diagnostics that did not verify.
    pub fn teardown(mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Some(trust) = self.trust.take() {
            diagnostics.extend(trust.teardown().err().unwrap_or_default());
        }
        for mapping in &self.reverse_mappings {
            let removed = self.control.command(
                &[
                    "reverse".to_owned(),
                    "--remove".to_owned(),
                    format!("tcp:{}", mapping.device_port),
                ],
                Duration::from_secs(15),
            );
            if !removed.is_ok_and(|output| output.exit_code == Some(0)) {
                diagnostics.push(catalogue::DEVICE_REVERSE_TUNNEL_FAILED.instantiate(
                    diag_context(
                        self.control.transport_id(),
                        "operation",
                        format!("reverse --remove tcp:{} failed", mapping.device_port),
                    ),
                ));
            }
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// Drives adb device detection and provisioning for the workbench.
pub struct DeviceProvisioner {
    runner: Arc<dyn ExternalToolRunner>,
    adb_executable: String,
}

impl DeviceProvisioner {
    /// Creates a provisioner over an injected tool runner and adb executable
    /// (use [`crate::BundledEmulatorConfig::resolve`]'s `adb_executable` for the
    /// bundled platform-tools adb).
    #[must_use]
    pub fn new(runner: Arc<dyn ExternalToolRunner>, adb_executable: impl Into<String>) -> Self {
        Self {
            runner,
            adb_executable: adb_executable.into(),
        }
    }

    fn adb_probe(&self) -> Result<ToolProbe, Diagnostic> {
        crate::probe_tool(
            &self.runner,
            "android.adb",
            &self.adb_executable,
            &["version"],
        )
        .map_err(|error| {
            catalogue::SANDBOX_ADB_UNREACHABLE.instantiate(diag_context(
                "device.provision",
                "error",
                error.to_string(),
            ))
        })
    }

    /// Lists attached adb devices (`adb devices -l`).
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the adb executable cannot be probed or the
    /// listing command fails.
    pub fn detect_devices(&self) -> Result<Vec<DetectedDevice>, Diagnostic> {
        let probe = self.adb_probe()?;
        let output = crate::invoke_tool(
            &self.runner,
            &probe,
            &["devices".to_owned(), "-l".to_owned()],
            Duration::from_secs(30),
        )
        .map_err(|error| {
            catalogue::SANDBOX_ADB_UNREACHABLE.instantiate(diag_context(
                "device.provision",
                "error",
                error.to_string(),
            ))
        })?;
        Ok(parse_devices(&output.stdout))
    }

    /// Detects a single provisionable device, preferring a `Ready` one.
    ///
    /// Emits [`catalogue::DEVICE_DETECTED`] on success and returns a legible
    /// [`catalogue::DEVICE_NOT_DETECTED`] / [`catalogue::DEVICE_UNAUTHORIZED`]
    /// diagnostic otherwise.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no ready device is attached.
    pub fn detect_ready_device(&self) -> Result<(DetectedDevice, Diagnostic), Diagnostic> {
        let devices = self.detect_devices()?;
        if let Some(device) = devices
            .iter()
            .find(|device| device.state == DeviceState::Ready)
        {
            let detected = catalogue::DEVICE_DETECTED.instantiate(diag_context(
                "device.provision",
                "serial",
                device.serial.clone(),
            ));
            return Ok((device.clone(), detected));
        }
        if devices.iter().any(|device| {
            matches!(
                device.state,
                DeviceState::Unauthorized | DeviceState::Offline
            )
        }) {
            return Err(catalogue::DEVICE_UNAUTHORIZED.instantiate(DiagnosticContext::new()));
        }
        Err(catalogue::DEVICE_NOT_DETECTED.instantiate(DiagnosticContext::new()))
    }

    /// Builds a secured control channel for a device serial.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the adb executable cannot be probed.
    pub fn control_for(&self, serial: &str) -> Result<Arc<dyn SandboxControl>, Diagnostic> {
        let probe = self.adb_probe()?;
        Ok(Arc::new(AdbControl::for_device(
            Arc::clone(&self.runner),
            probe,
            serial.to_owned(),
        )))
    }

    /// Establishes only the adb-reverse tunnel(s) for a device — the transport a
    /// device needs to reach the workbench before pairing (Phase C5 arming).
    ///
    /// This installs no trust and grants no capability; it merely forwards the
    /// device's loopback ports to the workbench loopback so the device can present
    /// its pairing token. The trust-granting steps (system-CA install, frida) stay
    /// in [`Self::provision`], which runs only after the operator accepts.
    ///
    /// # Errors
    ///
    /// Returns the reverse-tunnel diagnostics when a mapping cannot be installed.
    pub fn establish_tunnel(
        &self,
        serial: &str,
        mappings: &[PortMapping],
    ) -> Result<(), Vec<Diagnostic>> {
        let control = self.control_for(serial).map_err(|error| vec![error])?;
        for mapping in mappings {
            establish_reverse(&control, *mapping)?;
        }
        Ok(())
    }

    /// Provisions a device end to end: reverse tunnel, version-routed system-CA
    /// install, and the optional frida-server start.
    ///
    /// # Errors
    ///
    /// Returns the failure diagnostics for the first step that could not
    /// complete; earlier successful steps' info diagnostics are dropped on the
    /// error path.
    pub fn provision(
        &self,
        serial: &str,
        ca: &SessionCa,
        options: &ProvisionOptions,
    ) -> Result<ProvisionedDevice, Vec<Diagnostic>> {
        let control = self.control_for(serial).map_err(|error| vec![error])?;
        let mut report = DeviceProvisionReport {
            serial: serial.to_owned(),
            android_sdk: 0,
            mechanism: TrustMechanism::AvdWritableSystem,
            reverse_mappings: Vec::new(),
            frida_server_started: false,
            diagnostics: Vec::new(),
        };

        // 1. Reverse tunnel mappings: device loopback -> workbench loopback.
        let mut mappings = vec![options.proxy];
        if let Some(control_mapping) = options.control {
            mappings.push(control_mapping);
        }

        // 2. Detect the Android version and route to the correct install path.
        let sdk = detect_android_sdk(&control)?;
        let mechanism = select_trust_mechanism(sdk)?;
        report.android_sdk = sdk;
        report.mechanism = mechanism;
        report.diagnostics.push(
            catalogue::DEVICE_TRUST_PATH_SELECTED.instantiate(version_context(
                control.transport_id(),
                sdk,
                mechanism,
            )),
        );

        // 3. Ensure root before touching the read-only system/APEX trust store.
        ensure_device_root(&control)?;

        // 3b. Establish the reverse tunnel(s) AFTER escalating to root. `adb root`
        // restarts adbd, which drops every existing `adb reverse` mapping — so a
        // tunnel set up before this step would be silently wiped, leaving the
        // paired client unable to reach the workbench control/proxy loopback
        // ("Failed to connect to 127.0.0.1:<port>"). Establishing them here, after
        // the last adbd restart, makes the transport durable on Windows and Linux.
        for mapping in &mappings {
            establish_reverse(&control, *mapping)?;
        }
        report.reverse_mappings.clone_from(&mappings);
        report
            .diagnostics
            .push(catalogue::DEVICE_TUNNEL_READY.instantiate(diag_context(
                control.transport_id(),
                "proxy",
                format!(
                    "device tcp:{} -> workbench tcp:{}",
                    options.proxy.device_port, options.proxy.host_port
                ),
            )));

        // 4. Install the session CA system-trusted via the version-routed path.
        let trust = provision_system_ca(
            Arc::clone(&control),
            ca,
            &CaTrustConfig {
                mechanism,
                lease_id: options.lease_id.clone(),
            },
        )?;
        report
            .diagnostics
            .push(catalogue::DEVICE_CA_INSTALLED.instantiate(version_context(
                control.transport_id(),
                sdk,
                mechanism,
            )));

        // 5. Optional frida-server start (hook for C4). Non-fatal: interception
        // over the installed CA already works for unpinned apps.
        if options.start_frida_server {
            match start_frida_server(&control, options) {
                Ok(diagnostic) => {
                    report.frida_server_started = true;
                    report.diagnostics.push(diagnostic);
                }
                Err(diagnostic) => report.diagnostics.push(diagnostic),
            }
        }

        // 6. Re-assert the reverse tunnel(s) as the final step. Everything above
        // (CA install, frida start) can, on a device whose adbd was NOT already
        // root, trigger another `adb root`/`adb unroot` adbd restart that silently
        // drops the mappings from step 3b. `adb reverse` is idempotent (re-adding
        // replaces), so re-asserting here guarantees the transport is live when the
        // client connects — regardless of how many adbd restarts happened. This is
        // the belt-and-braces that closes the non-root-adbd tunnel-survival case.
        for mapping in &mappings {
            establish_reverse(&control, *mapping)?;
        }

        Ok(ProvisionedDevice {
            control,
            trust: Some(trust),
            reverse_mappings: mappings,
            report,
        })
    }
}

/// Establishes one `adb reverse` mapping.
fn establish_reverse(
    control: &Arc<dyn SandboxControl>,
    mapping: PortMapping,
) -> Result<(), Vec<Diagnostic>> {
    if mapping.device_port == 0 || mapping.host_port == 0 {
        return Err(vec![catalogue::DEVICE_REVERSE_TUNNEL_FAILED.instantiate(
            diag_context(
                control.transport_id(),
                "error",
                "reverse tunnel ports must be non-zero".to_owned(),
            ),
        )]);
    }
    let output = control
        .command(
            &[
                "reverse".to_owned(),
                format!("tcp:{}", mapping.device_port),
                format!("tcp:{}", mapping.host_port),
            ],
            Duration::from_secs(30),
        )
        .map_err(|error| {
            vec![
                catalogue::DEVICE_REVERSE_TUNNEL_FAILED.instantiate(diag_context(
                    control.transport_id(),
                    "error",
                    error.to_string(),
                )),
            ]
        })?;
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(vec![catalogue::DEVICE_REVERSE_TUNNEL_FAILED.instantiate(
            diag_context(control.transport_id(), "stderr", output.stderr),
        )])
    }
}

/// Elevates the adb daemon to root and confirms `uid=0`, retrying across the
/// racy adbd restart. Emits [`catalogue::DEVICE_ROOT_REFUSED`] on failure.
fn ensure_device_root(control: &Arc<dyn SandboxControl>) -> Result<(), Vec<Diagnostic>> {
    for _ in 0..3 {
        let _ = control.command(&["root".to_owned()], Duration::from_secs(30));
        let _ = control.command(&["wait-for-device".to_owned()], Duration::from_secs(60));
        if let Ok(output) = control.shell(&["id".to_owned()], Duration::from_secs(10)) {
            if output.stdout.contains("uid=0") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(vec![catalogue::DEVICE_ROOT_REFUSED.instantiate(
        diag_context(
            control.transport_id(),
            "error",
            "adb root did not yield a uid=0 shell".to_owned(),
        ),
    )])
}

/// Deploys and starts the bundled frida-server on the device.
fn start_frida_server(
    control: &Arc<dyn SandboxControl>,
    options: &ProvisionOptions,
) -> Result<Diagnostic, Diagnostic> {
    let host_path = options.frida_server_path.as_ref().ok_or_else(|| {
        catalogue::DEVICE_FRIDA_SERVER_UNAVAILABLE.instantiate(diag_context(
            control.transport_id(),
            "error",
            "no bundled frida-server path was supplied".to_owned(),
        ))
    })?;
    let bytes = std::fs::read(host_path).map_err(|error| {
        catalogue::DEVICE_FRIDA_SERVER_UNAVAILABLE.instantiate(diag_context(
            control.transport_id(),
            "host_path",
            format!("{}: {error}", host_path.display()),
        ))
    })?;
    let remote = format!(
        "/data/local/tmp/apiaxess-frida-{}/frida-server",
        safe_suffix(&options.lease_id)
    );
    let unavailable = |detail: String| {
        catalogue::DEVICE_FRIDA_SERVER_UNAVAILABLE.instantiate(diag_context(
            control.transport_id(),
            "operation",
            detail,
        ))
    };
    control
        .put(&bytes, &remote, Duration::from_secs(60))
        .map_err(|error| unavailable(format!("push frida-server: {error}")))?;
    frida_shell_ok(
        control,
        &["chmod".to_owned(), "0755".to_owned(), remote.clone()],
    )
    .map_err(|detail| unavailable(format!("chmod frida-server: {detail}")))?;
    frida_shell_ok(
        control,
        &[
            "sh".to_owned(),
            "-c".to_owned(),
            format!("{remote} >/dev/null 2>&1 &"),
        ],
    )
    .map_err(|detail| unavailable(format!("start frida-server: {detail}")))?;
    let pid = control
        .shell(
            &["pidof".to_owned(), "frida-server".to_owned()],
            Duration::from_secs(15),
        )
        .map_err(|error| unavailable(format!("pidof frida-server: {error}")))?;
    if pid.exit_code != Some(0) || pid.stdout.trim().is_empty() {
        return Err(unavailable(
            "frida-server did not report a live process".to_owned(),
        ));
    }
    Ok(
        catalogue::DEVICE_FRIDA_SERVER_STARTED.instantiate(diag_context(
            control.transport_id(),
            "pid",
            pid.stdout.trim().to_owned(),
        )),
    )
}

fn frida_shell_ok(control: &Arc<dyn SandboxControl>, command: &[String]) -> Result<(), String> {
    let output = control
        .shell(command, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(output.stderr)
    }
}

/// Parses `adb devices -l` output into detected devices.
fn parse_devices(stdout: &str) -> Vec<DetectedDevice> {
    stdout
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("List of devices"))
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let serial = fields.next()?.to_owned();
            let state = fields.next()?;
            let description = fields.collect::<Vec<_>>().join(" ");
            Some(DetectedDevice {
                serial,
                state: DeviceState::parse(state),
                description,
            })
        })
        .collect()
}

fn safe_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(40)
        .collect()
}

fn diag_context(backend: &str, key: &str, value: String) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String(backend.to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value));
    context
}

fn version_context(backend: &str, sdk: u32, mechanism: TrustMechanism) -> DiagnosticContext {
    let mut context = diag_context(backend, "android_sdk", sdk.to_string());
    context.insert(
        "mechanism".to_owned(),
        DiagnosticValue::String(format!("{mechanism:?}")),
    );
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_adb_devices_listing_states() {
        let listing = "List of devices attached\n\
             emulator-5554          device product:sdk_gphone model:Pixel transport_id:1\n\
             ABCDEF0123             unauthorized usb:1-1\n\
             99887766               offline\n\
             \n";
        let devices = parse_devices(listing);
        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].serial, "emulator-5554");
        assert_eq!(devices[0].state, DeviceState::Ready);
        assert!(devices[0].description.contains("model:Pixel"));
        assert_eq!(devices[1].state, DeviceState::Unauthorized);
        assert_eq!(devices[2].state, DeviceState::Offline);
    }

    #[test]
    fn parses_empty_listing() {
        assert!(parse_devices("List of devices attached\n").is_empty());
        assert!(parse_devices("").is_empty());
    }

    #[test]
    fn device_state_parse_covers_known_states() {
        assert_eq!(DeviceState::parse("device"), DeviceState::Ready);
        assert_eq!(
            DeviceState::parse("unauthorized"),
            DeviceState::Unauthorized
        );
        assert_eq!(DeviceState::parse("offline"), DeviceState::Offline);
        assert_eq!(DeviceState::parse("recovery"), DeviceState::Unknown);
    }
}
