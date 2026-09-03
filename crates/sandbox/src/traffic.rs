//! Phase 3.2 traffic routing, QUIC downgrade, and disposable system trust.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{
    ExternalToolRunner, ToolInvocationRequest, ToolProbeRequest, ToolProcess, ToolProcessRequest,
    ToolRequirement, ToolVersion,
};
use apiaxess_session::Session;
use apiaxess_workbench_proxy::{FlowObserver, ProxyCore, SessionCa, TransparentFrontend};
use serde::{Deserialize, Serialize};

use crate::{
    RemoteConfig, SandboxCaptureBridge, SandboxCaptureEndpoint, SandboxCleanup,
    SandboxCommandOutput, SandboxControl, SandboxLease, SandboxTier,
};

/// Packet-filter mechanism used inside the Android runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3Mechanism {
    /// Android legacy packet filter and NAT interface.
    Iptables,
    /// Modern packet filter interface.
    Nftables,
}

/// Transparent routing configuration for one session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3RoutingConfig {
    /// Host or gateway address visible from Android.
    pub proxy_host: String,
    /// Port on which the session proxy is reachable from Android.
    pub proxy_port: u16,
    /// Redirect target port inside the runtime.
    pub redirect_port: u16,
    /// Packet-filter implementation.
    pub mechanism: L3Mechanism,
    /// Session-safe rule suffix.
    pub lease_id: String,
}

/// Exact rules installed for a session, retained for verified teardown.
pub struct L3RoutingReceipt {
    control: Arc<dyn SandboxControl>,
    mechanism: L3Mechanism,
    add_rules: Vec<Vec<String>>,
    remove_rules: Vec<Vec<String>>,
}

impl std::fmt::Debug for L3RoutingReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("L3RoutingReceipt")
            .field("mechanism", &self.mechanism)
            .field("rule_count", &self.add_rules.len())
            .finish_non_exhaustive()
    }
}

impl L3RoutingReceipt {
    /// Removes the UDP/443 drop and all TCP redirection rules.
    pub fn teardown(self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        match self.mechanism {
            L3Mechanism::Iptables => {
                for rule in self.remove_rules.iter().rev() {
                    if !successful(&self.control.shell(rule, Duration::from_secs(15))) {
                        diagnostics.push(routing_teardown_diagnostic(
                            self.control.transport_id(),
                            format!("iptables rule removal failed: {rule:?}"),
                        ));
                    }
                }
            }
            L3Mechanism::Nftables => {
                if !successful(
                    &self
                        .control
                        .shell(&self.remove_rules[0], Duration::from_secs(15)),
                ) {
                    diagnostics.push(routing_teardown_diagnostic(
                        self.control.transport_id(),
                        "nftables table removal failed".to_owned(),
                    ));
                }
            }
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// Installs transparent TCP redirection and the mandatory UDP/443 QUIC drop.
pub fn install_l3_routing(
    control: Arc<dyn SandboxControl>,
    config: &L3RoutingConfig,
) -> Result<L3RoutingReceipt, Vec<Diagnostic>> {
    if config.proxy_host.trim().is_empty() || config.proxy_port == 0 || config.redirect_port == 0 {
        return Err(vec![
            catalogue::SANDBOX_L3_REDIRECTION_UNAVAILABLE.instantiate(context(
                control.transport_id(),
                "reason",
                "proxy host and ports must be explicit".to_owned(),
            )),
        ]);
    }
    let (add_rules, remove_rules) = match config.mechanism {
        L3Mechanism::Iptables => iptables_rules(config),
        L3Mechanism::Nftables => nftables_rules(config),
    };
    let mut installed: Vec<Vec<String>> = Vec::new();
    for rule in &add_rules {
        let result = control.shell(rule, Duration::from_secs(15));
        if !successful(&result) {
            if config.mechanism == L3Mechanism::Nftables {
                let _ = control.shell(&remove_rules[0], Duration::from_secs(15));
            } else {
                for rollback in installed.iter().enumerate().rev() {
                    let _ = control.shell(&remove_rules[rollback.0], Duration::from_secs(15));
                }
            }
            let diagnostic =
                if rule.iter().any(|item| item == "443") && rule.iter().any(|item| item == "udp") {
                    catalogue::SANDBOX_QUIC_DROP_UNAVAILABLE
                } else if result
                    .as_ref()
                    .err()
                    .is_some_and(|error| error.id.as_ref() == "sandbox.proxy-unreachable")
                {
                    catalogue::SANDBOX_L3_REDIRECTION_UNAVAILABLE
                } else {
                    catalogue::SANDBOX_L3_REDIRECTION_SETUP_FAILED
                };
            return Err(vec![diagnostic.instantiate(context(
                control.transport_id(),
                "error",
                format!("rule rejected: {rule:?}"),
            ))]);
        }
        installed.push(rule.clone());
    }
    Ok(L3RoutingReceipt {
        control,
        mechanism: config.mechanism,
        add_rules,
        remove_rules,
    })
}

fn iptables_rules(config: &L3RoutingConfig) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let bypass = vec![
        "iptables".to_owned(),
        "-t".to_owned(),
        "nat".to_owned(),
        "-A".to_owned(),
        "OUTPUT".to_owned(),
        "-p".to_owned(),
        "tcp".to_owned(),
        "-d".to_owned(),
        config.proxy_host.clone(),
        "--dport".to_owned(),
        config.proxy_port.to_string(),
        "-j".to_owned(),
        "RETURN".to_owned(),
    ];
    let redirect = vec![
        "iptables".to_owned(),
        "-t".to_owned(),
        "nat".to_owned(),
        "-A".to_owned(),
        "OUTPUT".to_owned(),
        "-p".to_owned(),
        "tcp".to_owned(),
        "-j".to_owned(),
        "DNAT".to_owned(),
        "--to-destination".to_owned(),
        format!("{}:{}", config.proxy_host, config.redirect_port),
    ];
    let quic = vec![
        "iptables".to_owned(),
        "-A".to_owned(),
        "OUTPUT".to_owned(),
        "-p".to_owned(),
        "udp".to_owned(),
        "--dport".to_owned(),
        "443".to_owned(),
        "-j".to_owned(),
        "DROP".to_owned(),
    ];
    let remove = |rule: &[String]| {
        let mut value = rule.to_vec();
        if let Some(position) = value.iter().position(|item| item == "-A") {
            "-D".clone_into(&mut value[position]);
        }
        value
    };
    let add = vec![bypass, redirect, quic];
    let remove = add.iter().map(|rule| remove(rule)).collect();
    (add, remove)
}

fn nftables_rules(config: &L3RoutingConfig) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let table = format!("apiaxess_{}", safe_suffix(&config.lease_id));
    let add = vec![
        vec![
            "nft".to_owned(),
            "add".to_owned(),
            "table".to_owned(),
            "inet".to_owned(),
            table.clone(),
        ],
        vec![
            "nft".to_owned(),
            "add".to_owned(),
            "chain".to_owned(),
            "inet".to_owned(),
            table.clone(),
            "output".to_owned(),
            "{".to_owned(),
            "type".to_owned(),
            "nat".to_owned(),
            "hook".to_owned(),
            "output".to_owned(),
            "priority".to_owned(),
            "-100".to_owned(),
            ";".to_owned(),
            "policy".to_owned(),
            "accept".to_owned(),
            ";".to_owned(),
            "}".to_owned(),
        ],
        vec![
            "nft".to_owned(),
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.clone(),
            "output".to_owned(),
            "ip".to_owned(),
            "daddr".to_owned(),
            config.proxy_host.clone(),
            "tcp".to_owned(),
            "dport".to_owned(),
            config.proxy_port.to_string(),
            "return".to_owned(),
        ],
        vec![
            "nft".to_owned(),
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.clone(),
            "output".to_owned(),
            "tcp".to_owned(),
            "dnat".to_owned(),
            "to".to_owned(),
            format!("{}:{}", config.proxy_host, config.redirect_port),
        ],
        vec![
            "nft".to_owned(),
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.clone(),
            "output".to_owned(),
            "udp".to_owned(),
            "dport".to_owned(),
            "443".to_owned(),
            "drop".to_owned(),
        ],
    ];
    (
        add,
        vec![vec![
            "nft".to_owned(),
            "delete".to_owned(),
            "table".to_owned(),
            "inet".to_owned(),
            table,
        ]],
    )
}

/// System trust mechanism selected for the runtime tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustMechanism {
    /// `adb root`/`adb remount` and hashed system cacerts path.
    AvdWritableSystem,
    /// Disposable overlay mount over redroid's system cacerts directory.
    RedroidOverlay,
}

/// Trust provisioning configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaTrustConfig {
    /// Mechanism appropriate for the selected runtime.
    pub mechanism: TrustMechanism,
    /// Host `openssl` executable used for `subject_hash_old`.
    pub openssl_executable: String,
    /// Session-safe path suffix.
    pub lease_id: String,
}

impl CaTrustConfig {
    /// Selects the disposable trust path from the sandbox tier.
    #[must_use]
    pub fn for_tier(
        tier: SandboxTier,
        openssl_executable: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> Self {
        let mechanism = match tier {
            // The bundled AOSP emulator uses the same writable-system + adb root
            // CA-install path as the legacy AVD.
            SandboxTier::BundledEmulator | SandboxTier::Avd => TrustMechanism::AvdWritableSystem,
            SandboxTier::Redroid | SandboxTier::RemoteOffload => TrustMechanism::RedroidOverlay,
        };
        Self {
            mechanism,
            openssl_executable: openssl_executable.into(),
            lease_id: lease_id.into(),
        }
    }
}

/// Receipt for exact trust-state cleanup.
pub struct CaTrustReceipt {
    control: Arc<dyn SandboxControl>,
    mechanism: TrustMechanism,
    installed_path: String,
    temporary_path: String,
    overlay_root: Option<String>,
}

impl std::fmt::Debug for CaTrustReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaTrustReceipt")
            .field("mechanism", &self.mechanism)
            .field("installed_path", &self.installed_path)
            .finish_non_exhaustive()
    }
}

impl CaTrustReceipt {
    /// Removes the exact certificate and any disposable overlay mount.
    pub fn teardown(self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        // Both the redroid overlay and the Android-10 tmpfs trust mount install
        // the CA *inside* a disposable mount over the trust directory (signalled
        // by `overlay_root`). Unmounting reverts the directory to the pristine
        // read-only lower filesystem, so the hashed CA disappears with it and
        // needs no separate file removal. The writable-system copy path (no mount)
        // removes the exact hashed file instead.
        if self.overlay_root.is_some() {
            if !successful(&self.control.shell(
                &[
                    "umount".to_owned(),
                    "/system/etc/security/cacerts".to_owned(),
                ],
                Duration::from_secs(15),
            )) {
                diagnostics.push(ca_teardown_diagnostic(
                    self.control.transport_id(),
                    "trust overlay unmount failed",
                ));
            }
        } else if !successful(
            &self
                .control
                .remove(&self.installed_path, Duration::from_secs(15)),
        ) {
            diagnostics.push(ca_teardown_diagnostic(
                self.control.transport_id(),
                "hashed system CA removal failed",
            ));
        }
        if !successful(
            &self
                .control
                .remove(&self.temporary_path, Duration::from_secs(15)),
        ) {
            diagnostics.push(ca_teardown_diagnostic(
                self.control.transport_id(),
                "temporary CA removal failed",
            ));
        }
        if let Some(root) = self.overlay_root {
            if !successful(&self.control.shell(
                &["rm".to_owned(), "-rf".to_owned(), root],
                Duration::from_secs(15),
            )) {
                diagnostics.push(ca_teardown_diagnostic(
                    self.control.transport_id(),
                    "overlay state removal failed",
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

/// Provisions the Phase-2 session CA into Android system-level trust.
#[allow(clippy::too_many_lines)]
pub fn provision_system_ca(
    control: Arc<dyn SandboxControl>,
    runner: &Arc<dyn ExternalToolRunner>,
    ca: &SessionCa,
    config: &CaTrustConfig,
) -> Result<CaTrustReceipt, Vec<Diagnostic>> {
    let hash = subject_hash_old(runner, &config.openssl_executable, ca)?;
    let temporary_path = format!(
        "/data/local/tmp/apiaxess-{}.pem",
        safe_suffix(&config.lease_id)
    );
    control
        .put(
            ca.root_certificate_der(),
            &temporary_path,
            Duration::from_secs(30),
        )
        .map_err(|error| {
            vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
                control.transport_id(),
                "error",
                error.to_string(),
            ))]
        })?;
    let (installed_path, overlay_root) = match config.mechanism {
        TrustMechanism::AvdWritableSystem => {
            // The emulator was booted `-writable-system`; gain root so we can mount.
            control
                .command(&["root".to_owned()], Duration::from_secs(30))
                .map_err(|error| {
                    vec![catalogue::SANDBOX_CA_REMOUNT_FAILED.instantiate(context(
                        control.transport_id(),
                        "error",
                        error.to_string(),
                    ))]
                })?;
            // On Android 10 (API 29) `/system` stays read-only under dm-verity even
            // after `adb remount` (which reports success), so a plain copy into
            // `/system/etc/security/cacerts` fails with "Read-only file system".
            // Instead, stage the platform's existing trust anchors plus the session
            // CA, mount a disposable tmpfs over the trust directory (a new mount is
            // permitted even when the lower fs is read-only, and needs no
            // disable-verity reboot), and repopulate it — preserving the platform
            // anchors so the app's other TLS keeps validating.
            let directory = "/system/etc/security/cacerts".to_owned();
            let stage = format!(
                "/data/local/tmp/apiaxess-cacerts-{}",
                safe_suffix(&config.lease_id)
            );
            ensure_shell(
                &control,
                &["mkdir".to_owned(), "-p".to_owned(), stage.clone()],
                "cacerts staging directory",
            )?;
            // Direct commands only — a `sh -c "<script>"` string is re-split by
            // `adb shell` so the script's words become the shell's positional
            // parameters instead of the command's arguments. Passed directly, the
            // glob is expanded by the guest shell `adb shell` spawns.
            ensure_shell(
                &control,
                &[
                    "cp".to_owned(),
                    "-f".to_owned(),
                    format!("{directory}/*"),
                    format!("{stage}/"),
                ],
                "stage existing trust anchors",
            )?;
            ensure_shell(
                &control,
                &[
                    "cp".to_owned(),
                    "-f".to_owned(),
                    temporary_path.clone(),
                    format!("{stage}/{hash}.0"),
                ],
                "stage session CA",
            )?;
            ensure_shell(
                &control,
                &[
                    "mount".to_owned(),
                    "-t".to_owned(),
                    "tmpfs".to_owned(),
                    "tmpfs".to_owned(),
                    directory.clone(),
                ],
                "cacerts tmpfs mount",
            )?;
            ensure_shell(
                &control,
                &[
                    "cp".to_owned(),
                    "-f".to_owned(),
                    format!("{stage}/*"),
                    format!("{directory}/"),
                ],
                "repopulate trust anchors",
            )?;
            ensure_shell(
                &control,
                &["chmod".to_owned(), "644".to_owned(), format!("{directory}/*")],
                "trust anchor permissions",
            )?;
            ensure_shell(
                &control,
                &[
                    "chown".to_owned(),
                    "root:root".to_owned(),
                    format!("{directory}/*"),
                ],
                "trust anchor ownership",
            )?;
            // Best-effort SELinux relabel so the anchors carry the expected type.
            let _ = control.shell(
                &["restorecon".to_owned(), "-R".to_owned(), directory.clone()],
                Duration::from_secs(30),
            );
            (format!("{directory}/{hash}.0"), Some(stage))
        }
        TrustMechanism::RedroidOverlay => {
            let root = format!(
                "/data/local/tmp/apiaxess-overlay-{}",
                safe_suffix(&config.lease_id)
            );
            let upper = format!("{root}/upper");
            let work = format!("{root}/work");
            for path in [&upper, &work, &format!("{upper}/etc/security/cacerts")] {
                ensure_shell(
                    &control,
                    &["mkdir".to_owned(), "-p".to_owned(), (*path).clone()],
                    "overlay directory creation",
                )?;
            }
            let target = format!("{upper}/etc/security/cacerts/{hash}.0");
            install_hashed_ca(&control, &temporary_path, &target)?;
            ensure_shell(
                &control,
                &[
                    "mount".to_owned(),
                    "-t".to_owned(),
                    "overlay".to_owned(),
                    "overlay".to_owned(),
                    "-o".to_owned(),
                    format!(
                        "lowerdir=/system/etc/security/cacerts,upperdir={upper}/etc/security/cacerts,workdir={work}"
                    ),
                    "/system/etc/security/cacerts".to_owned(),
                ],
                "overlay mount",
            )?;
            (format!("/system/etc/security/cacerts/{hash}.0"), Some(root))
        }
    };
    verify_installed_ca(
        &control,
        &temporary_path,
        &installed_path,
        config.mechanism == TrustMechanism::AvdWritableSystem,
    )?;
    Ok(CaTrustReceipt {
        control,
        mechanism: config.mechanism,
        installed_path,
        temporary_path,
        overlay_root,
    })
}

fn install_hashed_ca(
    control: &Arc<dyn SandboxControl>,
    temporary: &str,
    target: &str,
) -> Result<(), Vec<Diagnostic>> {
    ensure_shell(
        control,
        &["cp".to_owned(), temporary.to_owned(), target.to_owned()],
        "CA copy",
    )?;
    ensure_shell(
        control,
        &["chmod".to_owned(), "0644".to_owned(), target.to_owned()],
        "CA permissions",
    )?;
    ensure_shell(
        control,
        &[
            "chown".to_owned(),
            "root:root".to_owned(),
            target.to_owned(),
        ],
        "CA ownership",
    )?;
    ensure_shell(
        control,
        &["restorecon".to_owned(), target.to_owned()],
        "CA SELinux relabel",
    )
}

fn verify_installed_ca(
    control: &Arc<dyn SandboxControl>,
    temporary: &str,
    target: &str,
    require_system_label: bool,
) -> Result<(), Vec<Diagnostic>> {
    ensure_shell(
        control,
        &["test".to_owned(), "-s".to_owned(), target.to_owned()],
        "CA file presence",
    )?;
    ensure_shell(
        control,
        &[
            "cmp".to_owned(),
            "-s".to_owned(),
            temporary.to_owned(),
            target.to_owned(),
        ],
        "CA content verification",
    )?;
    let metadata = control
        .shell(
            &[
                "stat".to_owned(),
                "-c".to_owned(),
                "%a:%U:%G".to_owned(),
                target.to_owned(),
            ],
            Duration::from_secs(15),
        )
        .map_err(|error| {
            vec![ca_verify_diagnostic(
                control.transport_id(),
                error.to_string(),
            )]
        })?;
    if metadata.exit_code != Some(0) || metadata.stdout.trim() != "644:root:root" {
        return Err(vec![ca_verify_diagnostic(
            control.transport_id(),
            format!(
                "CA file metadata was {:?}: expected 644:root:root, got {}",
                metadata.exit_code,
                metadata.stdout.trim()
            ),
        )]);
    }
    if require_system_label {
        let label = control
            .shell(
                &["ls".to_owned(), "-Zd".to_owned(), target.to_owned()],
                Duration::from_secs(15),
            )
            .map_err(|error| {
                vec![ca_verify_diagnostic(
                    control.transport_id(),
                    error.to_string(),
                )]
            })?;
        if label.exit_code != Some(0) || !label.stdout.contains("system_security_cacerts_file") {
            return Err(vec![ca_verify_diagnostic(
                control.transport_id(),
                format!(
                    "CA file SELinux label was {:?}: {}",
                    label.exit_code,
                    label.stdout.trim()
                ),
            )]);
        }
    }
    Ok(())
}

fn ensure_shell(
    control: &Arc<dyn SandboxControl>,
    command: &[String],
    operation: &str,
) -> Result<(), Vec<Diagnostic>> {
    let output = control
        .shell(command, Duration::from_secs(30))
        .map_err(|error| {
            vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
                control.transport_id(),
                "operation",
                format!("{operation}: {error}"),
            ))]
        })?;
    if output.exit_code == Some(0) {
        Ok(())
    } else {
        Err(vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(
            context(
                control.transport_id(),
                "operation",
                format!("{operation}: {}", output.stderr),
            ),
        )])
    }
}

fn subject_hash_old(
    runner: &Arc<dyn ExternalToolRunner>,
    executable: &str,
    ca: &SessionCa,
) -> Result<String, Vec<Diagnostic>> {
    let path = std::env::temp_dir().join(format!(
        "apiaxess-ca-hash-{}.pem",
        crate::generated_lease_id()
    ));
    std::fs::write(&path, ca.root_certificate_pem()).map_err(|error| {
        vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
            "sandbox.ca",
            "error",
            error.to_string(),
        ))]
    })?;
    let probe = runner
        .probe(&ToolProbeRequest {
            tool_id: "crypto.openssl".to_owned(),
            executable: executable.to_owned(),
            version_arguments: vec!["version".to_owned()],
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        })
        .map_err(|error| {
            vec![
                catalogue::SANDBOX_CA_SYSTEM_STORE_UNAVAILABLE.instantiate(context(
                    "sandbox.ca",
                    "error",
                    error.to_string(),
                )),
            ]
        })?;
    let output = runner.invoke(&ToolInvocationRequest {
        probe,
        arguments: vec![
            "x509".to_owned(),
            "-subject_hash_old".to_owned(),
            "-in".to_owned(),
            path.display().to_string(),
            "-noout".to_owned(),
        ],
        working_directory: None,
        environment: Vec::new(),
        timeout: Duration::from_secs(30),
    });
    let _ = std::fs::remove_file(&path);
    let output = output.map_err(|error| {
        vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
            "sandbox.ca",
            "error",
            error.to_string(),
        ))]
    })?;
    let hash = output
        .stdout
        .lines()
        .find(|line| {
            line.trim().len() == 8
                && line
                    .trim()
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
        })
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if hash.is_empty() {
        return Err(vec![catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(
            context("sandbox.ca", "openssl_output", output.stdout),
        )]);
    }
    Ok(hash)
}

/// A secured SSH local forward for remote captured traffic.
pub struct RemoteTrafficStream {
    process: Option<ToolProcess>,
    local_addr: SocketAddr,
}
impl std::fmt::Debug for RemoteTrafficStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteTrafficStream")
            .field("local_addr", &self.local_addr)
            .field("active", &self.process.is_some())
            .finish()
    }
}
impl RemoteTrafficStream {
    /// Starts an encrypted SSH local forward to the remote proxy listener.
    pub fn start(
        runner: &Arc<dyn ExternalToolRunner>,
        config: &RemoteConfig,
        local_proxy_addr: SocketAddr,
        remote_bind_port: u16,
    ) -> Result<Self, Diagnostic> {
        let ssh = runner
            .probe(&ToolProbeRequest {
                tool_id: "remote.ssh-encrypted".to_owned(),
                executable: config.ssh_executable.clone(),
                version_arguments: vec!["-V".to_owned()],
                requirement: ToolRequirement {
                    minimum: ToolVersion {
                        major: 0,
                        minor: 0,
                        patch: 0,
                    },
                },
            })
            .map_err(|error| {
                catalogue::SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED.instantiate(context(
                    "sandbox.remote-offload",
                    "error",
                    error.to_string(),
                ))
            })?;
        if remote_bind_port == 0 || local_proxy_addr.port() == 0 {
            return Err(
                catalogue::SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED.instantiate(context(
                    "sandbox.remote-offload",
                    "error",
                    "stream ports must be non-zero".to_owned(),
                )),
            );
        }
        let mut args = vec![
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=yes".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", config.known_hosts_file.display()),
            "-i".to_owned(),
            config.identity_file.display().to_string(),
            "-R".to_owned(),
            format!(
                "127.0.0.1:{remote_bind_port}:127.0.0.1:{}",
                local_proxy_addr.port()
            ),
            format!("{}@{}", config.user, config.host),
            config.helper_path.clone(),
            "stream".to_owned(),
            "--listen-port".to_owned(),
            remote_bind_port.to_string(),
        ];
        let process = runner
            .spawn(&ToolProcessRequest {
                probe: ssh,
                arguments: std::mem::take(&mut args),
                working_directory: None,
                environment: Vec::new(),
            })
            .map_err(|error| {
                catalogue::SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED.instantiate(context(
                    "sandbox.remote-offload",
                    "error",
                    error.to_string(),
                ))
            })?;
        Ok(Self {
            process: Some(process),
            local_addr: SocketAddr::from(([127, 0, 0, 1], remote_bind_port)),
        })
    }
    /// Local endpoint forwarded through encrypted SSH.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    /// Stops and reaps the encrypted forward.
    pub fn stop(mut self) -> Result<(), Diagnostic> {
        self.process.take().map_or(Ok(()), |process| {
            process.stop().map_err(|error| {
                catalogue::SANDBOX_REMOTE_TRAFFIC_STREAM_FAILED.instantiate(context(
                    "sandbox.remote-offload",
                    "error",
                    error.to_string(),
                ))
            })
        })
    }
}

fn successful(result: &Result<SandboxCommandOutput, Diagnostic>) -> bool {
    result
        .as_ref()
        .is_ok_and(|output| output.exit_code == Some(0))
}
fn safe_suffix(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(40)
        .collect()
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
fn routing_teardown_diagnostic(backend: &str, error: String) -> Diagnostic {
    catalogue::SANDBOX_L3_REDIRECTION_TEARDOWN_FAILED.instantiate(context(backend, "error", error))
}
fn ca_teardown_diagnostic(backend: &str, error: &str) -> Diagnostic {
    catalogue::SANDBOX_CA_TEARDOWN_FAILED.instantiate(context(backend, "error", error.to_owned()))
}
fn ca_verify_diagnostic(backend: &str, error: String) -> Diagnostic {
    catalogue::SANDBOX_CA_TRUST_VERIFICATION_FAILED.instantiate(context(backend, "error", error))
}

struct CaptureCleanup {
    trust: Option<CaTrustReceipt>,
    routing: Option<L3RoutingReceipt>,
    stream: Option<RemoteTrafficStream>,
    bridge: Option<Box<dyn SandboxCaptureBridge>>,
}
impl SandboxCleanup for CaptureCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Some(trust) = self.trust.take() {
            diagnostics.extend(trust.teardown().err().unwrap_or_default());
        }
        if let Some(routing) = self.routing.take() {
            diagnostics.extend(routing.teardown().err().unwrap_or_default());
        }
        if let Some(stream) = self.stream.take() {
            if let Err(error) = stream.stop() {
                diagnostics.push(error);
            }
        }
        if let Some(mut bridge) = self.bridge.take() {
            diagnostics.extend(bridge.cleanup().err().unwrap_or_default());
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

/// End-to-end session capture setup joining the sandbox to the existing proxy.
pub struct SandboxTrafficSession {
    proxy: Option<ProxyCore>,
    /// Transparent front-end that converts L3-redirected (no-CONNECT) TLS into
    /// explicit CONNECTs to `proxy`, so redirected guest HTTPS is intercepted.
    frontend: Option<TransparentFrontend>,
    lease: Option<SandboxLease>,
    proxy_addr: SocketAddr,
    capture_endpoint: SandboxCaptureEndpoint,
}
impl std::fmt::Debug for SandboxTrafficSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SandboxTrafficSession")
            .field("proxy_addr", &self.proxy_addr)
            .field("capture_endpoint", &self.capture_endpoint)
            .field("proxy_running", &self.proxy.is_some())
            .finish_non_exhaustive()
    }
}
impl SandboxTrafficSession {
    /// Returns the secured runtime control while capture is active.
    #[must_use]
    pub fn control(&self) -> Option<Arc<dyn SandboxControl>> {
        self.lease.as_ref().map(SandboxLease::control)
    }

    /// Starts the existing Phase-2 proxy, CA trust, L3 routing, and QUIC drop.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn start(
        mut proxy: ProxyCore,
        mut lease: SandboxLease,
        session: &Session,
        ca: SessionCa,
        observer: Arc<dyn FlowObserver>,
        routing: L3RoutingConfig,
        trust: CaTrustConfig,
        runner: Arc<dyn ExternalToolRunner>,
        remote_stream: Option<(RemoteConfig, SocketAddr)>,
    ) -> Result<Self, Vec<Diagnostic>> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], routing.proxy_port));
        let hudsucker_addr = proxy
            .start(session, bind_addr, ca.clone(), observer)
            .await
            .map_err(|error| vec![error])?;
        // Front the hudsucker listener with the transparent-interception
        // converter. Redirected guest traffic (no CONNECT) targets the
        // front-end, which recovers the TLS SNI and synthesizes a CONNECT so the
        // proven explicit MITM engages; the guest-visible capture endpoint and
        // the iptables redirect therefore point at the front-end, not hudsucker
        // directly. Explicit clients (the web path) are untouched — they keep
        // using their own workbench proxy.
        let hudsucker_loopback = SocketAddr::from(([127, 0, 0, 1], hudsucker_addr.port()));
        let frontend = match TransparentFrontend::start(hudsucker_loopback).await {
            Ok(frontend) => frontend,
            Err(error) => {
                let _ = proxy.shutdown().await;
                return Err(vec![catalogue::SANDBOX_L3_REDIRECTION_SETUP_FAILED.instantiate(
                    context(
                        "sandbox.traffic",
                        "transparent_frontend",
                        error.to_string(),
                    ),
                )]);
            }
        };
        let proxy_addr = frontend.local_addr();
        let mut bridge = lease.take_capture_bridge();
        let endpoint = match bridge.as_mut() {
            Some(bridge) => match bridge.prepare(proxy_addr) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let _ = bridge.cleanup();
                    let _ = proxy.shutdown().await;
                    return Err(vec![error]);
                }
            },
            None => SandboxCaptureEndpoint {
                host: routing.proxy_host.clone(),
                port: proxy_addr.port(),
                topology: "direct-sandbox-proxy".to_owned(),
            },
        };
        let control = lease.control();
        let trust_receipt = match provision_system_ca(control.clone(), &runner, &ca, &trust) {
            Ok(receipt) => receipt,
            Err(mut errors) => {
                if let Some(mut bridge) = bridge.take() {
                    errors.extend(bridge.cleanup().err().unwrap_or_default());
                }
                let _ = proxy.shutdown().await;
                errors.push(catalogue::SANDBOX_CA_INJECTION_FAILED.instantiate(context(
                    control.transport_id(),
                    "phase",
                    "trust provisioning".to_owned(),
                )));
                return Err(errors);
            }
        };
        let mut routing = routing;
        routing.proxy_host.clone_from(&endpoint.host);
        routing.proxy_port = endpoint.port;
        routing.redirect_port = endpoint.port;
        let routing_receipt =
            match install_l3_routing(control.clone(), &routing) {
                Ok(receipt) => receipt,
                Err(mut errors) => {
                    if let Some(mut bridge) = bridge.take() {
                        errors.extend(bridge.cleanup().err().unwrap_or_default());
                    }
                    let _ = trust_receipt.teardown();
                    let _ = proxy.shutdown().await;
                    errors.push(catalogue::SANDBOX_L3_REDIRECTION_SETUP_FAILED.instantiate(
                        context(control.transport_id(), "phase", "routing".to_owned()),
                    ));
                    return Err(errors);
                }
            };
        // Direct command (no `sh -c`): `adb shell` re-splits a `sh -c "<script>"`
        // string so the script's words land as the shell's positional parameters
        // rather than nc's arguments. `-w 5` bounds the probe without redirections.
        let endpoint_probe = control.shell(
            &[
                "toybox".to_owned(),
                "nc".to_owned(),
                "-w".to_owned(),
                "5".to_owned(),
                endpoint.host.clone(),
                endpoint.port.to_string(),
            ],
            Duration::from_secs(15),
        );
        if !successful(&endpoint_probe) {
            let mut errors =
                vec![
                    catalogue::SANDBOX_CAPTURE_ENDPOINT_UNREACHABLE.instantiate(context(
                        control.transport_id(),
                        "error",
                        format!(
                            "endpoint {}:{} probe failed: {endpoint_probe:?}",
                            endpoint.host, endpoint.port
                        ),
                    )),
                ];
            errors.extend(routing_receipt.teardown().err().unwrap_or_default());
            errors.extend(trust_receipt.teardown().err().unwrap_or_default());
            if let Some(mut bridge) = bridge.take() {
                errors.extend(bridge.cleanup().err().unwrap_or_default());
            }
            let _ = proxy.shutdown().await;
            return Err(errors);
        }
        let stream = if let Some((remote_config, remote_addr)) = remote_stream {
            match RemoteTrafficStream::start(
                &runner,
                &remote_config,
                proxy_addr,
                remote_addr.port(),
            ) {
                Ok(stream) => Some(stream),
                Err(error) => {
                    let mut errors = vec![error];
                    errors.extend(trust_receipt.teardown().err().unwrap_or_default());
                    errors.extend(routing_receipt.teardown().err().unwrap_or_default());
                    if let Some(mut bridge) = bridge.take() {
                        errors.extend(bridge.cleanup().err().unwrap_or_default());
                    }
                    let _ = proxy.shutdown().await;
                    return Err(errors);
                }
            }
        } else {
            None
        };
        lease.add_cleanup(Box::new(CaptureCleanup {
            trust: Some(trust_receipt),
            routing: Some(routing_receipt),
            stream,
            bridge,
        }));
        Ok(Self {
            proxy: Some(proxy),
            frontend: Some(frontend),
            lease: Some(lease),
            proxy_addr,
            capture_endpoint: endpoint,
        })
    }
    /// Endpoint to use in sandbox routing diagnostics and provenance.
    #[must_use]
    pub const fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }
    /// Guest-visible endpoint that forwards to [`Self::proxy_addr`].
    #[must_use]
    pub fn capture_endpoint(&self) -> &SandboxCaptureEndpoint {
        &self.capture_endpoint
    }
    /// Returns a warning when setup completed but no decryptable flow arrived.
    #[must_use]
    pub fn no_decryptable_traffic(&self) -> Diagnostic {
        catalogue::SANDBOX_NO_DECRYPTABLE_TRAFFIC.instantiate(context(
            "sandbox.traffic",
            "proxy_endpoint",
            self.proxy_addr.to_string(),
        ))
    }
    /// Returns a diagnostic when UDP/443 attempts were not seen to fall back.
    #[must_use]
    pub fn quic_downgrade_failed(&self, evidence: impl Into<String>) -> Diagnostic {
        let mut diagnostic = catalogue::SANDBOX_QUIC_DOWNGRADE_FAILED.instantiate(context(
            "sandbox.traffic",
            "proxy_endpoint",
            self.proxy_addr.to_string(),
        ));
        diagnostic.why = evidence.into().into_boxed_str();
        diagnostic
    }
    /// Shuts down the proxy, then removes trust, routing, and remote stream state.
    pub async fn teardown(mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        // Stop accepting redirected connections before shutting down the proxy
        // they bridge to.
        if let Some(frontend) = self.frontend.take() {
            frontend.shutdown().await;
        }
        if let Some(mut proxy) = self.proxy.take() {
            if let Err(error) = proxy.shutdown().await {
                diagnostics.push(error);
            }
        }
        if let Some(lease) = self.lease.take() {
            diagnostics.extend(lease.teardown().err().unwrap_or_default());
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(diagnostics)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CaTrustConfig, L3Mechanism, L3RoutingConfig, TrustMechanism, iptables_rules};
    use crate::SandboxTier;

    #[test]
    fn iptables_plan_always_drops_udp_443_and_bypasses_proxy_endpoint() {
        let (add, remove) = iptables_rules(&L3RoutingConfig {
            proxy_host: "10.0.2.2".to_owned(),
            proxy_port: 18080,
            redirect_port: 18080,
            mechanism: L3Mechanism::Iptables,
            lease_id: "lease-test".to_owned(),
        });
        assert!(add.iter().any(
            |rule| rule.windows(2).any(|pair| pair == ["udp", "--dport"])
                && rule.contains(&"443".to_owned())
                && rule.contains(&"DROP".to_owned())
        ));
        assert!(add.iter().any(|rule| {
            rule.contains(&"DNAT".to_owned())
                && rule.contains(&"--to-destination".to_owned())
                && rule.contains(&"10.0.2.2:18080".to_owned())
        }));
        assert_eq!(add.len(), remove.len());
        assert!(remove.iter().all(|rule| rule.contains(&"-D".to_owned())));
    }

    #[test]
    fn trust_path_is_selected_from_runtime_tier() {
        assert_eq!(
            CaTrustConfig::for_tier(SandboxTier::Avd, "openssl", "lease-test").mechanism,
            TrustMechanism::AvdWritableSystem
        );
        assert_eq!(
            CaTrustConfig::for_tier(SandboxTier::Redroid, "openssl", "lease-test").mechanism,
            TrustMechanism::RedroidOverlay
        );
    }
}
