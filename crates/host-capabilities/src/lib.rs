//! Capability declaration and detection seam.
//!
//! The plugin contract's handshake consumes this service's future observations
//! as supported/degraded/unavailable/unknown host-capability offers. Runtime
//! detection is evidence-backed and deliberately reports unknown as a gap.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticSeverity, DiagnosticValue,
    catalogue::HOST_CAPABILITY_GAP,
};
use apiaxess_external_tools::{
    ExternalToolRunner, ProcessToolRunner, ToolInvocationRequest, ToolProbeRequest,
    ToolRequirement, ToolVersion,
};
use serde::{Deserialize, Serialize};

/// Result of observing one host capability requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailability {
    /// Capability is fully available.
    Supported,
    /// Capability exists with a named limitation.
    Degraded,
    /// Capability is known not to be available.
    Unavailable,
    /// Detection could not establish availability.
    Unknown,
}

impl CapabilityAvailability {
    /// Whether a plan may use this capability without an explicit degraded-tier opt-in.
    #[must_use]
    pub const fn is_supported(self, allow_degraded: bool) -> bool {
        matches!(self, Self::Supported) || (allow_degraded && matches!(self, Self::Degraded))
    }
}

/// Evidence-backed host-capability observation consumed by future planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityObservation {
    /// Stable capability ID shared with the plugin handshake adapter.
    pub capability_id: String,
    /// Explicit availability; absence is never treated as support.
    pub availability: CapabilityAvailability,
    /// Human-readable detector evidence.
    pub evidence: String,
    /// Exact host-specific remediation or fallback selection.
    pub remediation: String,
    /// Capability rung that remains usable, when known.
    pub fallback_tier: Option<String>,
}

impl CapabilityObservation {
    /// Converts a non-supported observation into the canonical what/why/fix diagnostic.
    ///
    /// A supported observation produces no failure diagnostic. Detection remains
    /// out of scope; this is the stable reporting seam.
    #[must_use]
    pub fn gap_diagnostic(&self) -> Option<Diagnostic> {
        if self.availability == CapabilityAvailability::Supported {
            return None;
        }
        let availability = match self.availability {
            CapabilityAvailability::Supported => "supported",
            CapabilityAvailability::Degraded => "degraded",
            CapabilityAvailability::Unavailable => "unavailable",
            CapabilityAvailability::Unknown => "unknown",
        };
        let mut context = DiagnosticContext::new();
        context.insert(
            "capability_id".to_owned(),
            DiagnosticValue::String(self.capability_id.clone()),
        );
        context.insert(
            "availability".to_owned(),
            DiagnosticValue::String(availability.to_owned()),
        );
        context.insert(
            "evidence".to_owned(),
            DiagnosticValue::String(self.evidence.clone()),
        );
        context.insert(
            "remediation".to_owned(),
            DiagnosticValue::String(self.remediation.clone()),
        );
        if let Some(fallback) = &self.fallback_tier {
            context.insert(
                "fallback_tier".to_owned(),
                DiagnosticValue::String(fallback.clone()),
            );
        }
        let mut diagnostic = HOST_CAPABILITY_GAP.instantiate(context);
        diagnostic.severity = if self.availability == CapabilityAvailability::Degraded {
            DiagnosticSeverity::Warning
        } else {
            DiagnosticSeverity::Error
        };
        diagnostic.why = format!(
            "Capability `{}` is {availability}: {}",
            self.capability_id, self.evidence
        )
        .into_boxed_str();
        diagnostic.fix = if self.remediation.trim().is_empty() {
            "Run host capability detection again and select a reported fallback tier.".into()
        } else {
            self.remediation.clone().into_boxed_str()
        };
        Some(diagnostic)
    }
}

/// Placeholder service for the phase 0.1 physical boundary.
pub struct HostCapabilityService {
    runner: Arc<dyn ExternalToolRunner>,
    config: HostDetectionConfig,
}

impl Default for HostCapabilityService {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCapabilityService {
    /// Creates a detector using the production external-tool runner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(ProcessToolRunner),
            config: HostDetectionConfig::default(),
        }
    }

    /// Creates a detector with an injected external-tool runner.
    #[must_use]
    pub fn with_runner(runner: Arc<dyn ExternalToolRunner>) -> Self {
        Self {
            runner,
            config: HostDetectionConfig::default(),
        }
    }

    /// Creates a detector with explicit executable names and probe policy.
    #[must_use]
    pub fn with_config(runner: Arc<dyn ExternalToolRunner>, config: HostDetectionConfig) -> Self {
        Self { runner, config }
    }

    /// Detects the capabilities relevant to the Phase 3.1 sandbox tiers.
    #[must_use]
    pub fn detect(&self) -> HostCapabilityReport {
        let mut observations = vec![
            detect_virtualization(),
            self.detect_tool(
                CAPABILITY_AVD_EMULATOR,
                &self.config.emulator_executable,
                emulator_version_argument(),
            ),
            self.detect_tool(
                CAPABILITY_ANDROID_ADB,
                &self.config.adb_executable,
                "version",
            ),
            self.detect_emulator_acceleration(),
            detect_vm_posture(),
            self.detect_wsl2_nested_kvm(),
        ];

        let docker = self.detect_tool(
            CAPABILITY_DOCKER,
            &self.config.docker_executable,
            "version --format {{.Server.Version}}",
        );
        observations.push(docker.clone());
        if cfg!(target_os = "linux") {
            let privileged = match docker.availability {
                CapabilityAvailability::Supported => CapabilityObservation {
                    capability_id: CAPABILITY_DOCKER_PRIVILEGED.to_owned(),
                    availability: CapabilityAvailability::Degraded,
                    evidence: "Docker is reachable, but --privileged was not independently exercised during passive detection.".to_owned(),
                    remediation: "Run the redroid preflight to verify --privileged, or use AVD/remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                },
                _ => CapabilityObservation {
                    capability_id: CAPABILITY_DOCKER_PRIVILEGED.to_owned(),
                    availability: docker.availability,
                    evidence: docker.evidence.clone(),
                    remediation: "Install and start Docker with --privileged access, or use AVD/remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                },
            };
            observations.push(privileged);
            observations.push(detect_redroid_kernel());
        } else {
            observations.push(CapabilityObservation {
                capability_id: CAPABILITY_DOCKER_PRIVILEGED.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence:
                    "redroid's privileged shared-kernel contract is unavailable on this host."
                        .to_owned(),
                remediation: "Select AVD or remote-offload.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            });
            observations.push(CapabilityObservation {
                capability_id: CAPABILITY_REDOID_KERNEL.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence: "redroid is a native-Linux-only tier and is not supported on Windows."
                    .to_owned(),
                remediation: "Use the native Windows AVD tier or select remote-offload.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            });
        }
        observations.push(CapabilityObservation {
            capability_id: CAPABILITY_REMOTE_SSH.to_owned(),
            availability: CapabilityAvailability::Supported,
            evidence: "Remote capability is selected and verified by the secured backend during preflight.".to_owned(),
            remediation: "Configure a strict SSH key and pinned known-hosts file.".to_owned(),
            fallback_tier: None,
        });
        HostCapabilityReport { observations }
    }

    fn detect_wsl2_nested_kvm(&self) -> CapabilityObservation {
        if cfg!(target_os = "windows") {
            let probe = self.runner.probe(&ToolProbeRequest {
                tool_id: "virtualization.wsl2".to_owned(),
                executable: "wsl.exe".to_owned(),
                version_arguments: vec!["--version".to_owned()],
                requirement: ToolRequirement {
                    minimum: ToolVersion {
                        major: 0,
                        minor: 0,
                        patch: 0,
                    },
                },
            });
            let Ok(probe) = probe else {
                return CapabilityObservation {
                    capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
                    availability: CapabilityAvailability::Unavailable,
                    evidence: "wsl.exe was not available for a Linux /dev/kvm probe.".to_owned(),
                    remediation: "Install WSL2, enable nested virtualization, and ensure /dev/kvm is readable and writable by the WSL user; otherwise use remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                };
            };
            let result = self.runner.invoke(&ToolInvocationRequest {
                probe,
                arguments: vec![
                    "--".to_owned(),
                    "bash".to_owned(),
                    "-lc".to_owned(),
                    "uname -a; test -r /dev/kvm && test -w /dev/kvm && echo APIAXESS_WSL2_KVM_RW"
                        .to_owned(),
                ],
                working_directory: None,
                environment: Vec::new(),
                timeout: std::time::Duration::from_secs(15),
            });
            return match result {
                Ok(output) if output.stdout.contains("APIAXESS_WSL2_KVM_RW") => CapabilityObservation {
                    capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
                    availability: CapabilityAvailability::Supported,
                    evidence: format!("WSL2 /dev/kvm is readable and writable: {}", output.stdout.trim()),
                    remediation: "Keep Docker's Linux engine on the WSL2 backend and pass /dev/kvm to HQarroum.".to_owned(),
                    fallback_tier: Some("sandbox.avd".to_owned()),
                },
                Ok(output) => CapabilityObservation {
                    capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
                    availability: CapabilityAvailability::Unavailable,
                    evidence: format!("WSL2 probe did not confirm writable /dev/kvm: {}", output.stderr.trim()),
                    remediation: "Run wsl.exe -u root -- usermod -aG kvm <user>, terminate/restart the distro, and verify ls -l /dev/kvm; otherwise use remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                },
                Err(error) => CapabilityObservation {
                    capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
                    availability: CapabilityAvailability::Unavailable,
                    evidence: format!("WSL2 /dev/kvm probe failed: {error}"),
                    remediation: "Enable WSL2 nested virtualization and verify /dev/kvm access; otherwise use remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                },
            };
        }
        if cfg!(target_os = "linux") && is_wsl2_kernel() {
            let path = Path::new("/dev/kvm");
            return CapabilityObservation {
                capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
                availability: if fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .is_ok()
                {
                    CapabilityAvailability::Supported
                } else {
                    CapabilityAvailability::Unavailable
                },
                evidence: format!("WSL2 kernel detected; /dev/kvm path: {}", path.display()),
                remediation: "Grant the WSL user access to the kvm group and restart the distro; do not use TCG fallback.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            };
        }
        CapabilityObservation {
            capability_id: CAPABILITY_WSL2_NESTED_KVM.to_owned(),
            availability: CapabilityAvailability::Supported,
            evidence: "This host is not using the WSL2 nested-virtualization path.".to_owned(),
            remediation: "Use the native Linux KVM or native Windows hypervisor evidence for the selected local tier.".to_owned(),
            fallback_tier: None,
        }
    }

    fn detect_emulator_acceleration(&self) -> CapabilityObservation {
        let capability_id = CAPABILITY_AVD_ACCELERATION.to_owned();
        let probe = match self.runner.probe(&ToolProbeRequest {
            tool_id: CAPABILITY_AVD_EMULATOR.to_owned(),
            executable: self.config.emulator_executable.clone(),
            version_arguments: vec![emulator_version_argument().to_owned()],
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        }) {
            Ok(probe) => probe,
            Err(error) => {
                return CapabilityObservation {
                    capability_id,
                    availability: CapabilityAvailability::Unavailable,
                    evidence: format!("emulator probe failed before -accel-check: {error}"),
                    remediation: "Install/configure the Android emulator, enable KVM or WHPX, or select remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                };
            }
        };
        match self.runner.invoke(&ToolInvocationRequest {
            probe,
            arguments: vec!["-accel-check".to_owned()],
            working_directory: None,
            environment: Vec::new(),
            timeout: std::time::Duration::from_secs(30),
        }) {
            Ok(output) if output.exit_code == Some(0) => {
                let evidence = format!("{}{}", output.stdout, output.stderr);
                let lower = evidence.to_ascii_lowercase();
                let usable = ["kvm", "whpx", "aehd", "accel", "usable"]
                    .iter()
                    .any(|marker| lower.contains(marker));
                let degraded = cfg!(target_os = "windows")
                    && lower.contains("aehd")
                    && !lower.contains("whpx");
                CapabilityObservation {
                    capability_id,
                    availability: if !usable {
                        CapabilityAvailability::Unavailable
                    } else if degraded {
                        CapabilityAvailability::Degraded
                    } else {
                        CapabilityAvailability::Supported
                    },
                    evidence: format!("emulator -accel-check: {}", evidence.trim()),
                    remediation: "Enable the reported native accelerator or select remote-offload.".to_owned(),
                    fallback_tier: Some("remote-offload".to_owned()),
                }
            }
            Ok(output) => CapabilityObservation {
                capability_id,
                availability: CapabilityAvailability::Unavailable,
                evidence: format!(
                    "emulator -accel-check exited {:?}: {}{}",
                    output.exit_code, output.stdout, output.stderr
                ),
                remediation: "Enable KVM/WHPX on the native host or select remote-offload.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            },
            Err(error) => CapabilityObservation {
                capability_id,
                availability: CapabilityAvailability::Unavailable,
                evidence: format!("emulator -accel-check failed: {error}"),
                remediation: "Run APIaxess on the native host with usable acceleration, or select remote-offload.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            },
        }
    }

    fn detect_tool(
        &self,
        capability_id: &str,
        executable: &str,
        arguments: &str,
    ) -> CapabilityObservation {
        let request = ToolProbeRequest {
            tool_id: capability_id.to_owned(),
            executable: executable.to_owned(),
            version_arguments: arguments.split_whitespace().map(str::to_owned).collect(),
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        };
        match self.runner.probe(&request) {
            Ok(probe) => CapabilityObservation {
                capability_id: capability_id.to_owned(),
                availability: CapabilityAvailability::Supported,
                evidence: format!("{} reported version {}", probe.executable, probe.version),
                remediation: String::new(),
                fallback_tier: None,
            },
            Err(error) => CapabilityObservation {
                capability_id: capability_id.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence: error.to_string(),
                remediation: format!(
                    "Install or configure `{executable}`, then rerun capability detection."
                ),
                fallback_tier: Some("remote-offload".to_owned()),
            },
        }
    }
}

// TODO(macos-phase2): the bundled emulator's own preflight probes `-version` on
// every platform (sandbox `BundledEmulatorBackend`), while this host probe uses
// `--version` off Windows. Confirm which spelling the macOS emulator accepts
// and make the two agree.
fn emulator_version_argument() -> &'static str {
    if cfg!(target_os = "windows") {
        "-version"
    } else {
        "--version"
    }
}

/// Stable capability IDs used by sandbox planning and plugin handshakes.
pub const CAPABILITY_KVM: &str = "virtualization.kvm";
/// Stable Windows virtualization capability ID.
pub const CAPABILITY_WINDOWS_HYPERVISOR: &str = "virtualization.windows-hypervisor";
/// Stable Android emulator executable capability ID.
pub const CAPABILITY_AVD_EMULATOR: &str = "android.avd-emulator";
/// Stable ADB executable capability ID.
pub const CAPABILITY_ANDROID_ADB: &str = "android.adb";
/// Stable functional emulator-acceleration capability ID.
pub const CAPABILITY_AVD_ACCELERATION: &str = "android.avd-acceleration";
/// Stable Docker daemon capability ID.
pub const CAPABILITY_DOCKER: &str = "container.docker";
/// Stable Docker privileged-container capability ID.
pub const CAPABILITY_DOCKER_PRIVILEGED: &str = "container.docker-privileged";
/// Stable encrypted remote transport capability ID.
pub const CAPABILITY_REMOTE_SSH: &str = "remote.ssh-encrypted";
/// Stable native-Linux redroid kernel prerequisite capability ID.
pub const CAPABILITY_REDOID_KERNEL: &str = "container.redroid-kernel";
/// Stable VM/host-posture capability ID; guidance, not a CPUID-only gate.
pub const CAPABILITY_VM_POSTURE: &str = "virtualization.vm-posture";
/// WSL2 nested virtualization and user-accessible KVM device.
pub const CAPABILITY_WSL2_NESTED_KVM: &str = "virtualization.wsl2-nested-kvm";

/// Configuration for passive host capability probes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDetectionConfig {
    /// Emulator executable or PATH name.
    pub emulator_executable: String,
    /// ADB executable or PATH name.
    pub adb_executable: String,
    /// Docker executable or PATH name.
    pub docker_executable: String,
}

impl Default for HostDetectionConfig {
    fn default() -> Self {
        Self {
            emulator_executable: default_android_tool("emulator", "emulator"),
            adb_executable: default_android_tool("platform-tools", "adb"),
            docker_executable: "docker".to_owned(),
        }
    }
}

/// Candidate roots for the bundled analysis-runtime, mirroring
/// `sandbox::analysis_runtime_root()`: the `APIAXESS_ANALYSIS_RUNTIME` override
/// first, otherwise the install-relative `analysis-runtime/` directory.
fn analysis_runtime_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(configured) = std::env::var_os("APIAXESS_ANALYSIS_RUNTIME") {
        roots.push(PathBuf::from(configured));
    }
    if let Some(base) = apiaxess_install_layout::resource_base() {
        roots.push(base.join("analysis-runtime"));
    }
    roots
}

fn default_android_tool(directory: &str, executable: &str) -> String {
    let mut roots = Vec::new();
    // The bundled analysis-runtime emulator/platform-tools take precedence: the
    // dynamic backend runs THAT emulator, so the acceleration/adb capability
    // probes must inspect the same one. Otherwise the probe falls through to a
    // host SDK (or a bare name), and a broken/absent host emulator makes the
    // functional acceleration probe report `acceleration-check-failed` even
    // though the bundled emulator's WHPX is usable — contradicting the planner's
    // `accelerated-mode-active`. Matches sandbox::analysis_runtime_root().
    for root in analysis_runtime_roots() {
        roots.push(root);
    }
    for variable in ["ANDROID_HOME", "ANDROID_SDK_ROOT"] {
        if let Some(root) = std::env::var_os(variable) {
            roots.push(PathBuf::from(root));
        }
    }
    if cfg!(target_os = "windows") {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            roots.push(PathBuf::from(local_app_data).join("Android").join("Sdk"));
        }
    }
    let executable_name = if cfg!(target_os = "windows") {
        format!("{executable}.exe")
    } else {
        executable.to_owned()
    };
    roots
        .into_iter()
        .map(|root| root.join(directory).join(&executable_name))
        .find(|path| path.is_file())
        .map_or_else(|| executable.to_owned(), |path| path.display().to_string())
}

/// Complete, evidence-backed host capability matrix for sandbox planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostCapabilityReport {
    /// Individual observations; absence is never interpreted as support.
    pub observations: Vec<CapabilityObservation>,
}

impl HostCapabilityReport {
    /// Finds a capability observation by stable ID.
    #[must_use]
    pub fn get(&self, capability_id: &str) -> Option<&CapabilityObservation> {
        self.observations
            .iter()
            .find(|item| item.capability_id == capability_id)
    }

    /// Returns whether a capability is usable under the selected degradation policy.
    #[must_use]
    pub fn supports(&self, capability_id: &str, allow_degraded: bool) -> bool {
        self.get(capability_id)
            .is_some_and(|item| item.availability.is_supported(allow_degraded))
    }
}

fn detect_virtualization() -> CapabilityObservation {
    if cfg!(target_os = "linux") {
        let path = Path::new("/dev/kvm");
        if path.exists()
            && fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .is_ok()
        {
            CapabilityObservation {
                capability_id: CAPABILITY_KVM.to_owned(),
                availability: CapabilityAvailability::Supported,
                evidence: "The Linux KVM device exists and is readable/writable by the process."
                    .to_owned(),
                remediation: String::new(),
                fallback_tier: None,
            }
        } else if path.exists() {
            CapabilityObservation {
                capability_id: CAPABILITY_KVM.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence: "The Linux /dev/kvm device exists but could not be opened with read/write access.".to_owned(),
                remediation: "Grant the APIaxess user access to /dev/kvm or select remote-offload.".to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            }
        } else {
            CapabilityObservation {
                capability_id: CAPABILITY_KVM.to_owned(),
                availability: CapabilityAvailability::Unavailable,
                evidence:
                    "The Linux /dev/kvm device is absent; hardware acceleration is unavailable."
                        .to_owned(),
                remediation:
                    "Enable virtualization in BIOS/UEFI and load KVM, or use remote-offload."
                        .to_owned(),
                fallback_tier: Some("remote-offload".to_owned()),
            }
        }
    } else if cfg!(target_os = "windows") {
        let whpx = Path::new(r"C:\Windows\System32\WinHvPlatform.dll").exists();
        let aehd = Path::new(r"C:\Windows\System32\aehd.dll").exists();
        CapabilityObservation {
            capability_id: CAPABILITY_WINDOWS_HYPERVISOR.to_owned(),
            availability: if whpx {
                CapabilityAvailability::Supported
            } else if aehd {
                CapabilityAvailability::Degraded
            } else {
                CapabilityAvailability::Unavailable
            },
            evidence: format!(
                "WHPX detected: {whpx}; AEHD detected: {aehd}; WHPX is the durable path and AEHD is transitional."
            ),
            remediation: if whpx {
                String::new()
            } else if aehd {
                "Enable WHPX for the durable native path; AEHD is transitional and should not be a long-term dependency.".to_owned()
            } else {
                "Enable WHPX or select remote-offload.".to_owned()
            },
            fallback_tier: Some("remote-offload".to_owned()),
        }
    } else if cfg!(target_os = "macos") {
        // Hypervisor.framework acceleration is not probed yet: there is no macOS
        // emulator runtime to accelerate.
        CapabilityObservation {
            capability_id: CAPABILITY_KVM.to_owned(),
            availability: CapabilityAvailability::Unavailable,
            evidence: "Dynamic analysis is not yet available on macOS: this build has no macOS Android emulator runtime or Hypervisor.framework acceleration path."
                .to_owned(),
            remediation: "Use remote-offload, or run dynamic analysis on a supported Windows or Linux host."
                .to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        }
    } else {
        CapabilityObservation {
            capability_id: CAPABILITY_KVM.to_owned(),
            availability: CapabilityAvailability::Unavailable,
            evidence: "This operating system is outside the supported local virtualization matrix."
                .to_owned(),
            remediation: "Use a supported Linux/Windows host or select remote-offload.".to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        }
    }
}

fn detect_redroid_kernel() -> CapabilityObservation {
    if !cfg!(target_os = "linux") {
        return CapabilityObservation {
            capability_id: CAPABILITY_REDOID_KERNEL.to_owned(),
            availability: CapabilityAvailability::Unavailable,
            evidence: "redroid requires a native Linux kernel.".to_owned(),
            remediation: "Use AVD on Windows or Linux, or select remote-offload.".to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        };
    }
    let binder = ["/dev/binderfs", "/dev/binder"]
        .iter()
        .copied()
        .find(|path| Path::new(path).exists());
    let ashmem = Path::new("/dev/ashmem").exists();
    let memfd = kernel_supports_memfd();
    let supported = binder.is_some() && (ashmem || memfd);
    CapabilityObservation {
        capability_id: CAPABILITY_REDOID_KERNEL.to_owned(),
        availability: if supported {
            CapabilityAvailability::Supported
        } else {
            CapabilityAvailability::Unavailable
        },
        evidence: format!(
            "binder device: {}; ashmem: {ashmem}; memfd kernel floor: {memfd}",
            binder.unwrap_or("missing")
        ),
        remediation: "Load binder/binderfs and provide ashmem or memfd support on a native Linux host, or use AVD/remote-offload.".to_owned(),
        fallback_tier: Some("sandbox.avd".to_owned()),
    }
}

fn kernel_supports_memfd() -> bool {
    let Ok(value) = fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return false;
    };
    let mut parts = value
        .split(['.', '-'])
        .filter_map(|part| part.parse::<u32>().ok());
    matches!(
        (parts.next(), parts.next()),
        (Some(major), Some(minor)) if major > 3 || (major == 3 && minor >= 17)
    )
}

fn detect_vm_posture() -> CapabilityObservation {
    let mut signals = Vec::new();
    if cfg!(target_os = "linux") {
        if std::env::var_os("WSL_INTEROP").is_some() {
            signals.push("WSL2 environment variable");
        }
        if let Ok(version) = fs::read_to_string("/proc/version") {
            let lower = version.to_ascii_lowercase();
            if lower.contains("microsoft") || lower.contains("wsl") {
                signals.push("Linux kernel identifies Microsoft/WSL");
            }
        }
        for path in [
            "/sys/class/dmi/id/hypervisor_vendor",
            "/sys/class/dmi/id/sys_vendor",
        ] {
            if let Ok(value) = fs::read_to_string(path) {
                let lower = value.to_ascii_lowercase();
                if ["microsoft", "vmware", "virtualbox", "qemu", "kvm", "xen"]
                    .iter()
                    .any(|marker| lower.contains(marker))
                {
                    signals.push("DMI virtualization vendor");
                    break;
                }
            }
        }
    }
    if signals.is_empty() {
        CapabilityObservation {
            capability_id: CAPABILITY_VM_POSTURE.to_owned(),
            availability: CapabilityAvailability::Supported,
            evidence: "No supplemental VM signal was observed; functional acceleration remains authoritative.".to_owned(),
            remediation: String::new(),
            fallback_tier: None,
        }
    } else {
        CapabilityObservation {
            capability_id: CAPABILITY_VM_POSTURE.to_owned(),
            availability: CapabilityAvailability::Degraded,
            evidence: signals.join(", "),
            remediation: "Run APIaxess on the native host for local AVD, or select remote-offload; do not treat this guidance signal as a CPUID-only hard block.".to_owned(),
            fallback_tier: Some("remote-offload".to_owned()),
        }
    }
}

fn is_wsl2_kernel() -> bool {
    std::env::var_os("WSL_INTEROP").is_some()
        || fs::read_to_string("/proc/version")
            .map(|version| {
                let lower = version.to_ascii_lowercase();
                lower.contains("microsoft") || lower.contains("wsl")
            })
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{CapabilityAvailability, CapabilityObservation};
    use apiaxess_diagnostics::catalogue::HOST_CAPABILITY_GAP;

    #[test]
    fn unavailable_capability_names_exact_gap_and_remedy() {
        let observation = CapabilityObservation {
            capability_id: "virtualization.kvm".to_owned(),
            availability: CapabilityAvailability::Unavailable,
            evidence: "the KVM device is absent".to_owned(),
            remediation: "Select the remote Linux sandbox tier.".to_owned(),
            fallback_tier: Some("offloaded".to_owned()),
        };
        let diagnostic = observation.gap_diagnostic().unwrap();

        assert_eq!(diagnostic.id.as_ref(), HOST_CAPABILITY_GAP.id);
        assert_eq!(diagnostic.fix.as_ref(), observation.remediation);
        assert!(diagnostic.why.contains("virtualization.kvm"));
    }
}
