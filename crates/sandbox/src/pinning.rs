//! Automated, session-scoped certificate-pinning bypass.
//!
//! This module owns the Phase 3.3 dynamic runtime boundary. Techniques are
//! declarative data, while lanes only execute a plan through the existing
//! external-tool and sandbox-control ports. APK tooling remains external;
//! Frida is driven through linked frida-core only in the optional
//! `frida-embedded` product variant.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use apiaxess_artifact_intake::NormalizedUnpackedArtifact;
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{
    ExternalToolRunner, ToolInvocationRequest, ToolProbe, ToolProbeRequest, ToolProcess,
    ToolRequirement, ToolVersion,
};
use serde::{Deserialize, Serialize};

use crate::{SandboxCleanup, SandboxCommandOutput, SandboxControl, SandboxLease};

/// Declarative return behavior for one verifier hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnStrategy {
    /// Return `false`, used by boolean pin/hostname checks.
    BooleanFalse,
    /// Return `null`, used by void/object verification paths.
    Null,
    /// Return an empty accepted chain/collection.
    EmptyCollection,
    /// Return `true`, used by positive hostname/verifier callbacks.
    BooleanTrue,
    /// Invoke the original implementation without changing its result.
    PassThrough,
}

/// One community-extensible pinning technique mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassSpec {
    /// Stable technique ID.
    pub technique_id: String,
    /// Optional package glob. `*` matches every package.
    pub package_pattern: String,
    /// Java/Mono class or runtime target.
    pub target_class: String,
    /// Method or callback name.
    pub target_method: String,
    /// Human-readable overload signature.
    pub signature: String,
    /// Replacement behavior.
    pub return_strategy: ReturnStrategy,
}

impl BypassSpec {
    /// Creates a declarative Java hook specification.
    #[must_use]
    pub fn java(
        technique_id: impl Into<String>,
        package_pattern: impl Into<String>,
        target_class: impl Into<String>,
        target_method: impl Into<String>,
        signature: impl Into<String>,
        return_strategy: ReturnStrategy,
    ) -> Self {
        Self {
            technique_id: technique_id.into(),
            package_pattern: package_pattern.into(),
            target_class: target_class.into(),
            target_method: target_method.into(),
            signature: signature.into(),
            return_strategy,
        }
    }

    fn applies_to(&self, package_name: &str) -> bool {
        glob_matches(&self.package_pattern, package_name)
    }
}

/// Registry of declarative techniques. Plugins add siblings through `register`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassTechniqueRegistry {
    specs: Vec<BypassSpec>,
}

impl BypassTechniqueRegistry {
    /// Creates the built-in common Java/platform technique set.
    #[must_use]
    pub fn builtins() -> Self {
        let mut registry = Self::default();
        for spec in [
            BypassSpec::java(
                "java.okhttp.certificate-pinner.check",
                "*",
                "okhttp3.CertificatePinner",
                "check",
                "(java.lang.String,java.util.List)",
                ReturnStrategy::Null,
            ),
            BypassSpec::java(
                "java.okhttp.certificate-pinner.check-array",
                "*",
                "okhttp3.CertificatePinner",
                "check",
                "(java.lang.String,java.security.cert.Certificate[])",
                ReturnStrategy::Null,
            ),
            // OkHttp 4.x performs the actual pin check + throw in the internal
            // `check$okhttp(String, Function0)` during the TLS handshake, not the
            // public `check` overloads above — so this is the overload that must be
            // neutralized for OkHttp 4.x pinned apps.
            BypassSpec::java(
                "java.okhttp.certificate-pinner.check-okhttp",
                "*",
                "okhttp3.CertificatePinner",
                "check$okhttp",
                "(java.lang.String,kotlin.jvm.functions.Function0)",
                ReturnStrategy::Null,
            ),
            BypassSpec::java(
                "java.x509-trust-manager.check-server-trusted",
                "*",
                "javax.net.ssl.X509TrustManager",
                "checkServerTrusted",
                "(java.security.cert.X509Certificate[],java.lang.String)",
                ReturnStrategy::EmptyCollection,
            ),
            BypassSpec::java(
                "java.hostname-verifier.verify",
                "*",
                "javax.net.ssl.HostnameVerifier",
                "verify",
                "(java.lang.String,javax.net.ssl.SSLSession)",
                ReturnStrategy::BooleanTrue,
            ),
            BypassSpec::java(
                "java.network-security-config.pin-set",
                "*",
                "android.security.net.config.PinSet",
                "getPins",
                "()",
                ReturnStrategy::EmptyCollection,
            ),
            BypassSpec::java(
                "java.conscrypt.trust-manager.verify-chain",
                "*",
                "com.android.org.conscrypt.TrustManagerImpl",
                "verifyChain",
                "(java.util.List,java.util.List,java.lang.String,byte[])",
                ReturnStrategy::EmptyCollection,
            ),
            BypassSpec::java(
                "java.conscrypt.trust-manager.check-trusted-recursive",
                "*",
                "com.android.org.conscrypt.TrustManagerImpl",
                "checkTrustedRecursive",
                "(java.security.cert.X509Certificate[],java.security.cert.X509Certificate[],java.lang.String,boolean,java.util.List,java.util.List)",
                ReturnStrategy::EmptyCollection,
            ),
            BypassSpec::java(
                "java.conscrypt.trust-manager.verify-chain-org",
                "*",
                "org.conscrypt.TrustManagerImpl",
                "verifyChain",
                "(java.util.List,java.util.List,java.lang.String,byte[])",
                ReturnStrategy::EmptyCollection,
            ),
        ] {
            registry.register(spec);
        }
        registry
    }

    /// Adds one declarative technique without changing a central lane switch.
    pub fn register(&mut self, spec: BypassSpec) {
        self.specs.push(spec);
    }

    /// Returns all registered specs applicable to a package.
    #[must_use]
    pub fn for_package(&self, package_name: &str) -> Vec<BypassSpec> {
        self.specs
            .iter()
            .filter(|spec| spec.applies_to(package_name))
            .cloned()
            .collect()
    }

    /// All registered specs, for plugin inventory and audit output.
    #[must_use]
    pub fn specs(&self) -> &[BypassSpec] {
        &self.specs
    }
}

/// Framework identity used by automatic lane selection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameworkKind {
    /// Ordinary Java/platform networking.
    Java,
    /// Flutter's native `BoringSSL` implementation.
    Flutter,
    /// Xamarin/.NET running on Mono.
    XamarinDotNet,
}

/// Known honest escalation boundary.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationBoundary {
    /// Hardware-backed key or integrity attestation.
    HardwareBackedAttestation,
    /// Stripped NDK pinning with dynamic memory obfuscation.
    StrippedNdkDynamicObfuscation,
    /// Client certificate/private-key mTLS boundary.
    ClientMtls,
    /// Anti-Frida RASP terminates the process during early load.
    AntiFridaRasp,
}

impl EscalationBoundary {
    fn label(self) -> &'static str {
        match self {
            Self::HardwareBackedAttestation => "hardware-backed key attestation",
            Self::StrippedNdkDynamicObfuscation => {
                "stripped NDK pinning with dynamic memory obfuscation"
            }
            Self::ClientMtls => "client-side mTLS requiring private-key extraction",
            Self::AntiFridaRasp => "anti-Frida RASP during early load",
        }
    }
}

/// One APK in the normalized package set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetApk {
    /// Stable split ID.
    pub id: String,
    /// Original APK path.
    pub path: PathBuf,
    /// Whether this is the base APK.
    pub is_base: bool,
}

/// Runtime and static observations used for transparent lane selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetInventory {
    /// Android package name.
    pub package_name: String,
    /// Resolved base and configuration/feature splits.
    pub apks: Vec<TargetApk>,
    /// Whether the selected runtime can provide root plus Frida deployment.
    pub rooted_available: bool,
    /// Detected framework identities.
    pub frameworks: Vec<FrameworkKind>,
    /// Native library names observed in the normalized artifact.
    pub native_libraries: Vec<String>,
    /// Optional build identity used by native offset catalogs.
    pub build_fingerprint: Option<String>,
    /// Explicit or detector-produced escalation signals.
    pub escalation_boundaries: Vec<EscalationBoundary>,
    /// Bounded evidence retained for diagnostics.
    pub evidence: Vec<String>,
}

impl TargetInventory {
    /// Builds inventory from the Phase-1 normalized Android handoff.
    #[must_use]
    pub fn from_normalized(
        package_name: impl Into<String>,
        artifact: &NormalizedUnpackedArtifact,
        rooted_available: bool,
    ) -> Self {
        let apks = artifact
            .installable_apks
            .iter()
            .map(|apk| TargetApk {
                id: apk.id.clone(),
                path: PathBuf::from(&apk.path),
                is_base: apk.is_base,
            })
            .collect::<Vec<_>>();
        let mut paths = apks.iter().map(|apk| apk.path.clone()).collect::<Vec<_>>();
        paths.extend(artifact.structural_outputs.iter().flat_map(|output| {
            [
                PathBuf::from(&output.manifest),
                PathBuf::from(&output.resource_root),
                PathBuf::from(&output.asset_root),
            ]
        }));
        let mut inventory = Self::from_paths(package_name, &paths, rooted_available);
        inventory.apks = apks;
        inventory
    }

    /// Builds a conservative inventory from APK/decoded workspace paths.
    #[must_use]
    pub fn from_paths(
        package_name: impl Into<String>,
        paths: &[PathBuf],
        rooted_available: bool,
    ) -> Self {
        let mut frameworks = Vec::new();
        let mut native_libraries = Vec::new();
        let mut evidence = Vec::new();
        let mut boundaries = Vec::new();
        for path in paths {
            let lower = path.to_string_lossy().to_ascii_lowercase();
            if lower.contains("libflutter.so") || lower.contains("flutter") {
                push_unique(&mut frameworks, FrameworkKind::Flutter);
                push_unique_string(&mut native_libraries, "libflutter.so");
                evidence.push(format!("flutter marker: {}", path.display()));
            }
            if lower.contains("mono") || lower.contains("xamarin") || lower.contains("assemblies") {
                push_unique(&mut frameworks, FrameworkKind::XamarinDotNet);
                evidence.push(format!("xamarin/mono marker: {}", path.display()));
            }
            if let Ok(contents) = fs::read_to_string(path) {
                let lower_contents = contents.to_ascii_lowercase();
                if lower_contents.contains("libflutter.so") {
                    push_unique(&mut frameworks, FrameworkKind::Flutter);
                    push_unique_string(&mut native_libraries, "libflutter.so");
                }
                if lower_contents.contains("mono.android") || lower_contents.contains("xamarin") {
                    push_unique(&mut frameworks, FrameworkKind::XamarinDotNet);
                }
                if lower_contents.contains("keymint")
                    || lower_contents.contains("strong_integrity")
                    || lower_contents.contains("hardwarebacked")
                {
                    push_unique(
                        &mut boundaries,
                        EscalationBoundary::HardwareBackedAttestation,
                    );
                }
                if lower_contents.contains("clientcertificate")
                    || lower_contents.contains("client_cert")
                    || lower_contents.contains("mutual tls")
                {
                    push_unique(&mut boundaries, EscalationBoundary::ClientMtls);
                }
                if lower_contents.contains("frida detection")
                    || lower_contents.contains("frida-server")
                    || lower_contents.contains("anti-frida")
                {
                    push_unique(&mut boundaries, EscalationBoundary::AntiFridaRasp);
                }
                if (lower_contents.contains("memfd") || lower_contents.contains("dynamic offset"))
                    && (lower_contents.contains("boringssl")
                        || lower_contents.contains("certificate pin"))
                {
                    push_unique(
                        &mut boundaries,
                        EscalationBoundary::StrippedNdkDynamicObfuscation,
                    );
                }
            }
        }
        if frameworks.is_empty() {
            frameworks.push(FrameworkKind::Java);
        }
        Self {
            package_name: package_name.into(),
            apks: paths
                .iter()
                .enumerate()
                .map(|(index, path)| TargetApk {
                    id: format!("apk-{index}"),
                    path: path.clone(),
                    is_base: index == 0,
                })
                .collect(),
            rooted_available,
            frameworks,
            native_libraries,
            build_fingerprint: None,
            escalation_boundaries: boundaries,
            evidence,
        }
    }
}

/// User-facing lane preference. Technique selection remains automatic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePreference {
    /// Prefer the strongest available automated lane.
    #[default]
    Auto,
    /// Require the no-root patch-and-resign lane.
    NoRoot,
    /// Require rooted Frida; do not silently fall back to patching.
    RootedFrida,
}

/// Lane selected by the automatic planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BypassLane {
    /// Rooted Java/platform Frida lane.
    PrimaryFrida,
    /// Automated decode, rewrite, gadget, rebuild, align, sign, install.
    FallbackPatch,
    /// Flutter native `BoringSSL` lane.
    FlutterNative,
    /// Xamarin/.NET Mono callback lane.
    XamarinMono,
    /// Honest manual boundary; no bypass was attempted.
    Escalation,
}

/// A native interception mapping for Flutter or another specialized runtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeHookSpec {
    /// Stable native technique ID.
    pub technique_id: String,
    /// Symbol or offset label.
    pub symbol: String,
    /// Offset in the reviewed framework build.
    pub offset: u64,
}

/// External tools and session assets needed by Phase 3.3.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassToolchain {
    /// Host Frida CLI executable.
    pub frida_executable: String,
    /// Host path to a compatible baseline frida-server binary.
    pub frida_server_path: PathBuf,
    /// APK decoder/builder executable.
    pub apktool_executable: String,
    /// Android zipalign executable.
    pub zipalign_executable: String,
    /// Android apksigner executable.
    pub apksigner_executable: String,
    /// Approved disposable-session signing keystore.
    pub signing_keystore: PathBuf,
    /// Environment variable read by apksigner for the keystore password.
    pub signing_password_env: String,
    /// Frida Gadget shared object used by the no-root lane.
    pub frida_gadget_path: PathBuf,
    /// Optional reviewed Flutter native patcher.
    pub flutter_native_patcher: Option<String>,
    /// Reviewed native offset catalogs keyed by build fingerprint.
    pub native_offset_catalog: BTreeMap<String, Vec<NativeHookSpec>>,
}

impl Default for BypassToolchain {
    fn default() -> Self {
        Self {
            frida_executable: "frida".to_owned(),
            frida_server_path: PathBuf::from("frida-server"),
            apktool_executable: "apktool".to_owned(),
            zipalign_executable: "zipalign".to_owned(),
            apksigner_executable: "apksigner".to_owned(),
            signing_keystore: PathBuf::from("debug.keystore"),
            signing_password_env: "APIAXESS_APK_SIGNING_PASSWORD".to_owned(),
            frida_gadget_path: PathBuf::from("libfrida-gadget.so"),
            flutter_native_patcher: None,
            native_offset_catalog: BTreeMap::new(),
        }
    }
}

/// Device-side frida-server port. `frida-server` binds this on the device; the
/// workbench `adb forward`s a host loopback port to it.
pub const DEVICE_FRIDA_SERVER_PORT: u16 = 27042;

/// Which device hosts frida-server and how the workbench reaches it (Phase C4).
///
/// The bundled-emulator path leaves this at its default (`device_serial: None`,
/// host port 27042); the `adb forward` there is already scoped to the emulator by
/// the control transport's serial. For an arbitrary connected device the workbench
/// sets `device_serial` (so it builds that device's control) and a distinct
/// `frida_host_port` (so multiple attached devices do not collide on the host).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FridaTargeting {
    /// adb serial of the device hosting frida-server. `None` targets whatever the
    /// control transport is already bound to (the single bundled emulator).
    pub device_serial: Option<String>,
    /// Host loopback port `adb forward`ed to the device's frida-server. Frida-core
    /// attaches to `127.0.0.1:<frida_host_port>`.
    pub frida_host_port: u16,
}

impl Default for FridaTargeting {
    fn default() -> Self {
        Self {
            device_serial: None,
            frida_host_port: DEVICE_FRIDA_SERVER_PORT,
        }
    }
}

/// One complete automatic bypass request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassRequest {
    /// Active session ID used in evidence and temporary paths.
    pub session_id: String,
    /// Active sandbox lease ID.
    pub lease_id: String,
    /// Target inventory and framework observations.
    pub target: TargetInventory,
    /// Automatic lane preference.
    pub preference: LanePreference,
    /// External tools and reviewed session assets.
    pub toolchain: BypassToolchain,
    /// Which device hosts frida-server and how the workbench reaches it.
    pub frida: FridaTargeting,
    /// Parent for the session-only host workspace.
    pub workspace_root: Option<PathBuf>,
    /// Whether the patched package should be installed automatically.
    pub install_patched_app: bool,
}

impl BypassRequest {
    /// Creates an automatic request with installation enabled.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        lease_id: impl Into<String>,
        target: TargetInventory,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            lease_id: lease_id.into(),
            target,
            preference: LanePreference::Auto,
            toolchain: BypassToolchain::default(),
            frida: FridaTargeting::default(),
            workspace_root: None,
            install_patched_app: true,
        }
    }
}

/// Planned lane plus the exact declarative specs it will use.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassPlan {
    /// Selected implementation lane.
    pub lane: BypassLane,
    /// Applicable declarative Java specs.
    pub specs: Vec<BypassSpec>,
    /// Human-readable selection reason.
    pub reason: String,
    /// Planning diagnostics, including a boundary when no lane is safe.
    pub diagnostics: Vec<Diagnostic>,
}

/// Result surfaced after a bypass lane has been started.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BypassOutcome {
    /// Planned lane.
    pub plan: BypassPlan,
    /// Technique IDs actually loaded or applied.
    pub applied_technique_ids: Vec<String>,
    /// Whether a patched package was installed.
    pub patched_app_installed: bool,
    /// Whether the session runtime has a Frida server process.
    pub frida_server_started: bool,
}

/// Plans automatic lane selection without mutating the runtime.
#[must_use]
pub fn plan_bypass(request: &BypassRequest, registry: &BypassTechniqueRegistry) -> BypassPlan {
    let specs = registry.for_package(&request.target.package_name);
    if let Some(boundary) = request.target.escalation_boundaries.first().copied() {
        return BypassPlan {
            lane: BypassLane::Escalation,
            specs,
            reason: format!("{} boundary detected", boundary.label()),
            diagnostics: vec![boundary_diagnostic(request, boundary)],
        };
    }
    let specialized = if request.target.frameworks.contains(&FrameworkKind::Flutter) {
        Some((BypassLane::FlutterNative, "Flutter native BoringSSL lane"))
    } else if request
        .target
        .frameworks
        .contains(&FrameworkKind::XamarinDotNet)
    {
        Some((BypassLane::XamarinMono, "Xamarin/.NET Mono callback lane"))
    } else {
        None
    };
    let (lane, reason) = specialized.unwrap_or(match request.preference {
        LanePreference::NoRoot => (
            BypassLane::FallbackPatch,
            "user-selected no-root patch-and-resign lane",
        ),
        LanePreference::RootedFrida if request.target.rooted_available => {
            (BypassLane::PrimaryFrida, "user-selected rooted Frida lane")
        }
        LanePreference::RootedFrida => (
            BypassLane::Escalation,
            "rooted Frida was required but the selected runtime is not rooted",
        ),
        LanePreference::Auto if request.target.rooted_available => (
            BypassLane::PrimaryFrida,
            "rooted runtime available; selected automated Frida lane",
        ),
        LanePreference::Auto => (
            BypassLane::FallbackPatch,
            "root unavailable; selected automated patch-and-resign lane",
        ),
    });
    let diagnostics = if lane == BypassLane::Escalation {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_ESCALATION_BOUNDARY,
            "reason",
            reason.to_owned(),
        )]
    } else {
        Vec::new()
    };
    BypassPlan {
        lane,
        specs,
        reason: reason.to_owned(),
        diagnostics,
    }
}

/// Evidence-based assessment of whether the target enforces TLS certificate
/// pinning.
///
/// Used to gate the bypass lane in the live pipeline: a pinned app has its
/// pinning bypassed before capture, while a plain app skips the lane entirely —
/// its traffic already reaches the blanket-trusted session proxy, exactly as the
/// capstone showed. The check is deliberately conservative and bounded.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PinningAssessment {
    /// Whether certificate pinning was detected.
    pub present: bool,
    /// Bounded human-readable evidence for the decision.
    pub evidence: Vec<String>,
    /// Whether the bounded bytecode/resource scan hit its cap before completing.
    ///
    /// When `present` is false but this is true, absence of pinning is not
    /// certain: a deep pin literal could sit beyond the scanned prefix. Callers
    /// surface this so a truncated scan is a legible signal, never a silent
    /// false-negative that leaves a pinned app capturing zero flows.
    pub truncated: bool,
}

// The scan is bounded so a pathological multi-gigabyte corpus cannot run
// unbounded, but the caps are set well above any real app so a genuine pin
// literal is not missed for sitting deep in the bytecode. Reading is one file at
// a time (only the running totals are retained), so a high byte cap costs scan
// time, not memory. A corpus that still exceeds these bounds marks the assessment
// truncated rather than silently reporting "no pinning".
const MAX_PINNING_SCAN_FILES: usize = 500_000;
const MAX_PINNING_SCAN_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Scans the normalized artifact for certificate-pinning indicators: framework
/// TLS stacks (Flutter/Xamarin), a Network Security Config pin-set, and `OkHttp`
/// `CertificatePinner`/pin literals in bytecode. The bytecode scan is bounded.
#[must_use]
pub fn assess_pinning(artifact: &NormalizedUnpackedArtifact) -> PinningAssessment {
    let inventory = TargetInventory::from_normalized(String::new(), artifact, false);
    let mut evidence = Vec::new();
    if inventory.frameworks.contains(&FrameworkKind::Flutter) {
        evidence.push("Flutter framework: BoringSSL pinning bypass lane applies".to_owned());
    }
    if inventory.frameworks.contains(&FrameworkKind::XamarinDotNet) {
        evidence.push("Xamarin/.NET framework: Mono TLS callback bypass lane applies".to_owned());
    }
    let mut scan = ScanState::new();
    let mut nsc_pins = false;
    let mut okhttp_pins = false;
    for output in &artifact.structural_outputs {
        // Scan the bytecode (OkHttp pins) first: it is the most common pinning
        // location, so it should never be starved of budget by a large resource
        // tree scanned ahead of it.
        if !okhttp_pins {
            for smali_root in &output.smali_roots {
                if scan_tree(
                    Path::new(smali_root),
                    &["smali"],
                    &["CertificatePinner", "sha256/"],
                    &mut scan,
                ) {
                    okhttp_pins = true;
                    break;
                }
            }
        }
        if !nsc_pins
            && fs::read_to_string(&output.manifest)
                .is_ok_and(|manifest| manifest.contains("networkSecurityConfig"))
            && scan_tree(
                Path::new(&output.resource_root),
                &["xml"],
                &["pin-set", "<pin digest"],
                &mut scan,
            )
        {
            nsc_pins = true;
        }
    }
    if nsc_pins {
        evidence.push("Network Security Config declares certificate pins".to_owned());
    }
    if okhttp_pins {
        evidence.push("OkHttp CertificatePinner / pin literals present in bytecode".to_owned());
    }
    let present = !evidence.is_empty();
    PinningAssessment {
        present,
        evidence,
        // Truncation only matters when nothing was found: if a pin was detected the
        // bounded scan already did its job.
        truncated: scan.truncated && !present,
    }
}

/// Running state and bounds for a bytecode/resource pinning scan.
struct ScanState {
    files: usize,
    bytes: u64,
    truncated: bool,
    max_files: usize,
    max_bytes: u64,
}

impl ScanState {
    fn new() -> Self {
        Self {
            files: 0,
            bytes: 0,
            truncated: false,
            max_files: MAX_PINNING_SCAN_FILES,
            max_bytes: MAX_PINNING_SCAN_BYTES,
        }
    }

    fn over_cap(&self) -> bool {
        self.files >= self.max_files || self.bytes >= self.max_bytes
    }
}

/// Bounded recursive search: returns whether any file with one of `exts` under
/// `root` contains any of `needles`. Stops at the scan caps, setting `truncated`
/// when a cap (not the end of the tree) ends the scan so the caller can report an
/// incomplete scan rather than a false "not found".
fn scan_tree(root: &Path, exts: &[&str], needles: &[&str], scan: &mut ScanState) -> bool {
    if scan.over_cap() {
        scan.truncated = true;
        return false;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if scan_tree(&path, exts, needles, scan) {
                return true;
            }
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| exts.contains(&extension))
        {
            scan.files += 1;
            if let Ok(contents) = fs::read_to_string(&path) {
                scan.bytes += contents.len() as u64;
                if needles.iter().any(|needle| contents.contains(needle)) {
                    return true;
                }
            }
        }
        if scan.over_cap() {
            scan.truncated = true;
            return false;
        }
    }
    false
}

/// Applies the planned lane and attaches all cleanup to the sandbox lease.
pub fn apply_bypass(
    lease: &mut SandboxLease,
    request: &BypassRequest,
    registry: &BypassTechniqueRegistry,
    runner: &Arc<dyn ExternalToolRunner>,
) -> Result<BypassOutcome, Vec<Diagnostic>> {
    let control = lease.control();
    let (outcome, cleanup) = run_bypass_core(&control, request, registry, runner)?;
    lease.add_cleanup(Box::new(cleanup));
    Ok(outcome)
}

/// Applies the planned lane against a device identified by its control transport,
/// without a disposable sandbox lease (Phase C4).
///
/// This is how the pinned-app bypass targets the user's *chosen connected device*
/// rather than the bundled emulator: build the device's control from its adb
/// serial (see `device_provision::DeviceProvisioner::control_for`), set
/// `request.frida.device_serial` + a distinct `frida_host_port`, and the same
/// proven lanes (`plan_bypass`/`apply_frida`, the OkHttp/Java pinning hooks) run
/// against that device's frida-server over the adb tunnel. The workbench owns the
/// returned [`BypassSession`] and tears it down when capture ends.
///
/// # Errors
///
/// Returns the bypass diagnostics when planning hits an escalation boundary or a
/// lane fails (attach/script/deploy); cleanup of any partial state runs first.
pub fn apply_bypass_on_control(
    control: &Arc<dyn SandboxControl>,
    request: &BypassRequest,
    registry: &BypassTechniqueRegistry,
    runner: &Arc<dyn ExternalToolRunner>,
) -> Result<(BypassOutcome, BypassSession), Vec<Diagnostic>> {
    let (outcome, cleanup) = run_bypass_core(control, request, registry, runner)?;
    Ok((outcome, BypassSession { cleanup }))
}

/// A live device-targeted bypass. Its Frida instrumentation and the device-side
/// frida-server stay active until [`BypassSession::teardown`] is called.
pub struct BypassSession {
    cleanup: BypassCleanup,
}

impl std::fmt::Debug for BypassSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BypassSession")
            .field("package", &self.cleanup.package_name)
            .field("frida_server_started", &self.cleanup.server_started)
            .finish_non_exhaustive()
    }
}

impl BypassSession {
    /// Unloads the instrumentation and removes device-side bypass artifacts.
    ///
    /// # Errors
    ///
    /// Returns the teardown diagnostics for any artifact that could not be removed.
    pub fn teardown(mut self) -> Result<(), Vec<Diagnostic>> {
        self.cleanup.cleanup()
    }
}

/// Shared bypass core over a control transport, independent of lease ownership.
fn run_bypass_core(
    control: &Arc<dyn SandboxControl>,
    request: &BypassRequest,
    registry: &BypassTechniqueRegistry,
    runner: &Arc<dyn ExternalToolRunner>,
) -> Result<(BypassOutcome, BypassCleanup), Vec<Diagnostic>> {
    let plan = plan_bypass(request, registry);
    if plan.lane == BypassLane::Escalation {
        return Err(plan.diagnostics);
    }
    let workspace = session_workspace(request)?;
    let mut cleanup = BypassCleanup {
        control: Arc::clone(control),
        server_path: None,
        server_started: false,
        frida_process: None,
        #[cfg(feature = "frida-embedded")]
        embedded_controller: None,
        installed_package: false,
        package_name: request.target.package_name.clone(),
        workspace: Some(workspace.clone()),
    };
    let applied = match plan.lane {
        BypassLane::PrimaryFrida => apply_frida(
            control,
            runner,
            request,
            &plan,
            &workspace,
            &mut cleanup,
            None,
        ),
        BypassLane::FallbackPatch => apply_patch_lane(
            control,
            runner,
            request,
            &plan,
            &workspace,
            &mut cleanup,
            None,
        ),
        BypassLane::FlutterNative => {
            apply_flutter_lane(control, runner, request, &plan, &workspace, &mut cleanup)
        }
        BypassLane::XamarinMono => {
            apply_xamarin_lane(control, runner, request, &plan, &workspace, &mut cleanup)
        }
        BypassLane::Escalation => unreachable!(),
    };
    match applied {
        Ok((technique_ids, patched)) => {
            cleanup.installed_package = patched;
            let server_started = cleanup.server_started;
            Ok((
                BypassOutcome {
                    plan,
                    applied_technique_ids: technique_ids,
                    patched_app_installed: patched,
                    frida_server_started: server_started,
                },
                cleanup,
            ))
        }
        Err(mut diagnostics) => {
            diagnostics.extend(cleanup.cleanup().err().unwrap_or_default());
            Err(diagnostics)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn apply_frida(
    control: &Arc<dyn SandboxControl>,
    runner: &Arc<dyn ExternalToolRunner>,
    request: &BypassRequest,
    plan: &BypassPlan,
    workspace: &Path,
    cleanup: &mut BypassCleanup,
    extra_script: Option<String>,
) -> Result<(Vec<String>, bool), Vec<Diagnostic>> {
    #[cfg(not(feature = "frida-embedded"))]
    {
        let _ = (
            control,
            runner,
            request,
            plan,
            workspace,
            cleanup,
            extra_script,
        );
        Err(vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_SPAWN_GATE_FAILED,
            "capability",
            "the Frida bypass lane requires the frida-embedded product variant; the base build intentionally does not include frida-core".to_owned(),
        )])
    }
    #[cfg(feature = "frida-embedded")]
    apply_frida_embedded(
        control,
        runner,
        request,
        plan,
        workspace,
        cleanup,
        extra_script,
    )
}

/// Elevates the guest transport to root and blocks until it is confirmed, so a
/// privileged device-side step (starting `frida-server`) runs as root.
///
/// `adb root` restarts adbd; the transport drops and reconnects, so a root
/// escalation performed earlier (e.g. the pre-bypass root probe) is not reliably
/// in effect at deploy time. This escalates again, waits for the device to
/// return, and verifies `uid=0`, retrying briefly across the reconnect window.
#[cfg(feature = "frida-embedded")]
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
    Err(vec![bypass_diagnostic(
        catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
        "error",
        "could not elevate the guest to root (adb root) before starting frida-server".to_owned(),
    )])
}

/// Feature-gated primary pinning lane. The device-side server remains a guest
/// artifact, while script execution is delegated to linked frida-core rather
/// than a host `frida` CLI.
#[cfg(feature = "frida-embedded")]
#[allow(clippy::too_many_lines)]
fn apply_frida_embedded(
    control: &Arc<dyn SandboxControl>,
    _runner: &Arc<dyn ExternalToolRunner>,
    request: &BypassRequest,
    plan: &BypassPlan,
    workspace: &Path,
    cleanup: &mut BypassCleanup,
    extra_script: Option<String>,
) -> Result<(Vec<String>, bool), Vec<Diagnostic>> {
    let remote_server = format!(
        "/data/local/tmp/apiaxess-bypass-{}/frida-server",
        safe_token(&request.lease_id)
    );
    let server_bytes = fs::read(&request.toolchain.frida_server_path).map_err(|error| {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
            "host_path",
            format!("{}: {error}", request.toolchain.frida_server_path.display()),
        )]
    })?;
    control
        .put(&server_bytes, &remote_server, Duration::from_secs(30))
        .map_err(|error| {
            vec![bypass_diagnostic(
                catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
                "error",
                error.to_string(),
            )]
        })?;
    cleanup.server_path = Some(remote_server.clone());
    // Elevate the guest transport to root *immediately* before starting
    // frida-server. `adb root` restarts adbd and the reconnect is racy, so an
    // earlier probe's escalation is not reliably in effect here: without this,
    // frida-server can start as the `shell` user and be killed under enforcing
    // SELinux, leaving the host frida-core to see a "jailed" device (it then asks
    // for a Gadget and the spawn gate fails). Escalating + waiting + verifying
    // uid=0 right here makes the frida lane deterministic on Linux and Windows.
    ensure_device_root(control)?;
    ensure_control_success(
        control,
        &["chmod".to_owned(), "0755".to_owned(), remote_server.clone()],
        catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
        "chmod frida-server",
    )?;
    ensure_control_success(
        control,
        &[
            "sh".to_owned(),
            "-c".to_owned(),
            format!("{remote_server} >/dev/null 2>&1 &"),
        ],
        catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
        "start frida-server",
    )?;
    let pid = control.shell(
        &["pidof".to_owned(), "frida-server".to_owned()],
        Duration::from_secs(15),
    );
    if !successful(&pid) {
        return Err(vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
            "evidence",
            "frida-server did not report a live process".to_owned(),
        )]);
    }
    cleanup.server_started = true;

    // Forward a host port to the device-side frida-server so the embedded
    // frida-core connects to it explicitly (`add_remote_device 127.0.0.1:<port>`)
    // rather than enumerating USB devices — which mis-resolves a phantom device
    // for an emulator on Linux and never reaches this server. `adb forward` is a
    // HOST-side adb subcommand, so it must go through `control.command` (host
    // transport, already scoped to this device's adb serial), NOT `control.shell`.
    // Idempotent (re-adding replaces). The host port is parameterized (Phase C4)
    // so multiple attached devices map to distinct host ports; the device port is
    // always the frida-server default. The serial that disambiguates which device
    // is carried by `control` (and recorded in `request.frida.device_serial`).
    let host_port = request.frida.frida_host_port;
    control
        .command(
            &[
                "forward".to_owned(),
                format!("tcp:{host_port}"),
                format!("tcp:{DEVICE_FRIDA_SERVER_PORT}"),
            ],
            Duration::from_secs(30),
        )
        .map_err(|error| {
            vec![bypass_diagnostic(
                catalogue::SANDBOX_BYPASS_FRIDA_SERVER_DEPLOY_FAILED,
                "operation",
                format!(
                    "adb forward frida-server port for device {}: {error}",
                    request
                        .frida
                        .device_serial
                        .as_deref()
                        .unwrap_or("<default>"),
                ),
            )]
        })?;
    // frida-server needs a moment to bind its port after launch before the forward
    // target is reachable by the embedded frida-core.
    std::thread::sleep(Duration::from_secs(2));

    let script = generate_frida_script(&request.target.package_name, &plan.specs, extra_script);
    let embedded_request = crate::instrumentation::InstrumentationRequest {
        session_id: request.session_id.clone(),
        lease_id: request.lease_id.clone(),
        package_name: request.target.package_name.clone(),
        mode: crate::instrumentation::InstrumentationMode::Spawn,
        script,
        workspace_root: Some(workspace.to_path_buf()),
        config: crate::instrumentation::FridaSubstrateConfig {
            device_address: format!("127.0.0.1:{host_port}"),
            ..crate::instrumentation::FridaSubstrateConfig::default()
        },
    };
    let embedded = crate::frida_embedded::FridaCoreController::start(embedded_request)
        .map_err(|diagnostic| vec![diagnostic])?;
    cleanup.embedded_controller = Some(embedded);
    Ok((
        plan.specs
            .iter()
            .map(|spec| spec.technique_id.clone())
            .collect(),
        false,
    ))
}

fn apply_flutter_lane(
    control: &Arc<dyn SandboxControl>,
    runner: &Arc<dyn ExternalToolRunner>,
    request: &BypassRequest,
    plan: &BypassPlan,
    workspace: &Path,
    cleanup: &mut BypassCleanup,
) -> Result<(Vec<String>, bool), Vec<Diagnostic>> {
    let key = request
        .target
        .build_fingerprint
        .as_deref()
        .unwrap_or("default");
    let hooks = request
        .toolchain
        .native_offset_catalog
        .get(key)
        .ok_or_else(|| {
            vec![framework_offset_diagnostic(
                request,
                FrameworkKind::Flutter,
                key,
            )]
        })?;
    if hooks.is_empty() {
        return Err(vec![framework_offset_diagnostic(
            request,
            FrameworkKind::Flutter,
            key,
        )]);
    }
    let mut native_script = String::new();
    for hook in hooks {
        let _ = writeln!(native_script, "// {}", hook.symbol);
        let _ = writeln!(
            native_script,
            "// reviewed native offset: 0x{:x}",
            hook.offset
        );
    }
    if request.target.rooted_available && request.preference != LanePreference::NoRoot {
        let mut ids = hooks
            .iter()
            .map(|hook| hook.technique_id.clone())
            .collect::<Vec<_>>();
        let (mut java_ids, _) = apply_frida(
            control,
            runner,
            request,
            plan,
            workspace,
            cleanup,
            Some(native_script),
        )?;
        ids.append(&mut java_ids);
        Ok((ids, false))
    } else {
        apply_patch_lane(
            control,
            runner,
            request,
            plan,
            workspace,
            cleanup,
            Some(&(key.to_owned(), hooks.clone())),
        )
    }
}

fn apply_xamarin_lane(
    control: &Arc<dyn SandboxControl>,
    runner: &Arc<dyn ExternalToolRunner>,
    request: &BypassRequest,
    plan: &BypassPlan,
    workspace: &Path,
    cleanup: &mut BypassCleanup,
) -> Result<(Vec<String>, bool), Vec<Diagnostic>> {
    let mono_script = r"
// APIaxess Mono lane: resolve Mono runtime validation callbacks before app code.
// The callback mapping is declarative and intentionally separate from stealth.
"
    .to_owned();
    if request.target.rooted_available && request.preference != LanePreference::NoRoot {
        apply_frida(
            control,
            runner,
            request,
            plan,
            workspace,
            cleanup,
            Some(mono_script),
        )
    } else {
        apply_patch_lane(control, runner, request, plan, workspace, cleanup, None)
    }
}

#[allow(clippy::too_many_lines)]
fn apply_patch_lane(
    control: &Arc<dyn SandboxControl>,
    runner: &Arc<dyn ExternalToolRunner>,
    request: &BypassRequest,
    _plan: &BypassPlan,
    workspace: &Path,
    _cleanup: &mut BypassCleanup,
    native_patch: Option<&(String, Vec<NativeHookSpec>)>,
) -> Result<(Vec<String>, bool), Vec<Diagnostic>> {
    let apktool = probe(
        runner,
        "android.apktool",
        &request.toolchain.apktool_executable,
        &["--version"],
    )
    .map_err(|error| {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_DECOMPILE_FAILED,
            "error",
            error,
        )]
    })?;
    let zipalign = probe(
        runner,
        "android.zipalign",
        &request.toolchain.zipalign_executable,
        &["-h"],
    )
    .map_err(|error| {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_ZIPALIGN_FAILED,
            "error",
            error,
        )]
    })?;
    let apksigner = probe(
        runner,
        "android.apksigner",
        &request.toolchain.apksigner_executable,
        &["version"],
    )
    .map_err(|error| {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_RESIGN_FAILED,
            "error",
            error,
        )]
    })?;
    if request.target.apks.is_empty() {
        return Err(vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_DECOMPILE_FAILED,
            "package",
            "no installable APKs were supplied".to_owned(),
        )]);
    }
    let mut signed = Vec::new();
    for apk in &request.target.apks {
        let stem = safe_token(&apk.id);
        let decoded = workspace.join(format!("{stem}-decoded"));
        let rebuilt = workspace.join(format!("{stem}-rebuilt.apk"));
        let aligned = workspace.join(format!("{stem}-aligned.apk"));
        let output = workspace.join(format!("{stem}-patched.apk"));
        let decode = invoke(
            runner,
            &apktool,
            &[
                "d",
                "-f",
                &apk.path.display().to_string(),
                "-o",
                &decoded.display().to_string(),
            ],
            Duration::from_secs(120),
        );
        require_exit(decode, catalogue::SANDBOX_BYPASS_DECOMPILE_FAILED, &apk.id)?;
        rewrite_decoded(
            &decoded,
            &request.target.package_name,
            apk.is_base,
            &request.toolchain.frida_gadget_path,
        )
        .map_err(|error| {
            vec![bypass_diagnostic(
                catalogue::SANDBOX_BYPASS_PATCH_FAILED,
                "apk",
                format!("{}: {error}", apk.id),
            )]
        })?;
        if let Some((build, hooks)) = native_patch.as_ref() {
            let Some(patcher) = request.toolchain.flutter_native_patcher.as_deref() else {
                return Err(vec![bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_PATCH_FAILED,
                    "tool",
                    "Flutter native patcher is not configured".to_owned(),
                )]);
            };
            let library = find_named_file(&decoded, "libflutter.so").ok_or_else(|| {
                vec![framework_offset_diagnostic(
                    request,
                    FrameworkKind::Flutter,
                    build,
                )]
            })?;
            let patcher_probe = probe(
                runner,
                "instrumentation.flutter-native-patcher",
                patcher,
                &["--version"],
            )
            .map_err(|error| {
                vec![bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_PATCH_FAILED,
                    "tool",
                    error,
                )]
            })?;
            let offsets = hooks
                .iter()
                .flat_map(|hook| {
                    [
                        "--offset".to_owned(),
                        format!("{}=0x{:x}", hook.symbol, hook.offset),
                    ]
                })
                .collect::<Vec<_>>();
            let mut args = vec![
                "--input".to_owned(),
                library.display().to_string(),
                "--output".to_owned(),
                library.display().to_string(),
                "--build".to_owned(),
                build.clone(),
            ];
            args.extend(offsets);
            let result = invoke(runner, &patcher_probe, &args, Duration::from_secs(120));
            require_exit(
                result,
                catalogue::SANDBOX_BYPASS_PATCH_FAILED,
                "Flutter libflutter.so",
            )?;
        }
        let build = invoke(
            runner,
            &apktool,
            &[
                "b",
                &decoded.display().to_string(),
                "-o",
                &rebuilt.display().to_string(),
            ],
            Duration::from_secs(180),
        );
        require_exit(build, catalogue::SANDBOX_BYPASS_REBUILD_FAILED, &apk.id)?;
        let align = invoke(
            runner,
            &zipalign,
            &[
                "-p",
                "4",
                &rebuilt.display().to_string(),
                &aligned.display().to_string(),
            ],
            Duration::from_secs(60),
        );
        require_exit(align, catalogue::SANDBOX_BYPASS_ZIPALIGN_FAILED, &apk.id)?;
        let sign = invoke(
            runner,
            &apksigner,
            &[
                "sign",
                "--ks",
                &request.toolchain.signing_keystore.display().to_string(),
                "--ks-pass",
                &format!("env:{}", request.toolchain.signing_password_env),
                "--out",
                &output.display().to_string(),
                &aligned.display().to_string(),
            ],
            Duration::from_secs(120),
        );
        let signing_definition = if apk.is_base {
            catalogue::SANDBOX_BYPASS_RESIGN_FAILED
        } else {
            catalogue::SANDBOX_BYPASS_SPLIT_SIGNING_FAILED
        };
        require_exit(sign, signing_definition, &apk.id)?;
        signed.push(output);
    }
    if request.install_patched_app {
        let installed = control
            .install_apks(&signed, Duration::from_secs(120))
            .map_err(|error| {
                vec![bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_INSTALL_FAILED,
                    "error",
                    error.to_string(),
                )]
            })?;
        if installed.exit_code != Some(0) {
            return Err(vec![bypass_diagnostic(
                catalogue::SANDBOX_BYPASS_INSTALL_FAILED,
                "stderr",
                installed.stderr,
            )]);
        }
    }
    Ok((
        vec!["fallback.network-security-config-and-gadget".to_owned()],
        request.install_patched_app,
    ))
}

fn rewrite_decoded(
    decoded: &Path,
    package_name: &str,
    is_base: bool,
    gadget: &Path,
) -> Result<(), String> {
    let manifest = decoded.join("AndroidManifest.xml");
    let mut contents = fs::read_to_string(&manifest)
        .map_err(|error| format!("{}: {error}", manifest.display()))?;
    if !contents.contains("android:networkSecurityConfig=") {
        let application = contents
            .find("<application")
            .ok_or("manifest has no application element")?;
        let end = contents[application..]
            .find('>')
            .map(|offset| application + offset)
            .ok_or("application element is not closed")?;
        contents.insert_str(
            end,
            " android:networkSecurityConfig=\"@xml/apiaxess_pinning_bypass\"",
        );
    }
    if is_base && !contents.contains("apiaxess.bypass.BypassInitProvider") {
        let provider = format!(
            "<provider android:name=\"com.apiaxess.bypass.BypassInitProvider\" android:authorities=\"{package_name}.apiaxess-bypass\" android:exported=\"false\" android:initOrder=\"1000\" />"
        );
        let close = contents
            .rfind("</application>")
            .ok_or("manifest has no application close element")?;
        contents.insert_str(close, &provider);
    }
    fs::write(&manifest, contents).map_err(|error| error.to_string())?;
    let xml_dir = decoded.join("res/xml");
    fs::create_dir_all(&xml_dir).map_err(|error| error.to_string())?;
    fs::write(xml_dir.join("apiaxess_pinning_bypass.xml"), "<network-security-config><base-config cleartextTrafficPermitted=\"true\"><trust-anchors><certificates src=\"system\"/><certificates src=\"user\"/></trust-anchors></base-config></network-security-config>").map_err(|error| error.to_string())?;
    let smali = decoded.join("smali_classes99/com/apiaxess/bypass/BypassInitProvider.smali");
    fs::create_dir_all(smali.parent().ok_or("smali path has no parent")?)
        .map_err(|error| error.to_string())?;
    fs::write(
        smali,
        r#".class public Lcom/apiaxess/bypass/BypassInitProvider;
.super Landroid/content/ContentProvider;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V
    return-void
.end method

.method public onCreate()Z
    .locals 1
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
"#,
    )
    .map_err(|error| error.to_string())?;
    inject_gadget(decoded, gadget)
}

fn inject_gadget(decoded: &Path, gadget: &Path) -> Result<(), String> {
    if !gadget.is_file() {
        return Err(format!("Frida Gadget is missing: {}", gadget.display()));
    }
    let lib_root = decoded.join("lib");
    fs::create_dir_all(&lib_root).map_err(|error| error.to_string())?;
    let mut abi_dirs = fs::read_dir(&lib_root)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    if abi_dirs.is_empty() {
        let arm64 = lib_root.join("arm64-v8a");
        fs::create_dir_all(&arm64).map_err(|error| error.to_string())?;
        abi_dirs.push(arm64);
    }
    for abi in abi_dirs {
        fs::copy(gadget, abi.join("libfrida-gadget.so")).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[allow(dead_code)] // Exercised by the feature-gated lane and unit-tested in the base build.
fn generate_frida_script(
    package_name: &str,
    specs: &[BypassSpec],
    extra: Option<String>,
) -> String {
    // Frida 17 removed the built-in `Java` runtime bridge, so a raw `Java.perform`
    // script throws `ReferenceError: Java is not defined` and installs no hooks
    // (the bypass silently no-ops). Bundle the compiled frida-java-bridge and expose
    // it as the `Java` global, exactly as frida-compile/frida-tools do.
    let mut script = String::new();
    script.push_str(include_str!("frida_java_bridge.js"));
    script.push_str("\nglobalThis.Java = bridge;\n");
    let _ = writeln!(
        script,
        "// APIaxess spawn-gated pinning bypass for {package_name}"
    );
    // `apiaxessDone` guards each technique so the retry loop below never stacks a
    // second wrapper on an already-hooked method.
    script.push_str("var apiaxessDone = {};\nfunction apiaxessInstall() {\n");
    for spec in specs {
        let return_value = match spec.return_strategy {
            ReturnStrategy::BooleanFalse => "false",
            ReturnStrategy::Null => "null",
            ReturnStrategy::EmptyCollection => "[]",
            ReturnStrategy::BooleanTrue => "true",
            ReturnStrategy::PassThrough => "__apiaxess_original.apply(this, arguments)",
        };
        let _ = writeln!(
            script,
            "  try {{ if (!apiaxessDone[{id:?}]) {{ var C = Java.use({class:?}); var M = C[{method:?}]; M.overloads.forEach(function(O) {{ var original = O.implementation; O.implementation = function() {{ var __apiaxess_original = original; return {return_value}; }}; }}); apiaxessDone[{id:?}] = true; }} }} catch (_) {{ /* class not loaded yet; retried by the install interval */ }}",
            id = spec.technique_id,
            class = spec.target_class,
            method = spec.target_method,
            return_value = return_value
        );
    }
    // Install immediately, again on Application.onCreate, and then re-attempt on a
    // short interval: certificate-pinning classes (e.g. okhttp3.CertificatePinner)
    // are frequently loaded lazily on first network use — after both the spawn-time
    // install and Application.onCreate — so a one-shot hook misses them. The guarded
    // interval re-runs the install until each technique's class has loaded and been
    // hooked (bounded so the script does not spin forever).
    script.push_str("}\nJava.perform(function() { apiaxessInstall(); try { var A = Java.use('android.app.Application'); A.onCreate.overloads.forEach(function(O) { var original = O.implementation; O.implementation = function() { apiaxessInstall(); return original.call(this); }; }); } catch (_) {} });\nvar apiaxessTries = 0;\nvar apiaxessTimer = setInterval(function() { apiaxessTries += 1; try { Java.perform(function() { apiaxessInstall(); }); } catch (_) {} if (apiaxessTries >= 120) { clearInterval(apiaxessTimer); } }, 250);\n");
    if let Some(extra) = extra {
        script.push_str(&extra);
        script.push('\n');
    }
    script
}

struct BypassCleanup {
    control: Arc<dyn SandboxControl>,
    server_path: Option<String>,
    server_started: bool,
    frida_process: Option<ToolProcess>,
    /// The loaded linked frida-core script, retained until session cleanup.
    #[cfg(feature = "frida-embedded")]
    embedded_controller: Option<crate::frida_embedded::FridaCoreController>,
    installed_package: bool,
    package_name: String,
    workspace: Option<PathBuf>,
}

impl SandboxCleanup for BypassCleanup {
    fn cleanup(&mut self) -> Result<(), Vec<Diagnostic>> {
        let mut diagnostics = Vec::new();
        if let Some(process) = self.frida_process.take() {
            if let Err(error) = process.stop() {
                diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "frida_process",
                    error.to_string(),
                ));
            }
        }
        // Stop the owning Frida thread so it unloads the script before the
        // guest-side server is stopped.
        #[cfg(feature = "frida-embedded")]
        if let Some(controller) = self.embedded_controller.take() {
            if let Err(error) = controller.teardown() {
                diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "frida_controller",
                    error.to_string(),
                ));
            }
        }
        if self.server_started {
            if let Some(path) = self.server_path.as_deref() {
                let stopped = self.control.shell(
                    &["pkill".to_owned(), "-f".to_owned(), path.to_owned()],
                    Duration::from_secs(15),
                );
                if stopped.is_err() {
                    diagnostics.push(bypass_diagnostic(
                        catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                        "frida_server",
                        format!("could not stop {path}"),
                    ));
                }
            }
        }
        if let Some(path) = self.server_path.take() {
            if let Err(error) = self.control.remove(&path, Duration::from_secs(15)) {
                diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "server_artifact",
                    error.to_string(),
                ));
            }
        }
        if self.installed_package {
            match self.control.command(
                &["uninstall".to_owned(), self.package_name.clone()],
                Duration::from_secs(30),
            ) {
                Ok(output) if output.exit_code == Some(0) => {}
                Ok(output)
                    if output.stderr.contains("Unknown package")
                        || output.stderr.contains("not found") => {}
                Ok(output) => diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "installed_package",
                    output.stderr,
                )),
                Err(error) => diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "installed_package",
                    error.to_string(),
                )),
            }
        }
        if let Some(workspace) = self.workspace.take() {
            if let Err(error) = fs::remove_dir_all(&workspace) {
                diagnostics.push(bypass_diagnostic(
                    catalogue::SANDBOX_BYPASS_TEARDOWN_FAILED,
                    "workspace",
                    format!("{}: {error}", workspace.display()),
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

fn session_workspace(request: &BypassRequest) -> Result<PathBuf, Vec<Diagnostic>> {
    let parent = request
        .workspace_root
        .clone()
        .unwrap_or_else(std::env::temp_dir);
    let workspace = parent.join(format!("apiaxess-bypass-{}", safe_token(&request.lease_id)));
    fs::create_dir_all(&workspace).map_err(|error| {
        vec![bypass_diagnostic(
            catalogue::SANDBOX_BYPASS_PATCH_FAILED,
            "workspace",
            format!("{}: {error}", workspace.display()),
        )]
    })?;
    Ok(workspace)
}

fn probe(
    runner: &Arc<dyn ExternalToolRunner>,
    tool_id: &str,
    executable: &str,
    version_arguments: &[&str],
) -> Result<ToolProbe, String> {
    runner
        .probe(&ToolProbeRequest {
            tool_id: tool_id.to_owned(),
            executable: executable.to_owned(),
            version_arguments: version_arguments
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
            requirement: ToolRequirement {
                minimum: ToolVersion {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
            },
        })
        .map_err(|error| error.to_string())
}

fn invoke<A: AsRef<str>>(
    runner: &Arc<dyn ExternalToolRunner>,
    probe: &ToolProbe,
    args: &[A],
    timeout: Duration,
) -> Result<SandboxCommandOutput, String> {
    let output = runner
        .invoke(&ToolInvocationRequest {
            probe: probe.clone(),
            arguments: args.iter().map(|arg| arg.as_ref().to_owned()).collect(),
            working_directory: None,
            environment: Vec::new(),
            timeout,
        })
        .map_err(|error| error.to_string())?;
    Ok(SandboxCommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
        exit_code: output.exit_code,
    })
}

fn require_exit(
    result: Result<SandboxCommandOutput, String>,
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    subject: &str,
) -> Result<(), Vec<Diagnostic>> {
    match result {
        Ok(output) if output.exit_code == Some(0) => Ok(()),
        Ok(output) => Err(vec![bypass_diagnostic(
            definition,
            "subject",
            format!("{subject}: {}", output.stderr),
        )]),
        Err(error) => Err(vec![bypass_diagnostic(
            definition,
            "subject",
            format!("{subject}: {error}"),
        )]),
    }
}

#[cfg(feature = "frida-embedded")]
fn ensure_control_success(
    control: &Arc<dyn SandboxControl>,
    args: &[String],
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    operation: &str,
) -> Result<(), Vec<Diagnostic>> {
    match control.shell(args, Duration::from_secs(30)) {
        Ok(output) if output.exit_code == Some(0) => Ok(()),
        Ok(output) => Err(vec![bypass_diagnostic(
            definition,
            "operation",
            format!("{operation}: {}", output.stderr),
        )]),
        Err(error) => Err(vec![bypass_diagnostic(
            definition,
            "operation",
            format!("{operation}: {error}"),
        )]),
    }
}

#[cfg(feature = "frida-embedded")]
fn successful(result: &Result<SandboxCommandOutput, Diagnostic>) -> bool {
    result
        .as_ref()
        .is_ok_and(|output| output.exit_code == Some(0))
}

fn boundary_diagnostic(request: &BypassRequest, boundary: EscalationBoundary) -> Diagnostic {
    let mut diagnostic = bypass_diagnostic(
        catalogue::SANDBOX_BYPASS_ESCALATION_BOUNDARY,
        "boundary",
        boundary.label().to_owned(),
    );
    diagnostic.why = format!(
        "{}; automated bypass exhausted; manual reverse-engineering required",
        boundary.label()
    )
    .into_boxed_str();
    diagnostic.fix = "Automated bypass is exhausted for this specific boundary; manual reverse-engineering and target-specific authorization are required.".into();
    let _ = request;
    diagnostic
}

fn framework_offset_diagnostic(
    request: &BypassRequest,
    framework: FrameworkKind,
    build: &str,
) -> Diagnostic {
    bypass_diagnostic(
        catalogue::SANDBOX_BYPASS_FRAMEWORK_OFFSET_MISS,
        "framework",
        format!(
            "{framework:?} build {build} for {}",
            request.target.package_name
        ),
    )
}

fn bypass_diagnostic(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    key: &str,
    value: String,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "backend_id".to_owned(),
        DiagnosticValue::String("sandbox.bypass".to_owned()),
    );
    context.insert(key.to_owned(), DiagnosticValue::String(value));
    definition.instantiate(context)
}

fn find_named_file(root: &Path, filename: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && path.file_name().is_some_and(|name| name == filename) {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_named_file(&path, filename) {
                return Some(found);
            }
        }
    }
    None
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    pattern == value
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_string(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn safe_token(value: &str) -> String {
    let token = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .take(48)
        .collect::<String>();
    if token.is_empty() {
        "session".to_owned()
    } else {
        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_tree_matches_by_extension_and_needle_and_respects_recursion() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-pin-scan-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let nested = root.join("res").join("xml");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("network_security_config.xml"), "<network-security-config><pin-set><pin digest=\"SHA-256\">AAAA</pin></pin-set></network-security-config>").unwrap();
        // A same-content file with the wrong extension must not match.
        fs::write(root.join("readme.txt"), "pin-set").unwrap();

        let mut scan = ScanState::new();
        assert!(scan_tree(&root, &["xml"], &["pin-set"], &mut scan));
        assert!(!scan.truncated, "a small tree must scan to completion");

        let mut scan = ScanState::new();
        assert!(
            !scan_tree(&root, &["smali"], &["CertificatePinner"], &mut scan),
            "no smali files present"
        );

        let mut scan = ScanState::new();
        assert!(
            !scan_tree(&root, &["txt"], &["absent-needle"], &mut scan),
            "needle not present"
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn unique_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "apiaxess-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn deep_pin_literal_is_found_regardless_of_position() {
        let root = unique_root("pin-deep");
        // Many decoy files plus a deeply nested directory whose smali carries the
        // real CertificatePinner reference — the exact "deep pin literal" the old
        // 8k-file cap could miss.
        let branch = root.join("smali").join("a").join("b");
        fs::create_dir_all(&branch).unwrap();
        for index in 0..64 {
            fs::write(branch.join(format!("Decoy{index}.smali")), "nothing here").unwrap();
        }
        let deep = branch.join("c").join("d").join("e");
        fs::create_dir_all(&deep).unwrap();
        fs::write(
            deep.join("Pinner.smali"),
            "invoke-virtual {v0}, Lokhttp3/CertificatePinner$Builder;->add(...)",
        )
        .unwrap();

        let mut scan = ScanState::new();
        assert!(
            scan_tree(&root, &["smali"], &["CertificatePinner"], &mut scan),
            "a deep pin literal must be found, not missed by the scan cap"
        );
        assert!(
            !scan.truncated,
            "an ample scan completes without truncation"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_reports_truncation_when_the_cap_is_hit() {
        let root = unique_root("pin-cap");
        fs::create_dir_all(&root).unwrap();
        // More non-matching files than the cap: the scan stops early and must
        // report truncation instead of a silent (false) "no pinning".
        for index in 0..16 {
            fs::write(root.join(format!("Class{index}.smali")), "no pins here").unwrap();
        }
        let mut capped = ScanState::new();
        capped.max_files = 3;
        assert!(!scan_tree(
            &root,
            &["smali"],
            &["CertificatePinner"],
            &mut capped
        ));
        assert!(
            capped.truncated,
            "a scan stopped by the cap must be reported as truncated, not a false negative"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn builtin_registry_covers_common_java_pinning_landscape() {
        let registry = BypassTechniqueRegistry::builtins();
        let ids = registry
            .specs()
            .iter()
            .map(|spec| spec.technique_id.as_str())
            .collect::<Vec<_>>();
        assert!(ids.iter().any(|id| id.contains("okhttp")));
        assert!(ids.iter().any(|id| id.contains("x509")));
        assert!(ids.iter().any(|id| id.contains("hostname")));
        assert!(ids.iter().any(|id| id.contains("network-security")));
        assert!(ids.iter().any(|id| id.contains("conscrypt")));
    }

    #[test]
    fn declarative_specs_render_into_spawn_gated_script() {
        let registry = BypassTechniqueRegistry::builtins();
        let script = generate_frida_script("com.example.pinned", registry.specs(), None);
        assert!(script.contains("okhttp3.CertificatePinner"));
        assert!(script.contains("android.app.Application"));
        assert!(script.contains("Java.perform"));
    }

    fn inventory(rooted: bool, framework: Option<FrameworkKind>) -> TargetInventory {
        TargetInventory {
            package_name: "com.example.pinned".to_owned(),
            apks: vec![TargetApk {
                id: "base".to_owned(),
                path: PathBuf::from("base.apk"),
                is_base: true,
            }],
            rooted_available: rooted,
            frameworks: framework.into_iter().collect::<Vec<_>>(),
            native_libraries: Vec::new(),
            build_fingerprint: None,
            escalation_boundaries: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn lane_selection_is_automatic_and_specialized_lanes_take_precedence() {
        let registry = BypassTechniqueRegistry::builtins();
        let mut request = BypassRequest::new("session", "lease", inventory(true, None));
        assert_eq!(
            plan_bypass(&request, &registry).lane,
            BypassLane::PrimaryFrida
        );
        request.target.rooted_available = false;
        assert_eq!(
            plan_bypass(&request, &registry).lane,
            BypassLane::FallbackPatch
        );
        request.target.frameworks = vec![FrameworkKind::Flutter];
        assert_eq!(
            plan_bypass(&request, &registry).lane,
            BypassLane::FlutterNative
        );
    }

    #[test]
    fn escalation_is_explicit_and_does_not_fall_through_to_patch() {
        let registry = BypassTechniqueRegistry::builtins();
        let mut request = BypassRequest::new("session", "lease", inventory(true, None));
        request.target.escalation_boundaries = vec![EscalationBoundary::ClientMtls];
        let plan = plan_bypass(&request, &registry);
        assert_eq!(plan.lane, BypassLane::Escalation);
        assert!(plan.diagnostics[0].why.contains("private-key extraction"));
    }

    #[test]
    fn native_offset_miss_has_a_distinct_diagnostic() {
        let registry = BypassTechniqueRegistry::builtins();
        let mut request = BypassRequest::new(
            "session",
            "lease",
            inventory(false, Some(FrameworkKind::Flutter)),
        );
        request.target.build_fingerprint = Some("flutter-unknown".to_owned());
        let plan = plan_bypass(&request, &registry);
        assert_eq!(plan.lane, BypassLane::FlutterNative);
        let definition =
            framework_offset_diagnostic(&request, FrameworkKind::Flutter, "flutter-unknown");
        assert_eq!(
            definition.id.as_ref(),
            "sandbox.bypass.framework-offset-miss"
        );
    }

    #[test]
    fn frida_targeting_defaults_to_the_bundled_emulator_and_no_serial() {
        let targeting = FridaTargeting::default();
        assert_eq!(targeting.frida_host_port, DEVICE_FRIDA_SERVER_PORT);
        assert!(targeting.device_serial.is_none());
        // A request built with `new` carries the default targeting, so the bundled
        // emulator path is unchanged.
        let request = BypassRequest::new("s", "l", inventory(true, None));
        assert_eq!(request.frida, FridaTargeting::default());
    }

    #[test]
    fn device_targeting_by_serial_and_distinct_host_port_is_retained() {
        let mut request = BypassRequest::new("s", "l", inventory(true, None));
        request.frida = FridaTargeting {
            device_serial: Some("0A1B2C3D".to_owned()),
            frida_host_port: 27055,
        };
        assert_eq!(request.frida.device_serial.as_deref(), Some("0A1B2C3D"));
        assert_eq!(request.frida.frida_host_port, 27055);
    }

    /// A control transport whose methods are never reached on the escalation path.
    struct UnreachableControl;
    impl SandboxControl for UnreachableControl {
        fn command(
            &self,
            _arguments: &[String],
            _timeout: Duration,
        ) -> Result<crate::SandboxCommandOutput, Diagnostic> {
            unreachable!("escalation returns before the control transport is used")
        }
        fn shell(
            &self,
            _arguments: &[String],
            _timeout: Duration,
        ) -> Result<crate::SandboxCommandOutput, Diagnostic> {
            unreachable!("escalation returns before the control transport is used")
        }
        fn put(
            &self,
            _bytes: &[u8],
            _remote_path: &str,
            _timeout: Duration,
        ) -> Result<crate::SandboxCommandOutput, Diagnostic> {
            unreachable!("escalation returns before the control transport is used")
        }
        fn remove(
            &self,
            _remote_path: &str,
            _timeout: Duration,
        ) -> Result<crate::SandboxCommandOutput, Diagnostic> {
            unreachable!("escalation returns before the control transport is used")
        }
        fn install_apks(
            &self,
            _apk_paths: &[PathBuf],
            _timeout: Duration,
        ) -> Result<crate::SandboxCommandOutput, Diagnostic> {
            unreachable!("escalation returns before the control transport is used")
        }
        fn transport_id(&self) -> &str {
            "device-adb"
        }
    }

    struct UnreachableRunner;
    impl ExternalToolRunner for UnreachableRunner {
        fn probe(
            &self,
            _request: &ToolProbeRequest,
        ) -> Result<ToolProbe, apiaxess_external_tools::ExternalToolError> {
            unreachable!("escalation returns before any tool is probed")
        }
        fn invoke(
            &self,
            _request: &ToolInvocationRequest,
        ) -> Result<
            apiaxess_external_tools::ToolInvocation,
            apiaxess_external_tools::ExternalToolError,
        > {
            unreachable!("escalation returns before any tool is invoked")
        }
    }

    #[test]
    fn lease_free_device_entry_short_circuits_on_an_escalation_boundary() {
        // apply_bypass_on_control is the Phase C4 lease-free entry used to target a
        // device by serial. On an escalation boundary it must return the boundary
        // diagnostics without touching the device transport.
        let registry = BypassTechniqueRegistry::builtins();
        let mut request = BypassRequest::new("session", "lease", inventory(true, None));
        request.target.escalation_boundaries = vec![EscalationBoundary::ClientMtls];
        request.frida.device_serial = Some("0A1B2C3D".to_owned());
        let control: Arc<dyn SandboxControl> = Arc::new(UnreachableControl);
        let runner: Arc<dyn ExternalToolRunner> = Arc::new(UnreachableRunner);
        let diagnostics = apply_bypass_on_control(&control, &request, &registry, &runner)
            .expect_err("escalation boundary is an error");
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "sandbox.bypass.escalation-boundary")
        );
    }
}
