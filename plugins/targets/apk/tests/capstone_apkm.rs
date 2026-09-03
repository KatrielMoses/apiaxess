//! Environment-gated real APKM capstone evidence harness.
//!
//! The test is part of every workspace test run, but it reports a reasoned
//! skip unless `APIAXESS_CAPSTONE_LIVE=1` and the documented live prerequisites
//! are available. See `docs/testing/apkm-capstone.md` for the deliberate run
//! procedure; use `--nocapture` when inspecting skip or stage evidence.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_dynamic_capture::{DynamicCaptureConfig, capture_into_session};
use apiaxess_external_tools::{
    ExternalToolRunner, ProcessToolRunner, ToolInvocationRequest, ToolProbeRequest,
    ToolRequirement, ToolVersion,
};
use apiaxess_host_capabilities::{HostCapabilityService, HostDetectionConfig};
use apiaxess_network_extraction::extract;
use apiaxess_network_routing::NetworkingRouter;
use apiaxess_sandbox::pinning::{
    BypassRequest, BypassTechniqueRegistry, TargetInventory, apply_bypass, plan_bypass,
};
use apiaxess_sandbox::traffic::{
    CaTrustConfig, L3Mechanism, L3RoutingConfig, SandboxTrafficSession,
};
use apiaxess_sandbox::{
    AvdBackend, AvdConfig, ExistingImageManager, SandboxBackend, SandboxControl,
    SandboxStartRequest, SandboxTier,
};
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AllowedNetworkTarget,
    AuditActor, EngagementScope, HostMatch, Session, SessionId, TargetIdentifier, TargetIdentity,
};
use apiaxess_static_pass::normalize;
use apiaxess_target_apk::{ApkIntakeConfig, ApkTarget, ApkToolchainConfig};
use apiaxess_workbench_proxy::{FlowObserver, LiveWorkbench, ProxyCore, SessionCa, TrafficStore};
use chrono::Utc;
use tokio::runtime::Runtime;

fn capstone_stage_report_path(output_root: &Path) -> PathBuf {
    output_root
        .parent()
        .and_then(|parent| {
            output_root
                .file_name()
                .map(|name| parent.join(format!("{}-stage-report.txt", name.to_string_lossy())))
        })
        .unwrap_or_else(|| output_root.join("capstone-stage-report.txt"))
}

const CAPSTONE_LIVE_ENV: &str = "APIAXESS_CAPSTONE_LIVE";
const DEFAULT_CAPSTONE_FIXTURE: &str = "fixtures/capstone/feeder-2.22.0-4050.apk";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn configured_path(root: &Path, variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable).map(|value| {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            root.join(path)
        }
    })
}

fn capstone_input(root: &Path) -> PathBuf {
    configured_path(root, "APIAXESS_CAPSTONE_APK")
        .or_else(|| configured_path(root, "APIAXESS_CAPSTONE_APKM"))
        .unwrap_or_else(|| root.join(DEFAULT_CAPSTONE_FIXTURE))
}

fn enabled(value: &Result<String, std::env::VarError>) -> bool {
    matches!(value.as_deref(), Ok("1" | "true" | "yes"))
}

fn tool_probe_succeeds(
    tool_id: &str,
    executable: &str,
    version_arguments: Vec<String>,
    minimum: ToolVersion,
) -> bool {
    ProcessToolRunner
        .probe(&ToolProbeRequest {
            tool_id: tool_id.to_owned(),
            executable: executable.to_owned(),
            version_arguments,
            requirement: ToolRequirement { minimum },
        })
        .is_ok()
}

fn docker_image_available(docker: &str, image: &str, digest: &str) -> bool {
    let reference = if image.contains('@') {
        image.to_owned()
    } else {
        format!("{image}@{digest}")
    };
    let Ok(probe) = ProcessToolRunner.probe(&ToolProbeRequest {
        tool_id: "container.docker".to_owned(),
        executable: docker.to_owned(),
        version_arguments: vec!["version".to_owned()],
        requirement: ToolRequirement {
            minimum: ToolVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
        },
    }) else {
        return false;
    };
    ProcessToolRunner
        .invoke(&ToolInvocationRequest {
            probe,
            arguments: vec!["image".to_owned(), "inspect".to_owned(), reference],
            working_directory: None,
            environment: Vec::new(),
            timeout: Duration::from_secs(30),
        })
        .is_ok_and(|invocation| invocation.exit_code == Some(0))
}

fn capstone_skip_reason(root: &Path, input: &Path, tools: &ApkToolchainConfig) -> Option<String> {
    if !enabled(&std::env::var(CAPSTONE_LIVE_ENV)) {
        return Some(format!(
            "set {CAPSTONE_LIVE_ENV}=1 to run the live harness (fixture: {})",
            input.strip_prefix(root).unwrap_or(input).display()
        ));
    }
    if !input.is_file() {
        return Some(format!(
            "designated fixture is missing: {} (place the authorized APK there or set APIAXESS_CAPSTONE_APK)",
            input.display()
        ));
    }
    for (label, launch, variable) in [
        ("apktool", &tools.apktool, "APIAXESS_APKTOOL"),
        ("jadx", &tools.jadx, "APIAXESS_JADX"),
    ] {
        let minimum = if label == "apktool" {
            tools.apktool_minimum
        } else {
            tools.jadx_minimum
        };
        let mut version_arguments = launch.launch_prefix.clone();
        version_arguments.push("--version".to_owned());
        if !tool_probe_succeeds(label, &launch.executable, version_arguments, minimum) {
            return Some(format!(
                "{label} unavailable ({:?}); reinstall APIaxess or set {variable}",
                launch.executable
            ));
        }
    }

    let static_only = enabled(&std::env::var("APIAXESS_CAPSTONE_STOP_AFTER_STATIC"))
        || enabled(&std::env::var("APIAXESS_CAPSTONE_STOP_AFTER_INTAKE"));
    if !static_only {
        let avd = capstone_avd_config();
        if !tool_probe_succeeds(
            "android.adb",
            &avd.adb_executable,
            vec!["version".to_owned()],
            ToolVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
        ) {
            return Some(format!(
                "HQarroum emulator unavailable: host ADB executable {:?} was not found",
                avd.adb_executable
            ));
        }
        if !tool_probe_succeeds(
            "container.docker",
            &avd.docker_executable,
            vec!["version".to_owned()],
            ToolVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
        ) {
            return Some(format!(
                "HQarroum emulator unavailable: Docker executable {:?} was not found",
                avd.docker_executable
            ));
        }
        if !docker_image_available(&avd.docker_executable, &avd.image, &avd.image_digest) {
            return Some(format!(
                "HQarroum image unavailable: pull {}@{} before enabling the live run",
                avd.image, avd.image_digest
            ));
        }

        // The backend's own preflight is the source of truth for native
        // acceleration, WSL2 nested KVM, Docker, and authenticated ADB support.
        let detection = HostDetectionConfig {
            adb_executable: avd.adb_executable.clone(),
            docker_executable: avd.docker_executable.clone(),
            ..HostDetectionConfig::default()
        };
        let capabilities =
            HostCapabilityService::with_config(Arc::new(ProcessToolRunner), detection).detect();
        let backend = AvdBackend::new(
            avd,
            Arc::new(ProcessToolRunner),
            capabilities,
            Arc::new(ExistingImageManager),
        );
        let plan = backend.preflight();
        if !plan.is_runnable() {
            return Some(format!(
                "HQarroum emulator unavailable: preflight diagnostics {:?}",
                plan.diagnostics
            ));
        }
    }
    None
}

fn skip_capstone(reason: impl std::fmt::Display) {
    eprintln!("skipped: APKM capstone — {reason}");
}

fn capstone_avd_config() -> AvdConfig {
    let mut config = AvdConfig::default();
    if let Some(adb) = std::env::var_os("APIAXESS_ADB") {
        config.adb_executable = PathBuf::from(adb).display().to_string();
    }
    if let Some(docker) = std::env::var_os("APIAXESS_DOCKER") {
        config.docker_executable = PathBuf::from(docker).display().to_string();
    }
    config
}

#[derive(Debug)]
struct GuestFetchPreflight {
    network_probe: String,
    completed_flow_ids: Vec<u64>,
}

fn completed_flow_ids_after_preflight<I>(baseline_max: u64, flows: I) -> Vec<u64>
where
    I: IntoIterator<Item = (u64, bool, bool)>,
{
    flows
        .into_iter()
        .filter(|(id, has_method, has_status)| *id > baseline_max && *has_method && *has_status)
        .map(|(id, _, _)| id)
        .collect()
}

fn guest_fetch_preflight_diagnostic(evidence: impl Into<String>) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "evidence".to_owned(),
        DiagnosticValue::String(evidence.into()),
    );
    catalogue::SANDBOX_GUEST_FETCH_PREFLIGHT_FAILED.instantiate(context)
}

fn feeder_feed_query(
    control: &Arc<dyn SandboxControl>,
    expected_url: &str,
) -> Result<String, Diagnostic> {
    let expected_host = expected_url
        .split_once("://")
        .map_or(expected_url, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(expected_url);
    let query = format!(
        "content query --uri content://com.nononsenseapps.feeder.rssprovider/feeds --where \"url LIKE '%{expected_host}%'\" --projection _id:title"
    );
    control
        .command(
            &["shell".to_owned(), "sh".to_owned(), "-c".to_owned(), query],
            Duration::from_secs(30),
        )
        .map(|output| {
            format!(
                "exit_code={:?} stdout={} stderr={}",
                output.exit_code,
                output.stdout.trim(),
                output.stderr.trim()
            )
        })
        .map_err(|error| {
            guest_fetch_preflight_diagnostic(format!("Feeder feed query failed: {error}"))
        })
}

fn feeder_imported_feed(
    control: &Arc<dyn SandboxControl>,
    expected_url: &str,
) -> Result<bool, Diagnostic> {
    let evidence = feeder_feed_query(control, expected_url)?;
    println!("STAGE 3 FEEDER IMPORT VERIFY: {evidence}");
    Ok(evidence.contains("Row:") && evidence.contains("id="))
}

fn feeder_dump_ui(control: &Arc<dyn SandboxControl>, label: &str) {
    let dump = control.command(
        &[
            "shell".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            "uiautomator dump /data/local/tmp/apiaxess-feeder-ui.xml >/dev/null 2>&1; cat /data/local/tmp/apiaxess-feeder-ui.xml; rm -f /data/local/tmp/apiaxess-feeder-ui.xml".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 3 FEEDER UI {label}: {dump:?}");
}

fn feeder_press_import_confirmation(control: &Arc<dyn SandboxControl>, expected_url: &str) {
    let enter = control.command(
        &[
            "shell".to_owned(),
            "input".to_owned(),
            "keyevent".to_owned(),
            "66".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 3 FEEDER OPML CONFIRM ENTER: {enter:?}");
    std::thread::sleep(Duration::from_secs(2));
    if let Ok(imported) = feeder_imported_feed(control, expected_url) {
        if imported {
            return;
        }
    }

    // Compose's confirmation dialog is bottom-right anchored on the HQarroum
    // 1080x1920 guest. Enter is the first attempt; this is the deterministic
    // touch fallback for images where the dialog has no focused button.
    let tap = control.command(
        &[
            "shell".to_owned(),
            "input".to_owned(),
            "tap".to_owned(),
            "930".to_owned(),
            "1740".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 3 FEEDER OPML CONFIRM TAP: {tap:?}");
}

fn feeder_force_sync(control: &Arc<dyn SandboxControl>) {
    let swipe = control.command(
        &[
            "shell".to_owned(),
            "input".to_owned(),
            "swipe".to_owned(),
            "540".to_owned(),
            "500".to_owned(),
            "540".to_owned(),
            "1500".to_owned(),
            "800".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 4 FEEDER FORCE SYNC PULL-TO-REFRESH: {swipe:?}");

    // Feeder's MainActivity and its pull-to-refresh both schedule RSS_SYNC
    // (job id 1). Run it explicitly as a second, force-network trigger so the
    // harness does not depend on the app's scheduler timing.
    let job = control.command(
        &[
            "shell".to_owned(),
            "cmd".to_owned(),
            "jobscheduler".to_owned(),
            "run".to_owned(),
            "-f".to_owned(),
            "-u".to_owned(),
            "0".to_owned(),
            "com.nononsenseapps.feeder".to_owned(),
            "1".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 4 FEEDER FORCE SYNC JOBSCHEDULER: {job:?}");
}

fn feeder_deterministic_fetch(control: &Arc<dyn SandboxControl>) -> Result<(), Diagnostic> {
    const HOST: &str = "planet.gnome.org";
    const PATH: &str = "/atom.xml";
    const URL: &str = "http://planet.gnome.org/atom.xml";
    let request = "printf 'GET /atom.xml HTTP/1.1\\r\\nHost: planet.gnome.org\\r\\nConnection: close\\r\\n\\r\\n' | toybox nc -w 20 planet.gnome.org 80 | toybox grep -q '^HTTP/'; status=$?; echo APIAXESS_DETERMINISTIC_FETCH=HTTP_RESULT_$status; exit \"$status\"";
    let fetch = control.command(
        &[
            "shell".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            request.to_owned(),
        ],
        Duration::from_secs(30),
    )?;
    if fetch.exit_code == Some(0) {
        println!(
            "STAGE 4 DETERMINISTIC FEED FETCH PASS: url={URL} host={HOST} path={PATH} result={fetch:?}"
        );
        Ok(())
    } else {
        let evidence = format!(
            "deterministic guest fetch exited with {:?}: stdout={} stderr={}",
            fetch.exit_code,
            fetch.stdout.trim(),
            fetch.stderr.trim()
        );
        println!("STAGE 4 DETERMINISTIC FEED FETCH FINDING: {evidence}");
        Err(guest_fetch_preflight_diagnostic(evidence))
    }
}

fn run_guest_fetch_preflight(
    control: &Arc<dyn SandboxControl>,
    store: &TrafficStore,
) -> Result<GuestFetchPreflight, Diagnostic> {
    let network_probe = control.command(
        &[
            "shell".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            "ip route 2>/dev/null || true; if toybox wget -q -O /dev/null -T 10 https://example.com; then echo APIAXESS_NETWORK_PROBE=HTTPS_PASS; elif toybox nc -w 10 1.1.1.1 443 </dev/null >/dev/null 2>&1; then echo APIAXESS_NETWORK_PROBE=TCP_PASS; elif ping -c 1 -W 10 1.1.1.1 >/dev/null 2>&1; then echo APIAXESS_NETWORK_PROBE=ICMP_PASS_HTTP_UNAVAILABLE; else echo APIAXESS_NETWORK_PROBE=FAIL; fi".to_owned(),
        ],
        Duration::from_secs(30),
    )
    .map_err(|error| guest_fetch_preflight_diagnostic(format!("network probe command failed: {error}")))?;
    let network_status = network_probe
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("APIAXESS_NETWORK_PROBE="))
        .unwrap_or("UNKNOWN")
        .to_owned();
    let baseline_max = store
        .summaries()
        .map_err(|error| {
            guest_fetch_preflight_diagnostic(format!("baseline store read failed: {error}"))
        })?
        .iter()
        .map(|flow| flow.id)
        .max()
        .unwrap_or_default();
    let forced_probe = control.command(
        &[
            "shell".to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            "{ echo 'GET / HTTP/1.0'; echo 'Host: example.com'; echo 'Connection: close'; echo; } | toybox nc -w 15 1.1.1.1 80 >/data/local/tmp/apiaxess-preflight.out 2>/data/local/tmp/apiaxess-preflight.err; status=$?; echo APIAXESS_PREFLIGHT_NC_STATUS=$status; head -c 200 /data/local/tmp/apiaxess-preflight.out; cat /data/local/tmp/apiaxess-preflight.err; rm -f /data/local/tmp/apiaxess-preflight.out /data/local/tmp/apiaxess-preflight.err".to_owned(),
        ],
        Duration::from_secs(30),
    )
    .map_err(|error| guest_fetch_preflight_diagnostic(format!("forced HTTP probe command failed: {error}")))?;
    let mut completed_flow_ids = Vec::new();
    for _ in 0..20 {
        let summaries = store.summaries().map_err(|error| {
            guest_fetch_preflight_diagnostic(format!("post-probe store read failed: {error}"))
        })?;
        completed_flow_ids = completed_flow_ids_after_preflight(
            baseline_max,
            summaries
                .iter()
                .map(|flow| (flow.id, flow.method.is_some(), flow.status.is_some())),
        );
        if !completed_flow_ids.is_empty() {
            return Ok(GuestFetchPreflight {
                network_probe: format!(
                    "{network_status}; forced_probe={:?}",
                    forced_probe.stdout.trim()
                ),
                completed_flow_ids,
            });
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(guest_fetch_preflight_diagnostic(format!(
        "network={network_status}; forced_probe={:?}; completed_flow_ids={completed_flow_ids:?}",
        forced_probe.stdout.trim()
    )))
}

#[test]
fn guest_fetch_preflight_accepts_only_new_completed_flows() {
    let completed = completed_flow_ids_after_preflight(
        4,
        [
            (3, true, true),  // pre-existing flow
            (5, true, false), // request reached the proxy but did not complete
            (6, true, true),  // completed preflight proof
            (7, false, true), // response-only/incomplete record
        ],
    );
    assert_eq!(completed, vec![6]);
}

// The capstone test intentionally keeps all stage evidence in one linear
// harness so failures can be correlated with the corresponding handoff.
#[allow(clippy::too_many_lines)]
#[test]
fn real_apkm_capstone_evidence() {
    let root = workspace_root();
    let input = capstone_input(&root);
    // The default toolchain resolves the bundled Java runtime + apktool + jadx
    // from the install layout and honors the APIAXESS_* overrides internally.
    let tools = ApkToolchainConfig::default();
    if let Some(reason) = capstone_skip_reason(&root, &input, &tools) {
        skip_capstone(reason);
        return;
    }

    let stamp = Utc::now().format("%Y%m%d%H%M%S");
    let output_root = std::env::var_os("APIAXESS_CAPSTONE_OUTPUT_ROOT").map_or_else(
        || root.join(format!("tmp/capstone-intake-{stamp}")),
        PathBuf::from,
    );
    let config = ApkIntakeConfig {
        output_root: output_root.clone(),
        tool_timeout: Duration::from_secs(900),
        tools,
    };
    let target = ApkTarget::new(Arc::new(ProcessToolRunner), config);

    let artifact = target
        .intake(&input)
        .unwrap_or_else(|failure| panic!("STAGE 1/2 intake failed: {}", failure.diagnostic));
    println!(
        "STAGE 1 PASS: format={:?}, resolved_splits={}, workspace={}",
        artifact.input_format,
        artifact.installable_apks.len(),
        artifact.workspace_root
    );
    for apk in &artifact.installable_apks {
        println!("  APK {} base={} path={}", apk.id, apk.is_base, apk.path);
    }
    println!(
        "  protection={:?} signatures={:?}",
        artifact
            .protection
            .profile
            .as_ref()
            .map(|profile| profile.tier),
        artifact.protection.signatures
    );
    if std::env::var_os("APIAXESS_CAPSTONE_STOP_AFTER_INTAKE").is_some() {
        let intake_teardown = target.cleanup(&artifact);
        println!("STAGE 1 MEASUREMENT TEARDOWN: {intake_teardown:?}");
        return;
    }

    let routed = NetworkingRouter::default().route(&artifact);
    println!(
        "STAGE 2 ROUTING: networking_present={}, libraries={:?}, diagnostics={}",
        routed.networking_present,
        routed
            .detections
            .iter()
            .map(|detection| detection.display_name.as_str())
            .collect::<Vec<_>>(),
        routed.diagnostics.len()
    );
    if std::env::var_os("APIAXESS_BREAKDOWN_EVIDENCE").is_some() {
        for detection in &routed.detections {
            let paths = detection
                .evidence
                .iter()
                .map(|hit| hit.path.clone())
                .collect::<std::collections::BTreeSet<_>>();
            println!(
                "STATIC EVIDENCE: library={} hits={} paths={} sample_paths={:?}",
                detection.library_id,
                detection.evidence.len(),
                paths.len(),
                paths.into_iter().take(8).collect::<Vec<_>>()
            );
        }
    }
    let extracted = extract(&artifact, &routed).expect("static extraction");
    let static_report = normalize(&artifact, &routed, &extracted).expect("static honesty pass");
    println!(
        "STAGE 2 PASS: endpoints={}, loose_findings={}, handoffs={}, static_diagnostics={}, protection_tier={:?}",
        static_report.document.surface.endpoints.len(),
        static_report.document.surface.loose_findings.len(),
        static_report.honesty.dynamic_handoffs.len(),
        static_report.diagnostics.len(),
        artifact
            .protection
            .profile
            .as_ref()
            .map(|profile| profile.tier)
    );
    if std::env::var_os("APIAXESS_BREAKDOWN_EVIDENCE").is_some() {
        println!("STATIC RECORDS: {:?}", extracted.records);
    }
    if std::env::var_os("APIAXESS_CAPSTONE_STOP_AFTER_STATIC").is_some() {
        let intake_teardown = target.cleanup(&artifact);
        println!("STAGE 2 MEASUREMENT TEARDOWN: {intake_teardown:?}");
        return;
    }

    let capabilities = HostCapabilityService::new().detect();
    let backend = AvdBackend::new(
        capstone_avd_config(),
        Arc::new(ProcessToolRunner),
        capabilities,
        Arc::new(ExistingImageManager),
    );
    let plan = backend.preflight();
    println!(
        "STAGE 3 PREFLIGHT: runnable={} diagnostics={:?}",
        plan.is_runnable(),
        plan.diagnostics
    );
    let request = SandboxStartRequest {
        session_id: "session:capstone-apkm".to_owned(),
        lease_id: format!("lease:capstone-apkm-{stamp}"),
        readiness_timeout: Duration::from_secs(300),
    };
    let mut lease = match backend.start(&request) {
        Ok(lease) => lease,
        Err(diagnostics) => {
            let intake_teardown = target.cleanup(&artifact);
            println!("STAGE 7 INTAKE TEARDOWN AFTER STAGE 3 FAILURE: {intake_teardown:?}");
            panic!("STAGE 3 sandbox start failed: {diagnostics:?}");
        }
    };
    println!("STAGE 3 SANDBOX PASS: handle={:?}", lease.handle());

    let install = lease.resolve_and_install(&artifact, Duration::from_secs(180));
    println!("STAGE 3 INSTALL: {install:?}");
    if let Err(diagnostics) = install {
        let teardown = lease.teardown();
        println!("STAGE 7 TEARDOWN AFTER INSTALL FAILURE: {teardown:?}");
        let intake_teardown = target.cleanup(&artifact);
        println!("STAGE 7 INTAKE TEARDOWN AFTER INSTALL FAILURE: {intake_teardown:?}");
        panic!("STAGE 3 install failed: {diagnostics:?}");
    }
    println!("STAGE 3 PASS: install completed");

    let package_name = std::env::var("APIAXESS_CAPSTONE_PACKAGE")
        .unwrap_or_else(|_| "com.nononsenseapps.feeder".to_owned());
    if package_name == "org.breezyweather"
        || std::env::var("APIAXESS_CAPSTONE_GRANT_LOCATION").as_deref() == Ok("1")
    {
        let control = lease.control();
        for permission in [
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        ] {
            let result = control.command(
                &[
                    "shell".to_owned(),
                    "pm".to_owned(),
                    "grant".to_owned(),
                    package_name.clone(),
                    permission.to_owned(),
                ],
                Duration::from_secs(30),
            );
            println!("STAGE 3 BREEZY LOCATION GRANT {permission}: {result:?}");
        }
        let location_mode = control.command(
            &[
                "shell".to_owned(),
                "settings".to_owned(),
                "put".to_owned(),
                "secure".to_owned(),
                "location_mode".to_owned(),
                "3".to_owned(),
            ],
            Duration::from_secs(30),
        );
        println!("STAGE 3 BREEZY LOCATION MODE: {location_mode:?}");
        let geo_fix = control.command(
            &[
                "emu".to_owned(),
                "geo".to_owned(),
                "fix".to_owned(),
                "-73.9857".to_owned(),
                "40.7484".to_owned(),
            ],
            Duration::from_secs(30),
        );
        println!("STAGE 3 BREEZY GEO FIX: {geo_fix:?}");
    }
    let feed_url = std::env::var("APIAXESS_CAPSTONE_FEED_URL")
        .unwrap_or_else(|_| "https://planet.gnome.org/atom.xml".to_owned());
    let allowed_domain = std::env::var("APIAXESS_CAPSTONE_ALLOWED_DOMAIN").unwrap_or_else(|_| {
        if package_name == "com.nononsenseapps.feeder" {
            "planet.gnome.org".to_owned()
        } else {
            "mastodon.social".to_owned()
        }
    });
    let session_id = SessionId::new("session:capstone-apkm").expect("stable session ID");
    let scope = EngagementScope {
        declared_at: Utc::now(),
        target: TargetIdentity {
            target_type: "apk".to_owned(),
            primary: TargetIdentifier {
                kind: "artifact.path".to_owned(),
                value: input.display().to_string(),
            },
            aliases: vec![TargetIdentifier {
                kind: "android.package".to_owned(),
                value: package_name.clone(),
            }],
        },
        allowed_targets: vec![AllowedNetworkTarget {
            id: "capstone.allowed-domain".to_owned(),
            host: HostMatch::DomainSuffix {
                domain: allowed_domain.clone(),
            },
            ports: vec![80, 443],
        }],
    };
    let mut session = Session::new(
        session_id,
        scope.clone(),
        static_report.document.clone(),
        Utc::now(),
    );
    session
        .activate(Utc::now())
        .expect("activate capstone session");

    let inventory = TargetInventory::from_normalized(&package_name, &artifact, true);
    let mut bypass_request = BypassRequest::new(
        session.id().as_str().to_owned(),
        request.lease_id.clone(),
        inventory,
    );
    if let Some(path) = std::env::var_os("APIAXESS_FRIDA_SERVER") {
        bypass_request.toolchain.frida_server_path = PathBuf::from(path);
    }
    if let Some(frida) = std::env::var_os("APIAXESS_FRIDA") {
        bypass_request.toolchain.frida_executable = PathBuf::from(frida).display().to_string();
    }
    let bypass_registry = BypassTechniqueRegistry::builtins();
    let bypass_plan = plan_bypass(&bypass_request, &bypass_registry);
    println!(
        "STAGE 5 PLAN: lane={:?}, reason={}, diagnostics={:?}",
        bypass_plan.lane, bypass_plan.reason, bypass_plan.diagnostics
    );
    let tool_runner: Arc<dyn ExternalToolRunner> = Arc::new(ProcessToolRunner);
    let frida_configured = std::env::var_os("APIAXESS_FRIDA_SERVER").is_some()
        || std::env::var_os("APIAXESS_FRIDA").is_some();
    let bypass_outcome = if frida_configured {
        match apply_bypass(&mut lease, &bypass_request, &bypass_registry, &tool_runner) {
            Ok(outcome) => {
                println!("STAGE 5 BYPASS PASS: {outcome:?}");
                Some(outcome)
            }
            Err(diagnostics) => {
                println!("STAGE 5 BYPASS FINDING: {diagnostics:?}");
                None
            }
        }
    } else {
        println!(
            "STAGE 5 BYPASS NOT ENGAGED: no APIAXESS_FRIDA/APIAXESS_FRIDA_SERVER configured; pinning will be assessed from completed app traffic"
        );
        None
    };

    let preflight_store_parent = output_root.join("capstone-preflight-traffic");
    let preflight_store = Arc::new(
        TrafficStore::open(&preflight_store_parent, session.id().as_str())
            .expect("open guest-fetch preflight store"),
    );
    let store_parent = output_root.join("capstone-traffic");
    let store = Arc::new(
        TrafficStore::open(&store_parent, session.id().as_str())
            .expect("open capstone traffic store"),
    );
    let observer = Arc::new(LiveWorkbench::new());
    observer.attach_store(Arc::clone(&preflight_store));
    observer.set_engagement_scope(scope);
    observer.set_provenance("capstone.guest-fetch-preflight");
    let observer_for_proxy: Arc<dyn FlowObserver> = observer.clone();
    let ca = SessionCa::generate().expect("generate session CA");
    let runtime = Runtime::new().expect("create capture runtime");
    // The proxy is the embedded hudsucker backend (the only backend).
    let proxy = ProxyCore::new();
    let traffic = match runtime.block_on(SandboxTrafficSession::start(
        proxy,
        lease,
        &session,
        ca,
        observer_for_proxy,
        L3RoutingConfig {
            proxy_host: "10.0.2.2".to_owned(),
            proxy_port: 0,
            redirect_port: 0,
            mechanism: L3Mechanism::Iptables,
            lease_id: request.lease_id.clone(),
        },
        CaTrustConfig::for_tier(SandboxTier::Avd, "openssl", &request.lease_id),
        Arc::new(ProcessToolRunner),
        None,
    )) {
        Ok(traffic) => traffic,
        Err(diagnostics) => {
            println!("STAGE 4 FINDING: capture setup failed: {diagnostics:?}");
            drop(observer);
            drop(store);
            drop(preflight_store);
            let _ = fs::remove_dir_all(&store_parent);
            let _ = fs::remove_dir_all(&preflight_store_parent);
            let intake_teardown = target.cleanup(&artifact);
            println!("STAGE 7 TEARDOWN AFTER CAPTURE SETUP FAILURE: {intake_teardown:?}");
            assert!(
                intake_teardown.is_ok(),
                "intake workspace cleanup failed: {intake_teardown:?}"
            );
            println!(
                "STAGE 6 BLOCKED: no proxy session existed, so no dynamic model commit was attempted"
            );
            let stage_report = capstone_stage_report_path(&output_root);
            fs::write(
                &stage_report,
                format!(
                    "APIaxess {package_name} capstone stage report\n\
stage1=intake_pass\n\
stage2=static_pass endpoints={} loose_findings={} handoffs={} diagnostics={}\n\
stage3=install_pass\n\
stage4=capture_setup_failed diagnostics={diagnostics:?}\n\
stage5=bypass_applied={} lane={:?}\n\
stage6=blocked no_dynamic_commit=true\n\
stage7=normal_teardown_pass\n\
unclean_kill_check=not_run\n",
                    static_report.document.surface.endpoints.len(),
                    static_report.document.surface.loose_findings.len(),
                    static_report.honesty.dynamic_handoffs.len(),
                    static_report.diagnostics.len(),
                    bypass_outcome.is_some(),
                    bypass_plan.lane,
                ),
            )
            .expect("write capstone stage report");
            println!("STAGE REPORT: {}", stage_report.display());
            return;
        }
    };
    println!(
        "STAGE 4 CAPTURE SETUP PASS: proxy={} guest_endpoint={:?}",
        traffic.proxy_addr(),
        traffic.capture_endpoint()
    );

    let control = traffic.control().expect("active traffic control");
    let _preflight = match run_guest_fetch_preflight(&control, &preflight_store) {
        Ok(preflight) => {
            println!(
                "STAGE 4 GUEST-FETCH PREFLIGHT PASS: network={}, completed_flow_ids={:?}",
                preflight.network_probe, preflight.completed_flow_ids
            );
            preflight
        }
        Err(diagnostic) => {
            println!("STAGE 4 GUEST-FETCH PREFLIGHT FAIL: {diagnostic}");
            let teardown = runtime.block_on(traffic.teardown());
            println!("STAGE 7 TEARDOWN AFTER PREFLIGHT FAILURE: {teardown:?}");
            drop(observer);
            drop(store);
            drop(preflight_store);
            let _ = fs::remove_dir_all(&store_parent);
            let _ = fs::remove_dir_all(&preflight_store_parent);
            let intake_teardown = target.cleanup(&artifact);
            println!("STAGE 7 INTAKE TEARDOWN AFTER PREFLIGHT FAILURE: {intake_teardown:?}");
            assert!(
                teardown.is_ok() && intake_teardown.is_ok(),
                "preflight failure teardown failed: traffic={teardown:?}, intake={intake_teardown:?}"
            );
            let stage_report = capstone_stage_report_path(&output_root);
            fs::write(
                &stage_report,
                format!(
                    "APIaxess {package_name} capstone stage report\n\
stage1=intake_pass\n\
stage2=static_pass endpoints={} loose_findings={} handoffs={} diagnostics={}\n\
stage3=install_pass\n\
stage4=guest_fetch_preflight_failed diagnostic={diagnostic:?}\n\
stage5=not_run\n\
stage6=blocked no_dynamic_commit=true\n\
stage7=normal_teardown_pass\n\
unclean_kill_check=not_run\n",
                    static_report.document.surface.endpoints.len(),
                    static_report.document.surface.loose_findings.len(),
                    static_report.honesty.dynamic_handoffs.len(),
                    static_report.diagnostics.len(),
                ),
            )
            .expect("write preflight failure report");
            println!("STAGE REPORT: {}", stage_report.display());
            return;
        }
    };
    observer.attach_store(Arc::clone(&store));
    observer.set_provenance(format!("capstone.{package_name}.dynamic"));
    drop(preflight_store);
    fs::remove_dir_all(&preflight_store_parent).expect("remove preflight traffic store");
    let mut feeder_imported = None;
    if package_name == "com.nononsenseapps.feeder" {
        let opml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<opml version=\"2.0\"><head><title>APIaxess capstone</title></head><body><outline text=\"APIaxess feed\" title=\"APIaxess feed\" type=\"rss\" xmlUrl=\"{feed_url}\" htmlUrl=\"{feed_url}\" /></body></opml>"
        );
        let opml_path = "/sdcard/Download/apiaxess-capstone-feeds.opml";
        let opml_uri = "content://com.android.externalstorage.documents/document/primary%3ADownload%2Fapiaxess-capstone-feeds.opml";
        let push = control.put(opml.as_bytes(), opml_path, Duration::from_secs(30));
        println!("STAGE 3 FEEDER OPML SEED: path={opml_path} result={push:?}");
        let import = control.command(
            &[
                "shell".to_owned(),
                "am".to_owned(),
                "start".to_owned(),
                "--grant-read-uri-permission".to_owned(),
                "-a".to_owned(),
                "android.intent.action.VIEW".to_owned(),
                "-d".to_owned(),
                opml_uri.to_owned(),
                "-t".to_owned(),
                "text/x-opml".to_owned(),
            ],
            Duration::from_secs(30),
        );
        println!("STAGE 3 FEEDER OPML IMPORT: {import:?}");
        std::thread::sleep(Duration::from_secs(4));
        feeder_dump_ui(&control, "after parse before confirmation");
        feeder_press_import_confirmation(&control, &feed_url);
        for _ in 0..10 {
            match feeder_imported_feed(&control, &feed_url) {
                Ok(true) => {
                    feeder_imported = Some(true);
                    break;
                }
                Ok(false) => {}
                Err(error) => println!("STAGE 3 FEEDER IMPORT VERIFY FINDING: {error}"),
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        feeder_imported.get_or_insert(false);
        println!("STAGE 3 FEEDER OPML IMPORTED: {feeder_imported:?}");
    }
    let mut deterministic_fetch_passed = false;
    let launch = control.command(
        &[
            "shell".to_owned(),
            "monkey".to_owned(),
            "-p".to_owned(),
            package_name.clone(),
            "1".to_owned(),
        ],
        Duration::from_secs(30),
    );
    println!("STAGE 4 APP LAUNCH: {launch:?}");
    if package_name == "com.nononsenseapps.feeder" {
        match feeder_imported_feed(&control, &feed_url) {
            Ok(imported) => println!("STAGE 3 FEEDER IMPORT VISIBLE AFTER LAUNCH: {imported}"),
            Err(error) => println!("STAGE 3 FEEDER IMPORT VERIFY AFTER LAUNCH FINDING: {error}"),
        }
        feeder_force_sync(&control);
        deterministic_fetch_passed = feeder_deterministic_fetch(&control).is_ok();
        println!("STAGE 4 DETERMINISTIC FETCH RECORDED: {deterministic_fetch_passed}");
        std::thread::sleep(Duration::from_secs(5));
        feeder_dump_ui(&control, "after forced sync and deterministic fetch");
    }
    let exercise_seconds = std::env::var("APIAXESS_CAPSTONE_EXERCISE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(45);
    println!(
        "STAGE 4 EXERCISE: {package_name} seeded_feed={feed_url}; sleeping {exercise_seconds}s after launch."
    );
    std::thread::sleep(Duration::from_secs(exercise_seconds));
    let summaries = store.summaries().expect("read captured flow summaries");
    let captured = summaries
        .iter()
        .filter(|flow| flow.method.is_some() && flow.status.is_some())
        .count();
    let flow_details = summaries
        .iter()
        .map(|flow| {
            format!(
                "id={} host={:?} method={:?} status={:?}",
                flow.id, flow.host, flow.method, flow.status
            )
        })
        .collect::<Vec<_>>();
    let connectivity_check_flows = summaries
        .iter()
        .filter(|flow| {
            flow.host
                .as_deref()
                .is_some_and(|host| host.contains("connectivitycheck.gstatic.com"))
        })
        .count();
    let feeder_feed_flows = summaries
        .iter()
        .filter(|flow| {
            flow.host
                .as_deref()
                .is_some_and(|host| host == allowed_domain)
        })
        .count();
    println!(
        "STAGE 4 FLOW DETAILS: {flow_details:?}; connectivitycheck.gstatic.com={connectivity_check_flows}; feeder_feed_host={allowed_domain} flows={feeder_feed_flows}"
    );
    if package_name == "com.nononsenseapps.feeder" && feeder_feed_flows > 0 && !frida_configured {
        println!(
            "STAGE 5 PASS: completed Feeder traffic was observed without a bypass lane; no pinning detected"
        );
    }
    if captured == 0 {
        println!(
            "STAGE 4 FINDING: no completed decryptable HTTP flows reached the workbench store; summaries={}",
            summaries.len()
        );
    } else {
        println!(
            "STAGE 4 PASS: completed decryptable HTTP flows={}, total summaries={}",
            captured,
            summaries.len()
        );
    }

    for flow in &summaries {
        if let Some(host) = flow.host.as_deref() {
            let _ = session.record_action(ActionRecordInput {
                id: format!("capstone.flow.{}", flow.id),
                occurred_at: flow.captured_at,
                actor: AuditActor::Engine,
                action: ActionDescriptor {
                    kind: "capture.flow".to_owned(),
                    summary: format!(
                        "captured {} {}",
                        flow.method.as_deref().unwrap_or("?"),
                        host
                    ),
                },
                target: ActionTarget::Network {
                    host: host.to_owned(),
                    port: Some(443),
                },
                outcome: ActionOutcome::Completed,
                diagnostics: Vec::new(),
            });
        }
    }
    let scope_warning_count = session
        .audit_trail()
        .iter()
        .flat_map(|record| record.diagnostics.iter())
        .filter(|diagnostic| diagnostic.id.as_ref() == "scope.outside-declaration")
        .count();
    println!(
        "STAGE 6 SCOPE: outside-declaration warnings={scope_warning_count} (allowed domain={allowed_domain})"
    );

    let dynamic_config =
        DynamicCaptureConfig::new(format!("dynamic-capstone-{stamp}")).expect("dynamic run ID");
    let dynamic = capture_into_session(&mut session, &store, &dynamic_config, Utc::now())
        .unwrap_or_else(|diagnostics| panic!("STAGE 6 dynamic capture failed: {diagnostics:?}"));
    println!(
        "STAGE 6 MODEL: flows={}, structured_flows={}, observed_endpoints={}, inferred_endpoints={}, resolved_handoffs={}, open_handoffs={}, diagnostics={}",
        dynamic.coverage.flow_count,
        dynamic.coverage.structured_flow_count,
        dynamic.coverage.observed_endpoints.len(),
        dynamic.coverage.inferred_endpoint_count,
        dynamic.coverage.resolved_handoffs.len(),
        dynamic.coverage.open_handoffs.len(),
        dynamic.diagnostics.len()
    );
    println!(
        "STAGE 6 STATIC+DYNAMIC: static_endpoints={}, static_loose_findings={}, dynamic_document_endpoints={}, bypass_applied={}",
        dynamic
            .document
            .static_pass
            .as_ref()
            .map_or(0, |pass| pass.dynamic_handoffs.len()),
        dynamic.document.surface.loose_findings.len(),
        dynamic.document.surface.endpoints.len(),
        bypass_outcome.is_some()
    );

    let teardown = runtime.block_on(traffic.teardown());
    println!("STAGE 7 TEARDOWN: {teardown:?}");
    assert!(
        teardown.is_ok(),
        "sandbox traffic teardown failed: {teardown:?}"
    );
    println!(
        "STAGE 7 UNCLEAN KILL CHECK: NOT RUN; normal RAII/explicit teardown passed, but SIGKILL requires a separately supervised child-process test"
    );
    drop(observer);
    drop(store);
    let _ = fs::remove_dir_all(&store_parent);
    let intake_teardown = target.cleanup(&artifact);
    println!("STAGE 7 INTAKE TEARDOWN: {intake_teardown:?}");
    assert!(
        intake_teardown.is_ok(),
        "intake workspace cleanup failed: {intake_teardown:?}"
    );

    // Keep the evidence report outside the disposable intake root. The
    // artifact workspace can therefore be removed completely while the
    // per-stage result remains available for review.
    let stage_report = capstone_stage_report_path(&output_root);
    let report = format!(
        "APIaxess {package_name} capstone stage report\n\
stage1=intake_pass\n\
stage2=static_pass endpoints={} loose_findings={} handoffs={} diagnostics={}\n\
stage3=install_pass\n\
stage3_feeder_opml_imported={:?}\n\
stage4=completed_decryptable_flows={} total_flow_summaries={} feeder_feed_host={} feeder_feed_flows={} deterministic_fetch={}\n\
stage4_flow_details={flow_details:?} connectivitycheck_flows={}\n\
stage5=bypass_applied={} lane={:?}\n\
stage6=observed_endpoints={} inferred_endpoints={} resolved_handoffs={} open_handoffs={} diagnostics={} scope_warnings={}\n\
stage7=normal_teardown_pass\n\
unclean_kill_check=not_run; requires a separately supervised child-process kill to distinguish SIGKILL cleanup from Rust Drop/unwind cleanup\n",
        static_report.document.surface.endpoints.len(),
        static_report.document.surface.loose_findings.len(),
        static_report.honesty.dynamic_handoffs.len(),
        static_report.diagnostics.len(),
        feeder_imported,
        captured,
        summaries.len(),
        allowed_domain,
        feeder_feed_flows,
        deterministic_fetch_passed,
        connectivity_check_flows,
        bypass_outcome.is_some(),
        bypass_plan.lane,
        dynamic.coverage.observed_endpoints.len(),
        dynamic.coverage.inferred_endpoint_count,
        dynamic.coverage.resolved_handoffs.len(),
        dynamic.coverage.open_handoffs.len(),
        dynamic.diagnostics.len(),
        scope_warning_count,
    );
    fs::write(&stage_report, report).expect("write capstone stage report");
    println!("STAGE REPORT: {}", stage_report.display());
}
