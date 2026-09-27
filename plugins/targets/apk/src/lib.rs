//! APK/AAB/APKS intake and decomposition.
//!
//! This target owns Android-specific routing. All process execution is behind
//! apiaxess-external-tools; archive I/O here is limited to preserving and
//! safely materializing bundle members.

use std::{
    fs::{self, File},
    io,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use apiaxess_artifact_intake::{
    ArtifactComponent, ArtifactFormat, ComponentProvenance, DexAccess, InstallableApk,
    NORMALIZED_ARTIFACT_SCHEMA_VERSION, NormalizedUnpackedArtifact, ProtectionMetadata, RawArchive,
    StaticArchiveIndex, StructuralOutput, TargetProbe, TargetType, index_static_archive,
};
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticSeverity, DiagnosticValue,
    catalogue::{
        ARTIFACT_BUNDLE_RESOLUTION_FAILED, ARTIFACT_DECOMPILATION_FAILED,
        ARTIFACT_DECOMPILATION_PARTIAL, ARTIFACT_DEX_ACCESS_UNAVAILABLE,
        ARTIFACT_MALFORMED_ARCHIVE, ARTIFACT_NOT_FOUND, ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE,
        ARTIFACT_UNPACK_FAILED, ARTIFACT_UNSUPPORTED_FORMAT, EXTERNAL_TOOL_INVOCATION_FAILED,
        EXTERNAL_TOOL_MISSING, EXTERNAL_TOOL_VERSION_INCOMPATIBLE, INSTALL_COMPONENT_MISSING,
    },
};
use apiaxess_external_tools::{
    ExternalToolError, ExternalToolRunner, ProcessToolRunner, ToolInvocation,
    ToolInvocationRequest, ToolProbe, ToolProbeRequest, ToolRequirement, ToolVersion,
};
use apiaxess_protection_detector::ProtectionDetector;
use zip::ZipArchive;

mod bundled;

pub use bundled::{BundledComponent, resolve_default_toolchain, resolve_from_resource_base};

/// Stable target ID for Android package artifacts.
pub const APK_TARGET_TYPE_ID: &str = "android.apk";

/// A fully-resolved way to launch one external tool.
///
/// The executable is invoked with `launch_prefix` placed before the tool's own
/// arguments. For the bundled Java tools the executable is the bundled `java`
/// and the prefix carries `-jar <apktool.jar>` or the jadx classpath, so intake
/// runs them through the owned runtime by absolute path rather than any host
/// `java`, apktool, or jadx.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolLaunch {
    /// Absolute path (or, for an operator override, name) of the executable.
    pub executable: String,
    /// Argument tokens placed before the tool's own arguments.
    pub launch_prefix: Vec<String>,
}

impl ToolLaunch {
    /// A launch that runs an executable directly with no prefix arguments.
    #[must_use]
    pub fn command(executable: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            launch_prefix: Vec::new(),
        }
    }
}

/// Tool configuration for the Android intake pipeline.
#[derive(Clone, Debug)]
pub struct ApkToolchainConfig {
    /// apktool launch recipe (bundled: the owned Java runtime + apktool jar).
    pub apktool: ToolLaunch,
    /// jadx launch recipe (bundled: the owned Java runtime + jadx classpath).
    pub jadx: ToolLaunch,
    /// bundletool launch recipe (AAB branch only; not bundled in this phase).
    pub bundletool: ToolLaunch,
    /// Minimum apktool version.
    pub apktool_minimum: ToolVersion,
    /// Minimum jadx version.
    pub jadx_minimum: ToolVersion,
    /// Minimum bundletool version.
    pub bundletool_minimum: ToolVersion,
    /// Bundled components whose absence is an install-integrity failure rather
    /// than a missing host prerequisite. Empty for tools an operator overrode.
    pub bundled_components: Vec<BundledComponent>,
}

impl ApkToolchainConfig {
    /// A configuration carrying only the version minimums, with placeholder
    /// launches the resolver fills in. Not usable on its own.
    #[must_use]
    fn minimums() -> Self {
        Self {
            apktool: ToolLaunch::command("apktool"),
            jadx: ToolLaunch::command("jadx"),
            bundletool: ToolLaunch::command("bundletool"),
            apktool_minimum: ToolVersion {
                major: 2,
                minor: 7,
                patch: 0,
            },
            jadx_minimum: ToolVersion {
                major: 1,
                minor: 4,
                patch: 0,
            },
            bundletool_minimum: ToolVersion {
                major: 1,
                minor: 15,
                patch: 0,
            },
            bundled_components: Vec::new(),
        }
    }
}

impl Default for ApkToolchainConfig {
    /// Resolves the bundled, host-independent toolchain from the install
    /// layout, honoring the advanced `APIAXESS_JAVA`/`APIAXESS_APKTOOL`/
    /// `APIAXESS_JADX` overrides when present.
    fn default() -> Self {
        resolve_default_toolchain()
    }
}

/// Intake limits and output location.
#[derive(Clone, Debug)]
pub struct ApkIntakeConfig {
    /// Parent directory for normalized workspaces.
    pub output_root: PathBuf,
    /// Maximum runtime per external invocation.
    pub tool_timeout: Duration,
    /// Toolchain executable/version configuration.
    pub tools: ApkToolchainConfig,
}

/// Floor per-invocation deadline for a bundled external tool (apktool/jadx).
const DEFAULT_TOOL_TIMEOUT_SECS: u64 = 300;

/// Base component of the size-scaled deadline, before the per-megabyte term.
const TOOL_TIMEOUT_BASE_SECS: u64 = 120;

/// Per-megabyte-of-input component of the size-scaled deadline. apktool's
/// baksmali step (the measured intake hotspot) scales with code size: a 60 MB APK
/// needs ~5-6 min, a 250 MB APK tens of minutes. A fixed 300 s deadline therefore
/// makes a large real APK *fail* mid-unpack (surfacing as a hang that then dies),
/// so the deadline scales with the input instead. Deliberately generous: a
/// deadline exists to catch a genuinely wedged tool, not to bound normal work on a
/// large app.
const TOOL_TIMEOUT_PER_MB_SECS: u64 = 12;

/// Resolves the per-invocation external-tool deadline for an input of
/// `input_bytes`, honoring the advanced `APIAXESS_TOOL_TIMEOUT_SECS` override.
///
/// When the override is set it wins exactly. Otherwise the deadline scales with
/// input size (`BASE + per-MB * MB`, floored at [`DEFAULT_TOOL_TIMEOUT_SECS`]) so
/// a large APK is not failed by a fixed deadline mid-unpack. Also respects a
/// configured `tool_timeout` as a floor (a caller may only raise it).
fn resolve_tool_timeout(configured_floor: Duration, input_bytes: u64) -> Duration {
    if let Some(seconds) = std::env::var("APIAXESS_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
    {
        return Duration::from_secs(seconds);
    }
    Duration::from_secs(size_scaled_timeout_secs(input_bytes)).max(configured_floor)
}

/// Pure size→deadline computation (`BASE + per-MB * MB`, floored at the default),
/// factored out so the scaling contract is testable without process env.
fn size_scaled_timeout_secs(input_bytes: u64) -> u64 {
    let megabytes = input_bytes / (1024 * 1024);
    TOOL_TIMEOUT_BASE_SECS
        .saturating_add(megabytes.saturating_mul(TOOL_TIMEOUT_PER_MB_SECS))
        .max(DEFAULT_TOOL_TIMEOUT_SECS)
}

/// The deadline stored in the default config is the floor; the effective
/// per-invocation deadline is resolved from the input size at intake time.
fn default_tool_timeout() -> Duration {
    if let Some(seconds) = std::env::var("APIAXESS_TOOL_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
    {
        return Duration::from_secs(seconds);
    }
    Duration::from_secs(DEFAULT_TOOL_TIMEOUT_SECS)
}

impl Default for ApkIntakeConfig {
    fn default() -> Self {
        Self {
            output_root: std::env::temp_dir().join("apiaxess-artifacts"),
            tool_timeout: default_tool_timeout(),
            tools: ApkToolchainConfig::default(),
        }
    }
}

/// How far an intake has got, for a caller that shows progress.
#[derive(Clone, Debug)]
pub struct IntakeProgress {
    /// Share of intake done, 0.0–1.0.
    pub fraction: f32,
    /// What intake is doing.
    pub message: String,
}

/// An intake failure represented by the canonical diagnostic framework.
#[derive(Clone, Debug)]
pub struct IntakeFailure {
    /// Actionable structured diagnostic.
    pub diagnostic: Diagnostic,
}

impl std::fmt::Display for IntakeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for IntakeFailure {}

/// Android target implementation.
pub struct ApkTarget {
    runner: Arc<dyn ExternalToolRunner>,
    config: ApkIntakeConfig,
}

impl std::fmt::Debug for ApkTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApkTarget")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Default for ApkTarget {
    fn default() -> Self {
        Self::new(Arc::new(ProcessToolRunner), ApkIntakeConfig::default())
    }
}

impl ApkTarget {
    /// Creates an APK target with an injectable external-tool runner.
    #[must_use]
    pub fn new(runner: Arc<dyn ExternalToolRunner>, config: ApkIntakeConfig) -> Self {
        Self { runner, config }
    }

    /// Resolves, unpacks, and normalizes an Android artifact.
    ///
    /// # Errors
    ///
    /// Returns a structured diagnostic for unsupported or malformed input,
    /// tool preflight gaps, tool failures, or incomplete output.
    ///
    /// # Panics
    ///
    /// Panics only if a worker thread unexpectedly panics while an external
    /// invocation is being joined; the production runner does not do so.
    pub fn intake(&self, input: &Path) -> Result<NormalizedUnpackedArtifact, IntakeFailure> {
        self.intake_with_progress(input, &|_| {})
    }

    /// [`Self::intake`], reporting how far it has got: fixed points as each
    /// phase completes, and — through the long apktool/jadx step — the share
    /// of the artifact's classes both tools have written out, measured against
    /// the class count in the DEX headers.
    ///
    /// # Errors
    ///
    /// See [`Self::intake`].
    ///
    /// # Panics
    ///
    /// See [`Self::intake`].
    // Intake is one ordered sequence of phases; splitting it would scatter the
    // workspace guard and provenance bookkeeping across helpers.
    #[allow(clippy::too_many_lines)]
    pub fn intake_with_progress(
        &self,
        input: &Path,
        progress: &(dyn Fn(IntakeProgress) + Sync),
    ) -> Result<NormalizedUnpackedArtifact, IntakeFailure> {
        let report = |fraction: f32, message: &str| {
            progress(IntakeProgress {
                fraction,
                message: message.to_owned(),
            });
        };
        let intake_started = Instant::now();
        let format = detect_format(input)?;
        verify_bundled_integrity(&self.config.tools)?;
        // Resolve the effective external-tool deadline from the input size: a
        // fixed deadline fails a large APK mid-unpack (apktool's baksmali scales
        // with code size). The configured `tool_timeout` acts as a floor.
        let input_bytes = fs::metadata(input).map(|meta| meta.len()).unwrap_or(0);
        let tool_timeout = resolve_tool_timeout(self.config.tool_timeout, input_bytes);
        profile_intake("format_detected", intake_started, None);
        report(0.03, "Artifact format recognized");
        let workspace = create_workspace(&self.config.output_root)?;
        let mut workspace_guard = IntakeWorkspaceGuard::new(workspace.clone());
        let raw_root = workspace.join("raw");
        let resolved_root = workspace.join("resolved");
        fs::create_dir_all(&raw_root)
            .map_err(|error| io_failure("create intake workspace", error))?;
        fs::create_dir_all(&resolved_root)
            .map_err(|error| io_failure("create resolved workspace", error))?;

        let raw_input = raw_root.join(input.file_name().unwrap_or_default());
        fs::copy(input, &raw_input).map_err(|error| io_failure("preserve raw artifact", error))?;
        let mut raw_archives = vec![archive_record(format, &raw_input)?];
        let installable_apks = match format {
            ArtifactFormat::Apk => {
                validate_apk(input)?;
                vec![copy_apk(input, &resolved_root, "base")?]
            }
            ArtifactFormat::Apks
            | ArtifactFormat::Apkm
            | ArtifactFormat::Xapk
            | ArtifactFormat::ZipSplits => extract_apks_from_container(input, &resolved_root)?,
            ArtifactFormat::Aab => {
                let bundletool = self.probe_required(&bundletool_request(&self.config.tools))?;
                let generated = resolved_root.join("bundletool.apks");
                let invocation = self
                    .runner
                    .invoke(&ToolInvocationRequest {
                        probe: bundletool,
                        arguments: with_prefix(
                            &self.config.tools.bundletool.launch_prefix,
                            [
                                "build-apks".to_owned(),
                                "--bundle".to_owned(),
                                input.display().to_string(),
                                "--output".to_owned(),
                                generated.display().to_string(),
                                "--mode".to_owned(),
                                "universal".to_owned(),
                                "--overwrite".to_owned(),
                            ],
                        ),
                        working_directory: Some(workspace.clone()),
                        environment: Vec::new(),
                        timeout: tool_timeout,
                    })
                    .map_err(|error| Self::tool_failure("bundle resolution", error, true))?;
                ensure_success("bundletool", &invocation).map_err(|diagnostic| IntakeFailure {
                    diagnostic: with_definition(diagnostic, ARTIFACT_BUNDLE_RESOLUTION_FAILED),
                })?;
                raw_archives.push(archive_record(ArtifactFormat::Apks, &generated)?);
                extract_apks_from_container(&generated, &resolved_root)?
            }
        };
        profile_intake(
            "resolved_installable_apks",
            intake_started,
            Some(format!("count={}", installable_apks.len())),
        );
        report(0.08, "Installable APKs resolved");
        if installable_apks.is_empty() {
            return Err(failure(
                ARTIFACT_BUNDLE_RESOLUTION_FAILED,
                "no installable APK members were resolved",
            ));
        }

        let static_archives = installable_apks
            .iter()
            .map(|apk| {
                index_static_archive(Path::new(&apk.path)).map_err(|error| {
                    failure(ARTIFACT_MALFORMED_ARCHIVE, format!("{}: {error}", apk.path))
                })
            })
            .collect::<Result<Vec<StaticArchiveIndex>, IntakeFailure>>()?;
        profile_intake(
            "static_archive_indexed",
            intake_started,
            Some(format!(
                "archives={} entries={}",
                static_archives.len(),
                static_archives
                    .iter()
                    .map(|archive| archive.entries.len())
                    .sum::<usize>()
            )),
        );
        report(0.15, "Archive indexed");

        let mut diagnostics = Vec::new();
        let (apktool, jadx) = self.probe_unpackers()?;
        profile_intake("toolchain_probed", intake_started, None);
        report(0.2, "Decoding and decompiling with apktool and jadx");
        let mut structural_outputs = Vec::with_capacity(installable_apks.len());
        let mut decompiled_source_roots = Vec::with_capacity(installable_apks.len());
        let mut provenance = vec![
            ComponentProvenance {
                component: ArtifactComponent::RawArchive,
                source_tool: "apiaxess.artifact-preservation".to_owned(),
                source_version: None,
                recorded_at_unix_seconds: now_seconds(),
                output_root: raw_root.display().to_string(),
            },
            ComponentProvenance {
                component: ArtifactComponent::StaticArchiveIndex,
                source_tool: "apiaxess.static-archive-index".to_owned(),
                source_version: None,
                recorded_at_unix_seconds: now_seconds(),
                output_root: resolved_root.display().to_string(),
            },
        ];
        let mut dex_files = Vec::new();

        let apk_count = installable_apks.len().max(1);
        for (apk_index, apk) in installable_apks.iter().enumerate() {
            let class_total = dex_class_count(Path::new(&apk.path));
            let apk_workspace = workspace.join("unpacked").join(&apk.id);
            let apktool_root = apk_workspace.join("apktool");
            let jadx_root = apk_workspace.join("jadx");
            fs::create_dir_all(&apktool_root)
                .map_err(|error| io_failure("create apktool output", error))?;
            fs::create_dir_all(&jadx_root)
                .map_err(|error| io_failure("create jadx output", error))?;

            // apktool's baksmali on a large APK runs for minutes with no
            // intermediate output; without a sign of life it reads as a hang. A
            // heartbeat thread reports elapsed time while the (blocking) tool
            // invocations run, and stops as soon as they return. Declared outside
            // the scope so the spawned heartbeat may borrow them.
            let running = AtomicBool::new(true);
            let heartbeat_started = Instant::now();
            let (apktool_result, jadx_result) = std::thread::scope(|scope| {
                let apk_id = apk.id.as_str();
                // Class and file counts stay far below f32's exact range; the
                // fraction only drives a progress bar.
                #[allow(clippy::cast_precision_loss)]
                let heartbeat = scope.spawn(|| {
                    report_unpack_progress(&running, heartbeat_started, apk_id, &|written| {
                        // Both tools write one file per class; together they
                        // have written 2 × classes files when done.
                        let done = if class_total == 0 {
                            0.0
                        } else {
                            (written as f32 / (2.0 * class_total as f32)).min(1.0)
                        };
                        report(
                            0.2 + 0.6 * ((apk_index as f32 + done) / apk_count as f32),
                            &format!(
                                "Decoding and decompiling with apktool and jadx: {}% of {} classes",
                                (done * 100.0).round(),
                                class_total
                            ),
                        );
                    }, &apktool_root, &jadx_root);
                });
                let apktool =
                    scope.spawn(|| self.run_apktool(&apktool, apk, &apktool_root, tool_timeout));
                let jadx = scope.spawn(|| self.run_jadx(&jadx, apk, &jadx_root, tool_timeout));
                let results = (
                    apktool.join().expect("apktool invocation thread panicked"),
                    jadx.join().expect("jadx invocation thread panicked"),
                );
                running.store(false, Ordering::Relaxed);
                let _ = heartbeat.join();
                results
            });
            let apktool_invocation = apktool_result
                .map_err(|error| Self::tool_failure("apktool unpack", error, true))?;
            let jadx_invocation = jadx_result
                .map_err(|error| Self::tool_failure("jadx decompilation", error, true))?;
            let (apktool_files, apktool_bytes) = materialized_file_stats(&apktool_root);
            let (jadx_files, jadx_bytes) = materialized_file_stats(&jadx_root);
            profile_intake(
                "external_tools_finished",
                intake_started,
                Some(format!(
                    "apk_id={} apktool_ms={} jadx_ms={} apktool_files={} apktool_bytes={} jadx_files={} jadx_bytes={}",
                    apk.id,
                    apktool_invocation.duration.as_millis(),
                    jadx_invocation.duration.as_millis(),
                    apktool_files,
                    apktool_bytes,
                    jadx_files,
                    jadx_bytes,
                )),
            );
            ensure_success("apktool", &apktool_invocation).map_err(|diagnostic| IntakeFailure {
                diagnostic: with_definition(diagnostic, ARTIFACT_UNPACK_FAILED),
            })?;
            if let Err(diagnostic) = ensure_success("jadx", &jadx_invocation) {
                if has_decompilation_output(&jadx_root) {
                    // jadx is best-effort: a non-zero exit that still produced a
                    // source tree means it decompiled most classes and failed a
                    // fraction (routine on large apps). Surface this as a distinct,
                    // legible *partial* warning — not the generic failure, and not a
                    // silent swallow — so it is clear jadx contributed partially
                    // while apktool smali remains authoritative and complete.
                    let mut diagnostic =
                        with_definition(diagnostic, ARTIFACT_DECOMPILATION_PARTIAL);
                    diagnostic.severity = DiagnosticSeverity::Warning;
                    diagnostics.push(diagnostic);
                } else {
                    // No output at all: jadx contributed nothing. Still not fatal to
                    // the analysis (apktool is authoritative), so downgrade to a
                    // warning and continue rather than aborting a run whose
                    // structural model is complete.
                    let mut diagnostic = with_definition(diagnostic, ARTIFACT_DECOMPILATION_FAILED);
                    diagnostic.severity = DiagnosticSeverity::Warning;
                    diagnostics.push(diagnostic);
                }
            }

            let structure = structural_output(apk, &apktool_root)?;
            let extracted_dex =
                extract_dex_files(Path::new(&apk.path), &workspace.join("dex").join(&apk.id))?;
            dex_files.extend(extracted_dex);
            provenance.push(tool_provenance(
                ArtifactComponent::Manifest,
                &apktool,
                &apktool_root,
            ));
            provenance.push(tool_provenance(
                ArtifactComponent::Smali,
                &apktool,
                &apktool_root,
            ));
            provenance.push(tool_provenance(
                ArtifactComponent::Resources,
                &apktool,
                &apktool_root,
            ));
            provenance.push(tool_provenance(
                ArtifactComponent::DecompiledSource,
                &jadx,
                &jadx_root,
            ));
            structural_outputs.push(structure);
            decompiled_source_roots.push(jadx_root.display().to_string());
            profile_intake(
                "normalized_apk_output",
                intake_started,
                Some(format!(
                    "apk_id={} dex_files={} smali_roots={}",
                    apk.id,
                    dex_files.len(),
                    structural_outputs
                        .last()
                        .map_or(0, |output| output.smali_roots.len())
                )),
            );
            report(0.88, "Normalizing decoded output");
        }
        if dex_files.is_empty() {
            return Err(failure(
                ARTIFACT_DEX_ACCESS_UNAVAILABLE,
                "resolved APK set contains no DEX file",
            ));
        }
        provenance.push(ComponentProvenance {
            component: ArtifactComponent::Dex,
            source_tool: "android.dex.programmatic-handoff".to_owned(),
            source_version: None,
            recorded_at_unix_seconds: now_seconds(),
            output_root: workspace.join("dex").display().to_string(),
        });
        let mut artifact = NormalizedUnpackedArtifact {
            schema_version: NORMALIZED_ARTIFACT_SCHEMA_VERSION,
            target_type_id: APK_TARGET_TYPE_ID.to_owned(),
            workspace_root: workspace.display().to_string(),
            input_format: format,
            raw_archives,
            static_archives,
            installable_apks,
            structural_outputs,
            dex_access: DexAccess {
                dex_files,
                parser_handoff: "android.dex.androguard-or-dexlib2".to_owned(),
                capabilities: vec![
                    "string-pool".to_owned(),
                    "cross-references".to_owned(),
                    "annotations".to_owned(),
                    "call-graph".to_owned(),
                ],
            },
            decompiled_source_roots,
            protection: ProtectionMetadata {
                detector: "pending".to_owned(),
                detector_version: None,
                distribution_posture: "pending".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance,
            diagnostics: {
                diagnostics.shrink_to_fit();
                diagnostics
            },
        };
        artifact
            .validate()
            .map_err(|why| failure(ARTIFACT_UNPACK_FAILED, why))?;
        let protection_result = ProtectionDetector::default().detect(&artifact);
        artifact.protection = protection_result.metadata;
        artifact.diagnostics.extend(protection_result.diagnostics);
        profile_intake(
            "protection_detected",
            intake_started,
            Some(format!(
                "tier={:?}",
                artifact
                    .protection
                    .profile
                    .as_ref()
                    .map(|profile| profile.tier)
            )),
        );
        report(0.95, "Protection detection done");
        artifact.provenance.push(ComponentProvenance {
            component: ArtifactComponent::ProtectionMetadata,
            source_tool: artifact.protection.detector.clone(),
            source_version: artifact.protection.detector_version.clone(),
            recorded_at_unix_seconds: now_seconds(),
            output_root: workspace.display().to_string(),
        });
        artifact
            .validate()
            .map_err(|why| failure(ARTIFACT_UNPACK_FAILED, why))?;
        profile_intake("intake_complete", intake_started, None);
        report(1.0, "Artifact normalized");
        workspace_guard.disarm();
        Ok(artifact)
    }

    /// Removes the normalized intake workspace after all consumers have
    /// finished with the artifact.
    ///
    /// The deletion is restricted to a direct child of this target's
    /// configured output root. This makes static-intake teardown explicit and
    /// prevents a malformed handoff from turning cleanup into a broad delete.
    ///
    /// # Errors
    ///
    /// Returns an intake failure when the output root or workspace cannot be
    /// resolved, or when cleanup would leave the configured output root.
    pub fn cleanup(&self, artifact: &NormalizedUnpackedArtifact) -> Result<(), IntakeFailure> {
        cleanup_intake_workspace(&self.config.output_root, &artifact.workspace_root)
    }

    fn probe_unpackers(&self) -> Result<(ToolProbe, ToolProbe), IntakeFailure> {
        std::thread::scope(|scope| -> Result<(ToolProbe, ToolProbe), IntakeFailure> {
            let apktool = scope.spawn(|| self.probe_required(&apktool_request(&self.config.tools)));
            let jadx = scope.spawn(|| self.probe_required(&jadx_request(&self.config.tools)));
            let apktool = apktool.join().expect("apktool probe thread panicked")?;
            let jadx = jadx.join().expect("jadx probe thread panicked")?;
            Ok((apktool, jadx))
        })
    }

    fn probe_required(&self, request: &ToolProbeRequest) -> Result<ToolProbe, IntakeFailure> {
        self.runner
            .probe(request)
            .map_err(|error| Self::tool_failure("tool preflight", error, true))
    }

    fn run_apktool(
        &self,
        probe: &ToolProbe,
        apk: &InstallableApk,
        output: &Path,
        timeout: Duration,
    ) -> Result<ToolInvocation, ExternalToolError> {
        let arguments = with_prefix(
            &self.config.tools.apktool.launch_prefix,
            [
                "d".to_owned(),
                "--force".to_owned(),
                "--output".to_owned(),
                output.display().to_string(),
                apk.path.clone(),
            ],
        );
        self.runner.invoke(&ToolInvocationRequest {
            probe: probe.clone(),
            arguments,
            working_directory: output.parent().map(Path::to_path_buf),
            environment: Vec::new(),
            timeout,
        })
    }

    fn run_jadx(
        &self,
        probe: &ToolProbe,
        apk: &InstallableApk,
        output: &Path,
        timeout: Duration,
    ) -> Result<ToolInvocation, ExternalToolError> {
        // jadx is a best-effort, supplementary decompiler: apktool smali is the
        // authoritative structural source, and jadx's Java output is complementary
        // routing evidence. On large/complex apps jadx routinely fails to
        // decompile a fraction of classes and exits non-zero. `--show-bad-code`
        // makes it still emit those classes (as best-effort code) instead of
        // dropping them, maximizing the contribution we do get; the intake handler
        // treats a non-zero exit with output as a legible partial, not a hard fail.
        let arguments = with_prefix(
            &self.config.tools.jadx.launch_prefix,
            [
                "--show-bad-code".to_owned(),
                "-d".to_owned(),
                output.display().to_string(),
                apk.path.clone(),
            ],
        );
        self.runner.invoke(&ToolInvocationRequest {
            probe: probe.clone(),
            arguments,
            working_directory: output.parent().map(Path::to_path_buf),
            environment: Vec::new(),
            timeout,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn tool_failure(operation: &str, error: ExternalToolError, required: bool) -> IntakeFailure {
        let mut context = DiagnosticContext::new();
        context.insert(
            "operation".to_owned(),
            DiagnosticValue::String(operation.to_owned()),
        );
        let (definition, why) = match error {
            ExternalToolError::Start {
                tool_id,
                executable,
                source,
            } => {
                context.insert(
                    "tool_id".to_owned(),
                    DiagnosticValue::String(tool_id.clone()),
                );
                context.insert("executable".to_owned(), DiagnosticValue::String(executable));
                (
                    if required {
                        EXTERNAL_TOOL_MISSING
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    source.to_string(),
                )
            }
            ExternalToolError::VersionMismatch {
                tool_id,
                found,
                minimum,
            } => {
                context.insert("tool_id".to_owned(), DiagnosticValue::String(tool_id));
                context.insert(
                    "detected_version".to_owned(),
                    DiagnosticValue::String(found.to_string()),
                );
                context.insert(
                    "required_version".to_owned(),
                    DiagnosticValue::String(minimum.to_string()),
                );
                (
                    if required {
                        EXTERNAL_TOOL_VERSION_INCOMPATIBLE
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    format!("detected {found}, required {minimum}"),
                )
            }
            ExternalToolError::Probe {
                tool_id,
                detail,
                output,
            } => {
                context.insert("tool_id".to_owned(), DiagnosticValue::String(tool_id));
                context.insert("bounded_output".to_owned(), DiagnosticValue::String(output));
                (
                    if required {
                        EXTERNAL_TOOL_INVOCATION_FAILED
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    detail,
                )
            }
            ExternalToolError::Wait { tool_id, source }
            | ExternalToolError::Kill { tool_id, source } => {
                context.insert("tool_id".to_owned(), DiagnosticValue::String(tool_id));
                (
                    if required {
                        EXTERNAL_TOOL_INVOCATION_FAILED
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    source.to_string(),
                )
            }
            ExternalToolError::Timeout { tool_id, timeout } => {
                context.insert("tool_id".to_owned(), DiagnosticValue::String(tool_id));
                context.insert(
                    "timeout_ms".to_owned(),
                    DiagnosticValue::Integer(
                        i64::try_from(timeout.as_millis()).unwrap_or(i64::MAX),
                    ),
                );
                (
                    if required {
                        EXTERNAL_TOOL_INVOCATION_FAILED
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    format!("exceeded {timeout:?} deadline"),
                )
            }
            ExternalToolError::Unsupported { tool_id, detail } => {
                context.insert("tool_id".to_owned(), DiagnosticValue::String(tool_id));
                (
                    if required {
                        EXTERNAL_TOOL_INVOCATION_FAILED
                    } else {
                        ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE
                    },
                    detail,
                )
            }
        };
        let mut diagnostic = definition.instantiate(context);
        diagnostic.why = format!("{operation}: {why}").into_boxed_str();
        IntakeFailure { diagnostic }
    }
}

impl TargetType for ApkTarget {
    fn target_type_id(&self) -> &'static str {
        APK_TARGET_TYPE_ID
    }

    fn probe(&self, artifact: &Path) -> TargetProbe {
        match detect_format(artifact) {
            Ok(format) => TargetProbe {
                target_type_id: APK_TARGET_TYPE_ID.to_owned(),
                match_basis_points: 10_000,
                observed_media_types: vec![
                    format!("{format:?}").to_lowercase(),
                    "application/zip".to_owned(),
                ],
                diagnostics: Vec::new(),
            },
            Err(error) => TargetProbe {
                target_type_id: APK_TARGET_TYPE_ID.to_owned(),
                match_basis_points: 0,
                observed_media_types: Vec::new(),
                diagnostics: vec![error.diagnostic],
            },
        }
    }
}

/// Prepends a tool's launch prefix (for example `-jar <apktool.jar>`) to its
/// own arguments, producing the full argument vector for one invocation.
fn with_prefix<const N: usize>(prefix: &[String], arguments: [String; N]) -> Vec<String> {
    let mut full = Vec::with_capacity(prefix.len() + N);
    full.extend_from_slice(prefix);
    full.extend(arguments);
    full
}

/// Confirms every bundled component this run relies on is present before any
/// tool is probed. With bundling, a missing apktool/jadx/Java is an
/// install-integrity failure with a concrete what/why/fix, never a silent
/// intake death. Overridden tools carry no bundled component and are validated
/// by the ordinary probe instead.
fn verify_bundled_integrity(config: &ApkToolchainConfig) -> Result<(), IntakeFailure> {
    for component in &config.bundled_components {
        if !component.path.is_file() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "component".to_owned(),
                DiagnosticValue::String(component.label.to_owned()),
            );
            context.insert(
                "expected_path".to_owned(),
                DiagnosticValue::String(component.path.display().to_string()),
            );
            let mut diagnostic = INSTALL_COMPONENT_MISSING.instantiate(context);
            diagnostic.why = format!(
                "bundled {} was not found at {}",
                component.label,
                component.path.display()
            )
            .into_boxed_str();
            return Err(IntakeFailure { diagnostic });
        }
    }
    Ok(())
}

fn apktool_request(config: &ApkToolchainConfig) -> ToolProbeRequest {
    probe_request(
        "apktool",
        &config.apktool,
        "--version",
        config.apktool_minimum,
    )
}

fn jadx_request(config: &ApkToolchainConfig) -> ToolProbeRequest {
    probe_request("jadx", &config.jadx, "--version", config.jadx_minimum)
}

fn bundletool_request(config: &ApkToolchainConfig) -> ToolProbeRequest {
    probe_request(
        "bundletool",
        &config.bundletool,
        "version",
        config.bundletool_minimum,
    )
}

fn probe_request(
    tool_id: &str,
    launch: &ToolLaunch,
    version_argument: &str,
    minimum: ToolVersion,
) -> ToolProbeRequest {
    // The launch prefix (for example `-jar <apktool.jar>` or the jadx
    // classpath) must precede the version flag so the probe measures exactly
    // the same executable the invocation will run.
    let mut version_arguments = launch.launch_prefix.clone();
    version_arguments.push(version_argument.to_owned());
    ToolProbeRequest {
        tool_id: tool_id.to_owned(),
        executable: launch.executable.clone(),
        version_arguments,
        requirement: ToolRequirement { minimum },
    }
}

/// Checks, before a run is confirmed, that `input` is an artifact the pipeline
/// can take: an existing file of a supported Android format. The same check
/// intake runs first, so the answer is the one the run would give.
///
/// # Errors
///
/// Returns the intake diagnostic (`artifact.not-found`, unsupported format,
/// malformed archive).
pub fn check_artifact(input: &Path) -> Result<ArtifactFormat, Diagnostic> {
    detect_format(input).map_err(|failure| failure.diagnostic)
}

fn detect_format(input: &Path) -> Result<ArtifactFormat, IntakeFailure> {
    if !input.is_file() {
        // A missing (or non-file) path is a not-found problem, not an
        // unsupported-format one; the headline must say so.
        return Err(failure(
            ARTIFACT_NOT_FOUND,
            format!("input {} is not a regular file", input.display()),
        ));
    }
    let extension = input
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let entries = zip_entries(input)?;
    if entries.iter().any(|entry| entry == "AndroidManifest.xml")
        && (entries.iter().any(|entry| entry == "classes.dex")
            || entries.iter().any(|entry| entry == "resources.arsc"))
    {
        return Ok(ArtifactFormat::Apk);
    }

    if extension == "aab" && looks_like_aab(&entries) {
        return Ok(ArtifactFormat::Aab);
    }
    if has_apk_member(&entries) {
        // APKMirror packages are ZIP containers whose content identifies the
        // family: a base APK plus config split members. The extension is only
        // a hint, so a renamed .zip is handled identically to .apkm.
        if looks_like_xapk(&entries) {
            return Ok(ArtifactFormat::Xapk);
        }
        if looks_like_apkm(&entries) {
            return Ok(ArtifactFormat::Apkm);
        }
        if extension == "apks" && looks_like_apks(&entries) {
            return Ok(ArtifactFormat::Apks);
        }
        return Ok(ArtifactFormat::ZipSplits);
    }

    Err(failure(
        ARTIFACT_UNSUPPORTED_FORMAT,
        format!("extension .{extension} did not identify an Android package family"),
    ))
}

fn has_apk_member(entries: &[String]) -> bool {
    entries.iter().any(|entry| {
        Path::new(entry)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
    })
}

fn looks_like_aab(entries: &[String]) -> bool {
    entries.iter().any(|entry| entry == "BundleConfig.pb")
        && entries
            .iter()
            .any(|entry| entry.ends_with("/manifest/AndroidManifest.xml"))
}

fn looks_like_apks(entries: &[String]) -> bool {
    entries.iter().any(|entry| entry == "toc.pb")
        || entries.iter().any(|entry| entry.starts_with("splits/"))
}

fn looks_like_xapk(entries: &[String]) -> bool {
    entries.iter().any(|entry| {
        Path::new(entry)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("manifest.json"))
    }) && has_apk_member(entries)
}

fn looks_like_apkm(entries: &[String]) -> bool {
    let has_base = entries.iter().any(|entry| {
        Path::new(entry)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("base.apk"))
    });
    let has_config_split = entries.iter().any(|entry| {
        Path::new(entry)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.to_ascii_lowercase().starts_with("split_config_")
                    && Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"))
            })
    });
    let has_apkm_metadata = entries.iter().any(|entry| {
        matches!(
            Path::new(entry)
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("info.json" | "icon.png")
        )
    });
    has_base && (has_config_split || has_apkm_metadata)
}

fn archive_record(format: ArtifactFormat, path: &Path) -> Result<RawArchive, IntakeFailure> {
    Ok(RawArchive {
        format,
        path: path.display().to_string(),
        entries: zip_entries(path)?,
    })
}

fn zip_entries(path: &Path) -> Result<Vec<String>, IntakeFailure> {
    let file = File::open(path).map_err(|error| io_failure("open archive", error))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
    let mut entries = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
        validate_entry_name(entry.name())?;
        entries.push(entry.name().to_owned());
    }
    entries.sort();
    Ok(entries)
}

fn validate_apk(path: &Path) -> Result<(), IntakeFailure> {
    let entries = zip_entries(path)?;
    let has_manifest = entries.iter().any(|entry| entry == "AndroidManifest.xml");
    // A split APK can be a native-library-only or resource-only member and
    // therefore legitimately has no DEX file or base resources. Require the
    // APK manifest plus at least one installable payload class instead of
    // applying the standalone/base-APK rule to every split member.
    let has_payload = entries.iter().any(|entry| {
        entry == "classes.dex"
            || entry == "resources.arsc"
            || entry.starts_with("lib/")
            || entry.starts_with("res/")
            || entry.starts_with("assets/")
    });
    if !has_manifest || !has_payload {
        return Err(failure(
            ARTIFACT_UNSUPPORTED_FORMAT,
            format!("{} is not an installable APK", path.display()),
        ));
    }
    Ok(())
}

fn copy_apk(input: &Path, root: &Path, id: &str) -> Result<InstallableApk, IntakeFailure> {
    let path = root.join(format!("{id}.apk"));
    fs::copy(input, &path).map_err(|error| io_failure("preserve standalone APK", error))?;
    Ok(InstallableApk {
        id: id.to_owned(),
        path: path.display().to_string(),
        is_base: true,
    })
}

fn extract_apks_from_container(
    input: &Path,
    root: &Path,
) -> Result<Vec<InstallableApk>, IntakeFailure> {
    let file = File::open(input).map_err(|error| io_failure("open split container", error))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
    let mut members = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
        let name = entry.name().to_owned();
        validate_entry_name(&name)?;
        if name.to_ascii_lowercase().ends_with(".apk") {
            let id = Path::new(&name)
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or("split")
                .to_owned();
            let destination = root.join(format!("{id}.apk"));
            let mut output = File::create(&destination)
                .map_err(|error| io_failure("extract split APK", error))?;
            io::copy(&mut entry, &mut output)
                .map_err(|error| io_failure("write split APK", error))?;
            validate_apk(&destination)?;
            members.push((id, destination));
        }
    }
    members.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(members
        .into_iter()
        .enumerate()
        .map(|(index, (mut id, path))| {
            if id.is_empty() {
                id = format!("split-{index}");
            }
            InstallableApk {
                is_base: id.contains("base") || index == 0,
                id,
                path: path.display().to_string(),
            }
        })
        .collect())
}

fn extract_dex_files(apk: &Path, root: &Path) -> Result<Vec<String>, IntakeFailure> {
    fs::create_dir_all(root).map_err(|error| io_failure("create DEX access directory", error))?;
    let file = File::open(apk).map_err(|error| io_failure("open APK for DEX access", error))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
    let mut paths = Vec::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| failure(ARTIFACT_MALFORMED_ARCHIVE, error.to_string()))?;
        let name = entry.name().to_owned();
        if name.starts_with("classes")
            && Path::new(&name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
        {
            let destination = root.join(Path::new(&name).file_name().unwrap_or_default());
            let mut output = File::create(&destination)
                .map_err(|error| io_failure("materialize DEX access", error))?;
            io::copy(&mut entry, &mut output)
                .map_err(|error| io_failure("write DEX access", error))?;
            paths.push(destination.display().to_string());
        }
    }
    paths.sort();
    Ok(paths)
}

fn structural_output(apk: &InstallableApk, root: &Path) -> Result<StructuralOutput, IntakeFailure> {
    let manifest = root.join("AndroidManifest.xml");
    let resources = root.join("res");
    let assets = root.join("assets");
    if !resources.exists() {
        fs::create_dir(&resources)
            .map_err(|error| io_failure("create empty resource root", error))?;
    }
    if !assets.exists() {
        fs::create_dir(&assets).map_err(|error| io_failure("create empty asset root", error))?;
    }
    let smali_roots = fs::read_dir(root)
        .map_err(|error| io_failure("inspect apktool output", error))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "smali" || name.starts_with("smali_classes"))
        })
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    // Resource, language, density, and native-ABI splits are installable
    // members even when they carry no classes.dex and therefore produce no
    // smali directory. The base/code split remains represented by the same
    // structural contract; an empty smali list is an honest split property,
    // not an unpack failure.
    if !manifest.is_file() || !resources.is_dir() {
        return Err(failure(
            ARTIFACT_UNPACK_FAILED,
            format!("apktool output for {} is incomplete", apk.id),
        ));
    }
    Ok(StructuralOutput {
        apk_id: apk.id.clone(),
        manifest: manifest.display().to_string(),
        smali_roots,
        resource_root: resources.display().to_string(),
        asset_root: assets.display().to_string(),
    })
}

/// Interval between intake progress heartbeats during the long external-tool step.
const UNPACK_HEARTBEAT_SECS: u64 = 30;

/// Emits a periodic elapsed-time heartbeat while apktool/jadx run, so a long
/// large-APK unpack reads as progressing rather than hung. Stops promptly once
/// `running` is cleared. Nothing is emitted before the first interval, so a fast
/// small-APK intake stays quiet.
fn report_unpack_progress(
    running: &AtomicBool,
    started: Instant,
    apk_id: &str,
    written: &dyn Fn(u64),
    apktool_root: &Path,
    jadx_root: &Path,
) {
    let mut since_report = Duration::ZERO;
    let mut since_count = Duration::ZERO;
    let tick = Duration::from_millis(250);
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(tick);
        since_report = since_report.saturating_add(tick);
        since_count = since_count.saturating_add(tick);
        if since_count >= Duration::from_secs(2) {
            since_count = Duration::ZERO;
            // One smali file per class from apktool, one Java file per
            // top-level class from jadx.
            written(
                count_files_with(apktool_root, "smali")
                    + count_files_with(&jadx_root.join("sources"), "java"),
            );
        }
        if since_report.as_secs() >= UNPACK_HEARTBEAT_SECS {
            since_report = Duration::ZERO;
            eprintln!(
                "apiaxess: still unpacking APK ({apk_id}) — apktool/jadx running, elapsed {}s…",
                started.elapsed().as_secs()
            );
        }
    }
}

/// Files with `extension` below `root` (recursively); 0 when it is absent.
fn count_files_with(root: &Path, extension: &str) -> u64 {
    let mut count = 0;
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
            {
                count += 1;
            }
        }
    }
    count
}

/// Classes defined across an APK's `classes*.dex` files, read from each DEX
/// header's `class_defs_size` (offset 0x60); 0 when unreadable.
fn dex_class_count(apk: &Path) -> u64 {
    let Ok(file) = File::open(apk) else {
        return 0;
    };
    let Ok(mut archive) = ZipArchive::new(file) else {
        return 0;
    };
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let Ok(mut entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name().to_owned();
        // A top-level `classes.dex`, `classes2.dex`, ...
        let member = Path::new(&name);
        let is_dex = !name.contains('/')
            && member
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dex"))
            && member
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.strip_prefix("classes"))
                .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit()));
        if !is_dex {
            continue;
        }
        let mut header = [0_u8; 0x70];
        if io::Read::read_exact(&mut entry, &mut header).is_ok() {
            total += u64::from(u32::from_le_bytes([
                header[0x60],
                header[0x61],
                header[0x62],
                header[0x63],
            ]));
        }
    }
    total
}

fn profile_intake(stage: &str, started: Instant, detail: Option<String>) {
    if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
        match detail {
            Some(detail) => eprintln!(
                "STATIC INTAKE PROFILE: stage={stage} elapsed_ms={} {detail}",
                started.elapsed().as_millis()
            ),
            None => eprintln!(
                "STATIC INTAKE PROFILE: stage={stage} elapsed_ms={}",
                started.elapsed().as_millis()
            ),
        }
    }
}

fn materialized_file_stats(root: &Path) -> (usize, u64) {
    let mut pending = vec![root.to_path_buf()];
    let mut files = 0usize;
    let mut bytes = 0u64;
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(entry.metadata().map_or(0, |metadata| metadata.len()));
            }
        }
    }
    (files, bytes)
}

/// Removes a normalized intake workspace once all consumers have finished with
/// the artifact.
///
/// This is the single source of truth for intake teardown: [`ApkTarget::cleanup`]
/// delegates here, and the pipeline's run-scoped scratch guard calls it directly
/// so a completed (or failed) run does not leave its unpacked scratch behind to
/// accumulate across runs under the configured output root.
///
/// The deletion is restricted to a direct child of the configured `output_root`.
/// This keeps teardown explicit and prevents a malformed handoff from turning
/// cleanup into a broad delete.
///
/// # Errors
///
/// Returns an intake failure when the output root or workspace cannot be
/// resolved, or when cleanup would leave the configured output root.
pub fn cleanup_intake_workspace(
    output_root: &Path,
    workspace_root: &str,
) -> Result<(), IntakeFailure> {
    let workspace = PathBuf::from(workspace_root);
    let output_root = fs::canonicalize(output_root)
        .map_err(|error| io_failure("resolve intake output root for cleanup", error))?;
    let parent = workspace
        .parent()
        .ok_or_else(|| failure(ARTIFACT_UNPACK_FAILED, "intake workspace has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_failure("resolve intake workspace parent", error))?;
    if parent != output_root || workspace.file_name().is_none() {
        return Err(failure(
            ARTIFACT_UNPACK_FAILED,
            format!(
                "refusing intake cleanup outside configured output root: {}",
                workspace.display()
            ),
        ));
    }
    if workspace.exists() {
        fs::remove_dir_all(&workspace)
            .map_err(|error| io_failure("remove intake workspace", error))?;
    }
    if workspace.exists() {
        return Err(failure(
            ARTIFACT_UNPACK_FAILED,
            format!(
                "intake workspace remained after cleanup: {}",
                workspace.display()
            ),
        ));
    }
    Ok(())
}

/// Default age after which an orphaned intake workspace is reaped, in seconds
/// (24 hours). A live run's workspace is removed by the pipeline's run-scoped
/// guard when the run ends; this age-based reap is the second line of defense
/// for scratch orphaned by a *hard* kill (`SIGKILL`/`TerminateProcess`, OOM, or
/// power loss) that skips the guard's drop. The bound is generous enough that no
/// concurrent, still-running analysis (which keeps its workspace freshly
/// modified) is ever reaped.
const INTAKE_RETENTION_SECS_DEFAULT: u64 = 24 * 60 * 60;

/// Resolves the orphaned-workspace retention window, honoring the advanced
/// `APIAXESS_INTAKE_RETENTION_SECS` override. A missing, empty, or unparseable
/// value falls back to the default; `0` disables reaping.
fn intake_retention_secs() -> u64 {
    std::env::var("APIAXESS_INTAKE_RETENTION_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(INTAKE_RETENTION_SECS_DEFAULT)
}

/// Best-effort removal of intake workspaces older than the retention window,
/// bounding the output root so it cannot grow without limit when a hard-killed
/// run leaves scratch behind. Only direct `intake-*` children are considered, and
/// only those whose last-modified time is older than the window, so an active
/// concurrent run is never touched. Failures are ignored: a workspace that cannot
/// be reaped now is simply retried on the next run.
fn reap_stale_workspaces(root: &Path, retention: Duration) {
    if retention.is_zero() {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("intake-") {
            continue;
        }
        let modified = entry.metadata().and_then(|metadata| metadata.modified());
        if let Ok(modified) = modified
            && is_stale(modified, now, retention)
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Whether a workspace last modified at `modified` is older than `retention`
/// relative to `now`. A workspace modified in the (clock-skew) future is treated
/// as fresh, never reaped.
fn is_stale(modified: SystemTime, now: SystemTime, retention: Duration) -> bool {
    now.duration_since(modified)
        .is_ok_and(|age| age > retention)
}

fn create_workspace(root: &Path) -> Result<PathBuf, IntakeFailure> {
    fs::create_dir_all(root).map_err(|error| io_failure("create artifact output root", error))?;
    reap_stale_workspaces(root, Duration::from_secs(intake_retention_secs()));
    let base = format!("intake-{}", now_seconds());
    let mut path = root.join(&base);
    let mut suffix = 0;
    while path.exists() {
        suffix += 1;
        path = root.join(format!("{base}-{suffix}"));
    }
    fs::create_dir(&path).map_err(|error| io_failure("create artifact workspace", error))?;
    Ok(path)
}

struct IntakeWorkspaceGuard {
    path: Option<PathBuf>,
}

impl IntakeWorkspaceGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for IntakeWorkspaceGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_entry_name(name: &str) -> Result<(), IntakeFailure> {
    let path = Path::new(name);
    if path.is_absolute()
        || name.contains('\\')
        || path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err(failure(
            ARTIFACT_MALFORMED_ARCHIVE,
            format!("unsafe archive entry {name}"),
        ));
    }
    Ok(())
}

fn tool_provenance(
    component: ArtifactComponent,
    probe: &ToolProbe,
    output: &Path,
) -> ComponentProvenance {
    ComponentProvenance {
        component,
        source_tool: probe.tool_id.clone(),
        source_version: Some(probe.version.to_string()),
        recorded_at_unix_seconds: now_seconds(),
        output_root: output.display().to_string(),
    }
}

fn ensure_success(tool: &str, invocation: &ToolInvocation) -> Result<(), Diagnostic> {
    if invocation.exit_code == Some(0) {
        Ok(())
    } else {
        let raw = if invocation.stderr.trim().is_empty() {
            invocation.stdout.trim()
        } else {
            invocation.stderr.trim()
        };
        // Report the tool's own final message, not its entire progress log. Tools
        // like jadx stream progress with a carriage-return bar (`\r`, no newline)
        // and end on the real signal (e.g. "finished with errors, count: 51"), so
        // split on both `\r` and `\n` and keep only the last non-empty segment.
        // Splitting on `\n` alone treats the whole `\r` bar as one line and leaks
        // the firehose.
        let summary: String = raw
            .split(['\n', '\r'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .next_back()
            .unwrap_or("no output")
            .chars()
            .take(200)
            .collect();
        Err(failure(
            EXTERNAL_TOOL_INVOCATION_FAILED,
            format!(
                "{tool} exited with {}: {summary}",
                format_exit_code(invocation.exit_code)
            ),
        )
        .diagnostic)
    }
}

/// Renders a process exit status for humans — never the `Option` debug form.
fn format_exit_code(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("code {code}"),
        None => "no exit code (process terminated by signal)".to_owned(),
    }
}

fn has_decompilation_output(root: &Path) -> bool {
    fs::read_dir(root)
        .map(|entries| entries.flatten().any(|entry| entry.path().is_dir()))
        .unwrap_or(false)
}

fn with_definition(
    mut diagnostic: Diagnostic,
    definition: apiaxess_diagnostics::DiagnosticDefinition,
) -> Diagnostic {
    diagnostic.id = definition.id.into();
    diagnostic.what = definition.what.into();
    diagnostic.fix = definition.fix.into();
    diagnostic
}

fn failure(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    why: impl Into<String>,
) -> IntakeFailure {
    let mut diagnostic = definition.instantiate(DiagnosticContext::new());
    diagnostic.why = why.into().into_boxed_str();
    IntakeFailure { diagnostic }
}

#[allow(clippy::needless_pass_by_value)]
fn io_failure(operation: &str, error: io::Error) -> IntakeFailure {
    failure(ARTIFACT_MALFORMED_ARCHIVE, format!("{operation}: {error}"))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{ApkTarget, detect_format, validate_apk};
    use apiaxess_artifact_intake::ArtifactFormat;
    use std::{fs, fs::File, io::Write, path::Path};
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn dex_class_count_reads_every_classes_dex_header() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-dex-count-{}-{}.apk",
            std::process::id(),
            super::now_seconds()
        ));
        let dex = |classes: u32| {
            let mut header = vec![0_u8; 0x70];
            header[..4].copy_from_slice(b"dex\n");
            header[0x60..0x64].copy_from_slice(&classes.to_le_bytes());
            header
        };
        let file = File::create(&path).expect("create fixture");
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for (name, body) in [
            ("classes.dex", dex(42)),
            ("classes2.dex", dex(8)),
            ("assets/classes.dex", dex(1000)),
            ("AndroidManifest.xml", b"manifest".to_vec()),
        ] {
            archive.start_file(name, options).expect("start member");
            archive.write_all(&body).expect("write member");
        }
        archive.finish().expect("finish fixture");
        // The two top-level DEX files count; a DEX nested in assets does not.
        assert_eq!(super::dex_class_count(&path), 50);
        assert_eq!(super::dex_class_count(Path::new("missing.apk")), 0);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn missing_input_is_not_misclassified_as_an_apk() {
        let result = detect_format(Path::new("does-not-exist.apk"));
        // A non-existent path is reported as not-found, not as a format problem.
        assert_eq!(
            result
                .expect_err("missing input must fail")
                .diagnostic
                .id
                .as_ref(),
            "artifact.not-found"
        );
    }

    #[test]
    fn target_probe_reports_the_android_target_id() {
        let target = ApkTarget::default();
        let probe = apiaxess_artifact_intake::TargetType::probe(&target, Path::new("missing.apk"));
        assert_eq!(probe.target_type_id, "android.apk");
        assert_eq!(probe.match_basis_points, 0);
    }

    #[test]
    fn apkm_is_recognized_from_split_contents_even_when_renamed() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-apkm-fixture-{}-{}.zip",
            std::process::id(),
            super::now_seconds()
        ));
        let file = File::create(&path).expect("create fixture");
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for name in [
            "base.apk",
            "split_config.arm64_v8a.apk",
            "split_config.xxhdpi.apk",
            "info.json",
        ] {
            archive.start_file(name, options).expect("start member");
            archive.write_all(b"fixture").expect("write member");
        }
        archive.finish().expect("finish fixture");

        assert_eq!(
            detect_format(&path).expect("detect APKM"),
            ArtifactFormat::Apkm
        );
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn xapk_and_bare_split_zip_are_content_classified() {
        let xapk_path = std::env::temp_dir().join(format!(
            "apiaxess-xapk-fixture-{}-{}.zip",
            std::process::id(),
            super::now_seconds()
        ));
        let file = File::create(&xapk_path).expect("create xapk fixture");
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for name in ["base.apk", "config.x86.apk", "manifest.json"] {
            archive
                .start_file(name, options)
                .expect("start xapk member");
            archive.write_all(b"fixture").expect("write xapk member");
        }
        archive.finish().expect("finish xapk fixture");
        assert_eq!(
            detect_format(&xapk_path).expect("detect xapk"),
            ArtifactFormat::Xapk
        );
        fs::remove_file(&xapk_path).expect("remove xapk fixture");

        let zip_path = std::env::temp_dir().join(format!(
            "apiaxess-splits-fixture-{}-{}.zip",
            std::process::id(),
            super::now_seconds()
        ));
        let file = File::create(&zip_path).expect("create split fixture");
        let mut archive = ZipWriter::new(file);
        for name in ["base.apk", "split_config.x86.apk"] {
            archive
                .start_file(name, options)
                .expect("start split member");
            archive.write_all(b"fixture").expect("write split member");
        }
        archive.finish().expect("finish split fixture");
        assert_eq!(
            detect_format(&zip_path).expect("detect bare split zip"),
            ArtifactFormat::ZipSplits
        );
        fs::remove_file(zip_path).expect("remove split fixture");
    }

    #[test]
    fn native_only_split_member_is_validated_as_an_installable_apk() {
        let path = std::env::temp_dir().join(format!(
            "apiaxess-native-split-fixture-{}-{}.apk",
            std::process::id(),
            super::now_seconds()
        ));
        let file = File::create(&path).expect("create native split fixture");
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        archive
            .start_file("AndroidManifest.xml", options)
            .expect("start manifest");
        archive.write_all(b"manifest").expect("write manifest");
        archive
            .start_file("lib/x86_64/libfixture.so", options)
            .expect("start native payload");
        archive.write_all(b"native").expect("write native payload");
        archive.finish().expect("finish native split fixture");

        validate_apk(&path).expect("native-only split should be installable");
        fs::remove_file(path).expect("remove native split fixture");
    }

    #[test]
    fn tool_timeout_scales_with_apk_size_and_keeps_a_floor() {
        use super::{
            DEFAULT_TOOL_TIMEOUT_SECS, TOOL_TIMEOUT_BASE_SECS, TOOL_TIMEOUT_PER_MB_SECS,
            size_scaled_timeout_secs,
        };
        let mb = 1024 * 1024;
        // A tiny input still gets at least the default floor (never less).
        assert_eq!(size_scaled_timeout_secs(0), DEFAULT_TOOL_TIMEOUT_SECS);
        assert_eq!(size_scaled_timeout_secs(mb), DEFAULT_TOOL_TIMEOUT_SECS);
        // A 60 MB APK (feeder: apktool alone needs ~5 min) gets a scaled deadline
        // above the old fixed 300s that used to fail it mid-unpack.
        let sixty = size_scaled_timeout_secs(60 * mb);
        assert_eq!(
            sixty,
            TOOL_TIMEOUT_BASE_SECS + 60 * TOOL_TIMEOUT_PER_MB_SECS
        );
        assert!(
            sixty > DEFAULT_TOOL_TIMEOUT_SECS,
            "60 MB must scale past the floor"
        );
        // A 249 MB APK (Openly, ~44 min observed) scales into the tens of minutes
        // so it is not failed by a fixed deadline.
        let large = size_scaled_timeout_secs(249 * mb);
        assert!(
            large >= 3_000,
            "a 249 MB APK deadline must be tens of minutes, got {large}s"
        );
        // Monotonic in size.
        assert!(size_scaled_timeout_secs(250 * mb) >= large);
    }

    #[test]
    fn cleanup_removes_the_run_workspace_but_keeps_the_output_root() {
        let output_root = std::env::temp_dir().join(format!(
            "apiaxess-cleanup-root-{}-{}",
            std::process::id(),
            super::now_seconds()
        ));
        let workspace = output_root.join("intake-fixture");
        fs::create_dir_all(workspace.join("unpacked")).expect("create workspace scratch");
        fs::write(workspace.join("unpacked").join("f"), b"scratch").expect("write scratch");

        super::cleanup_intake_workspace(&output_root, &workspace.display().to_string())
            .expect("cleanup removes the workspace");

        assert!(!workspace.exists(), "run workspace must be removed");
        assert!(
            output_root.exists(),
            "the shared output root must survive so it is reusable across runs"
        );
        fs::remove_dir_all(&output_root).expect("remove fixture root");
    }

    #[test]
    fn cleanup_refuses_a_workspace_outside_the_output_root() {
        let output_root = std::env::temp_dir().join(format!(
            "apiaxess-cleanup-guard-{}-{}",
            std::process::id(),
            super::now_seconds()
        ));
        fs::create_dir_all(&output_root).expect("create output root");
        // A sibling of the output root, not a child: cleanup must refuse it so a
        // malformed handoff can never turn teardown into a broad delete.
        let outside = std::env::temp_dir().join(format!(
            "apiaxess-cleanup-outside-{}-{}",
            std::process::id(),
            super::now_seconds()
        ));
        fs::create_dir_all(&outside).expect("create outside dir");

        let result = super::cleanup_intake_workspace(&output_root, &outside.display().to_string());

        assert!(result.is_err(), "cleanup outside the output root must fail");
        assert!(outside.exists(), "the outside directory must be untouched");
        fs::remove_dir_all(&output_root).expect("remove output root");
        fs::remove_dir_all(&outside).expect("remove outside dir");
    }

    #[test]
    fn staleness_predicate_bounds_the_window_and_tolerates_clock_skew() {
        use std::time::{Duration, SystemTime};
        let now = SystemTime::now();
        let retention = Duration::from_secs(3600);
        // Older than the window: stale.
        assert!(super::is_stale(
            now - Duration::from_secs(7200),
            now,
            retention
        ));
        // Within the window (an active concurrent run): kept.
        assert!(!super::is_stale(
            now - Duration::from_secs(60),
            now,
            retention
        ));
        // Modified in the future (clock skew): never reaped.
        assert!(!super::is_stale(
            now + Duration::from_secs(60),
            now,
            retention
        ));
    }

    #[test]
    fn reap_leaves_fresh_workspaces_and_is_disabled_at_zero_retention() {
        use std::time::Duration;
        let root = std::env::temp_dir().join(format!(
            "apiaxess-reap-{}-{}",
            std::process::id(),
            super::now_seconds()
        ));
        let fresh = root.join("intake-fresh");
        let unrelated = root.join("keep-me");
        fs::create_dir_all(&fresh).expect("create fresh workspace");
        fs::create_dir_all(&unrelated).expect("create unrelated dir");

        // A just-created workspace is inside any sane window, so it survives.
        super::reap_stale_workspaces(&root, Duration::from_secs(3600));
        assert!(fresh.exists(), "a fresh workspace must not be reaped");

        // Zero retention disables reaping entirely.
        super::reap_stale_workspaces(&root, Duration::ZERO);
        assert!(fresh.exists(), "zero retention must disable reaping");
        // Non-`intake-` siblings are never touched.
        assert!(
            unrelated.exists(),
            "unrelated directories must be untouched"
        );

        fs::remove_dir_all(&root).expect("remove reap fixture");
    }
}
