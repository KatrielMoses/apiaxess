//! Stable handoff contracts between target-type intake and Phase 1 analysis.
//!
//! A target implementation owns ecosystem-specific decomposition. Shared
//! engine code sees only this target-type seam and the normalized representation
//! below, so web, executable, and package targets can be added as siblings.

use std::{
    fs::File,
    path::{Component, Path},
};

use apiaxess_diagnostics::Diagnostic;
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

/// Version of the normalized Phase 1.1 handoff schema.
pub const NORMALIZED_ARTIFACT_SCHEMA_VERSION: u32 = 1;

/// A target-type implementation that can probe and inspect an artifact.
pub trait TargetType {
    /// Stable target ID used for routing and provenance.
    fn target_type_id(&self) -> &'static str;

    /// Probe without mutating the artifact or running unpacking tools.
    fn probe(&self, artifact: &Path) -> TargetProbe;
}

/// Target routing observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetProbe {
    /// Stable target ID.
    pub target_type_id: String,
    /// Routing confidence in basis points, not model confidence.
    pub match_basis_points: u16,
    /// Media types and archive observations.
    pub observed_media_types: Vec<String>,
    /// Non-fatal probe diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Archive family recognized at intake.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// A standalone installable Android package.
    Apk,
    /// Android App Bundle.
    Aab,
    /// Bundletool/APKS split container.
    Apks,
    /// `APKMirror`'s ZIP-family split container.
    Apkm,
    /// XAPK archive containing APK members and XAPK metadata.
    Xapk,
    /// A ZIP archive containing APK split members without a stronger family marker.
    ZipSplits,
}

/// Which component of the handoff was produced by a tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactComponent {
    /// Original input or generated split archive.
    RawArchive,
    /// Central-directory index used by filesystem-light static analysis.
    StaticArchiveIndex,
    /// Decoded Android manifest.
    Manifest,
    /// Authoritative smali output.
    Smali,
    /// Raw resources and assets.
    Resources,
    /// DEX bytecode access.
    Dex,
    /// Lossy Java source output.
    DecompiledSource,
    /// Protection/obfuscation detection metadata.
    ProtectionMetadata,
}

/// Provenance for one normalized component.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComponentProvenance {
    /// Component this record explains.
    pub component: ArtifactComponent,
    /// Stable producing tool or handoff source.
    pub source_tool: String,
    /// Detected producing tool version, when applicable.
    pub source_version: Option<String>,
    /// Unix timestamp in seconds for the tool run.
    pub recorded_at_unix_seconds: u64,
    /// Human-readable evidence path within the normalized workspace.
    pub output_root: String,
}

/// A preserved input or resolved bundle archive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RawArchive {
    /// Archive format.
    pub format: ArtifactFormat,
    /// Original or generated archive path in the normalized workspace.
    pub path: String,
    /// Entry names observed before extraction.
    pub entries: Vec<String>,
}

/// Lightweight central-directory index for one installable APK archive.
///
/// The index deliberately retains names and bounded metadata only. Contents
/// remain in the APK and are read sequentially by static consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StaticArchiveIndex {
    /// APK archive path in the normalized workspace.
    pub archive_path: String,
    /// File members in deterministic archive order.
    pub entries: Vec<StaticArchiveEntry>,
}

/// Metadata for one file member in a [`StaticArchiveIndex`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StaticArchiveEntry {
    /// ZIP member name using `/` separators.
    pub name: String,
    /// Uncompressed member size reported by the ZIP central directory.
    pub uncompressed_size: u64,
}

/// Indexes an APK without extracting any member.
///
/// # Errors
///
/// Returns the underlying ZIP or filesystem error. Callers should attach the
/// artifact-malformed-archive diagnostic at their target boundary.
pub fn index_static_archive(path: &Path) -> Result<StaticArchiveIndex, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut archive = ZipArchive::new(file).map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| error.to_string())?;
        if !entry.is_dir() {
            let name = entry.name();
            let member_path = Path::new(name);
            if member_path.is_absolute()
                || name.contains('\\')
                || member_path
                    .components()
                    .any(|component| component == Component::ParentDir)
            {
                return Err(format!("unsafe archive member path {name}"));
            }
            entries.push(StaticArchiveEntry {
                name: name.to_owned(),
                uncompressed_size: entry.size(),
            });
        }
    }
    Ok(StaticArchiveIndex {
        archive_path: path.display().to_string(),
        entries,
    })
}

/// A resolved standalone APK consumed by the unpacking toolchains.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstallableApk {
    /// Stable local identifier, such as `base` or `split_config_x86`.
    pub id: String,
    /// Preserved APK path in the normalized workspace.
    pub path: String,
    /// Whether this APK is the base package.
    pub is_base: bool,
}

/// Deferred programmatic DEX access, without exposing raw tool output to callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DexAccess {
    /// DEX files in deterministic order.
    pub dex_files: Vec<String>,
    /// Stable parser handoff ID for later sub-phases.
    pub parser_handoff: String,
    /// Capabilities promised by the later parser adapter.
    pub capabilities: Vec<String>,
}

/// Protection metadata that downstream confidence logic must consume.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectionMetadata {
    /// Detector state.
    pub detector: String,
    /// Detector version, when the isolated detector was available.
    pub detector_version: Option<String>,
    /// License/distribution posture of the detector.
    pub distribution_posture: String,
    /// Signatures reported by the detector.
    pub signatures: Vec<String>,
    /// Whether a downstream handler is currently available.
    pub handled: bool,
    /// Quantified in-house detector result, when the detector ran.
    #[serde(default)]
    pub profile: Option<ProtectionProfile>,
}

/// Protection severity tier consumed by routing and honesty roll-ups.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionTier {
    /// No protection signal was established.
    Tier0Unprotected,
    /// Stock R8/ProGuard minification/optimization only.
    Tier1StockR8,
    /// Obfuscation signals exceed ordinary compiler minification.
    Tier2Obfuscated,
    /// Heavy control-flow, reflection, native, or RASP boundary signals.
    Tier3HeavyCfgNative,
    /// Orthogonal packing evidence indicates a loader/payload boundary.
    Tier4Packed,
}

/// Quantified recoverability features produced by the in-house detector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoverabilityFeatureVector {
    /// Visible class coverage against manifest/DEX-declared classes.
    pub code_coverage_basis_points: u16,
    /// Fraction of identifiers showing minification-like naming.
    pub identifier_minification_basis_points: u16,
    /// Density of high-entropy/encrypted string regions.
    pub string_entropy_basis_points: u16,
    /// Control-flow complexity signal from bounded structural counts.
    pub control_flow_complexity_basis_points: u16,
    /// Reflection/dynamic lookup density.
    pub reflection_density_basis_points: u16,
    /// Native-boundary ratio.
    pub native_boundary_basis_points: u16,
    /// Packing/RASP marker strength.
    pub packing_rasp_basis_points: u16,
}

/// One independently observed protection signal and its provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectionSignalEvidence {
    /// Stable in-house signature identifier.
    pub signature_id: String,
    /// Orthogonal signal class.
    pub signal_class: String,
    /// Strength of this signal in basis points.
    pub strength_basis_points: u16,
    /// Normalized artifact locations supporting the signal.
    pub locations: Vec<String>,
}

/// Full quantified result from the clean-room protection detector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectionProfile {
    /// Detector schema version.
    pub schema_version: u32,
    /// Best-supported protection identity, if one was established.
    pub identity: Option<String>,
    /// Protection tier.
    pub tier: ProtectionTier,
    /// Confidence in the protection verdict.
    pub detection_confidence_basis_points: u16,
    /// Feature vector consumed by recoverability logic.
    pub recoverability: RecoverabilityFeatureVector,
    /// Signal evidence retained for audit and diagnostics.
    pub signals: Vec<ProtectionSignalEvidence>,
    /// Whether the packer verdict met the orthogonal-signal gate.
    pub orthogonal_gate_satisfied: bool,
}

/// Single normalized decomposition handoff for Phase 1.2–1.4.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NormalizedUnpackedArtifact {
    /// Handoff schema version.
    pub schema_version: u32,
    /// Target seam ID.
    pub target_type_id: String,
    /// Normalized workspace root.
    pub workspace_root: String,
    /// Format of the original input.
    pub input_format: ArtifactFormat,
    /// Preserved raw archive structures.
    pub raw_archives: Vec<RawArchive>,
    /// Indexed installable APKs used by filesystem-light static analysis.
    #[serde(default)]
    pub static_archives: Vec<StaticArchiveIndex>,
    /// Standalone APKs resolved from the input.
    pub installable_apks: Vec<InstallableApk>,
    /// Authoritative decoded manifests, smali, resources, and assets.
    pub structural_outputs: Vec<StructuralOutput>,
    /// Read-only programmatic DEX access.
    pub dex_access: DexAccess,
    /// Lossy convenience source outputs.
    pub decompiled_source_roots: Vec<String>,
    /// Detection result that drives later confidence expectations.
    pub protection: ProtectionMetadata,
    /// Provenance for each output component.
    pub provenance: Vec<ComponentProvenance>,
    /// Warnings retained with the handoff.
    pub diagnostics: Vec<Diagnostic>,
}

/// Structural output for one standalone APK.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuralOutput {
    /// APK identifier.
    pub apk_id: String,
    /// Decoded manifest path.
    pub manifest: String,
    /// Smali roots.
    pub smali_roots: Vec<String>,
    /// Resource root.
    pub resource_root: String,
    /// Asset root.
    pub asset_root: String,
}

impl NormalizedUnpackedArtifact {
    /// Validates the handoff's minimum completeness guarantees.
    ///
    /// # Errors
    ///
    /// Returns the first schema or completeness violation.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != NORMALIZED_ARTIFACT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported normalized artifact schema {}; expected {}",
                self.schema_version, NORMALIZED_ARTIFACT_SCHEMA_VERSION
            ));
        }
        if self.target_type_id.trim().is_empty() {
            return Err("normalized handoff has no target type".to_owned());
        }
        if self.installable_apks.is_empty() {
            return Err("normalized handoff contains no installable APKs".to_owned());
        }
        if self.structural_outputs.len() != self.installable_apks.len() {
            return Err("every installable APK must have structural output".to_owned());
        }
        if self.dex_access.dex_files.is_empty() {
            return Err("normalized handoff contains no DEX access".to_owned());
        }
        if self.decompiled_source_roots.len() != self.installable_apks.len() {
            return Err("every installable APK must have a decompiled source root".to_owned());
        }
        Ok(())
    }
}
