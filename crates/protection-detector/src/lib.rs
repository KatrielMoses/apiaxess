//! Clean-room Android protection detection from normalized artifact structure.
//!
//! The detector never invokes a third-party protection scanner. Fingerprints
//! are sibling implementations behind [`ProtectionSignature`], and every
//! enabled signature must have an audited entry in `ledger.rs` and the
//! repository clean-room ledger.

mod ledger;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
    time::Instant,
};

use aho_corasick::AhoCorasick;
use apiaxess_artifact_intake::{
    NormalizedUnpackedArtifact, ProtectionMetadata, ProtectionProfile, ProtectionSignalEvidence,
    ProtectionTier, RecoverabilityFeatureVector,
};
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        ARTIFACT_PROTECTION_DETECTED, ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE,
        ARTIFACT_PROTECTION_HEAVY, ARTIFACT_PROTECTION_LEDGER_GAP, ARTIFACT_PROTECTION_SUSPECTED,
    },
};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

/// Detector implementation version.
pub const DETECTOR_VERSION: &str = "clean-room-1";

/// Maximum bytes loaded from one protection-scan document at a time.
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

/// A normalized document available to protection signatures.
#[derive(Clone, Debug)]
pub struct ProtectionDocument {
    /// Normalized path.
    pub path: String,
    source: ProtectionSource,
}

#[derive(Clone, Debug)]
enum ProtectionSource {
    File,
    Archive {
        archive_path: String,
        member_name: String,
        uncompressed_size: u64,
    },
}

impl ProtectionDocument {
    fn load_bytes(&self) -> Result<Vec<u8>, String> {
        match &self.source {
            ProtectionSource::File => {
                let file = File::open(&self.path).map_err(|error| error.to_string())?;
                read_bounded(file)
            }
            ProtectionSource::Archive {
                archive_path,
                member_name,
                uncompressed_size,
            } => {
                if *uncompressed_size > MAX_DOCUMENT_BYTES {
                    return Err(format!(
                        "document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes"
                    ));
                }
                let file = File::open(archive_path).map_err(|error| error.to_string())?;
                let mut archive = ZipArchive::new(file).map_err(|error| error.to_string())?;
                let entry = archive
                    .by_name(member_name)
                    .map_err(|error| error.to_string())?;
                read_bounded(entry)
            }
        }
    }
}

/// Search corpus built only from the 1.1 normalized artifact.
#[derive(Clone, Debug, Default)]
pub struct ProtectionCorpus {
    /// Deterministically ordered structural documents.
    pub documents: Vec<ProtectionDocument>,
    failures: RefCell<Vec<String>>,
    failure_keys: RefCell<BTreeSet<String>>,
}

impl ProtectionCorpus {
    /// Builds a corpus from manifest, smali, resources, assets, and DEX paths.
    #[must_use]
    pub fn from_artifact(artifact: &NormalizedUnpackedArtifact) -> (Self, Vec<String>) {
        let mut corpus = Self::default();
        let mut failures = Vec::new();
        if !artifact.static_archives.is_empty() {
            for archive in &artifact.static_archives {
                for entry in &archive.entries {
                    corpus.documents.push(ProtectionDocument {
                        path: format!("{}!/{}", archive.archive_path, entry.name),
                        source: ProtectionSource::Archive {
                            archive_path: archive.archive_path.clone(),
                            member_name: entry.name.clone(),
                            uncompressed_size: entry.uncompressed_size,
                        },
                    });
                }
            }
            return (corpus, failures);
        }
        for output in &artifact.structural_outputs {
            add_path(&mut corpus, Path::new(&output.manifest), &mut failures);
            for root in [
                &output.smali_roots,
                &vec![output.resource_root.clone()],
                &vec![output.asset_root.clone()],
            ] {
                for path in root {
                    add_path(&mut corpus, Path::new(path), &mut failures);
                }
            }
        }
        for path in &artifact.dex_access.dex_files {
            add_path(&mut corpus, Path::new(path), &mut failures);
        }
        corpus
            .documents
            .sort_by(|left, right| left.path.cmp(&right.path));
        corpus
            .documents
            .dedup_by(|left, right| left.path == right.path);
        (corpus, failures)
    }

    fn text_for(&self, document: &ProtectionDocument) -> Option<String> {
        match document.load_bytes() {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(error) => {
                self.record_failure(document, &error);
                None
            }
        }
    }

    fn marker_locations(
        &self,
        specifications: &[(&str, &'static [&'static str])],
    ) -> BTreeMap<String, Vec<String>> {
        if specifications.is_empty() {
            return BTreeMap::new();
        }
        // One case-insensitive automaton over every signature's needles replaces
        // the previous per-needle `.contains` loop (dozens of full passes over
        // each decompressed document — the measured intake hotspot). Each document
        // is now scanned in a single pass regardless of needle count. `owner` maps
        // an automaton pattern back to the specification that contributed it.
        let mut needles: Vec<&str> = Vec::new();
        let mut owner: Vec<usize> = Vec::new();
        for (spec_index, (_, markers)) in specifications.iter().enumerate() {
            for marker in *markers {
                needles.push(marker);
                owner.push(spec_index);
            }
        }
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&needles)
            .expect("protection marker needles form a valid automaton");
        let mut locations = specifications
            .iter()
            .map(|(id, _)| ((*id).to_owned(), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let spec_count = specifications.len();
        self.for_each_bytes(|document, bytes| {
            let mut matched = vec![false; spec_count];
            // Overlapping matches so a needle is never masked by an overlapping
            // match of another needle — presence detection must not miss any.
            for found in automaton.find_overlapping_iter(bytes) {
                matched[owner[found.pattern().as_usize()]] = true;
            }
            // The path was part of the searched text before; keep matching it.
            for found in automaton.find_overlapping_iter(document.path.as_bytes()) {
                matched[owner[found.pattern().as_usize()]] = true;
            }
            for (spec_index, (id, _)) in specifications.iter().enumerate() {
                if matched[spec_index]
                    && let Some(entries) = locations.get_mut(*id)
                {
                    entries.push(document.path.clone());
                }
            }
        });
        locations
    }

    fn bytes_for(&self, document: &ProtectionDocument) -> Option<Vec<u8>> {
        match document.load_bytes() {
            Ok(bytes) => Some(bytes),
            Err(error) => {
                self.record_failure(document, &error);
                None
            }
        }
    }

    fn for_each_bytes(&self, mut visit: impl FnMut(&ProtectionDocument, &[u8])) {
        let mut archives = BTreeMap::<String, Vec<&ProtectionDocument>>::new();
        for document in &self.documents {
            if let ProtectionSource::Archive { archive_path, .. } = &document.source {
                archives
                    .entry(archive_path.clone())
                    .or_default()
                    .push(document);
            } else if let Some(bytes) = self.bytes_for(document) {
                visit(document, &bytes);
            }
        }
        for (archive_path, documents) in archives {
            let file = match File::open(&archive_path) {
                Ok(file) => file,
                Err(error) => {
                    for document in documents {
                        self.record_failure(document, &error.to_string());
                    }
                    continue;
                }
            };
            let mut archive = match ZipArchive::new(file) {
                Ok(archive) => archive,
                Err(error) => {
                    for document in documents {
                        self.record_failure(document, &error.to_string());
                    }
                    continue;
                }
            };
            for document in documents {
                let ProtectionSource::Archive {
                    member_name,
                    uncompressed_size,
                    ..
                } = &document.source
                else {
                    continue;
                };
                if *uncompressed_size > MAX_DOCUMENT_BYTES {
                    self.record_failure(
                        document,
                        &format!(
                            "document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes"
                        ),
                    );
                    continue;
                }
                match archive
                    .by_name(member_name)
                    .map_err(|error| error.to_string())
                    .and_then(read_bounded)
                {
                    Ok(bytes) => visit(document, &bytes),
                    Err(error) => self.record_failure(document, &error),
                }
            }
        }
    }

    fn failures(&self) -> Vec<String> {
        self.failures.borrow().clone()
    }

    fn record_failure(&self, document: &ProtectionDocument, error: &str) {
        let failure = format!("{}: {error}", document.path);
        let mut keys = self.failure_keys.borrow_mut();
        if keys.insert(failure.clone()) {
            self.failures.borrow_mut().push(failure);
        }
    }
}

fn read_bounded<R: Read>(mut reader: R) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

/// Orthogonal signal class used by the packer evidence gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalClass {
    /// Visible/declared class structure.
    VisibleStructure,
    /// Manifest references not present in visible code.
    ManifestGap,
    /// Opaque asset or payload indicator.
    OpaquePayload,
    /// Dynamic DEX/class loading API.
    DynamicLoader,
    /// Native library or native loader boundary.
    NativeLoader,
    /// Compiler marker.
    CompilerMarker,
    /// Known named-protector marker.
    ProtectorMarker,
}

#[derive(Clone, Debug)]
struct RawSignal {
    signature_id: String,
    class: SignalClass,
    strength: u16,
    locations: Vec<String>,
}

/// Extensible sibling seam for protection fingerprints.
pub trait ProtectionSignature: Send + Sync {
    /// Stable ledger-backed signature ID.
    fn signature_id(&self) -> &'static str;
    /// Signal class emitted by the signature.
    fn signal_class(&self) -> SignalClass;
    /// Returns marker definitions that can be evaluated in one corpus pass.
    fn marker_spec(&self) -> Option<&'static [&'static str]> {
        None
    }
    /// Baseline strength for evidence emitted by this signature.
    fn strength_basis_points(&self) -> u16 {
        0
    }
    /// Finds this signature in the normalized corpus.
    fn detect(&self, corpus: &ProtectionCorpus) -> Option<ProtectionSignalEvidence>;
}

#[derive(Clone, Debug)]
struct MarkerSignature {
    id: &'static str,
    class: SignalClass,
    markers: &'static [&'static str],
    strength: u16,
}

impl ProtectionSignature for MarkerSignature {
    fn signature_id(&self) -> &'static str {
        self.id
    }

    fn signal_class(&self) -> SignalClass {
        self.class
    }

    fn marker_spec(&self) -> Option<&'static [&'static str]> {
        Some(self.markers)
    }

    fn strength_basis_points(&self) -> u16 {
        self.strength
    }

    fn detect(&self, corpus: &ProtectionCorpus) -> Option<ProtectionSignalEvidence> {
        if !ledger::contains(self.id) {
            return None;
        }
        let locations = corpus
            .documents
            .iter()
            .filter_map(|document| {
                let text = corpus.text_for(document)?;
                let lower = format!(
                    "{}\n{}",
                    document.path.to_ascii_lowercase(),
                    text.to_ascii_lowercase()
                );
                self.markers
                    .iter()
                    .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
                    .then(|| document.path.clone())
            })
            .collect::<Vec<_>>();
        (!locations.is_empty()).then(|| ProtectionSignalEvidence {
            signature_id: self.id.to_owned(),
            signal_class: format!("{:?}", self.class).to_ascii_lowercase(),
            strength_basis_points: self.strength,
            locations,
        })
    }
}

/// Extensible registry of clean-room protection signatures.
pub struct ProtectionDetector {
    signatures: Vec<Box<dyn ProtectionSignature>>,
}

impl std::fmt::Debug for ProtectionDetector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectionDetector")
            .field("signature_count", &self.signatures.len())
            .field("ledger_version", &ledger::LEDGER_VERSION)
            .finish()
    }
}

impl Default for ProtectionDetector {
    fn default() -> Self {
        Self::with_signatures(vec![
            Box::new(MarkerSignature {
                id: "r8.compiler-marker",
                class: SignalClass::CompilerMarker,
                markers: &["~~d8{", "~~r8{"],
                strength: 9_500,
            }),
            Box::new(MarkerSignature {
                id: "jiagu.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libjiagu.so", "com.qihoo.util", "jiagu_data"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "legu.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["liblegu.so", "libshella", "com.tencent.stubshell"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "bangcle.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libsecexe.so", "libsecmain.so", "com.secneo"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "aliprotect.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libmobisec.so", "libsgmain.so", "com.ali.mobisec"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "ijiami.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libijiami.so", "com.ijiami", "ijiami.dat"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "dexprotector.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libdexprotector", "dexprotector", "eprotect.dat"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "baidu.native-loader",
                class: SignalClass::ProtectorMarker,
                markers: &["libbaiduprotect.so", "com.baidu.protect", "baiduprotect"],
                strength: 8_000,
            }),
            Box::new(MarkerSignature {
                id: "android.dynamic-loader",
                class: SignalClass::DynamicLoader,
                markers: &[
                    "dexclassloader",
                    "pathclassloader",
                    "inmemorydexclassloader",
                    "loaddex",
                ],
                strength: 7_000,
            }),
            Box::new(MarkerSignature {
                id: "android.native-loader-api",
                class: SignalClass::NativeLoader,
                markers: &["system.loadlibrary", "runtime.load", "system.load("],
                strength: 6_500,
            }),
            Box::new(MarkerSignature {
                id: "payload.opaque-asset",
                class: SignalClass::OpaquePayload,
                markers: &[
                    "jiagu_data.bin",
                    "secdata0.jar",
                    "eprotect.dat",
                    "encrypted",
                    "payload",
                ],
                strength: 6_500,
            }),
            Box::new(MarkerSignature {
                id: "rasp.integrity-marker",
                class: SignalClass::NativeLoader,
                markers: &["ptrace", "integrity", "tamper", "anti-debug"],
                strength: 5_500,
            }),
        ])
    }
}

impl ProtectionDetector {
    /// Creates a detector from sibling signatures. Unledgered signatures are
    /// retained for diagnostics but cannot contribute a verdict.
    #[must_use]
    pub fn with_signatures(signatures: Vec<Box<dyn ProtectionSignature>>) -> Self {
        Self { signatures }
    }

    /// Detects protection and computes the recoverability vector.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn detect(&self, artifact: &NormalizedUnpackedArtifact) -> ProtectionDetection {
        let started = Instant::now();
        let (corpus, failures) = ProtectionCorpus::from_artifact(artifact);
        profile_protection(
            "corpus_built",
            started,
            format!("documents={}", corpus.documents.len()),
        );
        let mut diagnostics = Vec::new();
        let mut signals = Vec::new();
        let marker_specs = self
            .signatures
            .iter()
            .filter_map(|signature| {
                signature
                    .marker_spec()
                    .map(|markers| (signature.signature_id(), markers))
            })
            .collect::<Vec<_>>();
        let marker_started = Instant::now();
        let marker_locations = corpus.marker_locations(&marker_specs);
        profile_protection(
            "marker_scan",
            marker_started,
            format!("signatures={}", marker_specs.len()),
        );
        for signature in &self.signatures {
            if !ledger::contains(signature.signature_id()) {
                let mut context = DiagnosticContext::new();
                context.insert(
                    "signature_id".to_owned(),
                    DiagnosticValue::String(signature.signature_id().to_owned()),
                );
                diagnostics.push(ARTIFACT_PROTECTION_LEDGER_GAP.instantiate(context));
                continue;
            }
            let signal = if signature.marker_spec().is_some() {
                marker_locations
                    .get(signature.signature_id())
                    .filter(|locations| !locations.is_empty())
                    .map(|locations| ProtectionSignalEvidence {
                        signature_id: signature.signature_id().to_owned(),
                        signal_class: format!("{:?}", signature.signal_class())
                            .to_ascii_lowercase(),
                        strength_basis_points: signature.strength_basis_points(),
                        locations: locations.clone(),
                    })
            } else {
                signature.detect(&corpus)
            };
            if let Some(signal) = signal {
                signals.push(RawSignal {
                    signature_id: signal.signature_id,
                    class: signature.signal_class(),
                    strength: signal.strength_basis_points,
                    locations: signal.locations,
                });
            }
        }

        let feature_started = Instant::now();
        let features = feature_vector(&corpus);
        profile_protection("feature_vector", feature_started, String::new());
        let manifest_started = Instant::now();
        let thin_or_gap = features.code_coverage_basis_points < 5_000 || manifest_gap(&corpus);
        profile_protection("manifest_gap", manifest_started, String::new());
        let mut failures = failures;
        failures.extend(corpus.failures());
        if !failures.is_empty() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "locations".to_owned(),
                DiagnosticValue::StringList(failures),
            );
            diagnostics.push(ARTIFACT_PROTECTION_DETECTOR_UNAVAILABLE.instantiate(context));
        }
        let opaque_or_loader = signals.iter().any(|signal| {
            matches!(
                signal.class,
                SignalClass::OpaquePayload | SignalClass::DynamicLoader | SignalClass::NativeLoader
            ) || (signal.class == SignalClass::ProtectorMarker
                && signal.locations.iter().any(|location| {
                    let lower = location.to_ascii_lowercase();
                    is_shared_object_path(&lower)
                        || lower.contains("/lib/")
                        || lower.contains("\\lib\\")
                }))
        });
        let orthogonal_gate_satisfied = thin_or_gap && opaque_or_loader;
        let compiler_marker = signals
            .iter()
            .any(|signal| signal.signature_id == "r8.compiler-marker");
        let packer_marker = signals
            .iter()
            .any(|signal| signal.class == SignalClass::ProtectorMarker);
        let named_identity = if packer_marker && orthogonal_gate_satisfied {
            signals
                .iter()
                .find(|signal| signal.class == SignalClass::ProtectorMarker)
                .map(|signal| identity_for(&signal.signature_id))
        } else {
            None
        };
        let statistical_stock = !compiler_marker
            && !packer_marker
            && features.identifier_minification_basis_points >= 7_000
            && features.control_flow_complexity_basis_points <= 5_000
            && features.reflection_density_basis_points <= 2_500;
        let identity = named_identity.clone().or_else(|| {
            (compiler_marker || statistical_stock).then(|| "stock-r8-proguard".to_owned())
        });
        let tier = if named_identity.is_some() {
            ProtectionTier::Tier4Packed
        } else if compiler_marker || statistical_stock {
            ProtectionTier::Tier1StockR8
        } else if features.native_boundary_basis_points > 3_500
            || features.control_flow_complexity_basis_points > 5_500
            || features.reflection_density_basis_points > 4_500
            || features.packing_rasp_basis_points > 3_500
        {
            ProtectionTier::Tier3HeavyCfgNative
        } else if features.identifier_minification_basis_points > 3_500
            || features.string_entropy_basis_points > 3_500
        {
            ProtectionTier::Tier2Obfuscated
        } else {
            ProtectionTier::Tier0Unprotected
        };
        let suspected = (packer_marker && !orthogonal_gate_satisfied)
            || (!signals.is_empty()
                && identity.is_none()
                && tier == ProtectionTier::Tier0Unprotected);
        if identity.is_some() {
            let mut context = DiagnosticContext::new();
            context.insert(
                "identity".to_owned(),
                DiagnosticValue::String(identity.clone().unwrap_or_default()),
            );
            context.insert(
                "tier".to_owned(),
                DiagnosticValue::String(format!("{tier:?}").to_ascii_lowercase()),
            );
            diagnostics.push(ARTIFACT_PROTECTION_DETECTED.instantiate(context));
        }
        if suspected {
            diagnostics.push(ARTIFACT_PROTECTION_SUSPECTED.instantiate(DiagnosticContext::new()));
        }
        if tier >= ProtectionTier::Tier3HeavyCfgNative {
            diagnostics.push(ARTIFACT_PROTECTION_HEAVY.instantiate(DiagnosticContext::new()));
        }
        let detection_confidence = if named_identity.is_some() {
            9_000
        } else if compiler_marker {
            9_500
        } else if statistical_stock {
            6_500
        } else if suspected {
            4_500
        } else if tier == ProtectionTier::Tier0Unprotected {
            9_000
        } else {
            6_000
        };
        let mut signature_names = signals
            .iter()
            .map(|signal| signal.signature_id.clone())
            .collect::<Vec<_>>();
        if suspected {
            signature_names.push("suspected:orthogonal-protection".to_owned());
        }
        if statistical_stock {
            signature_names.push("statistical:stock-r8-proguard".to_owned());
        }
        signature_names.sort();
        signature_names.dedup();
        let profile = ProtectionProfile {
            schema_version: 1,
            identity,
            tier,
            detection_confidence_basis_points: detection_confidence,
            recoverability: features,
            signals: signals
                .into_iter()
                .map(|signal| ProtectionSignalEvidence {
                    signature_id: signal.signature_id,
                    signal_class: format!("{:?}", signal.class).to_ascii_lowercase(),
                    strength_basis_points: signal.strength,
                    locations: signal.locations,
                })
                .collect(),
            orthogonal_gate_satisfied,
        };
        profile_protection(
            "detection_complete",
            started,
            format!("signals={} tier={tier:?}", profile.signals.len()),
        );
        ProtectionDetection {
            metadata: ProtectionMetadata {
                detector: "apiaxess.protection-detector".to_owned(),
                detector_version: Some(DETECTOR_VERSION.to_owned()),
                distribution_posture: "Apache-2.0-clean-room".to_owned(),
                signatures: signature_names,
                handled: true,
                profile: Some(profile),
            },
            diagnostics,
        }
    }
}

fn profile_protection(stage: &str, started: Instant, detail: impl std::fmt::Display) {
    if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
        eprintln!(
            "STATIC PROTECTION PROFILE: stage={stage} elapsed_ms={} {detail}",
            started.elapsed().as_millis()
        );
    }
}

/// Detector output consumed by artifact intake.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectionDetection {
    /// Normalized protection metadata.
    pub metadata: ProtectionMetadata,
    /// Structured detector diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

fn identity_for(signature_id: &str) -> String {
    match signature_id {
        "jiagu.native-loader" => "360-jiagu",
        "legu.native-loader" => "tencent-legu",
        "bangcle.native-loader" => "bangcle-secshell",
        "aliprotect.native-loader" => "alibaba-aliprotect",
        "ijiami.native-loader" => "ijiami",
        "dexprotector.native-loader" => "dexprotector",
        "baidu.native-loader" => "baidu-protect",
        _ => "unknown-protection",
    }
    .to_owned()
}

fn add_path(corpus: &mut ProtectionCorpus, path: &Path, failures: &mut Vec<String>) {
    if path.is_file() {
        corpus.documents.push(ProtectionDocument {
            path: path.display().to_string(),
            source: ProtectionSource::File,
        });
    } else if path.is_dir() {
        let Ok(entries) = fs::read_dir(path) else {
            failures.push(path.display().to_string());
            return;
        };
        for entry in entries.flatten() {
            add_path(corpus, &entry.path(), failures);
        }
    }
}

fn feature_vector(corpus: &ProtectionCorpus) -> RecoverabilityFeatureVector {
    let mut visible = 0_usize;
    let mut declared = 0_usize;
    let mut identifiers = 0_usize;
    let mut short_identifiers = 0_usize;
    let mut entropy_files = 0_usize;
    let mut branches = 0_usize;
    let mut reflection_count = 0_usize;
    let mut native_count = 0_usize;
    let mut rasp_count = 0_usize;
    corpus.for_each_bytes(|document, bytes| {
        let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        visible = visible
            .saturating_add(text.matches(".class").count())
            .saturating_add(text.matches(".method").count());
        declared = declared.saturating_add(text.matches("android:name=").count());
        identifiers =
            identifiers.saturating_add(text.lines().filter(|line| line.contains(".class")).count());
        short_identifiers = short_identifiers.saturating_add(
            text.lines()
                .filter(|line| {
                    line.contains(".class")
                        && line
                            .split('/')
                            .next_back()
                            .is_some_and(|name| name.trim_matches(';').len() <= 3)
                })
                .count(),
        );
        entropy_files = entropy_files.saturating_add(usize::from(entropy(bytes) > 7.0));
        branches = branches.saturating_add(
            ["if-", "goto", "packed-switch", "sparse-switch", ".catch"]
                .iter()
                .map(|token| text.matches(token).count())
                .sum::<usize>(),
        );
        reflection_count = reflection_count.saturating_add(
            [
                "class.forname",
                "method.invoke",
                "getdeclared",
                "reflect",
                "dexclassloader",
            ]
            .iter()
            .map(|token| text.matches(token).count())
            .sum::<usize>(),
        );
        let path = document.path.to_ascii_lowercase();
        native_count = native_count
            .saturating_add(usize::from(
                path.contains("/lib/") || path.contains("\\lib\\") || is_shared_object_path(&path),
            ))
            .saturating_add(text.matches("loadlibrary").count());
        rasp_count = rasp_count.saturating_add(
            [
                "ptrace",
                "integrity",
                "tamper",
                "anti-debug",
                "root",
                "emulator",
            ]
            .iter()
            .map(|token| text.matches(token).count())
            .sum::<usize>(),
        );
    });
    let code_coverage = if declared == 0 {
        10_000
    } else {
        ratio_bp(visible, declared)
    };
    let minification = ratio_bp(short_identifiers, identifiers.max(1));
    let entropy_density = ratio_bp(entropy_files, corpus.documents.len().max(1));
    let cfg = (branches.saturating_mul(1_000) / visible.max(1)).min(10_000);
    let reflection = (reflection_count.saturating_mul(1_000) / visible.max(1)).min(10_000);
    let native = ratio_bp(native_count, corpus.documents.len().saturating_add(1));
    let rasp = (rasp_count.saturating_mul(1_500)).min(10_000);
    RecoverabilityFeatureVector {
        code_coverage_basis_points: code_coverage,
        identifier_minification_basis_points: minification,
        string_entropy_basis_points: entropy_density,
        control_flow_complexity_basis_points: u16::try_from(cfg).unwrap_or(10_000),
        reflection_density_basis_points: u16::try_from(reflection).unwrap_or(10_000),
        native_boundary_basis_points: native,
        packing_rasp_basis_points: u16::try_from(rasp).unwrap_or(10_000),
    }
}

fn manifest_gap(corpus: &ProtectionCorpus) -> bool {
    let mut names = Vec::new();
    corpus.for_each_bytes(|document, bytes| {
        if !document.path.contains("AndroidManifest") {
            return;
        }
        names.extend(
            String::from_utf8_lossy(bytes)
                .split("android:name=")
                .skip(1)
                .filter_map(|value| value.split(['"', '\'']).next().map(str::to_owned))
                .filter(|name| !name.is_empty()),
        );
    });
    if names.is_empty() {
        return false;
    }
    let mut missing = names
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    corpus.for_each_bytes(|document, bytes| {
        if missing.is_empty() {
            return;
        }
        let path = document.path.to_ascii_lowercase();
        let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        missing.retain(|name| !path.contains(name) && !text.contains(name));
    });
    !missing.is_empty()
}

fn ratio_bp(numerator: usize, denominator: usize) -> u16 {
    if denominator == 0 {
        return 0;
    }
    u16::try_from((numerator.saturating_mul(10_000) / denominator).min(10_000)).unwrap_or(10_000)
}

fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[usize::from(*byte)] += 1;
    }
    let length = f64::from(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = f64::from(u32::try_from(*count).unwrap_or(u32::MAX)) / length;
            -probability * probability.log2()
        })
        .sum()
}

fn is_shared_object_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == "so")
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_artifact_intake::{
        ArtifactFormat, DexAccess, InstallableApk, ProtectionMetadata, StructuralOutput,
    };
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn artifact(source: &str, marker_name: &str) -> NormalizedUnpackedArtifact {
        // Parallel tests can read the same coarse clock tick (notably on
        // Windows), so a per-call counter keeps each fixture root private.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "apiaxess-protection-test-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let smali = root.join("smali");
        let res = root.join("res");
        let assets = root.join("assets");
        let manifest = root.join("AndroidManifest.xml");
        fs::create_dir_all(&smali).unwrap();
        fs::create_dir_all(&res).unwrap();
        fs::create_dir_all(&assets).unwrap();
        fs::write(smali.join("Stub.smali"), source).unwrap();
        fs::write(
            &manifest,
            format!("android:name=\"{marker_name}\"\nandroid:name=\"missing.Real\"\n"),
        )
        .unwrap();
        NormalizedUnpackedArtifact {
            schema_version: 1,
            target_type_id: "apk".to_owned(),
            workspace_root: root.display().to_string(),
            input_format: ArtifactFormat::Apk,
            raw_archives: Vec::new(),
            static_archives: Vec::new(),
            installable_apks: vec![InstallableApk {
                id: "base".to_owned(),
                path: "base.apk".to_owned(),
                is_base: true,
            }],
            structural_outputs: vec![StructuralOutput {
                apk_id: "base".to_owned(),
                manifest: manifest.display().to_string(),
                smali_roots: vec![smali.display().to_string()],
                resource_root: res.display().to_string(),
                asset_root: assets.display().to_string(),
            }],
            dex_access: DexAccess {
                dex_files: Vec::new(),
                parser_handoff: "test".to_owned(),
                capabilities: Vec::new(),
            },
            decompiled_source_roots: Vec::new(),
            protection: ProtectionMetadata {
                detector: "fixture".to_owned(),
                detector_version: None,
                distribution_posture: "fixture".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn requires_orthogonal_evidence_for_named_packer() {
        let weak = artifact(
            ".class public Lx/A;\nconst-string v0, \"libjiagu.so\"",
            "x.A",
        );
        let result = ProtectionDetector::default().detect(&weak);
        assert_eq!(result.metadata.profile.as_ref().unwrap().identity, None);
        assert!(
            result
                .metadata
                .signatures
                .iter()
                .any(|signature| signature.starts_with("suspected:"))
        );
    }

    #[test]
    fn compiler_marker_and_loader_evidence_produce_quantified_tier() {
        let strong = artifact(
            ".class public Lx/A;\nconst-string v0, \"~~R8{8.3.0}\"\ninvoke-static {}, Ldalvik/system/DexClassLoader;",
            "x.A",
        );
        let result = ProtectionDetector::default().detect(&strong);
        let profile = result.metadata.profile.unwrap();
        assert_eq!(profile.tier, ProtectionTier::Tier1StockR8);
        assert!(profile.detection_confidence_basis_points > 8_000);
        assert!(profile.recoverability.code_coverage_basis_points <= 10_000);
    }

    #[test]
    fn checked_in_feeder_fixture_is_a_reproducible_unpacked_negative_control() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root")
            .join("fixtures/capstone/feeder-2.22.0-4050.apk");
        assert!(
            fixture.is_file(),
            "missing checked-in fixture: {}",
            fixture.display()
        );
        let static_archive =
            apiaxess_artifact_intake::index_static_archive(&fixture).expect("index Feeder fixture");
        let artifact = NormalizedUnpackedArtifact {
            schema_version: 1,
            target_type_id: "apk".to_owned(),
            workspace_root: fixture
                .parent()
                .expect("fixture parent")
                .display()
                .to_string(),
            input_format: ArtifactFormat::Apk,
            raw_archives: Vec::new(),
            static_archives: vec![static_archive],
            installable_apks: vec![InstallableApk {
                id: "base".to_owned(),
                path: fixture.display().to_string(),
                is_base: true,
            }],
            structural_outputs: Vec::new(),
            dex_access: DexAccess {
                dex_files: Vec::new(),
                parser_handoff: "negative-control-test".to_owned(),
                capabilities: Vec::new(),
            },
            decompiled_source_roots: Vec::new(),
            protection: ProtectionMetadata {
                detector: "fixture".to_owned(),
                detector_version: None,
                distribution_posture: "fixture".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance: Vec::new(),
            diagnostics: Vec::new(),
        };

        // This exercises the real large-corpus scan path (5678 archive members),
        // the measured intake hotspot. Before the single-pass marker scan this
        // detect() took ~70s (marker scan alone ~56s of per-needle passes); it is
        // now single-pass. A generous bound locks the fix so an accidental return
        // to per-needle scanning (which would push this back toward a minute)
        // fails loudly instead of silently regressing intake time.
        let scan_started = Instant::now();
        let result = ProtectionDetector::default().detect(&artifact);
        let scan_elapsed = scan_started.elapsed();
        assert!(
            scan_elapsed.as_secs() < 40,
            "protection scan of the Feeder corpus took {}s; expected well under 40s (single-pass marker scan). A regression to per-needle scanning is the likely cause.",
            scan_elapsed.as_secs()
        );
        let profile = result.metadata.profile.expect("detector profile");
        let named_signatures = [
            "jiagu.native-loader",
            "legu.native-loader",
            "bangcle.native-loader",
            "aliprotect.native-loader",
            "ijiami.native-loader",
            "dexprotector.native-loader",
            "baidu.native-loader",
        ];
        assert!(
            profile
                .signals
                .iter()
                .all(|signal| !named_signatures.contains(&signal.signature_id.as_str())),
            "Feeder unexpectedly matched a named commercial packer: {:?}",
            profile.signals
        );
        assert!(
            profile.identity.as_deref() != Some("360-jiagu")
                && profile.identity.as_deref() != Some("tencent-legu")
                && profile.identity.as_deref() != Some("bangcle-secshell")
                && profile.identity.as_deref() != Some("alibaba-aliprotect")
                && profile.identity.as_deref() != Some("ijiami")
                && profile.identity.as_deref() != Some("dexprotector")
                && profile.identity.as_deref() != Some("baidu-protect"),
            "Feeder unexpectedly received a named commercial-packer identity: {:?}",
            profile.identity
        );
        println!(
            "Feeder negative control: tier={:?}, identity={:?}, signatures={:?}, signals={:?}",
            profile.tier, profile.identity, result.metadata.signatures, profile.signals
        );
    }
}
