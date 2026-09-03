//! Phase 1.2 networking detection and localization.
//!
//! The router never extracts endpoint, parameter, payload, or schema values.
//! It produces locations and expectations for Phase 1.3. Each supported
//! library is a protocol-decoder detector implementation behind the same
//! registry seam, so community decoders do not require a central match block.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufReader, Read},
    path::Path,
    time::Instant,
};

use aho_corasick::AhoCorasickBuilder;
use apiaxess_artifact_intake::{NormalizedUnpackedArtifact, ProtectionMetadata};
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        NETWORKING_ARTIFACT_LOCATION_UNAVAILABLE, NETWORKING_PROTECTION_OBSCURES_MAP,
        NETWORKING_SIGNATURE_AMBIGUOUS, NETWORKING_USAGE_UNIDENTIFIED,
    },
};
use serde::{Deserialize, Serialize};
use zip::ZipArchive;

/// Version of the routed detection-map handoff.
pub const ROUTED_DETECTION_MAP_SCHEMA_VERSION: u32 = 1;

/// Stable plugin-kind label from the Phase 0 contract.
pub const PROTOCOL_DECODER_PLUGIN_KIND: &str = "protocol-decoder";

/// Maximum text retained for one extraction document at a time.
pub const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

const GENERIC_NETWORKING_MARKERS: &[&str] = &[
    "httpurlconnection",
    "java/net/url",
    "java/net/socket",
    "java/nio",
    "okhttp",
    "retrofit",
    "ktor.client",
    "com/android/volley",
    "org/apache/http",
    "cz/msebera/android/httpclient",
    "io/grpc",
    "graphql",
    "apollo",
    "android/webkit/webview",
    "addjavascriptinterface",
];

/// A source form scanned by the router.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Authoritative apktool smali.
    Smali,
    /// Lossy jadx Java source.
    DecompiledSource,
    /// Programmatic DEX access bytes.
    Dex,
    /// Decoded resources or packaged assets.
    ResourcesOrAssets,
}

/// One static signature hit retained as routing evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignatureHit {
    /// File or DEX path containing the marker.
    pub path: String,
    /// Source representation.
    pub source_kind: SourceKind,
    /// One-based line hint when the source is text-like.
    pub line_hint: Option<u32>,
    /// Marker that matched.
    pub marker: String,
}

/// Bounded searchable view of the normalized handoff.
///
/// The corpus retains file metadata only. Signature searches stream one file
/// at a time, and extraction loads only the current matching file.
#[derive(Clone, Debug, Default)]
pub struct SignatureCorpus {
    units: Vec<CorpusDocument>,
    scan_diagnostics: RefCell<Vec<Diagnostic>>,
    scan_diagnostic_keys: RefCell<BTreeSet<String>>,
    hit_cache: RefCell<BTreeMap<String, Vec<SignatureHit>>>,
}

/// One normalized file or DEX document available to extractors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusDocument {
    /// File or DEX path.
    pub path: String,
    /// Source representation.
    pub source_kind: SourceKind,
    source: CorpusSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CorpusSource {
    File,
    Archive {
        archive_path: String,
        member_name: String,
        uncompressed_size: u64,
    },
}

impl CorpusDocument {
    /// Loads one document for bounded extraction.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the source cannot be read, an archive member
    /// cannot be opened, or the bounded extraction limit is exceeded.
    pub fn load_text(&self) -> Result<String, Diagnostic> {
        let bytes = match &self.source {
            CorpusSource::File => read_bounded_file(Path::new(&self.path))?,
            CorpusSource::Archive {
                archive_path,
                member_name,
                uncompressed_size,
            } => read_bounded_archive_member(
                Path::new(archive_path),
                member_name,
                *uncompressed_size,
                &self.path,
            )?,
        };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl SignatureCorpus {
    /// Builds a corpus from every normalized structural location.
    ///
    /// # Errors
    ///
    /// Returns diagnostics for missing normalized locations. Read and size
    /// failures discovered during the later streaming scan are retained on
    /// the returned corpus and surfaced by [`Self::take_scan_diagnostics`].
    #[must_use]
    pub fn from_artifact(artifact: &NormalizedUnpackedArtifact) -> (Self, Vec<Diagnostic>) {
        let mut corpus = Self::default();
        let mut diagnostics = Vec::new();
        let mut paths = BTreeMap::<String, SourceKind>::new();

        let indexed_archives = !artifact.static_archives.is_empty();
        let package_markers = if indexed_archives {
            artifact
                .structural_outputs
                .iter()
                .filter_map(|structure| package_marker_from_manifest(&structure.manifest))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if indexed_archives {
            for archive in &artifact.static_archives {
                for entry in &archive.entries {
                    corpus.units.push(CorpusDocument {
                        path: format!("{}!/{}", archive.archive_path, entry.name),
                        source_kind: archive_source_kind(&entry.name),
                        source: CorpusSource::Archive {
                            archive_path: archive.archive_path.clone(),
                            member_name: entry.name.clone(),
                            uncompressed_size: entry.uncompressed_size,
                        },
                    });
                }
            }
        }

        for structure in &artifact.structural_outputs {
            for path in &structure.smali_roots {
                paths.insert(path.clone(), SourceKind::Smali);
            }
            if !indexed_archives {
                paths.insert(
                    structure.resource_root.clone(),
                    SourceKind::ResourcesOrAssets,
                );
                paths.insert(structure.asset_root.clone(), SourceKind::ResourcesOrAssets);
            }
        }
        for path in &artifact.decompiled_source_roots {
            paths.insert(path.clone(), SourceKind::DecompiledSource);
        }
        // An indexed APK already supplies the DEX bytes in-place. Keep the
        // materialized smali/jadx views as complementary typed evidence when
        // they exist, but do not scan an extracted DEX a second time.
        if !indexed_archives {
            for path in &artifact.dex_access.dex_files {
                paths.insert(path.clone(), SourceKind::Dex);
            }
        }

        for (path, source_kind) in paths {
            // The indexed path is authoritative for archive members. A
            // missing optional exploded view must not turn an otherwise valid
            // archive scan into a false location diagnostic (and is expected
            // in the filesystem-light regression fixture).
            if indexed_archives && !Path::new(&path).exists() {
                continue;
            }
            if let Err(diagnostic) =
                add_path_scoped(&mut corpus, Path::new(&path), source_kind, &package_markers)
            {
                diagnostics.push(diagnostic);
            }
        }
        (corpus, diagnostics)
    }

    /// Returns hits for case-insensitive marker fragments.
    #[must_use]
    pub fn hits_for(&self, markers: &[&str]) -> Vec<SignatureHit> {
        let markers = markers
            .iter()
            .map(|marker| marker.to_ascii_lowercase())
            .collect::<Vec<_>>();
        self.ensure_markers(&markers);
        let cache = self.hit_cache.borrow();
        self.units
            .iter()
            .flat_map(|unit| {
                markers.iter().flat_map(|marker| {
                    cache
                        .get(marker)
                        .into_iter()
                        .flat_map(|hits| hits.iter())
                        .filter(|hit| hit.path == unit.path)
                        .cloned()
                })
            })
            .collect()
    }

    /// Ensures that a group of marker searches is completed in one corpus
    /// pass. Callers that know their detector set up front should prime all
    /// markers together; this avoids reopening every materialized Windows
    /// source file once per detector.
    pub fn warm_markers(&self, markers: &[&str]) {
        let markers = markers
            .iter()
            .map(|marker| marker.to_ascii_lowercase())
            .collect::<Vec<_>>();
        self.ensure_markers(&markers);
    }

    fn ensure_markers(&self, markers: &[String]) {
        let missing = markers
            .iter()
            .filter(|marker| !self.hit_cache.borrow().contains_key(*marker))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            let mut cached = missing
                .iter()
                .map(|marker| (marker.clone(), Vec::new()))
                .collect::<BTreeMap<_, _>>();
            let mut archives = BTreeMap::<String, Vec<&CorpusDocument>>::new();
            let mut scanned_documents = 0usize;
            for unit in &self.units {
                if let CorpusSource::Archive { archive_path, .. } = &unit.source {
                    archives.entry(archive_path.clone()).or_default().push(unit);
                } else {
                    let mut unit_hits = Vec::new();
                    if let Err(diagnostic) = scan_file_for_hits(unit, &missing, &mut unit_hits) {
                        self.record_scan_diagnostic(diagnostic);
                    }
                    for hit in unit_hits {
                        if let Some(hits) = cached.get_mut(&hit.marker) {
                            hits.push(hit);
                        }
                    }
                    scanned_documents = scanned_documents.saturating_add(1);
                    if scanned_documents % 1_000 == 0
                        && std::env::var_os("APIAXESS_PROFILE_STATIC").is_some()
                    {
                        eprintln!(
                            "STATIC ROUTING PROFILE: marker_scan_progress documents={} total={} source=filesystem",
                            scanned_documents,
                            self.units.len()
                        );
                    }
                }
            }
            for (archive_path, units) in archives {
                if let Err(diagnostic) =
                    scan_archive_for_hits(Path::new(&archive_path), &units, &missing, &mut cached)
                {
                    self.record_scan_diagnostic(diagnostic);
                }
                scanned_documents = scanned_documents.saturating_add(units.len());
                if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
                    eprintln!(
                        "STATIC ROUTING PROFILE: marker_scan_progress documents={} total={} source=archive",
                        scanned_documents,
                        self.units.len()
                    );
                }
            }
            self.hit_cache.borrow_mut().extend(cached);
        }
    }

    /// Whether any marker exists in any normalized representation.
    #[must_use]
    pub fn contains_any(&self, markers: &[&str]) -> bool {
        !self.hits_for(markers).is_empty()
    }

    /// Returns all searchable normalized documents.
    #[must_use]
    pub fn documents(&self) -> &[CorpusDocument] {
        &self.units
    }

    /// Whether this corpus includes an indexed archive as its authoritative
    /// binary/string-pool source.
    #[must_use]
    pub fn has_indexed_archives(&self) -> bool {
        self.units
            .iter()
            .any(|document| matches!(&document.source, CorpusSource::Archive { .. }))
    }

    /// Loads one document and records any read or size failure for the final
    /// static-analysis diagnostic roll-up.
    #[must_use]
    pub fn text_for(&self, document: &CorpusDocument) -> Option<String> {
        match document.load_text() {
            Ok(text) => Some(text),
            Err(diagnostic) => {
                self.record_scan_diagnostic(diagnostic);
                None
            }
        }
    }

    /// Visits every searchable document while opening each indexed archive
    /// once. This is the bulk-scan seam used by string-pool extraction.
    pub fn for_each_text(&self, mut visit: impl FnMut(&CorpusDocument, &str)) {
        let mut archives = BTreeMap::<String, Vec<&CorpusDocument>>::new();
        for document in &self.units {
            if let CorpusSource::Archive { archive_path, .. } = &document.source {
                archives
                    .entry(archive_path.clone())
                    .or_default()
                    .push(document);
            } else if let Some(text) = self.text_for(document) {
                visit(document, &text);
            }
        }
        for (archive_path, documents) in archives {
            let file = match File::open(&archive_path) {
                Ok(file) => file,
                Err(error) => {
                    self.record_scan_diagnostic(location_diagnostic(
                        Path::new(&archive_path),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            let mut archive = match ZipArchive::new(file) {
                Ok(archive) => archive,
                Err(error) => {
                    self.record_scan_diagnostic(location_diagnostic(
                        Path::new(&archive_path),
                        error.to_string(),
                    ));
                    continue;
                }
            };
            for document in documents {
                let CorpusSource::Archive {
                    member_name,
                    uncompressed_size,
                    ..
                } = &document.source
                else {
                    continue;
                };
                match read_archive_member_from_open_archive(
                    &mut archive,
                    member_name,
                    *uncompressed_size,
                    &document.path,
                ) {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        visit(document, &text);
                    }
                    Err(diagnostic) => self.record_scan_diagnostic(diagnostic),
                }
            }
        }
    }

    /// Takes diagnostics emitted while streaming or loading corpus members.
    #[must_use]
    pub fn take_scan_diagnostics(&self) -> Vec<Diagnostic> {
        std::mem::take(&mut *self.scan_diagnostics.borrow_mut())
    }

    /// Approximate bytes retained by corpus metadata, excluding the current
    /// bounded scan buffer and any caller-owned hit results.
    #[must_use]
    pub fn retained_metadata_bytes(&self) -> usize {
        self.units
            .iter()
            .map(|document| document.path.capacity() + std::mem::size_of::<CorpusDocument>())
            .sum()
    }

    /// Returns deterministic paths for a set of hits.
    #[must_use]
    pub fn paths_for(hits: &[SignatureHit]) -> Vec<String> {
        let mut paths = hits.iter().map(|hit| hit.path.clone()).collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        paths
    }

    fn record_scan_diagnostic(&self, diagnostic: Diagnostic) {
        let key = diagnostic.to_string();
        let mut keys = self.scan_diagnostic_keys.borrow_mut();
        if keys.insert(key) {
            self.scan_diagnostics.borrow_mut().push(diagnostic);
        }
    }
}

/// Protocol-decoder plugin identity advertised by a detector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecoderDescriptor {
    /// Stable library identity.
    pub library_id: String,
    /// Human-readable library name.
    pub display_name: String,
    /// Stable protocol-decoder plugin ID.
    pub protocol_decoder_id: String,
    /// Protocol-decoder interface version.
    pub protocol_decoder_interface_version: String,
    /// Baseline static recoverability before protection adjustment.
    pub baseline_recoverability_basis_points: u16,
}

/// Detector result before shared protection adjustment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectorObservation {
    /// Detection confidence in basis points.
    pub detection_basis_points: u16,
    /// Signature evidence.
    pub evidence: Vec<SignatureHit>,
    /// Structural locations for Phase 1.3.
    pub locations: Vec<ApiMapLocation>,
    /// Whether extraction is currently supported.
    pub extraction_status: ExtractionStatus,
}

/// Whether Phase 1.3 has an extractor for this detection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionStatus {
    /// Phase 1.3 can select a library-specific extractor.
    Extractable,
    /// Detection is retained, but extraction is deferred.
    DetectedButDeferred,
}

/// Protocol-decoder detector seam.
pub trait ProtocolDecoderDetector: Send + Sync {
    /// Returns the stable plugin identity and recoverability baseline.
    fn descriptor(&self) -> DecoderDescriptor;

    /// Marker set used by this detector, for one-pass corpus priming.
    fn marker_hints(&self) -> &'static [&'static str] {
        &[]
    }

    /// Detects and localizes this library without extracting API values.
    fn detect(&self, corpus: &SignatureCorpus) -> Option<DetectorObservation>;
}

/// Location kind understood by Phase 1.3 extractors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiMapLocationKind {
    /// Retrofit-style interface method annotation tables.
    DexAnnotationTables,
    /// URL/path/header builder call sites.
    BuilderCallSites,
    /// Request constructor argument sites.
    RequestConstructorArguments,
    /// Generated gRPC service stubs and descriptors.
    GeneratedServiceStubs,
    /// Generated GraphQL operation classes and assets.
    GeneratedGraphQlOperations,
    /// `WebView` bridge and JavaScript asset locations.
    WebViewJsBridge,
    /// Raw connection or socket call sites.
    RawTransportCallSites,
}

/// A structural pointer for a future extractor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApiMapLocation {
    /// Representation containing the location.
    pub source_kind: SourceKind,
    /// Tool provenance inherited from the normalized 1.1 handoff.
    pub source_tool: String,
    /// Path inside the normalized handoff workspace.
    pub path: String,
    /// Semantic location kind.
    pub kind: ApiMapLocationKind,
    /// Line hints or semantic selectors; these are not extracted values.
    pub selectors: Vec<String>,
    /// Why this is the right place for the library extractor to inspect.
    pub notes: String,
    /// Candidate line hints for prioritization.
    pub line_hints: Vec<u32>,
}

/// Protection-adjusted static recoverability expectation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoverabilityExpectation {
    /// Library baseline before protection adjustment.
    pub baseline_basis_points: u16,
    /// Adjusted expectation for this artifact.
    pub adjusted_basis_points: u16,
    /// Basis-point penalty applied for protection.
    pub protection_penalty_basis_points: u16,
    /// Human-readable rationale for the honesty layer.
    pub rationale: String,
}

/// One detected networking library and its Phase 1.3 handoff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LibraryDetection {
    /// Stable library identity.
    pub library_id: String,
    /// Human-readable library name.
    pub display_name: String,
    /// Phase 0 protocol-decoder plugin kind.
    pub plugin_kind: String,
    /// Stable protocol-decoder plugin ID.
    pub protocol_decoder_id: String,
    /// Protocol-decoder interface version.
    pub protocol_decoder_interface_version: String,
    /// Confidence that this library is present.
    pub detection_basis_points: u16,
    /// Static signature evidence.
    pub evidence: Vec<SignatureHit>,
    /// Where the extractor should look.
    pub api_map_locations: Vec<ApiMapLocation>,
    /// Current Phase 1.3 support state.
    pub extraction_status: ExtractionStatus,
    /// Protection-aware expectation.
    pub recoverability: RecoverabilityExpectation,
}

/// Networking was present but no detector could identify the implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnidentifiedNetworkingObservation {
    /// Generic networking signature evidence.
    pub evidence: Vec<SignatureHit>,
    /// Dynamic or plugin-based next step.
    pub recommended_next_step: String,
}

/// Routed detection-map handoff to Phase 1.3.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoutedDetectionMap {
    /// Handoff schema version.
    pub schema_version: u32,
    /// Source normalized artifact schema version.
    pub source_artifact_schema_version: u32,
    /// Target seam ID.
    pub target_type_id: String,
    /// Whether any networking signature was found.
    pub networking_present: bool,
    /// Detected libraries, including deferred detections.
    pub detections: Vec<LibraryDetection>,
    /// Unidentified networking observations.
    pub unidentified: Vec<UnidentifiedNetworkingObservation>,
    /// Warnings and structural diagnostics retained with the map.
    pub diagnostics: Vec<Diagnostic>,
}

/// Extensible detector registry.
pub struct NetworkingRouter {
    detectors: Vec<Box<dyn ProtocolDecoderDetector>>,
}

impl std::fmt::Debug for NetworkingRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkingRouter")
            .field("detector_count", &self.detectors.len())
            .finish()
    }
}

impl Default for NetworkingRouter {
    fn default() -> Self {
        Self::with_detectors(builtin_detectors())
    }
}

impl NetworkingRouter {
    /// Creates a router from sibling protocol-decoder implementations.
    #[must_use]
    pub fn with_detectors(detectors: Vec<Box<dyn ProtocolDecoderDetector>>) -> Self {
        Self { detectors }
    }

    /// Routes an unpacked artifact without extracting endpoint or parameter values.
    #[must_use]
    pub fn route(&self, artifact: &NormalizedUnpackedArtifact) -> RoutedDetectionMap {
        let routing_started = Instant::now();
        let (corpus, mut diagnostics) = SignatureCorpus::from_artifact(artifact);
        profile_routing(
            "corpus_built",
            routing_started,
            format!("documents={}", corpus.documents().len()),
        );
        let mut marker_hints = GENERIC_NETWORKING_MARKERS.to_vec();
        marker_hints.extend(
            self.detectors
                .iter()
                .flat_map(|detector| detector.marker_hints().iter().copied()),
        );
        let stage_started = Instant::now();
        corpus.warm_markers(&marker_hints);
        profile_routing(
            "marker_corpus_prime",
            stage_started,
            format!("markers={}", marker_hints.len()),
        );
        let stage_started = Instant::now();
        let networking_evidence = generic_networking_hits(&corpus);
        let networking_present = !networking_evidence.is_empty();
        profile_routing(
            "generic_networking_scan",
            stage_started,
            format!("hits={}", networking_evidence.len()),
        );
        let mut detections = Vec::new();

        for detector in &self.detectors {
            let detector_started = Instant::now();
            if let Some(observation) = detector.detect(&corpus) {
                let descriptor = detector.descriptor();
                let descriptor_id = descriptor.library_id.clone();
                let recoverability = adjust_recoverability(
                    descriptor.baseline_recoverability_basis_points,
                    &artifact.protection,
                );
                if observation.locations.is_empty() {
                    diagnostics.push(signature_ambiguous(&descriptor, &observation.evidence));
                }
                detections.push(LibraryDetection {
                    library_id: descriptor.library_id,
                    display_name: descriptor.display_name,
                    plugin_kind: PROTOCOL_DECODER_PLUGIN_KIND.to_owned(),
                    protocol_decoder_id: descriptor.protocol_decoder_id,
                    protocol_decoder_interface_version: descriptor
                        .protocol_decoder_interface_version,
                    detection_basis_points: observation.detection_basis_points,
                    evidence: observation.evidence,
                    api_map_locations: observation.locations,
                    extraction_status: observation.extraction_status,
                    recoverability,
                });
                profile_routing(
                    "detector",
                    detector_started,
                    format!("id={descriptor_id} matched=true"),
                );
            } else {
                profile_routing("detector", detector_started, "matched=false".to_owned());
            }
        }

        let unidentified = if networking_present && detections.is_empty() {
            let evidence = networking_evidence;
            diagnostics.push(unidentified_diagnostic(&evidence));
            vec![UnidentifiedNetworkingObservation {
                evidence,
                recommended_next_step:
                    "Use dynamic capture or install a community protocol-decoder plugin.".to_owned(),
            }]
        } else {
            Vec::new()
        };

        if networking_present && protection_obscures_networking(&artifact.protection) {
            diagnostics.push(protection_diagnostic(&artifact.protection));
        }
        diagnostics.extend(corpus.take_scan_diagnostics());
        profile_routing(
            "route_complete",
            routing_started,
            format!(
                "detections={} diagnostics={}",
                detections.len(),
                diagnostics.len()
            ),
        );

        RoutedDetectionMap {
            schema_version: ROUTED_DETECTION_MAP_SCHEMA_VERSION,
            source_artifact_schema_version: artifact.schema_version,
            target_type_id: artifact.target_type_id.clone(),
            networking_present,
            detections,
            unidentified,
            diagnostics,
        }
    }
}

fn profile_routing(stage: &str, started: Instant, detail: impl std::fmt::Display) {
    if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
        eprintln!(
            "STATIC ROUTING PROFILE: stage={stage} elapsed_ms={} {detail}",
            started.elapsed().as_millis()
        );
    }
}

fn builtin_detectors() -> Vec<Box<dyn ProtocolDecoderDetector>> {
    vec![
        Box::new(RetrofitDetector),
        Box::new(OkHttpDetector),
        Box::new(KtorDetector),
        Box::new(VolleyDetector),
        Box::new(ApacheHttpClientDetector),
        Box::new(HttpUrlConnectionDetector),
        Box::new(RawSocketDetector),
        Box::new(GrpcDetector),
        Box::new(ApolloDetector),
        Box::new(WebViewDetector),
    ]
}

struct RetrofitDetector;
struct OkHttpDetector;
struct KtorDetector;
struct VolleyDetector;
struct ApacheHttpClientDetector;
struct HttpUrlConnectionDetector;
struct RawSocketDetector;
struct GrpcDetector;
struct ApolloDetector;
struct WebViewDetector;

fn descriptor(
    library_id: &str,
    display_name: &str,
    protocol_decoder_id: &str,
    baseline_recoverability_basis_points: u16,
) -> DecoderDescriptor {
    DecoderDescriptor {
        library_id: library_id.to_owned(),
        display_name: display_name.to_owned(),
        protocol_decoder_id: protocol_decoder_id.to_owned(),
        protocol_decoder_interface_version: "1.0".to_owned(),
        baseline_recoverability_basis_points,
    }
}

macro_rules! detector_impl {
    ($type:ty, $id:literal, $name:literal, $decoder:literal, $baseline:expr, $markers:expr, $kind:expr, $selectors:expr, $notes:literal, $status:expr, $confidence:expr) => {
        impl ProtocolDecoderDetector for $type {
            fn descriptor(&self) -> DecoderDescriptor {
                descriptor($id, $name, $decoder, $baseline)
            }

            fn marker_hints(&self) -> &'static [&'static str] {
                $markers
            }

            fn detect(&self, corpus: &SignatureCorpus) -> Option<DetectorObservation> {
                let evidence = corpus.hits_for($markers);
                (!evidence.is_empty()).then(|| DetectorObservation {
                    detection_basis_points: $confidence,
                    evidence: evidence.clone(),
                    locations: locations_for(&evidence, $kind, $selectors, $notes),
                    extraction_status: $status,
                })
            }
        }
    };
}

detector_impl!(
    RetrofitDetector,
    "retrofit",
    "Retrofit",
    "retrofit",
    9300,
    &[
        "retrofit2/",
        "retrofit2.http",
        "retrofit2/retrofit",
        // R8 can rename the Retrofit annotation types.  The bounded extractor
        // subsequently requires an interface-attached, known annotation shape
        // before it emits a route, so this only supplies routing locality.
        "\"api/v",
        "\"oauth/",
    ],
    ApiMapLocationKind::DexAnnotationTables,
    &[
        "interface method annotations",
        "retrofit2.http.* annotations",
        "method parameter annotations"
    ],
    "Read DEX annotation tables on Retrofit service interfaces and methods.",
    ExtractionStatus::Extractable,
    9800
);
detector_impl!(
    OkHttpDetector,
    "okhttp",
    "OkHttp",
    "okhttp",
    7200,
    &[
        "okhttp3/",
        "okhttp3.okhttpclient",
        "request$builder",
        ".url(",
        "addpathsegment"
    ],
    ApiMapLocationKind::BuilderCallSites,
    &[
        "OkHttpClient construction",
        "Request.Builder call sites",
        ".url()",
        ".addPathSegment()"
    ],
    "Read builder call sites; endpoint values are intentionally left for Phase 1.3.",
    ExtractionStatus::Extractable,
    9500
);
detector_impl!(
    KtorDetector,
    "ktor-client",
    "Ktor client",
    "ktor-client",
    9250,
    &[
        "io/ktor/client/",
        "io.ktor.client.",
        "io/ktor/http/",
        "io/ktor/resources",
        "io.ktor.resources",
    ],
    ApiMapLocationKind::BuilderCallSites,
    &[
        "HttpClient configuration",
        "request builders",
        "io.ktor.resources"
    ],
    "Read Ktor client request builders and typed resource declarations.",
    ExtractionStatus::Extractable,
    9500
);
detector_impl!(
    VolleyDetector,
    "volley",
    "Volley",
    "volley",
    7200,
    &[
        "com/android/volley/",
        "com.android.volley.",
        "stringrequest",
        "jsonobjectrequest"
    ],
    ApiMapLocationKind::RequestConstructorArguments,
    &[
        "Request constructors",
        "StringRequest",
        "JsonObjectRequest",
        "RequestQueue.add"
    ],
    "Read Volley request constructor and queue call sites.",
    ExtractionStatus::Extractable,
    9300
);
detector_impl!(
    ApacheHttpClientDetector,
    "apache-httpclient",
    "Apache HttpClient",
    "apache-httpclient",
    7000,
    &[
        "org/apache/http/",
        "org.apache.http.",
        "cz/msebera/android/httpclient",
        "cz.msebera.android.httpclient"
    ],
    ApiMapLocationKind::BuilderCallSites,
    &[
        "HttpUriRequest constructors",
        "HttpHost",
        "HttpClient.execute call sites"
    ],
    "Read Apache or repackaged cz.msebera request construction and execute sites.",
    ExtractionStatus::Extractable,
    9000
);
detector_impl!(
    HttpUrlConnectionDetector,
    "httpurlconnection",
    "HttpURLConnection",
    "httpurlconnection",
    2500,
    &[
        "java/net/httpurlconnection",
        "java.net.httpurlconnection",
        "url.openconnection",
        "java/net/urlconnection"
    ],
    ApiMapLocationKind::RawTransportCallSites,
    &[
        "URL.openConnection()",
        "HttpURLConnection methods",
        "URLConnection call sites"
    ],
    "Read raw URL-connection call sites; dynamic composition sharply limits static completeness.",
    ExtractionStatus::Extractable,
    8500
);
detector_impl!(
    RawSocketDetector,
    "raw-sockets",
    "Raw sockets",
    "raw-sockets",
    2500,
    &[
        "java/net/socket",
        "java.net.socket",
        "serversocket",
        "socketchannel",
        "datagramsocket",
        "datagram socket"
    ],
    ApiMapLocationKind::RawTransportCallSites,
    &[
        "Socket constructors",
        "SocketChannel",
        "DatagramSocket",
        "read/write call sites"
    ],
    "Raw socket protocol interpretation is deferred; retain locations for honesty and dynamic capture planning.",
    ExtractionStatus::DetectedButDeferred,
    8500
);
detector_impl!(
    GrpcDetector,
    "grpc-java",
    "gRPC Java",
    "grpc-java",
    8750,
    &[
        "io/grpc/managedchannelbuilder",
        "io.grpc.managedchannelbuilder",
        "grpc.stub",
        "generatefullmethodname",
        "grpc/",
        "grpc.",
        "grpc;"
    ],
    ApiMapLocationKind::GeneratedServiceStubs,
    &[
        "ManagedChannelBuilder",
        "generated *Grpc stubs",
        "protobuf descriptors"
    ],
    "Read generated service stubs and protobuf descriptor locations.",
    ExtractionStatus::Extractable,
    9400
);
detector_impl!(
    ApolloDetector,
    "graphql-apollo",
    "GraphQL/Apollo",
    "graphql-apollo",
    8750,
    &[
        "com/apollographql/apollo",
        "com.apollographql.apollo",
        "apollo3",
        "apolloquery",
        "apollomutation",
        "graphql"
    ],
    ApiMapLocationKind::GeneratedGraphQlOperations,
    &[
        "ApolloClient",
        "generated *Query",
        "generated *Mutation",
        "GraphQL assets"
    ],
    "Read generated operation classes and packaged GraphQL assets.",
    ExtractionStatus::Extractable,
    9300
);
detector_impl!(
    WebViewDetector,
    "webview-js-bridge",
    "WebView/JS bridge networking",
    "webview-js-bridge",
    5500,
    &[
        "android/webkit/webview",
        "android.webkit.webview",
        "addjavascriptinterface",
        "evaluatejavascript",
        "webview.loadurl"
    ],
    ApiMapLocationKind::WebViewJsBridge,
    &[
        "WebView",
        "addJavascriptInterface",
        "evaluateJavascript",
        "loadUrl",
        "JS assets"
    ],
    "Read WebView bridge call sites plus JavaScript and packaged asset roots.",
    ExtractionStatus::Extractable,
    9000
);

fn locations_for(
    evidence: &[SignatureHit],
    kind: ApiMapLocationKind,
    selectors: &[&str],
    notes: &str,
) -> Vec<ApiMapLocation> {
    let mut grouped = BTreeMap::<(String, SourceKind), (Vec<u32>, Vec<String>)>::new();
    for hit in evidence {
        let entry = grouped
            .entry((hit.path.clone(), hit.source_kind))
            .or_default();
        if let Some(line) = hit.line_hint {
            entry.0.push(line);
        }
        entry.1.push(hit.marker.clone());
    }
    grouped
        .into_iter()
        .map(|((path, source_kind), (mut line_hints, mut markers))| {
            line_hints.sort_unstable();
            line_hints.dedup();
            markers.sort();
            markers.dedup();
            let mut location_selectors = selectors
                .iter()
                .map(|selector| (*selector).to_owned())
                .collect::<Vec<_>>();
            location_selectors.extend(
                markers
                    .into_iter()
                    .map(|marker| format!("signature:{marker}")),
            );
            ApiMapLocation {
                source_kind,
                source_tool: match source_kind {
                    SourceKind::Smali | SourceKind::ResourcesOrAssets => "apktool".to_owned(),
                    SourceKind::DecompiledSource => "jadx".to_owned(),
                    SourceKind::Dex => "android.dex.androguard-or-dexlib2".to_owned(),
                },
                path,
                kind,
                selectors: location_selectors,
                notes: notes.to_owned(),
                line_hints,
            }
        })
        .collect()
}

fn add_path_scoped(
    corpus: &mut SignatureCorpus,
    path: &Path,
    source_kind: SourceKind,
    package_markers: &[String],
) -> Result<(), Diagnostic> {
    if path.is_file() {
        if package_markers.is_empty()
            // Obfuscated apps frequently move the meaningful interface out of
            // the manifest package (for example, Tusky's Retrofit service is
            // emitted by JADX as `hg/c.java`). Smali remains package-scoped
            // because the indexed archive is authoritative for bytecode, but
            // JADX is a complementary, lossier semantic view and must retain
            // those relocated declarations.
            || !matches!(source_kind, SourceKind::Smali)
            || package_markers.iter().any(|marker| {
                let lower = path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .replace('\\', "/");
                lower.contains(&format!("/{marker}/"))
            })
        {
            add_file(corpus, path, source_kind);
        }
        Ok(())
    } else if path.is_dir() {
        if !package_markers.is_empty()
            && matches!(source_kind, SourceKind::Smali)
        {
            let mut found_package_root = false;
            for marker in package_markers {
                let package_path = marker
                    .split('/')
                    .fold(path.to_path_buf(), |root, component| root.join(component));
                if package_path.is_dir() {
                    found_package_root = true;
                    add_path_scoped(corpus, &package_path, source_kind, &[])?;
                }
            }
            if found_package_root {
                return Ok(());
            }
        }
        let entries =
            fs::read_dir(path).map_err(|error| location_diagnostic(path, error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| location_diagnostic(path, error.to_string()))?;
            add_path_scoped(corpus, &entry.path(), source_kind, package_markers)?;
        }
        Ok(())
    } else {
        Err(location_diagnostic(path, "path does not exist".to_owned()))
    }
}

fn package_marker_from_manifest(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let package = text.split("package=\"").nth(1)?.split('"').next()?;
    let marker = package.replace('.', "/").to_ascii_lowercase();
    (!marker.is_empty()).then_some(marker)
}

fn add_file(corpus: &mut SignatureCorpus, path: &Path, source_kind: SourceKind) {
    corpus.units.push(CorpusDocument {
        path: path.display().to_string(),
        source_kind,
        source: CorpusSource::File,
    });
}

fn scan_file_for_hits(
    document: &CorpusDocument,
    markers: &[String],
    hits: &mut Vec<SignatureHit>,
) -> Result<(), Diagnostic> {
    if markers.is_empty() {
        return Ok(());
    }
    let path = Path::new(&document.path);
    let file = File::open(path).map_err(|error| location_diagnostic(path, error.to_string()))?;
    scan_reader_for_hits(document, BufReader::new(file), markers, hits)
}

fn scan_archive_for_hits(
    archive_path: &Path,
    documents: &[&CorpusDocument],
    markers: &[String],
    cached: &mut BTreeMap<String, Vec<SignatureHit>>,
) -> Result<(), Diagnostic> {
    let file = File::open(archive_path)
        .map_err(|error| location_diagnostic(archive_path, error.to_string()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| location_diagnostic(archive_path, error.to_string()))?;
    for document in documents {
        let CorpusSource::Archive {
            member_name,
            uncompressed_size,
            ..
        } = &document.source
        else {
            continue;
        };
        let entry = archive
            .by_name(member_name)
            .map_err(|error| location_diagnostic(Path::new(&document.path), error.to_string()))?;
        let mut unit_hits = Vec::new();
        scan_reader_for_hits(
            document,
            entry.take(uncompressed_size.saturating_add(1)),
            markers,
            &mut unit_hits,
        )?;
        for hit in unit_hits {
            if let Some(hits) = cached.get_mut(&hit.marker) {
                hits.push(hit);
            }
        }
    }
    Ok(())
}

fn scan_reader_for_hits<R: Read>(
    document: &CorpusDocument,
    mut reader: R,
    markers: &[String],
    hits: &mut Vec<SignatureHit>,
) -> Result<(), Diagnostic> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| location_diagnostic(Path::new(&document.path), error.to_string()))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(location_diagnostic(
            Path::new(&document.path),
            format!("document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes",),
        ));
    }
    bytes.make_ascii_lowercase();
    let matcher = AhoCorasickBuilder::new()
        .build(markers)
        .map_err(|error| location_diagnostic(Path::new(&document.path), error.to_string()))?;
    let mut found = vec![false; markers.len()];
    for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        for matched in matcher.find_overlapping_iter(line) {
            found[matched.pattern().as_usize()] = true;
        }
        emit_line_hits(
            document,
            markers,
            &found,
            u32::try_from(line_index).unwrap_or(u32::MAX),
            hits,
        );
        found.fill(false);
    }
    Ok(())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, Diagnostic> {
    let file = File::open(path).map_err(|error| location_diagnostic(path, error.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| location_diagnostic(path, error.to_string()))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(location_diagnostic(
            path,
            format!("document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes",),
        ));
    }
    Ok(bytes)
}

fn read_bounded_archive_member(
    archive_path: &Path,
    member_name: &str,
    uncompressed_size: u64,
    display_path: &str,
) -> Result<Vec<u8>, Diagnostic> {
    if uncompressed_size > MAX_DOCUMENT_BYTES {
        return Err(location_diagnostic(
            Path::new(display_path),
            format!("document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes",),
        ));
    }
    let file = File::open(archive_path)
        .map_err(|error| location_diagnostic(Path::new(display_path), error.to_string()))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|error| location_diagnostic(Path::new(display_path), error.to_string()))?;
    read_archive_member_from_open_archive(
        &mut archive,
        member_name,
        uncompressed_size,
        display_path,
    )
}

fn read_archive_member_from_open_archive<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    member_name: &str,
    uncompressed_size: u64,
    display_path: &str,
) -> Result<Vec<u8>, Diagnostic> {
    if uncompressed_size > MAX_DOCUMENT_BYTES {
        return Err(location_diagnostic(
            Path::new(display_path),
            format!("document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes",),
        ));
    }
    let entry = archive
        .by_name(member_name)
        .map_err(|error| location_diagnostic(Path::new(display_path), error.to_string()))?;
    let mut bytes = Vec::new();
    entry
        .take(MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| location_diagnostic(Path::new(display_path), error.to_string()))?;
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(location_diagnostic(
            Path::new(display_path),
            format!("document exceeds the bounded extraction window of {MAX_DOCUMENT_BYTES} bytes",),
        ));
    }
    Ok(bytes)
}

// Archive suffix matching intentionally normalizes case before comparison.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn archive_source_kind(name: &str) -> SourceKind {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".smali") {
        SourceKind::Smali
    } else if lower.ends_with(".java") || lower.ends_with(".kt") {
        SourceKind::DecompiledSource
    } else if lower.ends_with(".dex") {
        SourceKind::Dex
    } else if lower == "androidmanifest.xml"
        || lower.starts_with("res/")
        || lower.starts_with("assets/")
        || lower.starts_with("lib/")
    {
        SourceKind::ResourcesOrAssets
    } else {
        // APK members outside the typed buckets are still searchable bytes;
        // classify them as DEX-like programmatic input for marker scanning.
        SourceKind::Dex
    }
}

fn emit_line_hits(
    document: &CorpusDocument,
    markers: &[String],
    found: &[bool],
    line_index: u32,
    hits: &mut Vec<SignatureHit>,
) {
    for (index, marker) in markers.iter().enumerate() {
        if found[index] {
            hits.push(SignatureHit {
                path: document.path.clone(),
                source_kind: document.source_kind,
                line_hint: Some(line_index.saturating_add(1)),
                marker: marker.clone(),
            });
        }
    }
}

fn generic_networking_hits(corpus: &SignatureCorpus) -> Vec<SignatureHit> {
    corpus.hits_for(GENERIC_NETWORKING_MARKERS)
}

fn protection_obscures_networking(protection: &ProtectionMetadata) -> bool {
    if let Some(profile) = &protection.profile {
        return profile.tier >= apiaxess_artifact_intake::ProtectionTier::Tier2Obfuscated
            || profile.recoverability.native_boundary_basis_points >= 3_500
            || profile.recoverability.string_entropy_basis_points >= 3_500;
    }
    if protection.signatures.is_empty() && protection.handled {
        return false;
    }
    protection.signatures.iter().any(|signature| {
        let signature = signature.to_ascii_lowercase();
        signature.contains("dexguard")
            || signature.contains("string")
            || signature.contains("encrypt")
            || signature.contains("native")
            || signature.contains("packer")
            || signature.contains("obfuscat")
    }) || !protection.handled
}

fn adjust_recoverability(
    baseline_basis_points: u16,
    protection: &ProtectionMetadata,
) -> RecoverabilityExpectation {
    let penalty = if let Some(profile) = &protection.profile {
        let tier_penalty = match profile.tier {
            apiaxess_artifact_intake::ProtectionTier::Tier0Unprotected => 0_u32,
            apiaxess_artifact_intake::ProtectionTier::Tier1StockR8 => 750,
            apiaxess_artifact_intake::ProtectionTier::Tier2Obfuscated => 2_000,
            apiaxess_artifact_intake::ProtectionTier::Tier3HeavyCfgNative => 4_500,
            apiaxess_artifact_intake::ProtectionTier::Tier4Packed => 6_500,
        };
        let vector = &profile.recoverability;
        let feature_penalty = (u32::from(vector.string_entropy_basis_points) * 35
            + u32::from(vector.control_flow_complexity_basis_points) * 20
            + u32::from(vector.reflection_density_basis_points) * 15
            + u32::from(vector.native_boundary_basis_points) * 20
            + u32::from(vector.packing_rasp_basis_points) * 30)
            / 100;
        u16::try_from(tier_penalty.max(feature_penalty).min(7_500)).unwrap_or(7_500)
    } else if protection_obscures_networking(protection) {
        if protection.signatures.iter().any(|signature| {
            let signature = signature.to_ascii_lowercase();
            signature.contains("dexguard")
                || signature.contains("packer")
                || signature.contains("native")
        }) {
            5500
        } else {
            3500
        }
    } else {
        0
    };
    let adjusted = baseline_basis_points.saturating_sub(penalty);
    let rationale = if penalty == 0 {
        "Library baseline applies; no networking-obscuring protection signature was recorded."
            .to_owned()
    } else if let Some(profile) = &protection.profile {
        format!(
            "Library baseline reduced by {penalty} basis points using protection tier {:?} and the quantified recoverability vector.",
            profile.tier
        )
    } else {
        format!(
            "Library baseline reduced by {penalty} basis points because protection metadata indicates {}.",
            protection.signatures.join(", ")
        )
    };
    RecoverabilityExpectation {
        baseline_basis_points,
        adjusted_basis_points: adjusted,
        protection_penalty_basis_points: penalty,
        rationale,
    }
}

fn context_with_hits(hits: &[SignatureHit]) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "locations".to_owned(),
        DiagnosticValue::StringList(
            SignatureCorpus::paths_for(hits)
                .into_iter()
                .take(32)
                .collect(),
        ),
    );
    context.insert(
        "signature_count".to_owned(),
        DiagnosticValue::Integer(i64::try_from(hits.len()).unwrap_or(i64::MAX)),
    );
    context
}

fn unidentified_diagnostic(hits: &[SignatureHit]) -> Diagnostic {
    let mut diagnostic = NETWORKING_USAGE_UNIDENTIFIED.instantiate(context_with_hits(hits));
    diagnostic.why = format!(
        "Generic networking markers were found in {} normalized location(s), but no registered protocol decoder matched.",
        SignatureCorpus::paths_for(hits).len()
    )
    .into_boxed_str();
    diagnostic
}

fn protection_diagnostic(protection: &ProtectionMetadata) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "detector".to_owned(),
        DiagnosticValue::String(protection.detector.clone()),
    );
    context.insert(
        "signatures".to_owned(),
        DiagnosticValue::StringList(protection.signatures.clone()),
    );
    let mut diagnostic = NETWORKING_PROTECTION_OBSCURES_MAP.instantiate(context);
    diagnostic.why = format!(
        "Protection detector {} reported: {}.",
        protection.detector,
        protection.signatures.join(", ")
    )
    .into_boxed_str();
    diagnostic
}

fn signature_ambiguous(descriptor: &DecoderDescriptor, hits: &[SignatureHit]) -> Diagnostic {
    let mut diagnostic = NETWORKING_SIGNATURE_AMBIGUOUS.instantiate(context_with_hits(hits));
    diagnostic.why = format!(
        "{} signatures were found, but no stable structural location could be localized.",
        descriptor.display_name
    )
    .into_boxed_str();
    diagnostic
}

fn location_diagnostic(path: &Path, why: String) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    let mut diagnostic = NETWORKING_ARTIFACT_LOCATION_UNAVAILABLE.instantiate(context);
    diagnostic.why = why.into_boxed_str();
    diagnostic
}

#[cfg(test)]
mod tests {
    use super::{
        CorpusDocument, CorpusSource, MAX_DOCUMENT_BYTES, NetworkingRouter, SignatureCorpus,
        SignatureHit, SourceKind,
    };
    use apiaxess_artifact_intake::{
        ArtifactFormat, DexAccess, InstallableApk, NormalizedUnpackedArtifact, ProtectionMetadata,
        StructuralOutput, index_static_archive,
    };
    use std::{
        collections::BTreeSet,
        fs::{self, File},
        io::{Seek, SeekFrom, Write},
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{ZipWriter, write::SimpleFileOptions};

    fn artifact_for_root(root: &Path, smali: &Path) -> NormalizedUnpackedArtifact {
        fs::create_dir_all(root.join("res")).unwrap();
        fs::create_dir_all(root.join("assets")).unwrap();
        NormalizedUnpackedArtifact {
            schema_version: 1,
            target_type_id: "android.apk".to_owned(),
            workspace_root: root.display().to_string(),
            input_format: ArtifactFormat::Apk,
            raw_archives: Vec::new(),
            static_archives: Vec::new(),
            installable_apks: vec![InstallableApk {
                id: "base".to_owned(),
                path: root.join("base.apk").display().to_string(),
                is_base: true,
            }],
            structural_outputs: vec![StructuralOutput {
                apk_id: "base".to_owned(),
                manifest: root.join("AndroidManifest.xml").display().to_string(),
                smali_roots: vec![smali.display().to_string()],
                resource_root: root.join("res").display().to_string(),
                asset_root: root.join("assets").display().to_string(),
            }],
            dex_access: DexAccess {
                dex_files: Vec::new(),
                parser_handoff: "test".to_owned(),
                capabilities: Vec::new(),
            },
            decompiled_source_roots: Vec::new(),
            protection: ProtectionMetadata {
                detector: "test".to_owned(),
                detector_version: None,
                distribution_posture: "test".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
            provenance: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn fixture(lines: &[&str], protection: ProtectionMetadata) -> NormalizedUnpackedArtifact {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let smali = root.join("smali");
        fs::create_dir_all(&smali).unwrap();
        fs::write(smali.join("Network.smali"), lines.join("\n")).unwrap();
        NormalizedUnpackedArtifact {
            schema_version: 1,
            target_type_id: "android.apk".to_owned(),
            workspace_root: root.display().to_string(),
            input_format: ArtifactFormat::Apk,
            raw_archives: Vec::new(),
            static_archives: Vec::new(),
            installable_apks: vec![InstallableApk {
                id: "base".to_owned(),
                path: root.join("base.apk").display().to_string(),
                is_base: true,
            }],
            structural_outputs: vec![StructuralOutput {
                apk_id: "base".to_owned(),
                manifest: root.join("AndroidManifest.xml").display().to_string(),
                smali_roots: vec![smali.display().to_string()],
                resource_root: root.join("res").display().to_string(),
                asset_root: root.join("assets").display().to_string(),
            }],
            dex_access: DexAccess {
                dex_files: Vec::new(),
                parser_handoff: "test".to_owned(),
                capabilities: Vec::new(),
            },
            decompiled_source_roots: Vec::new(),
            protection,
            provenance: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    fn clean_protection() -> ProtectionMetadata {
        ProtectionMetadata {
            detector: "test".to_owned(),
            detector_version: None,
            distribution_posture: "test".to_owned(),
            signatures: Vec::new(),
            handled: true,
            profile: None,
        }
    }

    #[test]
    fn detects_multiple_libraries_and_preserves_library_specific_locations() {
        let artifact = fixture(
            &[
                ".class public interface abstract Lapi/Service;",
                "Lretrofit2/http/GET;",
                "Lokhttp3/Request$Builder;",
                ".method public call()Lokhttp3/Call;",
                "Lio/grpc/ManagedChannelBuilder;",
            ],
            clean_protection(),
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let ids = routed
            .detections
            .iter()
            .map(|detection| detection.library_id.as_str())
            .collect::<Vec<_>>();
        assert!(ids.contains(&"retrofit"));
        assert!(ids.contains(&"okhttp"));
        assert!(ids.contains(&"grpc-java"));
        assert!(routed.detections.iter().any(|detection| {
            detection
                .api_map_locations
                .iter()
                .any(|location| location.kind == super::ApiMapLocationKind::DexAnnotationTables)
        }));
        assert!(
            routed
                .detections
                .iter()
                .all(|detection| detection.plugin_kind == "protocol-decoder")
        );
    }

    #[test]
    fn builtins_cover_required_networking_families() {
        let artifact = fixture(
            &[
                "Lretrofit2/http/GET;",
                "Lokhttp3/OkHttpClient;",
                "Lio/ktor/client/HttpClient;",
                "Lcom/android/volley/Request;",
                "Lorg/apache/http/client/HttpClient;",
                "Ljava/net/HttpURLConnection;",
                "Ljava/net/Socket;",
                "Lio/grpc/ManagedChannelBuilder;",
                "Lcom/apollographql/apollo/ApolloClient;",
                "Landroid/webkit/WebView; addJavascriptInterface",
            ],
            clean_protection(),
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let ids = routed
            .detections
            .iter()
            .map(|detection| detection.library_id.as_str())
            .collect::<Vec<_>>();
        for required in [
            "retrofit",
            "okhttp",
            "ktor-client",
            "volley",
            "apache-httpclient",
            "httpurlconnection",
            "raw-sockets",
            "grpc-java",
            "graphql-apollo",
            "webview-js-bridge",
        ] {
            assert!(ids.contains(&required), "missing detector for {required}");
        }
    }

    #[test]
    fn records_unidentified_networking_as_a_diagnostic() {
        let artifact = fixture(
            &["Ljava/net/URL;", "invoke-custom unknownTransport"],
            clean_protection(),
        );
        let routed = NetworkingRouter::default().route(&artifact);
        assert!(routed.networking_present);
        assert!(routed.detections.is_empty());
        assert_eq!(routed.unidentified.len(), 1);
        assert!(
            routed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "networking.usage-unidentified")
        );
    }

    #[test]
    fn protection_reduces_expectation_and_emits_honesty_diagnostic() {
        let mut protection = clean_protection();
        protection.handled = false;
        protection.signatures = vec!["DexGuard string encryption".to_owned()];
        let artifact = fixture(&["Lokhttp3/OkHttpClient;"], protection);
        let routed = NetworkingRouter::default().route(&artifact);
        let okhttp = routed
            .detections
            .iter()
            .find(|detection| detection.library_id == "okhttp")
            .unwrap();
        assert!(
            okhttp.recoverability.adjusted_basis_points
                < okhttp.recoverability.baseline_basis_points
        );
        assert!(
            routed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.id.as_ref() == "networking.protection-obscures-map")
        );
    }

    #[test]
    fn streaming_hits_match_the_previous_whole_file_reference() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-equivalence-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let smali = root.join("smali");
        fs::create_dir_all(&smali).unwrap();
        let path = smali.join("Network.smali");
        let content = format!(
            "prefix\n{}OkHtTp and retrofit\njava/net/url\n",
            "a".repeat(65_534)
        );
        fs::write(&path, &content).unwrap();
        let artifact = artifact_for_root(&root, &smali);
        let (corpus, diagnostics) = SignatureCorpus::from_artifact(&artifact);
        assert!(
            diagnostics.is_empty(),
            "unexpected corpus diagnostics: {diagnostics:?}"
        );

        let markers = ["okhttp", "retrofit", "java/net/url"];
        let path_text = path.display().to_string();
        let actual = corpus.hits_for(&markers);
        let expected = content
            .lines()
            .enumerate()
            .flat_map(|(line_index, line)| {
                let path_text = path_text.clone();
                let line = line.to_ascii_lowercase();
                markers
                    .iter()
                    .filter(move |marker| line.contains(**marker))
                    .map(move |marker| SignatureHit {
                        path: path_text.clone(),
                        source_kind: SourceKind::Smali,
                        line_hint: Some(
                            u32::try_from(line_index)
                                .unwrap_or(u32::MAX)
                                .saturating_add(1),
                        ),
                        marker: (*marker).to_owned(),
                    })
            })
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
        assert!(corpus.take_scan_diagnostics().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn large_corpus_scans_with_bounded_retained_memory() {
        const FILE_COUNT: usize = 4_096;
        const FILE_BYTES: u64 = 128 * 1024;
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-large-corpus-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let smali = root.join("smali");
        fs::create_dir_all(&smali).unwrap();
        for index in 0..FILE_COUNT {
            let path = smali.join(format!("Class{index}.smali"));
            let mut file = File::create(path).unwrap();
            file.set_len(FILE_BYTES).unwrap();
            if index == FILE_COUNT / 2 {
                file.seek(SeekFrom::Start(0)).unwrap();
                file.write_all(b"OkHttp").unwrap();
            }
        }
        let artifact = artifact_for_root(&root, &smali);
        let (corpus, diagnostics) = SignatureCorpus::from_artifact(&artifact);
        assert!(
            diagnostics.is_empty(),
            "unexpected corpus diagnostics: {diagnostics:?}"
        );
        assert_eq!(corpus.documents().len(), FILE_COUNT);

        let hits = corpus.hits_for(&["okhttp"]);
        assert_eq!(hits.len(), 1);
        assert!(
            corpus.retained_metadata_bytes() < 2 * 1024 * 1024,
            "corpus retained too much metadata: {} bytes",
            corpus.retained_metadata_bytes()
        );
        assert!(corpus.take_scan_diagnostics().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_extraction_document_is_a_legible_diagnostic() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-oversized-document-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("Oversized.smali");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_DOCUMENT_BYTES + 1).unwrap();
        let document = CorpusDocument {
            path: path.display().to_string(),
            source_kind: SourceKind::Smali,
            source: CorpusSource::File,
        };
        let diagnostic = document
            .load_text()
            .expect_err("size boundary must be reported");
        assert_eq!(
            diagnostic.id.as_ref(),
            "networking.artifact-location-unavailable"
        );
        assert!(diagnostic.why.contains("bounded extraction window"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn indexed_large_archive_scans_without_exploding_members() {
        const CLASS_COUNT: usize = 44_202;
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-indexed-archive-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("base.apk");
        let file = File::create(&archive_path).unwrap();
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        for index in 0..CLASS_COUNT {
            let name = format!("smali/com/example/Class{index}.smali");
            archive.start_file(name, options).unwrap();
            if index == CLASS_COUNT - 1 {
                archive
                    .write_all(b".class public Lcom/example/OkHttpNetwork;\n")
                    .unwrap();
            } else {
                archive
                    .write_all(b".class public Lcom/example/Generated;\n")
                    .unwrap();
            }
        }
        archive.finish().unwrap();

        let mut artifact = artifact_for_root(&root, &root.join("unused-smali"));
        artifact.static_archives = vec![index_static_archive(&archive_path).unwrap()];
        let (corpus, diagnostics) = SignatureCorpus::from_artifact(&artifact);
        assert!(diagnostics.is_empty());
        assert_eq!(corpus.documents().len(), CLASS_COUNT);
        assert_eq!(corpus.hits_for(&["okhttp"]).len(), 1);
        corpus.warm_markers(&[
            "httpurlconnection",
            "java/net/url",
            "java/net/socket",
            "java/nio",
            "okhttp",
            "retrofit",
            "ktor.client",
            "com/android/volley",
            "io/grpc",
            "graphql",
            "apollo",
            "android/webkit/webview",
        ]);
        // Keep this regression test deterministic: wall-clock limits are
        // machine-load dependent and caused false failures on CI. The scan's
        // bounded work is asserted structurally by the fixed member count,
        // retained metadata bound, and complete marker pass below.
        assert!(corpus.retained_metadata_bytes() < CLASS_COUNT * 1_024);
        assert!(!root.join("smali").exists());
        assert!(corpus.take_scan_diagnostics().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn indexed_text_members_match_file_tree_detection() {
        let tree = fixture(
            &[
                ".class public interface abstract Lapi/Service;",
                "Lretrofit2/http/GET;",
                "Lokhttp3/Request$Builder;",
                ".method public call()Lokhttp3/Call;",
            ],
            clean_protection(),
        );
        let root = Path::new(&tree.workspace_root);
        let archive_path = root.join("indexed.apk");
        let file = File::create(&archive_path).unwrap();
        let mut archive = ZipWriter::new(file);
        archive
            .start_file("smali/Network.smali", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(
                b".class public interface abstract Lapi/Service;\nLretrofit2/http/GET;\nLokhttp3/Request$Builder;\n.method public call()Lokhttp3/Call;\n",
            )
            .unwrap();
        archive.finish().unwrap();

        let mut indexed = tree.clone();
        indexed.static_archives = vec![index_static_archive(&archive_path).unwrap()];
        let file_tree = NetworkingRouter::default().route(&tree);
        let archive_route = NetworkingRouter::default().route(&indexed);
        let file_ids = file_tree
            .detections
            .iter()
            .map(|detection| detection.library_id.clone())
            .collect::<BTreeSet<_>>();
        let archive_ids = archive_route
            .detections
            .iter()
            .map(|detection| detection.library_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(archive_ids, file_ids);
        assert!(
            archive_route
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.id.as_ref()
                    != "networking.artifact-location-unavailable")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn indexed_corpus_scopes_typed_sources_to_manifest_package() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-routing-scoped-source-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let smali_root = root.join("smali");
        let app_source = smali_root.join("com/example/app");
        let dependency_source = smali_root.join("com/example/library");
        fs::create_dir_all(&app_source).unwrap();
        fs::create_dir_all(&dependency_source).unwrap();
        fs::write(
            root.join("AndroidManifest.xml"),
            r#"<manifest package="com.example.app"/>"#,
        )
        .unwrap();
        fs::write(
            app_source.join("Service.smali"),
            ".annotation Lretrofit2/http/GET;",
        )
        .unwrap();
        fs::write(
            dependency_source.join("Service.smali"),
            ".annotation Lretrofit2/http/POST;",
        )
        .unwrap();

        let archive_path = root.join("base.apk");
        let file = File::create(&archive_path).unwrap();
        let mut archive = ZipWriter::new(file);
        archive
            .start_file("classes.dex", SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"retrofit2/http/GET").unwrap();
        archive.finish().unwrap();

        let mut artifact = artifact_for_root(&root, &smali_root);
        artifact.static_archives = vec![index_static_archive(&archive_path).unwrap()];
        let (corpus, diagnostics) = SignatureCorpus::from_artifact(&artifact);
        assert!(diagnostics.is_empty());
        let paths = corpus
            .documents()
            .iter()
            .map(|document| document.path.replace('\\', "/"))
            .collect::<BTreeSet<_>>();
        assert!(
            paths
                .iter()
                .any(|path| path.ends_with("Service.smali") && path.contains("com/example/app"))
        );
        assert!(
            !paths
                .iter()
                .any(|path| path.contains("com/example/library"))
        );
        assert!(paths.iter().any(|path| path.contains("!/classes.dex")));
        fs::remove_dir_all(root).unwrap();
    }
}
