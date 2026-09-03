//! Phase 1.4 static-pass normalization and honest boundary handoff.
//!
//! This crate consumes the 1.1 artifact, 1.2 routed map, and 1.3 extraction
//! report. It performs no new artifact scanning or endpoint extraction: it
//! validates the canonical view, rolls up coverage and explicit static gaps,
//! and commits the resulting document through the session aggregate.

use std::{collections::BTreeMap, time::Instant};

use apiaxess_api_model::{
    ApiDocument, DynamicHandoff, LibraryCoverage, StaticBoundaryReason, StaticCoverage,
    StaticKnowledgeStatus, StaticPassSummary,
};
use apiaxess_artifact_intake::NormalizedUnpackedArtifact;
use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue,
    catalogue::{
        STATIC_PASS_COVERAGE_LIMIT, STATIC_PASS_DYNAMIC_HANDOFF, STATIC_PASS_NATIVE_LOGIC,
        STATIC_PASS_PROTECTION_LIMIT,
    },
};
use apiaxess_network_extraction::ExtractionReport;
use apiaxess_network_routing::{ExtractionStatus, RoutedDetectionMap};
use apiaxess_session::Session;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current static-pass honesty handoff schema.
pub const STATIC_PASS_SCHEMA_VERSION: u32 = 1;

/// Failure to produce an invariant-valid normalized static pass.
#[derive(Clone, Debug)]
pub struct StaticPassFailure {
    /// Actionable diagnostic.
    pub diagnostic: Diagnostic,
}

impl std::fmt::Display for StaticPassFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.diagnostic.fmt(formatter)
    }
}

impl std::error::Error for StaticPassFailure {}

/// Complete normalized static-pass result before session commitment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StaticPassReport {
    /// Canonical API document with the static honesty layer attached.
    pub document: ApiDocument,
    /// All diagnostics from 1.1–1.4 retained in one view.
    pub diagnostics: Vec<Diagnostic>,
    /// The persisted machine-readable honesty summary.
    pub honesty: StaticPassSummary,
}

/// Normalizes a 1.3 report and produces the explicit static-to-dynamic handoff.
///
/// No extractor is invoked here. Existing canonical findings are retained and
/// the report is checked after the honesty summary is attached.
///
/// # Errors
///
/// Returns a structured diagnostic if the incoming report or normalized
/// document violates the canonical API-model invariants.
pub fn normalize(
    artifact: &NormalizedUnpackedArtifact,
    routed: &RoutedDetectionMap,
    extraction: &ExtractionReport,
) -> Result<StaticPassReport, StaticPassFailure> {
    let started = Instant::now();
    let mut normalized_document = extraction.document.clone();
    canonicalize_document(&mut normalized_document);
    normalized_document
        .validate()
        .map_err(|error| model_failure(error.to_string()))?;

    let mut rollup = HonestyRollup::new();
    rollup.add_detections(routed, extraction);
    rollup.add_protection(&artifact.protection);
    rollup.add_unidentified(routed);
    let mut honesty = rollup.finish();

    let mut diagnostics = artifact.diagnostics.clone();
    diagnostics.extend(routed.diagnostics.clone());
    diagnostics.extend(extraction.diagnostics.clone());
    diagnostics.extend(honesty.diagnostics.clone());
    honesty.diagnostics.clone_from(&diagnostics);

    let document = normalized_document.with_static_pass(honesty.clone());
    document
        .validate()
        .map_err(|error| model_failure(error.to_string()))?;

    let elapsed_millis = started.elapsed().as_millis();
    if std::env::var_os("APIAXESS_PROFILE_STATIC").is_some() {
        eprintln!("STATIC NORMALIZATION PROFILE: millis={elapsed_millis}");
    }

    Ok(StaticPassReport {
        document,
        diagnostics,
        honesty,
    })
}

fn canonicalize_document(document: &mut ApiDocument) {
    document
        .surface
        .endpoints
        .sort_by(|left, right| left.identity.cmp(&right.identity));
    document
        .surface
        .protocol_operations
        .sort_by(|left, right| left.identity.cmp(&right.identity));
    document.surface.loose_findings.sort_by(|left, right| {
        (
            left.kind,
            left.value
                .selected_candidate()
                .map_or_else(String::new, |candidate| candidate.value.clone()),
        )
            .cmp(&(
                right.kind,
                right
                    .value
                    .selected_candidate()
                    .map_or_else(String::new, |candidate| candidate.value.clone()),
            ))
    });
}

/// Commits a normalized static pass to an active session.
///
/// The session owns the durable API document; this operation performs the
/// lifecycle, timestamp, model-validation, and persistence boundary in one
/// place.
///
/// # Errors
///
/// Returns the session lifecycle, timestamp, or API-model diagnostic.
pub fn commit(
    session: &mut Session,
    report: &StaticPassReport,
    at: DateTime<Utc>,
) -> Result<(), Diagnostic> {
    session.commit_api_document(report.document.clone(), at)
}

fn model_failure(error: String) -> StaticPassFailure {
    let mut context = DiagnosticContext::new();
    context.insert("model_error".to_owned(), DiagnosticValue::String(error));
    StaticPassFailure {
        diagnostic: apiaxess_diagnostics::catalogue::EXTRACTION_MODEL_INVALID.instantiate(context),
    }
}

struct HonestyRollup {
    libraries: BTreeMap<String, LibraryCoverage>,
    handoffs: Vec<DynamicHandoff>,
    diagnostics: Vec<Diagnostic>,
    expected_basis_points: u64,
    covered_basis_points: u64,
}

impl HonestyRollup {
    fn new() -> Self {
        Self {
            libraries: BTreeMap::new(),
            handoffs: Vec::new(),
            diagnostics: Vec::new(),
            expected_basis_points: 0,
            covered_basis_points: 0,
        }
    }

    fn add_detections(&mut self, routed: &RoutedDetectionMap, extraction: &ExtractionReport) {
        for detection in &routed.detections {
            let records = extraction
                .records
                .iter()
                .filter(|record| record.library_id == detection.library_id)
                .collect::<Vec<_>>();
            let endpoint_count = records.iter().map(|record| record.endpoint_count).sum();
            let operation_count = records.iter().map(|record| record.operation_count).sum();
            let partial_count = extraction
                .partial_recoveries
                .iter()
                .filter(|partial| partial.library_id == detection.library_id)
                .count();
            let status = if detection.extraction_status == ExtractionStatus::DetectedButDeferred {
                StaticKnowledgeStatus::KnownMissing
            } else if partial_count > 0 || detection.recoverability.adjusted_basis_points < 8_500 {
                StaticKnowledgeStatus::Partial
            } else if endpoint_count == 0 && operation_count == 0 {
                StaticKnowledgeStatus::Silent
            } else {
                StaticKnowledgeStatus::HighConfidence
            };
            let expected = u64::from(detection.recoverability.adjusted_basis_points);
            self.expected_basis_points = self.expected_basis_points.saturating_add(expected);
            self.covered_basis_points = self.covered_basis_points.saturating_add(match status {
                StaticKnowledgeStatus::HighConfidence => expected,
                StaticKnowledgeStatus::Partial => expected / 2,
                StaticKnowledgeStatus::KnownMissing | StaticKnowledgeStatus::Silent => 0,
            });
            self.libraries.insert(
                detection.library_id.clone(),
                LibraryCoverage {
                    library_id: detection.library_id.clone(),
                    expected_recoverability_basis_points: detection
                        .recoverability
                        .adjusted_basis_points,
                    status,
                    endpoint_count,
                    operation_count,
                    partial_count,
                },
            );

            match status {
                StaticKnowledgeStatus::KnownMissing => {
                    self.add_handoff(
                        Some(&detection.library_id),
                        first_location(detection),
                        StaticBoundaryReason::RawSocketDeferred,
                        "raw socket usage, deferred; static protocol interpretation is not available in Phase 1",
                        false,
                    );
                }
                StaticKnowledgeStatus::Partial => {
                    for partial in extraction
                        .partial_recoveries
                        .iter()
                        .filter(|partial| partial.library_id == detection.library_id)
                    {
                        self.add_handoff(
                            Some(&detection.library_id),
                            &partial.location,
                            StaticBoundaryReason::RuntimeAssembly,
                            &partial.reason,
                            false,
                        );
                    }
                    if partial_count == 0 {
                        self.add_handoff(
                            Some(&detection.library_id),
                            first_location(detection),
                            StaticBoundaryReason::RuntimeAssembly,
                            "library recoverability is medium; runtime composition may escape bounded static analysis",
                            false,
                        );
                    }
                }
                StaticKnowledgeStatus::Silent => self.add_handoff(
                    Some(&detection.library_id),
                    first_location(detection),
                    StaticBoundaryReason::StaticSilence,
                    "static is silent here; no absence assertion was made",
                    true,
                ),
                StaticKnowledgeStatus::HighConfidence => {}
            }
        }
    }

    fn add_protection(&mut self, protection: &apiaxess_artifact_intake::ProtectionMetadata) {
        let signatures = protection.signatures.join(" ").to_ascii_lowercase();
        if signatures.contains("dexguard")
            || signatures.contains("commercial")
            || signatures.contains("encrypt")
            || signatures.contains("obfuscat")
        {
            self.add_handoff(
                None,
                "protection metadata",
                StaticBoundaryReason::CommercialObfuscation,
                "strings encrypted (commercial obfuscation detected)",
                false,
            );
            self.diagnostics.push(
                STATIC_PASS_PROTECTION_LIMIT
                    .instantiate(protection_context(&protection.signatures)),
            );
        }
        if signatures.contains("native") || signatures.contains("jni") || signatures.contains(".so")
        {
            self.add_handoff(
                None,
                "native libraries",
                StaticBoundaryReason::NativeLogic,
                "networking logic in native library",
                false,
            );
            self.diagnostics.push(
                STATIC_PASS_NATIVE_LOGIC.instantiate(protection_context(&protection.signatures)),
            );
        }
        if let Some(profile) = &protection.profile {
            if profile.tier >= apiaxess_artifact_intake::ProtectionTier::Tier2Obfuscated
                && !signatures.contains("encrypt")
                && !signatures.contains("obfuscat")
            {
                self.add_handoff(
                    None,
                    "protection recoverability vector",
                    StaticBoundaryReason::CommercialObfuscation,
                    "quantified protection tier limits static recovery; dynamic capture recommended",
                    false,
                );
                self.diagnostics.push(
                    STATIC_PASS_PROTECTION_LIMIT
                        .instantiate(protection_context(&protection.signatures)),
                );
            }
            if profile.recoverability.native_boundary_basis_points >= 3_500
                && !signatures.contains("native")
            {
                self.add_handoff(
                    None,
                    "protection recoverability vector",
                    StaticBoundaryReason::NativeLogic,
                    "native-boundary ratio is elevated; networking logic may be in native library",
                    false,
                );
                self.diagnostics.push(
                    STATIC_PASS_NATIVE_LOGIC
                        .instantiate(protection_context(&protection.signatures)),
                );
            }
        }
    }

    fn add_unidentified(&mut self, routed: &RoutedDetectionMap) {
        if routed.unidentified.is_empty() {
            return;
        }
        self.add_handoff(
            None,
            "unidentified networking locations",
            StaticBoundaryReason::UnidentifiedNetworking,
            "networking present but unidentifiable; dynamic capture recommended",
            false,
        );
    }

    fn add_handoff(
        &mut self,
        library_id: Option<&str>,
        location: &str,
        reason: StaticBoundaryReason,
        detail: &str,
        static_silence: bool,
    ) {
        let id = format!(
            "handoff:{}:{}:{}",
            reason_token(reason),
            library_id.unwrap_or("networking"),
            location
        );
        let id = stable_token(&id);
        if self.handoffs.iter().any(|handoff| handoff.id == id) {
            return;
        }
        self.handoffs.push(DynamicHandoff {
            id,
            library_id: library_id.map(str::to_owned),
            location: location.to_owned(),
            reason,
            detail: detail.to_owned(),
            static_silence,
        });
        let mut context = DiagnosticContext::new();
        context.insert(
            "library_id".to_owned(),
            DiagnosticValue::String(library_id.unwrap_or("unknown").to_owned()),
        );
        context.insert(
            "location".to_owned(),
            DiagnosticValue::String(location.to_owned()),
        );
        context.insert(
            "reason".to_owned(),
            DiagnosticValue::String(reason_token(reason).to_owned()),
        );
        self.diagnostics
            .push(STATIC_PASS_DYNAMIC_HANDOFF.instantiate(context));
    }

    fn finish(mut self) -> StaticPassSummary {
        let coverage_limited = self
            .libraries
            .values()
            .any(|library| library.status != StaticKnowledgeStatus::HighConfidence);
        if coverage_limited {
            self.diagnostics
                .push(STATIC_PASS_COVERAGE_LIMIT.instantiate(DiagnosticContext::new()));
        }
        StaticPassSummary {
            schema_version: STATIC_PASS_SCHEMA_VERSION,
            coverage: StaticCoverage {
                expected_basis_points: self.expected_basis_points,
                covered_basis_points: self.covered_basis_points,
                methodology: "per-library protection-adjusted recoverability; high-confidence libraries count fully, partial libraries count at half weight, and known-missing/silent libraries count zero; this is coverage, not endpoint confidence".to_owned(),
                libraries: self.libraries.into_values().collect(),
            },
            dynamic_handoffs: self.handoffs,
            diagnostics: self.diagnostics,
        }
    }
}

fn first_location(detection: &apiaxess_network_routing::LibraryDetection) -> &str {
    detection
        .api_map_locations
        .first()
        .map_or("routed detection", |location| location.path.as_str())
}

fn protection_context(signatures: &[String]) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "signatures".to_owned(),
        DiagnosticValue::StringList(signatures.to_vec()),
    );
    context
}

fn reason_token(reason: StaticBoundaryReason) -> &'static str {
    match reason {
        StaticBoundaryReason::RuntimeAssembly => "runtime-assembly",
        StaticBoundaryReason::CommercialObfuscation => "commercial-obfuscation",
        StaticBoundaryReason::NativeLogic => "native-logic",
        StaticBoundaryReason::RawSocketDeferred => "raw-socket-deferred",
        StaticBoundaryReason::UnidentifiedNetworking => "unidentified-networking",
        StaticBoundaryReason::StaticSilence => "static-silence",
    }
}

fn stable_token(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() || character.is_ascii_digit() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_artifact_intake::{
        ArtifactFormat, DexAccess, InstallableApk, ProtectionMetadata, StructuralOutput,
    };
    use apiaxess_network_extraction::extract;
    use apiaxess_network_routing::NetworkingRouter;
    use apiaxess_session::{
        EngagementScope, Session, SessionDocument, SessionId, TargetIdentifier, TargetIdentity,
    };
    use chrono::TimeZone;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fixture(lines: &[&str], protection: ProtectionMetadata) -> NormalizedUnpackedArtifact {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("apiaxess-static-pass-{stamp}"));
        let smali = root.join("smali");
        let resources = root.join("res");
        let assets = root.join("assets");
        fs::create_dir_all(&smali).unwrap();
        fs::create_dir_all(&resources).unwrap();
        fs::create_dir_all(&assets).unwrap();
        fs::write(smali.join("Service.smali"), lines.join("\n")).unwrap();
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
                manifest: "AndroidManifest.xml".to_owned(),
                smali_roots: vec![smali.display().to_string()],
                resource_root: resources.display().to_string(),
                asset_root: assets.display().to_string(),
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

    #[test]
    fn rolls_up_silence_and_preserves_native_operation_shapes() {
        let artifact = fixture(
            &[
                "Lio/grpc/ManagedChannelBuilder;",
                "generateFullMethodName(\"demo.Users\", \"GetUser\")",
            ],
            ProtectionMetadata {
                detector: "test".to_owned(),
                detector_version: None,
                distribution_posture: "test".to_owned(),
                signatures: vec!["native JNI networking".to_owned()],
                handled: true,
                profile: None,
            },
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let extraction = extract(&artifact, &routed).unwrap();
        let report = normalize(&artifact, &routed, &extraction).unwrap();
        assert!(report.document.static_pass.is_some());
        assert!(report.honesty.coverage.expected_basis_points > 0);
        assert!(
            report
                .honesty
                .dynamic_handoffs
                .iter()
                .any(|handoff| handoff.reason == StaticBoundaryReason::NativeLogic)
        );
        assert!(
            report
                .document
                .surface
                .protocol_operations
                .iter()
                .any(|operation| matches!(
                    operation.identity,
                    apiaxess_api_model::ProtocolOperationIdentity::Grpc { .. }
                ))
        );
    }

    #[test]
    fn commits_static_pass_and_round_trips_without_flattening() {
        let artifact = fixture(
            &["Lretrofit2/http/GET;", "value = \"/users\""],
            ProtectionMetadata {
                detector: "test".to_owned(),
                detector_version: None,
                distribution_posture: "test".to_owned(),
                signatures: Vec::new(),
                handled: true,
                profile: None,
            },
        );
        let routed = NetworkingRouter::default().route(&artifact);
        let extraction = extract(&artifact, &routed).unwrap();
        let report = normalize(&artifact, &routed, &extraction).unwrap();
        let at = |second| Utc.with_ymd_and_hms(2026, 8, 18, 12, 0, second).unwrap();
        let scope = EngagementScope {
            declared_at: at(0),
            target: TargetIdentity {
                target_type: "apk".to_owned(),
                primary: TargetIdentifier {
                    kind: "artifact.sha256".to_owned(),
                    value: "00".repeat(32),
                },
                aliases: Vec::new(),
            },
            allowed_targets: Vec::new(),
        };
        let mut session = Session::new(
            SessionId::new("session:static-pass").unwrap(),
            scope,
            extraction.document,
            at(1),
        );
        session.activate(at(2)).unwrap();
        commit(&mut session, &report, at(3)).unwrap();
        let original = SessionDocument::new(session, at(4));
        let bytes = original.to_json_pretty().unwrap();
        let loaded = SessionDocument::from_json(&bytes).unwrap();
        assert_eq!(loaded, original);
        assert_eq!(
            loaded.session.api_document().static_pass,
            Some(report.honesty)
        );
        assert!(
            !loaded
                .session
                .api_document()
                .static_pass
                .as_ref()
                .unwrap()
                .diagnostics
                .is_empty()
        );
    }
}
