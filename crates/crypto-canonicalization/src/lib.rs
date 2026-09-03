//! Phase 4.3: infer request canonicalization from captured signing preimages.
//!
//! This crate deliberately emits ranked hypotheses. It can correlate exact
//! update chunks and run differential/held-out checks, but it does not claim
//! that a finite capture set proves unobserved application branches.

use apiaxess_api_model::provenance::SourceType;
use apiaxess_crypto_capture::{CryptoCaptureRecord, UpdateChunk};
use apiaxess_crypto_scheme_detection::{DetectionOutcome, ReproductionShortcut, SchemeDetection};
use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use serde::{Deserialize, Serialize};

/// Current Phase 4.3 result schema.
pub const CANONICALIZATION_SCHEMA_VERSION: u32 = 1;

/// Raw request fields available to canonicalization hypotheses.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestSnapshot {
    /// Request identifier from the capture correlation boundary.
    pub request_id: Option<String>,
    /// Flow identifier from the capture correlation boundary.
    pub flow_id: Option<u64>,
    /// HTTP method as observed on the wire.
    pub method: String,
    /// Path as observed before hypothesis encoding.
    pub path: String,
    /// Query pairs in wire order.
    pub query: Vec<(String, String)>,
    /// Headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Exact body bytes, when observable.
    pub body: Option<Vec<u8>>,
    /// Timestamp known to be associated with the request, if available.
    pub timestamp: Option<String>,
    /// Nonce known to be associated with the request, if available.
    pub nonce: Option<String>,
}

/// One request plus its Phase 4.1 signing operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalizationCapture {
    /// Stable capture identifier used by provenance and fixtures.
    pub capture_id: String,
    /// Raw request snapshot correlated with the operation.
    pub request: RequestSnapshot,
    /// Exact primitive capture, including update chunks and output.
    pub operation: CryptoCaptureRecord,
}

impl CanonicalizationCapture {
    /// Returns the exact preimage captured by Phase 4.1.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.operation.accumulated_message
    }

    /// Returns true when the capture has the ordered update evidence needed
    /// for direct chunk correlation.
    #[must_use]
    pub fn has_ordered_updates(&self) -> bool {
        !self.operation.updates.is_empty()
    }
}

/// A replay seam supplied by the primitive/key owner for held-out validation.
pub trait ReplayOracle {
    /// Reproduce the primitive output for a candidate canonical message.
    fn replay(&self, capture: &CanonicalizationCapture, canonical_bytes: &[u8]) -> Option<Vec<u8>>;
}

/// Optional input state from Phase 4.2 and the observability boundary.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceInput {
    /// Captures used to form and score candidate hypotheses.
    pub training_captures: Vec<CanonicalizationCapture>,
    /// Captures never used to form candidates; used for honest validation.
    pub held_out_captures: Vec<CanonicalizationCapture>,
    /// Recognized Phase 4.2 shortcut, when detection succeeded.
    pub scheme_shortcut: Option<ReproductionShortcut>,
    /// Explicit anti-hooking or observability block from the capture layer.
    pub blocked_reason: Option<String>,
}

/// Carries only a confidently recognized Phase 4.2 shortcut into 4.3.
/// Ambiguous and unrecognized detections intentionally fall through to the
/// generic candidate plans.
#[must_use]
pub fn shortcut_from_detection(detection: &SchemeDetection) -> Option<ReproductionShortcut> {
    match &detection.result {
        DetectionOutcome::Recognized { identification } => {
            Some(identification.reproduction.clone())
        }
        DetectionOutcome::Ambiguous { .. } | DetectionOutcome::Unrecognized { .. } => None,
    }
}

/// A property that a differential pair appears to vary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialProperty {
    /// HTTP method changed.
    Method,
    /// Path or path encoding changed.
    Path,
    /// Query order or query contents changed.
    Query,
    /// A header was added, removed, or changed.
    Headers,
    /// Body bytes changed.
    Body,
    /// Timestamp changed while other visible fields stayed stable.
    Timestamp,
    /// Nonce changed while other visible fields stayed stable.
    Nonce,
    /// More than one request property changed.
    Multiple,
}

/// One pairwise differential experiment retained as evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DifferentialExperiment {
    /// Left capture identifier.
    pub left_capture_id: String,
    /// Right capture identifier.
    pub right_capture_id: String,
    /// Property classified as changed.
    pub property: DifferentialProperty,
    /// Whether the exact preimage changed too.
    pub preimage_changed: bool,
    /// Whether the primitive output changed too, when both outputs exist.
    pub output_changed: Option<bool>,
}

/// Source field used by a canonicalization plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalSource {
    /// HTTP method.
    Method,
    /// Request path.
    Path,
    /// Query serialized in captured order.
    Query,
    /// Query serialized in sorted key/value order.
    SortedQuery,
    /// Headers serialized in captured order.
    Headers,
    /// Headers serialized in sorted order.
    SortedHeaders,
    /// Exact body bytes.
    Body,
    /// Associated timestamp.
    Timestamp,
    /// Associated nonce.
    Nonce,
    /// Constant bytes observed in an update stream.
    Literal(Vec<u8>),
}

/// Encoding applied to a rendered source field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueEncoding {
    /// No transformation.
    Raw,
    /// RFC-style percent encoding.
    PercentEncoded,
    /// Form encoding where spaces become plus signs.
    FormEncoded,
    /// Lowercase hexadecimal.
    HexLower,
    /// Standard Base64 with padding.
    Base64,
    /// Base64URL without padding.
    Base64Url,
}

/// One ordered component of a candidate canonical message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalComponent {
    /// Request source or literal bytes.
    pub source: CanonicalSource,
    /// Encoding applied to the source.
    pub encoding: ValueEncoding,
}

/// Provenance retained for a hypothesis or fixture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceProvenance {
    /// Static, dynamic, or fusion origin.
    pub source_type: SourceType,
    /// Human-readable evidence statement.
    pub detail: String,
}

/// Replay evidence retained for review and Phase 4.4 packaging.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalizationFixture {
    /// Capture that generated the fixture.
    pub capture_id: String,
    /// Whether this fixture was held out from candidate formation.
    pub held_out: bool,
    /// Request used by the fixture.
    pub request: RequestSnapshot,
    /// Candidate canonical bytes.
    pub canonical_bytes: Vec<u8>,
    /// Observed primitive output, if present.
    pub observed_output: Option<Vec<u8>>,
    /// Output reproduced by the replay oracle, if available.
    pub reproduced_output: Option<Vec<u8>>,
    /// Exact preimage equality for this fixture.
    pub preimage_match: bool,
    /// Held-out output equality for this fixture.
    pub replay_match: Option<bool>,
}

/// Ranked candidate canonicalization hypothesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalizationHypothesis {
    /// Stable candidate identifier.
    pub hypothesis_id: String,
    /// Short explanation of the plan.
    pub description: String,
    /// Ordered plan components.
    pub components: Vec<CanonicalComponent>,
    /// Bytes inserted between components.
    pub delimiter: Vec<u8>,
    /// Phase 4.2 shortcut carried into this starting hypothesis.
    pub scheme_shortcut: Option<ReproductionShortcut>,
    /// Evidence statements supporting this candidate.
    pub provenance: Vec<InferenceProvenance>,
    /// Training preimage match count.
    pub training_matches: usize,
    /// Training capture count.
    pub training_total: usize,
    /// Held-out replay match count.
    pub held_out_matches: usize,
    /// Held-out capture count.
    pub held_out_total: usize,
    /// Whether a replay oracle was available for held-out scoring.
    pub held_out_validation_available: bool,
    /// Bounded confidence score.
    pub confidence: f64,
    /// Human review is needed before claiming reusable recovery.
    pub human_assist_needed: bool,
    /// Supporting request/preimage/output fixtures.
    pub fixtures: Vec<CanonicalizationFixture>,
}

impl PartialEq for CanonicalizationHypothesis {
    fn eq(&self, other: &Self) -> bool {
        self.hypothesis_id == other.hypothesis_id
            && self.components == other.components
            && self.delimiter == other.delimiter
            && self.training_matches == other.training_matches
            && self.held_out_matches == other.held_out_matches
            && self.confidence == other.confidence
    }
}

/// Honest 4.3 outcome states consumed by the next phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum InferenceOutcome {
    /// A candidate reproduced every available held-out signature.
    Reproducible {
        /// Ranked hypotheses, with the best candidate first.
        hypotheses: Vec<CanonicalizationHypothesis>,
    },
    /// Candidate(s) exist but validation or evidence is incomplete.
    PartialHypothesis {
        /// Ranked hypotheses, with the best candidate first.
        hypotheses: Vec<CanonicalizationHypothesis>,
        /// Why review or more captures are still needed.
        reason: String,
    },
    /// A primitive was observed, but no canonicalization was recoverable.
    ObservedOnly {
        /// Explanation for the non-recoverable state.
        reason: String,
        /// Captures supporting the observation.
        capture_ids: Vec<String>,
    },
    /// Instrumentation or request visibility blocked inference.
    Blocked {
        /// Blocking explanation.
        reason: String,
    },
}

/// Durable 4.3 result, including differential evidence and diagnostics.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalizationInference {
    /// Result schema version.
    pub schema_version: u32,
    /// Captures used to form candidates.
    pub training_capture_ids: Vec<String>,
    /// Captures held out for validation.
    pub held_out_capture_ids: Vec<String>,
    /// Differential evidence across the supplied captures.
    pub differential_experiments: Vec<DifferentialExperiment>,
    /// Honest inference state.
    pub outcome: InferenceOutcome,
    /// Diagnostic-legible outcome.
    pub diagnostic: Diagnostic,
}

/// Configurable inference engine. The candidate set is intentionally small,
/// explainable, and extensible through the replay oracle rather than a hidden
/// canonicalization switch.
#[derive(Clone, Debug)]
pub struct CanonicalizationInferer {
    /// Maximum number of ranked candidates retained for review.
    pub max_hypotheses: usize,
}

impl Default for CanonicalizationInferer {
    fn default() -> Self {
        Self { max_hypotheses: 12 }
    }
}

impl CanonicalizationInferer {
    /// Infers, ranks, and held-out-validates canonicalization candidates.
    #[must_use]
    pub fn infer(
        &self,
        input: &InferenceInput,
        replay_oracle: Option<&dyn ReplayOracle>,
    ) -> CanonicalizationInference {
        let training_ids = input
            .training_captures
            .iter()
            .map(|capture| capture.capture_id.clone())
            .collect::<Vec<_>>();
        let held_out_ids = input
            .held_out_captures
            .iter()
            .map(|capture| capture.capture_id.clone())
            .collect::<Vec<_>>();
        let all_captures = input
            .training_captures
            .iter()
            .chain(input.held_out_captures.iter())
            .collect::<Vec<_>>();
        let differential_experiments = build_differential_experiments(&all_captures);

        if let Some(reason) = input
            .blocked_reason
            .as_deref()
            .filter(|reason| !reason.trim().is_empty())
        {
            return self.finish(
                training_ids,
                held_out_ids,
                differential_experiments,
                InferenceOutcome::Blocked {
                    reason: reason.to_owned(),
                },
            );
        }

        if input.training_captures.is_empty() {
            let reason = if all_captures.is_empty() {
                "No correlated signing preimage capture was available.".to_owned()
            } else {
                "Primitive evidence exists, but no training request/preimage pair was available."
                    .to_owned()
            };
            return self.finish(
                training_ids,
                held_out_ids,
                differential_experiments,
                InferenceOutcome::ObservedOnly {
                    reason,
                    capture_ids: all_captures
                        .iter()
                        .map(|capture| capture.capture_id.clone())
                        .collect(),
                },
            );
        }

        let plans = candidate_plans(&input.training_captures[0], input.scheme_shortcut.clone());
        let mut hypotheses = plans
            .into_iter()
            .map(|plan| score_plan(plan, input, replay_oracle, &differential_experiments))
            .filter(|hypothesis| hypothesis.training_matches > 0)
            .collect::<Vec<_>>();
        hypotheses.sort_by(|left, right| {
            right
                .confidence
                .total_cmp(&left.confidence)
                .then_with(|| right.held_out_matches.cmp(&left.held_out_matches))
        });
        hypotheses.truncate(self.max_hypotheses.max(1));

        if hypotheses.is_empty() {
            return self.finish(
                training_ids,
                held_out_ids,
                differential_experiments,
                InferenceOutcome::ObservedOnly {
                    reason: "The captured preimage could not be correlated to the observable request fields.".to_owned(),
                    capture_ids: input
                        .training_captures
                        .iter()
                        .map(|capture| capture.capture_id.clone())
                        .collect(),
                },
            );
        }

        let reproducible = !input.held_out_captures.is_empty()
            && replay_oracle.is_some()
            && hypotheses[0].held_out_matches == hypotheses[0].held_out_total
            && hypotheses[0].held_out_total > 0
            && !hypotheses[0].human_assist_needed;
        let outcome = if reproducible {
            InferenceOutcome::Reproducible { hypotheses }
        } else {
            InferenceOutcome::PartialHypothesis {
                hypotheses,
                reason: partial_reason(input, replay_oracle),
            }
        };
        self.finish(
            training_ids,
            held_out_ids,
            differential_experiments,
            outcome,
        )
    }

    fn finish(
        &self,
        training_capture_ids: Vec<String>,
        held_out_capture_ids: Vec<String>,
        differential_experiments: Vec<DifferentialExperiment>,
        outcome: InferenceOutcome,
    ) -> CanonicalizationInference {
        let diagnostic = outcome_diagnostic(&outcome, &training_capture_ids, &held_out_capture_ids);
        CanonicalizationInference {
            schema_version: CANONICALIZATION_SCHEMA_VERSION,
            training_capture_ids,
            held_out_capture_ids,
            differential_experiments,
            outcome,
            diagnostic,
        }
    }
}

/// Builds pairwise differential evidence. A pair is still retained when more
/// than one field changed, because that is useful evidence against overclaiming.
#[must_use]
pub fn build_differential_experiments(
    captures: &[&CanonicalizationCapture],
) -> Vec<DifferentialExperiment> {
    let mut experiments = Vec::new();
    for (left_index, left) in captures.iter().enumerate() {
        for right in captures.iter().skip(left_index + 1) {
            let changed = changed_properties(&left.request, &right.request);
            if changed.is_empty() {
                continue;
            }
            let property = if changed.len() == 1 {
                changed[0].clone()
            } else {
                DifferentialProperty::Multiple
            };
            experiments.push(DifferentialExperiment {
                left_capture_id: left.capture_id.clone(),
                right_capture_id: right.capture_id.clone(),
                property,
                preimage_changed: left.preimage() != right.preimage(),
                output_changed: match (
                    left.operation.primitive_output.as_ref(),
                    right.operation.primitive_output.as_ref(),
                ) {
                    (Some(left_output), Some(right_output)) => Some(left_output != right_output),
                    _ => None,
                },
            });
        }
    }
    experiments
}

fn changed_properties(
    left: &RequestSnapshot,
    right: &RequestSnapshot,
) -> Vec<DifferentialProperty> {
    let mut changed = Vec::new();
    if left.method != right.method {
        changed.push(DifferentialProperty::Method);
    }
    if left.path != right.path {
        changed.push(DifferentialProperty::Path);
    }
    if left.query != right.query {
        changed.push(DifferentialProperty::Query);
    }
    if left.headers != right.headers {
        changed.push(DifferentialProperty::Headers);
    }
    if left.body != right.body {
        changed.push(DifferentialProperty::Body);
    }
    if left.timestamp != right.timestamp {
        changed.push(DifferentialProperty::Timestamp);
    }
    if left.nonce != right.nonce {
        changed.push(DifferentialProperty::Nonce);
    }
    changed
}

#[derive(Clone, Debug)]
struct CandidatePlan {
    description: String,
    components: Vec<CanonicalComponent>,
    delimiter: Vec<u8>,
    shortcut: Option<ReproductionShortcut>,
    provenance: Vec<InferenceProvenance>,
    direct_chunk_evidence: bool,
    unknown_chunk_literals: bool,
}

fn candidate_plans(
    first: &CanonicalizationCapture,
    shortcut: Option<ReproductionShortcut>,
) -> Vec<CandidatePlan> {
    let mut plans = Vec::new();
    if first.has_ordered_updates() {
        let mut components = Vec::new();
        let mut unknown = false;
        for chunk in &first.operation.updates {
            if let Some(component) = identify_chunk(chunk, &first.request) {
                components.push(component);
            } else {
                unknown |= !is_common_delimiter(&chunk.bytes);
                components.push(CanonicalComponent {
                    source: CanonicalSource::Literal(chunk.bytes.clone()),
                    encoding: ValueEncoding::Raw,
                });
            }
        }
        plans.push(CandidatePlan {
            description: "ordered Phase 4.1 update chunks".to_owned(),
            components,
            delimiter: Vec::new(),
            shortcut: shortcut.clone(),
            provenance: vec![InferenceProvenance {
                source_type: SourceType::DynamicCapture,
                detail: "Recovered from the ordered update() chunk sequence.".to_owned(),
            }],
            direct_chunk_evidence: true,
            unknown_chunk_literals: unknown,
        });
    }

    let standard = [
        (
            "method + path",
            vec![
                source(CanonicalSource::Method),
                source(CanonicalSource::Path),
            ],
            Vec::new(),
        ),
        (
            "method + path + sorted query",
            vec![
                source(CanonicalSource::Method),
                source(CanonicalSource::Path),
                source(CanonicalSource::SortedQuery),
            ],
            Vec::new(),
        ),
        (
            "method + path + sorted headers + body",
            vec![
                source(CanonicalSource::Method),
                source(CanonicalSource::Path),
                source(CanonicalSource::SortedHeaders),
                source(CanonicalSource::Body),
            ],
            vec![b'\n'],
        ),
        (
            "path + sorted query",
            vec![
                source(CanonicalSource::Path),
                source(CanonicalSource::SortedQuery),
            ],
            vec![b'&'],
        ),
        ("body only", vec![source(CanonicalSource::Body)], Vec::new()),
        (
            "sorted query only",
            vec![source(CanonicalSource::SortedQuery)],
            Vec::new(),
        ),
    ];
    for (description, components, delimiter) in standard {
        plans.push(CandidatePlan {
            description: description.to_owned(),
            components,
            delimiter,
            shortcut: shortcut.clone(),
            provenance: vec![InferenceProvenance {
                source_type: if shortcut.is_some() {
                    SourceType::Fusion
                } else {
                    SourceType::DynamicCapture
                },
                detail: if let Some(shortcut) = &shortcut {
                    format!("Started from the Phase 4.2 {shortcut:?} template shortcut.")
                } else {
                    "Generated as a generic request-field hypothesis.".to_owned()
                },
            }],
            direct_chunk_evidence: false,
            unknown_chunk_literals: false,
        });
    }
    plans
}

fn source(source: CanonicalSource) -> CanonicalComponent {
    CanonicalComponent {
        source,
        encoding: ValueEncoding::Raw,
    }
}

fn is_common_delimiter(bytes: &[u8]) -> bool {
    matches!(bytes, b"\n" | b"\r\n" | b"&" | b":" | b"=" | b".")
}

fn identify_chunk(chunk: &UpdateChunk, request: &RequestSnapshot) -> Option<CanonicalComponent> {
    let sources = [
        CanonicalSource::Method,
        CanonicalSource::Path,
        CanonicalSource::Query,
        CanonicalSource::SortedQuery,
        CanonicalSource::Headers,
        CanonicalSource::SortedHeaders,
        CanonicalSource::Body,
        CanonicalSource::Timestamp,
        CanonicalSource::Nonce,
    ];
    let encodings = [
        ValueEncoding::Raw,
        ValueEncoding::PercentEncoded,
        ValueEncoding::FormEncoded,
        ValueEncoding::HexLower,
        ValueEncoding::Base64,
        ValueEncoding::Base64Url,
    ];
    for source in sources {
        for encoding in &encodings {
            let component = CanonicalComponent {
                source: source.clone(),
                encoding: encoding.clone(),
            };
            if render_component(&component, request).as_deref() == Some(chunk.bytes.as_slice()) {
                return Some(component);
            }
        }
    }
    None
}

fn score_plan(
    plan: CandidatePlan,
    input: &InferenceInput,
    replay_oracle: Option<&dyn ReplayOracle>,
    differential_experiments: &[DifferentialExperiment],
) -> CanonicalizationHypothesis {
    let mut fixtures = Vec::new();
    let mut training_matches = 0;
    for capture in &input.training_captures {
        let canonical_bytes = render_plan(&plan.components, &plan.delimiter, &capture.request);
        let preimage_match = canonical_bytes == capture.preimage();
        training_matches += usize::from(preimage_match);
        fixtures.push(CanonicalizationFixture {
            capture_id: capture.capture_id.clone(),
            held_out: false,
            request: capture.request.clone(),
            canonical_bytes,
            observed_output: capture.operation.primitive_output.clone(),
            reproduced_output: None,
            preimage_match,
            replay_match: None,
        });
    }

    let mut held_out_matches = 0;
    for capture in &input.held_out_captures {
        let canonical_bytes = render_plan(&plan.components, &plan.delimiter, &capture.request);
        let (reproduced_output, replay_match) = if let Some(oracle) = replay_oracle {
            let reproduced = oracle.replay(capture, &canonical_bytes);
            let matched = reproduced
                .as_ref()
                .zip(capture.operation.primitive_output.as_ref())
                .map(|(actual, expected)| actual == expected);
            if matched == Some(true) {
                held_out_matches += 1;
            }
            (reproduced, matched)
        } else {
            (None, None)
        };
        fixtures.push(CanonicalizationFixture {
            capture_id: capture.capture_id.clone(),
            held_out: true,
            request: capture.request.clone(),
            canonical_bytes,
            observed_output: capture.operation.primitive_output.clone(),
            reproduced_output,
            preimage_match: false,
            replay_match,
        });
    }

    let training_rate = ratio(training_matches, input.training_captures.len());
    let held_out_rate = ratio(held_out_matches, input.held_out_captures.len());
    let validation_available = replay_oracle.is_some() && !input.held_out_captures.is_empty();
    let differential_count = differential_experiments.len() as f64;
    let differential_bonus = if differential_count > 0.0 { 0.05 } else { 0.0 };
    let direct_bonus = if plan.direct_chunk_evidence {
        0.10
    } else {
        0.0
    };
    let confidence = (training_rate * 0.25
        + held_out_rate * 0.60
        + f64::from(validation_available) * 0.05
        + differential_bonus
        + direct_bonus)
        .min(1.0);
    let human_assist_needed = plan.unknown_chunk_literals
        || !validation_available
        || held_out_rate < 1.0
        || training_rate < 1.0;
    let hypothesis_id = stable_hypothesis_id(&plan);
    let mut provenance = plan.provenance;
    if plan.direct_chunk_evidence {
        provenance.push(InferenceProvenance {
            source_type: SourceType::DynamicCapture,
            detail: format!(
                "Ordered chunk correlation matched {training_matches}/{} training preimages.",
                input.training_captures.len()
            ),
        });
    }
    if !differential_experiments.is_empty() {
        provenance.push(InferenceProvenance {
            source_type: SourceType::Fusion,
            detail: format!(
                "Compared {} differential capture pair(s) to test inclusion and ordering.",
                differential_experiments.len()
            ),
        });
    }
    if validation_available {
        provenance.push(InferenceProvenance {
            source_type: SourceType::DynamicCapture,
            detail: format!(
                "Held-out replay matched {held_out_matches}/{} capture(s).",
                input.held_out_captures.len()
            ),
        });
    }
    CanonicalizationHypothesis {
        hypothesis_id,
        description: plan.description,
        components: plan.components,
        delimiter: plan.delimiter,
        scheme_shortcut: plan.shortcut,
        provenance,
        training_matches,
        training_total: input.training_captures.len(),
        held_out_matches,
        held_out_total: input.held_out_captures.len(),
        held_out_validation_available: validation_available,
        confidence,
        human_assist_needed,
        fixtures,
    }
}

fn stable_hypothesis_id(plan: &CandidatePlan) -> String {
    let mut value = plan.description.replace(' ', "-");
    if plan.direct_chunk_evidence {
        value.push_str("-ordered-updates");
    }
    if !plan.delimiter.is_empty() {
        value.push_str("-delimited");
    }
    value
}

fn ratio(matched: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        matched as f64 / total as f64
    }
}

fn partial_reason(input: &InferenceInput, replay_oracle: Option<&dyn ReplayOracle>) -> String {
    if input.held_out_captures.is_empty() {
        return "No held-out captures were supplied; training fit is not proof of generalization."
            .to_owned();
    }
    if replay_oracle.is_none() {
        return "Held-out captures exist, but no replay oracle was supplied to validate signatures.".to_owned();
    }
    "No candidate reproduced every held-out signature, or the candidate contains an unobserved transform.".to_owned()
}

fn render_plan(
    components: &[CanonicalComponent],
    delimiter: &[u8],
    request: &RequestSnapshot,
) -> Vec<u8> {
    let mut rendered = Vec::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            rendered.extend_from_slice(delimiter);
        }
        if let Some(bytes) = render_component(component, request) {
            rendered.extend_from_slice(&bytes);
        }
    }
    rendered
}

fn render_component(component: &CanonicalComponent, request: &RequestSnapshot) -> Option<Vec<u8>> {
    let raw = match &component.source {
        CanonicalSource::Method => request.method.as_bytes().to_vec(),
        CanonicalSource::Path => request.path.as_bytes().to_vec(),
        CanonicalSource::Query | CanonicalSource::SortedQuery => {
            let mut query = request.query.clone();
            if matches!(component.source, CanonicalSource::SortedQuery) {
                query.sort();
            }
            query
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes()
        }
        CanonicalSource::Headers | CanonicalSource::SortedHeaders => {
            let mut headers = request.headers.clone();
            if matches!(component.source, CanonicalSource::SortedHeaders) {
                headers.sort_by(|left, right| {
                    left.0
                        .to_ascii_lowercase()
                        .cmp(&right.0.to_ascii_lowercase())
                        .then_with(|| left.1.cmp(&right.1))
                });
            }
            headers
                .into_iter()
                .map(|(key, value)| format!("{key}:{value}"))
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes()
        }
        CanonicalSource::Body => request.body.clone()?,
        CanonicalSource::Timestamp => request.timestamp.clone()?.into_bytes(),
        CanonicalSource::Nonce => request.nonce.clone()?.into_bytes(),
        CanonicalSource::Literal(bytes) => bytes.clone(),
    };
    Some(apply_encoding(&raw, &component.encoding))
}

fn apply_encoding(bytes: &[u8], encoding: &ValueEncoding) -> Vec<u8> {
    match encoding {
        ValueEncoding::Raw => bytes.to_vec(),
        ValueEncoding::PercentEncoded => percent_encode(bytes, false),
        ValueEncoding::FormEncoded => percent_encode(bytes, true),
        ValueEncoding::HexLower => bytes
            .iter()
            .flat_map(|byte| format!("{byte:02x}").into_bytes())
            .collect(),
        ValueEncoding::Base64 => base64_encode(bytes, false),
        ValueEncoding::Base64Url => base64_encode(bytes, true),
    }
}

fn percent_encode(bytes: &[u8], form: bool) -> Vec<u8> {
    let mut result = Vec::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(*byte);
        } else if form && *byte == b' ' {
            result.push(b'+');
        } else {
            result.extend_from_slice(format!("%{byte:02X}").as_bytes());
        }
    }
    result
}

fn base64_encode(bytes: &[u8], url_safe: bool) -> Vec<u8> {
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let alphabet = if url_safe { URL_SAFE } else { STANDARD };
    let mut result = Vec::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or_default() as u32;
        let third = chunk.get(2).copied().unwrap_or_default() as u32;
        let value = (first << 16) | (second << 8) | third;
        result.push(alphabet[((value >> 18) & 0x3f) as usize]);
        result.push(alphabet[((value >> 12) & 0x3f) as usize]);
        if chunk.len() > 1 {
            result.push(alphabet[((value >> 6) & 0x3f) as usize]);
        } else if !url_safe {
            result.push(b'=');
        }
        if chunk.len() > 2 {
            result.push(alphabet[(value & 0x3f) as usize]);
        } else if !url_safe {
            result.push(b'=');
        }
    }
    result
}

fn outcome_diagnostic(
    outcome: &InferenceOutcome,
    training_capture_ids: &[String],
    held_out_capture_ids: &[String],
) -> Diagnostic {
    let (definition, reason, confidence) = match outcome {
        InferenceOutcome::Reproducible { hypotheses } => (
            catalogue::CRYPTO_CANONICALIZATION_RECOVERED,
            "Held-out replay succeeded for the leading canonicalization hypothesis.".to_owned(),
            hypotheses.first().map(|hypothesis| hypothesis.confidence),
        ),
        InferenceOutcome::PartialHypothesis { hypotheses, reason } => (
            catalogue::CRYPTO_CANONICALIZATION_HYPOTHESIS_REVIEW,
            reason.clone(),
            hypotheses.first().map(|hypothesis| hypothesis.confidence),
        ),
        InferenceOutcome::ObservedOnly { reason, .. } => (
            catalogue::CRYPTO_CANONICALIZATION_NOT_RECOVERABLE,
            reason.clone(),
            None,
        ),
        InferenceOutcome::Blocked { reason } => (
            catalogue::CRYPTO_CANONICALIZATION_BLOCKED,
            reason.clone(),
            None,
        ),
    };
    let mut context = DiagnosticContext::new();
    context.insert(
        "training_capture_ids".to_owned(),
        DiagnosticValue::StringList(training_capture_ids.to_vec()),
    );
    context.insert(
        "held_out_capture_ids".to_owned(),
        DiagnosticValue::StringList(held_out_capture_ids.to_vec()),
    );
    context.insert("reason".to_owned(), DiagnosticValue::String(reason));
    if let Some(confidence) = confidence {
        context.insert(
            "confidence".to_owned(),
            DiagnosticValue::String(format!("{confidence:.3}")),
        );
    }
    definition.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_crypto_capture::{KeyCapture, KeyExportability, Primitive};

    fn capture(
        id: &str,
        method: &str,
        path: &str,
        body: &[u8],
        preimage: &[u8],
        output: &[u8],
        updates: Vec<UpdateChunk>,
    ) -> CanonicalizationCapture {
        CanonicalizationCapture {
            capture_id: id.to_owned(),
            request: RequestSnapshot {
                request_id: Some(id.to_owned()),
                flow_id: Some(1),
                method: method.to_owned(),
                path: path.to_owned(),
                query: vec![("a".to_owned(), "1".to_owned())],
                headers: vec![("x-test".to_owned(), "yes".to_owned())],
                body: Some(body.to_vec()),
                timestamp: None,
                nonce: None,
            },
            operation: CryptoCaptureRecord {
                schema_version: 1,
                operation_id: format!("op-{id}"),
                primitive: Primitive::Mac,
                algorithm: Some("HmacSHA256".to_owned()),
                provider: None,
                key: KeyCapture {
                    exportability: KeyExportability::Exportable,
                    ..KeyCapture::default()
                },
                updates,
                accumulated_message: preimage.to_vec(),
                primitive_output: Some(output.to_vec()),
                update_outputs: Vec::new(),
                wire_output: Vec::new(),
                stacks: Vec::new(),
                thread_id: None,
                request_id: Some(id.to_owned()),
                flow_id: Some(1),
                reused_after_finalize: false,
            },
        }
    }

    struct EchoOracle;

    impl ReplayOracle for EchoOracle {
        fn replay(
            &self,
            capture: &CanonicalizationCapture,
            canonical_bytes: &[u8],
        ) -> Option<Vec<u8>> {
            let mut output = canonical_bytes.to_vec();
            output.extend_from_slice(capture.request.method.as_bytes());
            Some(output)
        }
    }

    #[test]
    fn ordered_updates_are_correlated_before_generic_candidates() {
        let updates = vec![
            UpdateChunk {
                method: "update(String)".to_owned(),
                bytes: b"GET".to_vec(),
                source_offset: None,
                source_length: None,
                byte_buffer: false,
            },
            UpdateChunk {
                method: "update(String)".to_owned(),
                bytes: b"\n".to_vec(),
                source_offset: None,
                source_length: None,
                byte_buffer: false,
            },
            UpdateChunk {
                method: "update(String)".to_owned(),
                bytes: b"/items".to_vec(),
                source_offset: None,
                source_length: None,
                byte_buffer: false,
            },
        ];
        let first = capture(
            "one",
            "GET",
            "/items",
            b"",
            b"GET\n/items",
            b"GET\n/itemsGET",
            updates.clone(),
        );
        let second = capture(
            "two",
            "POST",
            "/items",
            b"",
            b"POST\n/items",
            b"POST\n/itemsPOST",
            vec![
                UpdateChunk {
                    bytes: b"POST".to_vec(),
                    ..updates[0].clone()
                },
                updates[1].clone(),
                updates[2].clone(),
            ],
        );
        let input = InferenceInput {
            training_captures: vec![first],
            held_out_captures: vec![second],
            scheme_shortcut: Some(ReproductionShortcut::CustomHmac),
            blocked_reason: None,
        };
        let result = CanonicalizationInferer::default().infer(&input, Some(&EchoOracle));
        match result.outcome {
            InferenceOutcome::Reproducible { hypotheses } => {
                assert_eq!(hypotheses[0].description, "ordered Phase 4.1 update chunks");
                assert_eq!(hypotheses[0].held_out_matches, 1);
                assert!(hypotheses[0].scheme_shortcut.is_some());
            }
            other => panic!("expected reproducible result, got {other:?}"),
        }
    }

    #[test]
    fn held_out_failure_is_partial_and_keeps_fixtures() {
        let first = capture("one", "GET", "/a", b"", b"GET/a", b"GET/aGET", Vec::new());
        let held_out = capture("two", "POST", "/b", b"", b"POST/b", b"wrong", Vec::new());
        let input = InferenceInput {
            training_captures: vec![first],
            held_out_captures: vec![held_out],
            ..InferenceInput::default()
        };
        let result = CanonicalizationInferer::default().infer(&input, Some(&EchoOracle));
        match result.outcome {
            InferenceOutcome::PartialHypothesis { hypotheses, .. } => {
                assert!(!hypotheses.is_empty());
                assert_eq!(hypotheses[0].fixtures.len(), 2);
            }
            other => panic!("expected partial result, got {other:?}"),
        }
    }

    #[test]
    fn differential_pairs_classify_single_property() {
        let left = capture("one", "GET", "/a", b"", b"GET/a", b"x", Vec::new());
        let right = capture("two", "GET", "/b", b"", b"GET/b", b"y", Vec::new());
        let left_ref = &left;
        let right_ref = &right;
        let experiments = build_differential_experiments(&[left_ref, right_ref]);
        assert_eq!(experiments.len(), 1);
        assert_eq!(experiments[0].property, DifferentialProperty::Path);
        assert!(experiments[0].preimage_changed);
    }

    #[test]
    fn blocked_and_observed_only_are_first_class() {
        let blocked = CanonicalizationInferer::default().infer(
            &InferenceInput {
                blocked_reason: Some("anti-hooking hid the preimage".to_owned()),
                ..InferenceInput::default()
            },
            None,
        );
        assert!(matches!(blocked.outcome, InferenceOutcome::Blocked { .. }));

        let observed = CanonicalizationInferer::default().infer(&InferenceInput::default(), None);
        assert!(matches!(
            observed.outcome,
            InferenceOutcome::ObservedOnly { .. }
        ));
    }
}
