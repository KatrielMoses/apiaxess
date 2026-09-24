//! Crash-durable session traffic storage and HAR interchange.

use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_session::{ScopeDisposition, Session, SessionDocument, WorkbenchStateSlot};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current normalized traffic payload schema stored in the canonical session.
pub const TRAFFIC_SCHEMA_VERSION: u32 = 1;
const TRAFFIC_SCHEMA_ID: &str = "workbench.traffic";
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Process-wide sequence for unique content-addressed blob temp filenames, so
/// concurrent writers of the same blob never share (and stomp) a temp path.
static BLOB_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// How a recorded flow entered the traffic store.
///
/// Every flow is written through one path, so the origin is tagged at write
/// time and used as a read-time filter: the Live traffic list and the fused API
/// surface show only [`FlowOrigin::Capture`] flows, while tool-synthesized
/// traffic ([`FlowOrigin::Resend`] / [`FlowOrigin::Fuzz`]) stays recorded but
/// hidden so the Resend history and Fuzz results views keep working and a future
/// "show attack traffic" toggle remains possible.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowOrigin {
    /// Observed proxy traffic — the only origin surfaced by default.
    #[default]
    Capture,
    /// A request replayed by the Resend tool.
    Resend,
    /// A request synthesized by the Fuzz tool.
    Fuzz,
}

impl FlowOrigin {
    /// Stable lowercase token used for the durable `origin` column.
    #[must_use]
    pub fn as_db_str(self) -> &'static str {
        match self {
            FlowOrigin::Capture => "capture",
            FlowOrigin::Resend => "resend",
            FlowOrigin::Fuzz => "fuzz",
        }
    }

    /// Parses a durable `origin` token, defaulting unknown/legacy values to
    /// [`FlowOrigin::Capture`].
    #[must_use]
    pub fn from_db_str(value: &str) -> Self {
        match value {
            "resend" => FlowOrigin::Resend,
            "fuzz" => FlowOrigin::Fuzz,
            _ => FlowOrigin::Capture,
        }
    }
}

/// One captured flow accepted by the durable store.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowCapture {
    /// Stable session-local flow identifier.
    pub id: u64,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// Negotiated protocol.
    pub protocol: String,
    /// HTTP method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Exact request URL, including scheme, authority, port, path, and query.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Request path and query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Response status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Request headers.
    pub request_headers: Vec<(String, String)>,
    /// Response headers.
    pub response_headers: Vec<(String, String)>,
    /// Request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Vec<u8>>,
    /// Response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<Vec<u8>>,
    /// Advisory engagement-scope classification.
    pub scope: ScopeDisposition,
    /// Capture provenance.
    pub provenance: String,
    /// How this flow entered the store (capture vs. Resend/Fuzz-synthesized).
    #[serde(default)]
    pub origin: FlowOrigin,
}

/// Metadata-only flow row for list views.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    /// Stable flow identifier.
    pub id: u64,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// Negotiated protocol.
    pub protocol: String,
    /// HTTP method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Exact request URL, including scheme, authority, port, path, and query.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Request path and query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Response status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Response content type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Request body size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_size: Option<u64>,
    /// Response body size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_size: Option<u64>,
    /// Scope classification.
    pub scope: ScopeDisposition,
    /// Capture provenance.
    pub provenance: String,
    /// How this flow entered the store (capture vs. Resend/Fuzz-synthesized).
    #[serde(default)]
    pub origin: FlowOrigin,
}

/// Editable HTTP request held by one resend context or revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendRequest {
    /// HTTP method.
    pub method: String,
    /// Absolute request URL.
    pub url: String,
    /// Header names and values in user-editable order.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// Response captured from one resend send.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u64,
    /// HTTP version from the upstream status line (e.g. `HTTP/1.1`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    /// Reason phrase from the upstream status line (e.g. `Found`), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One append-only resend send revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendRevision {
    /// One-based revision number within its context.
    pub revision: u64,
    /// Send timestamp.
    pub sent_at: DateTime<Utc>,
    /// Exact request sent.
    pub request: ResendRequest,
    /// Response, when the upstream exchange completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResendResponse>,
    /// Stable diagnostic when the send or persistence failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
    /// Advisory scope classification at send time.
    pub scope: ScopeDisposition,
    /// Redirect hops followed to reach this request (empty for a direct send).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_chain: Vec<RedirectHop>,
    /// The revision whose 3xx this request followed, when it is a redirect hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followed_from: Option<u64>,
}

/// Independent resend tab/context with a linear append-only history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendContext {
    /// Stable session-local context identifier.
    pub id: String,
    /// Captured flow from which this context was created, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_flow_id: Option<u64>,
    /// Context creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Current editable request.
    pub current: ResendRequest,
    /// Append-only sends, including failed attempts.
    pub history: Vec<ResendRevision>,
    /// Operator-given label for the queue and panel title; absent = derived
    /// from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Request field where a fuzzer payload is substituted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerPositionLocation {
    /// Position in the complete URL, including path and query.
    Url,
    /// Position in a named header value.
    Header,
    /// Position in the UTF-8 request body.
    Body,
}

/// One marked payload position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadPosition {
    /// Field containing the position.
    pub location: FuzzerPositionLocation,
    /// Header name when the location is `Header`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    /// Inclusive byte offset.
    pub start: usize,
    /// Exclusive byte offset.
    pub end: usize,
    /// Payload set used by this position.
    pub set_index: usize,
}

/// A payload set: how raw values are produced (`source`), an ordered
/// per-value processing pipeline (`processors`), and an optional final
/// URL-encode step (`url_encode_chars`).
///
/// Deserialization is backward compatible with the legacy shape
/// `{ "name": ..., "values": [...] }`, which is mapped to a
/// [`PayloadSource::SimpleList`] with an empty pipeline so old persisted jobs
/// still load.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadSet {
    /// Human-readable payload-set label.
    pub name: String,
    /// How raw payload values are produced.
    pub source: PayloadSource,
    /// Ordered processing pipeline applied to each raw value before insertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processors: Vec<PayloadProcessor>,
    /// Burp-style "URL-encode these characters", applied after all processors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_encode_chars: Option<String>,
}

impl<'de> Deserialize<'de> for PayloadSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // A permissive intermediate that accepts both the current shape and the
        // legacy `{ name, values }` shape. When `source` is absent the legacy
        // `values` list becomes a `SimpleList`, preserving old persisted jobs.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Compat {
            name: String,
            #[serde(default)]
            source: Option<PayloadSource>,
            #[serde(default)]
            processors: Vec<PayloadProcessor>,
            #[serde(default)]
            url_encode_chars: Option<String>,
            #[serde(default)]
            values: Option<Vec<String>>,
        }
        let compat = Compat::deserialize(deserializer)?;
        let source = compat.source.unwrap_or(PayloadSource::SimpleList {
            values: compat.values.unwrap_or_default(),
        });
        Ok(Self {
            name: compat.name,
            source,
            processors: compat.processors,
            url_encode_chars: compat.url_encode_chars,
        })
    }
}

/// How a payload set produces its raw values, before processing.
///
/// Every variant is designed to be generated lazily so astronomically large
/// sources (numbers, brute-force, cluster products) never materialize a full
/// list. Payloads are UTF-8 strings; variants that describe non-UTF-8 bytes
/// (illegal Unicode, bit flips, block shuffles) emit the standard textual
/// representation used to deliver those bytes over HTTP (percent-encoding or
/// ASCII-hex), which is documented on each variant.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PayloadSource {
    /// A literal, caller-managed list of values.
    SimpleList {
        /// Values emitted in order.
        values: Vec<String>,
    },
    /// A file streamed line-by-line at run time; never fully materialized.
    RuntimeFile {
        /// Absolute path to the newline-delimited payload file.
        path: PathBuf,
    },
    /// Up to eight ordered slots whose cross-product is joined into one value.
    CustomIterator {
        /// Ordered slots; each slot contributes one item per emitted value.
        slots: Vec<IteratorSlot>,
    },
    /// Each base value with every character-substitution rule applied.
    CharacterSubstitution {
        /// Base values transformed by the rules.
        base: Vec<String>,
        /// Ordered `(from, to)` character replacements applied to each base.
        rules: Vec<CharacterRule>,
    },
    /// Each base value emitted once per selected case transform.
    CaseModification {
        /// Base values transformed by the modes.
        base: Vec<String>,
        /// Case transforms applied, one emitted value each.
        modes: Vec<CaseMode>,
    },
    /// Payloads seeded from a previous response's extract item (Grep-Extract).
    ///
    /// Runs only in sequential mode and requires a configured extract item;
    /// until that is wired it is validate-rejected rather than silently no-op.
    RecursiveGrep {
        /// Initial seed values used before any extract feedback exists.
        seed: Vec<String>,
    },
    /// Illegal / overlong UTF-8 encodings of a target character, spliced into
    /// each base value and emitted percent-encoded (e.g. `%C0%AE` for `.`).
    IllegalUnicode {
        /// Base values the illegal encodings are spliced into.
        base: Vec<String>,
        /// Character whose illegal encodings are generated.
        target: char,
    },
    /// A single item repeated in growing blocks from `min` to `max` by `step`.
    CharacterBlocks {
        /// The repeated unit.
        item: String,
        /// Smallest repeat count (inclusive).
        min: usize,
        /// Largest repeat count (inclusive).
        max: usize,
        /// Repeat-count increment.
        step: usize,
    },
    /// A numeric range, formatted per radix and digit padding.
    Numbers {
        /// Range start (inclusive).
        from: f64,
        /// Range end (inclusive).
        to: f64,
        /// Step between successive numbers; sign is honored for descending.
        step: f64,
        /// Sequential stepping or uniformly random draws within the range.
        order: NumberOrder,
        /// Decimal or hexadecimal formatting.
        radix: NumberRadix,
        /// Minimum integer digits, left-padded with zeros.
        min_integer_digits: usize,
        /// Maximum fractional digits retained.
        max_fraction_digits: usize,
    },
    /// A date range formatted with a `chrono` format string.
    Dates {
        /// Range start (inclusive), `YYYY-MM-DD`.
        from: chrono::NaiveDate,
        /// Range end (inclusive), `YYYY-MM-DD`.
        to: chrono::NaiveDate,
        /// Days between successive dates.
        step_days: i64,
        /// `chrono` strftime format string.
        format: String,
    },
    /// Every string over `charset` from `min_len` to `max_len` characters.
    BruteForcer {
        /// Alphabet drawn from, one position at a time.
        charset: String,
        /// Shortest generated length (inclusive).
        min_len: usize,
        /// Longest generated length (inclusive).
        max_len: usize,
    },
    /// Empty payloads, either a fixed count or continuously (capped at run time).
    NullPayloads {
        /// How many empty payloads to emit.
        count: NullCount,
    },
    /// Each base value with one character position incremented by one code, one
    /// emitted value per position.
    CharacterFrobber {
        /// Base values frobbed one position at a time.
        base: Vec<String>,
    },
    /// Each base value with a single bit flipped, one emitted value per bit.
    BitFlipper {
        /// Base values whose bits are flipped.
        base: Vec<String>,
        /// Whether the base is literal text or an ASCII-hex byte string.
        format: BitFlipFormat,
    },
    /// Common username schemes derived from full names or email addresses.
    UsernameGenerator {
        /// Full names (`First Last`) or email addresses.
        names: Vec<String>,
    },
    /// Every block-ordering (permutation) of each base value split into fixed
    /// `block_size` byte blocks; emitted percent-encoded when not valid UTF-8.
    EcbBlockShuffler {
        /// Base values split into blocks.
        base: Vec<String>,
        /// Block size in bytes.
        block_size: usize,
    },
    /// Mirrors another position's current payload; only meaningful in Pitchfork
    /// and Cluster bomb, where it is slaved to the referenced position.
    CopyOtherPayload {
        /// Index of the position whose current value is mirrored.
        source_position: usize,
    },
}

impl PayloadSet {
    /// Whether this set is trivially empty — a simple list with no values.
    /// Generated sources (numbers, brute-force, dates, …) are never trivially
    /// empty; their emptiness, if any, only becomes known at generation time.
    #[must_use]
    pub fn is_trivially_empty(&self) -> bool {
        matches!(&self.source, PayloadSource::SimpleList { values } if values.is_empty())
    }
}

/// One slot of a [`PayloadSource::CustomIterator`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IteratorSlot {
    /// Items this slot cycles through.
    pub items: Vec<String>,
    /// Separator emitted immediately before this slot's item.
    pub separator: String,
}

/// One character-substitution rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CharacterRule {
    /// Character to replace.
    pub from: char,
    /// Replacement character.
    pub to: char,
}

/// A case transform applied by [`PayloadSource::CaseModification`] and the
/// [`PayloadProcessor::ModifyCase`] processor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseMode {
    /// Lowercase every character.
    Lower,
    /// Uppercase every character.
    Upper,
    /// Uppercase the first character, lowercase the rest (per whitespace word).
    Propercase,
    /// Swap the case of every character.
    Toggle,
}

/// Stepping order for [`PayloadSource::Numbers`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberOrder {
    /// Deterministic stepped sequence from `from` to `to`.
    Sequential,
    /// Uniformly random draws within `[from, to]` (with replacement).
    Random,
}

/// Numeric radix for [`PayloadSource::Numbers`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumberRadix {
    /// Base-10 formatting, honoring the digit-padding settings.
    Dec,
    /// Base-16 formatting of the integer value.
    Hex,
}

/// How many empty payloads [`PayloadSource::NullPayloads`] emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullCount {
    /// Exactly this many empty payloads.
    Fixed(u64),
    /// Emit continuously; the run loop caps it at `max_results`.
    Continuous,
}

/// How [`PayloadSource::BitFlipper`] interprets its base values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitFlipFormat {
    /// Base is literal text; output is percent-encoded when not valid UTF-8.
    Literal,
    /// Base is an ASCII-hex byte string; output is re-encoded as ASCII hex.
    AsciiHex,
}

/// One ordered processing step applied to each generated payload before it is
/// inserted. `apply` returning `None` drops the payload (it is not sent).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum PayloadProcessor {
    /// Prepend a fixed string.
    AddPrefix {
        /// Text placed before the value.
        text: String,
    },
    /// Append a fixed string.
    AddSuffix {
        /// Text placed after the value.
        text: String,
    },
    /// Replace regex matches with a replacement string.
    MatchReplace {
        /// Rust regex pattern.
        pattern: String,
        /// Replacement (supports `$1` capture references).
        replacement: String,
    },
    /// Keep a substring starting at `from` for an optional `length`.
    Substring {
        /// Start character offset.
        from: usize,
        /// Optional length in characters; to the end when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
    },
    /// Keep a substring counted from the end.
    ReverseSubstring {
        /// Offset from the end.
        from: usize,
        /// Optional length in characters; to the end when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<usize>,
    },
    /// Apply a case transform.
    ModifyCase {
        /// Case transform applied.
        mode: CaseMode,
    },
    /// Encode the value with a named scheme.
    Encode {
        /// Encoding scheme.
        scheme: EncodeScheme,
    },
    /// Decode the value with a named scheme; drops the payload on failure.
    Decode {
        /// Decoding scheme.
        scheme: DecodeScheme,
    },
    /// Hash the value and emit the digest.
    Hash {
        /// Digest algorithm.
        algorithm: HashAlgorithm,
        /// Digest output encoding.
        output: HashOutput,
    },
    /// Append the pre-processing raw value after the processed value.
    AddRawPayload,
    /// Drop the payload when it matches the regex.
    SkipIfMatchesRegex {
        /// Rust regex pattern; a match drops the payload.
        pattern: String,
    },
}

/// Encoding scheme for [`PayloadProcessor::Encode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodeScheme {
    /// Percent-encode URL-unsafe characters.
    Url,
    /// Percent-encode every character.
    UrlAll,
    /// HTML-entity encode the five reserved characters.
    Html,
    /// Standard Base64.
    Base64,
    /// Lowercase ASCII-hex of the UTF-8 bytes.
    AsciiHex,
}

/// Decoding scheme for [`PayloadProcessor::Decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeScheme {
    /// Percent-decode.
    Url,
    /// HTML-entity decode.
    Html,
    /// Standard Base64 decode.
    Base64,
    /// ASCII-hex decode.
    AsciiHex,
}

/// Digest algorithm for [`PayloadProcessor::Hash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    /// MD5.
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

/// Digest output encoding for [`PayloadProcessor::Hash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashOutput {
    /// Lowercase hexadecimal.
    Hex,
    /// Standard Base64.
    Base64,
}

/// Standard payload combination mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerAttackType {
    /// Test one marked position at a time with a single payload set.
    Sniper,
    /// Place each payload from a single set into every marked position at once.
    BatteringRam,
    /// Cartesian product across payload sets.
    Clusterbomb,
    /// Pair values by ordinal across payload sets.
    Pitchfork,
}

/// Match/filter rules used to surface interesting responses.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerMatchFilter {
    /// Status codes considered interesting; empty means any status.
    pub statuses: Vec<u16>,
    /// Minimum response-body size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u64>,
    /// Maximum response-body size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Literal content that must occur in the response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contains: Option<String>,
    /// Regex content that must match the response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
}

/// Dynamic value extractor used by a stateful sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FuzzerTokenExtractor {
    /// Extract a value from a JSON response using a simple dotted path.
    JsonPath {
        /// Variable name for later `{{variable}}` injection.
        variable: String,
        /// Dotted JSON path, such as `data.csrf`.
        path: String,
    },
    /// Extract a response header.
    Header {
        /// Variable name for later injection.
        variable: String,
        /// Header name, case-insensitive.
        name: String,
    },
    /// Extract the first capture from a response-body regex.
    Regex {
        /// Variable name for later injection.
        variable: String,
        /// Rust regex pattern with one capture group.
        pattern: String,
    },
}

/// One request in a stateful native attack sequence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerSequenceStep {
    /// Step label shown in diagnostics.
    pub name: String,
    /// Request template; `{{variable}}` placeholders are injected before send.
    pub request: ResendRequest,
    /// Values extracted from this response for subsequent steps.
    pub extractors: Vec<FuzzerTokenExtractor>,
}

/// Automatically selected execution tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerTier {
    /// Hidden ffuf subprocess for stateless bulk work.
    Ffuf,
    /// Native Rust sender for stateful/authenticated sequences.
    Native,
}

/// Lifecycle of a fuzzer job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzerJobState {
    /// Created but not yet launched.
    Pending,
    /// Currently generating requests.
    Running,
    /// Temporarily held at a request boundary.
    Paused,
    /// Stopped by the user or session.
    Stopped,
    /// Exhausted its bounded request set.
    Completed,
    /// Failed before normal completion.
    Failed,
}

/// The grep subsystem: additive response inspection that flags and annotates
/// results without filtering them. Distinct from [`FuzzerMatchFilter`], which is
/// the keep/display filter — grep only adds columns (match counts, extracts,
/// reflected counts), it never drops a result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrepConfig {
    /// Named match expressions; each yields an occurrence-count column.
    pub match_rules: Vec<GrepMatchRule>,
    /// Named extract expressions; each yields an extracted-value column.
    pub extract_rules: Vec<GrepExtractRule>,
    /// Reflected-payload detection settings.
    pub reflected: GrepReflectedConfig,
}

/// One named grep-match expression counted per response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrepMatchRule {
    /// Column label.
    pub name: String,
    /// Literal string or regex, per `is_regex`.
    pub pattern: String,
    /// Whether `pattern` is a regex.
    pub is_regex: bool,
    /// Whether matching is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to search the body only (excluding response headers).
    pub exclude_headers: bool,
}

/// One named grep-extract expression producing a per-result value column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrepExtractRule {
    /// Column label.
    pub name: String,
    /// How the value is located in the response.
    pub locator: ExtractLocator,
    /// Hard cap on the extracted string length.
    pub max_length: usize,
    /// Extract only the first occurrence (vs. joining all occurrences).
    pub first_only: bool,
}

/// How a [`GrepExtractRule`] locates its value in the response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ExtractLocator {
    /// The text between a start and end delimiter.
    BetweenDelimiters {
        /// Delimiter that precedes the value.
        start: String,
        /// Delimiter that follows the value.
        end: String,
    },
    /// A regex capture group (group 0 = whole match).
    Regex {
        /// Rust regex pattern.
        pattern: String,
        /// Capture-group index to extract.
        group: usize,
    },
    /// A fixed byte offset and length into the response body.
    Offset {
        /// Start byte offset into the body.
        start: usize,
        /// Number of bytes to take.
        length: usize,
    },
}

/// Reflected-payload detection: counts how often the sent payload appears in the
/// response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct GrepReflectedConfig {
    /// Whether reflected detection is on.
    pub enabled: bool,
    /// Whether reflection matching is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to search the body only (excluding response headers).
    pub exclude_headers: bool,
    /// Also count the pre-URL-encoded form of the payload.
    pub match_pre_url_encoded: bool,
}

/// How the send path follows HTTP redirects during an attack.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectMode {
    /// Never follow; the 3xx is the result.
    Never,
    /// Follow only when the target host equals the original request host.
    OnSite,
    /// Follow only when the target is within the session engagement scope.
    InScope,
    /// Follow every redirect, up to `max_hops`.
    Always,
}

/// Redirect-following policy for an attack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectPolicy {
    /// When to follow redirects.
    pub mode: RedirectMode,
    /// Carry `Set-Cookie` forward across the redirect chain when following.
    pub process_cookies: bool,
    /// Maximum redirects to follow before returning the last response.
    pub max_hops: u8,
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        // Burp-style: do not follow — the 3xx is surfaced as the result (more
        // honest for a security tool, and lets the all-default status-only sweep
        // ride the fast ffuf tier). This is a deliberate change from the prior
        // fuzzer behavior (reqwest silently followed up to 10); operators pick
        // On-site / In-scope / Always to follow. The manual Resend tool is
        // unaffected and still follows.
        Self {
            mode: RedirectMode::Never,
            process_cookies: false,
            max_hops: 10,
        }
    }
}

/// Retry policy for transient transport failures / timeouts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Additional attempts after the first failure (0 = no retry).
    pub max_retries: u32,
    /// Pause between attempts, in milliseconds.
    pub pause_ms: u64,
}

/// Inter-request delay strategy pacing dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum DelayPolicy {
    /// Cap sends per second (0 = unlimited) — the historical control.
    Fixed {
        /// Maximum sends per second; zero means unlimited.
        rate_per_second: u32,
    },
    /// A fixed gap between successive requests.
    Interval {
        /// Milliseconds between requests.
        ms: u64,
    },
    /// A uniformly random gap in `[min_ms, max_ms]` between requests.
    Random {
        /// Minimum gap in milliseconds.
        min_ms: u64,
        /// Maximum gap in milliseconds.
        max_ms: u64,
    },
}

impl Default for DelayPolicy {
    fn default() -> Self {
        Self::Fixed { rate_per_second: 0 }
    }
}

/// One followed redirect hop, recorded on the result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectHop {
    /// The 3xx status that triggered this hop.
    pub status: u16,
    /// The resolved absolute target followed to.
    pub location: String,
}

fn default_true() -> bool {
    true
}

/// Migrates a persisted delay setting: the new `delay` wins; a legacy
/// `rate_per_second` (no `delay`) becomes `DelayPolicy::Fixed`; neither present
/// yields the unlimited default.
fn migrate_delay(delay: Option<DelayPolicy>, rate_per_second: Option<u32>) -> DelayPolicy {
    delay.unwrap_or(DelayPolicy::Fixed {
        rate_per_second: rate_per_second.unwrap_or(0),
    })
}

/// Fuzzer attack configuration persisted with a job.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerConfig {
    /// Request template before payload substitution.
    pub base_request: ResendRequest,
    /// Marked substitution positions.
    pub positions: Vec<PayloadPosition>,
    /// Payload values by set.
    pub payload_sets: Vec<PayloadSet>,
    /// Standard payload combination mode.
    pub attack_type: FuzzerAttackType,
    /// Optional response match/filter rules (the keep/display filter).
    pub match_filter: FuzzerMatchFilter,
    /// Additive grep inspection (match counts, extracts, reflected). Defaults to
    /// empty so legacy configs load unchanged.
    #[serde(default)]
    pub grep: GrepConfig,
    /// Maximum concurrent native requests.
    pub concurrency: usize,
    /// Inter-request delay strategy. Defaults to unlimited fixed rate; a legacy
    /// `ratePerSecond` config is migrated into `Fixed` on load (see the store).
    #[serde(default)]
    pub delay: DelayPolicy,
    /// Per-request retry policy for transient failures/timeouts.
    #[serde(default)]
    pub retry: RetryPolicy,
    /// Redirect-following policy.
    #[serde(default)]
    pub redirect: RedirectPolicy,
    /// Send `Connection: close` on each request.
    #[serde(default)]
    pub connection_close: bool,
    /// Recompute `Content-Length` from the (possibly edited) body. Default true —
    /// already the effective behavior; exposed as a toggle for parity.
    #[serde(default = "default_true")]
    pub update_content_length: bool,
    /// Hard result bound.
    pub max_results: usize,
    /// Optional pre-request authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_preflight: Option<ResendRequest>,
    /// Stateful sequence steps after the optional pre-flight.
    pub sequence: Vec<FuzzerSequenceStep>,
    /// Enable the ffuf soft-404/catch-all auto-calibration (`-ac`) so a wildcard
    /// or WAF site that answers every path does not produce false-positive hits.
    /// Used by directory discovery; absent (false) for everything else.
    #[serde(default)]
    pub auto_calibrate: bool,
}

/// Response comparison features used by the fuzzer UI.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerResponseDiff {
    /// Whether status differs from the prior result.
    pub status_changed: bool,
    /// Whether body length differs from the prior result.
    pub size_changed: bool,
    /// Signed body-size delta from the prior result.
    pub size_delta: i64,
    /// Whether body text differs from the prior result.
    pub content_changed: bool,
}

/// One captured fuzzer result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerResult {
    /// One-based result ordinal.
    pub ordinal: u64,
    /// Payload values used for this request.
    pub payloads: Vec<String>,
    /// Exact request sent.
    pub request: ResendRequest,
    /// Response, when a request completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResendResponse>,
    /// Response match outcome.
    pub matched: bool,
    /// Whether the result was filtered from the primary view.
    pub filtered: bool,
    /// Comparison to the prior response when available.
    pub diff: FuzzerResponseDiff,
    /// Scope classification at send time.
    pub scope: ScopeDisposition,
    /// Failure diagnostic, if any (surfaced as the Error column).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
    /// Whether the request timed out (distinct from a transport error).
    #[serde(default)]
    pub timeout: bool,
    /// User-editable annotation for the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Occurrence count per `grep.match_rules`, in order.
    #[serde(default)]
    pub grep_match_counts: Vec<u32>,
    /// Extracted value per `grep.extract_rules`, in order.
    #[serde(default)]
    pub grep_extracts: Vec<Option<String>>,
    /// Reflected-payload occurrence count, when reflected detection is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflected_count: Option<u32>,
    /// Followed redirect hops (empty when none followed or mode is Never).
    #[serde(default)]
    pub redirect_chain: Vec<RedirectHop>,
    /// Number of retries performed before this result (0 = first attempt).
    #[serde(default)]
    pub retry_count: u32,
}

/// Durable fuzzer job, configuration, state, and bounded results.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FuzzerJob {
    /// Stable session-local job identifier.
    pub id: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Auto-selected execution tier.
    pub tier: FuzzerTier,
    /// Lifecycle state.
    pub state: FuzzerJobState,
    /// Persisted attack configuration.
    pub config: FuzzerConfig,
    /// Captured result rows.
    pub results: Vec<FuzzerResult>,
    /// Job-level diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

/// Redacts sensitive values from a captured flow immediately before it is
/// persisted or surfaced.
///
/// The credential-handling layer installs an implementation so that login
/// secrets the crawler injects into an app can never land in the durable store,
/// the assembled surface, or any export. This is the authoritative choke-point:
/// every write path funnels through [`TrafficStore::upsert`], so a redactor set
/// here scrubs regardless of how the flow was captured.
pub trait FlowRedactor: Send + Sync {
    /// Scrubs registered secret values from the flow's URL, headers, and bodies
    /// in place. Must be idempotent — it may run more than once per flow.
    fn redact(&self, flow: &mut FlowCapture);
}

/// Internal SQLite/blob store owned by one session runtime.
pub struct TrafficStore {
    root: PathBuf,
    blobs: PathBuf,
    connection: Mutex<Connection>,
    redactor: RwLock<Option<Arc<dyn FlowRedactor>>>,
    /// Single authoritative flow-id allocator for this store. Seeded from the
    /// persisted `MAX(id)` at open and advanced atomically, it is the ONE source
    /// of globally-unique flow ids across every concurrent traffic source (live
    /// capture via the proxy, HAR import, and any future source). Reconciling the
    /// former split allocation (a proxy `AtomicU64` plus the store's `MAX(id)+1`)
    /// into this single sequence is what makes concurrent inserts collision-proof,
    /// so no two flows can ever receive the same id and silently overwrite.
    next_flow_id: AtomicU64,
}

impl std::fmt::Debug for TrafficStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrafficStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl TrafficStore {
    /// Opens or creates a session store and verifies `SQLite` integrity.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the runtime directory or database cannot be
    /// created, configured, or passed an integrity check.
    pub fn open(parent: &Path, session_id: &str) -> Result<Self, Diagnostic> {
        let root = Self::session_root(parent, session_id);
        let blobs = root.join("blobs");
        fs::create_dir_all(&blobs).map_err(|e| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "directory",
                &root,
                &e.to_string(),
            )
        })?;
        let database = root.join("traffic.sqlite3");
        let connection = Connection::open(&database).map_err(|e| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "database",
                &database,
                &e.to_string(),
            )
        })?;
        // Preserve durability across the Repeater→Resend / Intruder→Fuzzer
        // rename: carry a legacy store's tables over to the new names. A failure
        // (the old table is absent, or the new one already exists) is expected on
        // fresh or already-migrated stores and is ignored — the CREATE TABLE IF
        // NOT EXISTS below then owns the schema.
        let _ = connection.execute("ALTER TABLE repeater_contexts RENAME TO resend_contexts", []);
        let _ = connection.execute("ALTER TABLE intruder_jobs RENAME TO fuzzer_jobs", []);
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS flows (
               id INTEGER PRIMARY KEY,
               captured_at TEXT NOT NULL,
               protocol TEXT NOT NULL,
               method TEXT,
               host TEXT,
               path TEXT,
               status INTEGER,
               duration_ms INTEGER,
               request_headers TEXT NOT NULL,
               response_headers TEXT NOT NULL,
               request_body_hash TEXT,
               response_body_hash TEXT,
               scope TEXT NOT NULL,
               provenance TEXT NOT NULL,
               url TEXT,
               origin TEXT NOT NULL DEFAULT 'capture'
             );
             CREATE INDEX IF NOT EXISTS flows_captured_at ON flows(captured_at);
             CREATE TABLE IF NOT EXISTS resend_contexts (
               id TEXT PRIMARY KEY,
               source_flow_id INTEGER,
               created_at TEXT NOT NULL,
               current_json TEXT NOT NULL,
               history_json TEXT NOT NULL,
               name TEXT
             );
             CREATE TABLE IF NOT EXISTS fuzzer_jobs (
               id TEXT PRIMARY KEY,
               created_at TEXT NOT NULL,
               tier TEXT NOT NULL,
               state TEXT NOT NULL,
               config_json TEXT NOT NULL,
               results_json TEXT NOT NULL,
               diagnostics_json TEXT NOT NULL
             );
             PRAGMA user_version=1;",
            )
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_STORE_OPEN_FAILED,
                    "schema",
                    &database,
                    &e.to_string(),
                )
            })?;
        ensure_columns(&connection, &database)?;
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_STORE_CORRUPT,
                    "integrity",
                    &database,
                    &e.to_string(),
                )
            })?;
        if integrity != "ok" {
            return Err(storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "integrity",
                &database,
                &integrity,
            ));
        }
        // Seed the id allocator above every persisted flow so a reopened session
        // (resume) never reissues an id that already exists on disk.
        let seed = seed_next_flow_id(&connection, &database)?;
        Ok(Self {
            root,
            blobs,
            connection: Mutex::new(connection),
            redactor: RwLock::new(None),
            next_flow_id: AtomicU64::new(seed),
        })
    }

    /// Allocates the next globally-unique flow id for this store.
    ///
    /// This is the single authority for flow ids. Every traffic source — live
    /// capture (through the proxy), HAR import, and any future concurrent source —
    /// must obtain ids here, so simultaneous allocations can never collide and
    /// silently overwrite one another in the `flows` table. The allocation is a
    /// single atomic step, correct under concurrent access.
    #[must_use]
    pub fn allocate_flow_id(&self) -> u64 {
        self.next_flow_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Installs a redactor consulted on every durable write.
    ///
    /// Setting this before any credential is injected guarantees no secret is
    /// ever written to the store, even transiently.
    pub fn set_redactor(&self, redactor: Arc<dyn FlowRedactor>) {
        if let Ok(mut current) = self.redactor.write() {
            *current = Some(redactor);
        }
    }

    /// Clears any installed redactor.
    pub fn clear_redactor(&self) {
        if let Ok(mut current) = self.redactor.write() {
            *current = None;
        }
    }

    /// Returns the deterministic runtime directory for a session identity.
    #[must_use]
    pub fn session_root(parent: &Path, session_id: &str) -> PathBuf {
        parent.join(format!("session-{}", digest_hex(session_id.as_bytes())))
    }

    /// Runtime directory containing `SQLite` and blobs.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `SQLite` database path.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.root.join("traffic.sqlite3")
    }

    /// Upserts one flow and durably commits its metadata/body references.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when validation, blob durability, serialization,
    /// or the metadata transaction fails.
    pub fn upsert(&self, flow: &FlowCapture) -> Result<(), Diagnostic> {
        // Redact registered credential values before anything touches disk: the
        // content-addressed body blobs and header JSON are written below, so
        // scrubbing must happen on an owned copy first. When no redactor is
        // installed this is a zero-cost borrow of the original.
        let redacted;
        let flow = match self.redactor.read().ok().and_then(|guard| guard.clone()) {
            Some(redactor) => {
                let mut owned = flow.clone();
                redactor.redact(&mut owned);
                redacted = owned;
                &redacted
            }
            None => flow,
        };
        validate_flow(flow)?;
        let request_hash = self.write_blob(flow.request_body.as_deref())?;
        let response_hash = self.write_blob(flow.response_body.as_deref())?;
        let request_headers = serde_json::to_string(&flow.request_headers)
            .map_err(|e| serialization_diag("request_headers", &e.to_string()))?;
        let response_headers = serde_json::to_string(&flow.response_headers)
            .map_err(|e| serialization_diag("response_headers", &e.to_string()))?;
        let scope = serde_json::to_string(&flow.scope)
            .map_err(|e| serialization_diag("scope", &e.to_string()))?;
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection.execute(
            "INSERT INTO flows (id,captured_at,protocol,method,host,path,status,duration_ms,request_headers,response_headers,request_body_hash,response_body_hash,scope,provenance,url,origin)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)
             ON CONFLICT(id) DO UPDATE SET captured_at=excluded.captured_at,protocol=excluded.protocol,method=excluded.method,host=excluded.host,path=excluded.path,status=excluded.status,duration_ms=excluded.duration_ms,request_headers=excluded.request_headers,response_headers=excluded.response_headers,request_body_hash=excluded.request_body_hash,response_body_hash=excluded.response_body_hash,scope=excluded.scope,provenance=excluded.provenance,url=excluded.url,origin=excluded.origin",
            params![
                i64::try_from(flow.id).unwrap_or(i64::MAX), flow.captured_at.to_rfc3339_opts(SecondsFormat::Nanos, true), flow.protocol,
                flow.method, flow.host, flow.path, flow.status.map(i64::from),
                flow.duration_ms.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                request_headers, response_headers, request_hash, response_hash, scope, flow.provenance, flow.url, flow.origin.as_db_str(),
            ],
        ).map_err(|e| storage_diag(catalogue::PROXY_STORE_WRITE_FAILED, "flow", &self.root, &e.to_string()))?;
        Ok(())
    }

    /// Reads one complete flow and resolves its content-addressed bodies.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when metadata cannot be read or a referenced blob
    /// is missing or fails its SHA-256 integrity check.
    pub fn get(&self, id: u64) -> Result<Option<FlowCapture>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let parts = connection.query_row(
            "SELECT id,captured_at,protocol,method,host,path,status,duration_ms,request_headers,response_headers,request_body_hash,response_body_hash,scope,provenance,url,origin FROM flows WHERE id=?1",
            params![i64::try_from(id).unwrap_or(i64::MAX)], row_to_parts,
        ).optional().map_err(|e| storage_diag(catalogue::PROXY_STORE_CORRUPT, "read", &self.root, &e.to_string()))?;
        drop(connection);
        parts.map(|parts| self.resolve(parts)).transpose()
    }

    /// Reads metadata-only rows ordered by capture time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the metadata query or stored JSON fields are
    /// invalid.
    pub fn summaries(&self) -> Result<Vec<FlowSummary>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let mut statement = connection.prepare("SELECT id,captured_at,protocol,method,host,path,status,duration_ms,request_body_hash,response_body_hash,response_headers,scope,provenance,url,origin FROM flows ORDER BY captured_at,id")
            .map_err(|e| storage_diag(catalogue::PROXY_STORE_CORRUPT, "query", &self.root, &e.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                let captured: String = row.get(1)?;
                let response_headers: String = row.get(10)?;
                let scope: String = row.get(11)?;
                Ok(FlowSummary {
                    id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or_default(),
                    captured_at: parse_time(&captured),
                    protocol: row.get(2)?,
                    method: row.get(3)?,
                    host: row.get(4)?,
                    path: row.get(5)?,
                    status: row
                        .get::<_, Option<i64>>(6)?
                        .and_then(|v| u16::try_from(v).ok()),
                    duration_ms: row
                        .get::<_, Option<i64>>(7)?
                        .and_then(|v| u64::try_from(v).ok()),
                    content_type: serde_json::from_str::<Vec<(String, String)>>(&response_headers)
                        .ok()
                        .and_then(|headers| {
                            headers.into_iter().find_map(|(name, value)| {
                                name.eq_ignore_ascii_case("content-type").then_some(value)
                            })
                        }),
                    request_size: row
                        .get::<_, Option<String>>(8)?
                        .and_then(|h| self.blob_size(&h)),
                    response_size: row
                        .get::<_, Option<String>>(9)?
                        .and_then(|h| self.blob_size(&h)),
                    scope: serde_json::from_str(&scope).unwrap_or(ScopeDisposition::Undetermined),
                    provenance: row.get(12)?,
                    url: row.get(13)?,
                    origin: FlowOrigin::from_db_str(&row.get::<_, String>(14)?),
                })
            })
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_STORE_CORRUPT,
                    "query",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| {
            storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "row",
                &self.root,
                &e.to_string(),
            )
        })
    }

    /// Returns the normalized portable traffic snapshot.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when any stored flow cannot be rehydrated.
    pub fn snapshot(&self) -> Result<TrafficSnapshot, Diagnostic> {
        let mut flows = Vec::new();
        for summary in self.summaries()? {
            let Some(flow) = self.get(summary.id)? else {
                return Err(storage_diag(
                    catalogue::PROXY_STORE_CORRUPT,
                    "snapshot",
                    &self.root,
                    "flow disappeared during snapshot",
                ));
            };
            flows.push(CanonicalFlow::from_capture(&flow));
        }
        Ok(TrafficSnapshot {
            schema_version: TRAFFIC_SCHEMA_VERSION,
            flows,
            resend_contexts: self.resend_contexts()?,
            fuzzer_jobs: self.fuzzer_jobs()?,
        })
    }

    /// Commits normalized traffic into the active canonical session slot.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the snapshot cannot be built or the session
    /// rejects the workbench state slot.
    pub fn commit_to_session(
        &self,
        session: &mut Session,
        at: DateTime<Utc>,
    ) -> Result<(), Diagnostic> {
        let snapshot = self.snapshot()?;
        let payload = serde_json::to_value(snapshot)
            .map_err(|e| serialization_diag("traffic_snapshot", &e.to_string()))?;
        session
            .set_workbench_state(
                Some(WorkbenchStateSlot {
                    schema_id: TRAFFIC_SCHEMA_ID.to_owned(),
                    format_version: TRAFFIC_SCHEMA_VERSION,
                    payload,
                }),
                at,
            )
            .map_err(|e| {
                let mut context = DiagnosticContext::new();
                context.insert("error".to_owned(), DiagnosticValue::String(e.to_string()));
                catalogue::PROXY_STORE_SESSION_COMMIT_FAILED.instantiate(context)
            })
    }

    /// Serializes a complete canonical session after committing traffic.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when commit or JSON serialization fails.
    pub fn serialize_session(
        &self,
        session: &mut Session,
        at: DateTime<Utc>,
    ) -> Result<Vec<u8>, Diagnostic> {
        self.commit_to_session(session, at)?;
        SessionDocument::new(session.clone(), at)
            .to_json_pretty()
            .map_err(|e| {
                let mut context = DiagnosticContext::new();
                context.insert("error".to_owned(), DiagnosticValue::String(e.to_string()));
                catalogue::PROXY_STORE_SESSION_COMMIT_FAILED.instantiate(context)
            })
    }

    /// Rehydrates a fresh runtime store from the canonical traffic slot.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the slot is incompatible, malformed, or a
    /// canonical flow cannot be restored.
    pub fn resume_from_session(&self, session: &Session) -> Result<usize, Diagnostic> {
        let Some(slot) = session.workbench_state() else {
            return Ok(0);
        };
        if slot.schema_id != TRAFFIC_SCHEMA_ID || slot.format_version != TRAFFIC_SCHEMA_VERSION {
            return Err(catalogue::PROXY_STORE_RESUME_FAILED.instantiate(DiagnosticContext::new()));
        }
        let snapshot: TrafficSnapshot =
            serde_json::from_value(slot.payload.clone()).map_err(|e| {
                let mut context = DiagnosticContext::new();
                context.insert("error".to_owned(), DiagnosticValue::String(e.to_string()));
                catalogue::PROXY_STORE_RESUME_FAILED.instantiate(context)
            })?;
        if snapshot.schema_version != TRAFFIC_SCHEMA_VERSION {
            let mut context = DiagnosticContext::new();
            context.insert(
                "found_version".to_owned(),
                DiagnosticValue::Integer(i64::from(snapshot.schema_version)),
            );
            context.insert(
                "supported_version".to_owned(),
                DiagnosticValue::Integer(i64::from(TRAFFIC_SCHEMA_VERSION)),
            );
            return Err(catalogue::PROXY_STORE_RESUME_FAILED.instantiate(context));
        }
        let mut count = 0;
        for flow in snapshot.flows {
            self.upsert(&flow.into_capture()?)?;
            count += 1;
        }
        for context in snapshot.resend_contexts {
            self.upsert_resend(&context)?;
        }
        for job in snapshot.fuzzer_jobs {
            self.upsert_fuzzer(&job)?;
        }
        Ok(count)
    }

    /// Imports HAR entries into the runtime store.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when HAR parsing, body decoding, or persistence
    /// fails.
    pub fn import_har(
        &self,
        bytes: &[u8],
        provenance: &str,
        classify_scope: impl Fn(Option<&str>, Option<&str>) -> ScopeDisposition,
    ) -> Result<usize, Diagnostic> {
        let document: HarDocument = serde_json::from_slice(bytes)
            .map_err(|e| interchange_diag("import", &e.to_string()))?;
        let mut count = 0;
        for entry in document.log.entries {
            // Draw each id from the store's single authoritative allocator so a
            // concurrent import and live capture can never collide on an id.
            let id = self.allocate_flow_id();
            let (host, path) = split_url(&entry.request.url);
            // Classify against the active engagement scope exactly as live capture
            // does, instead of leaving imported flows `Undetermined`. Dynamic
            // fusion only consumes in-scope flows, so an unclassified import fuses
            // into zero endpoints — the "import a HAR, get nothing" bug.
            let scope = classify_scope(host.as_deref(), Some(entry.request.url.as_str()));
            let flow = FlowCapture {
                id,
                captured_at: entry
                    .started_date_time
                    .as_deref()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .map_or_else(Utc::now, |v| v.with_timezone(&Utc)),
                protocol: entry
                    .request
                    .http_version
                    .unwrap_or_else(|| "HTTP/1.1".to_owned()),
                method: Some(entry.request.method),
                host,
                url: Some(entry.request.url),
                path,
                status: Some(entry.response.status),
                duration_ms: entry.time.and_then(har_duration_ms),
                request_headers: entry
                    .request
                    .headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
                response_headers: entry
                    .response
                    .headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
                request_body: match entry.request.post_data {
                    Some(value) => decode_har_body(&value)?,
                    None => None,
                },
                response_body: match entry.response.content {
                    Some(value) => decode_har_body(&value)?,
                    None => None,
                },
                scope,
                provenance: provenance.to_owned(),
                origin: FlowOrigin::Capture,
            };
            self.upsert(&flow)?;
            count += 1;
        }
        Ok(count)
    }

    /// Exports stored flows as HAR interchange bytes.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when stored flows cannot be loaded or the HAR
    /// document cannot be serialized.
    pub fn export_har(&self) -> Result<Vec<u8>, Diagnostic> {
        let mut entries = Vec::new();
        for summary in self.summaries()? {
            if let Some(flow) = self.get(summary.id)? {
                entries.push(HarEntryOut::from_capture(&flow));
            }
        }
        serde_json::to_vec_pretty(&HarDocumentOut {
            log: HarLogOut {
                version: "1.2".to_owned(),
                creator: HarCreator {
                    name: "APIaxess".to_owned(),
                    version: "0.1.0".to_owned(),
                },
                entries,
            },
        })
        .map_err(|e| interchange_diag("export", &e.to_string()))
    }

    /// Persists one resend context and its append-only history.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when request validation, body durability, JSON
    /// serialization, or the metadata transaction fails.
    pub fn upsert_resend(&self, context: &ResendContext) -> Result<(), Diagnostic> {
        validate_resend(context)?;
        let current = self.stored_resend_request(&context.current)?;
        let history = context
            .history
            .iter()
            .map(|entry| self.stored_resend_revision(entry))
            .collect::<Result<Vec<_>, _>>()?;
        let current_json = serde_json::to_string(&current)
            .map_err(|e| serialization_diag("resend.current", &e.to_string()))?;
        let history_json = serde_json::to_string(&history)
            .map_err(|e| serialization_diag("resend.history", &e.to_string()))?;
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_RESEND_HISTORY_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute(
                "INSERT INTO resend_contexts (id,source_flow_id,created_at,current_json,history_json,name)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(id) DO UPDATE SET source_flow_id=excluded.source_flow_id,created_at=excluded.created_at,current_json=excluded.current_json,history_json=excluded.history_json,name=excluded.name",
                params![
                    context.id,
                    context.source_flow_id.map(|id| i64::try_from(id).unwrap_or(i64::MAX)),
                    context.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    current_json,
                    history_json,
                    context.name,
                ],
            )
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_RESEND_HISTORY_FAILED,
                    "write",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Deletes one resend context. Removing an absent id is not an error.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the metadata database cannot be written.
    pub fn remove_resend(&self, id: &str) -> Result<(), Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_RESEND_HISTORY_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute("DELETE FROM resend_contexts WHERE id = ?1", params![id])
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_RESEND_HISTORY_FAILED,
                    "delete",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Loads all resend contexts ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the context table or its serialized request
    /// and history records cannot be read.
    pub fn resend_contexts(&self) -> Result<Vec<ResendContext>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_RESEND_HISTORY_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let mut statement = connection
            .prepare(
                "SELECT id,source_flow_id,created_at,current_json,history_json,name FROM resend_contexts ORDER BY created_at,id",
            )
            .map_err(|e| storage_diag(catalogue::PROXY_RESEND_HISTORY_FAILED, "query", &self.root, &e.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                let current: String = row.get(3)?;
                let history: String = row.get(4)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, String>(2)?,
                    current,
                    history,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_RESEND_HISTORY_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        let mut contexts = Vec::new();
        for row in rows {
            let (id, source_flow_id, created_at, current, history, name) = row.map_err(|e| {
                storage_diag(
                    catalogue::PROXY_RESEND_HISTORY_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
            contexts.push(ResendContext {
                id,
                source_flow_id: source_flow_id.and_then(|id| u64::try_from(id).ok()),
                created_at: parse_time(&created_at),
                current: self.resolve_resend_request(
                    serde_json::from_str(&current)
                        .map_err(|e| serialization_diag("resend.current", &e.to_string()))?,
                )?,
                history: serde_json::from_str::<Vec<StoredResendRevision>>(&history)
                    .map_err(|e| serialization_diag("resend.history", &e.to_string()))?
                    .into_iter()
                    .map(|entry| self.resolve_resend_revision(entry))
                    .collect::<Result<Vec<_>, _>>()?,
                name,
            });
        }
        Ok(contexts)
    }

    /// Persists one bounded fuzzer job and its results.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the job cannot be serialized or committed.
    pub fn upsert_fuzzer(&self, job: &FuzzerJob) -> Result<(), Diagnostic> {
        validate_fuzzer(job)?;
        let config_json = serde_json::to_string(&self.stored_fuzzer_config(&job.config)?)
            .map_err(|e| serialization_diag("fuzzer.config", &e.to_string()))?;
        let results_json = serde_json::to_string(
            &job.results
                .iter()
                .map(|result| self.stored_fuzzer_result(result))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|e| serialization_diag("fuzzer.results", &e.to_string()))?;
        let diagnostics_json = serde_json::to_string(&job.diagnostics)
            .map_err(|e| serialization_diag("fuzzer.diagnostics", &e.to_string()))?;
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute(
                "INSERT INTO fuzzer_jobs (id,created_at,tier,state,config_json,results_json,diagnostics_json)
                 VALUES (?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at,tier=excluded.tier,state=excluded.state,config_json=excluded.config_json,results_json=excluded.results_json,diagnostics_json=excluded.diagnostics_json",
                params![
                    job.id,
                    job.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    serde_json::to_string(&job.tier).unwrap_or_default(),
                    serde_json::to_string(&job.state).unwrap_or_default(),
                    config_json,
                    results_json,
                    diagnostics_json,
                ],
            )
            .map_err(|e| storage_diag(catalogue::PROXY_FUZZER_PERSISTENCE_FAILED, "write", &self.root, &e.to_string()))?;
        Ok(())
    }

    /// Deletes one fuzzer job. Removing an absent id is not an error.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the metadata database cannot be written.
    pub fn remove_fuzzer(&self, id: &str) -> Result<(), Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute("DELETE FROM fuzzer_jobs WHERE id = ?1", params![id])
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                    "delete",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Loads persisted fuzzer jobs ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when a job row or its structured payload is
    /// malformed.
    pub fn fuzzer_jobs(&self) -> Result<Vec<FuzzerJob>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let mut statement = connection
            .prepare("SELECT id,created_at,tier,state,config_json,results_json,diagnostics_json FROM fuzzer_jobs ORDER BY created_at,id")
            .map_err(|e| storage_diag(catalogue::PROXY_FUZZER_PERSISTENCE_FAILED, "query", &self.root, &e.to_string()))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        let mut jobs = Vec::new();
        for row in rows {
            let (id, created_at, tier, state, config, results, diagnostics) = row.map_err(|e| {
                storage_diag(
                    catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
            jobs.push(FuzzerJob {
                id,
                created_at: parse_time(&created_at),
                tier: serde_json::from_str(&tier)
                    .map_err(|e| serialization_diag("fuzzer.tier", &e.to_string()))?,
                state: serde_json::from_str(&state)
                    .map_err(|e| serialization_diag("fuzzer.state", &e.to_string()))?,
                config: self.resolve_fuzzer_config(
                    serde_json::from_str(&config)
                        .map_err(|e| serialization_diag("fuzzer.config", &e.to_string()))?,
                )?,
                results: serde_json::from_str::<Vec<StoredFuzzerResult>>(&results)
                    .map_err(|e| serialization_diag("fuzzer.results", &e.to_string()))?
                    .into_iter()
                    .map(|result| self.resolve_fuzzer_result(result))
                    .collect::<Result<Vec<_>, _>>()?,
                diagnostics: serde_json::from_str(&diagnostics)
                    .map_err(|e| serialization_diag("fuzzer.diagnostics", &e.to_string()))?,
            });
        }
        Ok(jobs)
    }

    fn stored_resend_request(
        &self,
        request: &ResendRequest,
    ) -> Result<StoredResendRequest, Diagnostic> {
        Ok(StoredResendRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body_hash: self.write_blob(request.body.as_deref())?,
        })
    }

    fn stored_fuzzer_config(
        &self,
        config: &FuzzerConfig,
    ) -> Result<StoredFuzzerConfig, Diagnostic> {
        Ok(StoredFuzzerConfig {
            base_request: self.stored_resend_request(&config.base_request)?,
            positions: config.positions.clone(),
            payload_sets: config.payload_sets.clone(),
            attack_type: config.attack_type,
            match_filter: config.match_filter.clone(),
            grep: config.grep.clone(),
            concurrency: config.concurrency,
            delay: Some(config.delay),
            rate_per_second: None,
            retry: config.retry,
            redirect: config.redirect,
            connection_close: config.connection_close,
            update_content_length: config.update_content_length,
            max_results: config.max_results,
            auth_preflight: config
                .auth_preflight
                .as_ref()
                .map(|request| self.stored_resend_request(request))
                .transpose()?,
            sequence: config
                .sequence
                .iter()
                .map(|step| {
                    Ok(StoredFuzzerSequenceStep {
                        name: step.name.clone(),
                        request: self.stored_resend_request(&step.request)?,
                        extractors: step.extractors.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Diagnostic>>()?,
            auto_calibrate: config.auto_calibrate,
        })
    }

    fn resolve_fuzzer_config(
        &self,
        config: StoredFuzzerConfig,
    ) -> Result<FuzzerConfig, Diagnostic> {
        Ok(FuzzerConfig {
            base_request: self.resolve_resend_request(config.base_request)?,
            positions: config.positions,
            payload_sets: config.payload_sets,
            attack_type: config.attack_type,
            match_filter: config.match_filter,
            grep: config.grep,
            concurrency: config.concurrency,
            // Legacy blobs carry `rate_per_second` but no `delay`; migrate it into
            // `DelayPolicy::Fixed` so old jobs pace exactly as before.
            delay: migrate_delay(config.delay, config.rate_per_second),
            retry: config.retry,
            redirect: config.redirect,
            connection_close: config.connection_close,
            update_content_length: config.update_content_length,
            max_results: config.max_results,
            auth_preflight: config
                .auth_preflight
                .map(|request| self.resolve_resend_request(request))
                .transpose()?,
            sequence: config
                .sequence
                .into_iter()
                .map(|step| {
                    Ok(FuzzerSequenceStep {
                        name: step.name,
                        request: self.resolve_resend_request(step.request)?,
                        extractors: step.extractors,
                    })
                })
                .collect::<Result<Vec<_>, Diagnostic>>()?,
            auto_calibrate: config.auto_calibrate,
        })
    }

    fn stored_fuzzer_result(
        &self,
        result: &FuzzerResult,
    ) -> Result<StoredFuzzerResult, Diagnostic> {
        Ok(StoredFuzzerResult {
            ordinal: result.ordinal,
            payloads: result.payloads.clone(),
            request: self.stored_resend_request(&result.request)?,
            response: result
                .response
                .as_ref()
                .map(|response| self.stored_resend_response(response))
                .transpose()?,
            matched: result.matched,
            filtered: result.filtered,
            diff: result.diff.clone(),
            scope: result.scope,
            diagnostic: result.diagnostic.clone(),
            timeout: result.timeout,
            comment: result.comment.clone(),
            grep_match_counts: result.grep_match_counts.clone(),
            grep_extracts: result.grep_extracts.clone(),
            reflected_count: result.reflected_count,
            redirect_chain: result.redirect_chain.clone(),
            retry_count: result.retry_count,
        })
    }

    fn resolve_fuzzer_result(
        &self,
        result: StoredFuzzerResult,
    ) -> Result<FuzzerResult, Diagnostic> {
        Ok(FuzzerResult {
            ordinal: result.ordinal,
            payloads: result.payloads,
            request: self.resolve_resend_request(result.request)?,
            response: result
                .response
                .map(|response| {
                    Ok(ResendResponse {
                        status: response.status,
                        headers: response.headers,
                        body: self.read_blob(response.body_hash.as_deref())?,
                        duration_ms: response.duration_ms,
                        http_version: response.http_version,
                        reason: response.reason,
                    })
                })
                .transpose()?,
            matched: result.matched,
            filtered: result.filtered,
            diff: result.diff,
            scope: result.scope,
            diagnostic: result.diagnostic,
            timeout: result.timeout,
            comment: result.comment,
            grep_match_counts: result.grep_match_counts,
            grep_extracts: result.grep_extracts,
            reflected_count: result.reflected_count,
            redirect_chain: result.redirect_chain,
            retry_count: result.retry_count,
        })
    }

    fn stored_resend_response(
        &self,
        response: &ResendResponse,
    ) -> Result<StoredResendResponse, Diagnostic> {
        Ok(StoredResendResponse {
            status: response.status,
            headers: response.headers.clone(),
            body_hash: self.write_blob(response.body.as_deref())?,
            duration_ms: response.duration_ms,
            http_version: response.http_version.clone(),
            reason: response.reason.clone(),
        })
    }

    fn stored_resend_revision(
        &self,
        revision: &ResendRevision,
    ) -> Result<StoredResendRevision, Diagnostic> {
        Ok(StoredResendRevision {
            revision: revision.revision,
            sent_at: revision.sent_at,
            request: self.stored_resend_request(&revision.request)?,
            response: revision
                .response
                .as_ref()
                .map(|response| self.stored_resend_response(response))
                .transpose()?,
            diagnostic: revision.diagnostic.clone(),
            scope: revision.scope,
            redirect_chain: revision.redirect_chain.clone(),
            followed_from: revision.followed_from,
        })
    }

    fn resolve_resend_request(
        &self,
        request: StoredResendRequest,
    ) -> Result<ResendRequest, Diagnostic> {
        Ok(ResendRequest {
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: self.read_blob(request.body_hash.as_deref())?,
        })
    }

    fn resolve_resend_revision(
        &self,
        revision: StoredResendRevision,
    ) -> Result<ResendRevision, Diagnostic> {
        Ok(ResendRevision {
            revision: revision.revision,
            sent_at: revision.sent_at,
            request: self.resolve_resend_request(revision.request)?,
            response: revision
                .response
                .map(|response| {
                    Ok(ResendResponse {
                        status: response.status,
                        headers: response.headers,
                        body: self.read_blob(response.body_hash.as_deref())?,
                        duration_ms: response.duration_ms,
                        http_version: response.http_version,
                        reason: response.reason,
                    })
                })
                .transpose()?,
            diagnostic: revision.diagnostic,
            scope: revision.scope,
            redirect_chain: revision.redirect_chain,
            followed_from: revision.followed_from,
        })
    }

    fn write_blob(&self, body: Option<&[u8]>) -> Result<Option<String>, Diagnostic> {
        let Some(body) = body else { return Ok(None) };
        if body.len() > MAX_BODY_BYTES {
            return Err(storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "body-size",
                &self.root,
                "body exceeds durable retention limit",
            ));
        }
        let hash = digest_hex(body);
        let path = self.blobs.join(&hash);
        if path.exists() {
            return Ok(Some(hash));
        }
        // A unique temp name per write. A shared `.{hash}.tmp` let a second writer
        // of the same content-addressed blob remove the first writer's in-progress
        // temp, corrupting its rename ("file not found") — a real hazard once two
        // sources capture the same body concurrently. The atomic nonce makes the
        // temp path unique, so writers never stomp each other; the identical final
        // blob is reconciled at rename below.
        let unique = BLOB_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .blobs
            .join(format!(".{hash}.{}.{unique}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|error| {
                storage_diag(
                    catalogue::PROXY_STORE_WRITE_FAILED,
                    "blob-create",
                    &tmp,
                    &error.to_string(),
                )
            })?;
        if let Err(error) = file.write_all(body).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&tmp);
            return Err(storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "blob-write",
                &tmp,
                &error.to_string(),
            ));
        }
        if let Err(error) = fs::rename(&tmp, &path) {
            // Another session handle may have completed the same content
            // address concurrently. The final hash-named blob is authoritative
            // once it exists; the losing temporary writer is disposable.
            if path.exists() {
                let _ = fs::remove_file(&tmp);
                return Ok(Some(hash));
            }
            return Err(storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "blob-rename",
                &path,
                &error.to_string(),
            ));
        }
        Ok(Some(hash))
    }

    fn resolve(&self, parts: StoredParts) -> Result<FlowCapture, Diagnostic> {
        Ok(FlowCapture {
            id: parts.id,
            captured_at: parts.captured_at,
            protocol: parts.protocol,
            method: parts.method,
            host: parts.host,
            url: parts.url,
            path: parts.path,
            status: parts.status,
            duration_ms: parts.duration_ms,
            request_headers: serde_json::from_str(&parts.request_headers)
                .map_err(|e| serialization_diag("request_headers", &e.to_string()))?,
            response_headers: serde_json::from_str(&parts.response_headers)
                .map_err(|e| serialization_diag("response_headers", &e.to_string()))?,
            request_body: self.read_blob(parts.request_body_hash.as_deref())?,
            response_body: self.read_blob(parts.response_body_hash.as_deref())?,
            scope: serde_json::from_str(&parts.scope)
                .map_err(|e| serialization_diag("scope", &e.to_string()))?,
            provenance: parts.provenance,
            origin: FlowOrigin::from_db_str(&parts.origin),
        })
    }

    fn read_blob(&self, hash: Option<&str>) -> Result<Option<Vec<u8>>, Diagnostic> {
        let Some(hash) = hash else { return Ok(None) };
        let path = self.blobs.join(hash);
        let body = fs::read(&path).map_err(|e| {
            storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "blob-read",
                &path,
                &e.to_string(),
            )
        })?;
        if digest_hex(&body) != hash {
            return Err(storage_diag(
                catalogue::PROXY_STORE_CORRUPT,
                "blob-hash",
                &path,
                "content hash does not match filename",
            ));
        }
        Ok(Some(body))
    }

    fn blob_size(&self, hash: &str) -> Option<u64> {
        fs::metadata(self.blobs.join(hash)).ok().map(|m| m.len())
    }
}

#[derive(Clone, Debug)]
struct StoredParts {
    id: u64,
    captured_at: DateTime<Utc>,
    protocol: String,
    method: Option<String>,
    host: Option<String>,
    url: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    duration_ms: Option<u64>,
    request_headers: String,
    response_headers: String,
    request_body_hash: Option<String>,
    response_body_hash: Option<String>,
    scope: String,
    provenance: String,
    origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredResendRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredResendResponse {
    status: u16,
    headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_hash: Option<String>,
    duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredResendRevision {
    revision: u64,
    sent_at: DateTime<Utc>,
    request: StoredResendRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<StoredResendResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
    scope: ScopeDisposition,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    redirect_chain: Vec<RedirectHop>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    followed_from: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFuzzerConfig {
    base_request: StoredResendRequest,
    positions: Vec<PayloadPosition>,
    payload_sets: Vec<PayloadSet>,
    attack_type: FuzzerAttackType,
    match_filter: FuzzerMatchFilter,
    #[serde(default)]
    grep: GrepConfig,
    concurrency: usize,
    /// New delay model; absent in legacy blobs (migrated from `rate_per_second`).
    #[serde(default)]
    delay: Option<DelayPolicy>,
    /// Legacy sends-per-second; migrated into `delay` on load.
    #[serde(default)]
    rate_per_second: Option<u32>,
    #[serde(default)]
    retry: RetryPolicy,
    #[serde(default)]
    redirect: RedirectPolicy,
    #[serde(default)]
    connection_close: bool,
    #[serde(default = "default_true")]
    update_content_length: bool,
    max_results: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_preflight: Option<StoredResendRequest>,
    sequence: Vec<StoredFuzzerSequenceStep>,
    #[serde(default)]
    auto_calibrate: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFuzzerSequenceStep {
    name: String,
    request: StoredResendRequest,
    extractors: Vec<FuzzerTokenExtractor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFuzzerResult {
    ordinal: u64,
    payloads: Vec<String>,
    request: StoredResendRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<StoredResendResponse>,
    matched: bool,
    filtered: bool,
    diff: FuzzerResponseDiff,
    scope: ScopeDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
    #[serde(default)]
    timeout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(default)]
    grep_match_counts: Vec<u32>,
    #[serde(default)]
    grep_extracts: Vec<Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reflected_count: Option<u32>,
    #[serde(default)]
    redirect_chain: Vec<RedirectHop>,
    #[serde(default)]
    retry_count: u32,
}

/// Computes the initial flow-id allocator value: one above the highest persisted
/// id, so a reopened store never reissues an id already on disk.
fn seed_next_flow_id(connection: &Connection, database: &Path) -> Result<u64, Diagnostic> {
    let max_id: i64 = connection
        .query_row("SELECT COALESCE(MAX(id),0) FROM flows", [], |row| {
            row.get(0)
        })
        .map_err(|error| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "seed-id",
                database,
                &error.to_string(),
            )
        })?;
    Ok(u64::try_from(max_id).unwrap_or(0).saturating_add(1))
}

/// Adds columns newer builds expect to tables created by older ones.
fn ensure_columns(connection: &Connection, database: &Path) -> Result<(), Diagnostic> {
    ensure_flows_columns(connection, database)?;
    ensure_resend_columns(connection, database)
}

fn ensure_flows_columns(connection: &Connection, database: &Path) -> Result<(), Diagnostic> {
    let mut statement = connection
        .prepare("PRAGMA table_info(flows)")
        .map_err(|error| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "schema",
                database,
                &error.to_string(),
            )
        })?;
    let columns: Vec<String> = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "schema",
                database,
                &error.to_string(),
            )
        })?
        .filter_map(Result::ok)
        .collect();
    if !columns.iter().any(|name| name == "url") {
        connection
            .execute("ALTER TABLE flows ADD COLUMN url TEXT", [])
            .map_err(|error| {
                storage_diag(
                    catalogue::PROXY_STORE_OPEN_FAILED,
                    "schema",
                    database,
                    &error.to_string(),
                )
            })?;
    }
    // Legacy stores predate flow-origin tagging; every existing row is observed
    // capture traffic, so the added column defaults to `'capture'`.
    if !columns.iter().any(|name| name == "origin") {
        connection
            .execute(
                "ALTER TABLE flows ADD COLUMN origin TEXT NOT NULL DEFAULT 'capture'",
                [],
            )
            .map_err(|error| {
                storage_diag(
                    catalogue::PROXY_STORE_OPEN_FAILED,
                    "schema",
                    database,
                    &error.to_string(),
                )
            })?;
    }
    Ok(())
}

/// Legacy stores predate durable Resend item names.
fn ensure_resend_columns(connection: &Connection, database: &Path) -> Result<(), Diagnostic> {
    let resend_columns: Vec<String> = connection
        .prepare("PRAGMA table_info(resend_contexts)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .map(|rows| rows.filter_map(Result::ok).collect())
        })
        .map_err(|error| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "schema",
                database,
                &error.to_string(),
            )
        })?;
    if !resend_columns.iter().any(|name| name == "name") {
        connection
            .execute("ALTER TABLE resend_contexts ADD COLUMN name TEXT", [])
            .map_err(|error| {
                storage_diag(
                    catalogue::PROXY_STORE_OPEN_FAILED,
                    "schema",
                    database,
                    &error.to_string(),
                )
            })?;
    }
    Ok(())
}

fn row_to_parts(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredParts> {
    let captured: String = row.get(1)?;
    Ok(StoredParts {
        id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or_default(),
        captured_at: parse_time(&captured),
        protocol: row.get(2)?,
        method: row.get(3)?,
        host: row.get(4)?,
        url: row.get(14)?,
        path: row.get(5)?,
        status: row
            .get::<_, Option<i64>>(6)?
            .and_then(|v| u16::try_from(v).ok()),
        duration_ms: row
            .get::<_, Option<i64>>(7)?
            .and_then(|v| u64::try_from(v).ok()),
        request_headers: row.get(8)?,
        response_headers: row.get(9)?,
        request_body_hash: row.get(10)?,
        response_body_hash: row.get(11)?,
        scope: row.get(12)?,
        provenance: row.get(13)?,
        origin: row.get(15)?,
    })
}

/// Normalized traffic payload embedded in canonical session JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrafficSnapshot {
    /// Snapshot schema version.
    pub schema_version: u32,
    /// Portable flow records.
    pub flows: Vec<CanonicalFlow>,
    /// Persisted resend contexts and their linear histories.
    #[serde(default)]
    pub resend_contexts: Vec<ResendContext>,
    /// Persisted fuzzer jobs and bounded results.
    #[serde(default)]
    pub fuzzer_jobs: Vec<FuzzerJob>,
}

/// One portable flow in the canonical session payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalFlow {
    /// Stable flow ID.
    pub id: u64,
    /// Capture timestamp.
    pub captured_at: DateTime<Utc>,
    /// Protocol.
    pub protocol: String,
    /// Method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Exact request URL.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Duration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Request headers.
    pub request_headers: Vec<(String, String)>,
    /// Response headers.
    pub response_headers: Vec<(String, String)>,
    /// Request body base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_base64: Option<String>,
    /// Response body base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_base64: Option<String>,
    /// Request body SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body_sha256: Option<String>,
    /// Response body SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body_sha256: Option<String>,
    /// Scope classification.
    pub scope: ScopeDisposition,
    /// Provenance.
    pub provenance: String,
    /// How this flow entered the store (capture vs. Resend/Fuzz-synthesized).
    #[serde(default)]
    pub origin: FlowOrigin,
}

impl CanonicalFlow {
    fn from_capture(flow: &FlowCapture) -> Self {
        Self {
            id: flow.id,
            captured_at: flow.captured_at,
            protocol: flow.protocol.clone(),
            method: flow.method.clone(),
            host: flow.host.clone(),
            url: flow.url.clone(),
            path: flow.path.clone(),
            status: flow.status,
            duration_ms: flow.duration_ms,
            request_headers: flow.request_headers.clone(),
            response_headers: flow.response_headers.clone(),
            request_body_base64: flow.request_body.as_deref().map(|b| BASE64.encode(b)),
            response_body_base64: flow.response_body.as_deref().map(|b| BASE64.encode(b)),
            request_body_sha256: flow.request_body.as_deref().map(digest_hex),
            response_body_sha256: flow.response_body.as_deref().map(digest_hex),
            scope: flow.scope,
            provenance: flow.provenance.clone(),
            origin: flow.origin,
        }
    }

    fn into_capture(self) -> Result<FlowCapture, Diagnostic> {
        Ok(FlowCapture {
            id: self.id,
            captured_at: self.captured_at,
            protocol: self.protocol,
            method: self.method,
            host: self.host,
            url: self.url,
            path: self.path,
            status: self.status,
            duration_ms: self.duration_ms,
            request_headers: self.request_headers,
            response_headers: self.response_headers,
            request_body: decode_snapshot(self.request_body_base64, self.request_body_sha256)?,
            response_body: decode_snapshot(self.response_body_base64, self.response_body_sha256)?,
            scope: self.scope,
            provenance: self.provenance,
            origin: self.origin,
        })
    }
}

fn decode_snapshot(
    body: Option<String>,
    expected: Option<String>,
) -> Result<Option<Vec<u8>>, Diagnostic> {
    let Some(body) = body else { return Ok(None) };
    let bytes = BASE64
        .decode(body)
        .map_err(|e| serialization_diag("body-base64", &e.to_string()))?;
    if expected.is_some_and(|hash| digest_hex(&bytes) != hash) {
        return Err(serialization_diag(
            "body-sha256",
            "canonical body hash mismatch",
        ));
    }
    Ok(Some(bytes))
}

#[derive(Deserialize)]
struct HarDocument {
    log: HarLog,
}
#[derive(Deserialize)]
struct HarLog {
    #[serde(default)]
    entries: Vec<HarEntry>,
}
#[derive(Deserialize)]
struct HarEntry {
    #[serde(rename = "startedDateTime")]
    started_date_time: Option<String>,
    time: Option<f64>,
    request: HarRequest,
    response: HarResponse,
}
#[derive(Deserialize)]
struct HarRequest {
    method: String,
    url: String,
    #[serde(rename = "httpVersion")]
    http_version: Option<String>,
    #[serde(default)]
    headers: Vec<HarHeader>,
    #[serde(rename = "postData")]
    post_data: Option<HarContent>,
}
#[derive(Deserialize)]
struct HarResponse {
    status: u16,
    #[serde(default)]
    headers: Vec<HarHeader>,
    content: Option<HarContent>,
}
#[derive(Deserialize)]
struct HarContent {
    text: String,
    encoding: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct HarHeader {
    name: String,
    value: String,
}
#[derive(Serialize)]
struct HarDocumentOut {
    log: HarLogOut,
}
#[derive(Serialize)]
struct HarLogOut {
    version: String,
    creator: HarCreator,
    entries: Vec<HarEntryOut>,
}
#[derive(Serialize)]
struct HarCreator {
    name: String,
    version: String,
}
#[derive(Serialize)]
struct HarEntryOut {
    #[serde(rename = "startedDateTime")]
    started_date_time: String,
    time: f64,
    request: HarRequestOut,
    response: HarResponseOut,
}
#[derive(Serialize)]
struct HarRequestOut {
    method: String,
    url: String,
    #[serde(rename = "httpVersion")]
    http_version: String,
    headers: Vec<HarHeader>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    post_data: Option<HarContentOut>,
}
#[derive(Serialize)]
struct HarResponseOut {
    status: u16,
    #[serde(rename = "httpVersion")]
    http_version: String,
    headers: Vec<HarHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<HarContentOut>,
}
#[derive(Serialize)]
struct HarContentOut {
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

impl HarEntryOut {
    fn from_capture(flow: &FlowCapture) -> Self {
        Self {
            started_date_time: flow.captured_at.to_rfc3339(),
            time: f64::from(
                u32::try_from(
                    flow.duration_ms
                        .unwrap_or_default()
                        .min(u64::from(u32::MAX)),
                )
                .unwrap_or(u32::MAX),
            ),
            request: HarRequestOut {
                method: flow.method.clone().unwrap_or_else(|| "GET".to_owned()),
                url: format!(
                    "https://{}{}",
                    flow.host.as_deref().unwrap_or("unknown"),
                    flow.path.as_deref().unwrap_or("/")
                ),
                http_version: flow.protocol.clone(),
                headers: flow
                    .request_headers
                    .iter()
                    .map(|(n, v)| HarHeader {
                        name: n.clone(),
                        value: v.clone(),
                    })
                    .collect(),
                post_data: flow.request_body.as_deref().map(encode_har_body),
            },
            response: HarResponseOut {
                status: flow.status.unwrap_or_default(),
                http_version: flow.protocol.clone(),
                headers: flow
                    .response_headers
                    .iter()
                    .map(|(n, v)| HarHeader {
                        name: n.clone(),
                        value: v.clone(),
                    })
                    .collect(),
                content: flow.response_body.as_deref().map(encode_har_body),
            },
        }
    }
}

fn encode_har_body(body: &[u8]) -> HarContentOut {
    match String::from_utf8(body.to_vec()) {
        Ok(text) => HarContentOut {
            text,
            encoding: None,
        },
        Err(_) => HarContentOut {
            text: BASE64.encode(body),
            encoding: Some("base64".to_owned()),
        },
    }
}

fn decode_har_body(content: &HarContent) -> Result<Option<Vec<u8>>, Diagnostic> {
    if content.encoding.as_deref() == Some("base64") {
        BASE64
            .decode(&content.text)
            .map(Some)
            .map_err(|error| interchange_diag("import-body", &error.to_string()))
    } else {
        Ok(Some(content.text.as_bytes().to_vec()))
    }
}

fn split_url(url: &str) -> (Option<String>, Option<String>) {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, "/"));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, v)| v)
        .split_once(':')
        .map_or(authority, |(_, v)| v);
    (Some(host.to_owned()), Some(format!("/{path}")))
}

fn parse_time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value).map_or_else(|_| Utc::now(), |v| v.with_timezone(&Utc))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn har_duration_ms(value: f64) -> Option<u64> {
    if value.is_finite() && value >= 0.0 {
        Some(value.floor() as u64)
    } else {
        None
    }
}

fn validate_flow(flow: &FlowCapture) -> Result<(), Diagnostic> {
    if flow.protocol.trim().is_empty() || flow.provenance.trim().is_empty() {
        return Err(storage_diag(
            catalogue::PROXY_STORE_WRITE_FAILED,
            "flow",
            Path::new(""),
            "protocol and provenance must be non-empty",
        ));
    }
    for body in [&flow.request_body, &flow.response_body] {
        if body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_BODY_BYTES)
        {
            return Err(storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "body-size",
                Path::new(""),
                "body exceeds durable retention limit",
            ));
        }
    }
    Ok(())
}

fn validate_resend(context: &ResendContext) -> Result<(), Diagnostic> {
    if context.id.trim().is_empty()
        || context.current.method.trim().is_empty()
        || context.current.url.trim().is_empty()
    {
        return Err(storage_diag(
            catalogue::PROXY_RESEND_HISTORY_FAILED,
            "validate",
            Path::new(""),
            "context ID, method, and URL must be non-empty",
        ));
    }
    for (index, entry) in context.history.iter().enumerate() {
        if entry.revision != u64::try_from(index + 1).unwrap_or(u64::MAX)
            || entry.request.method.trim().is_empty()
            || entry.request.url.trim().is_empty()
        {
            return Err(storage_diag(
                catalogue::PROXY_RESEND_HISTORY_FAILED,
                "validate",
                Path::new(""),
                "history revisions must be contiguous and contain method and URL",
            ));
        }
    }
    Ok(())
}

fn validate_fuzzer(job: &FuzzerJob) -> Result<(), Diagnostic> {
    if job.id.trim().is_empty()
        || job.config.base_request.method.trim().is_empty()
        || job.config.base_request.url.trim().is_empty()
        || job
            .config
            .payload_sets
            .iter()
            .any(PayloadSet::is_trivially_empty)
        || job.config.positions.is_empty()
        || job.config.max_results == 0
    {
        return Err(storage_diag(
            catalogue::PROXY_FUZZER_CONFIG_INVALID,
            "validate",
            Path::new(""),
            "job ID, request, positions, payload sets, and result limit must be usable",
        ));
    }
    if job.results.len() > job.config.max_results {
        return Err(storage_diag(
            catalogue::PROXY_FUZZER_PERSISTENCE_FAILED,
            "validate-results",
            Path::new(""),
            "result count exceeds configured bound",
        ));
    }
    Ok(())
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn storage_diag(
    definition: apiaxess_diagnostics::DiagnosticDefinition,
    operation: &str,
    path: &Path,
    error: &str,
) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    definition.instantiate(context)
}

fn serialization_diag(field: &str, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "field".to_owned(),
        DiagnosticValue::String(field.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_STORE_SESSION_COMMIT_FAILED.instantiate(context)
}

fn interchange_diag(operation: &str, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_HAR_INTERCHANGE_FAILED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apiaxess_api_model::{ApiDocument, ApiSurface, ProvenanceRegistry};
    use apiaxess_session::{EngagementScope, Session, SessionId, TargetIdentifier, TargetIdentity};
    use chrono::Duration;
    use std::{
        env,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn store() -> TrafficStore {
        let path = env::temp_dir().join(format!(
            "apiaxess-store-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            STORE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        TrafficStore::open(&path, "session:test").expect("store")
    }

    fn flow(id: u64) -> FlowCapture {
        FlowCapture {
            id,
            captured_at: Utc::now(),
            protocol: "HTTP/2".to_owned(),
            method: Some("POST".to_owned()),
            host: Some("api.example.test".to_owned()),
            url: Some("https://api.example.test/items".to_owned()),
            path: Some("/items".to_owned()),
            status: Some(200),
            duration_ms: Some(12),
            request_headers: vec![("x-test".to_owned(), "1".to_owned())],
            response_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            request_body: Some(br#"{"x":1}"#.to_vec()),
            response_body: Some(br#"{"ok":true}"#.to_vec()),
            scope: ScopeDisposition::InScope,
            provenance: "proxy.hudsucker".to_owned(),
            origin: FlowOrigin::Capture,
        }
    }

    #[test]
    fn sqlite_and_content_addressed_blobs_round_trip() {
        let store = store();
        let expected = flow(1);
        store.upsert(&expected).expect("insert");
        let second = flow(2);
        store.upsert(&second).expect("deduplicated insert");
        assert_eq!(store.summaries().expect("summaries").len(), 2);
        assert_eq!(store.get(1).expect("read"), Some(expected));
        assert_eq!(store.get(2).expect("read"), Some(second));
        assert_eq!(
            fs::read_dir(store.root().join("blobs"))
                .expect("blobs")
                .count(),
            2
        );
    }

    #[test]
    fn canonical_snapshot_round_trips_body_hashes() {
        let store = store();
        let expected = flow(1);
        store.upsert(&expected).expect("insert");
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(snapshot.flows.len(), 1);
        let restored = snapshot
            .flows
            .into_iter()
            .next()
            .expect("flow")
            .into_capture()
            .expect("capture");
        assert_eq!(restored, expected);
    }

    #[test]
    fn flow_origin_persists_through_upsert_get_and_summaries() {
        let store = store();
        let mut fuzz = flow(1);
        fuzz.origin = FlowOrigin::Fuzz;
        let mut resend = flow(2);
        resend.origin = FlowOrigin::Resend;
        let capture = flow(3); // defaults to Capture
        store.upsert(&fuzz).expect("insert fuzz");
        store.upsert(&resend).expect("insert resend");
        store.upsert(&capture).expect("insert capture");

        assert_eq!(
            store.get(1).expect("read").expect("present").origin,
            FlowOrigin::Fuzz
        );
        assert_eq!(
            store.get(2).expect("read").expect("present").origin,
            FlowOrigin::Resend
        );
        assert_eq!(
            store.get(3).expect("read").expect("present").origin,
            FlowOrigin::Capture
        );

        let by_id: std::collections::BTreeMap<u64, FlowOrigin> = store
            .summaries()
            .expect("summaries")
            .into_iter()
            .map(|summary| (summary.id, summary.origin))
            .collect();
        assert_eq!(by_id[&1], FlowOrigin::Fuzz);
        assert_eq!(by_id[&2], FlowOrigin::Resend);
        assert_eq!(by_id[&3], FlowOrigin::Capture);
    }

    #[test]
    fn flow_capture_without_origin_field_deserializes_as_capture() {
        // Legacy canonical/JSON payloads predate the origin tag; they must load as
        // observed capture traffic rather than fail to deserialize.
        let legacy = r#"{
            "id": 5,
            "capturedAt": "2026-01-01T00:00:00Z",
            "protocol": "HTTP/1.1",
            "requestHeaders": [],
            "responseHeaders": [],
            "scope": "in_scope",
            "provenance": "proxy.hudsucker"
        }"#;
        let flow: FlowCapture = serde_json::from_str(legacy).expect("legacy flow loads");
        assert_eq!(flow.origin, FlowOrigin::Capture);
    }

    #[test]
    fn legacy_flows_table_without_origin_column_migrates_to_capture() {
        // A store created before flow-origin tagging has a `flows` table with no
        // `origin` column. Opening it must add the column defaulting existing rows
        // to `'capture'` so legacy traffic reads back as observed capture.
        let connection = Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "CREATE TABLE flows (
                   id INTEGER PRIMARY KEY,
                   captured_at TEXT NOT NULL,
                   protocol TEXT NOT NULL,
                   method TEXT, host TEXT, path TEXT, status INTEGER, duration_ms INTEGER,
                   request_headers TEXT NOT NULL, response_headers TEXT NOT NULL,
                   request_body_hash TEXT, response_body_hash TEXT,
                   scope TEXT NOT NULL, provenance TEXT NOT NULL
                 );
                 INSERT INTO flows (id,captured_at,protocol,request_headers,response_headers,scope,provenance)
                 VALUES (1,'2026-01-01T00:00:00Z','HTTP/1.1','[]','[]','\"in_scope\"','proxy.observer');",
            )
            .expect("legacy schema");

        ensure_flows_columns(&connection, Path::new("test")).expect("migrate");

        let origin: String = connection
            .query_row("SELECT origin FROM flows WHERE id=1", [], |row| row.get(0))
            .expect("origin column present");
        assert_eq!(FlowOrigin::from_db_str(&origin), FlowOrigin::Capture);
    }

    #[test]
    fn har_round_trip_uses_interchange_only() {
        let database = store();
        database.upsert(&flow(1)).expect("insert");
        let har = database.export_har().expect("export");
        let other = store();
        // Re-import classifies against the (test) engagement scope exactly as live
        // capture does. Without this, imported flows are `Undetermined` and dynamic
        // fusion skips them, so a HAR import fuses into zero endpoints.
        let classify = |host: Option<&str>, _url: Option<&str>| {
            if host == Some("api.example.test") {
                ScopeDisposition::InScope
            } else {
                ScopeDisposition::OutsideDeclaredScope
            }
        };
        assert_eq!(
            other
                .import_har(&har, "har.import", classify)
                .expect("import"),
            1
        );
        let summaries = other.summaries().expect("summaries");
        assert_eq!(summaries.len(), 1);
        let reimported = other.get(summaries[0].id).expect("read").expect("flow");
        assert_eq!(
            reimported.scope,
            ScopeDisposition::InScope,
            "an in-scope imported flow must be classified in-scope so fusion consumes it"
        );
        assert_eq!(reimported.method.as_deref(), Some("POST"));
        assert_eq!(reimported.path.as_deref(), Some("/items"));
    }

    #[test]
    fn session_commit_and_resume_use_canonical_json_as_authority() {
        let database = store();
        let expected = flow(1);
        database.upsert(&expected).expect("insert");
        let now = Utc::now();
        let mut session = Session::new(
            SessionId::new("session:fixture").expect("session id"),
            EngagementScope {
                declared_at: now,
                target: TargetIdentity {
                    target_type: "apk".to_owned(),
                    primary: TargetIdentifier {
                        kind: "artifact.sha256".to_owned(),
                        value: "00".repeat(32),
                    },
                    aliases: Vec::new(),
                },
                allowed_targets: Vec::new(),
            },
            ApiDocument::new(ApiSurface {
                provenance: ProvenanceRegistry {
                    agents: Vec::new(),
                    activities: Vec::new(),
                    entities: Vec::new(),
                },
                endpoints: Vec::new(),
                protocol_operations: Vec::new(),
                loose_findings: Vec::new(),
                signers: Vec::new(),
            }),
            now,
        );
        session
            .activate(now + Duration::seconds(1))
            .expect("activate");
        let json = database
            .serialize_session(&mut session, now + Duration::seconds(2))
            .expect("serialize");
        let document = SessionDocument::from_json(&json).expect("canonical session");
        let resumed = store();
        assert_eq!(
            resumed
                .resume_from_session(&document.session)
                .expect("resume"),
            1
        );
        assert_eq!(resumed.get(1).expect("read"), Some(expected));
    }

    #[test]
    fn resend_contexts_round_trip_through_sqlite_and_snapshot() {
        let store = store();
        let context = ResendContext {
            id: "resend-test".to_owned(),
            source_flow_id: Some(7),
            created_at: Utc::now(),
            current: ResendRequest {
                method: "POST".to_owned(),
                url: "https://api.example.test/items?id=1".to_owned(),
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body: Some(br#"{"name":"first"}"#.to_vec()),
            },
            history: vec![ResendRevision {
                revision: 1,
                sent_at: Utc::now(),
                request: ResendRequest {
                    method: "POST".to_owned(),
                    url: "https://api.example.test/items?id=1".to_owned(),
                    headers: vec![],
                    body: Some(b"first".to_vec()),
                },
                response: Some(ResendResponse {
                    status: 201,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"{\"ok\":true}".to_vec()),
                    duration_ms: 12,
                    http_version: None,
                    reason: None,
                }),
                diagnostic: None,
                scope: ScopeDisposition::InScope,
                redirect_chain: vec![RedirectHop {
                    status: 302,
                    location: "https://api.example.test/next".to_owned(),
                }],
                followed_from: Some(1),
            }],
            name: Some("Login probe".to_owned()),
        };
        store.upsert_resend(&context).expect("resend persisted");
        assert_eq!(
            store.resend_contexts().expect("resend loaded"),
            vec![context]
        );
        assert_eq!(
            store.snapshot().expect("snapshot").resend_contexts.len(),
            1
        );
    }

    #[test]
    fn legacy_resend_table_without_name_column_migrates() {
        let connection = Connection::open_in_memory().expect("memory db");
        connection
            .execute_batch(
                "CREATE TABLE resend_contexts (
                   id TEXT PRIMARY KEY, source_flow_id INTEGER, created_at TEXT NOT NULL,
                   current_json TEXT NOT NULL, history_json TEXT NOT NULL
                 );",
            )
            .expect("legacy schema");
        ensure_resend_columns(&connection, Path::new("test")).expect("migrate");
        ensure_resend_columns(&connection, Path::new("test")).expect("idempotent");
        let name: Option<String> = connection
            .query_row("SELECT name FROM resend_contexts LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap_or(None);
        assert_eq!(name, None);
    }

    #[test]
    fn legacy_resend_revision_without_redirect_fields_loads() {
        let legacy = r#"{"revision":1,"sentAt":"2026-09-01T00:00:00Z","request":{"method":"GET","url":"http://a.test/","headers":[]},"scope":"in_scope"}"#;
        let revision: ResendRevision = serde_json::from_str(legacy).expect("legacy revision");
        assert!(revision.redirect_chain.is_empty());
        assert_eq!(revision.followed_from, None);
    }

    #[test]
    fn legacy_simple_list_payload_set_blob_deserializes_as_simple_list() {
        // A payload set persisted before the payload engine existed carried a
        // flat `{ name, values }` shape. It must still load, as a SimpleList
        // with an empty pipeline, so old jobs survive the upgrade.
        let legacy = r#"{ "name": "ids", "values": ["1", "2", "3"] }"#;
        let set: PayloadSet = serde_json::from_str(legacy).expect("legacy set loads");
        assert_eq!(set.name, "ids");
        assert!(set.processors.is_empty());
        assert!(set.url_encode_chars.is_none());
        match set.source {
            PayloadSource::SimpleList { values } => {
                assert_eq!(values, vec!["1", "2", "3"]);
            }
            other => panic!("legacy values must map to SimpleList, got {other:?}"),
        }
    }

    #[test]
    fn payload_set_round_trips_through_serde_with_source_and_processors() {
        let set = PayloadSet {
            name: "numbers".to_owned(),
            source: PayloadSource::Numbers {
                from: 0.0,
                to: 10.0,
                step: 1.0,
                order: NumberOrder::Sequential,
                radix: NumberRadix::Dec,
                min_integer_digits: 2,
                max_fraction_digits: 0,
            },
            processors: vec![
                PayloadProcessor::AddPrefix {
                    text: "id-".to_owned(),
                },
                PayloadProcessor::Encode {
                    scheme: EncodeScheme::Base64,
                },
            ],
            url_encode_chars: Some("&=".to_owned()),
        };
        let json = serde_json::to_string(&set).expect("serialize");
        // Struct-variant fields must be camelCase (the API contract), which needs
        // `rename_all_fields` on the enum — enum `rename_all` alone only renames
        // variants, leaving multi-word fields snake_case and breaking the GUI.
        assert!(
            json.contains("\"minIntegerDigits\""),
            "multi-word source fields must be camelCase: {json}"
        );
        assert!(
            !json.contains("min_integer_digits"),
            "no snake_case leak: {json}"
        );
        let restored: PayloadSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(set, restored);
        // A camelCase blob from the GUI must deserialize.
        let from_gui = r#"{"name":"n","source":{"type":"numbers","from":0.0,"to":9.0,"step":1.0,"order":"sequential","radix":"dec","minIntegerDigits":2,"maxFractionDigits":0}}"#;
        let parsed: PayloadSet = serde_json::from_str(from_gui).expect("camelCase GUI blob loads");
        assert!(matches!(
            parsed.source,
            PayloadSource::Numbers {
                min_integer_digits: 2,
                ..
            }
        ));
    }

    #[test]
    fn grep_config_round_trips_camelcase_on_the_wire() {
        let grep = GrepConfig {
            match_rules: vec![GrepMatchRule {
                name: "err".to_owned(),
                pattern: "error".to_owned(),
                is_regex: false,
                case_sensitive: false,
                exclude_headers: true,
            }],
            extract_rules: vec![GrepExtractRule {
                name: "csrf".to_owned(),
                locator: ExtractLocator::BetweenDelimiters {
                    start: "name=\"csrf\" value=\"".to_owned(),
                    end: "\"".to_owned(),
                },
                max_length: 100,
                first_only: true,
            }],
            reflected: GrepReflectedConfig {
                enabled: true,
                case_sensitive: false,
                exclude_headers: false,
                match_pre_url_encoded: true,
            },
        };
        let json = serde_json::to_string(&grep).expect("serialize");
        for expected in [
            "\"matchRules\"",
            "\"isRegex\"",
            "\"excludeHeaders\"",
            "\"maxLength\"",
            "\"firstOnly\"",
            "\"matchPreUrlEncoded\"",
        ] {
            assert!(json.contains(expected), "missing {expected} in {json}");
        }
        assert_eq!(grep, serde_json::from_str(&json).expect("deserialize"));
        // ExtractLocator is tag = "type", camelCase, with camelCase fields.
        let offset = serde_json::to_string(&ExtractLocator::Offset {
            start: 3,
            length: 5,
        })
        .expect("serialize locator");
        assert!(offset.contains("\"type\":\"offset\""), "{offset}");
        let between = serde_json::to_string(&ExtractLocator::BetweenDelimiters {
            start: "a".to_owned(),
            end: "b".to_owned(),
        })
        .expect("serialize locator");
        assert!(
            between.contains("\"type\":\"betweenDelimiters\""),
            "{between}"
        );
    }

    #[test]
    fn legacy_fuzzer_result_without_grep_fields_deserializes_with_defaults() {
        // A result persisted before WS3 has none of the grep/timeout/comment
        // fields. Strip them from a fresh result's JSON and confirm it still
        // loads with empty/false defaults.
        let result = FuzzerResult {
            ordinal: 1,
            payloads: vec!["a".to_owned()],
            request: ResendRequest {
                method: "GET".to_owned(),
                url: "http://x.test/".to_owned(),
                headers: Vec::new(),
                body: None,
            },
            response: None,
            matched: false,
            filtered: true,
            diff: FuzzerResponseDiff::default(),
            scope: ScopeDisposition::InScope,
            diagnostic: None,
            timeout: true,
            comment: Some("x".to_owned()),
            grep_match_counts: vec![1, 2],
            grep_extracts: vec![Some("v".to_owned())],
            reflected_count: Some(3),
            redirect_chain: Vec::new(),
            retry_count: 0,
        };
        let mut value = serde_json::to_value(&result).expect("to value");
        let object = value.as_object_mut().expect("object");
        for key in [
            "timeout",
            "comment",
            "grepMatchCounts",
            "grepExtracts",
            "reflectedCount",
        ] {
            object.remove(key);
        }
        let legacy: FuzzerResult = serde_json::from_value(value).expect("legacy result loads");
        assert!(!legacy.timeout);
        assert!(legacy.comment.is_none());
        assert!(legacy.grep_match_counts.is_empty());
        assert!(legacy.grep_extracts.is_empty());
        assert!(legacy.reflected_count.is_none());
    }

    #[test]
    fn legacy_rate_per_second_migrates_to_fixed_delay() {
        // A pre-WS4 config had `rate_per_second` and no `delay`.
        assert_eq!(
            migrate_delay(None, Some(25)),
            DelayPolicy::Fixed {
                rate_per_second: 25
            }
        );
        // Absent both -> unlimited default.
        assert_eq!(migrate_delay(None, None), DelayPolicy::default());
        // An explicit new delay always wins over the legacy field.
        assert_eq!(
            migrate_delay(Some(DelayPolicy::Interval { ms: 500 }), Some(25)),
            DelayPolicy::Interval { ms: 500 }
        );
    }

    #[test]
    fn attack_settings_round_trip_camelcase() {
        let delay = serde_json::to_string(&DelayPolicy::Random {
            min_ms: 10,
            max_ms: 50,
        })
        .expect("serialize delay");
        assert!(delay.contains("\"type\":\"random\""), "{delay}");
        assert!(delay.contains("\"minMs\""), "{delay}");
        let redirect =
            serde_json::to_string(&RedirectPolicy::default()).expect("serialize redirect");
        assert!(redirect.contains("\"processCookies\""), "{redirect}");
        assert!(redirect.contains("\"maxHops\""), "{redirect}");
        let mode = serde_json::to_string(&RedirectMode::OnSite).expect("serialize mode");
        assert_eq!(mode, "\"on_site\"");
        let retry = serde_json::to_string(&RetryPolicy {
            max_retries: 3,
            pause_ms: 250,
        })
        .expect("serialize retry");
        assert!(retry.contains("\"maxRetries\""), "{retry}");
        assert!(retry.contains("\"pauseMs\""), "{retry}");
    }

    #[test]
    fn fuzzer_jobs_round_trip_with_content_addressed_request_and_response_bodies() {
        let store = store();
        let request = ResendRequest {
            method: "GET".to_owned(),
            url: "https://api.example.test/items?id=FUZZ".to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: Some(b"request-body".to_vec()),
        };
        let job = FuzzerJob {
            id: "fuzzer-test".to_owned(),
            created_at: Utc::now(),
            tier: FuzzerTier::Native,
            state: FuzzerJobState::Completed,
            config: FuzzerConfig {
                base_request: request.clone(),
                positions: vec![PayloadPosition {
                    location: FuzzerPositionLocation::Url,
                    header_name: None,
                    start: 31,
                    end: 35,
                    set_index: 0,
                }],
                payload_sets: vec![PayloadSet {
                    name: "ids".to_owned(),
                    source: PayloadSource::SimpleList {
                        values: vec!["1".to_owned()],
                    },
                    processors: Vec::new(),
                    url_encode_chars: None,
                }],
                attack_type: FuzzerAttackType::Sniper,
                match_filter: FuzzerMatchFilter::default(),
                grep: GrepConfig::default(),
                concurrency: 1,
                delay: DelayPolicy::default(),
                retry: RetryPolicy::default(),
                redirect: RedirectPolicy::default(),
                connection_close: false,
                update_content_length: true,
                max_results: 10,
                auth_preflight: None,
                sequence: Vec::new(),
                auto_calibrate: false,
            },
            results: vec![FuzzerResult {
                ordinal: 1,
                payloads: vec!["1".to_owned()],
                request,
                response: Some(ResendResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"response-body".to_vec()),
                    duration_ms: 4,
                    http_version: None,
                    reason: None,
                }),
                matched: true,
                filtered: false,
                diff: FuzzerResponseDiff::default(),
                scope: ScopeDisposition::InScope,
                diagnostic: None,
                timeout: false,
                comment: None,
                grep_match_counts: Vec::new(),
                grep_extracts: Vec::new(),
                reflected_count: None,
                redirect_chain: Vec::new(),
                retry_count: 0,
            }],
            diagnostics: Vec::new(),
        };
        store.upsert_fuzzer(&job).expect("fuzzer persisted");
        assert_eq!(store.fuzzer_jobs().expect("fuzzer loaded"), vec![job]);
        assert_eq!(store.snapshot().expect("snapshot").fuzzer_jobs.len(), 1);
        assert_eq!(
            fs::read_dir(store.root().join("blobs"))
                .expect("blobs")
                .count(),
            2
        );
    }

    #[test]
    fn concurrent_flow_id_allocation_is_globally_unique() {
        use std::collections::BTreeSet;
        // Many sources allocating simultaneously from the single store authority
        // must never produce a duplicate id — the exact condition the multi-client
        // system creates.
        let store = Arc::new(store());
        let threads = 8;
        let per_thread = 1_000;
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    (0..per_thread)
                        .map(|_| store.allocate_flow_id())
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        let mut all = Vec::new();
        for handle in handles {
            all.extend(handle.join().expect("allocator thread"));
        }
        let unique: BTreeSet<u64> = all.iter().copied().collect();
        assert_eq!(all.len(), threads * per_thread);
        assert_eq!(
            unique.len(),
            all.len(),
            "every concurrently-allocated flow id must be unique"
        );
    }

    #[test]
    fn concurrent_two_source_inserts_never_overwrite() {
        // Simulate two concurrent traffic sources (live capture + HAR import) each
        // allocating from the store authority and inserting. Every flow must
        // persist; none may silently clobber another via an id collision.
        let store = Arc::new(store());
        let per_source = 300;
        let source = |store: Arc<TrafficStore>, provenance: &'static str| {
            std::thread::spawn(move || {
                for _ in 0..per_source {
                    let id = store.allocate_flow_id();
                    let mut flow = flow(id);
                    flow.provenance = provenance.to_owned();
                    // Distinct path per id so an overwrite would be detectable as a
                    // missing row, not a same-content merge.
                    flow.path = Some(format!("/{provenance}/{id}"));
                    store.upsert(&flow).expect("insert");
                }
            })
        };
        let live = source(Arc::clone(&store), "proxy.capture");
        let import = source(Arc::clone(&store), "har.import");
        live.join().expect("live source");
        import.join().expect("import source");
        let summaries = store.summaries().expect("summaries");
        assert_eq!(
            summaries.len(),
            per_source * 2,
            "both sources' flows must all persist with no overwrite"
        );
        let ids: std::collections::BTreeSet<u64> = summaries.iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), summaries.len(), "all stored ids are unique");
    }
}
