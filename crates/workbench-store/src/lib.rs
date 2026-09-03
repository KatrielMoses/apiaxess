//! Crash-durable session traffic storage and HAR interchange.

use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
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
}

/// Editable HTTP request held by one repeater context or revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterRequest {
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

/// Response captured from one repeater send.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
    /// Round-trip duration in milliseconds.
    pub duration_ms: u64,
}

/// One append-only repeater send revision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterRevision {
    /// One-based revision number within its context.
    pub revision: u64,
    /// Send timestamp.
    pub sent_at: DateTime<Utc>,
    /// Exact request sent.
    pub request: RepeaterRequest,
    /// Response, when the upstream exchange completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RepeaterResponse>,
    /// Stable diagnostic when the send or persistence failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
    /// Advisory scope classification at send time.
    pub scope: ScopeDisposition,
}

/// Independent repeater tab/context with a linear append-only history.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterContext {
    /// Stable session-local context identifier.
    pub id: String,
    /// Captured flow from which this context was created, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_flow_id: Option<u64>,
    /// Context creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Current editable request.
    pub current: RepeaterRequest,
    /// Append-only sends, including failed attempts.
    pub history: Vec<RepeaterRevision>,
}

/// Request field where an intruder payload is substituted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntruderPositionLocation {
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
    pub location: IntruderPositionLocation,
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

/// Named values available to an intruder position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadSet {
    /// Human-readable payload-set label.
    pub name: String,
    /// Values substituted in attack order.
    pub values: Vec<String>,
}

/// Standard payload combination mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntruderAttackType {
    /// Test one marked position at a time.
    Sniper,
    /// Cartesian product across payload sets.
    Clusterbomb,
    /// Pair values by ordinal across payload sets.
    Pitchfork,
}

/// Match/filter rules used to surface interesting responses.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntruderMatchFilter {
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
pub enum IntruderTokenExtractor {
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
pub struct IntruderSequenceStep {
    /// Step label shown in diagnostics.
    pub name: String,
    /// Request template; `{{variable}}` placeholders are injected before send.
    pub request: RepeaterRequest,
    /// Values extracted from this response for subsequent steps.
    pub extractors: Vec<IntruderTokenExtractor>,
}

/// Automatically selected execution tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntruderTier {
    /// Hidden ffuf subprocess for stateless bulk work.
    Ffuf,
    /// Native Rust sender for stateful/authenticated sequences.
    Native,
}

/// Lifecycle of an intruder job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntruderJobState {
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

/// Intruder attack configuration persisted with a job.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntruderConfig {
    /// Request template before payload substitution.
    pub base_request: RepeaterRequest,
    /// Marked substitution positions.
    pub positions: Vec<PayloadPosition>,
    /// Payload values by set.
    pub payload_sets: Vec<PayloadSet>,
    /// Standard payload combination mode.
    pub attack_type: IntruderAttackType,
    /// Optional response match/filter rules.
    pub match_filter: IntruderMatchFilter,
    /// Maximum concurrent native requests.
    pub concurrency: usize,
    /// Maximum sends per second; zero means unlimited.
    pub rate_per_second: u32,
    /// Hard result bound.
    pub max_results: usize,
    /// Optional pre-request authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_preflight: Option<RepeaterRequest>,
    /// Stateful sequence steps after the optional pre-flight.
    pub sequence: Vec<IntruderSequenceStep>,
    /// Enable the ffuf soft-404/catch-all auto-calibration (`-ac`) so a wildcard
    /// or WAF site that answers every path does not produce false-positive hits.
    /// Used by directory discovery; absent (false) for everything else.
    #[serde(default)]
    pub auto_calibrate: bool,
}

/// Response comparison features used by the intruder UI.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntruderResponseDiff {
    /// Whether status differs from the prior result.
    pub status_changed: bool,
    /// Whether body length differs from the prior result.
    pub size_changed: bool,
    /// Signed body-size delta from the prior result.
    pub size_delta: i64,
    /// Whether body text differs from the prior result.
    pub content_changed: bool,
}

/// One captured intruder result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntruderResult {
    /// One-based result ordinal.
    pub ordinal: u64,
    /// Payload values used for this request.
    pub payloads: Vec<String>,
    /// Exact request sent.
    pub request: RepeaterRequest,
    /// Response, when a request completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<RepeaterResponse>,
    /// Response match outcome.
    pub matched: bool,
    /// Whether the result was filtered from the primary view.
    pub filtered: bool,
    /// Comparison to the prior response when available.
    pub diff: IntruderResponseDiff,
    /// Scope classification at send time.
    pub scope: ScopeDisposition,
    /// Failure diagnostic, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
}

/// Durable intruder job, configuration, state, and bounded results.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntruderJob {
    /// Stable session-local job identifier.
    pub id: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Auto-selected execution tier.
    pub tier: IntruderTier,
    /// Lifecycle state.
    pub state: IntruderJobState,
    /// Persisted attack configuration.
    pub config: IntruderConfig,
    /// Captured result rows.
    pub results: Vec<IntruderResult>,
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
               url TEXT
             );
             CREATE INDEX IF NOT EXISTS flows_captured_at ON flows(captured_at);
             CREATE TABLE IF NOT EXISTS repeater_contexts (
               id TEXT PRIMARY KEY,
               source_flow_id INTEGER,
               created_at TEXT NOT NULL,
               current_json TEXT NOT NULL,
               history_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS intruder_jobs (
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
        ensure_flows_url_column(&connection, &database)?;
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
        Ok(Self {
            root,
            blobs,
            connection: Mutex::new(connection),
            redactor: RwLock::new(None),
        })
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
            "INSERT INTO flows (id,captured_at,protocol,method,host,path,status,duration_ms,request_headers,response_headers,request_body_hash,response_body_hash,scope,provenance,url)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO UPDATE SET captured_at=excluded.captured_at,protocol=excluded.protocol,method=excluded.method,host=excluded.host,path=excluded.path,status=excluded.status,duration_ms=excluded.duration_ms,request_headers=excluded.request_headers,response_headers=excluded.response_headers,request_body_hash=excluded.request_body_hash,response_body_hash=excluded.response_body_hash,scope=excluded.scope,provenance=excluded.provenance,url=excluded.url",
            params![
                i64::try_from(flow.id).unwrap_or(i64::MAX), flow.captured_at.to_rfc3339_opts(SecondsFormat::Nanos, true), flow.protocol,
                flow.method, flow.host, flow.path, flow.status.map(i64::from),
                flow.duration_ms.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
                request_headers, response_headers, request_hash, response_hash, scope, flow.provenance, flow.url,
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
            "SELECT id,captured_at,protocol,method,host,path,status,duration_ms,request_headers,response_headers,request_body_hash,response_body_hash,scope,provenance,url FROM flows WHERE id=?1",
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
        let mut statement = connection.prepare("SELECT id,captured_at,protocol,method,host,path,status,duration_ms,request_body_hash,response_body_hash,response_headers,scope,provenance,url FROM flows ORDER BY captured_at,id")
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
            repeater_contexts: self.repeater_contexts()?,
            intruder_jobs: self.intruder_jobs()?,
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
        for context in snapshot.repeater_contexts {
            self.upsert_repeater(&context)?;
        }
        for job in snapshot.intruder_jobs {
            self.upsert_intruder(&job)?;
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
        let mut id = self.next_id()?;
        let mut count = 0;
        for entry in document.log.entries {
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
            };
            self.upsert(&flow)?;
            id = id.saturating_add(1);
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

    /// Persists one repeater context and its append-only history.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when request validation, body durability, JSON
    /// serialization, or the metadata transaction fails.
    pub fn upsert_repeater(&self, context: &RepeaterContext) -> Result<(), Diagnostic> {
        validate_repeater(context)?;
        let current = self.stored_repeater_request(&context.current)?;
        let history = context
            .history
            .iter()
            .map(|entry| self.stored_repeater_revision(entry))
            .collect::<Result<Vec<_>, _>>()?;
        let current_json = serde_json::to_string(&current)
            .map_err(|e| serialization_diag("repeater.current", &e.to_string()))?;
        let history_json = serde_json::to_string(&history)
            .map_err(|e| serialization_diag("repeater.history", &e.to_string()))?;
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_REPEATER_HISTORY_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute(
                "INSERT INTO repeater_contexts (id,source_flow_id,created_at,current_json,history_json)
                 VALUES (?1,?2,?3,?4,?5)
                 ON CONFLICT(id) DO UPDATE SET source_flow_id=excluded.source_flow_id,created_at=excluded.created_at,current_json=excluded.current_json,history_json=excluded.history_json",
                params![
                    context.id,
                    context.source_flow_id.map(|id| i64::try_from(id).unwrap_or(i64::MAX)),
                    context.created_at.to_rfc3339_opts(SecondsFormat::Nanos, true),
                    current_json,
                    history_json,
                ],
            )
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_REPEATER_HISTORY_FAILED,
                    "write",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        Ok(())
    }

    /// Loads all repeater contexts ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the context table or its serialized request
    /// and history records cannot be read.
    pub fn repeater_contexts(&self) -> Result<Vec<RepeaterContext>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_REPEATER_HISTORY_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let mut statement = connection
            .prepare(
                "SELECT id,source_flow_id,created_at,current_json,history_json FROM repeater_contexts ORDER BY created_at,id",
            )
            .map_err(|e| storage_diag(catalogue::PROXY_REPEATER_HISTORY_FAILED, "query", &self.root, &e.to_string()))?;
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
                ))
            })
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_REPEATER_HISTORY_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        let mut contexts = Vec::new();
        for row in rows {
            let (id, source_flow_id, created_at, current, history) = row.map_err(|e| {
                storage_diag(
                    catalogue::PROXY_REPEATER_HISTORY_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
            contexts.push(RepeaterContext {
                id,
                source_flow_id: source_flow_id.and_then(|id| u64::try_from(id).ok()),
                created_at: parse_time(&created_at),
                current: self.resolve_repeater_request(
                    serde_json::from_str(&current)
                        .map_err(|e| serialization_diag("repeater.current", &e.to_string()))?,
                )?,
                history: serde_json::from_str::<Vec<StoredRepeaterRevision>>(&history)
                    .map_err(|e| serialization_diag("repeater.history", &e.to_string()))?
                    .into_iter()
                    .map(|entry| self.resolve_repeater_revision(entry))
                    .collect::<Result<Vec<_>, _>>()?,
            });
        }
        Ok(contexts)
    }

    /// Persists one bounded intruder job and its results.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the job cannot be serialized or committed.
    pub fn upsert_intruder(&self, job: &IntruderJob) -> Result<(), Diagnostic> {
        validate_intruder(job)?;
        let config_json = serde_json::to_string(&self.stored_intruder_config(&job.config)?)
            .map_err(|e| serialization_diag("intruder.config", &e.to_string()))?;
        let results_json = serde_json::to_string(
            &job.results
                .iter()
                .map(|result| self.stored_intruder_result(result))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|e| serialization_diag("intruder.results", &e.to_string()))?;
        let diagnostics_json = serde_json::to_string(&job.diagnostics)
            .map_err(|e| serialization_diag("intruder.diagnostics", &e.to_string()))?;
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        connection
            .execute(
                "INSERT INTO intruder_jobs (id,created_at,tier,state,config_json,results_json,diagnostics_json)
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
            .map_err(|e| storage_diag(catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED, "write", &self.root, &e.to_string()))?;
        Ok(())
    }

    /// Loads persisted intruder jobs ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when a job row or its structured payload is
    /// malformed.
    pub fn intruder_jobs(&self) -> Result<Vec<IntruderJob>, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let mut statement = connection
            .prepare("SELECT id,created_at,tier,state,config_json,results_json,diagnostics_json FROM intruder_jobs ORDER BY created_at,id")
            .map_err(|e| storage_diag(catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED, "query", &self.root, &e.to_string()))?;
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
                    catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        let mut jobs = Vec::new();
        for row in rows {
            let (id, created_at, tier, state, config, results, diagnostics) = row.map_err(|e| {
                storage_diag(
                    catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED,
                    "row",
                    &self.root,
                    &e.to_string(),
                )
            })?;
            jobs.push(IntruderJob {
                id,
                created_at: parse_time(&created_at),
                tier: serde_json::from_str(&tier)
                    .map_err(|e| serialization_diag("intruder.tier", &e.to_string()))?,
                state: serde_json::from_str(&state)
                    .map_err(|e| serialization_diag("intruder.state", &e.to_string()))?,
                config: self.resolve_intruder_config(
                    serde_json::from_str(&config)
                        .map_err(|e| serialization_diag("intruder.config", &e.to_string()))?,
                )?,
                results: serde_json::from_str::<Vec<StoredIntruderResult>>(&results)
                    .map_err(|e| serialization_diag("intruder.results", &e.to_string()))?
                    .into_iter()
                    .map(|result| self.resolve_intruder_result(result))
                    .collect::<Result<Vec<_>, _>>()?,
                diagnostics: serde_json::from_str(&diagnostics)
                    .map_err(|e| serialization_diag("intruder.diagnostics", &e.to_string()))?,
            });
        }
        Ok(jobs)
    }

    fn stored_repeater_request(
        &self,
        request: &RepeaterRequest,
    ) -> Result<StoredRepeaterRequest, Diagnostic> {
        Ok(StoredRepeaterRequest {
            method: request.method.clone(),
            url: request.url.clone(),
            headers: request.headers.clone(),
            body_hash: self.write_blob(request.body.as_deref())?,
        })
    }

    fn stored_intruder_config(
        &self,
        config: &IntruderConfig,
    ) -> Result<StoredIntruderConfig, Diagnostic> {
        Ok(StoredIntruderConfig {
            base_request: self.stored_repeater_request(&config.base_request)?,
            positions: config.positions.clone(),
            payload_sets: config.payload_sets.clone(),
            attack_type: config.attack_type,
            match_filter: config.match_filter.clone(),
            concurrency: config.concurrency,
            rate_per_second: config.rate_per_second,
            max_results: config.max_results,
            auth_preflight: config
                .auth_preflight
                .as_ref()
                .map(|request| self.stored_repeater_request(request))
                .transpose()?,
            sequence: config
                .sequence
                .iter()
                .map(|step| {
                    Ok(StoredIntruderSequenceStep {
                        name: step.name.clone(),
                        request: self.stored_repeater_request(&step.request)?,
                        extractors: step.extractors.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Diagnostic>>()?,
            auto_calibrate: config.auto_calibrate,
        })
    }

    fn resolve_intruder_config(
        &self,
        config: StoredIntruderConfig,
    ) -> Result<IntruderConfig, Diagnostic> {
        Ok(IntruderConfig {
            base_request: self.resolve_repeater_request(config.base_request)?,
            positions: config.positions,
            payload_sets: config.payload_sets,
            attack_type: config.attack_type,
            match_filter: config.match_filter,
            concurrency: config.concurrency,
            rate_per_second: config.rate_per_second,
            max_results: config.max_results,
            auth_preflight: config
                .auth_preflight
                .map(|request| self.resolve_repeater_request(request))
                .transpose()?,
            sequence: config
                .sequence
                .into_iter()
                .map(|step| {
                    Ok(IntruderSequenceStep {
                        name: step.name,
                        request: self.resolve_repeater_request(step.request)?,
                        extractors: step.extractors,
                    })
                })
                .collect::<Result<Vec<_>, Diagnostic>>()?,
            auto_calibrate: config.auto_calibrate,
        })
    }

    fn stored_intruder_result(
        &self,
        result: &IntruderResult,
    ) -> Result<StoredIntruderResult, Diagnostic> {
        Ok(StoredIntruderResult {
            ordinal: result.ordinal,
            payloads: result.payloads.clone(),
            request: self.stored_repeater_request(&result.request)?,
            response: result
                .response
                .as_ref()
                .map(|response| self.stored_repeater_response(response))
                .transpose()?,
            matched: result.matched,
            filtered: result.filtered,
            diff: result.diff.clone(),
            scope: result.scope,
            diagnostic: result.diagnostic.clone(),
        })
    }

    fn resolve_intruder_result(
        &self,
        result: StoredIntruderResult,
    ) -> Result<IntruderResult, Diagnostic> {
        Ok(IntruderResult {
            ordinal: result.ordinal,
            payloads: result.payloads,
            request: self.resolve_repeater_request(result.request)?,
            response: result
                .response
                .map(|response| {
                    Ok(RepeaterResponse {
                        status: response.status,
                        headers: response.headers,
                        body: self.read_blob(response.body_hash.as_deref())?,
                        duration_ms: response.duration_ms,
                    })
                })
                .transpose()?,
            matched: result.matched,
            filtered: result.filtered,
            diff: result.diff,
            scope: result.scope,
            diagnostic: result.diagnostic,
        })
    }

    fn stored_repeater_response(
        &self,
        response: &RepeaterResponse,
    ) -> Result<StoredRepeaterResponse, Diagnostic> {
        Ok(StoredRepeaterResponse {
            status: response.status,
            headers: response.headers.clone(),
            body_hash: self.write_blob(response.body.as_deref())?,
            duration_ms: response.duration_ms,
        })
    }

    fn stored_repeater_revision(
        &self,
        revision: &RepeaterRevision,
    ) -> Result<StoredRepeaterRevision, Diagnostic> {
        Ok(StoredRepeaterRevision {
            revision: revision.revision,
            sent_at: revision.sent_at,
            request: self.stored_repeater_request(&revision.request)?,
            response: revision
                .response
                .as_ref()
                .map(|response| self.stored_repeater_response(response))
                .transpose()?,
            diagnostic: revision.diagnostic.clone(),
            scope: revision.scope,
        })
    }

    fn resolve_repeater_request(
        &self,
        request: StoredRepeaterRequest,
    ) -> Result<RepeaterRequest, Diagnostic> {
        Ok(RepeaterRequest {
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: self.read_blob(request.body_hash.as_deref())?,
        })
    }

    fn resolve_repeater_revision(
        &self,
        revision: StoredRepeaterRevision,
    ) -> Result<RepeaterRevision, Diagnostic> {
        Ok(RepeaterRevision {
            revision: revision.revision,
            sent_at: revision.sent_at,
            request: self.resolve_repeater_request(revision.request)?,
            response: revision
                .response
                .map(|response| {
                    Ok(RepeaterResponse {
                        status: response.status,
                        headers: response.headers,
                        body: self.read_blob(response.body_hash.as_deref())?,
                        duration_ms: response.duration_ms,
                    })
                })
                .transpose()?,
            diagnostic: revision.diagnostic,
            scope: revision.scope,
        })
    }

    fn next_id(&self) -> Result<u64, Diagnostic> {
        let connection = self.connection.lock().map_err(|_| {
            storage_diag(
                catalogue::PROXY_STORE_WRITE_FAILED,
                "lock",
                &self.root,
                "database mutex poisoned",
            )
        })?;
        let id: i64 = connection
            .query_row("SELECT COALESCE(MAX(id),0)+1 FROM flows", [], |row| {
                row.get(0)
            })
            .map_err(|e| {
                storage_diag(
                    catalogue::PROXY_STORE_WRITE_FAILED,
                    "next-id",
                    &self.root,
                    &e.to_string(),
                )
            })?;
        Ok(u64::try_from(id).unwrap_or(u64::MAX))
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
        let tmp = self.blobs.join(format!(".{hash}.tmp"));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // A crashed writer may leave an incomplete temp blob. It is
                // never referenced by SQLite, so it is safe to replace.
                let _ = fs::remove_file(&tmp);
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
                    .map_err(|retry| {
                        storage_diag(
                            catalogue::PROXY_STORE_WRITE_FAILED,
                            "blob-create",
                            &tmp,
                            &retry.to_string(),
                        )
                    })?
            }
            Err(error) => {
                return Err(storage_diag(
                    catalogue::PROXY_STORE_WRITE_FAILED,
                    "blob-create",
                    &tmp,
                    &error.to_string(),
                ));
            }
        };
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRepeaterRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRepeaterResponse {
    status: u16,
    headers: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_hash: Option<String>,
    duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRepeaterRevision {
    revision: u64,
    sent_at: DateTime<Utc>,
    request: StoredRepeaterRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<StoredRepeaterResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
    scope: ScopeDisposition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIntruderConfig {
    base_request: StoredRepeaterRequest,
    positions: Vec<PayloadPosition>,
    payload_sets: Vec<PayloadSet>,
    attack_type: IntruderAttackType,
    match_filter: IntruderMatchFilter,
    concurrency: usize,
    rate_per_second: u32,
    max_results: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_preflight: Option<StoredRepeaterRequest>,
    sequence: Vec<StoredIntruderSequenceStep>,
    #[serde(default)]
    auto_calibrate: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIntruderSequenceStep {
    name: String,
    request: StoredRepeaterRequest,
    extractors: Vec<IntruderTokenExtractor>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredIntruderResult {
    ordinal: u64,
    payloads: Vec<String>,
    request: StoredRepeaterRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<StoredRepeaterResponse>,
    matched: bool,
    filtered: bool,
    diff: IntruderResponseDiff,
    scope: ScopeDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<Diagnostic>,
}

fn ensure_flows_url_column(connection: &Connection, database: &Path) -> Result<(), Diagnostic> {
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
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| {
            storage_diag(
                catalogue::PROXY_STORE_OPEN_FAILED,
                "schema",
                database,
                &error.to_string(),
            )
        })?;
    let has_url = columns.filter_map(Result::ok).any(|name| name == "url");
    if !has_url {
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
    /// Persisted repeater contexts and their linear histories.
    #[serde(default)]
    pub repeater_contexts: Vec<RepeaterContext>,
    /// Persisted intruder jobs and bounded results.
    #[serde(default)]
    pub intruder_jobs: Vec<IntruderJob>,
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

fn validate_repeater(context: &RepeaterContext) -> Result<(), Diagnostic> {
    if context.id.trim().is_empty()
        || context.current.method.trim().is_empty()
        || context.current.url.trim().is_empty()
    {
        return Err(storage_diag(
            catalogue::PROXY_REPEATER_HISTORY_FAILED,
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
                catalogue::PROXY_REPEATER_HISTORY_FAILED,
                "validate",
                Path::new(""),
                "history revisions must be contiguous and contain method and URL",
            ));
        }
    }
    Ok(())
}

fn validate_intruder(job: &IntruderJob) -> Result<(), Diagnostic> {
    if job.id.trim().is_empty()
        || job.config.base_request.method.trim().is_empty()
        || job.config.base_request.url.trim().is_empty()
        || job
            .config
            .payload_sets
            .iter()
            .any(|set| set.values.is_empty())
        || job.config.positions.is_empty()
        || job.config.max_results == 0
    {
        return Err(storage_diag(
            catalogue::PROXY_INTRUDER_CONFIG_INVALID,
            "validate",
            Path::new(""),
            "job ID, request, positions, payload sets, and result limit must be usable",
        ));
    }
    if job.results.len() > job.config.max_results {
        return Err(storage_diag(
            catalogue::PROXY_INTRUDER_PERSISTENCE_FAILED,
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
            other.import_har(&har, "har.import", classify).expect("import"),
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
    fn repeater_contexts_round_trip_through_sqlite_and_snapshot() {
        let store = store();
        let context = RepeaterContext {
            id: "repeater-test".to_owned(),
            source_flow_id: Some(7),
            created_at: Utc::now(),
            current: RepeaterRequest {
                method: "POST".to_owned(),
                url: "https://api.example.test/items?id=1".to_owned(),
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body: Some(br#"{"name":"first"}"#.to_vec()),
            },
            history: vec![RepeaterRevision {
                revision: 1,
                sent_at: Utc::now(),
                request: RepeaterRequest {
                    method: "POST".to_owned(),
                    url: "https://api.example.test/items?id=1".to_owned(),
                    headers: vec![],
                    body: Some(b"first".to_vec()),
                },
                response: Some(RepeaterResponse {
                    status: 201,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"{\"ok\":true}".to_vec()),
                    duration_ms: 12,
                }),
                diagnostic: None,
                scope: ScopeDisposition::InScope,
            }],
        };
        store.upsert_repeater(&context).expect("repeater persisted");
        assert_eq!(
            store.repeater_contexts().expect("repeater loaded"),
            vec![context]
        );
        assert_eq!(
            store.snapshot().expect("snapshot").repeater_contexts.len(),
            1
        );
    }

    #[test]
    fn intruder_jobs_round_trip_with_content_addressed_request_and_response_bodies() {
        let store = store();
        let request = RepeaterRequest {
            method: "GET".to_owned(),
            url: "https://api.example.test/items?id=FUZZ".to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: Some(b"request-body".to_vec()),
        };
        let job = IntruderJob {
            id: "intruder-test".to_owned(),
            created_at: Utc::now(),
            tier: IntruderTier::Native,
            state: IntruderJobState::Completed,
            config: IntruderConfig {
                base_request: request.clone(),
                positions: vec![PayloadPosition {
                    location: IntruderPositionLocation::Url,
                    header_name: None,
                    start: 31,
                    end: 35,
                    set_index: 0,
                }],
                payload_sets: vec![PayloadSet {
                    name: "ids".to_owned(),
                    values: vec!["1".to_owned()],
                }],
                attack_type: IntruderAttackType::Sniper,
                match_filter: IntruderMatchFilter::default(),
                concurrency: 1,
                rate_per_second: 0,
                max_results: 10,
                auth_preflight: None,
                sequence: Vec::new(),
                auto_calibrate: false,
            },
            results: vec![IntruderResult {
                ordinal: 1,
                payloads: vec!["1".to_owned()],
                request,
                response: Some(RepeaterResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"response-body".to_vec()),
                    duration_ms: 4,
                }),
                matched: true,
                filtered: false,
                diff: IntruderResponseDiff::default(),
                scope: ScopeDisposition::InScope,
                diagnostic: None,
            }],
            diagnostics: Vec::new(),
        };
        store.upsert_intruder(&job).expect("intruder persisted");
        assert_eq!(store.intruder_jobs().expect("intruder loaded"), vec![job]);
        assert_eq!(store.snapshot().expect("snapshot").intruder_jobs.len(), 1);
        assert_eq!(
            fs::read_dir(store.root().join("blobs"))
                .expect("blobs")
                .count(),
            2
        );
    }
}
