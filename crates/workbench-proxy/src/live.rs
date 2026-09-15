//! In-memory live traffic and intercept state for the 2.2 workbench surface.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, catalogue};
use apiaxess_session::{ActionTarget, EngagementScope, ScopeDisposition};
use getrandom::fill;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::{BodyDirection, FlowEvent, FlowObserver, InterceptController};
use apiaxess_workbench_store::{FlowCapture, TrafficStore};

const TELEMETRY_CAPACITY: usize = 256;
const MAX_LIVE_FLOWS: usize = 1_000;

/// A compact flow item sent over the lossy telemetry channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSummary {
    /// Stable session-local flow identifier.
    pub id: u64,
    /// Negotiated protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// HTTP method, when the request side was observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Request host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Exact request URL, including scheme, authority, port, path, and query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Request path and query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Response status, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Elapsed duration. The current backend observer reports this when the
    /// paired response arrives; it is absent for incomplete flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Response content type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Observed body size from protocol metadata, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Full in-memory flow detail fetched after selecting a live flow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowDetail {
    /// Compact summary.
    pub summary: FlowSummary,
    /// Request headers.
    pub request_headers: Vec<(String, String)>,
    /// Response headers.
    pub response_headers: Vec<(String, String)>,
    /// Request body, when the backend retained it within the session limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<Vec<u8>>,
    /// Response body, when the backend retained it within the session limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<Vec<u8>>,
}

/// Internal record retained only for the active session.
#[derive(Clone, Debug)]
pub struct FlowRecord {
    /// Full flow detail.
    pub detail: FlowDetail,
    captured_at: chrono::DateTime<chrono::Utc>,
    created_at: std::time::Instant,
}

/// One coalesced telemetry update.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveUpdate {
    /// Flow summaries in this batch.
    pub flows: Vec<FlowSummary>,
    /// Diagnostics emitted since the prior update.
    pub diagnostics: Vec<Diagnostic>,
    /// Live credential prompts the engine is blocking on (never carries secrets).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prompts: Vec<CredentialPrompt>,
}

/// One field an operator should fill on a login/OTP screen. Carries no value.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPromptField {
    /// Stable field key (resource-id or synthesized index).
    pub name: String,
    /// Human-readable hint for the operator.
    pub label: String,
    /// Inferred field role (`username`, `password`, `email`, `otp`, ...).
    pub kind: String,
    /// Whether the value is sensitive and must be masked in the prompt input.
    pub secret: bool,
}

/// A live credential prompt announced to the GUI over telemetry. It describes
/// only the *shape* of what is needed; the operator's answer returns over the
/// control channel and never appears here.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPrompt {
    /// Correlates the telemetry announcement with the control-channel answer.
    pub id: u64,
    /// Package under crawl.
    pub package: String,
    /// Short screen description.
    pub screen_summary: String,
    /// Why credentials are needed (`login_gate` or `otp`).
    pub reason: String,
    /// Fields to fill.
    pub fields: Vec<CredentialPromptField>,
}

/// The operator's answer to a [`CredentialPrompt`], received over the control
/// channel. Values are held in memory only and are never logged or persisted.
pub struct CredentialPromptAnswer {
    /// Whether the operator chose to continue without supplying credentials.
    pub skip: bool,
    /// Field name → value the operator supplied.
    pub values: Vec<(String, String)>,
}

/// Session-scoped live traffic store and transport-facing state.
#[derive(Debug)]
pub struct LiveWorkbench {
    token: Arc<str>,
    intercept: Arc<InterceptController>,
    flows: Mutex<BTreeMap<u64, FlowRecord>>,
    diagnostics: Mutex<Vec<Diagnostic>>,
    updates: broadcast::Sender<LiveUpdate>,
    closed: AtomicBool,
    store: RwLock<Option<Arc<TrafficStore>>>,
    engagement_scope: RwLock<Option<EngagementScope>>,
    /// When set, every captured flow classifies `InScope` regardless of the
    /// declared scope. Used by the sandboxed APK dynamic pass, where the app
    /// itself made every captured call: an observed, decrypted hit *is* the
    /// honesty guarantee, so every host the app is seen contacting — first-party
    /// backend and third-party SDK/telemetry alike — is real surface to fuse.
    admit_all_observed: AtomicBool,
    provenance: RwLock<String>,
    prompt_pending: Mutex<HashMap<u64, mpsc::Sender<CredentialPromptAnswer>>>,
    prompt_next_id: AtomicU64,
    /// Flow-id fallback used only before a durable store is attached (early setup
    /// and store-less tests). Once a store is attached, `allocate_flow_id`
    /// delegates to the store's single authoritative allocator so live capture
    /// and every other source share one id sequence.
    fallback_flow_id: AtomicU64,
}

impl LiveWorkbench {
    /// Creates a new live session with a cryptographically random token.
    #[must_use]
    pub fn new() -> Self {
        let mut token_bytes = [0_u8; 32];
        if fill(&mut token_bytes).is_err() {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos());
            token_bytes[..16].copy_from_slice(&nanos.to_le_bytes());
        }
        let mut token = String::with_capacity(token_bytes.len() * 2);
        for byte in token_bytes {
            let _ = write!(token, "{byte:02x}");
        }
        let (updates, _) = broadcast::channel(TELEMETRY_CAPACITY);
        Self {
            token: token.into(),
            intercept: Arc::new(InterceptController::default()),
            flows: Mutex::new(BTreeMap::new()),
            diagnostics: Mutex::new(Vec::new()),
            updates,
            closed: AtomicBool::new(false),
            store: RwLock::new(None),
            engagement_scope: RwLock::new(None),
            admit_all_observed: AtomicBool::new(false),
            provenance: RwLock::new("proxy.observer".to_owned()),
            prompt_pending: Mutex::new(HashMap::new()),
            prompt_next_id: AtomicU64::new(1),
            fallback_flow_id: AtomicU64::new(1),
        }
    }

    /// Returns the per-session bearer token. It is never persisted.
    #[must_use]
    pub fn auth_token(&self) -> &str {
        &self.token
    }

    /// Returns the controller used by the routed proxy backend.
    #[must_use]
    pub fn intercept_controller(&self) -> Arc<InterceptController> {
        Arc::clone(&self.intercept)
    }

    /// Subscribes to the bounded, lossy telemetry stream.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<LiveUpdate> {
        self.updates.subscribe()
    }

    /// Attaches the session's crash-durable traffic store.
    pub fn attach_store(&self, store: Arc<TrafficStore>) {
        if let Ok(mut current) = self.store.write() {
            *current = Some(store);
        }
        if let Ok(mut flows) = self.flows.lock() {
            flows.clear();
        }
    }

    /// Sets the engagement scope used to classify captured network flows.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        if let Ok(mut current) = self.engagement_scope.write() {
            *current = Some(scope);
        }
    }

    /// Admits every captured flow as `InScope`, bypassing declared-scope
    /// classification. Set for the sandboxed APK dynamic pass, where the crawled
    /// app made every captured call, so every observed host is real surface —
    /// see [`Self::admit_all_observed`].
    pub fn set_admit_all_observed(&self, admit: bool) {
        self.admit_all_observed.store(admit, Ordering::SeqCst);
    }

    /// Sets the provenance label retained with every subsequently persisted flow.
    pub fn set_provenance(&self, provenance: impl Into<String>) {
        if let Ok(mut current) = self.provenance.write() {
            *current = provenance.into();
        }
    }

    /// Reads a flow from the durable store when one is attached.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the durable store cannot read or validate the
    /// requested flow.
    pub fn durable_flow(&self, flow_id: u64) -> Result<Option<FlowDetail>, Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Ok(self.flow(flow_id));
        };
        store
            .get(flow_id)
            .map(|flow| flow.map(flow_detail_from_capture))
    }

    /// Reads metadata from the durable store when one is attached.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the durable store cannot query its metadata.
    pub fn durable_summaries(&self) -> Result<Option<Vec<FlowSummary>>, Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Ok(None);
        };
        store
            .summaries()
            .map(|flows| Some(flows.into_iter().map(flow_summary_from_store).collect()))
    }

    /// Returns a selected flow's full in-memory detail.
    #[must_use]
    pub fn flow(&self, flow_id: u64) -> Option<FlowDetail> {
        self.flows
            .lock()
            .ok()
            .and_then(|flows| flows.get(&flow_id).map(|flow| flow.detail.clone()))
    }

    /// Returns recent summaries for initial GUI hydration.
    #[must_use]
    pub fn recent_summaries(&self) -> Vec<FlowSummary> {
        self.flows
            .lock()
            .map(|flows| {
                flows
                    .values()
                    .map(|flow| flow.detail.summary.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Marks the live state closed and releases any paused requests.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.intercept.set_enabled(false);
        self.intercept.release();
        if let Ok(mut flows) = self.flows.lock() {
            flows.clear();
        }
    }

    /// Whether the session has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Publishes a session diagnostic to connected telemetry clients.
    pub fn publish_diagnostic(&self, diagnostic: Diagnostic) {
        if let Ok(mut diagnostics) = self.diagnostics.lock() {
            diagnostics.push(diagnostic.clone());
            diagnostics.truncate(100);
        }
        let _ = self.updates.send(LiveUpdate {
            flows: Vec::new(),
            diagnostics: vec![diagnostic],
            prompts: Vec::new(),
        });
    }

    /// Blocks the calling thread until the operator answers a live credential
    /// prompt, or the timeout elapses. The prompt (field shapes only, no values)
    /// is announced over telemetry; the answer arrives over the control channel.
    ///
    /// Runtime-agnostic (uses a std channel) so it is safe to call from the
    /// pipeline's dedicated capture thread. Returns `None` on timeout — the
    /// caller treats that as "continue without credentials".
    #[must_use]
    pub fn request_credential_prompt(
        &self,
        prompt: CredentialPrompt,
        timeout: Duration,
    ) -> Option<CredentialPromptAnswer> {
        let id = prompt.id;
        let (sender, receiver) = mpsc::channel();
        if let Ok(mut pending) = self.prompt_pending.lock() {
            pending.insert(id, sender);
        } else {
            return None;
        }
        let _ = self.updates.send(LiveUpdate {
            flows: Vec::new(),
            diagnostics: Vec::new(),
            prompts: vec![prompt],
        });
        let Ok(answer) = receiver.recv_timeout(timeout) else {
            if let Ok(mut pending) = self.prompt_pending.lock() {
                pending.remove(&id);
            }
            return None;
        };
        Some(answer)
    }

    /// Allocates the next prompt id.
    #[must_use]
    pub fn next_prompt_id(&self) -> u64 {
        self.prompt_next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Resolves a pending credential prompt with the operator's answer. Returns
    /// whether a prompt was waiting for that id.
    pub fn answer_credential_prompt(&self, id: u64, answer: CredentialPromptAnswer) -> bool {
        let sender = self
            .prompt_pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&id));
        sender.is_some_and(|sender| sender.send(answer).is_ok())
    }

    /// Ids of prompts currently awaiting an answer (for a reconnecting client).
    #[must_use]
    pub fn pending_prompt_ids(&self) -> Vec<u64> {
        self.prompt_pending
            .lock()
            .map(|pending| pending.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Returns the recent diagnostics retained for a reconnecting GUI client.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics
            .lock()
            .map(|diagnostics| diagnostics.clone())
            .unwrap_or_default()
    }
}

impl Default for LiveWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowObserver for LiveWorkbench {
    fn allocate_flow_id(&self) -> u64 {
        // The attached durable store is the single authority for flow ids across
        // all concurrent sources. Only when no store is attached yet (early setup
        // or a store-less test) does allocation fall back to a local monotonic
        // counter, which never coexists with a shared persistence layer.
        if let Some(store) = self.store.read().ok().and_then(|store| store.clone()) {
            return store.allocate_flow_id();
        }
        self.fallback_flow_id.fetch_add(1, Ordering::SeqCst)
    }

    #[allow(clippy::too_many_lines)]
    fn observe(&self, event: FlowEvent) {
        if self.is_closed() {
            return;
        }
        if let FlowEvent::Diagnostic(diagnostic) = event {
            self.publish_diagnostic(diagnostic);
            return;
        }
        if let FlowEvent::BodyChunk {
            flow_id,
            direction,
            bytes,
        } = event
        {
            if let Ok(mut flows) = self.flows.lock()
                && let Some(flow) = flows.get_mut(&flow_id)
            {
                let target = match direction {
                    BodyDirection::Request => &mut flow.detail.request_body,
                    BodyDirection::Response => &mut flow.detail.response_body,
                };
                target.get_or_insert_with(Vec::new).extend(bytes);
            }
            self.persist_flow(flow_id);
            return;
        }
        let (flow_id, summary) = match event {
            FlowEvent::Request {
                flow_id,
                method,
                uri,
                headers,
                version,
                ..
            } => {
                let (host, path) = split_uri(&uri);
                let summary = FlowSummary {
                    id: flow_id,
                    protocol: Some(protocol_from_version(&version)),
                    method: Some(method),
                    host,
                    url: Some(uri),
                    path,
                    status: None,
                    duration_ms: None,
                    content_type: None,
                    size: None,
                };
                let detail = FlowDetail {
                    summary: summary.clone(),
                    request_headers: headers,
                    response_headers: Vec::new(),
                    request_body: None,
                    response_body: None,
                };
                if let Ok(mut flows) = self.flows.lock() {
                    flows.insert(
                        flow_id,
                        FlowRecord {
                            detail,
                            captured_at: chrono::Utc::now(),
                            created_at: std::time::Instant::now(),
                        },
                    );
                    while flows.len() > MAX_LIVE_FLOWS {
                        let Some(first) = flows.keys().next().copied() else {
                            break;
                        };
                        flows.remove(&first);
                    }
                }
                (flow_id, summary)
            }
            FlowEvent::Response {
                flow_id,
                status,
                headers,
                ..
            } => {
                let mut summary = FlowSummary {
                    id: flow_id,
                    protocol: None,
                    method: None,
                    host: None,
                    url: None,
                    path: None,
                    status: Some(status),
                    duration_ms: None,
                    content_type: header_value(&headers, "content-type"),
                    size: header_value(&headers, "content-length")
                        .and_then(|value| value.parse().ok()),
                };
                if let Ok(mut flows) = self.flows.lock() {
                    if let Some(flow) = flows.get_mut(&flow_id) {
                        summary = flow.detail.summary.clone();
                        summary.status = Some(status);
                        summary.content_type = header_value(&headers, "content-type");
                        summary.size = header_value(&headers, "content-length")
                            .and_then(|value| value.parse().ok());
                        summary.duration_ms = Some(
                            u64::try_from(
                                flow.created_at
                                    .elapsed()
                                    .as_millis()
                                    .min(u128::from(u64::MAX)),
                            )
                            .unwrap_or(u64::MAX),
                        );
                        flow.detail.summary = summary.clone();
                        flow.detail.response_headers = headers;
                    }
                }
                (flow_id, summary)
            }
            FlowEvent::WebSocketMessage { .. } => return,
            FlowEvent::BodyChunk { .. } | FlowEvent::Diagnostic(_) => unreachable!(),
        };
        let _ = flow_id;
        self.persist_flow(flow_id);
        let _ = self.updates.send(LiveUpdate {
            flows: vec![summary],
            diagnostics: Vec::new(),
            prompts: Vec::new(),
        });
    }
}

impl LiveWorkbench {
    fn persist_flow(&self, flow_id: u64) {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return;
        };
        let Some(record) = self
            .flows
            .lock()
            .ok()
            .and_then(|flows| flows.get(&flow_id).cloned())
        else {
            return;
        };
        let scope = record
            .detail
            .summary
            .host
            .as_deref()
            .map_or(ScopeDisposition::Undetermined, |host| {
                self.classify_scope(host, record.detail.summary.url.as_deref())
            });
        let provenance = self.provenance.read().map_or_else(
            |_| "proxy.observer".to_owned(),
            |provenance| provenance.clone(),
        );
        let capture = FlowCapture {
            id: record.detail.summary.id,
            captured_at: record.captured_at,
            protocol: record
                .detail
                .summary
                .protocol
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            method: record.detail.summary.method.clone(),
            host: record.detail.summary.host.clone(),
            url: record.detail.summary.url.clone(),
            path: record.detail.summary.path.clone(),
            status: record.detail.summary.status,
            duration_ms: record.detail.summary.duration_ms,
            request_headers: record.detail.request_headers.clone(),
            response_headers: record.detail.response_headers.clone(),
            request_body: record.detail.request_body.clone(),
            response_body: record.detail.response_body.clone(),
            scope,
            provenance,
        };
        if let Err(diagnostic) = store.upsert(&capture) {
            self.publish_diagnostic(diagnostic);
        }
    }

    fn classify_scope(&self, host: &str, url: Option<&str>) -> ScopeDisposition {
        // Observed-hit mode: the sandboxed app itself made this call, so it is in
        // scope for analysis regardless of any declared host list.
        if self.admit_all_observed.load(Ordering::SeqCst) {
            return ScopeDisposition::InScope;
        }
        let Ok(scope) = self.engagement_scope.read() else {
            return ScopeDisposition::Undetermined;
        };
        let Some(scope) = scope.as_ref() else {
            return ScopeDisposition::Undetermined;
        };
        let port = url
            .and_then(|value| value.parse::<reqwest::Url>().ok())
            .and_then(|value| value.port_or_known_default());
        scope
            .assess(&ActionTarget::Network {
                host: host.to_owned(),
                port,
            })
            .disposition
    }

    /// Imports HAR entries into the attached durable store.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no store is attached or HAR parsing or
    /// persistence fails.
    pub fn import_har(&self, bytes: &[u8], provenance: &str) -> Result<usize, Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(catalogue::PROXY_STORE_OPEN_FAILED.instantiate(DiagnosticContext::new()));
        };
        // Classify each imported flow against the engagement scope, mirroring
        // `persist_flow` for live capture, so in-scope imported traffic fuses into
        // endpoints instead of being dropped as `Undetermined`.
        store.import_har(bytes, provenance, |host, url| {
            host.map_or(ScopeDisposition::Undetermined, |host| {
                self.classify_scope(host, url)
            })
        })
    }

    /// Exports the attached durable store as HAR interchange bytes.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no store is attached or export fails.
    pub fn export_har(&self) -> Result<Vec<u8>, Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(catalogue::PROXY_STORE_OPEN_FAILED.instantiate(DiagnosticContext::new()));
        };
        store.export_har()
    }
}

fn flow_summary_from_store(flow: apiaxess_workbench_store::FlowSummary) -> FlowSummary {
    FlowSummary {
        id: flow.id,
        protocol: Some(flow.protocol),
        method: flow.method,
        host: flow.host,
        url: flow.url,
        path: flow.path,
        status: flow.status,
        duration_ms: flow.duration_ms,
        content_type: flow.content_type,
        size: flow.response_size,
    }
}

fn flow_detail_from_capture(flow: FlowCapture) -> FlowDetail {
    FlowDetail {
        summary: FlowSummary {
            id: flow.id,
            protocol: Some(flow.protocol),
            method: flow.method,
            host: flow.host,
            url: flow.url,
            path: flow.path,
            status: flow.status,
            duration_ms: flow.duration_ms,
            content_type: flow.response_headers.iter().find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    .then(|| value.clone())
            }),
            size: flow.response_body.as_ref().map(|body| body.len() as u64),
        },
        request_headers: flow.request_headers,
        response_headers: flow.response_headers,
        request_body: flow.request_body,
        response_body: flow.response_body,
    }
}

fn split_uri(uri: &str) -> (Option<String>, Option<String>) {
    let without_scheme = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let (authority, path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, "/"));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    (
        (!host.is_empty()).then(|| host.to_owned()),
        Some(format!("/{path}")),
    )
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then(|| value.clone()))
}

fn protocol_from_version(version: &str) -> String {
    if version.contains('2') {
        "h2".to_owned()
    } else if version.contains('1') {
        "h1".to_owned()
    } else {
        version.to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_tokens_are_distinct_and_flow_details_are_lazy_but_complete() {
        let first = LiveWorkbench::new();
        let second = LiveWorkbench::new();
        assert_ne!(first.auth_token(), second.auth_token());
        first.observe(FlowEvent::Request {
            flow_id: 9,
            method: "POST".to_owned(),
            uri: "https://api.example.test/v1/items?x=1".to_owned(),
            version: "HTTP/2".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        });
        first.observe(FlowEvent::BodyChunk {
            flow_id: 9,
            direction: BodyDirection::Request,
            bytes: br#"{"name":"item"}"#.to_vec(),
        });
        first.observe(FlowEvent::Response {
            flow_id: 9,
            client_addr: "127.0.0.1:9".parse().expect("address"),
            status: 201,
            version: "HTTP/2".to_owned(),
            headers: vec![("content-length".to_owned(), "2".to_owned())],
        });
        let detail = first.flow(9).expect("flow detail");
        assert_eq!(detail.summary.host.as_deref(), Some("api.example.test"));
        assert_eq!(
            detail.summary.url.as_deref(),
            Some("https://api.example.test/v1/items?x=1")
        );
        assert_eq!(detail.summary.path.as_deref(), Some("/v1/items?x=1"));
        assert_eq!(detail.summary.status, Some(201));
        assert_eq!(detail.request_body, Some(br#"{"name":"item"}"#.to_vec()));
    }

    #[test]
    fn credential_prompt_blocks_until_answered() {
        let workbench = Arc::new(LiveWorkbench::new());
        let id = workbench.next_prompt_id();
        let prompt = CredentialPrompt {
            id,
            package: "com.demo".to_owned(),
            screen_summary: "login".to_owned(),
            reason: "login_gate".to_owned(),
            fields: Vec::new(),
        };
        let answerer = Arc::clone(&workbench);
        let handle = std::thread::spawn(move || {
            // Give the requester a moment to register the pending prompt.
            std::thread::sleep(Duration::from_millis(50));
            answerer.answer_credential_prompt(
                id,
                CredentialPromptAnswer {
                    skip: false,
                    values: vec![("user".to_owned(), "alice".to_owned())],
                },
            )
        });
        let answer = workbench
            .request_credential_prompt(prompt, Duration::from_secs(5))
            .expect("answered");
        assert!(!answer.skip);
        assert_eq!(answer.values[0].1, "alice");
        assert!(handle.join().unwrap());
    }

    #[test]
    fn credential_prompt_times_out_without_an_answer() {
        let workbench = LiveWorkbench::new();
        let id = workbench.next_prompt_id();
        let prompt = CredentialPrompt {
            id,
            package: "com.demo".to_owned(),
            screen_summary: "login".to_owned(),
            reason: "login_gate".to_owned(),
            fields: Vec::new(),
        };
        assert!(
            workbench
                .request_credential_prompt(prompt, Duration::from_millis(80))
                .is_none()
        );
        assert!(
            workbench.pending_prompt_ids().is_empty(),
            "timed-out prompt is cleaned up"
        );
    }
}
