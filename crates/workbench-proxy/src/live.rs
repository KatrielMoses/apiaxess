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

use crate::sse::{SseParser, is_event_stream};
use crate::{BodyDirection, FlowEvent, FlowObserver, InterceptController};
use apiaxess_workbench_store::{
    FlowCapture, FlowOrigin, SseEventRecord, SseStreamState, TrafficStore,
};

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
    /// How this flow entered the store. The Live list shows `capture` by default
    /// and hides Resend/Fuzz-synthesized traffic; always serialized so the GUI
    /// can filter and a future "show attack traffic" toggle can opt in.
    #[serde(default)]
    pub origin: FlowOrigin,
    /// Event-stream state, for a flow whose response is `text/event-stream`:
    /// a long-lived response read as a list of events, not one growing body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sse: Option<SseStreamState>,
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
    /// Size of a request body the store did not keep because the flow was
    /// outside the declared scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_withheld: Option<u64>,
    /// Size of a response body the store did not keep because the flow was
    /// outside the declared scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_withheld: Option<u64>,
}

/// Internal record retained only for the active session.
#[derive(Clone, Debug)]
pub struct FlowRecord {
    /// Full flow detail.
    pub detail: FlowDetail,
    captured_at: chrono::DateTime<chrono::Utc>,
    created_at: std::time::Instant,
    sse: Option<LiveSse>,
}

/// Live state of one flow's event stream.
#[derive(Clone, Debug, Default)]
struct LiveSse {
    parser: SseParser,
    event_count: u64,
    closed: bool,
    last_summary: Option<std::time::Instant>,
}

impl LiveSse {
    fn state(&self) -> SseStreamState {
        SseStreamState {
            event_count: self.event_count,
            closed: self.closed,
        }
    }
}

/// How often a streaming flow's row is refreshed while events arrive.
const SSE_SUMMARY_INTERVAL: Duration = Duration::from_millis(250);

/// Data carried per event on the live stream; the full retained data is read
/// from the events endpoint.
pub const LIVE_SSE_DATA_BYTES: usize = 64 * 1024;

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
    /// WebSocket connection and message events, as persisted (redacted). Tagged
    /// separately from `flows`: WebSocket traffic is its own view, never part of
    /// the HTTP flow list or fusion.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub websocket: Vec<LiveWebSocketEvent>,
    /// Server-Sent Events as persisted (redacted), data capped at
    /// [`LIVE_SSE_DATA_BYTES`]. Each belongs to an HTTP flow in `flows`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sse: Vec<SseEventRecord>,
}

/// One WebSocket event for the live telemetry stream.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveWebSocketEvent {
    /// The connection, with its current state and message count.
    pub connection: apiaxess_workbench_store::WsConnectionRecord,
    /// The message this event carries, when it is a message event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<LiveWebSocketMessage>,
}

/// A WebSocket message on the telemetry stream.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveWebSocketMessage {
    /// Position on the connection, from 1.
    pub sequence: u64,
    /// Sent or received.
    pub direction: apiaxess_workbench_store::WsDirection,
    /// Frame kind.
    pub kind: apiaxess_workbench_store::WsMessageKind,
    /// Retained payload (redacted), base64, capped at
    /// [`LIVE_WEBSOCKET_PAYLOAD_BYTES`] for the live stream.
    pub payload_base64: String,
    /// Bytes of payload in `payload_base64`.
    pub retained_bytes: u64,
    /// Full payload size on the wire.
    pub payload_bytes: u64,
    /// When the proxy observed it.
    pub observed_at: chrono::DateTime<chrono::Utc>,
}

/// Payload bytes carried per message on the live stream; the full retained
/// payload is read from the messages endpoint.
pub const LIVE_WEBSOCKET_PAYLOAD_BYTES: usize = 64 * 1024;

impl LiveWebSocketMessage {
    /// A live-stream view of a persisted message (payload capped for the stream).
    #[must_use]
    pub fn from_record(record: &apiaxess_workbench_store::WsMessageRecord) -> Self {
        Self::from_record_capped(record, LIVE_WEBSOCKET_PAYLOAD_BYTES)
    }

    /// A view of a persisted message carrying up to `cap` payload bytes.
    #[must_use]
    pub fn from_record_capped(
        record: &apiaxess_workbench_store::WsMessageRecord,
        cap: usize,
    ) -> Self {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let retained = &record.payload[..record.payload.len().min(cap)];
        Self {
            sequence: record.sequence,
            direction: record.direction,
            kind: record.kind,
            payload_base64: STANDARD.encode(retained),
            retained_bytes: u64::try_from(retained.len()).unwrap_or(u64::MAX),
            payload_bytes: record.payload_bytes,
            observed_at: record.observed_at,
        }
    }
}

/// Live state of one open WebSocket connection.
#[derive(Debug)]
struct LiveWsConnection {
    record: apiaxess_workbench_store::WsConnectionRecord,
    next_sequence: u64,
    client_closed: bool,
    server_closed: bool,
}

/// A durable streaming write (WebSocket or event stream), performed off the
/// forwarding path.
enum StreamWrite {
    Connection(
        Arc<TrafficStore>,
        apiaxess_workbench_store::WsConnectionRecord,
    ),
    Message(
        Arc<TrafficStore>,
        apiaxess_workbench_store::WsConnectionRecord,
        apiaxess_workbench_store::WsMessageRecord,
    ),
    SseOpen(Arc<TrafficStore>, u64, chrono::DateTime<chrono::Utc>),
    SseEvent(Arc<TrafficStore>, SseEventRecord),
    SseClose(Arc<TrafficStore>, u64, chrono::DateTime<chrono::Utc>),
}

/// An event with its data capped for the live stream.
fn live_sse_event(mut record: SseEventRecord) -> SseEventRecord {
    if record.data.len() > LIVE_SSE_DATA_BYTES {
        let mut end = LIVE_SSE_DATA_BYTES;
        while !record.data.is_char_boundary(end) {
            end -= 1;
        }
        record.data.truncate(end);
    }
    record
}

/// Persists streaming writes in order on a dedicated thread (so a chatty stream
/// never blocks forwarding on `SQLite`) and publishes each persisted, redacted
/// record on the live stream.
fn spawn_stream_writer(updates: broadcast::Sender<LiveUpdate>) -> mpsc::Sender<StreamWrite> {
    let (sender, receiver) = mpsc::channel::<StreamWrite>();
    std::thread::spawn(move || {
        for write in receiver {
            let event =
                match write {
                    StreamWrite::SseOpen(store, flow_id, at) => {
                        if let Err(diagnostic) = store.open_sse_stream(flow_id, at) {
                            let _ = updates.send(LiveUpdate {
                                diagnostics: vec![diagnostic],
                                ..LiveUpdate::default()
                            });
                        }
                        continue;
                    }
                    StreamWrite::SseClose(store, flow_id, at) => {
                        if let Err(diagnostic) = store.close_sse_stream(flow_id, at) {
                            let _ = updates.send(LiveUpdate {
                                diagnostics: vec![diagnostic],
                                ..LiveUpdate::default()
                            });
                        }
                        continue;
                    }
                    StreamWrite::SseEvent(store, record) => {
                        let update = match store.append_sse_event(&record) {
                            Ok(record) => LiveUpdate {
                                sse: vec![live_sse_event(record)],
                                ..LiveUpdate::default()
                            },
                            Err(diagnostic) => LiveUpdate {
                                diagnostics: vec![diagnostic],
                                ..LiveUpdate::default()
                            },
                        };
                        let _ = updates.send(update);
                        continue;
                    }
                    StreamWrite::Connection(store, record) => store
                        .upsert_ws_connection(&record)
                        .map(|connection| LiveWebSocketEvent {
                            connection,
                            message: None,
                        }),
                    StreamWrite::Message(store, connection, message) => {
                        store.append_ws_message(&message).and_then(|message| {
                            let connection = store.upsert_ws_connection(&connection)?;
                            Ok(LiveWebSocketEvent {
                                connection,
                                message: Some(LiveWebSocketMessage::from_record(&message)),
                            })
                        })
                    }
                };
            let update = match event {
                Ok(event) => LiveUpdate {
                    websocket: vec![event],
                    ..LiveUpdate::default()
                },
                Err(diagnostic) => LiveUpdate {
                    diagnostics: vec![diagnostic],
                    ..LiveUpdate::default()
                },
            };
            let _ = updates.send(update);
        }
    });
    sender
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
    /// Flows admitted in scope only because `admit_all_observed` was on (no
    /// scope declared yet). Once a scope is known they are re-classified
    /// against it, so browsing before declaring a target leaves no phantoms.
    admitted_without_scope: Mutex<std::collections::BTreeSet<u64>>,
    /// WebSocket connections admitted in scope only because of admit-all;
    /// re-classified with the flows once a scope is known.
    admitted_ws_without_scope: Mutex<std::collections::BTreeSet<u64>>,
    provenance: RwLock<String>,
    prompt_pending: Mutex<HashMap<u64, mpsc::Sender<CredentialPromptAnswer>>>,
    prompt_next_id: AtomicU64,
    /// Flow-id fallback used only before a durable store is attached (early setup
    /// and store-less tests). Once a store is attached, `allocate_flow_id`
    /// delegates to the store's single authoritative allocator so live capture
    /// and every other source share one id sequence.
    fallback_flow_id: AtomicU64,
    /// Open WebSocket connections by (client, URL).
    websockets: Mutex<HashMap<crate::WebSocketConnectionKey, LiveWsConnection>>,
    /// Ordered, off-path WebSocket and event-stream persistence.
    stream_writer: Mutex<mpsc::Sender<StreamWrite>>,
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
        let stream_writer = spawn_stream_writer(updates.clone());
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
            admitted_without_scope: Mutex::new(std::collections::BTreeSet::new()),
            admitted_ws_without_scope: Mutex::new(std::collections::BTreeSet::new()),
            provenance: RwLock::new("proxy.observer".to_owned()),
            prompt_pending: Mutex::new(HashMap::new()),
            prompt_next_id: AtomicU64::new(1),
            fallback_flow_id: AtomicU64::new(1),
            websockets: Mutex::new(HashMap::new()),
            stream_writer: Mutex::new(stream_writer),
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

    /// Whether every observed flow is currently admitted in scope.
    #[must_use]
    pub fn admits_all_observed(&self) -> bool {
        self.admit_all_observed.load(Ordering::SeqCst)
    }

    /// Ends admit-all because a scope is now known: turns it off and
    /// re-classifies every flow it admitted against the current scope, so
    /// browser background traffic and hosts outside the target leave the
    /// surface. Returns how many flows changed classification.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the store cannot be updated.
    pub fn end_admit_all_for_scope(&self) -> Result<usize, Diagnostic> {
        self.admit_all_observed.store(false, Ordering::SeqCst);
        let ids = self
            .admitted_without_scope
            .lock()
            .map(|mut ids| std::mem::take(&mut *ids))
            .unwrap_or_default();
        let ws_ids = self
            .admitted_ws_without_scope
            .lock()
            .map(|mut ids| std::mem::take(&mut *ids))
            .unwrap_or_default();
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Ok(0);
        };
        let classify = |host: Option<&str>, url: Option<&str>| {
            host.map_or(ScopeDisposition::Undetermined, |host| {
                self.classify_scope(host, url)
            })
        };
        if !ws_ids.is_empty() {
            self.relabel_ws_connections(&store, &ws_ids, &classify)?;
        }
        if ids.is_empty() {
            return Ok(0);
        }
        store.reclassify_flows(&ids.into_iter().collect::<Vec<_>>(), classify)
    }

    /// Re-classifies the WebSocket connections with `ids`. The relabelled
    /// record goes through the ordered stream writer, after any message
    /// writes already queued with the old label, so the new label is the one
    /// that persists; the writer then announces it to the WebSocket tab. An
    /// open connection's in-memory record is updated too, so its later
    /// messages carry the new label.
    fn relabel_ws_connections(
        &self,
        store: &Arc<TrafficStore>,
        ids: &std::collections::BTreeSet<u64>,
        classify: &dyn Fn(Option<&str>, Option<&str>) -> ScopeDisposition,
    ) -> Result<(), Diagnostic> {
        let mut records = store
            .ws_connections()?
            .into_iter()
            .filter(|record| ids.contains(&record.id))
            .map(|record| (record.id, record))
            .collect::<BTreeMap<_, _>>();
        let mut relabelled = Vec::new();
        if let Ok(mut websockets) = self.websockets.lock() {
            for live in websockets.values_mut() {
                if ids.contains(&live.record.id) {
                    let scope = classify(live.record.host.as_deref(), Some(&live.record.url));
                    if scope != live.record.scope {
                        live.record.scope = scope;
                        relabelled.push(live.record.clone());
                    }
                    records.remove(&live.record.id);
                }
            }
        }
        for mut record in records.into_values() {
            let scope = classify(record.host.as_deref(), Some(&record.url));
            if scope != record.scope {
                record.scope = scope;
                relabelled.push(record);
            }
        }
        for record in relabelled {
            self.enqueue_stream(StreamWrite::Connection(Arc::clone(store), record));
        }
        Ok(())
    }

    /// Pauses admit-all (the unscoped browser stopped): no new flow is
    /// admitted, but those already captured keep their admission until a
    /// scope is known, so browsing without a scope and fusing afterwards
    /// still works.
    pub fn pause_admit_all(&self) {
        self.admit_all_observed.store(false, Ordering::SeqCst);
    }

    /// Clears admit-all for a new session: its store starts with no flows
    /// admitted without a scope.
    pub fn reset_admit_all(&self) {
        self.admit_all_observed.store(false, Ordering::SeqCst);
        if let Ok(mut ids) = self.admitted_without_scope.lock() {
            ids.clear();
        }
        if let Ok(mut ids) = self.admitted_ws_without_scope.lock() {
            ids.clear();
        }
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
        let Some(mut detail) = store.get(flow_id)?.map(flow_detail_from_capture) else {
            return Ok(None);
        };
        detail.summary.sse = store.sse_state(flow_id)?;
        (detail.request_body_withheld, detail.response_body_withheld) =
            store.withheld_body_sizes(flow_id)?;
        if detail.response_body.is_none() {
            detail.summary.size = detail.response_body_withheld;
        }
        Ok(Some(detail))
    }

    /// A page of a flow's captured Server-Sent Events.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no store is attached or the read fails.
    pub fn sse_events(
        &self,
        flow_id: u64,
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<SseEventRecord>, Diagnostic> {
        let Some(store) = self.stream_store() else {
            return Err(catalogue::PROXY_STORE_OPEN_FAILED.instantiate(DiagnosticContext::new()));
        };
        store.sse_events(flow_id, after, limit)
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
            diagnostics: vec![diagnostic],
            ..LiveUpdate::default()
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
            prompts: vec![prompt],
            ..LiveUpdate::default()
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
        if let FlowEvent::BodyEnd { flow_id, direction } = event {
            if direction == BodyDirection::Response {
                self.observe_sse_end(flow_id);
            }
            return;
        }
        if let FlowEvent::BodyChunk {
            flow_id,
            direction,
            bytes,
        } = event
        {
            if direction == BodyDirection::Response && self.observe_sse_chunk(flow_id, &bytes) {
                return;
            }
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
                origin,
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
                    origin,
                    sse: None,
                };
                let detail = FlowDetail {
                    summary: summary.clone(),
                    request_headers: headers,
                    response_headers: Vec::new(),
                    request_body: None,
                    response_body: None,
                    request_body_withheld: None,
                    response_body_withheld: None,
                };
                if let Ok(mut flows) = self.flows.lock() {
                    flows.insert(
                        flow_id,
                        FlowRecord {
                            detail,
                            captured_at: chrono::Utc::now(),
                            created_at: std::time::Instant::now(),
                            sse: None,
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
                    origin: FlowOrigin::Capture,
                    sse: None,
                };
                // An event stream is read into events as it arrives. One sent
                // content-encoded cannot be framed without decoding it, so it
                // stays an ordinary body.
                let event_stream = header_value(&headers, "content-type")
                    .is_some_and(|value| is_event_stream(&value))
                    && header_value(&headers, "content-encoding")
                        .is_none_or(|value| value.trim().eq_ignore_ascii_case("identity"));
                let mut opened_stream = false;
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
                        if event_stream && flow.sse.is_none() {
                            let stream = LiveSse::default();
                            summary.sse = Some(stream.state());
                            flow.sse = Some(stream);
                            opened_stream = true;
                        }
                        flow.detail.summary = summary.clone();
                        flow.detail.response_headers = headers;
                    }
                }
                if opened_stream && let Some(store) = self.stream_store() {
                    self.enqueue_stream(StreamWrite::SseOpen(store, flow_id, chrono::Utc::now()));
                }
                (flow_id, summary)
            }
            FlowEvent::WebSocketMessage {
                connection,
                direction,
                kind,
                payload,
                payload_bytes,
                close_code,
                observed_at,
            } => {
                self.observe_ws_message(
                    &connection,
                    direction,
                    kind,
                    payload,
                    payload_bytes,
                    close_code,
                    observed_at,
                );
                return;
            }
            FlowEvent::WebSocketClosed {
                connection,
                direction,
            } => {
                self.observe_ws_closed(&connection, direction);
                return;
            }
            FlowEvent::BodyChunk { .. } | FlowEvent::BodyEnd { .. } | FlowEvent::Diagnostic(_) => {
                unreachable!()
            }
        };
        let _ = flow_id;
        self.persist_flow(flow_id);
        let _ = self.updates.send(LiveUpdate {
            flows: vec![summary],
            ..LiveUpdate::default()
        });
    }
}

impl LiveWorkbench {
    fn stream_store(&self) -> Option<Arc<TrafficStore>> {
        self.store.read().ok().and_then(|store| store.clone())
    }

    fn enqueue_stream(&self, write: StreamWrite) {
        if let Ok(writer) = self.stream_writer.lock() {
            let _ = writer.send(write);
        }
    }

    /// Feeds a response chunk to the flow's event-stream parser. Returns
    /// `false` when the flow is not an event stream (the chunk is then an
    /// ordinary body chunk). Events persist off the forwarding path; the raw
    /// stream is not also kept as one growing body.
    fn observe_sse_chunk(&self, flow_id: u64, bytes: &[u8]) -> bool {
        let (events, summary) = {
            let Ok(mut flows) = self.flows.lock() else {
                return false;
            };
            let Some(flow) = flows.get_mut(&flow_id) else {
                return false;
            };
            let Some(stream) = flow.sse.as_mut() else {
                return false;
            };
            let observed_at = chrono::Utc::now();
            let events = stream
                .parser
                .feed(bytes)
                .into_iter()
                .map(|event| {
                    stream.event_count += 1;
                    SseEventRecord {
                        flow_id,
                        sequence: stream.event_count,
                        event: event.event,
                        data: event.data,
                        data_bytes: u64::try_from(event.data_bytes).unwrap_or(u64::MAX),
                        id: event.id,
                        retry_ms: event.retry_ms,
                        observed_at,
                    }
                })
                .collect::<Vec<_>>();
            let due = !events.is_empty()
                && stream
                    .last_summary
                    .is_none_or(|last| last.elapsed() >= SSE_SUMMARY_INTERVAL);
            if due {
                stream.last_summary = Some(std::time::Instant::now());
            }
            flow.detail.summary.sse = Some(stream.state());
            (events, due.then(|| flow.detail.summary.clone()))
        };
        if let Some(store) = self.stream_store() {
            for event in events {
                self.enqueue_stream(StreamWrite::SseEvent(Arc::clone(&store), event));
            }
        }
        if let Some(summary) = summary {
            let _ = self.updates.send(LiveUpdate {
                flows: vec![summary],
                ..LiveUpdate::default()
            });
        }
        true
    }

    /// Marks a flow's event stream ended when its response body ends.
    fn observe_sse_end(&self, flow_id: u64) {
        let summary = {
            let Ok(mut flows) = self.flows.lock() else {
                return;
            };
            let Some(flow) = flows.get_mut(&flow_id) else {
                return;
            };
            let Some(stream) = flow.sse.as_mut().filter(|stream| !stream.closed) else {
                return;
            };
            stream.closed = true;
            flow.detail.summary.sse = Some(stream.state());
            flow.detail.summary.clone()
        };
        if let Some(store) = self.stream_store() {
            self.enqueue_stream(StreamWrite::SseClose(store, flow_id, chrono::Utc::now()));
        }
        let _ = self.updates.send(LiveUpdate {
            flows: vec![summary],
            ..LiveUpdate::default()
        });
    }

    /// Records one WebSocket message: opens the connection record on first
    /// sight (classified against scope like an HTTP flow), then persists the
    /// message off the forwarding path.
    #[allow(clippy::too_many_arguments)]
    fn observe_ws_message(
        &self,
        key: &crate::WebSocketConnectionKey,
        direction: crate::WebSocketDirection,
        kind: crate::WebSocketMessageKind,
        payload: Vec<u8>,
        payload_bytes: usize,
        close_code: Option<u16>,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) {
        use apiaxess_workbench_store::{
            WsConnectionRecord, WsDirection, WsMessageKind, WsMessageRecord,
        };
        let Some(store) = self.stream_store() else {
            return;
        };
        let Ok(mut websockets) = self.websockets.lock() else {
            return;
        };
        let (connection, message) = {
            let live = websockets.entry(key.clone()).or_insert_with(|| {
                let (host, path) = ws_host_and_path(&key.url);
                let scope = host
                    .as_deref()
                    .map_or(ScopeDisposition::Undetermined, |host| {
                        self.classify_scope(host, Some(&key.url))
                    });
                let provenance = self
                    .provenance
                    .read()
                    .map_or_else(|_| "proxy.observer".to_owned(), |value| value.clone());
                LiveWsConnection {
                    record: WsConnectionRecord {
                        id: store.allocate_ws_connection_id(),
                        url: key.url.clone(),
                        host,
                        path,
                        scope,
                        origin: FlowOrigin::Capture,
                        opened_at: observed_at,
                        closed_at: None,
                        close_code: None,
                        message_count: 0,
                        provenance,
                    },
                    next_sequence: 1,
                    client_closed: false,
                    server_closed: false,
                }
            });
            if self.admit_all_observed.load(Ordering::SeqCst) {
                if let Ok(mut ids) = self.admitted_ws_without_scope.lock() {
                    ids.insert(live.record.id);
                }
            }
            let sequence = live.next_sequence;
            live.next_sequence += 1;
            live.record.message_count = sequence;
            if live.record.close_code.is_none() {
                live.record.close_code = close_code;
            }
            let message = WsMessageRecord {
                connection_id: live.record.id,
                sequence,
                direction: match direction {
                    crate::WebSocketDirection::ClientToServer => WsDirection::ClientToServer,
                    crate::WebSocketDirection::ServerToClient => WsDirection::ServerToClient,
                },
                kind: match kind {
                    crate::WebSocketMessageKind::Text => WsMessageKind::Text,
                    crate::WebSocketMessageKind::Binary => WsMessageKind::Binary,
                    crate::WebSocketMessageKind::Ping => WsMessageKind::Ping,
                    crate::WebSocketMessageKind::Pong => WsMessageKind::Pong,
                    crate::WebSocketMessageKind::Close => WsMessageKind::Close,
                    crate::WebSocketMessageKind::Frame => WsMessageKind::Frame,
                },
                payload,
                payload_bytes: u64::try_from(payload_bytes).unwrap_or(u64::MAX),
                observed_at,
            };
            (live.record.clone(), message)
        };
        drop(websockets);
        if message.sequence == 1 {
            self.enqueue_stream(StreamWrite::Connection(
                Arc::clone(&store),
                connection.clone(),
            ));
        }
        self.enqueue_stream(StreamWrite::Message(store, connection, message));
    }

    /// Marks one direction of a WebSocket connection ended; once both have,
    /// records it closed.
    fn observe_ws_closed(
        &self,
        key: &crate::WebSocketConnectionKey,
        direction: crate::WebSocketDirection,
    ) {
        let Some(store) = self.stream_store() else {
            return;
        };
        let Ok(mut websockets) = self.websockets.lock() else {
            return;
        };
        let Some(live) = websockets.get_mut(key) else {
            return;
        };
        match direction {
            crate::WebSocketDirection::ClientToServer => live.client_closed = true,
            crate::WebSocketDirection::ServerToClient => live.server_closed = true,
        }
        if !(live.client_closed && live.server_closed) {
            return;
        }
        let Some(mut live) = websockets.remove(key) else {
            return;
        };
        drop(websockets);
        live.record.closed_at = Some(chrono::Utc::now());
        self.enqueue_stream(StreamWrite::Connection(store, live.record));
    }

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
        if self.admit_all_observed.load(Ordering::SeqCst) {
            if let Ok(mut ids) = self.admitted_without_scope.lock() {
                ids.insert(flow_id);
            }
        }
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
            origin: record.detail.summary.origin,
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

    /// Promotes stored flows that the current engagement scope now covers to
    /// in-scope (upgrade-only), so traffic captured before the scope was
    /// declared or widened is not silently left out of fusion. Returns how many
    /// flows were promoted; `0` when no store is attached.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the store cannot be read or updated.
    pub fn promote_stored_flows_into_scope(&self) -> Result<usize, Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Ok(0);
        };
        store.promote_to_in_scope(|host, url| {
            host.map_or(ScopeDisposition::Undetermined, |host| {
                self.classify_scope(host, url)
            })
        })
    }

    /// Imports HAR entries into the attached durable store.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when no store is attached or HAR parsing or
    /// persistence fails.
    pub fn import_har(
        &self,
        bytes: &[u8],
        provenance: &str,
    ) -> Result<apiaxess_workbench_store::HarImportOutcome, Diagnostic> {
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
        origin: flow.origin,
        sse: flow.sse,
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
            origin: flow.origin,
            sse: None,
        },
        request_headers: flow.request_headers,
        response_headers: flow.response_headers,
        request_body: flow.request_body,
        response_body: flow.response_body,
        request_body_withheld: None,
        response_body_withheld: None,
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

/// Host and path+query of a WebSocket URL.
fn ws_host_and_path(url: &str) -> (Option<String>, Option<String>) {
    let Ok(parsed) = url.parse::<reqwest::Url>() else {
        return (None, None);
    };
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    };
    (parsed.host_str().map(ToOwned::to_owned), Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn an_event_stream_is_captured_as_events_on_its_http_flow() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-live-sse-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = Arc::new(TrafficStore::open(&root, "session:sse-test").expect("store"));
        let live = LiveWorkbench::new();
        live.attach_store(Arc::clone(&store));
        let mut updates = live.subscribe();
        let flow_id = live.allocate_flow_id();
        live.observe(FlowEvent::Request {
            flow_id,
            method: "GET".to_owned(),
            uri: "https://feed.test/events".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![("accept".to_owned(), "text/event-stream".to_owned())],
            origin: FlowOrigin::Capture,
        });
        live.observe(FlowEvent::Response {
            flow_id,
            client_addr: "127.0.0.1:50124".parse().expect("address"),
            status: 200,
            version: "HTTP/1.1".to_owned(),
            headers: vec![(
                "content-type".to_owned(),
                "text/event-stream; charset=utf-8".to_owned(),
            )],
        });
        // Events arrive split across chunks, mid-line and mid-event.
        for chunk in [
            &b": connected\n\nevent: tick\nid: 1\ndata: {\"n\":"[..],
            b"1}\n\ndata: line one\ndata: line two\n",
            b"\nretry: 5000\ndata: third\n\n",
        ] {
            live.observe(FlowEvent::BodyChunk {
                flow_id,
                direction: BodyDirection::Response,
                bytes: chunk.to_vec(),
            });
        }
        live.observe(FlowEvent::BodyEnd {
            flow_id,
            direction: BodyDirection::Response,
        });

        let mut live_events = Vec::new();
        let mut last_summary = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while live_events.len() < 3 && std::time::Instant::now() < deadline {
            match updates.try_recv() {
                Ok(update) => {
                    live_events.extend(update.sse);
                    if let Some(summary) = update.flows.into_iter().last() {
                        last_summary = Some(summary);
                    }
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        assert_eq!(
            live_events
                .iter()
                .map(|event| (event.sequence, event.event.as_deref(), event.data.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (1, Some("tick"), "{\"n\":1}"),
                (2, None, "line one\nline two"),
                (3, None, "third"),
            ]
        );
        assert_eq!(live_events[0].id.as_deref(), Some("1"));
        assert_eq!(live_events[2].retry_ms, Some(5000));
        // The row reads as a finished stream, never as a hung request.
        assert_eq!(
            last_summary.and_then(|summary| summary.sse),
            Some(SseStreamState {
                event_count: 3,
                closed: true
            })
        );
        // Durable: the same events, the flow summarized as a closed stream,
        // and no raw stream kept as one growing body.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut state = None;
        while std::time::Instant::now() < deadline {
            state = store.sse_state(flow_id).expect("state");
            if state.is_some_and(|state| state.closed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            state,
            Some(SseStreamState {
                event_count: 3,
                closed: true
            })
        );
        assert_eq!(
            store.sse_events(flow_id, None, 10).expect("events").len(),
            3
        );
        let detail = live.durable_flow(flow_id).expect("read").expect("flow");
        assert_eq!(detail.response_body, None);
        assert_eq!(detail.summary.sse, state);
        assert_eq!(detail.summary.method.as_deref(), Some("GET"));
    }

    /// A captured GET with a response, observed through the live path.
    fn observe_get(live: &LiveWorkbench, url: &str) -> u64 {
        let flow_id = live.allocate_flow_id();
        live.observe(FlowEvent::Request {
            flow_id,
            method: "GET".to_owned(),
            uri: url.to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            origin: FlowOrigin::Capture,
        });
        live.observe(FlowEvent::Response {
            flow_id,
            client_addr: "127.0.0.1:50130".parse().expect("address"),
            status: 200,
            version: "HTTP/1.1".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        });
        flow_id
    }

    fn web_scope(host: &str, port: u16) -> EngagementScope {
        EngagementScope {
            declared_at: chrono::Utc::now(),
            target: apiaxess_session::TargetIdentity {
                target_type: "web.url".to_owned(),
                primary: apiaxess_session::TargetIdentifier {
                    kind: "url.origin".to_owned(),
                    value: format!("http://{host}:{port}"),
                },
                aliases: Vec::new(),
            },
            allowed_targets: vec![apiaxess_session::AllowedNetworkTarget {
                id: "web.target-domain".to_owned(),
                host: apiaxess_session::HostMatch::Exact {
                    host: host.to_owned(),
                },
                ports: vec![port],
            }],
        }
    }

    #[test]
    fn admit_all_ends_when_a_scope_is_known_and_what_it_admitted_is_reclassified() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-live-admit-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = Arc::new(TrafficStore::open(&root, "session:admit-test").expect("store"));
        let live = LiveWorkbench::new();
        live.attach_store(Arc::clone(&store));
        let scope_of = |id: u64| store.get(id).expect("get").expect("flow").scope;

        // Browsing before any target is declared: every observed host is admitted.
        live.set_admit_all_observed(true);
        let target = observe_get(&live, "http://127.0.0.1:9201/api/v1/status");
        let noise = observe_get(&live, "https://update.googleapis.com/service/update2/json");
        assert_eq!(scope_of(target), ScopeDisposition::InScope);
        assert_eq!(scope_of(noise), ScopeDisposition::InScope);

        // The browser stops: nothing new is admitted, but what was captured
        // keeps its admission until a scope is known.
        live.pause_admit_all();
        assert!(!live.admits_all_observed());
        let after_stop = observe_get(&live, "https://www.google.com/async/folae");
        assert_eq!(scope_of(after_stop), ScopeDisposition::Undetermined);
        assert_eq!(scope_of(noise), ScopeDisposition::InScope);

        // A target is declared: the admitted flows are classified against it.
        live.set_engagement_scope(web_scope("127.0.0.1", 9201));
        assert_eq!(live.end_admit_all_for_scope().expect("reclassify"), 1);
        assert_eq!(scope_of(target), ScopeDisposition::InScope);
        assert_eq!(scope_of(noise), ScopeDisposition::OutsideDeclaredScope);
        // Nothing is left to re-classify, and new traffic follows the scope.
        assert_eq!(live.end_admit_all_for_scope().expect("reclassify"), 0);
        let later = observe_get(&live, "https://accounts.google.com/ListAccounts");
        assert_eq!(scope_of(later), ScopeDisposition::OutsideDeclaredScope);

        // A new session clears the record without touching this store.
        live.set_admit_all_observed(true);
        let unscoped = observe_get(&live, "https://mtalk.google.com/");
        live.reset_admit_all();
        assert!(!live.admits_all_observed());
        assert_eq!(live.end_admit_all_for_scope().expect("reclassify"), 0);
        assert_eq!(scope_of(unscoped), ScopeDisposition::InScope);
    }

    #[test]
    fn websocket_connections_admitted_before_scope_are_relabelled_when_it_is_declared() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-live-ws-admit-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = Arc::new(TrafficStore::open(&root, "session:ws-admit").expect("store"));
        let live = LiveWorkbench::new();
        live.attach_store(Arc::clone(&store));
        let key = |url: &str| crate::WebSocketConnectionKey {
            client: "127.0.0.1:50150".parse().expect("address"),
            url: url.to_owned(),
        };
        let send = |url: &str| {
            live.observe(FlowEvent::WebSocketMessage {
                connection: key(url),
                direction: crate::WebSocketDirection::ClientToServer,
                kind: crate::WebSocketMessageKind::Text,
                payload: b"hi".to_vec(),
                payload_bytes: 2,
                close_code: None,
                observed_at: chrono::Utc::now(),
            });
        };
        let wait_for = |check: &dyn Fn(&[apiaxess_workbench_store::WsConnectionRecord]) -> bool| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let connections = store.ws_connections().expect("connections");
                if check(&connections) || std::time::Instant::now() > deadline {
                    return connections;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        let scope_of = |connections: &[apiaxess_workbench_store::WsConnectionRecord], url: &str| {
            connections
                .iter()
                .find(|connection| connection.url == url)
                .map(|connection| connection.scope)
        };
        let target = "ws://127.0.0.1:9201/ws?room=ref";
        let tracker = "wss://live.tracker.test/socket";

        live.set_admit_all_observed(true);
        send(target);
        send(tracker);
        let admitted = wait_for(&|connections| connections.len() == 2);
        assert_eq!(
            scope_of(&admitted, tracker),
            Some(ScopeDisposition::InScope)
        );

        let mut updates = live.subscribe();
        live.set_engagement_scope(web_scope("127.0.0.1", 9201));
        live.end_admit_all_for_scope().expect("reclassify");
        // The relabel lands through the ordered writer, after any queued writes.
        let relabelled = wait_for(&|connections| {
            scope_of(connections, tracker) == Some(ScopeDisposition::OutsideDeclaredScope)
        });
        assert_eq!(
            scope_of(&relabelled, target),
            Some(ScopeDisposition::InScope)
        );
        assert_eq!(
            scope_of(&relabelled, tracker),
            Some(ScopeDisposition::OutsideDeclaredScope)
        );
        // The tab is told, with the connection as now classified.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut announced = None;
        while announced.is_none() && std::time::Instant::now() < deadline {
            match updates.try_recv() {
                Ok(update) => {
                    announced = update.websocket.into_iter().find(|event| {
                        event.message.is_none()
                            && event.connection.url == tracker
                            && event.connection.scope == ScopeDisposition::OutsideDeclaredScope
                    });
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        assert!(announced.is_some(), "the relabel is announced");

        // The still-open connection keeps its new label as messages flow.
        send(tracker);
        let after = wait_for(&|connections| {
            connections
                .iter()
                .any(|connection| connection.url == tracker && connection.message_count == 2)
        });
        assert_eq!(
            scope_of(&after, tracker),
            Some(ScopeDisposition::OutsideDeclaredScope)
        );
    }

    #[test]
    fn an_ordinary_response_is_not_read_as_an_event_stream() {
        let live = LiveWorkbench::new();
        let flow_id = live.allocate_flow_id();
        live.observe(FlowEvent::Request {
            flow_id,
            method: "GET".to_owned(),
            uri: "https://api.test/items".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            origin: FlowOrigin::Capture,
        });
        live.observe(FlowEvent::Response {
            flow_id,
            client_addr: "127.0.0.1:50125".parse().expect("address"),
            status: 200,
            version: "HTTP/1.1".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        });
        live.observe(FlowEvent::BodyChunk {
            flow_id,
            direction: BodyDirection::Response,
            bytes: b"data: not an event\n\n".to_vec(),
        });
        live.observe(FlowEvent::BodyEnd {
            flow_id,
            direction: BodyDirection::Response,
        });
        let detail = live.flow(flow_id).expect("flow");
        assert_eq!(detail.summary.sse, None);
        assert_eq!(
            detail.response_body.as_deref(),
            Some(&b"data: not an event\n\n"[..])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end scenario, read top to bottom.
    fn websocket_messages_persist_stream_live_and_stay_out_of_http_flows() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-live-ws-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let store = Arc::new(TrafficStore::open(&root, "session:ws-test").expect("store"));
        let live = LiveWorkbench::new();
        live.attach_store(Arc::clone(&store));
        let mut updates = live.subscribe();
        let key = crate::WebSocketConnectionKey {
            client: "127.0.0.1:50123".parse().expect("address"),
            url: "wss://echo.test/socket".to_owned(),
        };
        let frames = [
            (
                crate::WebSocketDirection::ClientToServer,
                crate::WebSocketMessageKind::Text,
                b"hello".to_vec(),
            ),
            (
                crate::WebSocketDirection::ServerToClient,
                crate::WebSocketMessageKind::Text,
                b"hello".to_vec(),
            ),
            (
                crate::WebSocketDirection::ClientToServer,
                crate::WebSocketMessageKind::Binary,
                vec![0, 1, 2, 255],
            ),
        ];
        for (direction, kind, payload) in frames {
            let payload_bytes = payload.len();
            live.observe(FlowEvent::WebSocketMessage {
                connection: key.clone(),
                direction,
                kind,
                payload,
                payload_bytes,
                close_code: None,
                observed_at: chrono::Utc::now(),
            });
        }
        live.observe(FlowEvent::WebSocketClosed {
            connection: key.clone(),
            direction: crate::WebSocketDirection::ClientToServer,
        });
        live.observe(FlowEvent::WebSocketClosed {
            connection: key,
            direction: crate::WebSocketDirection::ServerToClient,
        });

        // The writer thread publishes each persisted message on the live stream.
        let mut live_messages = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while live_messages.len() < 3 && std::time::Instant::now() < deadline {
            match updates.try_recv() {
                Ok(update) => {
                    assert!(
                        update.flows.is_empty(),
                        "WebSocket must not become HTTP flows"
                    );
                    live_messages.extend(
                        update
                            .websocket
                            .into_iter()
                            .filter_map(|event| event.message),
                    );
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        assert_eq!(
            live_messages
                .iter()
                .map(|message| message.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            live_messages[2].kind,
            apiaxess_workbench_store::WsMessageKind::Binary
        );

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let connection = loop {
            let connections = store.ws_connections().expect("connections");
            if connections.first().is_some_and(|c| c.closed_at.is_some())
                || std::time::Instant::now() > deadline
            {
                break connections.into_iter().next().expect("one connection");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(connection.message_count, 3);
        assert!(connection.closed_at.is_some(), "both directions ended");
        assert_eq!(connection.host.as_deref(), Some("echo.test"));
        let messages = store
            .ws_messages(connection.id, None, 10)
            .expect("messages");
        assert_eq!(messages[2].payload, vec![0, 1, 2, 255]);
        assert_eq!(
            messages[1].direction,
            apiaxess_workbench_store::WsDirection::ServerToClient
        );
        // HTTP flows are untouched.
        assert!(store.summaries().expect("flows").is_empty());
    }

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
            origin: FlowOrigin::Capture,
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
