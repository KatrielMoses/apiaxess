//! Swappable proxy backend boundary and the embedded hudsucker adapter.

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_session::{Session, SessionLifecycle};
use http_body_util::{BodyStream, StreamBody};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    futures::TryStreamExt,
    hyper::{Method, Request, Response, StatusCode, Version},
    tokio_tungstenite::tungstenite::Message,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};

use crate::SessionCa;
use crate::raw_http::{
    UPSTREAM_ERROR_MARKER, UPSTREAM_HEADERS_MARKER, UPSTREAM_STATUS_MARKER, WIRE_HEADERS_MARKER,
    decode_header_list, encode_header_list,
};
use apiaxess_workbench_store::FlowOrigin;

/// Request header the Resend/Fuzz senders attach so the proxy can tag the
/// resulting flow's [`FlowOrigin`]. It is a private control marker: the proxy
/// removes it before the request is recorded or forwarded upstream, so it never
/// reaches the target and never appears in stored traffic.
pub(crate) const ORIGIN_MARKER_HEADER: &str = "x-apiaxess-origin";

/// Reads and removes the authored-header marker a workbench sender attaches
/// (see [`crate::raw_http`]). When present, the request's headers are replaced
/// by that list, in order, so the recorded flow shows what goes on the wire, and
/// the authored list is returned for the byte-faithful upstream write.
///
/// A list without `Host` gets one first, derived from the request URL the way a
/// client derives it (default port omitted). Resend's lists always carry one;
/// the ffuf tier omits it when the payload sits in the authority, because only
/// the request ffuf actually sent knows the substituted host.
fn take_wire_headers(req: &mut Request<Body>) -> Option<Vec<(String, String)>> {
    let value = req.headers_mut().remove(WIRE_HEADERS_MARKER)?;
    let mut list = decode_header_list(value.as_bytes())?;
    if !list
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        let uri = req.uri();
        let default_port = if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        };
        let host = uri.host()?;
        let authority = match uri.port_u16() {
            Some(port) if port != default_port => format!("{host}:{port}"),
            _ => host.to_owned(),
        };
        list.insert(0, ("Host".to_owned(), authority));
    }
    let mut replaced = hudsucker::hyper::HeaderMap::new();
    for (name, value) in &list {
        let (Ok(name), Ok(value)) = (
            hudsucker::hyper::header::HeaderName::try_from(name.as_str()),
            hudsucker::hyper::header::HeaderValue::try_from(value.as_str()),
        ) else {
            return None;
        };
        replaced.append(name, value);
    }
    *req.headers_mut() = replaced;
    Some(list)
}

/// The header list to write after an intercept edit of a workbench send: the
/// edited list in its order, keeping authored case for names that survive
/// (the held request was shown with the `http` crate's lowercased names).
fn wire_headers_after_edit(
    authored: &[(String, String)],
    edited: Vec<(String, String)>,
) -> Vec<(String, String)> {
    edited
        .into_iter()
        .map(|(name, value)| {
            let cased = authored
                .iter()
                .find(|(original, _)| original.eq_ignore_ascii_case(&name))
                .map_or(name, |(original, _)| original.clone());
            (cased, value)
        })
        .collect()
}

/// Reads and removes the origin marker header, returning the tagged origin.
///
/// Absent or unparseable markers default to [`FlowOrigin::Capture`], so ordinary
/// observed proxy traffic is unaffected.
fn take_origin_marker(req: &mut Request<Body>) -> FlowOrigin {
    match req.headers_mut().remove(ORIGIN_MARKER_HEADER) {
        Some(value) => value
            .to_str()
            .map_or(FlowOrigin::Capture, FlowOrigin::from_db_str),
        None => FlowOrigin::Capture,
    }
}

/// Boxed future used to keep the backend trait object-safe.
pub type BackendFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Backend implementations that can own the proxy listener and protocol machinery.
pub trait ProxyBackend: Send + Sync {
    /// Stable implementation name for diagnostics and telemetry.
    fn kind(&self) -> BackendKind;

    /// Returns the current capability health for this backend.
    fn health(&self) -> BackendFuture<BackendHealth> {
        Box::pin(async {
            BackendHealth {
                hudsucker_available: true,
            }
        })
    }

    /// Starts a session-scoped listener.
    fn start(
        &self,
        config: ProxyConfig,
        observer: Arc<dyn FlowObserver>,
    ) -> BackendFuture<Result<ProxyHandle, Diagnostic>>;
}

/// Available proxy implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// Embedded hudsucker adapter — the only proxy backend.
    Hudsucker,
}

/// Session capability health for the proxy backend.
///
/// The proxy is the embedded, compiled-in hudsucker backend, so it is always
/// available on a correct build; it is reported to the workbench for a stable
/// health contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendHealth {
    /// Whether the embedded hudsucker backend is available. Always true on a
    /// correct build.
    pub hudsucker_available: bool,
}

/// Runtime proxy configuration. It contains no persistent or trust-store state.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Session identifier attached to diagnostics and flow events.
    pub session_id: String,
    /// Address to bind. Use port zero for an ephemeral listener.
    pub bind_addr: SocketAddr,
    /// Session CA held in memory by the running backend.
    pub ca: SessionCa,
    /// Optional test/intercept gate held before a request is forwarded.
    pub intercept: Option<Arc<InterceptController>>,
    /// Also bind an ephemeral loopback listener used only by the `APIaxess`
    /// capture browser. Traffic arriving there is known to come from that
    /// browser, so its own service traffic can be kept out of the capture (see
    /// [`is_browser_internal`]) without guessing about any other client.
    pub capture_browser_listener: bool,
}

/// Which listener a request arrived on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerRole {
    /// The shared proxy port: devices, external browsers, workbench senders.
    Shared,
    /// The capture browser's dedicated port.
    CaptureBrowser,
}

/// Whether a request that reached the capture browser's dedicated listener is
/// the browser's own traffic rather than something a page or the operator
/// asked for.
///
/// Chromium stamps Fetch Metadata on requests to potentially trustworthy
/// destinations. `Sec-Fetch-Site` names the relation between the request's
/// initiator and its destination; every request a page issues has an initiator,
/// so it reads `same-origin`, `same-site` or `cross-site`. Only a request with
/// no initiator at all reads `none`, and there are exactly two kinds: a
/// navigation the user (or `APIaxess`, over CDP) started, and the browser's own
/// service traffic — component updater, GCM check-in, account probes — which
/// the network service sends as `none` / `no-cors`. So a `none` request is the
/// browser's own when it is not a navigation, or when it is a speculative
/// navigation (`Sec-Purpose`, e.g. the search warm-up page) no one asked for.
///
/// Fetch Metadata is absent from WebSocket handshakes and from every request to
/// a plain-HTTP remote host, so its absence alone says nothing. What does is
/// `Accept-Language`: Chromium adds it to every request made in a profile's
/// network context — all page traffic, WebSocket handshakes included — while
/// the browser's service traffic (component downloads over plain HTTP, update
/// checks) runs in the profile-less system network context and carries none.
/// A request with neither is the browser's own.
///
/// An HTTP/1.1 `CONNECT` is tunnel bookkeeping — the requests inside the tunnel
/// are recorded on their own — and is never a flow.
fn is_browser_internal(req: &Request<Body>) -> bool {
    if req.method() == Method::CONNECT {
        return req.version() != Version::HTTP_2;
    }
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
    };
    let Some(site) = header("sec-fetch-site") else {
        return header("accept-language").is_none();
    };
    if !site.eq_ignore_ascii_case("none") {
        return false;
    }
    let navigation =
        header("sec-fetch-mode").is_some_and(|mode| mode.eq_ignore_ascii_case("navigate"));
    !navigation || header("sec-purpose").is_some()
}

/// Longest a paused request may be held for a decision.
pub const MAX_INTERCEPT_HOLD: Duration = Duration::from_secs(600);

/// Flow pause gate used by acceptance fixtures and the future intercept layer.
///
/// It is session-scoped and contains no durable traffic state. Dropping a
/// client while the gate is closed exercises the same cancellation boundary
/// used when an intercepting UI holds a flow.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum InterceptDecision {
    /// Forward the original request unchanged.
    Forward,
    /// Replace the request before forwarding it. The edit is written upstream
    /// byte-for-byte (headers in edited order and case) with its framing
    /// recomputed for the edited body.
    ForwardModified {
        /// Replacement HTTP method.
        method: String,
        /// Replacement absolute `http`/`https` URL; `None` keeps the held URL.
        #[serde(default)]
        url: Option<String>,
        /// Replacement headers.
        headers: Vec<(String, String)>,
        /// Replacement request body.
        body: Vec<u8>,
    },
    /// Stop the request at the proxy.
    Drop,
    /// The configured wait elapsed; this is never sent by the UI.
    Timeout,
}

/// Session-scoped pause and UI decision controller.
#[derive(Debug)]
pub struct InterceptController {
    released: std::sync::atomic::AtomicBool,
    enabled: std::sync::atomic::AtomicBool,
    timeout: Mutex<Duration>,
    host_filter: RwLock<Option<Vec<String>>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<InterceptDecision>>>,
    notify: Notify,
}

impl Default for InterceptController {
    fn default() -> Self {
        Self {
            released: std::sync::atomic::AtomicBool::new(true),
            enabled: std::sync::atomic::AtomicBool::new(false),
            timeout: Mutex::new(Duration::from_secs(30)),
            host_filter: RwLock::new(None),
            pending: Mutex::new(HashMap::new()),
            notify: Notify::new(),
        }
    }
}

impl InterceptController {
    /// Creates a controller whose flows begin paused.
    #[must_use]
    pub fn paused() -> Self {
        let controller = Self::default();
        controller.released.store(false, Ordering::Release);
        controller
    }

    /// Releases all currently held flows.
    pub fn release(&self) {
        self.released
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Enables or disables UI-driven request interception.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.release_pending();
        }
    }

    /// Returns whether UI-driven interception is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Sets the maximum time a paused request may wait for a UI decision,
    /// bounded to [`MAX_INTERCEPT_HOLD`]: a request held longer is, to the
    /// client that sent it, simply hung.
    pub fn set_timeout(&self, timeout: Duration) {
        if let Ok(mut current) = self.timeout.lock() {
            *current = timeout.clamp(Duration::from_millis(100), MAX_INTERCEPT_HOLD);
        }
    }

    /// Sets the optional host allow-list used by live interception.
    pub fn set_host_filter(&self, hosts: Option<Vec<String>>) {
        if let Ok(mut filter) = self.host_filter.write() {
            *filter = hosts.map(|values| {
                values
                    .into_iter()
                    .map(|host| host.trim().to_ascii_lowercase())
                    .filter(|host| !host.is_empty())
                    .collect()
            });
        }
    }

    /// Supplies a decision for one paused flow. Returns false when the flow
    /// already timed out, was released, or never existed.
    pub fn decide(&self, flow_id: u64, decision: InterceptDecision) -> bool {
        self.pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&flow_id))
            .is_some_and(|sender| sender.send(decision).is_ok())
    }

    /// Drops every request still held for a decision, answering each client
    /// as an operator Drop would (403). Used when the session they belong to
    /// ends, so a new session never inherits — or forwards — a request no one
    /// approved. Returns how many were dropped.
    pub fn drop_all_pending(&self) -> usize {
        let held: Vec<_> = self
            .pending
            .lock()
            .map(|mut pending| pending.drain().map(|(_, sender)| sender).collect())
            .unwrap_or_default();
        let count = held.len();
        for sender in held {
            let _ = sender.send(InterceptDecision::Drop);
        }
        count
    }

    /// Returns the currently paused flow IDs for the live intercept queue.
    #[must_use]
    pub fn pending_ids(&self) -> Vec<u64> {
        self.pending
            .lock()
            .map(|pending| pending.keys().copied().collect())
            .unwrap_or_default()
    }

    fn release_pending(&self) {
        let pending = self
            .pending
            .lock()
            .map(|mut pending| {
                pending
                    .drain()
                    .map(|(_, sender)| sender)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for sender in pending {
            let _ = sender.send(InterceptDecision::Forward);
        }
    }

    /// Whether a request to `host` would be held for a decision right now.
    fn holds(&self, host: Option<&str>) -> bool {
        self.is_enabled() && self.matches_host(host)
    }

    async fn await_decision(&self, flow_id: u64, host: Option<&str>) -> InterceptDecision {
        if !self.holds(host) {
            return InterceptDecision::Forward;
        }
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(flow_id, sender);
        } else {
            return InterceptDecision::Forward;
        }
        let timeout = self
            .timeout
            .lock()
            .map(|timeout| *timeout)
            .unwrap_or(Duration::from_secs(30));
        if let Ok(Ok(decision)) = tokio::time::timeout(timeout, receiver).await {
            decision
        } else {
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(&flow_id);
            }
            if self.is_enabled() {
                InterceptDecision::Timeout
            } else {
                InterceptDecision::Forward
            }
        }
    }

    fn matches_host(&self, host: Option<&str>) -> bool {
        let Ok(filter) = self.host_filter.read() else {
            return false;
        };
        let Some(filter) = filter.as_ref() else {
            return true;
        };
        host.is_some_and(|host| {
            let host = host.to_ascii_lowercase();
            filter
                .iter()
                .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        })
    }

    async fn wait(&self) {
        while !self.released.load(std::sync::atomic::Ordering::Acquire) {
            self.notify.notified().await;
        }
    }
}

/// One observable event emitted by the proxy core. Bodies remain streaming and
/// are deliberately not retained here; durable traffic storage belongs to 2.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowEvent {
    /// An HTTP request reached the proxy.
    Request {
        /// Monotonic process-local flow ID.
        flow_id: u64,
        /// HTTP method.
        method: String,
        /// Request URI.
        uri: String,
        /// Negotiated/request HTTP version.
        version: String,
        /// Header names and values captured without consuming the body.
        headers: Vec<(String, String)>,
        /// How the request entered the proxy (observed capture vs. a request
        /// synthesized by the Resend/Fuzz senders).
        origin: FlowOrigin,
    },
    /// An HTTP response reached the proxy.
    Response {
        /// Paired request flow ID.
        flow_id: u64,
        /// Client address that owns the flow.
        client_addr: SocketAddr,
        /// Status code.
        status: u16,
        /// HTTP version.
        version: String,
        /// Header names and values captured without consuming the body.
        headers: Vec<(String, String)>,
    },
    /// A bounded body chunk retained for lazy selection in the live UI.
    BodyChunk {
        /// Paired request flow ID.
        flow_id: u64,
        /// Body direction.
        direction: BodyDirection,
        /// Chunk bytes, capped by the live in-memory retention limit.
        bytes: Vec<u8>,
    },
    /// A forwarded body ended: it completed, or the connection carrying it
    /// was dropped. Long-lived bodies (event streams) close on this.
    BodyEnd {
        /// Paired request flow ID.
        flow_id: u64,
        /// Body direction.
        direction: BodyDirection,
    },
    /// A WebSocket message was observed while being forwarded.
    WebSocketMessage {
        /// The connection the message belongs to.
        connection: WebSocketConnectionKey,
        /// Direction of the message.
        direction: WebSocketDirection,
        /// Frame kind.
        kind: WebSocketMessageKind,
        /// The payload, capped at [`MAX_WEBSOCKET_PAYLOAD_BYTES`].
        payload: Vec<u8>,
        /// The full payload size (larger than `payload.len()` when capped).
        payload_bytes: usize,
        /// Close code, for a close frame that carries one.
        close_code: Option<u16>,
        /// When the proxy observed the message.
        observed_at: chrono::DateTime<chrono::Utc>,
    },
    /// One direction of a WebSocket connection ended (its stream closed).
    WebSocketClosed {
        /// The connection that ended.
        connection: WebSocketConnectionKey,
        /// The direction whose stream ended.
        direction: WebSocketDirection,
    },
    /// The capture browser made a request of its own (not one a page issued);
    /// it was forwarded but deliberately not recorded. Carries only the host,
    /// so the withheld traffic can be counted honestly.
    BrowserInternalWithheld {
        /// Destination host of the withheld request.
        host: String,
    },
    /// A backend failure was converted to a canonical diagnostic.
    Diagnostic(Diagnostic),
}

/// Direction of an observed HTTP body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyDirection {
    /// Request body sent by the client.
    Request,
    /// Response body sent by the upstream server.
    Response,
}

/// Largest WebSocket payload retained per message; larger frames are recorded
/// with their full size and a truncated payload.
pub const MAX_WEBSOCKET_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Identifies one proxied WebSocket connection: the client socket and the
/// server URL. Both directions of a connection share it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WebSocketConnectionKey {
    /// The client's socket address at the proxy.
    pub client: std::net::SocketAddr,
    /// The server URL (`ws://` or `wss://`).
    pub url: String,
}

/// Kind of an observed WebSocket frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketMessageKind {
    /// UTF-8 text.
    Text,
    /// Binary data.
    Binary,
    /// Ping control frame.
    Ping,
    /// Pong control frame.
    Pong,
    /// Close control frame.
    Close,
    /// A raw frame outside the message layer.
    Frame,
}

/// Direction of an observed WebSocket message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDirection {
    /// Client to upstream server.
    ClientToServer,
    /// Upstream server to client.
    ServerToClient,
}

/// Sink used by the 2.2 observer/intercept layer.
pub trait FlowObserver: Send + Sync {
    /// Receives an in-memory protocol observation.
    fn observe(&self, event: FlowEvent);

    /// Allocates a globally-unique flow id for a new request.
    ///
    /// The persisting observer overrides this to draw from the durable store's
    /// single authoritative allocator, so ids are unique across every concurrent
    /// traffic source and no flow can silently overwrite another. The default is a
    /// process-monotonic fallback for non-persisting observers (which have no
    /// shared store to collide with).
    fn allocate_flow_id(&self) -> u64 {
        static FALLBACK_FLOW_ID: AtomicU64 = AtomicU64::new(1);
        FALLBACK_FLOW_ID.fetch_add(1, Ordering::SeqCst)
    }
}

/// No-op observer useful for callers that only need a live listener.
#[derive(Debug, Default)]
pub struct NoopObserver;

impl FlowObserver for NoopObserver {
    fn observe(&self, _event: FlowEvent) {}
}

/// Embedded hudsucker backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct HudsuckerBackend;

impl ProxyBackend for HudsuckerBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Hudsucker
    }

    fn start(
        &self,
        config: ProxyConfig,
        observer: Arc<dyn FlowObserver>,
    ) -> BackendFuture<Result<ProxyHandle, Diagnostic>> {
        Box::pin(async move {
            let listener = TcpListener::bind(config.bind_addr)
                .await
                .map_err(|error| bind_diagnostic(config.bind_addr, &error))?;
            let local_addr = listener
                .local_addr()
                .map_err(|error| bind_diagnostic(config.bind_addr, &error))?;
            let handler = ObserveHandler::new(config.session_id, observer, config.intercept);
            let mut roots = hudsucker::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots
                .add(hudsucker::rustls::pki_types::CertificateDer::from(
                    config.ca.root_certificate_der().to_vec(),
                ))
                .map_err(|error| backend_start_diagnostic(&error))?;
            let upstream_tls = hudsucker::rustls::ClientConfig::builder_with_provider(Arc::new(
                hudsucker::rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| backend_start_diagnostic(&error))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let upstream_connector = hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(upstream_tls.clone())
                .https_or_http()
                .enable_http1()
                .enable_http2()
                .build();
            // Workbench sends are written upstream byte-for-byte over HTTP/1.1.
            let mut raw_tls = upstream_tls.clone();
            raw_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
            let handler = handler.with_raw_upstream_tls(Arc::new(raw_tls));
            // The capture browser's dedicated listener shares the CA, upstream
            // connector, observer and intercept gate; only its role differs.
            let capture_browser = if config.capture_browser_listener {
                let browser_bind = SocketAddr::from(([127, 0, 0, 1], 0));
                let browser_listener = TcpListener::bind(browser_bind)
                    .await
                    .map_err(|error| bind_diagnostic(browser_bind, &error))?;
                let browser_addr = browser_listener
                    .local_addr()
                    .map_err(|error| bind_diagnostic(browser_bind, &error))?;
                let (sender, task) = serve_listener(
                    browser_listener,
                    config.ca.clone(),
                    upstream_connector.clone(),
                    handler.clone().with_role(ListenerRole::CaptureBrowser),
                )?;
                Some(ListenerTask {
                    local_addr: browser_addr,
                    stop_sender: Some(sender),
                    task: Some(task),
                })
            } else {
                None
            };
            let (stop_sender, task) =
                serve_listener(listener, config.ca, upstream_connector, handler)?;
            Ok(ProxyHandle {
                local_addr,
                backend: BackendKind::Hudsucker,
                stop_sender: Some(stop_sender),
                task: Some(task),
                capture_browser,
            })
        })
    }
}

type ProxyTask = JoinHandle<Result<(), Diagnostic>>;

/// Serves one bound listener with the shared MITM machinery until its stop
/// signal fires.
fn serve_listener(
    listener: TcpListener,
    ca: SessionCa,
    connector: hyper_rustls::HttpsConnector<
        hudsucker::hyper_util::client::legacy::connect::HttpConnector,
    >,
    handler: ObserveHandler,
) -> Result<(oneshot::Sender<()>, ProxyTask), Diagnostic> {
    let (stop_sender, stop_receiver) = oneshot::channel();
    let proxy = hudsucker::Proxy::builder()
        .with_listener(listener)
        .with_ca(ca)
        .with_http_connector(connector)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = stop_receiver.await;
        })
        .build()
        .map_err(|error| backend_start_diagnostic(&error))?;
    let task = tokio::spawn(async move {
        proxy
            .start()
            .await
            .map_err(|error| backend_start_diagnostic(&error))
    });
    Ok((stop_sender, task))
}

/// A secondary listener owned by a [`ProxyHandle`].
struct ListenerTask {
    local_addr: SocketAddr,
    stop_sender: Option<oneshot::Sender<()>>,
    task: Option<ProxyTask>,
}

/// A running proxy listener. Dropping it is not considered a clean lifecycle
/// transition; callers should call `shutdown` when the owning session closes.
pub struct ProxyHandle {
    pub(crate) local_addr: SocketAddr,
    pub(crate) backend: BackendKind,
    pub(crate) stop_sender: Option<oneshot::Sender<()>>,
    pub(crate) task: Option<JoinHandle<Result<(), Diagnostic>>>,
    /// The capture browser's dedicated listener, when one was requested.
    capture_browser: Option<ListenerTask>,
}

impl std::fmt::Debug for ProxyHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyHandle")
            .field("local_addr", &self.local_addr)
            .field("backend", &self.backend)
            .field(
                "capture_browser_addr",
                &self
                    .capture_browser
                    .as_ref()
                    .map(|listener| listener.local_addr),
            )
            .finish_non_exhaustive()
    }
}

impl ProxyHandle {
    /// Bound listener address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Backend implementation currently serving this listener.
    #[must_use]
    pub const fn backend(&self) -> BackendKind {
        self.backend
    }

    /// The capture browser's dedicated listener address, when one is bound.
    #[must_use]
    pub fn capture_browser_addr(&self) -> Option<SocketAddr> {
        self.capture_browser
            .as_ref()
            .map(|listener| listener.local_addr)
    }

    /// Gracefully stops the listener(s) and waits for the backend task(s).
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the backend task fails or cannot be joined.
    pub async fn shutdown(mut self) -> Result<(), Diagnostic> {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
        }
        if let Some(mut browser) = self.capture_browser.take() {
            if let Some(stop_sender) = browser.stop_sender.take() {
                let _ = stop_sender.send(());
            }
            if let Some(task) = browser.task.take() {
                match task.await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(error) => return Err(join_diagnostic(&error)),
                }
            }
        }
        if let Some(task) = self.task.take() {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => return Err(join_diagnostic(&error)),
            }
        }
        Ok(())
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
        }
        if let Some(stop_sender) = self
            .capture_browser
            .as_mut()
            .and_then(|browser| browser.stop_sender.take())
        {
            let _ = stop_sender.send(());
        }
    }
}

/// Session-owned facade. Its only durable relationship is the caller's
/// active session; the listener and CA remain process memory.
pub struct ProxyCore {
    backend: Box<dyn ProxyBackend>,
    handle: Option<ProxyHandle>,
    capture_browser_listener: bool,
}

impl std::fmt::Debug for ProxyCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCore")
            .field("backend", &self.backend.kind())
            .field("running", &self.handle.is_some())
            .field("capture_browser_listener", &self.capture_browser_listener)
            .finish()
    }
}

impl Default for ProxyCore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyCore {
    /// Creates a core using the embedded hudsucker backend.
    #[must_use]
    pub fn new() -> Self {
        Self::with_backend(Box::new(HudsuckerBackend))
    }

    /// Creates a core with an alternate backend implementation.
    #[must_use]
    pub fn with_backend(backend: Box<dyn ProxyBackend>) -> Self {
        Self {
            backend,
            handle: None,
            capture_browser_listener: false,
        }
    }

    /// Also binds the capture browser's dedicated loopback listener when the
    /// proxy starts (see [`ProxyConfig::capture_browser_listener`]).
    pub fn enable_capture_browser_listener(&mut self) {
        self.capture_browser_listener = true;
    }

    /// The capture browser's dedicated listener, while the proxy is running.
    #[must_use]
    pub fn capture_browser_addr(&self) -> Option<SocketAddr> {
        self.handle
            .as_ref()
            .and_then(ProxyHandle::capture_browser_addr)
    }

    /// Returns capability health for the configured proxy route.
    pub async fn health(&self) -> BackendHealth {
        self.backend.health().await
    }

    /// Starts the proxy only for an active session.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the session is inactive, the listener cannot
    /// bind, or the selected backend fails to start.
    pub async fn start(
        &mut self,
        session: &Session,
        bind_addr: SocketAddr,
        ca: SessionCa,
        observer: Arc<dyn FlowObserver>,
    ) -> Result<SocketAddr, Diagnostic> {
        self.start_internal(session, bind_addr, ca, observer, None)
            .await
    }

    /// Starts the proxy with the live workbench's per-flow intercept
    /// controller attached to the same backend route.
    ///
    /// # Errors
    ///
    /// Returns the same session/backend diagnostics as [`Self::start`].
    pub async fn start_with_intercept(
        &mut self,
        session: &Session,
        bind_addr: SocketAddr,
        ca: SessionCa,
        observer: Arc<dyn FlowObserver>,
        intercept: Arc<InterceptController>,
    ) -> Result<SocketAddr, Diagnostic> {
        self.start_internal(session, bind_addr, ca, observer, Some(intercept))
            .await
    }

    async fn start_internal(
        &mut self,
        session: &Session,
        bind_addr: SocketAddr,
        ca: SessionCa,
        observer: Arc<dyn FlowObserver>,
        intercept: Option<Arc<InterceptController>>,
    ) -> Result<SocketAddr, Diagnostic> {
        if session.lifecycle() != SessionLifecycle::Active {
            let mut context = DiagnosticContext::new();
            context.insert(
                "session_id".to_owned(),
                DiagnosticValue::String(session.id().as_str().to_owned()),
            );
            context.insert(
                "lifecycle".to_owned(),
                DiagnosticValue::String(format!("{:?}", session.lifecycle()).to_ascii_lowercase()),
            );
            return Err(catalogue::PROXY_SESSION_NOT_ACTIVE.instantiate(context));
        }
        if self.handle.is_some() {
            return Err(catalogue::PROXY_BACKEND_START_FAILED.instantiate(DiagnosticContext::new()));
        }
        let capture_browser_listener = self.capture_browser_listener;
        let handle = self
            .backend
            .start(
                ProxyConfig {
                    session_id: session.id().as_str().to_owned(),
                    bind_addr,
                    ca,
                    intercept,
                    capture_browser_listener,
                },
                observer,
            )
            .await?;
        let address = handle.local_addr();
        self.handle = Some(handle);
        Ok(address)
    }

    /// Stops the listener owned by this core. Calling it twice is harmless.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the backend task fails or cannot be joined.
    pub async fn shutdown(&mut self) -> Result<(), Diagnostic> {
        if let Some(handle) = self.handle.take() {
            handle.shutdown().await
        } else {
            Ok(())
        }
    }

    /// Whether this core currently owns a live listener handle.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for ProxyCore {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            drop(handle);
        }
    }
}

/// hudsucker clones the handler per request (`self.clone().proxy(req)`) and runs
/// `handle_request` then `handle_response` sequentially on that same clone, so a
/// request's flow id lives in a per-request field on the clone. This is correct
/// under HTTP/2 multiplexing (each stream is its own clone) and across multiple
/// concurrent clients (each request is independent) — unlike the former
/// `client_addr`-keyed map, where concurrent streams sharing one address
/// overwrote each other and responses were mis-attributed to the last request.
#[derive(Clone)]
struct ObserveHandler {
    session_id: Arc<str>,
    observer: Arc<dyn FlowObserver>,
    intercept: Option<Arc<InterceptController>>,
    /// Flow id of the request currently being handled by this per-request clone.
    current_flow_id: Option<u64>,
    /// TLS config for byte-faithful workbench sends (see [`crate::raw_http`]).
    raw_upstream_tls: Option<Arc<hudsucker::rustls::ClientConfig>>,
    /// The listener this handler serves.
    role: ListenerRole,
    /// Set when this per-request clone is forwarding the capture browser's own
    /// traffic, which is relayed but never observed.
    withheld: bool,
    /// Origins of documents the capture browser loaded speculatively on its
    /// own (e.g. the search warm-up page it prerenders), which were withheld.
    /// Their subresources are withheld too: see
    /// [`Self::loads_for_withheld_speculation`].
    speculative_origins: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    /// WebSocket upgrade requests awaiting their tunnel, by connection. hudsucker
    /// answers a successful upgrade itself (no `handle_response`), so the 101
    /// is recorded against the handshake flow once the tunnel opens.
    ws_handshakes: Arc<std::sync::Mutex<HashMap<WebSocketConnectionKey, u64>>>,
}

impl ObserveHandler {
    fn new(
        session_id: String,
        observer: Arc<dyn FlowObserver>,
        intercept: Option<Arc<InterceptController>>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            observer,
            intercept,
            current_flow_id: None,
            raw_upstream_tls: None,
            role: ListenerRole::Shared,
            withheld: false,
            ws_handshakes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            speculative_origins: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    /// A withheld speculative navigation (`Sec-Purpose`) marks its origin, so
    /// the prerendered page's own loads can be recognised.
    fn remember_withheld_speculation(&self, req: &Request<Body>) {
        let speculative = req.headers().contains_key("sec-purpose");
        let navigation = req
            .headers()
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|mode| mode.eq_ignore_ascii_case("navigate"));
        if !(speculative && navigation) {
            return;
        }
        if let (Some(origin), Ok(mut origins)) =
            (uri_origin(req.uri()), self.speculative_origins.lock())
        {
            origins.insert(origin);
        }
    }

    /// A speculative load (`Sec-Purpose: prefetch;prerender`) made by a page
    /// the browser prerendered for itself. Its initiator is that page, so its
    /// Fetch Metadata reads same-origin or cross-site like any page request;
    /// what gives it away is that its `Referer`/`Origin` is a document already
    /// withheld as the browser's own. A target page's own speculation rules
    /// never match: its documents were never withheld.
    fn loads_for_withheld_speculation(&self, req: &Request<Body>) -> bool {
        if !req.headers().contains_key("sec-purpose") {
            return false;
        }
        let Ok(origins) = self.speculative_origins.lock() else {
            return false;
        };
        if origins.is_empty() {
            return false;
        }
        ["referer", "origin"].iter().any(|name| {
            req.headers()
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<hudsucker::hyper::Uri>().ok())
                .and_then(|uri| uri_origin(&uri))
                .is_some_and(|origin| origins.contains(&origin))
        })
    }

    fn with_role(mut self, role: ListenerRole) -> Self {
        self.role = role;
        self
    }

    fn with_raw_upstream_tls(mut self, tls: Arc<hudsucker::rustls::ClientConfig>) -> Self {
        self.raw_upstream_tls = Some(tls);
        self
    }

    fn observe_request(
        &self,
        req: &Request<Body>,
        origin: FlowOrigin,
        sent_headers: Option<Vec<(String, String)>>,
    ) -> u64 {
        let flow_id = self.observer.allocate_flow_id();
        self.observer.observe(FlowEvent::Request {
            flow_id,
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            version: format!("{:?}", req.version()),
            headers: sent_headers.unwrap_or_else(|| headers(req.headers())),
            origin,
        });
        flow_id
    }
}

/// A request's headers with their names in the case the client sent them.
///
/// hyper keeps the received case only in a crate-private extension (hudsucker
/// enables `preserve_header_case`), and its `HeaderMap` lowercases names. The
/// case is recovered the way hyper itself would forward it: the head, with
/// those extensions, is encoded by an HTTP/1 client into an in-memory pipe and
/// the header lines are read back. `None` if anything about that fails.
async fn original_case_headers(req: &Request<Body>) -> Option<Vec<(String, String)>> {
    use hudsucker::hyper::client::conn::http1;
    use tokio::io::AsyncReadExt;

    let mut probe = Request::builder()
        .method(req.method().clone())
        .uri("/")
        .body(Body::empty())
        .ok()?;
    *probe.headers_mut() = req.headers().clone();
    *probe.extensions_mut() = req.extensions().clone();
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let (mut sender, connection) = http1::Builder::new()
        .preserve_header_case(true)
        .handshake(hudsucker::hyper_util::rt::TokioIo::new(client))
        .await
        .ok()?;
    let driver = tokio::spawn(connection);
    // Nothing answers; only the encoded head is read back.
    let request = tokio::spawn(async move { sender.send_request(probe).await });
    let mut head = Vec::new();
    let mut buffer = [0_u8; 4096];
    let read = tokio::time::timeout(Duration::from_millis(500), async {
        while !head.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = server.read(&mut buffer).await.ok()?;
            if read == 0 {
                return None;
            }
            head.extend_from_slice(&buffer[..read]);
        }
        Some(())
    })
    .await;
    request.abort();
    driver.abort();
    read.ok()??;
    let text = String::from_utf8_lossy(&head);
    let lines = text
        .split("\r\n")
        .skip(1)
        .take_while(|line| !line.is_empty());
    let recovered: Vec<(String, String)> = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.to_owned(), value.trim().to_owned()))
        })
        .collect();
    // hyper may add framing of its own (a zero Content-Length for the empty
    // probe body); keep only what the client really sent, in its order.
    let sent = headers(req.headers());
    let mut recased = Vec::with_capacity(sent.len());
    let mut pool = recovered;
    for (name, value) in sent {
        let position = pool
            .iter()
            .position(|(candidate, _)| candidate.eq_ignore_ascii_case(&name))?;
        let (cased, _) = pool.remove(position);
        recased.push((cased, value));
    }
    Some(recased)
}

/// Transparent DNAT delivers clear HTTP in origin-form because the Android
/// client does not know it is speaking to a proxy. Hudsucker's upstream
/// connector needs an absolute URI, so recover it from the mandatory HTTP
/// `Host` header before handing the request to the backend. Proxy-aware
/// absolute-form requests are left unchanged.
fn normalize_origin_form(req: &mut Request<Body>) {
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return;
    }
    let Some(host) = req
        .headers()
        .get(hudsucker::hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);
    let Ok(uri) = format!("http://{host}{path}").parse() else {
        return;
    };
    *req.uri_mut() = uri;
}

impl HttpHandler for ObserveHandler {
    // One request's path through the proxy, in order: marker handling,
    // withholding, observation, the intercept gate, then forwarding.
    #[allow(clippy::too_many_lines)]
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        normalize_origin_form(&mut req);
        // Resend/Fuzz senders route through this same proxy; strip their private
        // origin marker before the request is recorded or forwarded so the tag
        // never leaks upstream and never appears in stored traffic. Ordinary
        // observed traffic carries no marker and tags as `Capture`.
        let origin = take_origin_marker(&mut req);
        // The capture browser's own service traffic (and its CONNECT tunnel
        // bookkeeping) is relayed untouched but kept out of the capture: not
        // recorded, stored, scoped, intercepted, fused or exported. Only its
        // host is reported, so the withheld volume stays visible.
        if self.role == ListenerRole::CaptureBrowser
            && (is_browser_internal(&req) || self.loads_for_withheld_speculation(&req))
        {
            self.withheld = true;
            self.remember_withheld_speculation(&req);
            if req.method() != Method::CONNECT {
                self.observer.observe(FlowEvent::BrowserInternalWithheld {
                    host: req.uri().host().unwrap_or_default().to_owned(),
                });
            }
            return RequestOrResponse::Request(req);
        }
        // Applied before observation so the recorded request shows the headers
        // that actually go on the wire.
        let wire_headers = take_wire_headers(&mut req);
        // A CONNECT reaching the MITM request handler over HTTP/2 is an RFC 8441
        // extended-CONNECT (WebSocket-over-h2); ordinary CONNECT tunnels are
        // handled below this layer. Surface the known limitation as a signal.
        if req.method() == Method::CONNECT && req.version() == Version::HTTP_2 {
            self.observer
                .observe(FlowEvent::Diagnostic(rfc8441_diagnostic()));
        }
        // A request intercept is about to hold is recorded with its header names
        // in the case the client sent them, so the editor shows — and a
        // modified forward sends — exactly those names (as Resend does).
        let sent_headers = match &self.intercept {
            Some(intercept)
                if matches!(req.version(), Version::HTTP_10 | Version::HTTP_11)
                    && intercept.holds(req.uri().host()) =>
            {
                original_case_headers(&req).await
            }
            _ => None,
        };
        let flow_id = self.observe_request(&req, origin, sent_headers);
        // WebSocket upgrades: the proxy relays frames with tungstenite, which does
        // not implement permessage-deflate. Forwarding the client's offer would let
        // the server compress its frames, which then fail to decode, so the
        // server-to-client stream dies on its first message. Offer no extensions
        // upstream (the client side already negotiates none). The recorded request
        // above keeps what the client actually sent.
        if req
            .headers()
            .get(hudsucker::hyper::header::UPGRADE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        {
            req.headers_mut().remove("sec-websocket-extensions");
            if let Some(url) = websocket_url(req.uri()) {
                if let Ok(mut pending) = self.ws_handshakes.lock() {
                    pending.insert(
                        WebSocketConnectionKey {
                            client: ctx.client_addr,
                            url,
                        },
                        flow_id,
                    );
                }
            }
        }
        // Record on this per-request handler clone so `handle_response` correlates
        // to exactly this request — never to another concurrent stream on the same
        // connection or another client sharing transport attributes.
        self.current_flow_id = Some(flow_id);
        // Set once the request body has been read and recorded up front, so it
        // is not recorded a second time as it streams upstream.
        let mut body_recorded = false;
        if let Some(intercept) = &self.intercept {
            intercept.wait().await;
            let host = req.uri().host().map(str::to_owned);
            if intercept.holds(host.as_deref()) {
                // Read the whole body before pausing so the held request is
                // shown, and edited, complete rather than headers-only.
                let body = std::mem::replace(req.body_mut(), Body::empty());
                let Ok(collected) = http_body_util::BodyExt::collect(body).await else {
                    return RequestOrResponse::Response(
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::from("request body could not be read"))
                            .expect("static body-read response is valid"),
                    );
                };
                let bytes = collected.to_bytes();
                self.record_request_body(flow_id, &bytes);
                *req.body_mut() = Body::from(bytes);
                body_recorded = true;
            }
            match intercept.await_decision(flow_id, host.as_deref()).await {
                InterceptDecision::Forward => {}
                InterceptDecision::ForwardModified {
                    method,
                    url,
                    headers: replacement_headers,
                    body,
                } => {
                    match edited_request(&req, &method, url.as_deref(), &replacement_headers, body)
                    {
                        Ok(edit) => {
                            let response = self
                                .forward_edit(ctx, flow_id, origin, edit, wire_headers.as_deref())
                                .await;
                            return RequestOrResponse::Response(response);
                        }
                        Err(error) => {
                            // The original request is forwarded untouched.
                            self.observer.observe(FlowEvent::Diagnostic(
                                malformed_edit_diagnostic(flow_id, &error),
                            ));
                        }
                    }
                }
                InterceptDecision::Drop => {
                    // Record the outcome so the Live row shows 403 rather than
                    // hanging at a pending "…" forever (#19b).
                    self.observe_synthetic_response(ctx, flow_id, StatusCode::FORBIDDEN);
                    return RequestOrResponse::Response(
                        Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .body(Body::from("request dropped by APIaxess intercept"))
                            .expect("static drop response is valid"),
                    );
                }
                InterceptDecision::Timeout => {
                    self.observer
                        .observe(FlowEvent::Diagnostic(intercept_timeout_diagnostic(flow_id)));
                }
            }
        }
        let (parts, body) = req.into_parts();
        let body = if body_recorded {
            body
        } else {
            capture_body(
                body,
                flow_id,
                BodyDirection::Request,
                Arc::clone(&self.observer),
            )
        };
        if let (Some(wire_headers), Some(tls)) = (wire_headers, self.raw_upstream_tls.clone()) {
            if parts.method != Method::CONNECT {
                let response = self
                    .forward_raw(ctx, tls, &parts, &wire_headers, body, true)
                    .await;
                return RequestOrResponse::Response(response);
            }
        }
        RequestOrResponse::Request(Request::from_parts(parts, body))
    }

    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if self.withheld {
            return res;
        }
        // Correlate to the request this same per-request clone handled.
        let flow_id = self.current_flow_id.unwrap_or_default();
        self.observer.observe(FlowEvent::Response {
            flow_id,
            client_addr: ctx.client_addr,
            status: res.status().as_u16(),
            version: format!("{:?}", res.version()),
            headers: headers(res.headers()),
        });
        let (parts, body) = res.into_parts();
        Response::from_parts(
            parts,
            capture_body(
                body,
                flow_id,
                BodyDirection::Response,
                Arc::clone(&self.observer),
            ),
        )
    }

    async fn handle_error(
        &mut self,
        ctx: &HttpContext,
        error: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        // Walk the error source chain so upstream failures (TLS, connect,
        // protocol) are diagnosable rather than a bare "client error (Connect)".
        let mut chain = error.to_string();
        let mut source = std::error::Error::source(&error);
        while let Some(inner) = source {
            chain.push_str(" -> ");
            chain.push_str(&inner.to_string());
            source = inner.source();
        }
        self.upstream_failure(ctx, chain)
    }
}

impl ObserveHandler {
    /// Records a fully-read request body, within the capture limit.
    fn record_request_body(&self, flow_id: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.observer.observe(FlowEvent::BodyChunk {
            flow_id,
            direction: BodyDirection::Request,
            bytes: bytes[..bytes.len().min(MAX_CAPTURE_BYTES)].to_vec(),
        });
    }

    /// Forwards a validated intercept edit byte-for-byte. The flow is
    /// re-recorded as edited so it shows what the target actually received.
    /// `authored` is the header list of a held workbench send, whose case the
    /// edit keeps and whose sender expects the private response markers.
    async fn forward_edit(
        &mut self,
        ctx: &HttpContext,
        flow_id: u64,
        origin: FlowOrigin,
        mut edit: EditedRequest,
        authored: Option<&[(String, String)]>,
    ) -> Response<Body> {
        if let Some(authored) = authored {
            edit.headers = wire_headers_after_edit(authored, edit.headers);
        }
        let Some(tls) = self.raw_upstream_tls.clone() else {
            return self.upstream_failure(
                ctx,
                "byte-faithful upstream sender is not configured".to_owned(),
            );
        };
        self.observer.observe(FlowEvent::Request {
            flow_id,
            method: edit.parts.method.to_string(),
            uri: edit.parts.uri.to_string(),
            version: format!("{:?}", Version::HTTP_11),
            headers: edit.headers.clone(),
            origin,
        });
        self.record_request_body(flow_id, &edit.body);
        self.forward_raw(
            ctx,
            tls,
            &edit.parts,
            &edit.headers,
            Body::from(edit.body),
            authored.is_some(),
        )
        .await
    }

    /// Writes a request upstream byte-for-byte and returns the recorded
    /// response. For a workbench send (`markers`), the upstream status line and
    /// raw header list go back to the sender in private markers (added after
    /// recording, so never stored); an observed client gets the plain response.
    async fn forward_raw(
        &mut self,
        ctx: &HttpContext,
        tls: Arc<hudsucker::rustls::ClientConfig>,
        parts: &hudsucker::hyper::http::request::Parts,
        wire_headers: &[(String, String)],
        body: Body,
        markers: bool,
    ) -> Response<Body> {
        let fail = |this: &Self, chain: String| {
            if markers {
                this.raw_upstream_failure(ctx, chain)
            } else {
                this.upstream_failure(ctx, chain)
            }
        };
        let body = match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => return fail(self, format!("read request body: {error}")),
        };
        let raw = match crate::raw_http::exchange(
            tls,
            &parts.uri,
            parts.method.as_str(),
            wire_headers,
            &body,
        )
        .await
        {
            Ok(raw) => raw,
            Err(error) => return fail(self, error),
        };
        let status_line = raw.status_line();
        let header_list = encode_header_list(&raw.headers);
        let mut builder = Response::builder().status(raw.status);
        for (name, value) in &raw.headers {
            if let (Ok(name), Ok(value)) = (
                hudsucker::hyper::header::HeaderName::try_from(name.as_str()),
                hudsucker::hyper::header::HeaderValue::try_from(value.as_str()),
            ) {
                builder = builder.header(name, value);
            }
        }
        let Ok(response) = builder.body(Body::from(bytes::Bytes::from(raw.body))) else {
            return fail(self, format!("unrepresentable status {}", raw.status));
        };
        let mut response = self.handle_response(ctx, response).await;
        if !markers {
            return response;
        }
        for (marker, value) in [
            (UPSTREAM_STATUS_MARKER, status_line),
            (UPSTREAM_HEADERS_MARKER, header_list),
        ] {
            if let Ok(value) = hudsucker::hyper::header::HeaderValue::try_from(value) {
                response.headers_mut().insert(marker, value);
            }
        }
        response
    }

    /// [`Self::upstream_failure`] for a workbench send: the 502 also carries
    /// the failure in a private marker so the sender reports a transport
    /// failure rather than a server response. Workbench sends only, so an
    /// observed client never sees the marker.
    fn raw_upstream_failure(&self, ctx: &HttpContext, chain: String) -> Response<Body> {
        let marker = hudsucker::hyper::header::HeaderValue::try_from(
            chain
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect::<String>(),
        );
        let mut response = self.upstream_failure(ctx, chain);
        if let Ok(marker) = marker {
            response.headers_mut().insert(UPSTREAM_ERROR_MARKER, marker);
        }
        response
    }

    /// Records an upstream failure diagnostic and answers `502`.
    fn upstream_failure(&self, ctx: &HttpContext, chain: String) -> Response<Body> {
        if self.withheld {
            // The browser's own service call failing is not the operator's
            // concern; answer it without a diagnostic.
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("static proxy error response is valid");
        }
        let mut context = DiagnosticContext::new();
        context.insert(
            "session_id".to_owned(),
            DiagnosticValue::String(self.session_id.to_string()),
        );
        context.insert(
            "client_addr".to_owned(),
            DiagnosticValue::String(ctx.client_addr.to_string()),
        );
        context.insert("error".to_owned(), DiagnosticValue::String(chain));
        self.observer.observe(FlowEvent::Diagnostic(
            catalogue::PROXY_UPSTREAM_UNREACHABLE.instantiate(context),
        ));
        // Record the 502 against the in-flight flow so its Live row settles on a
        // real status instead of hanging at a pending "…" (#19b).
        if let Some(flow_id) = self.current_flow_id {
            self.observe_synthetic_response(ctx, flow_id, StatusCode::BAD_GATEWAY);
        }
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("static proxy error response is valid")
    }

    /// Emits a `Response` event for a proxy-generated answer (a dropped request
    /// or an unreachable upstream) that never had a real upstream response, so
    /// the flow's Live row reflects the outcome rather than staying pending.
    fn observe_synthetic_response(&self, ctx: &HttpContext, flow_id: u64, status: StatusCode) {
        self.observer.observe(FlowEvent::Response {
            flow_id,
            client_addr: ctx.client_addr,
            status: status.as_u16(),
            version: format!("{:?}", Version::HTTP_11),
            headers: Vec::new(),
        });
    }
}

fn contains_header(headers: &[(String, String)], wanted: &str) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
}

/// A validated intercept edit, ready for the byte-faithful upstream write.
struct EditedRequest {
    /// Edited method and URI (the rest of the held request's parts).
    parts: hudsucker::hyper::http::request::Parts,
    /// Header list to write, in edited order and case, with framing fixed.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Validates an intercept edit against the held request without touching it,
/// so a malformed edit leaves the original request to be forwarded as held.
///
/// The edited headers go on the wire in their edited order and case, but the
/// framing is made to match the edited body: the held body was read whole, so
/// it is sent with a fixed length — `Transfer-Encoding` is dropped and
/// `Content-Length` is recomputed in place (or added when a body has none).
/// `Host` is derived from the URL only when the edit has none.
fn edited_request(
    held: &Request<Body>,
    method: &str,
    url: Option<&str>,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<EditedRequest, String> {
    let method: Method = method
        .trim()
        .parse()
        .map_err(|error| format!("invalid HTTP method: {error}"))?;
    let target: hudsucker::hyper::Uri = match url.map(str::trim).filter(|url| !url.is_empty()) {
        Some(url) => url
            .parse()
            .map_err(|error| format!("invalid URL {url:?}: {error}"))?,
        None => held.uri().clone(),
    };
    if !matches!(target.scheme_str(), Some("http" | "https")) || target.host().is_none() {
        return Err(format!("URL must be an absolute http(s) URL, got {target}"));
    }
    let body_len = body.len().to_string();
    let mut wire: Vec<(String, String)> = Vec::with_capacity(headers.len() + 2);
    for (name, value) in headers {
        let name = name.trim();
        hudsucker::hyper::header::HeaderName::try_from(name)
            .map_err(|error| format!("invalid header name {name:?}: {error}"))?;
        hudsucker::hyper::header::HeaderValue::try_from(value.as_str())
            .map_err(|error| format!("invalid value for header {name:?}: {error}"))?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.to_ascii_lowercase().starts_with("x-apiaxess-")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            // One recomputed Content-Length, at the first one's position.
            if !contains_header(&wire, name) {
                wire.push((name.to_owned(), body_len.clone()));
            }
            continue;
        }
        wire.push((name.to_owned(), value.clone()));
    }
    if !contains_header(&wire, "host") {
        if let Some(authority) = target.authority() {
            wire.insert(0, ("Host".to_owned(), authority.to_string()));
        }
    }
    if !body.is_empty() && !contains_header(&wire, "content-length") {
        wire.push(("Content-Length".to_owned(), body_len));
    }
    let mut parts = Request::new(()).into_parts().0;
    parts.method = method;
    parts.uri = target;
    Ok(EditedRequest {
        parts,
        headers: wire,
        body,
    })
}

/// The durable store owns retention policy. Keep the observer capture limit
/// aligned with its 64 MiB per-body safety limit instead of the old 2.2
/// in-memory 1 MiB preview limit.
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;

fn capture_body(
    body: Body,
    flow_id: u64,
    direction: BodyDirection,
    observer: Arc<dyn FlowObserver>,
) -> Body {
    let retained = Arc::new(Mutex::new(0_usize));
    let end = BodyEndSignal {
        flow_id,
        direction,
        observer: Arc::clone(&observer),
    };
    let stream = BodyStream::new(body).map_ok(move |frame| {
        let _ = &end;
        if let Some(data) = frame.data_ref() {
            let bytes = if let Ok(mut retained) = retained.lock() {
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(*retained);
                let length = remaining.min(data.len());
                *retained += length;
                data.slice(..length).to_vec()
            } else {
                Vec::new()
            };
            if !bytes.is_empty() {
                observer.observe(FlowEvent::BodyChunk {
                    flow_id,
                    direction,
                    bytes,
                });
            }
        }
        frame
    });
    Body::from(StreamBody::new(stream))
}

/// Reports the end of a forwarded body when the stream carrying it is dropped,
/// which happens on completion and on a client or upstream disconnect alike.
struct BodyEndSignal {
    flow_id: u64,
    direction: BodyDirection,
    observer: Arc<dyn FlowObserver>,
}

impl Drop for BodyEndSignal {
    fn drop(&mut self) {
        self.observer.observe(FlowEvent::BodyEnd {
            flow_id: self.flow_id,
            direction: self.direction,
        });
    }
}

fn intercept_timeout_diagnostic(flow_id: u64) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "flow_id".to_owned(),
        DiagnosticValue::Integer(i64::try_from(flow_id).unwrap_or(i64::MAX)),
    );
    catalogue::PROXY_INTERCEPT_TIMEOUT.instantiate(context)
}

fn malformed_edit_diagnostic(flow_id: u64, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "flow_id".to_owned(),
        DiagnosticValue::Integer(i64::try_from(flow_id).unwrap_or(i64::MAX)),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_INTERCEPT_EDIT_INVALID.instantiate(context)
}

/// The connection and direction a WebSocket context describes.
/// `scheme://authority` of an absolute URI, lower-cased.
fn uri_origin(uri: &hudsucker::hyper::Uri) -> Option<String> {
    Some(format!(
        "{}://{}",
        uri.scheme_str()?.to_ascii_lowercase(),
        uri.authority()?.as_str().to_ascii_lowercase()
    ))
}

/// The `ws://`/`wss://` URL hudsucker dials for an upgrade request.
fn websocket_url(uri: &hudsucker::hyper::Uri) -> Option<String> {
    let scheme = match uri.scheme_str()? {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        _ => return None,
    };
    let authority = uri.authority()?;
    let path = uri.path_and_query().map_or("/", |path| path.as_str());
    Some(format!("{scheme}://{authority}{path}"))
}

fn websocket_endpoint(ctx: &WebSocketContext) -> (WebSocketConnectionKey, WebSocketDirection) {
    match ctx {
        WebSocketContext::ClientToServer { src, dst, .. } => (
            WebSocketConnectionKey {
                client: *src,
                url: dst.to_string(),
            },
            WebSocketDirection::ClientToServer,
        ),
        WebSocketContext::ServerToClient { src, dst, .. } => (
            WebSocketConnectionKey {
                client: *dst,
                url: src.to_string(),
            },
            WebSocketDirection::ServerToClient,
        ),
    }
}

impl WebSocketHandler for ObserveHandler {
    /// hudsucker's forwarding loop, plus an end-of-stream event so a closed
    /// connection is recorded as closed even without a close frame.
    fn handle_websocket(
        mut self,
        ctx: WebSocketContext,
        mut stream: impl hudsucker::futures::Stream<
            Item = Result<Message, hudsucker::tokio_tungstenite::tungstenite::Error>,
        > + Unpin
        + Send
        + 'static,
        mut sink: impl hudsucker::futures::Sink<
            Message,
            Error = hudsucker::tokio_tungstenite::tungstenite::Error,
        > + Unpin
        + Send
        + 'static,
    ) -> impl std::future::Future<Output = ()> + Send {
        use hudsucker::futures::{SinkExt, StreamExt};
        use hudsucker::tokio_tungstenite::tungstenite::Error as WsError;
        // The tunnel only opens on a 101: settle the handshake flow now, so its
        // Live row and exports show the switch rather than a pending request.
        let (connection, _) = websocket_endpoint(&ctx);
        let handshake = self
            .ws_handshakes
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&connection));
        if let Some(flow_id) = handshake {
            self.observer.observe(FlowEvent::Response {
                flow_id,
                client_addr: connection.client,
                status: StatusCode::SWITCHING_PROTOCOLS.as_u16(),
                version: format!("{:?}", Version::HTTP_11),
                headers: Vec::new(),
            });
        }
        async move {
            while let Some(message) = stream.next().await {
                let Ok(message) = message else {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                };
                let Some(message) = self.handle_message(&ctx, message).await else {
                    continue;
                };
                if let Err(error) = sink.send(message).await
                    && !matches!(error, WsError::ConnectionClosed)
                {
                    break;
                }
            }
            let (connection, direction) = websocket_endpoint(&ctx);
            self.observer.observe(FlowEvent::WebSocketClosed {
                connection,
                direction,
            });
        }
    }

    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (connection, direction) = websocket_endpoint(ctx);
        let (kind, close_code) = match &message {
            Message::Text(_) => (WebSocketMessageKind::Text, None),
            Message::Binary(_) => (WebSocketMessageKind::Binary, None),
            Message::Ping(_) => (WebSocketMessageKind::Ping, None),
            Message::Pong(_) => (WebSocketMessageKind::Pong, None),
            Message::Close(frame) => (
                WebSocketMessageKind::Close,
                frame.as_ref().map(|frame| u16::from(frame.code)),
            ),
            Message::Frame(_) => (WebSocketMessageKind::Frame, None),
        };
        let data = message.clone().into_data();
        let payload_bytes = data.len();
        let payload = data[..payload_bytes.min(MAX_WEBSOCKET_PAYLOAD_BYTES)].to_vec();
        self.observer.observe(FlowEvent::WebSocketMessage {
            connection,
            direction,
            kind,
            payload,
            payload_bytes,
            close_code,
            observed_at: chrono::Utc::now(),
        });
        Some(message)
    }
}

fn headers(headers: &hudsucker::hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_owned(),
            )
        })
        .collect()
}

fn bind_diagnostic(address: SocketAddr, error: &std::io::Error) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "address".to_owned(),
        DiagnosticValue::String(address.to_string()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    catalogue::PROXY_PORT_IN_USE.instantiate(context)
}

fn backend_start_diagnostic(error: &impl std::fmt::Display) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    catalogue::PROXY_BACKEND_START_FAILED.instantiate(context)
}

fn join_diagnostic(error: &tokio::task::JoinError) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_string()),
    );
    catalogue::PROXY_BACKEND_START_FAILED.instantiate(context)
}

/// The workbench does not support tunnelling `WebSocket` traffic over HTTP/2
/// extended CONNECT (RFC 8441); this records that limitation as a signal when the
/// pattern is observed. Prevalence is near-zero (mobile stacks use HTTP/1.1
/// WebSocket handshakes); runtime detection is the revisit trigger.
fn rfc8441_diagnostic() -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "transport".to_owned(),
        DiagnosticValue::String("rfc8441".to_owned()),
    );
    context.insert(
        "source".to_owned(),
        DiagnosticValue::String("hudsucker-http2-connect".to_owned()),
    );
    catalogue::PROXY_WEBSOCKET_HTTP2_UNSUPPORTED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::{HudsuckerBackend, NoopObserver, ProxyBackend, ProxyConfig};
    use crate::{LiveWorkbench, SessionCa, TrafficStore};
    use std::{
        env, fs,
        net::SocketAddr,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn send_http_request(
        proxy: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = tokio::net::TcpStream::connect(proxy).await?;
        client.write_all(request).await?;
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut response),
        )
        .await??;
        Ok(response)
    }

    #[test]
    fn origin_marker_is_read_and_stripped() {
        use super::{FlowOrigin, ORIGIN_MARKER_HEADER, take_origin_marker};
        use hudsucker::{Body, hyper::Request};

        // A marked request tags its origin and no longer carries the marker, so it
        // is neither recorded nor forwarded upstream.
        let mut marked = Request::builder()
            .uri("http://api.example.test/items")
            .header(ORIGIN_MARKER_HEADER, "fuzz")
            .header("accept", "application/json")
            .body(Body::empty())
            .expect("request");
        assert_eq!(take_origin_marker(&mut marked), FlowOrigin::Fuzz);
        assert!(!marked.headers().contains_key(ORIGIN_MARKER_HEADER));
        assert!(marked.headers().contains_key("accept"));

        // An unmarked request is ordinary observed capture traffic.
        let mut plain = Request::builder()
            .uri("http://api.example.test/items")
            .body(Body::empty())
            .expect("request");
        assert_eq!(take_origin_marker(&mut plain), FlowOrigin::Capture);
    }

    #[tokio::test]
    async fn origin_form_is_normalized_and_completes_like_absolute_form() {
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = upstream.accept().await.expect("upstream accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = socket.read(&mut buffer).await.expect("upstream read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .expect("upstream response");
            }
        });
        let store_path = env::temp_dir().join(format!(
            "apiaxess-proxy-origin-form-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            TrafficStore::open(&store_path, "session:origin-form-test").expect("traffic store"),
        );
        let observer = Arc::new(LiveWorkbench::new());
        observer.attach_store(Arc::clone(&store));
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:origin-form-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: None,
                    capture_browser_listener: false,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        let proxy = handle.local_addr();
        let authority = upstream_address.to_string();
        let absolute = format!(
            "GET http://{authority}/absolute HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        );
        let origin =
            format!("GET /origin HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
        let absolute_response = send_http_request(proxy, absolute.as_bytes())
            .await
            .expect("absolute request");
        let origin_response = send_http_request(proxy, origin.as_bytes())
            .await
            .expect("origin request");
        assert!(String::from_utf8_lossy(&absolute_response).starts_with("HTTP/1.1 200"));
        assert!(String::from_utf8_lossy(&origin_response).starts_with("HTTP/1.1 200"));
        handle.shutdown().await.expect("proxy shutdown");
        upstream_task.await.expect("upstream task");
        let summaries = store.summaries().expect("traffic summaries");
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|summary| summary.status == Some(200)));
        assert!(
            summaries
                .iter()
                .any(|summary| summary.path.as_deref() == Some("/absolute"))
        );
        assert!(
            summaries
                .iter()
                .any(|summary| summary.path.as_deref() == Some("/origin"))
        );
        drop(observer);
        drop(store);
        fs::remove_dir_all(store_path).expect("remove test traffic store");
    }

    #[test]
    fn browser_internal_traffic_is_the_initiator_less_requests_no_one_navigated_to() {
        use super::is_browser_internal;
        use hudsucker::{
            Body,
            hyper::{Method, Request, Version},
        };
        // Header sets as Chromium sends them (from a real capture).
        let request = |method: Method, uri: &str, headers: &[(&str, &str)]| {
            let mut builder = Request::builder().method(method).uri(uri);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            builder.body(Body::empty()).expect("request")
        };
        let service = [
            ("sec-fetch-site", "none"),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-dest", "empty"),
        ];
        // The browser's own service calls.
        for uri in [
            "https://update.googleapis.com/service/update2/json",
            "https://android.clients.google.com/checkin",
            "https://accounts.google.com/ListAccounts",
        ] {
            assert!(
                is_browser_internal(&request(Method::POST, uri, &service)),
                "{uri}"
            );
        }
        // The search warm-up: an initiator-less speculative navigation.
        assert!(is_browser_internal(&request(
            Method::GET,
            "https://www.google.com/search/warmup.html",
            &[
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
                ("sec-purpose", "prefetch"),
            ],
        )));
        // A navigation the operator (or APIaxess over CDP) started is kept.
        assert!(!is_browser_internal(&request(
            Method::GET,
            "http://127.0.0.1:9201/",
            &[
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-dest", "document"),
                ("sec-fetch-user", "?1"),
            ],
        )));
        // Page traffic always has an initiator, same-site or not.
        assert!(!is_browser_internal(&request(
            Method::POST,
            "http://127.0.0.1:9201/graphql",
            &[
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-mode", "cors")
            ],
        )));
        assert!(!is_browser_internal(&request(
            Method::GET,
            "https://fonts.gstatic.com/s/font.woff2",
            &[("sec-fetch-site", "cross-site"), ("sec-fetch-dest", "font")],
        )));
        // Without Fetch Metadata, page traffic still carries the profile's
        // Accept-Language: a WebSocket handshake, a plain-HTTP remote host.
        assert!(!is_browser_internal(&request(
            Method::GET,
            "http://127.0.0.1:9201/ws?room=ref",
            &[
                ("upgrade", "websocket"),
                ("origin", "http://127.0.0.1:9201"),
                ("accept-language", "en-US,en;q=0.9"),
            ],
        )));
        assert!(!is_browser_internal(&request(
            Method::GET,
            "http://example.test/page",
            &[("accept-language", "en-US,en;q=0.9")],
        )));
        // A component download from the profile-less system context has
        // neither.
        assert!(is_browser_internal(&request(
            Method::GET,
            "http://edgedl.me.gvt1.com/edgedl/release2/chrome_component/x.crx3",
            &[
                ("accept-encoding", "gzip, deflate"),
                ("user-agent", "Mozilla/5.0")
            ],
        )));
        // Tunnel bookkeeping is never a flow; an HTTP/2 extended CONNECT is a
        // WebSocket and is kept.
        assert!(is_browser_internal(&request(
            Method::CONNECT,
            "example.test:443",
            &[]
        )));
        let mut extended = request(Method::CONNECT, "https://example.test/ws", &[]);
        *extended.version_mut() = Version::HTTP_2;
        assert!(!is_browser_internal(&extended));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn capture_browser_listener_relays_but_withholds_the_browsers_own_traffic() {
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let mut paths = Vec::new();
            for _ in 0..3 {
                let (mut socket, _) = upstream.accept().await.expect("upstream accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = socket.read(&mut buffer).await.expect("upstream read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                paths.push(line);
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .expect("upstream response");
            }
            paths
        });
        let store_path = env::temp_dir().join(format!(
            "apiaxess-proxy-browser-internal-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            TrafficStore::open(&store_path, "session:browser-internal-test")
                .expect("traffic store"),
        );
        let observer = Arc::new(LiveWorkbench::new());
        observer.attach_store(Arc::clone(&store));
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:browser-internal-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: None,
                    capture_browser_listener: true,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        let shared = handle.local_addr();
        let browser = handle
            .capture_browser_addr()
            .expect("capture browser listener is bound");
        assert_ne!(shared, browser);
        let authority = upstream_address.to_string();
        let get = |path: &str, metadata: &str| {
            format!(
                "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\n{metadata}Connection: close\r\n\r\n"
            )
        };
        let service = "Sec-Fetch-Site: none\r\nSec-Fetch-Mode: no-cors\r\n";
        let own = send_http_request(browser, get("/browser-own", service).as_bytes())
            .await
            .expect("browser-internal request");
        let navigation = "Sec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\n";
        let page = send_http_request(browser, get("/page", navigation).as_bytes())
            .await
            .expect("page request");
        // The same service-shaped request from another client is not the
        // capture browser's, so it is captured.
        let device = send_http_request(shared, get("/shared", service).as_bytes())
            .await
            .expect("shared-listener request");
        for response in [&own, &page, &device] {
            assert!(String::from_utf8_lossy(response).starts_with("HTTP/1.1 200"));
        }
        handle.shutdown().await.expect("proxy shutdown");
        // All three really reached the upstream: nothing is blocked.
        assert_eq!(upstream_task.await.expect("upstream task").len(), 3);
        let mut recorded: Vec<_> = store
            .summaries()
            .expect("traffic summaries")
            .into_iter()
            .filter_map(|summary| summary.path)
            .collect();
        recorded.sort();
        // The navigation and the other client's request are captured; the
        // browser's own request is not.
        assert_eq!(recorded, vec!["/page".to_owned(), "/shared".to_owned()]);
        assert_eq!(
            observer.browser_internal_withheld(),
            vec![("127.0.0.1".to_owned(), 1)]
        );
        drop(observer);
        drop(store);
        fs::remove_dir_all(store_path).expect("remove test traffic store");
    }

    #[tokio::test]
    async fn a_websocket_handshake_settles_at_101_once_the_tunnel_opens() {
        use hudsucker::futures::{SinkExt, StreamExt};
        use hudsucker::tokio_tungstenite::{accept_async, client_async, tungstenite::Message};

        // An upstream WebSocket echo server.
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.expect("upstream accept");
            let mut ws = accept_async(socket).await.expect("upstream handshake");
            while let Some(Ok(message)) = ws.next().await {
                if message.is_close() {
                    break;
                }
                if message.is_text() && ws.send(message).await.is_err() {
                    break;
                }
            }
        });
        let store_path = env::temp_dir().join(format!(
            "apiaxess-proxy-ws-handshake-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            TrafficStore::open(&store_path, "session:ws-handshake-test").expect("traffic store"),
        );
        let observer = Arc::new(LiveWorkbench::new());
        observer.attach_store(Arc::clone(&store));
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:ws-handshake-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: None,
                    capture_browser_listener: false,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        // A proxy-aware client speaks to the proxy; tungstenite sends the
        // upgrade in origin form with a Host header, which the proxy resolves.
        let tcp = tokio::net::TcpStream::connect(handle.local_addr())
            .await
            .expect("connect proxy");
        let (mut ws, _) = client_async(format!("ws://{upstream_address}/ws?room=ref"), tcp)
            .await
            .expect("handshake through the proxy");
        ws.send(Message::text("hello")).await.expect("send");
        let echoed = ws.next().await.expect("echo").expect("echo frame");
        assert_eq!(echoed.into_text().expect("text").as_str(), "hello");
        ws.close(None).await.expect("close");
        drop(ws);
        upstream_task.await.expect("upstream task");
        // The tunnel's events are persisted off-path; give them a moment.
        let mut handshake = None;
        for _ in 0..50 {
            handshake = store
                .summaries()
                .expect("summaries")
                .into_iter()
                .find(|flow| flow.path.as_deref() == Some("/ws?room=ref"));
            if handshake.as_ref().is_some_and(|flow| flow.status.is_some()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let handshake = handshake.expect("the handshake is a flow");
        assert_eq!(handshake.status, Some(101), "not left pending at status 0");
        let mut connections = Vec::new();
        for _ in 0..50 {
            connections = store.ws_connections().expect("connections");
            if connections
                .first()
                .is_some_and(|connection| connection.message_count >= 2)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            connections
                .first()
                .is_some_and(|connection| connection.message_count >= 2)
        );
        handle.shutdown().await.expect("proxy shutdown");
        drop(observer);
        drop(store);
        let _ = fs::remove_dir_all(store_path);
    }

    #[tokio::test]
    async fn requests_held_by_a_replaced_session_are_dropped_not_inherited() {
        let controller = Arc::new(super::InterceptController::default());
        controller.set_enabled(true);
        let waiting = {
            let controller = Arc::clone(&controller);
            tokio::spawn(
                async move { controller.await_decision(7, Some("api.example.test")).await },
            )
        };
        let held = next_held(&controller, &[]).await;
        assert_eq!(held, 7);
        assert_eq!(controller.drop_all_pending(), 1);
        assert_eq!(
            waiting.await.expect("decision"),
            super::InterceptDecision::Drop
        );
        assert!(controller.pending_ids().is_empty());
    }

    #[tokio::test]
    async fn a_page_the_browser_prerendered_for_itself_is_withheld_with_its_loads() {
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = upstream.accept().await.expect("upstream accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = socket.read(&mut buffer).await.expect("upstream read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .expect("upstream response");
            }
        });
        let store_path = env::temp_dir().join(format!(
            "apiaxess-proxy-speculation-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            TrafficStore::open(&store_path, "session:speculation-test").expect("traffic store"),
        );
        let observer = Arc::new(LiveWorkbench::new());
        observer.attach_store(Arc::clone(&store));
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:speculation-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: None,
                    capture_browser_listener: true,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        let browser = handle.capture_browser_addr().expect("capture listener");
        let authority = upstream_address.to_string();
        let get = |path: &str, headers: &str| {
            format!(
                "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nAccept-Language: en-US\r\n{headers}Connection: close\r\n\r\n"
            )
        };
        // 1. The browser prerenders its own search warm-up page.
        let warmup = "Sec-Fetch-Site: none\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\nSec-Purpose: prefetch;prerender\r\n";
        send_http_request(browser, get("/search/warmup.html", warmup).as_bytes())
            .await
            .expect("warm-up");
        // 2. That prerendered page loads an image: same-origin to itself.
        let prerendered_load = format!(
            "Sec-Fetch-Site: same-origin\r\nSec-Fetch-Mode: no-cors\r\nSec-Fetch-Dest: image\r\nSec-Purpose: prefetch;prerender\r\nReferer: http://{authority}/search/warmup.html\r\n"
        );
        send_http_request(browser, get("/logo.png", &prerendered_load).as_bytes())
            .await
            .expect("prerendered load");
        // 3. The target's own page prefetches something (its own speculation
        //    rules): its document was never withheld, so it is captured.
        let target_prefetch = "Sec-Fetch-Site: cross-site\r\nSec-Fetch-Mode: no-cors\r\nSec-Purpose: prefetch\r\nReferer: http://target.test/\r\n";
        send_http_request(browser, get("/next", target_prefetch).as_bytes())
            .await
            .expect("target prefetch");
        handle.shutdown().await.expect("proxy shutdown");
        upstream_task.await.expect("upstream task");
        let recorded: Vec<_> = store
            .summaries()
            .expect("summaries")
            .into_iter()
            .filter_map(|summary| summary.path)
            .collect();
        assert_eq!(recorded, vec!["/next".to_owned()]);
        assert_eq!(
            observer.browser_internal_withheld(),
            vec![("127.0.0.1".to_owned(), 2)]
        );
        drop(observer);
        drop(store);
        let _ = fs::remove_dir_all(store_path);
    }

    /// Holds one request on `controller` and returns its flow id.
    async fn next_held(controller: &super::InterceptController, seen: &[u64]) -> u64 {
        for _ in 0..200 {
            if let Some(id) = controller
                .pending_ids()
                .into_iter()
                .find(|id| !seen.contains(id))
            {
                return id;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no request was held");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn intercept_shows_held_body_and_forwards_edits_faithfully() {
        use super::InterceptDecision;

        // Echo upstream: answers each request with the body it received and
        // hands the raw request bytes back for wire assertions.
        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let (wire_sender, mut wire) = tokio::sync::mpsc::unbounded_channel::<String>();
        let upstream_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = upstream.accept().await.expect("upstream accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                let body = loop {
                    let read = socket.read(&mut buffer).await.expect("upstream read");
                    assert!(read > 0, "request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
                    if request.len() >= end + 4 + length {
                        break request[end + 4..end + 4 + length].to_vec();
                    }
                };
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                response.extend_from_slice(&body);
                socket
                    .write_all(&response)
                    .await
                    .expect("upstream response");
                wire_sender
                    .send(String::from_utf8_lossy(&request).into_owned())
                    .expect("wire channel");
            }
        });
        let observer = Arc::new(LiveWorkbench::new());
        let controller = observer.intercept_controller();
        controller.set_enabled(true);
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:intercept-edit-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: Some(Arc::clone(&controller)),
                    capture_browser_listener: false,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        let proxy = handle.local_addr();
        let authority = upstream_address.to_string();
        let original = br#"{"name":"original-item"}"#;
        let request = |body: &[u8]| {
            let mut bytes = format!(
                "POST http://{authority}/items HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            bytes.extend_from_slice(body);
            bytes
        };
        let mut seen = Vec::new();

        // Forward modified: the held body is visible before any decision, and
        // the edit (longer body + added header) reaches the target as edited.
        let client = {
            let bytes = request(original);
            tokio::spawn(async move { send_http_request(proxy, &bytes).await })
        };
        let held = next_held(&controller, &seen).await;
        seen.push(held);
        let detail = observer.flow(held).expect("held flow");
        assert_eq!(detail.request_body.as_deref(), Some(&original[..]));
        // The held request shows its header names as the client sent them,
        // not hyper's lowercase map.
        let names: Vec<&str> = detail
            .request_headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert!(names.contains(&"Content-Type"), "{names:?}");
        assert!(names.contains(&"Content-Length"), "{names:?}");
        let edited = br#"{"name":"edited-item","extra":true}"#;
        let mut headers = detail.request_headers.clone();
        headers.push(("X-Edited".to_owned(), "Yes".to_owned()));
        assert!(controller.decide(
            held,
            InterceptDecision::ForwardModified {
                method: "POST".to_owned(),
                url: None,
                headers,
                body: edited.to_vec(),
            },
        ));
        let response = client.await.expect("client task").expect("client response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with(std::str::from_utf8(edited).expect("utf8")));
        let on_wire = wire.recv().await.expect("modified request on the wire");
        assert!(on_wire.contains("\r\nX-Edited: Yes\r\n"), "{on_wire}");
        // Edited, the names keep that case on the wire (as Resend sends them).
        assert!(
            on_wire.contains("\r\nContent-Type: application/json\r\n"),
            "{on_wire}"
        );
        assert!(
            on_wire.contains(&format!("\r\nContent-Length: {}\r\n", edited.len())),
            "{on_wire}"
        );
        assert!(on_wire.ends_with(std::str::from_utf8(edited).expect("utf8")));
        let recorded = observer.flow(held).expect("edited flow");
        assert_eq!(recorded.request_body.as_deref(), Some(&edited[..]));
        assert!(
            recorded
                .request_headers
                .iter()
                .any(|(name, _)| name == "X-Edited")
        );
        assert_eq!(recorded.summary.status, Some(200));

        // Plain forward: the original request, body intact.
        let client = {
            let bytes = request(original);
            tokio::spawn(async move { send_http_request(proxy, &bytes).await })
        };
        let held = next_held(&controller, &seen).await;
        seen.push(held);
        assert!(controller.decide(held, InterceptDecision::Forward));
        let response = client.await.expect("client task").expect("client response");
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let on_wire = wire.recv().await.expect("original request on the wire");
        assert!(on_wire.ends_with(std::str::from_utf8(original).expect("utf8")));
        let recorded = observer.flow(held).expect("forwarded flow");
        assert_eq!(recorded.request_body.as_deref(), Some(&original[..]));

        // Drop: the client gets 403 and nothing reaches the target.
        let client = {
            let bytes = request(original);
            tokio::spawn(async move { send_http_request(proxy, &bytes).await })
        };
        let held = next_held(&controller, &seen).await;
        assert!(controller.decide(held, InterceptDecision::Drop));
        let response = client.await.expect("client task").expect("client response");
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403"));

        handle.shutdown().await.expect("proxy shutdown");
        upstream_task.await.expect("upstream task");
        assert!(
            wire.try_recv().is_err(),
            "a dropped request reached the target"
        );
    }

    #[test]
    fn intercept_edit_recomputes_framing_and_rejects_malformed_edits() {
        use hudsucker::{Body, hyper::Request};

        let held = Request::builder()
            .uri("http://api.example.test/items")
            .body(Body::empty())
            .expect("request");
        let headers = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>()
        };
        // Order and case kept; stale length recomputed in place; chunked
        // framing dropped (the body is sent whole); missing Host derived first.
        let edit = super::edited_request(
            &held,
            "PUT",
            None,
            &headers(&[
                ("X-First", "1"),
                ("Content-Length", "24"),
                ("Transfer-Encoding", "chunked"),
                ("content-type", "text/plain"),
            ]),
            b"hello".to_vec(),
        )
        .expect("valid edit");
        assert_eq!(edit.parts.method, "PUT");
        assert_eq!(
            edit.headers,
            headers(&[
                ("Host", "api.example.test"),
                ("X-First", "1"),
                ("Content-Length", "5"),
                ("content-type", "text/plain"),
            ])
        );
        // A body without framing gains Content-Length; an edited URL applies.
        let edit = super::edited_request(
            &held,
            "POST",
            Some("https://other.example.test:8443/v2?q=1"),
            &headers(&[("Host", "kept.example.test")]),
            b"{}".to_vec(),
        )
        .expect("valid edit");
        assert_eq!(edit.parts.uri, "https://other.example.test:8443/v2?q=1");
        assert_eq!(
            edit.headers,
            headers(&[("Host", "kept.example.test"), ("Content-Length", "2")])
        );
        // Malformed edits are rejected without touching the held request.
        for (method, url, pairs) in [
            ("GE T", None, vec![]),
            ("GET", Some("/relative"), vec![]),
            ("GET", None, vec![("Bad Name", "x")]),
            ("GET", None, vec![("X-Injected", "a\r\nEvil: 1")]),
        ] {
            assert!(
                super::edited_request(&held, method, url, &headers(&pairs), Vec::new()).is_err()
            );
        }
        assert_eq!(held.method(), "GET");
    }

    #[tokio::test]
    async fn authored_host_reaches_the_wire_while_connecting_to_the_url_authority() {
        use crate::resend::{ProxyResendSender, ResendSender};
        use apiaxess_workbench_store::ResendRequest;

        let upstream = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let upstream_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.expect("upstream accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = socket.read(&mut buffer).await.expect("upstream read");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 Fine Thanks\r\nX-Upstream-Case: Kept\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .expect("upstream response");
            String::from_utf8_lossy(&request).into_owned()
        });
        let store_path = env::temp_dir().join(format!(
            "apiaxess-proxy-host-override-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = Arc::new(
            TrafficStore::open(&store_path, "session:host-override-test").expect("traffic store"),
        );
        let observer = Arc::new(LiveWorkbench::new());
        observer.attach_store(Arc::clone(&store));
        let ca = SessionCa::generate().expect("CA");
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:host-override-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: ca.clone(),
                    intercept: None,
                    capture_browser_listener: false,
                },
                observer.clone(),
            )
            .await
            .expect("proxy starts");
        let sender = ProxyResendSender::new(handle.local_addr(), ca);
        let send = sender.send(ResendRequest {
            method: "GET".to_owned(),
            url: format!("http://{upstream_address}/vhost"),
            headers: vec![
                ("X-Zeta".to_owned(), "first".to_owned()),
                ("Host".to_owned(), "evil.test".to_owned()),
                ("accept".to_owned(), "*/*".to_owned()),
                ("X-MiXeD-Case".to_owned(), "v".to_owned()),
            ],
            body: None,
        });
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), send)
            .await
            .expect("send completes")
            .expect("send");
        assert_eq!(response.status, 200);
        let wire = upstream_task.await.expect("upstream task");
        handle.shutdown().await.expect("proxy shutdown");
        // Connected to the URL authority, yet the request went out byte-for-byte
        // as authored: order, case and Host verbatim, nothing added, and no
        // private marker reached the target.
        assert_eq!(
            wire,
            "GET /vhost HTTP/1.1\r\nX-Zeta: first\r\nHost: evil.test\r\naccept: */*\r\nX-MiXeD-Case: v\r\n\r\n"
        );
        // The upstream status line and header case come back to the sender.
        assert_eq!(response.http_version.as_deref(), Some("HTTP/1.1"));
        assert_eq!(response.reason.as_deref(), Some("Fine Thanks"));
        assert_eq!(response.headers[0].0, "X-Upstream-Case");
        assert!(
            response
                .headers
                .iter()
                .all(|(name, _)| !name.starts_with("x-apiaxess"))
        );
        assert_eq!(response.body.as_deref(), Some(&b"ok"[..]));
        let summaries = store.summaries().expect("traffic summaries");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].status, Some(200));
        drop(observer);
        drop(store);
        fs::remove_dir_all(store_path).expect("remove test traffic store");
    }

    #[tokio::test]
    async fn embedded_listener_binds_and_closes_with_its_handle() {
        let handle = HudsuckerBackend
            .start(
                ProxyConfig {
                    session_id: "session:proxy-test".to_owned(),
                    bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    ca: SessionCa::generate().expect("CA"),
                    intercept: None,
                    capture_browser_listener: false,
                },
                Arc::new(NoopObserver),
            )
            .await
            .expect("proxy starts");
        let address = handle.local_addr();
        handle.shutdown().await.expect("proxy shuts down");
        assert!(tokio::net::TcpListener::bind(address).await.is_ok());
    }

    #[tokio::test]
    async fn hudsucker_is_the_only_backend_kind() {
        assert_eq!(HudsuckerBackend.kind(), super::BackendKind::Hudsucker);
        assert!(HudsuckerBackend.health().await.hudsucker_available);
    }

    #[tokio::test]
    async fn live_intercept_decision_is_per_flow_and_reliable() {
        let controller = std::sync::Arc::new(super::InterceptController::default());
        controller.set_enabled(true);
        let waiting = std::sync::Arc::clone(&controller);
        let task =
            tokio::spawn(async move { waiting.await_decision(42, Some("api.example.com")).await });
        tokio::task::yield_now().await;
        assert_eq!(controller.pending_ids(), vec![42]);
        assert!(controller.decide(42, super::InterceptDecision::Forward));
        assert_eq!(
            task.await.expect("decision task"),
            super::InterceptDecision::Forward
        );
        assert!(!controller.decide(42, super::InterceptDecision::Drop));
    }

    #[tokio::test]
    async fn live_intercept_timeout_is_explicit() {
        let controller = super::InterceptController::default();
        controller.set_enabled(true);
        controller.set_timeout(std::time::Duration::from_millis(100));
        assert_eq!(
            controller.await_decision(7, Some("api.example.com")).await,
            super::InterceptDecision::Timeout
        );
        assert!(controller.pending_ids().is_empty());
    }
}
