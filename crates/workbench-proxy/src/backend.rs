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
    UPSTREAM_HEADERS_MARKER, UPSTREAM_STATUS_MARKER, WIRE_HEADERS_MARKER, decode_header_list,
    encode_header_list,
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
fn take_wire_headers(req: &mut Request<Body>) -> Option<Vec<(String, String)>> {
    let value = req.headers_mut().remove(WIRE_HEADERS_MARKER)?;
    let list = decode_header_list(value.as_bytes())?;
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

/// The header list to write after an intercept edit replaced the headers:
/// the edited map in its order, keeping authored case for names that survive.
fn wire_headers_after_edit(
    authored: &[(String, String)],
    edited: &hudsucker::hyper::HeaderMap,
) -> Vec<(String, String)> {
    edited
        .iter()
        .map(|(name, value)| {
            let cased = authored
                .iter()
                .find(|(original, _)| original.eq_ignore_ascii_case(name.as_str()))
                .map_or_else(
                    || name.as_str().to_owned(),
                    |(original, _)| original.clone(),
                );
            (
                cased,
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
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
}

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
    /// Replace request metadata/body before forwarding through the backend.
    ForwardModified {
        /// Replacement HTTP method.
        method: String,
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

    /// Sets the maximum time a paused request may wait for a UI decision.
    pub fn set_timeout(&self, timeout: Duration) {
        if let Ok(mut current) = self.timeout.lock() {
            *current = timeout.max(Duration::from_millis(100));
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

    async fn await_decision(&self, flow_id: u64, host: Option<&str>) -> InterceptDecision {
        if !self.is_enabled() || !self.matches_host(host) {
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
    /// A WebSocket message was observed while being forwarded.
    WebSocketMessage {
        /// Direction of the message.
        direction: WebSocketDirection,
        /// Message kind, such as text, binary, ping, or close.
        kind: String,
        /// Payload size; the payload is not retained in Phase 2.1.
        payload_bytes: usize,
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

/// Direction of an observed WebSocket message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
            let (stop_sender, stop_receiver) = oneshot::channel();
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
            let proxy = hudsucker::Proxy::builder()
                .with_listener(listener)
                .with_ca(config.ca)
                .with_http_connector(upstream_connector)
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
            Ok(ProxyHandle {
                local_addr,
                backend: BackendKind::Hudsucker,
                stop_sender: Some(stop_sender),
                task: Some(task),
            })
        })
    }
}

/// A running proxy listener. Dropping it is not considered a clean lifecycle
/// transition; callers should call `shutdown` when the owning session closes.
pub struct ProxyHandle {
    pub(crate) local_addr: SocketAddr,
    pub(crate) backend: BackendKind,
    pub(crate) stop_sender: Option<oneshot::Sender<()>>,
    pub(crate) task: Option<JoinHandle<Result<(), Diagnostic>>>,
}

impl std::fmt::Debug for ProxyHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyHandle")
            .field("local_addr", &self.local_addr)
            .field("backend", &self.backend)
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

    /// Gracefully stops the listener and waits for the backend task.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic if the backend task fails or cannot be joined.
    pub async fn shutdown(mut self) -> Result<(), Diagnostic> {
        if let Some(stop_sender) = self.stop_sender.take() {
            let _ = stop_sender.send(());
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
    }
}

/// Session-owned facade. Its only durable relationship is the caller's
/// active session; the listener and CA remain process memory.
pub struct ProxyCore {
    backend: Box<dyn ProxyBackend>,
    handle: Option<ProxyHandle>,
}

impl std::fmt::Debug for ProxyCore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCore")
            .field("backend", &self.backend.kind())
            .field("running", &self.handle.is_some())
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
        }
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
        let handle = self
            .backend
            .start(
                ProxyConfig {
                    session_id: session.id().as_str().to_owned(),
                    bind_addr,
                    ca,
                    intercept,
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
        }
    }

    fn with_raw_upstream_tls(mut self, tls: Arc<hudsucker::rustls::ClientConfig>) -> Self {
        self.raw_upstream_tls = Some(tls);
        self
    }

    fn observe_request(&self, req: &Request<Body>, origin: FlowOrigin) -> u64 {
        let flow_id = self.observer.allocate_flow_id();
        self.observer.observe(FlowEvent::Request {
            flow_id,
            method: req.method().to_string(),
            uri: req.uri().to_string(),
            version: format!("{:?}", req.version()),
            headers: headers(req.headers()),
            origin,
        });
        flow_id
    }
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
        // Applied before observation so the recorded request shows the headers
        // that actually go on the wire.
        let mut wire_headers = take_wire_headers(&mut req);
        // A CONNECT reaching the MITM request handler over HTTP/2 is an RFC 8441
        // extended-CONNECT (WebSocket-over-h2); ordinary CONNECT tunnels are
        // handled below this layer. Surface the known limitation as a signal.
        if req.method() == Method::CONNECT && req.version() == Version::HTTP_2 {
            self.observer
                .observe(FlowEvent::Diagnostic(rfc8441_diagnostic()));
        }
        let flow_id = self.observe_request(&req, origin);
        // Record on this per-request handler clone so `handle_response` correlates
        // to exactly this request — never to another concurrent stream on the same
        // connection or another client sharing transport attributes.
        self.current_flow_id = Some(flow_id);
        if let Some(intercept) = &self.intercept {
            intercept.wait().await;
            match intercept.await_decision(flow_id, req.uri().host()).await {
                InterceptDecision::Forward => {}
                InterceptDecision::ForwardModified {
                    method,
                    headers: replacement_headers,
                    body,
                } => {
                    if let Err(error) =
                        modify_request(&mut req, &method, &replacement_headers, body)
                    {
                        self.observer
                            .observe(FlowEvent::Diagnostic(malformed_edit_diagnostic(
                                flow_id, &error,
                            )));
                    }
                    if let Some(authored) = &wire_headers {
                        wire_headers = Some(wire_headers_after_edit(authored, req.headers()));
                    }
                }
                InterceptDecision::Drop => {
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
        let body = capture_body(
            body,
            flow_id,
            BodyDirection::Request,
            Arc::clone(&self.observer),
        );
        if let (Some(wire_headers), Some(tls)) = (wire_headers, self.raw_upstream_tls.clone()) {
            if parts.method != Method::CONNECT {
                let response = self
                    .forward_raw(ctx, tls, &parts, &wire_headers, body)
                    .await;
                return RequestOrResponse::Response(response);
            }
        }
        RequestOrResponse::Request(Request::from_parts(parts, body))
    }

    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
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
    /// Writes a workbench send upstream byte-for-byte and returns the recorded
    /// response, carrying the upstream status line and raw header list back to
    /// the sender in private markers (added after recording, so never stored).
    async fn forward_raw(
        &mut self,
        ctx: &HttpContext,
        tls: Arc<hudsucker::rustls::ClientConfig>,
        parts: &hudsucker::hyper::http::request::Parts,
        wire_headers: &[(String, String)],
        body: Body,
    ) -> Response<Body> {
        let body = match http_body_util::BodyExt::collect(body).await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => return self.upstream_failure(ctx, format!("read request body: {error}")),
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
            Err(error) => return self.upstream_failure(ctx, error),
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
            return self.upstream_failure(ctx, format!("unrepresentable status {}", raw.status));
        };
        let mut response = self.handle_response(ctx, response).await;
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

    /// Records an upstream failure diagnostic and answers `502`.
    fn upstream_failure(&self, ctx: &HttpContext, chain: String) -> Response<Body> {
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
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::empty())
            .expect("static proxy error response is valid")
    }
}

fn modify_request(
    request: &mut Request<Body>,
    method: &str,
    replacement_headers: &[(String, String)],
    body: Vec<u8>,
) -> Result<(), String> {
    *request.method_mut() = method
        .parse()
        .map_err(|error| format!("invalid HTTP method: {error}"))?;
    let headers = request.headers_mut();
    headers.clear();
    for (name, value) in replacement_headers {
        let name: hudsucker::hyper::header::HeaderName = name
            .parse()
            .map_err(|error| format!("invalid header name: {error}"))?;
        let value: hudsucker::hyper::header::HeaderValue = value
            .parse()
            .map_err(|error| format!("invalid header value: {error}"))?;
        headers.append(name, value);
    }
    *request.body_mut() = Body::from(body);
    Ok(())
}

fn capture_body(
    body: Body,
    flow_id: u64,
    direction: BodyDirection,
    observer: Arc<dyn FlowObserver>,
) -> Body {
    // The durable store owns retention policy. Keep the observer capture limit
    // aligned with its 64 MiB per-body safety limit instead of the old 2.2
    // in-memory 1 MiB preview limit.
    const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
    let retained = Arc::new(Mutex::new(0_usize));
    let stream = BodyStream::new(body).map_ok(move |frame| {
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

impl WebSocketHandler for ObserveHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let (direction, kind) = match ctx {
            WebSocketContext::ClientToServer { .. } => {
                (WebSocketDirection::ClientToServer, "client_to_server")
            }
            WebSocketContext::ServerToClient { .. } => {
                (WebSocketDirection::ServerToClient, "server_to_client")
            }
        };
        let message_kind = match &message {
            Message::Text(_) => "text",
            Message::Binary(_) => "binary",
            Message::Ping(_) => "ping",
            Message::Pong(_) => "pong",
            Message::Close(_) => "close",
            Message::Frame(_) => "frame",
        };
        self.observer.observe(FlowEvent::WebSocketMessage {
            direction,
            kind: format!("{kind}:{message_kind}"),
            payload_bytes: message.len(),
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
