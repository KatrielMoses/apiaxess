//! Manual request resend backed by the active session proxy and store.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
    time::Instant,
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_session::{
    ActionDescriptor, ActionOutcome, ActionRecordInput, ActionTarget, AuditActor, EngagementScope,
    ScopeDisposition, Session,
};
use apiaxess_workbench_store::{
    FlowOrigin, RedirectHop, RedirectMode, RedirectPolicy, ResendContext, ResendRequest,
    ResendResponse, ResendRevision, RetryPolicy, TrafficStore,
};
use getrandom::fill;
use reqwest::header::{HeaderName, HeaderValue};

use crate::backend::ORIGIN_MARKER_HEADER;
use crate::raw_http::{
    UPSTREAM_HEADERS_MARKER, UPSTREAM_STATUS_MARKER, WIRE_HEADERS_MARKER, decode_header_list,
    encode_header_list,
};
use crate::{FlowDetail, SessionCa};

/// A host-in-scope predicate supplied by the caller (the fuzzer) so the send
/// path can resolve `RedirectMode::InScope` without owning the engagement scope.
pub type ScopePredicate = Arc<dyn Fn(&str, Option<u16>) -> bool + Send + Sync>;

/// Per-send attack settings (WS4): redirects, retries, connection handling.
/// Defaults reproduce the historical behavior (follow up to 10, no retries).
#[derive(Clone)]
pub struct SendOptions {
    /// Redirect-following policy.
    pub redirect: RedirectPolicy,
    /// Retry policy for transient failures/timeouts.
    pub retry: RetryPolicy,
    /// Whether to send `Connection: close`.
    pub connection_close: bool,
    /// Whether to recompute `Content-Length` (drop the template value).
    pub update_content_length: bool,
    /// In-scope predicate for `RedirectMode::InScope`; absent = treat as no-follow.
    pub in_scope: Option<ScopePredicate>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            redirect: RedirectPolicy::default(),
            retry: RetryPolicy::default(),
            connection_close: false,
            update_content_length: true,
            in_scope: None,
        }
    }
}

/// The full outcome of a policy-aware send: the final response (or the failure
/// diagnostic), the followed redirect chain, and how many retries it took.
pub struct SendOutcome {
    /// Final response, when a request completed.
    pub response: Option<ResendResponse>,
    /// Failure diagnostic, when the final attempt failed.
    pub diagnostic: Option<Diagnostic>,
    /// The redirect hops actually followed (empty when none).
    pub redirect_chain: Vec<RedirectHop>,
    /// Retries performed before the recorded outcome.
    pub retry_count: u32,
}

impl SendOutcome {
    /// Wraps a plain send result (no redirects/retries) as an outcome.
    fn plain(result: Result<ResendResponse, Diagnostic>) -> Self {
        match result {
            Ok(response) => Self {
                response: Some(response),
                diagnostic: None,
                redirect_chain: Vec::new(),
                retry_count: 0,
            },
            Err(diagnostic) => Self {
                response: None,
                diagnostic: Some(diagnostic),
                redirect_chain: Vec::new(),
                retry_count: 0,
            },
        }
    }
}

/// Result returned after a resend send, including any non-fatal warnings.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResendSendResult {
    /// Updated context containing the appended revision.
    pub context: ResendContext,
    /// The revision created by this send.
    pub revision: ResendRevision,
    /// Warnings or send diagnostics shown alongside the revision.
    pub diagnostics: Vec<Diagnostic>,
}

/// Request transport used by the resend. Implementations must send through
/// the session's routed proxy path rather than silently falling back to a
/// direct connection.
pub trait ResendSender: Send + Sync {
    /// Sends one fully edited request.
    fn send(
        &self,
        request: ResendRequest,
    ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>>;

    /// Sends one request honoring attack settings (redirects, retries,
    /// connection handling), returning the full outcome. The default ignores the
    /// options and performs a single plain send, so test doubles need only
    /// implement [`ResendSender::send`].
    fn send_with_options(
        &self,
        request: ResendRequest,
        _options: SendOptions,
    ) -> crate::backend::BackendFuture<Result<SendOutcome, Diagnostic>> {
        // `send` returns a 'static future; capture it (not `self`) in the block.
        let future = self.send(request);
        Box::pin(async move { Ok(SendOutcome::plain(future.await)) })
    }
}

/// HTTP client that sends through an already-running `ProxyHandle` listener.
#[derive(Clone, Debug)]
pub struct ProxyResendSender {
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
}

impl ProxyResendSender {
    /// Creates a sender bound to the session proxy listener and CA.
    #[must_use]
    pub const fn new(proxy_addr: std::net::SocketAddr, ca: SessionCa) -> Self {
        Self { proxy_addr, ca }
    }
}

impl ResendSender for ProxyResendSender {
    fn send(
        &self,
        request: ResendRequest,
    ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
        let proxy_addr = self.proxy_addr;
        let ca = self.ca.clone();
        Box::pin(async move { send_through_proxy(proxy_addr, ca, request).await })
    }

    fn send_with_options(
        &self,
        request: ResendRequest,
        options: SendOptions,
    ) -> crate::backend::BackendFuture<Result<SendOutcome, Diagnostic>> {
        let proxy_addr = self.proxy_addr;
        let ca = self.ca.clone();
        Box::pin(async move { Ok(send_with_policy(proxy_addr, ca, request, &options).await) })
    }
}

/// A [`ResendSender`] decorator that stamps every outgoing request with the
/// origin marker header. Both the Resend and Fuzz tools send through the same
/// session proxy, which records every request as a flow; the marker lets the
/// proxy tag the resulting flow's [`FlowOrigin`] (and strip the marker before
/// forwarding), so tool-synthesized traffic stays out of the Live list and the
/// fused API surface while remaining recorded for the Resend history / Fuzz
/// results views. The marker is added only to the request handed to the
/// transport; callers keep their own un-marked copy for their records.
#[derive(Clone)]
pub struct OriginTaggingSender {
    inner: Arc<dyn ResendSender>,
    origin: FlowOrigin,
}

impl OriginTaggingSender {
    /// Wraps `inner`, stamping every request it sends with `origin`.
    #[must_use]
    pub fn new(inner: Arc<dyn ResendSender>, origin: FlowOrigin) -> Self {
        Self { inner, origin }
    }
}

/// Replaces any inherited origin marker with an authoritative single value so a
/// re-sent (e.g. redirected) request carries exactly one, correct tag.
fn stamp_origin(mut request: ResendRequest, origin: FlowOrigin) -> ResendRequest {
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER));
    request.headers.push((
        ORIGIN_MARKER_HEADER.to_owned(),
        origin.as_db_str().to_owned(),
    ));
    request
}

impl ResendSender for OriginTaggingSender {
    fn send(
        &self,
        request: ResendRequest,
    ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
        self.inner.send(stamp_origin(request, self.origin))
    }

    fn send_with_options(
        &self,
        request: ResendRequest,
        options: SendOptions,
    ) -> crate::backend::BackendFuture<Result<SendOutcome, Diagnostic>> {
        self.inner
            .send_with_options(stamp_origin(request, self.origin), options)
    }
}

/// Sends a request under the attack settings: retry the redirect-following send
/// up to `max_retries` on transport failure/timeout, pausing between attempts.
async fn send_with_policy(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: ResendRequest,
    options: &SendOptions,
) -> SendOutcome {
    let mut retry_count = 0;
    loop {
        match send_following_redirects(proxy_addr, ca.clone(), request.clone(), options).await {
            Ok((response, redirect_chain)) => {
                return SendOutcome {
                    response: Some(response),
                    diagnostic: None,
                    redirect_chain,
                    retry_count,
                };
            }
            Err(diagnostic) => {
                if retry_count < options.retry.max_retries {
                    retry_count += 1;
                    if options.retry.pause_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            options.retry.pause_ms,
                        ))
                        .await;
                    }
                    continue;
                }
                return SendOutcome {
                    response: None,
                    diagnostic: Some(diagnostic),
                    redirect_chain: Vec::new(),
                    retry_count,
                };
            }
        }
    }
}

/// Sends once and follows redirects per policy, recording each followed hop.
/// Returns the final (or first non-followed) response plus the followed chain.
async fn send_following_redirects(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: ResendRequest,
    options: &SendOptions,
) -> Result<(ResendResponse, Vec<RedirectHop>), Diagnostic> {
    let original_host = request_host(&request.url);
    let mut current = apply_connection_close(request, options.connection_close);
    let mut chain = Vec::new();
    let mut hops: u8 = 0;
    loop {
        let response = send_raw(
            proxy_addr,
            ca.clone(),
            current.clone(),
            options.update_content_length,
        )
        .await?;
        if !is_redirect_status(response.status) {
            return Ok((response, chain));
        }
        let Some(location) = response_header(&response, "location") else {
            return Ok((response, chain));
        };
        let target = resolve_redirect_url(&current.url, &location);
        let follow = should_follow_redirect(
            options.redirect,
            &original_host,
            &target,
            options.in_scope.as_ref(),
        );
        if !follow || hops >= options.redirect.max_hops {
            return Ok((response, chain));
        }
        chain.push(RedirectHop {
            status: response.status,
            location: target.clone(),
        });
        hops += 1;
        current = next_redirect_request(
            &current,
            &response,
            &target,
            options.redirect.process_cookies,
        );
    }
}

/// Session-scoped resend contexts and their persistence bridge.
pub struct ResendWorkbench {
    store: RwLock<Option<Arc<TrafficStore>>>,
    sender: RwLock<Option<Arc<dyn ResendSender>>>,
    scope: RwLock<Option<EngagementScope>>,
    contexts: Mutex<BTreeMap<String, ResendContext>>,
}

impl std::fmt::Debug for ResendWorkbench {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResendWorkbench")
            .field("context_count", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Default for ResendWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl ResendWorkbench {
    /// Creates an empty resend surface.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: RwLock::new(None),
            sender: RwLock::new(None),
            scope: RwLock::new(None),
            contexts: Mutex::new(BTreeMap::new()),
        }
    }

    /// Attaches and hydrates the session's durable store.
    ///
    /// # Errors
    ///
    /// Returns the stable history diagnostic if persisted contexts cannot be
    /// loaded.
    pub fn attach_store(&self, store: Arc<TrafficStore>) -> Result<(), Diagnostic> {
        let contexts = store.resend_contexts()?;
        if let Ok(mut current) = self.store.write() {
            *current = Some(store);
        }
        if let Ok(mut current) = self.contexts.lock() {
            current.clear();
            current.extend(
                contexts
                    .into_iter()
                    .map(|context| (context.id.clone(), context)),
            );
        }
        Ok(())
    }

    /// Attaches the sender for the active routed proxy listener.
    pub fn attach_sender(&self, sender: Arc<dyn ResendSender>) {
        if let Ok(mut current) = self.sender.write() {
            *current = Some(sender);
        }
    }

    /// Sets the engagement scope used for resend warnings and records.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        if let Ok(mut current) = self.scope.write() {
            *current = Some(scope);
        }
    }

    /// Lists independent resend contexts.
    #[must_use]
    pub fn list(&self) -> Vec<ResendContext> {
        self.contexts
            .lock()
            .map(|contexts| contexts.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Reads one resend context.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<ResendContext> {
        self.contexts
            .lock()
            .ok()
            .and_then(|contexts| contexts.get(id).cloned())
    }

    /// Removes one resend context from the queue and the durable store.
    ///
    /// # Errors
    ///
    /// Returns a history diagnostic when the durable store cannot be written.
    pub fn remove(&self, id: &str) -> Result<(), Diagnostic> {
        if let Ok(mut contexts) = self.contexts.lock() {
            contexts.remove(id);
        }
        if let Some(store) = self.store.read().ok().and_then(|store| store.clone()) {
            store.remove_resend(id)?;
        }
        Ok(())
    }

    /// Creates a context from a captured request.
    ///
    /// # Errors
    ///
    /// Returns a history diagnostic when the initial request cannot be
    /// persisted.
    pub fn create_from_flow(&self, flow: &FlowDetail) -> Result<ResendContext, Diagnostic> {
        let url = flow.summary.url.clone().ok_or_else(|| {
            request_diagnostic(
                "create",
                "captured flow has no exact request URL; refresh the flow and retry",
            )
        })?;
        let request = ResendRequest {
            method: flow
                .summary
                .method
                .clone()
                .unwrap_or_else(|| "GET".to_owned()),
            url,
            headers: strip_proxy_artifact_headers(&flow.request_headers),
            body: flow.request_body.clone(),
        };
        self.create(request, Some(flow.summary.id))
    }

    /// Creates an independent context from an explicit request.
    ///
    /// # Errors
    ///
    /// Returns a history diagnostic when the request is malformed or cannot
    /// be persisted.
    pub fn create(
        &self,
        request: ResendRequest,
        source_flow_id: Option<u64>,
    ) -> Result<ResendContext, Diagnostic> {
        validate_request(&request)?;
        let context = ResendContext {
            id: new_context_id(),
            source_flow_id,
            created_at: chrono::Utc::now(),
            current: request,
            history: Vec::new(),
        };
        self.persist(&context)?;
        if let Ok(mut contexts) = self.contexts.lock() {
            contexts.insert(context.id.clone(), context.clone());
        }
        Ok(context)
    }

    /// Replaces the current editable request without changing history.
    ///
    /// # Errors
    ///
    /// Returns a request diagnostic when the edited request is malformed, or
    /// a history diagnostic when the updated context cannot be saved.
    pub fn update_request(
        &self,
        id: &str,
        request: ResendRequest,
    ) -> Result<ResendContext, Diagnostic> {
        validate_request(&request)?;
        let mut context = self
            .get(id)
            .ok_or_else(|| request_diagnostic("edit", "context not found"))?;
        context.current = request;
        self.persist(&context)?;
        self.replace_context(context.clone());
        Ok(context)
    }

    /// Loads a prior revision into the editable current request.
    ///
    /// # Errors
    ///
    /// Returns a request diagnostic when the context or revision is absent,
    /// or a history diagnostic when the re-derived state cannot be saved.
    pub fn derive(&self, id: &str, revision: u64) -> Result<ResendContext, Diagnostic> {
        let mut context = self
            .get(id)
            .ok_or_else(|| request_diagnostic("derive", "context not found"))?;
        let request = context
            .history
            .iter()
            .find(|entry| entry.revision == revision)
            .map(|entry| entry.request.clone())
            .ok_or_else(|| request_diagnostic("derive", "history revision not found"))?;
        context.current = request;
        self.persist(&context)?;
        self.replace_context(context.clone());
        Ok(context)
    }

    /// Sends the current request and appends the result as one linear revision.
    ///
    /// # Errors
    ///
    /// Returns a history diagnostic when the revision cannot be persisted.
    /// Transport and malformed-request failures are retained in the returned
    /// revision and diagnostics so the failed attempt is never hidden.
    pub async fn send(&self, id: &str) -> Result<ResendSendResult, Diagnostic> {
        let mut context = self
            .get(id)
            .ok_or_else(|| request_diagnostic("send", "context not found"))?;
        validate_request(&context.current)?;
        let scope = self.classify_scope(&context.current.url);
        let mut diagnostics = Vec::new();
        if scope == ScopeDisposition::OutsideDeclaredScope {
            diagnostics.push(outside_scope_diagnostic(&context.current.url));
        }
        let request = context.current.clone();
        let started = Instant::now();
        let result = match self.sender.read().ok().and_then(|sender| sender.clone()) {
            Some(sender) => sender.send(request.clone()).await,
            None => Err(transport_unavailable()),
        };
        let (response, diagnostic) = match result {
            Ok(response) => (Some(response), None),
            Err(diagnostic) => {
                diagnostics.push(diagnostic.clone());
                (None, Some(diagnostic))
            }
        };
        let revision = ResendRevision {
            revision: u64::try_from(context.history.len() + 1).unwrap_or(u64::MAX),
            sent_at: chrono::Utc::now(),
            request,
            response: response.map(|mut response| {
                response.duration_ms =
                    u64::try_from(started.elapsed().as_millis().min(u128::from(u64::MAX)))
                        .unwrap_or(u64::MAX);
                response
            }),
            diagnostic,
            scope,
        };
        context.history.push(revision.clone());
        self.persist(&context)?;
        self.replace_context(context.clone());
        Ok(ResendSendResult {
            context,
            revision,
            diagnostics,
        })
    }

    /// Sends and records the attempt in the canonical session audit trail.
    ///
    /// # Errors
    ///
    /// Returns a resend diagnostic for persistence/transport failures or a
    /// session diagnostic if the audit record cannot be appended.
    pub async fn send_in_session(
        &self,
        id: &str,
        session: &mut Session,
    ) -> Result<ResendSendResult, Diagnostic> {
        let result = self.send(id).await?;
        let (host, port) = url_target(&result.revision.request.url)
            .unwrap_or_else(|| ("unknown".to_owned(), None));
        let target = ActionTarget::Network { host, port };
        let outcome = if result.revision.diagnostic.is_some() {
            ActionOutcome::Failed
        } else {
            ActionOutcome::Completed
        };
        session.record_action(ActionRecordInput {
            id: format!("resend:{}:{}", id, result.revision.revision),
            occurred_at: result.revision.sent_at,
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.resend.send".to_owned(),
                summary: format!("Sent resend revision {}", result.revision.revision),
            },
            target,
            outcome,
            diagnostics: result.diagnostics.clone(),
        })?;
        Ok(result)
    }

    fn persist(&self, context: &ResendContext) -> Result<(), Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(
                catalogue::PROXY_RESEND_HISTORY_FAILED.instantiate(DiagnosticContext::new())
            );
        };
        store.upsert_resend(context)
    }

    fn replace_context(&self, context: ResendContext) {
        if let Ok(mut contexts) = self.contexts.lock() {
            contexts.insert(context.id.clone(), context);
        }
    }

    fn classify_scope(&self, url: &str) -> ScopeDisposition {
        let Some((host, port)) = url_target(url) else {
            return ScopeDisposition::Undetermined;
        };
        let Ok(scope) = self.scope.read() else {
            return ScopeDisposition::Undetermined;
        };
        scope
            .as_ref()
            .map_or(ScopeDisposition::Undetermined, |scope| {
                scope
                    .assess(&ActionTarget::Network { host, port })
                    .disposition
            })
    }
}

/// The plain resend path: follows redirects (up to 10, like the historical
/// reqwest default) and recomputes Content-Length. Following is done here, hop
/// by hop, so every hop is written byte-faithfully with its own header list.
async fn send_through_proxy(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: ResendRequest,
) -> Result<ResendResponse, Diagnostic> {
    let options = SendOptions {
        redirect: RedirectPolicy {
            mode: RedirectMode::Always,
            process_cookies: false,
            max_hops: 10,
        },
        ..SendOptions::default()
    };
    send_following_redirects(proxy_addr, ca, request, &options)
        .await
        .map(|(response, _)| response)
}

/// One raw request with no client-side redirect following (the Fuzzer follows
/// manually, per its policy), honoring the Content-Length toggle.
async fn send_raw(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: ResendRequest,
    update_content_length: bool,
) -> Result<ResendResponse, Diagnostic> {
    send_core(proxy_addr, ca, request, update_content_length).await
}

/// Sends one request through the session proxy with no redirect following.
///
/// The request travels to the proxy with its authored header list in a
/// private marker; the proxy writes exactly that list upstream (order, case,
/// `Host`) and returns the upstream status line and header list the same way.
async fn send_core(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: ResendRequest,
    update_content_length: bool,
) -> Result<ResendResponse, Diagnostic> {
    validate_request(&request)?;
    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}"))
        .map_err(|error| request_diagnostic("proxy", &error.to_string()))?;
    let root = reqwest::Certificate::from_pem(ca.root_certificate_pem().as_bytes())
        .map_err(|error| request_diagnostic("ca", &error.to_string()))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(root)
        .http2_adaptive_window(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| request_diagnostic("client", &error.to_string()))?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|error| request_diagnostic("method", &error.to_string()))?;
    let wire_headers = wire_header_list(&request, update_content_length);
    let mut builder = client.request(method, &request.url);
    if let Some((_, origin)) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER))
    {
        builder = builder.header(ORIGIN_MARKER_HEADER, origin);
    }
    builder = builder.header(WIRE_HEADERS_MARKER, encode_header_list(&wire_headers));
    if let Some(body) = request.body {
        builder = builder.body(body);
    }
    let response = builder.send().await.map_err(|error| {
        let mut diagnostic = request_diagnostic("send", &error.to_string());
        if error.is_timeout() {
            // Marked so the Fuzzer can surface a distinct Timeout column rather
            // than lumping timeouts in with other transport errors.
            diagnostic
                .context
                .insert("timeout".to_owned(), DiagnosticValue::Boolean(true));
        }
        diagnostic
    })?;
    let status = response.status().as_u16();
    let (http_version, reason) = response
        .headers()
        .get(UPSTREAM_STATUS_MARKER)
        .and_then(|value| value.to_str().ok())
        .map_or((None, None), parse_status_line);
    let headers = response
        .headers()
        .get(UPSTREAM_HEADERS_MARKER)
        .and_then(|value| decode_header_list(value.as_bytes()))
        .unwrap_or_else(|| {
            response
                .headers()
                .iter()
                .filter(|(name, _)| {
                    *name != UPSTREAM_STATUS_MARKER && *name != UPSTREAM_HEADERS_MARKER
                })
                .map(|(name, value)| {
                    (
                        name.to_string(),
                        value.to_str().unwrap_or("<non-utf8>").to_owned(),
                    )
                })
                .collect()
        });
    let body = response
        .bytes()
        .await
        .map(|body| (!body.is_empty()).then(|| body.to_vec()))
        .map_err(|error| request_diagnostic("response-body", &error.to_string()))?;
    Ok(ResendResponse {
        status,
        headers,
        body,
        duration_ms: 0,
        http_version,
        reason,
    })
}

/// Splits `HTTP/1.1 302 Found` into its version and reason phrase.
fn parse_status_line(line: &str) -> (Option<String>, Option<String>) {
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_owned);
    let _code = parts.next();
    let reason = parts
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_owned);
    (version, reason)
}

/// The exact header list to put on the wire: the authored headers in order and
/// case, minus private control markers. `Host` is added (first) only when the
/// request has none. `Content-Length` is as-sent: with `update_content_length`
/// its value is recomputed in place from the body, and a body with no framing
/// header gets one appended so it is not silently dropped by the target.
fn wire_header_list(request: &ResendRequest, update_content_length: bool) -> Vec<(String, String)> {
    let body_len = request.body.as_ref().map_or(0, Vec::len);
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .filter(|(name, _)| !name.to_ascii_lowercase().starts_with("x-apiaxess-"))
        .map(|(name, value)| {
            if update_content_length && name.eq_ignore_ascii_case("content-length") {
                (name.clone(), body_len.to_string())
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect();
    let has = |headers: &[(String, String)], wanted: &str| {
        headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
    };
    if !has(&headers, "host") {
        if let Some(authority) = url_authority(&request.url) {
            headers.insert(0, ("Host".to_owned(), authority));
        }
    }
    if body_len > 0 && !has(&headers, "content-length") && !has(&headers, "transfer-encoding") {
        headers.push(("Content-Length".to_owned(), body_len.to_string()));
    }
    headers
}

/// `host[:port]` as a client derives `Host` from the URL (default port omitted).
fn url_authority(url: &str) -> Option<String> {
    let parsed = url.parse::<reqwest::Url>().ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

/// Whether a redirect to `target` should be followed under `policy`.
fn should_follow_redirect(
    policy: RedirectPolicy,
    original_host: &str,
    target: &str,
    in_scope: Option<&ScopePredicate>,
) -> bool {
    match policy.mode {
        RedirectMode::Never => false,
        RedirectMode::Always => true,
        RedirectMode::OnSite => request_host(target) == original_host,
        RedirectMode::InScope => {
            let (host, port) = host_and_port(target);
            in_scope.is_some_and(|predicate| predicate(&host, port))
        }
    }
}

/// Whether a status is a redirect the fuzzer's policy may follow.
fn is_redirect_status(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn response_header(response: &ResendResponse, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn request_host(url: &str) -> String {
    url_target(url).map(|(host, _)| host).unwrap_or_default()
}

fn host_and_port(url: &str) -> (String, Option<u16>) {
    url_target(url).unwrap_or_default()
}

/// Sets `Connection: close`, overriding any existing Connection header.
fn apply_connection_close(mut request: ResendRequest, close: bool) -> ResendRequest {
    if close {
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));
        request
            .headers
            .push(("Connection".to_owned(), "close".to_owned()));
    }
    request
}

/// Resolves a redirect `Location` (absolute, protocol-relative, root-relative,
/// or path-relative) against the current request URL.
fn resolve_redirect_url(base: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_owned();
    }
    let scheme = if base.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    let authority = base
        .split_once("://")
        .map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
    if location.starts_with('/') {
        return format!("{scheme}://{authority}{location}");
    }
    // Path-relative: resolve against the base's directory.
    let path = base
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map_or(String::from("/"), |(_, path)| format!("/{path}"));
    let directory = path.rsplit_once('/').map_or("/", |(head, _)| head);
    format!("{scheme}://{authority}{directory}/{location}")
}

/// Builds the next request in a redirect chain, honoring HTTP method semantics
/// (307/308 preserve method+body; 301/302/303 become GET) and, when enabled,
/// carrying cookies forward.
fn next_redirect_request(
    current: &ResendRequest,
    response: &ResendResponse,
    target: &str,
    process_cookies: bool,
) -> ResendRequest {
    let keep_method = matches!(response.status, 307 | 308);
    let method = if keep_method {
        current.method.clone()
    } else {
        "GET".to_owned()
    };
    let body = if keep_method {
        current.body.clone()
    } else {
        None
    };
    let mut headers: Vec<(String, String)> = current
        .headers
        .iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("host")
                && !name.eq_ignore_ascii_case("content-length")
                && (keep_method || !name.eq_ignore_ascii_case("content-type"))
        })
        .cloned()
        .collect();
    if process_cookies {
        let cookies = merged_cookies(current, response);
        if !cookies.is_empty() {
            headers.retain(|(name, _)| !name.eq_ignore_ascii_case("cookie"));
            headers.push(("Cookie".to_owned(), cookies));
        }
    }
    ResendRequest {
        method,
        url: target.to_owned(),
        headers,
        body,
    }
}

/// Merges the current request's cookies with the response's `Set-Cookie`s,
/// later values overriding earlier ones by name.
fn merged_cookies(current: &ResendRequest, response: &ResendResponse) -> String {
    let mut jar: Vec<String> = Vec::new();
    let mut push_pair = |pair: &str| {
        let pair = pair.trim();
        if pair.is_empty() {
            return;
        }
        let name = pair.split('=').next().unwrap_or("");
        jar.retain(|existing| existing.split('=').next().unwrap_or("") != name);
        jar.push(pair.to_owned());
    };
    if let Some((_, existing)) = current
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    {
        for pair in existing.split(';') {
            push_pair(pair);
        }
    }
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("set-cookie") {
            if let Some(pair) = value.split(';').next() {
                push_pair(pair);
            }
        }
    }
    jar.join("; ")
}

/// Headers a capturing client adds for the proxy itself; they are not part of
/// the request to the target and must not be replayed to it.
fn strip_proxy_artifact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    const PROXY_ARTIFACTS: [&str; 3] = [
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    headers
        .iter()
        .filter(|(name, _)| {
            !PROXY_ARTIFACTS
                .iter()
                .any(|artifact| name.eq_ignore_ascii_case(artifact))
        })
        .cloned()
        .collect()
}

fn validate_request(request: &ResendRequest) -> Result<(), Diagnostic> {
    if request.method.trim().is_empty() {
        return Err(request_diagnostic("method", "HTTP method is empty"));
    }
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|error| request_diagnostic("method", &error.to_string()))?;
    if method.as_str().contains(' ') || request.url.parse::<reqwest::Url>().is_err() {
        return Err(request_diagnostic(
            "url",
            "request URL is not absolute and valid",
        ));
    }
    if !matches!(request.url.split(':').next(), Some("http" | "https")) {
        return Err(request_diagnostic(
            "url",
            "only HTTP and HTTPS URLs are supported",
        ));
    }
    for (name, value) in &request.headers {
        HeaderName::try_from(name)
            .map_err(|error| request_diagnostic("header-name", &error.to_string()))?;
        HeaderValue::try_from(value)
            .map_err(|error| request_diagnostic("header-value", &error.to_string()))?;
    }
    Ok(())
}

pub(crate) fn url_target(url: &str) -> Option<(String, Option<u16>)> {
    let parsed = url.parse::<reqwest::Url>().ok()?;
    Some((parsed.host_str()?.to_owned(), parsed.port()))
}

fn new_context_id() -> String {
    let mut bytes = [0_u8; 16];
    if fill(&mut bytes).is_err() {
        bytes[..8].copy_from_slice(
            &chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
                .to_le_bytes(),
        );
    }
    let mut id = String::from("resend-");
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

fn request_diagnostic(operation: &str, error: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String(operation.to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(error.to_owned()),
    );
    catalogue::PROXY_RESEND_REQUEST_FAILED.instantiate(context)
}

fn outside_scope_diagnostic(url: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("url".to_owned(), DiagnosticValue::String(url.to_owned()));
    catalogue::PROXY_RESEND_OUTSIDE_SCOPE.instantiate(context)
}

fn transport_unavailable() -> Diagnostic {
    catalogue::PROXY_RESEND_TRANSPORT_UNAVAILABLE.instantiate(DiagnosticContext::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowSummary;
    use apiaxess_workbench_store::RedirectMode;
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn policy(mode: RedirectMode) -> RedirectPolicy {
        RedirectPolicy {
            mode,
            process_cookies: false,
            max_hops: 10,
        }
    }

    #[test]
    fn redirect_status_recognized() {
        for status in [301, 302, 303, 307, 308] {
            assert!(is_redirect_status(status), "{status}");
        }
        for status in [200, 204, 304, 400, 500] {
            assert!(!is_redirect_status(status), "{status}");
        }
    }

    #[test]
    fn resolve_redirect_url_forms() {
        let base = "https://api.example.test/a/b?x=1";
        assert_eq!(
            resolve_redirect_url(base, "https://other.test/z"),
            "https://other.test/z"
        );
        assert_eq!(
            resolve_redirect_url(base, "//cdn.test/z"),
            "https://cdn.test/z"
        );
        assert_eq!(
            resolve_redirect_url(base, "/login"),
            "https://api.example.test/login"
        );
        assert_eq!(
            resolve_redirect_url(base, "next"),
            "https://api.example.test/a/next"
        );
    }

    #[test]
    fn follow_decision_honors_mode() {
        let host = "api.example.test";
        let same = "https://api.example.test/next";
        let other = "https://evil.test/next";
        assert!(!should_follow_redirect(
            policy(RedirectMode::Never),
            host,
            same,
            None
        ));
        assert!(should_follow_redirect(
            policy(RedirectMode::Always),
            host,
            other,
            None
        ));
        assert!(should_follow_redirect(
            policy(RedirectMode::OnSite),
            host,
            same,
            None
        ));
        assert!(!should_follow_redirect(
            policy(RedirectMode::OnSite),
            host,
            other,
            None
        ));
        // In-scope uses the caller predicate; absent predicate never follows.
        assert!(!should_follow_redirect(
            policy(RedirectMode::InScope),
            host,
            same,
            None
        ));
        let in_scope: ScopePredicate = Arc::new(|h: &str, _p| h == "api.example.test");
        assert!(should_follow_redirect(
            policy(RedirectMode::InScope),
            host,
            same,
            Some(&in_scope)
        ));
        assert!(!should_follow_redirect(
            policy(RedirectMode::InScope),
            host,
            other,
            Some(&in_scope)
        ));
    }

    #[test]
    fn redirect_request_method_and_body_semantics() {
        let current = ResendRequest {
            method: "POST".to_owned(),
            url: "https://api.example.test/a".to_owned(),
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Cookie".to_owned(), "s=1".to_owned()),
            ],
            body: Some(b"{}".to_vec()),
        };
        let response303 = ResendResponse {
            status: 303,
            headers: vec![("set-cookie".to_owned(), "s=2; Path=/".to_owned())],
            body: None,
            duration_ms: 0,
            http_version: None,
            reason: None,
        };
        // 303 -> GET, body dropped, cookies carried and overridden by Set-Cookie.
        let next =
            next_redirect_request(&current, &response303, "https://api.example.test/b", true);
        assert_eq!(next.method, "GET");
        assert!(next.body.is_none());
        let cookie = next
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .map(|(_, value)| value.clone());
        assert_eq!(cookie.as_deref(), Some("s=2"));
        // 307 preserves method + body.
        let response307 = ResendResponse {
            status: 307,
            headers: Vec::new(),
            body: None,
            duration_ms: 0,
            http_version: None,
            reason: None,
        };
        let kept =
            next_redirect_request(&current, &response307, "https://api.example.test/b", false);
        assert_eq!(kept.method, "POST");
        assert_eq!(kept.body.as_deref(), Some(b"{}".as_ref()));
    }

    #[test]
    fn connection_close_overrides_existing_header() {
        let request = ResendRequest {
            method: "GET".to_owned(),
            url: "https://api.example.test/".to_owned(),
            headers: vec![("Connection".to_owned(), "keep-alive".to_owned())],
            body: None,
        };
        let closed = apply_connection_close(request, true);
        let values: Vec<&str> = closed
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(values, vec!["close"]);
    }

    #[test]
    fn stamp_origin_sets_single_authoritative_marker() {
        // A fresh request gets exactly one marker with the tool's origin value.
        let stamped = stamp_origin(request(), FlowOrigin::Fuzz);
        let markers: Vec<&str> = stamped
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(markers, vec!["fuzz"]);

        // A re-sent request that already carries a (possibly stale) marker ends up
        // with a single, correct value rather than an accumulating list.
        let mut inherited = request();
        inherited
            .headers
            .push((ORIGIN_MARKER_HEADER.to_owned(), "capture".to_owned()));
        let restamped = stamp_origin(inherited, FlowOrigin::Resend);
        let markers: Vec<&str> = restamped
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(markers, vec!["resend"]);
    }

    #[derive(Debug, Default)]
    struct CapturingSender {
        seen: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl ResendSender for CapturingSender {
        fn send(
            &self,
            request: ResendRequest,
        ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(request.headers.clone());
            }
            Box::pin(async {
                Ok(ResendResponse {
                    status: 200,
                    headers: Vec::new(),
                    body: None,
                    duration_ms: 0,
                    http_version: None,
                    reason: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn origin_tagging_sender_marks_every_send_path() {
        let inner = Arc::new(CapturingSender::default());
        let tagging = OriginTaggingSender::new(
            Arc::clone(&inner) as Arc<dyn ResendSender>,
            FlowOrigin::Fuzz,
        );
        tagging.send(request()).await.expect("send");
        tagging
            .send_with_options(request(), SendOptions::default())
            .await
            .expect("send_with_options");
        let seen = inner.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        for headers in seen.iter() {
            let markers: Vec<&str> = headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case(ORIGIN_MARKER_HEADER))
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(markers, vec!["fuzz"]);
        }
    }

    #[derive(Debug)]
    struct MockSender;

    impl ResendSender for MockSender {
        fn send(
            &self,
            _request: ResendRequest,
        ) -> crate::backend::BackendFuture<Result<ResendResponse, Diagnostic>> {
            Box::pin(async {
                Ok(ResendResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"{\"ok\":true}".to_vec()),
                    duration_ms: 0,
                    http_version: None,
                    reason: None,
                })
            })
        }
    }

    fn store() -> Arc<TrafficStore> {
        let path = env::temp_dir().join(format!(
            "apiaxess-resend-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Arc::new(TrafficStore::open(&path, "session:resend-test").expect("store"))
    }

    fn request() -> ResendRequest {
        ResendRequest {
            method: "POST".to_owned(),
            url: "https://api.example.test/items".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: Some(b"{}".to_vec()),
        }
    }

    #[tokio::test]
    async fn send_appends_history_and_hydrates_again() {
        let store = store();
        let resend = ResendWorkbench::new();
        resend.attach_store(Arc::clone(&store)).expect("attach");
        resend.attach_sender(Arc::new(MockSender));
        let context = resend.create(request(), None).expect("create");
        let result = resend.send(&context.id).await.expect("send");
        assert_eq!(
            result.revision.response.as_ref().map(|r| r.status),
            Some(200)
        );
        assert_eq!(result.context.history.len(), 1);

        let restored = ResendWorkbench::new();
        restored.attach_store(store).expect("restore");
        assert_eq!(restored.get(&context.id).expect("context").history.len(), 1);
        restored.derive(&context.id, 1).expect("derive");
    }

    #[tokio::test]
    async fn missing_transport_is_a_recorded_diagnostic_not_a_direct_fallback() {
        let resend = ResendWorkbench::new();
        resend.attach_store(store()).expect("attach");
        let context = resend.create(request(), None).expect("create");
        let result = resend.send(&context.id).await.expect("record failure");
        assert_eq!(
            result.revision.diagnostic.as_ref().map(|d| d.id.as_ref()),
            Some("proxy.resend-transport-unavailable")
        );
        assert_eq!(result.context.history.len(), 1);
    }

    #[test]
    fn wire_header_list_keeps_authored_order_case_and_as_sent_length() {
        let owned = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect()
        };
        let request = |headers: &[(&str, &str)], body: Option<&[u8]>| ResendRequest {
            method: "POST".to_owned(),
            url: "http://127.0.0.1:9111/items".to_owned(),
            headers: owned(headers),
            body: body.map(<[u8]>::to_vec),
        };
        // Order and case kept; stale Content-Length recomputed in place; the
        // private origin marker never joins the wire list.
        let edited = request(
            &[
                ("X-Zeta", "z"),
                ("Host", "evil.test"),
                ("Content-Length", "999"),
                ("x-apiaxess-origin", "resend"),
                ("accept", "*/*"),
            ],
            Some(b"hello"),
        );
        assert_eq!(
            wire_header_list(&edited, true),
            owned(&[
                ("X-Zeta", "z"),
                ("Host", "evil.test"),
                ("Content-Length", "5"),
                ("accept", "*/*"),
            ])
        );
        // With the toggle off the authored value is sent as written.
        assert_eq!(wire_header_list(&edited, false)[2].1, "999");
        // Missing Host is derived first; an unframed body gains Content-Length.
        assert_eq!(
            wire_header_list(&request(&[("Accept", "*/*")], Some(b"{}")), true),
            owned(&[
                ("Host", "127.0.0.1:9111"),
                ("Accept", "*/*"),
                ("Content-Length", "2"),
            ])
        );
        // An empty body adds no framing header.
        assert_eq!(
            wire_header_list(&request(&[("Host", "h")], Some(b"")), true),
            owned(&[("Host", "h")])
        );
    }

    #[test]
    fn status_line_splits_version_and_reason() {
        assert_eq!(
            parse_status_line("HTTP/1.1 302 Found"),
            (Some("HTTP/1.1".to_owned()), Some("Found".to_owned()))
        );
        assert_eq!(
            parse_status_line("HTTP/1.1 418 I am a teapot"),
            (
                Some("HTTP/1.1".to_owned()),
                Some("I am a teapot".to_owned())
            )
        );
        assert_eq!(
            parse_status_line("HTTP/1.0 200"),
            (Some("HTTP/1.0".to_owned()), None)
        );
    }

    #[test]
    fn create_from_flow_strips_proxy_artifact_headers() {
        let resend = ResendWorkbench::new();
        resend.attach_store(store()).expect("attach");
        let flow = FlowDetail {
            summary: FlowSummary {
                id: 10,
                protocol: Some("h1".to_owned()),
                method: Some("GET".to_owned()),
                host: Some("api.example.test".to_owned()),
                url: Some("http://api.example.test/items".to_owned()),
                path: Some("/items".to_owned()),
                status: Some(200),
                duration_ms: Some(3),
                content_type: None,
                size: Some(2),
                origin: FlowOrigin::Capture,
            },
            request_headers: vec![
                ("host".to_owned(), "api.example.test".to_owned()),
                ("Proxy-Connection".to_owned(), "Keep-Alive".to_owned()),
                (
                    "proxy-authorization".to_owned(),
                    "Basic Zm9vOmJhcg==".to_owned(),
                ),
                ("accept".to_owned(), "*/*".to_owned()),
            ],
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
        };
        let context = resend.create_from_flow(&flow).expect("flow enters resend");
        let names: Vec<&str> = context
            .current
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["host", "accept"]);
    }

    #[test]
    fn create_from_flow_preserves_scheme_port_path_and_query() {
        let resend = ResendWorkbench::new();
        resend.attach_store(store()).expect("attach");
        let flow = FlowDetail {
            summary: FlowSummary {
                id: 9,
                protocol: Some("h1".to_owned()),
                method: Some("GET".to_owned()),
                host: Some("api.example.test".to_owned()),
                url: Some("http://api.example.test:8080/items?id=7".to_owned()),
                path: Some("/items?id=7".to_owned()),
                status: Some(200),
                duration_ms: Some(3),
                content_type: None,
                size: Some(2),
                origin: FlowOrigin::Capture,
            },
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
        };
        let context = resend.create_from_flow(&flow).expect("flow enters resend");
        assert_eq!(
            context.current.url,
            "http://api.example.test:8080/items?id=7"
        );
    }
}
