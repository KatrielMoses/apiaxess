//! Manual request repeater backed by the active session proxy and store.

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
    RepeaterContext, RepeaterRequest, RepeaterResponse, RepeaterRevision, TrafficStore,
};
use getrandom::fill;
use reqwest::header::{HeaderName, HeaderValue};

use crate::{FlowDetail, SessionCa};

/// Result returned after a repeater send, including any non-fatal warnings.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterSendResult {
    /// Updated context containing the appended revision.
    pub context: RepeaterContext,
    /// The revision created by this send.
    pub revision: RepeaterRevision,
    /// Warnings or send diagnostics shown alongside the revision.
    pub diagnostics: Vec<Diagnostic>,
}

/// Request transport used by the repeater. Implementations must send through
/// the session's routed proxy path rather than silently falling back to a
/// direct connection.
pub trait RepeaterSender: Send + Sync {
    /// Sends one fully edited request.
    fn send(
        &self,
        request: RepeaterRequest,
    ) -> crate::backend::BackendFuture<Result<RepeaterResponse, Diagnostic>>;
}

/// HTTP client that sends through an already-running `ProxyHandle` listener.
#[derive(Clone, Debug)]
pub struct ProxyRepeaterSender {
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
}

impl ProxyRepeaterSender {
    /// Creates a sender bound to the session proxy listener and CA.
    #[must_use]
    pub const fn new(proxy_addr: std::net::SocketAddr, ca: SessionCa) -> Self {
        Self { proxy_addr, ca }
    }
}

impl RepeaterSender for ProxyRepeaterSender {
    fn send(
        &self,
        request: RepeaterRequest,
    ) -> crate::backend::BackendFuture<Result<RepeaterResponse, Diagnostic>> {
        let proxy_addr = self.proxy_addr;
        let ca = self.ca.clone();
        Box::pin(async move { send_through_proxy(proxy_addr, ca, request).await })
    }
}

/// Session-scoped repeater contexts and their persistence bridge.
pub struct RepeaterWorkbench {
    store: RwLock<Option<Arc<TrafficStore>>>,
    sender: RwLock<Option<Arc<dyn RepeaterSender>>>,
    scope: RwLock<Option<EngagementScope>>,
    contexts: Mutex<BTreeMap<String, RepeaterContext>>,
}

impl std::fmt::Debug for RepeaterWorkbench {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepeaterWorkbench")
            .field("context_count", &self.list().len())
            .finish_non_exhaustive()
    }
}

impl Default for RepeaterWorkbench {
    fn default() -> Self {
        Self::new()
    }
}

impl RepeaterWorkbench {
    /// Creates an empty repeater surface.
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
        let contexts = store.repeater_contexts()?;
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
    pub fn attach_sender(&self, sender: Arc<dyn RepeaterSender>) {
        if let Ok(mut current) = self.sender.write() {
            *current = Some(sender);
        }
    }

    /// Sets the engagement scope used for repeater warnings and records.
    pub fn set_engagement_scope(&self, scope: EngagementScope) {
        if let Ok(mut current) = self.scope.write() {
            *current = Some(scope);
        }
    }

    /// Lists independent repeater contexts.
    #[must_use]
    pub fn list(&self) -> Vec<RepeaterContext> {
        self.contexts
            .lock()
            .map(|contexts| contexts.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Reads one repeater context.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<RepeaterContext> {
        self.contexts
            .lock()
            .ok()
            .and_then(|contexts| contexts.get(id).cloned())
    }

    /// Creates a context from a captured request.
    ///
    /// # Errors
    ///
    /// Returns a history diagnostic when the initial request cannot be
    /// persisted.
    pub fn create_from_flow(&self, flow: &FlowDetail) -> Result<RepeaterContext, Diagnostic> {
        let url = flow.summary.url.clone().ok_or_else(|| {
            request_diagnostic(
                "create",
                "captured flow has no exact request URL; refresh the flow and retry",
            )
        })?;
        let request = RepeaterRequest {
            method: flow
                .summary
                .method
                .clone()
                .unwrap_or_else(|| "GET".to_owned()),
            url,
            headers: flow.request_headers.clone(),
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
        request: RepeaterRequest,
        source_flow_id: Option<u64>,
    ) -> Result<RepeaterContext, Diagnostic> {
        validate_request(&request)?;
        let context = RepeaterContext {
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
        request: RepeaterRequest,
    ) -> Result<RepeaterContext, Diagnostic> {
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
    pub fn derive(&self, id: &str, revision: u64) -> Result<RepeaterContext, Diagnostic> {
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
    pub async fn send(&self, id: &str) -> Result<RepeaterSendResult, Diagnostic> {
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
        let revision = RepeaterRevision {
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
        Ok(RepeaterSendResult {
            context,
            revision,
            diagnostics,
        })
    }

    /// Sends and records the attempt in the canonical session audit trail.
    ///
    /// # Errors
    ///
    /// Returns a repeater diagnostic for persistence/transport failures or a
    /// session diagnostic if the audit record cannot be appended.
    pub async fn send_in_session(
        &self,
        id: &str,
        session: &mut Session,
    ) -> Result<RepeaterSendResult, Diagnostic> {
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
            id: format!("repeater:{}:{}", id, result.revision.revision),
            occurred_at: result.revision.sent_at,
            actor: AuditActor::User,
            action: ActionDescriptor {
                kind: "workbench.repeater.send".to_owned(),
                summary: format!("Sent repeater revision {}", result.revision.revision),
            },
            target,
            outcome,
            diagnostics: result.diagnostics.clone(),
        })?;
        Ok(result)
    }

    fn persist(&self, context: &RepeaterContext) -> Result<(), Diagnostic> {
        let Some(store) = self.store.read().ok().and_then(|store| store.clone()) else {
            return Err(
                catalogue::PROXY_REPEATER_HISTORY_FAILED.instantiate(DiagnosticContext::new())
            );
        };
        store.upsert_repeater(context)
    }

    fn replace_context(&self, context: RepeaterContext) {
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

async fn send_through_proxy(
    proxy_addr: std::net::SocketAddr,
    ca: SessionCa,
    request: RepeaterRequest,
) -> Result<RepeaterResponse, Diagnostic> {
    validate_request(&request)?;
    let proxy = reqwest::Proxy::all(format!("http://{proxy_addr}"))
        .map_err(|error| request_diagnostic("proxy", &error.to_string()))?;
    let root = reqwest::Certificate::from_pem(ca.root_certificate_pem().as_bytes())
        .map_err(|error| request_diagnostic("ca", &error.to_string()))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(root)
        .http2_adaptive_window(true)
        .build()
        .map_err(|error| request_diagnostic("client", &error.to_string()))?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|error| request_diagnostic("method", &error.to_string()))?;
    let mut builder = client.request(method, &request.url);
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("content-length") && request.body.is_some() {
            // Body edits must not reuse the captured length; reqwest recalculates it.
            continue;
        }
        let name = HeaderName::try_from(name)
            .map_err(|error| request_diagnostic("header-name", &error.to_string()))?;
        let value = HeaderValue::try_from(value)
            .map_err(|error| request_diagnostic("header-value", &error.to_string()))?;
        builder = builder.header(name, value);
    }
    if let Some(body) = request.body {
        builder = builder.body(body);
    }
    let response = builder
        .send()
        .await
        .map_err(|error| request_diagnostic("send", &error.to_string()))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or("<non-utf8>").to_owned(),
            )
        })
        .collect();
    let body = response
        .bytes()
        .await
        .map(|body| (!body.is_empty()).then(|| body.to_vec()))
        .map_err(|error| request_diagnostic("response-body", &error.to_string()))?;
    Ok(RepeaterResponse {
        status,
        headers,
        body,
        duration_ms: 0,
    })
}

fn validate_request(request: &RepeaterRequest) -> Result<(), Diagnostic> {
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
    let mut id = String::from("repeater-");
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
    catalogue::PROXY_REPEATER_REQUEST_FAILED.instantiate(context)
}

fn outside_scope_diagnostic(url: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("url".to_owned(), DiagnosticValue::String(url.to_owned()));
    catalogue::PROXY_REPEATER_OUTSIDE_SCOPE.instantiate(context)
}

fn transport_unavailable() -> Diagnostic {
    catalogue::PROXY_REPEATER_TRANSPORT_UNAVAILABLE.instantiate(DiagnosticContext::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FlowSummary;
    use std::{
        env,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Debug)]
    struct MockSender;

    impl RepeaterSender for MockSender {
        fn send(
            &self,
            _request: RepeaterRequest,
        ) -> crate::backend::BackendFuture<Result<RepeaterResponse, Diagnostic>> {
            Box::pin(async {
                Ok(RepeaterResponse {
                    status: 200,
                    headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                    body: Some(b"{\"ok\":true}".to_vec()),
                    duration_ms: 0,
                })
            })
        }
    }

    fn store() -> Arc<TrafficStore> {
        let path = env::temp_dir().join(format!(
            "apiaxess-repeater-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        Arc::new(TrafficStore::open(&path, "session:repeater-test").expect("store"))
    }

    fn request() -> RepeaterRequest {
        RepeaterRequest {
            method: "POST".to_owned(),
            url: "https://api.example.test/items".to_owned(),
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: Some(b"{}".to_vec()),
        }
    }

    #[tokio::test]
    async fn send_appends_history_and_hydrates_again() {
        let store = store();
        let repeater = RepeaterWorkbench::new();
        repeater.attach_store(Arc::clone(&store)).expect("attach");
        repeater.attach_sender(Arc::new(MockSender));
        let context = repeater.create(request(), None).expect("create");
        let result = repeater.send(&context.id).await.expect("send");
        assert_eq!(
            result.revision.response.as_ref().map(|r| r.status),
            Some(200)
        );
        assert_eq!(result.context.history.len(), 1);

        let restored = RepeaterWorkbench::new();
        restored.attach_store(store).expect("restore");
        assert_eq!(restored.get(&context.id).expect("context").history.len(), 1);
        restored.derive(&context.id, 1).expect("derive");
    }

    #[tokio::test]
    async fn missing_transport_is_a_recorded_diagnostic_not_a_direct_fallback() {
        let repeater = RepeaterWorkbench::new();
        repeater.attach_store(store()).expect("attach");
        let context = repeater.create(request(), None).expect("create");
        let result = repeater.send(&context.id).await.expect("record failure");
        assert_eq!(
            result.revision.diagnostic.as_ref().map(|d| d.id.as_ref()),
            Some("proxy.repeater-transport-unavailable")
        );
        assert_eq!(result.context.history.len(), 1);
    }

    #[test]
    fn create_from_flow_preserves_scheme_port_path_and_query() {
        let repeater = RepeaterWorkbench::new();
        repeater.attach_store(store()).expect("attach");
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
            },
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
        };
        let context = repeater
            .create_from_flow(&flow)
            .expect("flow enters repeater");
        assert_eq!(
            context.current.url,
            "http://api.example.test:8080/items?id=7"
        );
    }
}
