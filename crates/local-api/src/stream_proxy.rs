//! Phase D2: the authenticated reverse-proxy for the GUI Android target's screen
//! stream.
//!
//! ws-scrcpy has no built-in auth and is bound to loopback only, so it is never a
//! reachable surface. The engine is the sole listener on the workbench address and
//! reverse-proxies the Android view — both plain HTTP and the WebSocket upgrade
//! that carries the control channel — only after enforcing the same gate the
//! workbench uses: the loopback `Origin` plus a valid session/device token (the
//! workbench session token or a Phase C1 pairing → session bearer token). The
//! token is checked on the WebSocket upgrade, not just the initial GET, so a random
//! network client can neither view nor drive the target.
//!
//! Because it rides the one engine HTTP port, the Android view inherits the
//! workbench's three access modes unchanged (loopback default, SSH-tunnel for
//! remote, optional exposure-with-warning) — the ws-scrcpy port itself is never
//! exposed.

use std::sync::OnceLock;

use axum::{
    body::Bytes,
    extract::{FromRequestParts, Request, State, WebSocketUpgrade, ws},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

use crate::ApiState;

/// The cookie the engine sets after a token-bearing entry request, so the browser
/// carries the token on ws-scrcpy's own same-origin asset + WebSocket requests
/// (which the engine cannot inject a query token into). Scoped to the stream path,
/// `HttpOnly` (JS cannot read it) and `SameSite=Strict` (no cross-site sending).
const STREAM_COOKIE: &str = "apiaxess_stream";

/// The base path the Android view is reverse-proxied under. ws-scrcpy is built to
/// serve from the same base (`WS_SCRCPY_PATHNAME`), so its own asset/WS URLs stay
/// same-origin and carry the cookie.
pub(crate) const STREAM_BASE_PATH: &str = "/android-stream";

/// Hop-by-hop headers that must not be forwarded across a proxy (RFC 7230 §6.1),
/// plus the auth headers we deliberately do not leak to the ws-scrcpy upstream.
const STRIPPED_REQUEST_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "authorization",
    "cookie",
];

const STRIPPED_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// Maximum body size forwarded on a plain HTTP request to ws-scrcpy. ws-scrcpy's
/// HTTP surface is static assets + control JSON, so this is generous.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The reverse-proxy entry point for `/android-stream` and `/android-stream/*`.
///
/// One handler serves both roles: when the request is a WebSocket upgrade it
/// bridges to the upstream ws-scrcpy WebSocket; otherwise it forwards the HTTP
/// request. Both paths enforce the gate first — an unauthenticated upgrade is
/// rejected before `on_upgrade`.
pub(crate) async fn stream_proxy(State(state): State<ApiState>, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    let headers = parts.headers.clone();
    let uri = parts.uri.clone();
    let method = parts.method.clone();
    // Derive the upstream tail from the path (works for both the base route and the
    // `/{*rest}` wildcard without a Path extractor).
    let tail = uri
        .path()
        .strip_prefix(STREAM_BASE_PATH)
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_owned();

    // Enforce the gate FIRST — before revealing whether a stream is even running,
    // and before accepting a WebSocket upgrade. A WebSocket upgrade must present the
    // loopback Origin (browsers always send it on upgrades); a plain HTTP
    // GET/navigation may legitimately omit Origin.
    let is_upgrade = is_websocket_upgrade(&headers);
    let auth = match authorize_stream(&state, &headers, &uri, is_upgrade) {
        Ok(auth) => auth,
        Err(response) => return response,
    };

    let Some(port) = state.engine.android_stream_port() else {
        let diagnostic = apiaxess_diagnostics::catalogue::ANDROID_STREAM_NOT_ACTIVE
            .instantiate(apiaxess_diagnostics::DiagnosticContext::new());
        return (StatusCode::SERVICE_UNAVAILABLE, axum::Json(diagnostic)).into_response();
    };

    if is_upgrade {
        return match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
            Ok(upgrade) => proxy_websocket(port, &tail, uri.query(), upgrade),
            Err(rejection) => rejection.into_response(),
        };
    }

    let Ok(body) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    proxy_http(port, &method, &tail, &uri, &headers, body, &auth).await
}

/// Whether the request is a WebSocket upgrade (`Upgrade: websocket` +
/// `Connection: upgrade`).
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let upgrade = headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
    let connection = headers
        .get(header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        });
    upgrade && connection
}

/// The outcome of a successful gate check.
struct StreamAuth {
    /// The validated token, echoed into the stream cookie when it arrived fresh
    /// (from the query or a bearer header) rather than from the cookie itself.
    token: String,
    /// Whether to set the stream cookie on the response.
    set_cookie: bool,
}

impl std::fmt::Debug for StreamAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bearer token itself.
        formatter
            .debug_struct("StreamAuth")
            .field("token", &"<redacted>")
            .field("set_cookie", &self.set_cookie)
            .finish()
    }
}

/// Enforces the workbench gate: loopback `Origin` (required on WS upgrades) plus a
/// valid session/device token from the query, a bearer header, or the stream
/// cookie.
#[allow(clippy::result_large_err)] // The error is an axum Response, returned directly by callers.
fn authorize_stream(
    state: &ApiState,
    headers: &HeaderMap,
    uri: &Uri,
    require_origin: bool,
) -> Result<StreamAuth, Response> {
    let live = state.engine.live_workbench();

    // Origin: reject a present, mismatched Origin always; require it to be present
    // and matching on WebSocket upgrades.
    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        Some(origin) if origin == state.expected_origin.as_ref() => {}
        None if !require_origin => {}
        _ => return Err(reject()),
    }

    // Token: query > bearer > cookie.
    let (token, from_cookie) = if let Some(token) = query_value(uri.query(), "token") {
        (token, false)
    } else if let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_owned())
    {
        (token, false)
    } else if let Some(token) = cookie_value(headers, STREAM_COOKIE) {
        (token, true)
    } else {
        return Err(reject());
    };

    // Valid if it is the workbench session token OR a live device pairing token —
    // "the same gate the workbench uses", with the C1 device token also accepted.
    let valid = token == live.auth_token() || state.pairing.validate_session_token(&token);
    if !valid {
        return Err(reject());
    }
    Ok(StreamAuth {
        token,
        set_cookie: !from_cookie,
    })
}

fn reject() -> Response {
    let diagnostic = apiaxess_diagnostics::catalogue::ANDROID_STREAM_AUTH_REJECTED
        .instantiate(apiaxess_diagnostics::DiagnosticContext::new());
    (StatusCode::FORBIDDEN, axum::Json(diagnostic)).into_response()
}

/// Forwards a plain HTTP request to the loopback ws-scrcpy upstream.
async fn proxy_http(
    port: u16,
    method: &Method,
    tail: &str,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
    auth: &StreamAuth,
) -> Response {
    let target_url = upstream_url("http", port, tail, uri.query());
    let mut request = http_client().request(method.clone(), target_url).body(body);
    for (name, value) in headers {
        if !is_stripped(name.as_str(), STRIPPED_REQUEST_HEADERS) {
            request = request.header(name, value);
        }
    }
    let Ok(upstream) = request.send().await else {
        let diagnostic = apiaxess_diagnostics::catalogue::ANDROID_STREAM_UPSTREAM_UNREACHABLE
            .instantiate(apiaxess_diagnostics::DiagnosticContext::new());
        return (StatusCode::BAD_GATEWAY, axum::Json(diagnostic)).into_response();
    };

    let status = upstream.status();
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        if !is_stripped(name.as_str(), STRIPPED_RESPONSE_HEADERS) {
            response_headers.insert(name.clone(), value.clone());
        }
    }
    let body = upstream.bytes().await.unwrap_or_default();
    let mut response = (status, body).into_response();
    *response.headers_mut() = response_headers;
    // Persist the token as a scoped, HttpOnly, SameSite=Strict cookie so ws-scrcpy's
    // own same-origin asset + WebSocket requests authenticate without a query token.
    if auth.set_cookie
        && let Ok(cookie) = HeaderValue::from_str(&format!(
            "{STREAM_COOKIE}={}; Path={STREAM_BASE_PATH}; HttpOnly; SameSite=Strict",
            auth.token
        ))
    {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// Bridges the browser WebSocket to the upstream ws-scrcpy WebSocket. The gate has
/// already been enforced before this upgrade is accepted.
fn proxy_websocket(
    port: u16,
    tail: &str,
    query: Option<&str>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let url = upstream_url("ws", port, tail, query);
    upgrade.on_upgrade(move |client| bridge_sockets(client, url))
}

async fn bridge_sockets(client: ws::WebSocket, upstream_url: String) {
    let Ok((upstream, _response)) = tokio_tungstenite::connect_async(&upstream_url).await else {
        // The gate passed but ws-scrcpy did not accept the upgrade; close the client
        // socket by dropping it.
        return;
    };
    let (mut client_sink, mut client_stream) = client.split();
    let (mut upstream_sink, mut upstream_stream) = upstream.split();

    // client -> upstream
    let to_upstream = async {
        while let Some(Ok(message)) = client_stream.next().await {
            let forwarded = axum_to_tungstenite(message);
            let is_close = matches!(forwarded, tungstenite::Message::Close(_));
            if upstream_sink.send(forwarded).await.is_err() {
                break;
            }
            if is_close {
                break;
            }
        }
        let _ = upstream_sink.close().await;
    };

    // upstream -> client
    let to_client = async {
        while let Some(Ok(message)) = upstream_stream.next().await {
            let is_close = matches!(message, tungstenite::Message::Close(_));
            if let Some(message) = tungstenite_to_axum(message)
                && client_sink.send(message).await.is_err()
            {
                break;
            }
            if is_close {
                break;
            }
        }
        let _ = client_sink.close().await;
    };

    tokio::join!(to_upstream, to_client);
}

/// Builds the upstream URL on the loopback ws-scrcpy port, preserving the tail path
/// and query but stripping our `token` parameter so it never reaches ws-scrcpy.
fn upstream_url(scheme: &str, port: u16, tail: &str, query: Option<&str>) -> String {
    let tail = tail.trim_start_matches('/');
    let mut url = format!("{scheme}://127.0.0.1:{port}/{tail}");
    if let Some(query) = forward_query(query) {
        url.push('?');
        url.push_str(&query);
    }
    url
}

/// Rebuilds a query string without the `token` parameter, or `None` when nothing
/// remains.
fn forward_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.starts_with("token="))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("&"))
    }
}

/// Extracts a query parameter value (no percent-decoding; tokens are opaque hex).
fn query_value(query: Option<&str>, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix(&prefix))
        .map(str::to_owned)
}

/// Extracts a cookie value from the `Cookie` header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .find_map(|pair| pair.trim().strip_prefix(&prefix))
        .map(str::to_owned)
}

fn is_stripped(name: &str, set: &[&str]) -> bool {
    set.iter()
        .any(|stripped| name.eq_ignore_ascii_case(stripped))
}

/// Converts an inbound axum WebSocket message to a tungstenite message for the
/// upstream. `Ping`/`Pong` are forwarded so scrcpy keepalives survive the hop.
fn axum_to_tungstenite(message: ws::Message) -> tungstenite::Message {
    match message {
        ws::Message::Text(text) => tungstenite::Message::Text(text.as_str().into()),
        ws::Message::Binary(data) => tungstenite::Message::Binary(data),
        ws::Message::Ping(data) => tungstenite::Message::Ping(data),
        ws::Message::Pong(data) => tungstenite::Message::Pong(data),
        ws::Message::Close(frame) => {
            tungstenite::Message::Close(frame.map(|frame| tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.as_str().into(),
            }))
        }
    }
}

/// Converts an upstream tungstenite message to an axum WebSocket message for the
/// browser. Raw frames are not surfaced by axum and are dropped.
fn tungstenite_to_axum(message: tungstenite::Message) -> Option<ws::Message> {
    Some(match message {
        tungstenite::Message::Text(text) => ws::Message::Text(text.as_str().into()),
        tungstenite::Message::Binary(data) => ws::Message::Binary(data),
        tungstenite::Message::Ping(data) => ws::Message::Ping(data),
        tungstenite::Message::Pong(data) => ws::Message::Pong(data),
        tungstenite::Message::Close(frame) => {
            ws::Message::Close(frame.map(|frame| ws::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.as_str().into(),
            }))
        }
        tungstenite::Message::Frame(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApiState, PipelineRegistry,
        pairing::{DevicePairingRegistry, PendingPairingRegistry},
    };
    use apiaxess_engine_shell::Engine;
    use std::sync::Arc;

    fn state() -> ApiState {
        ApiState {
            engine: Engine::new(),
            expected_origin: Arc::from("http://127.0.0.1:7777"),
            pipeline_runs: PipelineRegistry::default(),
            pairing: DevicePairingRegistry::default(),
            pending_pairing: PendingPairingRegistry::default(),
            gui_port: 7777,
        }
    }

    fn origin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "http://127.0.0.1:7777".parse().unwrap());
        headers
    }

    #[test]
    fn valid_token_via_query_passes_and_sets_cookie() {
        let state = state();
        let token = state.engine.live_workbench().auth_token().to_owned();
        let uri: Uri = format!("/android-stream/?token={token}").parse().unwrap();
        let auth = authorize_stream(&state, &origin_headers(), &uri, true).expect("authorized");
        assert_eq!(auth.token, token);
        // Fresh from the query, so it is persisted as the stream cookie.
        assert!(auth.set_cookie);
    }

    #[test]
    fn valid_token_via_cookie_passes_without_resetting_cookie() {
        let state = state();
        let token = state.engine.live_workbench().auth_token().to_owned();
        let mut headers = origin_headers();
        headers.insert(
            header::COOKIE,
            format!("{STREAM_COOKIE}={token}").parse().unwrap(),
        );
        let uri: Uri = "/android-stream/".parse().unwrap();
        let auth = authorize_stream(&state, &headers, &uri, true).expect("authorized");
        assert!(!auth.set_cookie);
    }

    #[test]
    fn c1_device_session_token_is_accepted() {
        let state = state();
        let session = state
            .pairing
            .issue_session_token()
            .expect("device session token");
        let uri: Uri = format!("/android-stream/?token={}", session.token)
            .parse()
            .unwrap();
        assert!(authorize_stream(&state, &origin_headers(), &uri, true).is_ok());
    }

    #[test]
    fn wrong_token_is_rejected() {
        let state = state();
        let uri: Uri = "/android-stream/?token=not-a-real-token".parse().unwrap();
        let response =
            authorize_stream(&state, &origin_headers(), &uri, true).expect_err("rejected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn missing_token_is_rejected() {
        let state = state();
        let uri: Uri = "/android-stream/".parse().unwrap();
        assert!(authorize_stream(&state, &origin_headers(), &uri, true).is_err());
    }

    #[test]
    fn websocket_upgrade_requires_the_loopback_origin() {
        let state = state();
        let token = state.engine.live_workbench().auth_token().to_owned();
        let uri: Uri = format!("/android-stream/?token={token}").parse().unwrap();
        // No Origin header: rejected on the upgrade path (require_origin = true)...
        let response =
            authorize_stream(&state, &HeaderMap::new(), &uri, true).expect_err("rejected");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // ...but allowed on a plain GET/navigation (require_origin = false).
        assert!(authorize_stream(&state, &HeaderMap::new(), &uri, false).is_ok());
    }

    #[test]
    fn present_but_wrong_origin_is_always_rejected() {
        let state = state();
        let token = state.engine.live_workbench().auth_token().to_owned();
        let uri: Uri = format!("/android-stream/?token={token}").parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(authorize_stream(&state, &headers, &uri, false).is_err());
        assert!(authorize_stream(&state, &headers, &uri, true).is_err());
    }

    #[tokio::test]
    async fn handler_rejects_unauthenticated_requests_before_revealing_stream_state() {
        // No token at all: the router-level handler rejects with 403 before it even
        // checks whether a stream is running (a random network client learns nothing).
        let state = state();
        let request = Request::builder()
            .uri("/android-stream/health")
            .header(header::ORIGIN, "http://127.0.0.1:7777")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = stream_proxy(State(state), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn handler_rejects_unauthenticated_websocket_upgrade() {
        // An upgrade with the right shape but no token/origin is rejected before
        // `on_upgrade` — the control channel is never handed to a random client.
        let state = state();
        let request = Request::builder()
            .uri("/android-stream/ws")
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = stream_proxy(State(state), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authenticated_request_reports_not_active_when_no_stream_is_running() {
        let state = state();
        let token = state.engine.live_workbench().auth_token().to_owned();
        let request = Request::builder()
            .uri(format!("/android-stream/health?token={token}"))
            .header(header::ORIGIN, "http://127.0.0.1:7777")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = stream_proxy(State(state), request).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn upstream_url_strips_token_and_preserves_the_rest() {
        assert_eq!(
            upstream_url(
                "ws",
                8000,
                "",
                Some("action=proxy&token=abc&udid=emulator-5556")
            ),
            "ws://127.0.0.1:8000/?action=proxy&udid=emulator-5556"
        );
        assert_eq!(
            upstream_url("http", 8000, "bundle.js", None),
            "http://127.0.0.1:8000/bundle.js"
        );
        // A query that is only the token yields no query string upstream.
        assert_eq!(
            upstream_url("ws", 8000, "", Some("token=abc")),
            "ws://127.0.0.1:8000/"
        );
    }

    #[test]
    fn helpers_parse_query_and_cookies() {
        assert_eq!(
            query_value(Some("a=1&token=xyz&b=2"), "token").as_deref(),
            Some("xyz")
        );
        assert_eq!(query_value(Some("a=1"), "token"), None);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "other=1; apiaxess_stream=tok; z=2".parse().unwrap(),
        );
        assert_eq!(
            cookie_value(&headers, STREAM_COOKIE).as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn detects_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive, Upgrade".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
        assert!(!is_websocket_upgrade(&HeaderMap::new()));
    }

    #[test]
    fn hop_by_hop_and_auth_request_headers_are_stripped() {
        assert!(is_stripped("Authorization", STRIPPED_REQUEST_HEADERS));
        assert!(is_stripped("cookie", STRIPPED_REQUEST_HEADERS));
        assert!(is_stripped("Connection", STRIPPED_REQUEST_HEADERS));
        assert!(!is_stripped("accept", STRIPPED_REQUEST_HEADERS));
    }
}
