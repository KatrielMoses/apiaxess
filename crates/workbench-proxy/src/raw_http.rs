//! Byte-faithful HTTP/1.1 upstream exchange for workbench (Resend/Fuzz) sends.
//!
//! The `http` crate lowercases header names and hudsucker re-derives `Host`,
//! reordering headers on the way out; hyper's case-preserving map is private.
//! A raw editor must put on the wire exactly what the operator wrote, so these
//! sends carry their authored header list to the proxy in a private marker and
//! the proxy writes the request itself: request-line, headers in authored order
//! and case, blank line, body. The response head is parsed with `httparse` and
//! its status line and header list are handed back the same way.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hudsucker::hyper::Uri;
use hudsucker::rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Request marker: the authoritative, ordered, case-preserved header list.
pub(crate) const WIRE_HEADERS_MARKER: &str = "x-apiaxess-wire-headers";
/// Response marker: the upstream status line (`HTTP/1.1 302 Found`).
pub(crate) const UPSTREAM_STATUS_MARKER: &str = "x-apiaxess-upstream-status";
/// Response marker: the upstream header list as received.
pub(crate) const UPSTREAM_HEADERS_MARKER: &str = "x-apiaxess-upstream-headers";
/// Response marker: the upstream exchange failed (connect, TLS, timeout); the
/// value names the failure. Marks the proxy's synthetic 502 as not a response.
pub(crate) const UPSTREAM_ERROR_MARKER: &str = "x-apiaxess-upstream-error";

const MAX_HEAD_BYTES: usize = 256 * 1024;
const MAX_HEADERS: usize = 256;
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Encodes a header list for a marker value (base64 JSON, header-safe).
pub(crate) fn encode_header_list(headers: &[(String, String)]) -> String {
    STANDARD.encode(serde_json::to_vec(headers).unwrap_or_default())
}

/// Decodes a marker value produced by [`encode_header_list`].
pub(crate) fn decode_header_list(value: &[u8]) -> Option<Vec<(String, String)>> {
    let bytes = STANDARD.decode(value).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// One upstream response, exactly as received (body de-chunked).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    /// `HTTP/1.1 302 Found`.
    pub(crate) fn status_line(&self) -> String {
        if self.reason.is_empty() {
            format!("{} {}", self.version, self.status)
        } else {
            format!("{} {} {}", self.version, self.status, self.reason)
        }
    }
}

/// Serializes the request exactly as authored.
pub(crate) fn encode_request(
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// Connects to the URI authority (TLS for `https`), writes the request
/// verbatim, and reads one response.
pub(crate) async fn exchange(
    tls: Arc<ClientConfig>,
    uri: &Uri,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<RawResponse, String> {
    tokio::time::timeout(
        EXCHANGE_TIMEOUT,
        exchange_inner(tls, uri, method, headers, body),
    )
    .await
    .map_err(|_| format!("upstream exchange timed out after {EXCHANGE_TIMEOUT:?}"))?
}

async fn exchange_inner(
    tls: Arc<ClientConfig>,
    uri: &Uri,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<RawResponse, String> {
    let https = uri.scheme_str() == Some("https");
    let host = uri
        .host()
        .ok_or_else(|| "request URI has no host".to_owned())?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let target = uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), ToString::to_string);
    let request = encode_request(method, &target, headers, body);
    let head_only = method.eq_ignore_ascii_case("HEAD");
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| format!("connect {host}:{port}: {error}"))?;
    if https {
        let server_name = hudsucker::rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|error| format!("server name {host}: {error}"))?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, tcp)
            .await
            .map_err(|error| format!("tls {host}:{port}: {error}"))?;
        round_trip(stream, &request, head_only).await
    } else {
        round_trip(tcp, &request, head_only).await
    }
}

async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
    head_only: bool,
) -> Result<RawResponse, String> {
    stream
        .write_all(request)
        .await
        .map_err(|error| format!("write request: {error}"))?;
    stream
        .flush()
        .await
        .map_err(|error| format!("flush request: {error}"))?;
    read_response(&mut stream, head_only).await
}

/// Reads one response, skipping interim `1xx` heads.
pub(crate) async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    head_only: bool,
) -> Result<RawResponse, String> {
    let mut reader = Reader {
        stream,
        buf: Vec::new(),
        eof: false,
    };
    loop {
        let head = reader.read_head().await?;
        if (100..200).contains(&head.status) && head.status != 101 {
            continue;
        }
        let body = if head_only || head.status == 204 || head.status == 304 || head.status < 200 {
            Vec::new()
        } else if header(&head.headers, "transfer-encoding")
            .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            reader.read_chunked().await?
        } else if let Some(length) = header(&head.headers, "content-length") {
            let length: usize = length
                .trim()
                .parse()
                .map_err(|_| format!("invalid Content-Length {length:?}"))?;
            reader.read_exact_len(length).await?
        } else {
            reader.read_to_end().await?
        };
        return Ok(RawResponse {
            version: head.version,
            status: head.status,
            reason: head.reason,
            headers: head.headers,
            body,
        });
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

struct Head {
    version: String,
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

/// Parses a complete response head from `buf`, or `None` if more bytes are
/// needed. Synchronous so the header slots never live across an await.
fn parse_head(buf: &[u8]) -> Result<Option<(Head, usize)>, String> {
    let mut slots = vec![httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut slots);
    match parsed.parse(buf) {
        Ok(httparse::Status::Complete(consumed)) => Ok(Some((
            Head {
                version: format!("HTTP/1.{}", parsed.version.unwrap_or(1)),
                status: parsed.code.unwrap_or_default(),
                reason: parsed.reason.unwrap_or_default().to_owned(),
                headers: parsed
                    .headers
                    .iter()
                    .map(|header| {
                        (
                            header.name.to_owned(),
                            String::from_utf8_lossy(header.value).into_owned(),
                        )
                    })
                    .collect(),
            },
            consumed,
        ))),
        Ok(httparse::Status::Partial) => Ok(None),
        Err(error) => Err(format!("malformed response head: {error}")),
    }
}

struct Reader<'a, S> {
    stream: &'a mut S,
    buf: Vec<u8>,
    eof: bool,
}

impl<S: AsyncRead + Unpin> Reader<'_, S> {
    async fn fill(&mut self) -> Result<(), String> {
        // Read straight into the heap buffer; a stack chunk held across the
        // await would bloat every future up the call chain.
        self.buf.reserve(16 * 1024);
        let read = self
            .stream
            .read_buf(&mut self.buf)
            .await
            .map_err(|error| format!("read response: {error}"))?;
        if read == 0 {
            self.eof = true;
        }
        Ok(())
    }

    async fn read_head(&mut self) -> Result<Head, String> {
        loop {
            if let Some((head, consumed)) = parse_head(&self.buf)? {
                self.buf.drain(..consumed);
                return Ok(head);
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return Err("response head exceeds 256 KiB".to_owned());
            }
            if self.eof {
                return Err("connection closed before a complete response head".to_owned());
            }
            self.fill().await?;
        }
    }

    async fn read_line(&mut self) -> Result<Vec<u8>, String> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|window| window == b"\r\n") {
                let line = self.buf[..end].to_vec();
                self.buf.drain(..end + 2);
                return Ok(line);
            }
            if self.eof {
                return Err("connection closed inside a chunked body".to_owned());
            }
            self.fill().await?;
        }
    }

    async fn read_exact_len(&mut self, length: usize) -> Result<Vec<u8>, String> {
        if length > MAX_BODY_BYTES {
            return Err(format!("response body of {length} bytes exceeds 64 MiB"));
        }
        while self.buf.len() < length {
            if self.eof {
                return Err(format!(
                    "connection closed after {} of {length} body bytes",
                    self.buf.len()
                ));
            }
            self.fill().await?;
        }
        Ok(self.buf.drain(..length).collect())
    }

    async fn read_chunked(&mut self) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        loop {
            let line = self.read_line().await?;
            let size_text = String::from_utf8_lossy(&line);
            let size_hex = size_text.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16)
                .map_err(|_| format!("invalid chunk size {size_hex:?}"))?;
            if size == 0 {
                // Trailers until the terminating blank line.
                while !self.read_line().await?.is_empty() {}
                return Ok(body);
            }
            if body.len() + size > MAX_BODY_BYTES {
                return Err("response body exceeds 64 MiB".to_owned());
            }
            body.extend(self.read_exact_len(size).await?);
            if !self.read_line().await?.is_empty() {
                return Err("chunk not terminated by CRLF".to_owned());
            }
        }
    }

    async fn read_to_end(&mut self) -> Result<Vec<u8>, String> {
        while !self.eof {
            if self.buf.len() > MAX_BODY_BYTES {
                return Err("response body exceeds 64 MiB".to_owned());
            }
            self.fill().await?;
        }
        Ok(std::mem::take(&mut self.buf))
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_header_list, encode_header_list, encode_request, read_response};

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn request_keeps_authored_order_and_case() {
        let list = headers(&[
            ("X-Zeta", "1"),
            ("Host", "api.example.test"),
            ("content-TYPE", "text/plain"),
            ("Accept", "*/*"),
        ]);
        let bytes = encode_request("POST", "/a?b=1", &list, b"hi");
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            "POST /a?b=1 HTTP/1.1\r\nX-Zeta: 1\r\nHost: api.example.test\r\ncontent-TYPE: text/plain\r\nAccept: */*\r\n\r\nhi"
        );
    }

    #[test]
    fn header_list_marker_round_trips() {
        let list = headers(&[("X-A", "é; \"q\""), ("x-a", "2")]);
        assert_eq!(
            decode_header_list(encode_header_list(&list).as_bytes()),
            Some(list)
        );
        assert_eq!(decode_header_list(b"!!"), None);
    }

    #[tokio::test]
    async fn reads_content_length_response_with_reason_and_raw_headers() {
        let mut wire: &[u8] =
            b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 3\r\nX-Case: Kept\r\n\r\nabcEXTRA";
        let response = read_response(&mut wire, false).await.expect("response");
        assert_eq!(response.status_line(), "HTTP/1.1 302 Found");
        assert_eq!(
            response.headers,
            headers(&[
                ("Location", "/next"),
                ("Content-Length", "3"),
                ("X-Case", "Kept")
            ])
        );
        assert_eq!(response.body, b"abc");
    }

    #[tokio::test]
    async fn reads_chunked_close_delimited_head_and_interim_responses() {
        let mut chunked: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: t\r\n\r\n";
        assert_eq!(
            read_response(&mut chunked, false)
                .await
                .expect("chunked")
                .body,
            b"Wikipedia"
        );
        let mut close: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nuntil-close";
        let response = read_response(&mut close, false).await.expect("close");
        assert_eq!(response.version, "HTTP/1.0");
        assert_eq!(response.body, b"until-close");
        let mut head: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n";
        assert!(
            read_response(&mut head, true)
                .await
                .expect("head")
                .body
                .is_empty()
        );
        let mut interim: &[u8] =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        let response = read_response(&mut interim, false).await.expect("interim");
        assert_eq!(response.status_line(), "HTTP/1.1 201 Created");
    }

    #[tokio::test]
    async fn truncated_body_is_an_error_not_a_short_success() {
        let mut short: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert!(read_response(&mut short, false).await.is_err());
    }
}
