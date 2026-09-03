//! Transparent-interception front-end for L3-redirected sandbox traffic.
//!
//! The APK dynamic-capture path routes guest traffic to the proxy with an
//! iptables OUTPUT DNAT (transparent redirect). Unlike an explicit proxy client
//! (Chromium with `-x`, which sends an HTTP `CONNECT`), a transparently
//! redirected TLS client opens the connection with a raw `ClientHello` and *no*
//! CONNECT — so the stock hudsucker MITM (which learns the destination from the
//! CONNECT authority) cannot present a certificate or intercept it. Plain HTTP
//! already works: hudsucker's `normalize_origin_form` recovers the target from
//! the `Host` header. TLS is the gap this front-end closes.
//!
//! This front-end sits in front of the sandbox hudsucker listener. For each
//! redirected connection it peeks the opening bytes:
//! * a **TLS `ClientHello`** -> parse the **SNI**, synthesize a
//!   `CONNECT <sni>:443` to hudsucker, then splice the buffered `ClientHello` and
//!   the rest of the stream. Hudsucker's proven explicit MITM path then engages
//!   unchanged (presents the leaf for `<sni>`, decrypts, captures).
//! * **anything else** (origin-/absolute-form HTTP, or an already-explicit
//!   CONNECT) -> passed straight through to hudsucker, which handles it.
//!
//! ## Why not `SO_ORIGINAL_DST`?
//! The classic transparent-proxy recovery (`getsockopt SO_ORIGINAL_DST`) only
//! works when the proxy runs in the same network namespace as the iptables
//! redirect. Here the DNAT happens **inside the Android guest** and the proxy
//! runs on the **host**, across the emulator's user-mode (SLIRP) NAT — the
//! host socket's original destination is the proxy's own address, not the
//! guest's target. (On the Windows host the option does not exist at all.) The
//! `ClientHello` **SNI** is the only signal that survives end-to-end, so it is the
//! authoritative recovery mechanism for this topology.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Largest opening buffer we will read while classifying a connection and, for
/// TLS, recovering the SNI. A `ClientHello` is bounded well under this.
const MAX_HELLO_BYTES: usize = 16 * 1024;

/// Running transparent front-end. Redirected connections target
/// [`TransparentFrontend::local_addr`]; each is converted (TLS) or passed
/// through (HTTP) to the explicit hudsucker listener supplied at [`start`].
///
/// [`start`]: TransparentFrontend::start
#[derive(Debug)]
pub struct TransparentFrontend {
    local_addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl TransparentFrontend {
    /// Binds the front-end and starts accepting redirected connections, each
    /// bridged to `explicit_proxy` (the sandbox hudsucker listener).
    ///
    /// # Errors
    ///
    /// Returns the bind error if the ephemeral listener cannot be created.
    pub async fn start(explicit_proxy: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        let local_addr = listener.local_addr()?;
        let (stop, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok((client, _peer)) => {
                            tokio::spawn(async move {
                                // A single misbehaving connection must never take
                                // down capture; errors are per-connection.
                                let _ = bridge_connection(client, explicit_proxy).await;
                            });
                        }
                        Err(_) => break,
                    },
                    _ = &mut stop_rx => break,
                }
            }
        });
        Ok(Self {
            local_addr,
            stop: Some(stop),
            task: Some(task),
        })
    }

    /// The address redirected guest traffic should target (used as the sandbox
    /// capture endpoint and the iptables redirect destination).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting and joins the listener task. Idempotent.
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for TransparentFrontend {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Bridges one redirected connection to the explicit hudsucker listener.
async fn bridge_connection(mut client: TcpStream, explicit_proxy: SocketAddr) -> io::Result<()> {
    let mut prefix = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let read = client.read(&mut chunk).await?;
    if read == 0 {
        return Ok(());
    }
    prefix.extend_from_slice(&chunk[..read]);

    let mut upstream = TcpStream::connect(explicit_proxy).await?;

    if looks_like_tls_client_hello(&prefix) {
        // Read the remainder of the ClientHello (it may span several segments)
        // so the SNI is present before we synthesize the CONNECT.
        read_full_record(&mut client, &mut prefix).await?;
        if let Some(host) = extract_sni(&prefix) {
            let connect = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
            upstream.write_all(connect.as_bytes()).await?;
            consume_connect_response(&mut upstream).await?;
            // Replay the buffered ClientHello, then hand the rest to hudsucker,
            // which now MITMs the TLS because it saw the CONNECT authority.
            upstream.write_all(&prefix).await?;
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
        }
        // No SNI: nothing to key the MITM on in this topology; drop the
        // connection rather than proxy blind (rare for modern clients).
        return Ok(());
    }

    // Plain HTTP (origin-/absolute-form) or an explicit CONNECT: hudsucker
    // handles all of these, so relay verbatim.
    upstream.write_all(&prefix).await?;
    let _ = copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

/// A TLS handshake record carrying a `ClientHello` begins `16 03 xx xx xx` at the
/// record layer and `01` (`ClientHello`) as the first handshake byte.
fn looks_like_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[5] == 0x01
}

/// Reads until the full TLS record (per its length header) is buffered, bounded
/// by [`MAX_HELLO_BYTES`]. Returns early once complete or on EOF.
async fn read_full_record(client: &mut TcpStream, prefix: &mut Vec<u8>) -> io::Result<()> {
    let target = tls_record_end(prefix);
    let mut chunk = [0u8; 4096];
    while prefix.len() < target.unwrap_or(usize::MAX) && prefix.len() < MAX_HELLO_BYTES {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        prefix.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// End offset (exclusive) of the first TLS record given its 5-byte header, or
/// `None` if the header is not yet present.
fn tls_record_end(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 {
        return None;
    }
    let record_len = (usize::from(bytes[3]) << 8) | usize::from(bytes[4]);
    Some(5 + record_len)
}

/// Extracts the SNI `host_name` from a buffered TLS `ClientHello` record, or `None`
/// if absent/malformed. Pure and bounds-checked so a hostile `ClientHello` cannot
/// panic or over-read.
#[must_use]
pub fn extract_sni(record: &[u8]) -> Option<String> {
    // Record header (5) + handshake header (4) then the ClientHello body.
    let mut position = 5usize + 4;
    // client_version (2) + random (32)
    position = position.checked_add(2 + 32)?;
    // session_id
    let session_id_len = usize::from(*record.get(position)?);
    position = position.checked_add(1 + session_id_len)?;
    // cipher_suites
    let cipher_len = read_u16(record, position)?;
    position = position.checked_add(2 + cipher_len)?;
    // compression_methods
    let compression_len = usize::from(*record.get(position)?);
    position = position.checked_add(1 + compression_len)?;
    // extensions block length, then the extensions themselves
    let extensions_len = read_u16(record, position)?;
    position = position.checked_add(2)?;
    let extensions_end = position.checked_add(extensions_len)?;
    if extensions_end > record.len() {
        return None;
    }
    while position + 4 <= extensions_end {
        let ext_type = read_u16(record, position)?;
        let ext_len = read_u16(record, position + 2)?;
        let ext_data = position + 4;
        let ext_end = ext_data.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name extension: server_name_list length (2), then entries
            // of name_type (1) + name_length (2) + name.
            let mut cursor = ext_data.checked_add(2)?; // skip list length
            while cursor + 3 <= ext_end {
                let name_type = *record.get(cursor)?;
                let name_len = read_u16(record, cursor + 1)?;
                let name_start = cursor + 3;
                let name_end = name_start.checked_add(name_len)?;
                if name_end > ext_end {
                    return None;
                }
                if name_type == 0 {
                    let name = record.get(name_start..name_end)?;
                    return std::str::from_utf8(name).ok().map(str::to_owned);
                }
                cursor = name_end;
            }
            return None;
        }
        position = ext_end;
    }
    None
}

fn read_u16(bytes: &[u8], at: usize) -> Option<usize> {
    let high = *bytes.get(at)?;
    let low = *bytes.get(at + 1)?;
    Some((usize::from(high) << 8) | usize::from(low))
}

/// Reads and discards hudsucker's `CONNECT` response (up to the blank line that
/// ends the status/headers), so the client's `ClientHello` aligns with the tunnel.
async fn consume_connect_response(upstream: &mut TcpStream) -> io::Result<()> {
    let mut seen = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while seen.windows(4).all(|window| window != b"\r\n\r\n") {
        let read = upstream.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        seen.push(byte[0]);
        if seen.len() > 8 * 1024 {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{extract_sni, looks_like_tls_client_hello};

    /// Builds a minimal but well-formed `ClientHello` record carrying one SNI
    /// `host_name`, exercising the exact field walk `extract_sni` performs.
    // Lengths here are all small, fixed test inputs (short hostnames and a
    // hand-built record), so the `usize`-to-`u16`/`u8` field-length casts cannot
    // truncate; the fixture mirrors the on-the-wire encoding verbatim.
    #[allow(clippy::cast_possible_truncation)]
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        // server_name entry: type(0) + len(u16) + host
        let mut server_name = vec![0u8];
        server_name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name.extend_from_slice(host);
        // server_name_list: list_len(u16) + entry
        let mut sni_ext_data = (server_name.len() as u16).to_be_bytes().to_vec();
        sni_ext_data.extend_from_slice(&server_name);
        // extension: type(0x0000) + len(u16) + data
        let mut extension = vec![0x00, 0x00];
        extension.extend_from_slice(&(sni_ext_data.len() as u16).to_be_bytes());
        extension.extend_from_slice(&sni_ext_data);
        // extensions block: len(u16) + extension
        let mut extensions = (extension.len() as u16).to_be_bytes().to_vec();
        extensions.extend_from_slice(&extension);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites: len 2 + one suite
        body.extend_from_slice(&[0x01, 0x00]); // compression: len 1 + null
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01]; // ClientHello
        handshake.extend_from_slice(&[
            0,
            (body.len() >> 8) as u8,
            (body.len() & 0xff) as u8,
        ]); // 24-bit length
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01]; // handshake, TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn detects_tls_client_hello() {
        let record = client_hello_with_sni("example.com");
        assert!(looks_like_tls_client_hello(&record));
        assert!(!looks_like_tls_client_hello(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn extracts_sni_host_name() {
        let record = client_hello_with_sni("mastodon.social");
        assert_eq!(extract_sni(&record).as_deref(), Some("mastodon.social"));
    }

    #[test]
    fn missing_sni_returns_none() {
        // An HTTP request is not a ClientHello and yields no SNI.
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
    }

    #[test]
    fn truncated_record_does_not_panic() {
        let mut record = client_hello_with_sni("example.com");
        record.truncate(20);
        let _ = extract_sni(&record);
    }
}
