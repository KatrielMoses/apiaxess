//! Disposable browser process ownership and loopback CDP bootstrap.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
    path::Path,
    thread,
    time::{Duration, Instant},
};

use apiaxess_external_tools::{ManagedProcess, ManagedProcessCommand};
use serde::Deserialize;
use serde_json::json;
use tungstenite::{Message, client::IntoClientRequest, connect};

/// A browser child wrapped in an OS process boundary.
pub(crate) type BrowserChild = ManagedProcess;

/// Spawns a browser in a process group or Windows Job Object.
pub(crate) fn spawn_browser(command: ManagedProcessCommand) -> io::Result<BrowserChild> {
    command.spawn().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not create the browser process boundary: {error}"),
        )
    })
}

#[derive(Debug, Deserialize)]
struct DevToolsPage {
    #[serde(rename = "type")]
    page_type: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    websocket_url: Option<String>,
}

/// Waits for the browser's loopback-only `DevTools` endpoint and navigates the
/// already-created page through CDP. The browser is not considered ready until
/// both the endpoint and a page websocket are available.
pub(crate) fn bootstrap_cdp(profile: &Path, target: &str) -> Result<u16, String> {
    let active_port = profile.join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_error = String::from("DevToolsActivePort has not been created");
    while Instant::now() < deadline {
        match read_active_port(&active_port) {
            Ok(port) => match pages(port) {
                Ok(pages) => {
                    if let Some(websocket_url) = pages
                        .into_iter()
                        .find(|page| page.page_type == "page")
                        .and_then(|page| page.websocket_url)
                    {
                        navigate(&websocket_url, target)?;
                        return Ok(port);
                    }
                    last_error = String::from("the browser CDP endpoint has no page target");
                }
                Err(error) => last_error = error,
            },
            Err(error) => last_error = error,
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(last_error)
}

fn read_active_port(path: &Path) -> Result<u16, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let port = contents
        .lines()
        .next()
        .ok_or_else(|| String::from("DevToolsActivePort is empty"))?
        .parse::<u16>()
        .map_err(|error| format!("DevToolsActivePort contains an invalid port: {error}"))?;
    if port == 0 {
        return Err(String::from("DevToolsActivePort selected port zero"));
    }
    Ok(port)
}

fn pages(port: u16) -> Result<Vec<DevToolsPage>, String> {
    let body = http_get(port, "/json/list")?;
    serde_json::from_slice(&body)
        .map_err(|error| format!("CDP page list was invalid JSON: {error}"))
}

fn http_get(port: u16, path: &str) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|error| format!("could not connect to loopback CDP port {port}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| format!("could not configure CDP read timeout: {error}"))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("could not query CDP: {error}"))?;
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response_body_complete(&response) {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => break,
            Err(error) => return Err(format!("could not read CDP response: {error}")),
        }
        if Instant::now() >= deadline {
            break;
        }
    }
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            format!(
                "CDP returned a malformed HTTP response (prefix: {:?})",
                String::from_utf8_lossy(&response[..response.len().min(256)])
            )
        })?;
    let body = &response[separator + 4..];
    Ok(body.to_vec())
}

fn response_body_complete(response: &[u8]) -> bool {
    let Some(separator) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&response[..separator]);
    let Some(content_length) = headers.lines().find_map(|line| {
        line.strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
    }) else {
        return false;
    };
    response.len() >= separator + 4 + content_length
}

/// Injected at document-start on every page so that anyone looking at the
/// capture browser can tell, at a glance, that `APIaxess` opened it and is
/// recording — a persistent brand marker (a top accent rule + a corner pill),
/// mirroring how tools like Burp brand their bundled browser. The marker is
/// inert (`pointer-events:none`) and idempotent so it never interferes with the
/// page under test.
const CAPTURE_WATERMARK_JS: &str = r#"(function(){if(window.__apiaxessMarker)return;window.__apiaxessMarker=true;function mount(){try{var root=document.documentElement;if(!root)return;if(document.getElementById('apiaxess-capture-marker'))return;var bar=document.createElement('div');bar.id='apiaxess-capture-marker';bar.style.cssText='position:fixed;top:0;left:0;right:0;height:3px;background:#2d7ff9;z-index:2147483647;pointer-events:none;';var pill=document.createElement('div');pill.id='apiaxess-capture-pill';pill.style.cssText='position:fixed;bottom:12px;right:12px;display:flex;align-items:center;gap:6px;padding:5px 10px;background:#0d0d0d;color:#f0f0f0;font:600 12px/1 -apple-system,Segoe UI,Roboto,Arial,sans-serif;border:1px solid #2d7ff9;border-radius:4px;z-index:2147483647;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.45);opacity:.92;letter-spacing:.02em;';pill.innerHTML='<span style=\"color:#2d7ff9;font-size:13px;line-height:1;\">◆</span> APIaxess capture';root.appendChild(bar);root.appendChild(pill);}catch(e){}}mount();if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',mount);}window.addEventListener('load',mount);})();"#;

fn navigate(websocket_url: &str, target: &str) -> Result<(), String> {
    let mut request = websocket_url
        .into_client_request()
        .map_err(|error| format!("could not build the CDP websocket request: {error}"))?;
    // Chromium's DevTools endpoint is a loopback control channel, not a web
    // origin. Chromium 154 rejects the Origin header that generic websocket
    // clients commonly add, so make the omission explicit at this boundary.
    request.headers_mut().remove("origin");
    let (mut socket, _) = connect(request)
        .map_err(|error| format!("could not establish the CDP websocket: {error}"))?;
    // Order matters: enable the Page domain and register the brand marker as a
    // document-start script BEFORE navigating, so the very first document the
    // navigation creates already carries the watermark. Every later navigation
    // re-runs it too.
    for command in [
        json!({ "id": 1, "method": "Page.enable" }),
        json!({
            "id": 2,
            "method": "Page.addScriptToEvaluateOnNewDocument",
            "params": { "source": CAPTURE_WATERMARK_JS },
        }),
        json!({
            "id": 3,
            "method": "Page.navigate",
            "params": { "url": target },
        }),
    ] {
        socket
            .send(Message::Text(command.to_string().into()))
            .map_err(|error| format!("could not issue CDP command: {error}"))?;
    }
    // The frames are flushed to the OS by `send`; a brief settle lets Chromium's
    // websocket reader consume all three (the document-start script must be
    // registered before the navigation it applies to) before we close the
    // control channel.
    thread::sleep(Duration::from_millis(200));
    socket
        .close(None)
        .map_err(|error| format!("could not close the CDP websocket: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{http_get, navigate};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    #[test]
    fn cdp_navigation_handshake_omits_origin() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(
                !request
                    .lines()
                    .any(|line| { line.to_ascii_lowercase().starts_with("origin:") })
            );
            let key = request
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Sec-WebSocket-Key: ")
                        .or_else(|| line.strip_prefix("sec-websocket-key: "))
                })
                .unwrap();
            let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
            write!(
                stream,
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .unwrap();
            stream
        });

        navigate(&format!("ws://{address}"), "https://example.com/").unwrap();
        drop(server.join().unwrap());
    }

    #[test]
    fn cdp_endpoint_query_includes_dynamic_loopback_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains(&format!("Host: 127.0.0.1:{}", address.port())));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            .unwrap();
            // Keep the socket open briefly: the client must honor the
            // length-delimited response instead of waiting for EOF.
            thread::sleep(Duration::from_millis(250));
        });

        assert_eq!(http_get(address.port(), "/json/list").unwrap(), b"ok");
        server.join().unwrap();
    }
}
