//! Wire-level proof that the transparent front-end delivers L3-redirected
//! (no-CONNECT) traffic to hudsucker and that the flow is captured into the
//! durable store — the exact case that the APK dynamic route exercises.
//!
//! A local origin-form HTTP request (what a transparently redirected Android
//! client sends) is pushed at the front-end; the flow must land in the store.

use std::sync::Arc;
use std::time::Duration;

use apiaxess_workbench_proxy::{
    HudsuckerBackend, LiveWorkbench, ProxyBackend, ProxyConfig, SessionCa, TrafficStore,
    TransparentFrontend,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Minimal upstream that answers any request with `200 ok`, so hudsucker's
/// forward completes and the flow is recorded.
async fn spawn_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
    let addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
                let _ = socket.read(&mut buffer).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transparent_frontend_captures_redirected_origin_form_http() {
    let upstream = spawn_upstream().await;

    let store_path = std::env::temp_dir().join(format!(
        "apiaxess-transparent-http-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let store =
        Arc::new(TrafficStore::open(&store_path, "session:transparent-http").expect("store"));
    let workbench = Arc::new(LiveWorkbench::new());
    workbench.attach_store(Arc::clone(&store));

    let ca = SessionCa::generate().expect("ca");
    let observer: Arc<dyn apiaxess_workbench_proxy::FlowObserver> = workbench.clone();
    let handle = HudsuckerBackend
        .start(
            ProxyConfig {
                session_id: "session:transparent-http".to_owned(),
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                ca,
                intercept: None,
            },
            observer,
        )
        .await
        .expect("hudsucker start");
    let hudsucker_addr = handle.local_addr();

    let frontend = TransparentFrontend::start(hudsucker_addr)
        .await
        .expect("frontend start");

    // A transparently redirected Android client speaks origin-form HTTP to what
    // it believes is the origin server (no CONNECT). Host carries the target.
    // The front-end binds 0.0.0.0 (reached in production via the emulator's
    // 10.0.2.2 host alias); connect over loopback for the test.
    let frontend_loopback =
        std::net::SocketAddr::from(([127, 0, 0, 1], frontend.local_addr().port()));
    let mut client = TcpStream::connect(frontend_loopback)
        .await
        .expect("connect frontend");
    let request = format!(
        "GET /tphttp HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("send request");
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;

    // Allow the observer's async persist to settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let summaries = store.summaries().expect("summaries");
    assert!(
        summaries
            .iter()
            .any(|summary| summary.path.as_deref() == Some("/tphttp")),
        "redirected origin-form HTTP was not captured into the store: {summaries:?}"
    );

    frontend.shutdown().await;
    drop(workbench);
    drop(store);
    let _ = std::fs::remove_dir_all(store_path);
}
