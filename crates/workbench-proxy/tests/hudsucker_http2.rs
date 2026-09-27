//! Phase 11.3 wire-level proof that the embedded hudsucker backend carries the
//! HTTP/2 workflows that the removed mitmdump backend used to serve: TLS-ALPN
//! h2, stream multiplexing, gRPC trailers, and capture of h2 flows into the
//! durable store. These fixtures use raw TLS + h2 clients/servers and cross the
//! public proxy listener; nothing external is required (no Python, no mitmdump).

#![allow(clippy::cast_possible_truncation)]

use std::{error::Error, sync::Arc, time::Duration};

use apiaxess_workbench_proxy::{
    HudsuckerBackend, LiveWorkbench, ProxyBackend, ProxyConfig, ProxyHandle, SessionCa,
    TrafficStore,
};
use bytes::Bytes;
use h2::{RecvStream, server, server::SendResponse};
use http::{HeaderMap, Request, Response};
use hudsucker::certificate_authority::CertificateAuthority;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy)]
enum H2Case {
    Simple,
    Multiplex,
    Grpc,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hudsucker_carries_tls_alpn_http2() {
    let observation = run_h2_case(H2Case::Simple, None)
        .await
        .expect("hudsucker h2 simple");
    assert_eq!(observation.status, 200);
    assert_eq!(observation.body, b"h2-simple");
    assert_eq!(observation.alpn.as_deref(), Some(b"h2".as_slice()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hudsucker_carries_http2_stream_multiplexing() {
    let observation = run_h2_case(H2Case::Multiplex, None)
        .await
        .expect("hudsucker h2 multiplexing");
    assert_eq!(observation.status, 200);
    for stream in ["stream-1", "stream-2", "stream-3"] {
        assert!(
            observation
                .body
                .windows(stream.len())
                .any(|window| window == stream.as_bytes()),
            "multiplexed stream {stream} missing from {:?}",
            String::from_utf8_lossy(&observation.body)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hudsucker_preserves_grpc_trailers() {
    let observation = run_h2_case(H2Case::Grpc, None)
        .await
        .expect("hudsucker gRPC trailers");
    assert_eq!(observation.status, 200);
    assert!(
        observation
            .trailers
            .iter()
            .any(|(name, value)| name == "grpc-status" && value == "0"),
        "grpc-status trailer preserved through hudsucker: {:?}",
        observation.trailers
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hudsucker_captures_http2_flows_into_the_store() {
    let store_path = std::env::temp_dir().join(format!(
        "apiaxess-h2-capture-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let store =
        Arc::new(TrafficStore::open(&store_path, "session:h2-capture").expect("traffic store"));
    let workbench = Arc::new(LiveWorkbench::new());
    workbench.attach_store(Arc::clone(&store));

    let observation = run_h2_case(H2Case::Simple, Some(Arc::clone(&workbench)))
        .await
        .expect("hudsucker h2 capture");
    assert_eq!(observation.status, 200);

    let summaries = store.summaries().expect("traffic summaries");
    assert!(
        summaries.iter().any(
            |summary| summary.status == Some(200) && summary.path.as_deref() == Some("/simple")
        ),
        "h2 flow captured into the durable store: {summaries:?}"
    );
    drop(workbench);
    drop(store);
    let _ = std::fs::remove_dir_all(store_path);
}

/// Concurrency proof for the request↔response correlation fix: three multiplexed
/// h2 streams share ONE connection (one `client_addr`), and the upstream delays
/// `/stream-1` so responses return OUT OF ORDER. The upstream echoes each request
/// path as its response body, so each captured flow's response body must equal its
/// OWN request path. Under the former `client_addr`-keyed correlation every
/// response resolved to the last request's flow id and bodies were mis-attributed;
/// the per-request-clone correlation ties each response to its own request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hudsucker_correlates_multiplexed_h2_responses_to_the_right_request() {
    let store_path = std::env::temp_dir().join(format!(
        "apiaxess-h2-correlate-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let store =
        Arc::new(TrafficStore::open(&store_path, "session:h2-correlate").expect("traffic store"));
    let workbench = Arc::new(LiveWorkbench::new());
    workbench.attach_store(Arc::clone(&store));

    run_h2_case(H2Case::Multiplex, Some(Arc::clone(&workbench)))
        .await
        .expect("hudsucker h2 multiplex capture");
    // Let the response-body capture streams finish persisting.
    sleep(Duration::from_millis(300)).await;

    let summaries = store.summaries().expect("traffic summaries");
    let streams: std::collections::BTreeMap<String, u64> = summaries
        .iter()
        .filter_map(|summary| {
            summary
                .path
                .as_deref()
                .filter(|path| path.starts_with("/stream-"))
                .map(|path| (path.to_owned(), summary.id))
        })
        .collect();
    assert_eq!(
        streams.len(),
        3,
        "each multiplexed stream must be captured as its own flow: {summaries:?}"
    );
    // Every id is distinct (a single authoritative allocator, no collision).
    let ids: std::collections::BTreeSet<u64> = streams.values().copied().collect();
    assert_eq!(ids.len(), 3, "multiplexed flows must have unique ids");

    for (path, id) in streams {
        let flow = store.get(id).expect("read flow").expect("flow present");
        assert_eq!(flow.status, Some(200), "{path} status");
        assert_eq!(
            flow.response_body.as_deref(),
            Some(path.as_bytes()),
            "response for {path} must correlate to its OWN request (flow {id}), not another concurrent stream"
        );
    }

    drop(workbench);
    drop(store);
    let _ = std::fs::remove_dir_all(store_path);
}

#[derive(Clone, Debug)]
struct WireObservation {
    status: u16,
    body: Vec<u8>,
    trailers: Vec<(String, String)>,
    alpn: Option<Vec<u8>>,
}

async fn run_h2_case(
    case: H2Case,
    observer: Option<Arc<LiveWorkbench>>,
) -> TestResult<WireObservation> {
    let ca = SessionCa::generate().map_err(|error| error.to_string())?;
    let (upstream, server_task) = spawn_h2_upstream(case, ca.clone()).await?;
    let handle = start_proxy(ca.clone(), observer).await?;
    let result = async {
        let socket = connect_tunnel(handle.local_addr(), upstream).await?;
        let connector = TlsConnector::from(Arc::new(client_config(vec![b"h2".to_vec()])?));
        let tls = connector
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err("client TLS did not negotiate h2 with the proxy".into());
        }
        let (mut client, connection) = h2::client::handshake(tls).await?;
        let connection_task = tokio::spawn(connection);
        let authority = format!("localhost:{}", upstream.port());
        let observation = match case {
            H2Case::Simple => h2_simple(&mut client, &authority).await?,
            H2Case::Multiplex => h2_multiplex(&mut client, &authority).await?,
            H2Case::Grpc => h2_grpc(&mut client, &authority).await?,
        };
        drop(client);
        let _ = timeout(Duration::from_secs(3), connection_task).await;
        Ok(observation)
    }
    .await;
    timeout(Duration::from_secs(5), handle.shutdown()).await??;
    server_task.abort();
    let _ = server_task.await;
    result
}

async fn start_proxy(
    ca: SessionCa,
    observer: Option<Arc<LiveWorkbench>>,
) -> TestResult<ProxyHandle> {
    let observer: Arc<dyn apiaxess_workbench_proxy::FlowObserver> = match observer {
        Some(workbench) => workbench,
        None => Arc::new(apiaxess_workbench_proxy::NoopObserver),
    };
    HudsuckerBackend
        .start(
            ProxyConfig {
                session_id: "session:h2-proof".to_owned(),
                bind_addr: "127.0.0.1:0".parse()?,
                ca,
                intercept: None,
                capture_browser_listener: false,
            },
            observer,
        )
        .await
        .map_err(|error| Box::<dyn Error + Send + Sync>::from(error.to_string()))
}

async fn h2_simple(
    client: &mut h2::client::SendRequest<Bytes>,
    authority: &str,
) -> TestResult<WireObservation> {
    let (response, _) = client.send_request(
        Request::builder()
            .uri(format!("https://{authority}/simple"))
            .body(())?,
        true,
    )?;
    let response = response.await?;
    let status = response.status().as_u16();
    let body = collect_body(response.into_body()).await?;
    Ok(WireObservation {
        status,
        body,
        trailers: Vec::new(),
        alpn: Some(b"h2".to_vec()),
    })
}

async fn h2_multiplex(
    client: &mut h2::client::SendRequest<Bytes>,
    authority: &str,
) -> TestResult<WireObservation> {
    let mut responses = Vec::new();
    for index in 1..=3 {
        let (response, _) = client.send_request(
            Request::builder()
                .uri(format!("https://{authority}/stream-{index}"))
                .body(())?,
            true,
        )?;
        responses.push(response);
    }
    let mut bodies = Vec::new();
    for response in responses {
        bodies.push(collect_body(response.await?.into_body()).await?);
    }
    bodies.sort();
    Ok(WireObservation {
        status: 200,
        body: bodies.concat(),
        trailers: Vec::new(),
        alpn: Some(b"h2".to_vec()),
    })
}

async fn h2_grpc(
    client: &mut h2::client::SendRequest<Bytes>,
    authority: &str,
) -> TestResult<WireObservation> {
    let (response, mut stream) = client.send_request(
        Request::builder()
            .uri(format!("https://{authority}/grpc.Test/Call"))
            .header("content-type", "application/grpc")
            .body(())?,
        false,
    )?;
    stream.send_data(Bytes::from_static(b"\0\0\0\0\0"), true)?;
    let response = response.await?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        data.extend_from_slice(&chunk?);
    }
    let trailers = body
        .trailers()
        .await?
        .unwrap_or_default()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    Ok(WireObservation {
        status,
        body: data,
        trailers,
        alpn: Some(b"h2".to_vec()),
    })
}

async fn collect_body(mut body: RecvStream) -> TestResult<Vec<u8>> {
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

async fn spawn_h2_upstream(
    case: H2Case,
    ca: SessionCa,
) -> TestResult<(std::net::SocketAddr, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let authority = format!("localhost:{}", address.port()).parse()?;
    let config = ca.gen_server_config(&authority).await;
    let task = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let acceptor = TlsAcceptor::from(config);
            if let Ok(tls) = acceptor.accept(socket).await {
                let _ = serve_h2(tls, case).await;
            }
        }
    });
    Ok((address, task))
}

async fn serve_h2<S>(io: S, case: H2Case) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut connection = server::Builder::new().handshake(io).await?;
    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        tokio::spawn(handle_h2_request(request, respond, case));
    }
    Ok(())
}

async fn handle_h2_request(
    mut request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    case: H2Case,
) -> TestResult<()> {
    let path = request.uri().path().to_owned();
    let body = request.body_mut();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        body.flow_control().release_capacity(chunk.len())?;
    }
    if matches!(case, H2Case::Multiplex) && path.ends_with("stream-1") {
        sleep(Duration::from_millis(80)).await;
    }
    let mut response = Response::builder().status(200);
    if matches!(case, H2Case::Grpc) {
        response = response.header("content-type", "application/grpc");
    }
    let mut send = respond.send_response(response.body(())?, false)?;
    match case {
        H2Case::Simple => send.send_data(Bytes::from_static(b"h2-simple"), true)?,
        H2Case::Multiplex => send.send_data(Bytes::copy_from_slice(path.as_bytes()), true)?,
        H2Case::Grpc => {
            send.send_data(Bytes::from_static(b"\0\0\0\0\0"), false)?;
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", "0".parse()?);
            trailers.insert("grpc-message", "ok".parse()?);
            send.send_trailers(trailers)?;
        }
    }
    Ok(())
}

async fn connect_tunnel(
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
) -> TestResult<TcpStream> {
    let mut socket = TcpStream::connect(proxy).await?;
    socket
        .write_all(
            format!(
                "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                upstream.port(),
                upstream.port()
            )
            .as_bytes(),
        )
        .await?;
    let response = read_headers(&mut socket).await?;
    if !response.starts_with(b"HTTP/1.1 200") {
        return Err(format!("CONNECT failed: {response:?}").into());
    }
    Ok(socket)
}

fn client_config(alpn: Vec<Vec<u8>>) -> TestResult<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
    .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(config)
}

async fn read_headers<S: AsyncRead + Unpin>(stream: &mut S) -> TestResult<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut output = Vec::new();
    let mut byte = [0_u8; 1];
    while output.len() < 16 * 1024 {
        stream.read_exact(&mut byte).await?;
        output.push(byte[0]);
        if output.ends_with(b"\r\n\r\n") {
            return Ok(output);
        }
    }
    Err("header exceeded 16 KiB".into())
}

#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}
