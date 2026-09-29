use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use base64::Engine as _;
use ring::signature::KeyPair as _;

use super::*;

const PAYLOAD: &[u8] = b"pretend this is an MSI";

/// One recorded request: path, query, headers.
type Recorded = (String, Option<String>, Vec<(String, String)>);

#[derive(Clone, Default)]
struct Server {
    requests: Arc<Mutex<Vec<Recorded>>>,
    manifest: Arc<Mutex<Vec<u8>>>,
    signature: Arc<Mutex<Vec<u8>>>,
}

impl Server {
    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

async fn record(State(server): State<Server>, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    server.requests.lock().unwrap().push((
        path.clone(),
        request.uri().query().map(str::to_owned),
        headers,
    ));
    match path.as_str() {
        "/releases/latest.json" => server.manifest.lock().unwrap().clone().into_response(),
        "/releases/latest.json.sig" => server.signature.lock().unwrap().clone().into_response(),
        "/dl/0.1.1/APIaxess-0.1.1-windows-x64.msi" => PAYLOAD.to_vec().into_response(),
        "/dl/0.1.1/elsewhere.msi" => {
            Redirect::temporary("http://localhost:9/evil.msi").into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn start() -> (Server, Url) {
    let server = Server::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(get(record))
        .with_state(server.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = Url::parse(&format!("http://{address}/releases/latest.json")).unwrap();
    (server, url)
}

fn manifest_json(base: &Url, file: &str, sha256: &str, size: usize) -> Vec<u8> {
    let origin = base.origin().ascii_serialization();
    format!(
        r#"{{"version":"0.1.1","released":"2026-10-07","notes_url":"{origin}/release-notes#0.1.1","summary":"Fixes.","min_supported":"0.1.0",
        "assets":{{"windows-x64-msi":{{"url":"{origin}/dl/0.1.1/{file}","sha256":"{sha256}","size":{size}}}}}}}"#
    )
    .into_bytes()
}

fn payload_sha() -> String {
    verify::hex(&Sha256::digest(PAYLOAD))
}

fn config(url: Url, name: &str) -> UpdateConfig {
    let dir = std::env::temp_dir().join(format!("apiaxess-updater-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    UpdateConfig {
        manifest_url: url,
        interval: Duration::from_secs(3600),
        current_version: semver::Version::parse("0.1.0").unwrap(),
        channel: InstallChannel::Msi,
        updates_dir: dir,
        public_key: None,
        user_agent: user_agent(&semver::Version::parse("0.1.0").unwrap()),
    }
}

async fn wait_for_download(service: &UpdateService) -> DownloadState {
    for _ in 0..200 {
        let state = service.status().download;
        if !matches!(state, DownloadState::Downloading { .. }) {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the download did not finish");
}

#[tokio::test]
async fn the_check_is_one_identifier_free_get_and_finds_the_update() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(
        &url,
        "APIaxess-0.1.1-windows-x64.msi",
        &payload_sha(),
        PAYLOAD.len(),
    );
    let service = UpdateService::new(config(url, "check"), || true);
    let status = service.check_now().await.unwrap();

    let requests = server.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let (path, query, headers) = &requests[0];
    assert_eq!(path, "/releases/latest.json");
    assert_eq!(query, &None);
    let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();
    assert!(
        !names.contains(&"cookie") && !names.contains(&"referer"),
        "{names:?}"
    );
    let agent = &headers
        .iter()
        .find(|(name, _)| name == "user-agent")
        .unwrap()
        .1;
    assert_eq!(
        agent,
        &format!(
            "apiaxess/0.1.0 ({}-{})",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    );
    for (name, _) in headers {
        assert!(
            ["host", "user-agent", "accept"].contains(&name.as_str()),
            "unexpected header {name}"
        );
    }

    let available = status.available.expect("0.1.1 is newer");
    assert_eq!(available.version, "0.1.1");
    assert!(available.supported);
    assert_eq!(
        available.asset.unwrap().name,
        "APIaxess-0.1.1-windows-x64.msi"
    );
    assert!(status.last_checked.is_some() && status.last_error.is_none());
    assert_eq!(status.signature, SignatureState::NotRequired);
}

#[tokio::test]
async fn checks_off_means_no_request_at_all() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(&url, "a.msi", &payload_sha(), 1);
    let enabled = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&enabled);
    let mut config = config(url, "off");
    config.interval = Duration::from_secs(10);
    let service = UpdateService::new(config, move || flag.load(Ordering::SeqCst));
    service.spawn_scheduler();
    assert!(service.check_now().await.is_err());
    assert!(service.start_download().is_err());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(server.requests().is_empty());

    // Switching checks on checks right away (it was never checked).
    enabled.store(true, Ordering::SeqCst);
    service.wake();
    for _ in 0..100 {
        if !server.requests().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(server.requests().len(), 1);
    // And not again until the interval passes.
    service.wake();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn a_verified_download_is_staged_for_install() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(
        &url,
        "APIaxess-0.1.1-windows-x64.msi",
        &payload_sha(),
        PAYLOAD.len(),
    );
    let config = config(url, "download");
    let dir = config.updates_dir.clone();
    let service = UpdateService::new(config, || true);
    service.check_now().await.unwrap();
    service.start_download().unwrap();
    let DownloadState::Ready { path } = wait_for_download(&service).await else {
        panic!("the download should verify");
    };
    assert_eq!(std::fs::read(&path).unwrap(), PAYLOAD);
    let staged = service.stage_install(InstallWhen::Deferred, None).unwrap();
    assert_eq!(staged.sha256, payload_sha());
    assert!(service.status().scheduled);
    assert_eq!(handoff::read_handoff(&dir), Some(staged));
    service.cancel_scheduled();
    assert!(handoff::read_handoff(&dir).is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_wrong_hash_aborts_and_keeps_nothing() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(
        &url,
        "APIaxess-0.1.1-windows-x64.msi",
        &"00".repeat(32),
        PAYLOAD.len(),
    );
    let config = config(url, "badhash");
    let dir = config.updates_dir.clone();
    let service = UpdateService::new(config, || true);
    service.check_now().await.unwrap();
    service.start_download().unwrap();
    let DownloadState::Failed { message } = wait_for_download(&service).await else {
        panic!("a wrong hash must fail");
    };
    assert!(
        message.contains("does not match its published SHA-256"),
        "{message}"
    );
    assert!(message.contains("nothing was installed"), "{message}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "no file may be kept"
    );
    assert!(service.stage_install(InstallWhen::Now, None).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_redirect_off_the_release_origin_is_refused() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(&url, "elsewhere.msi", &payload_sha(), 0);
    let service = UpdateService::new(config(url, "redirect"), || true);
    service.check_now().await.unwrap();
    service.start_download().unwrap();
    let DownloadState::Failed { message } = wait_for_download(&service).await else {
        panic!("an off-origin redirect must fail");
    };
    assert!(message.contains("could not reach"), "{message}");
}

#[tokio::test]
async fn with_a_key_embedded_only_a_signed_manifest_is_trusted() {
    let (server, url) = start().await;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let manifest = manifest_json(
        &url,
        "APIaxess-0.1.1-windows-x64.msi",
        &payload_sha(),
        PAYLOAD.len(),
    );
    *server.manifest.lock().unwrap() = manifest.clone();
    let mut config = config(url, "signed");
    config.public_key = Some(pair.public_key().as_ref().try_into().unwrap());

    // A signature over different bytes: refused, nothing trusted.
    let forged = base64::engine::general_purpose::STANDARD.encode(pair.sign(b"{}"));
    *server.signature.lock().unwrap() = forged.into_bytes();
    let service = UpdateService::new(config.clone(), || true);
    let status = service.check_now().await.unwrap();
    assert!(status.available.is_none());
    assert!(
        status
            .last_error
            .unwrap()
            .contains("signature does not match")
    );

    // No signature at all: refused.
    server.signature.lock().unwrap().clear();
    assert!(service.check_now().await.unwrap().available.is_none());

    // The right signature over the exact served bytes: trusted.
    let good = base64::engine::general_purpose::STANDARD.encode(pair.sign(&manifest));
    *server.signature.lock().unwrap() = good.into_bytes();
    let status = service.check_now().await.unwrap();
    assert_eq!(status.available.unwrap().version, "0.1.1");
    assert_eq!(status.signature, SignatureState::Required);
    let paths: Vec<String> = server
        .requests()
        .into_iter()
        .map(|(path, _, _)| path)
        .collect();
    assert!(paths.contains(&"/releases/latest.json.sig".to_owned()));
}

#[tokio::test]
async fn an_up_to_date_install_offers_nothing() {
    let (server, url) = start().await;
    *server.manifest.lock().unwrap() = manifest_json(&url, "a.msi", &payload_sha(), 1);
    let mut config = config(url, "current");
    config.current_version = semver::Version::parse("0.1.1").unwrap();
    let service = UpdateService::new(config, || true);
    assert!(service.check_now().await.unwrap().available.is_none());
    assert!(service.start_download().is_err());
}

#[test]
fn manifest_url_overrides_must_be_https_or_loopback() {
    assert!(parse_manifest_url("https://staging.apiaxess.dev/releases/latest.json").is_ok());
    assert!(parse_manifest_url("http://127.0.0.1:8000/releases/latest.json").is_ok());
    assert!(parse_manifest_url("http://localhost:8000/latest.json").is_ok());
    assert!(parse_manifest_url("http://apiaxess.dev/releases/latest.json").is_err());
    assert!(parse_manifest_url("file:///tmp/latest.json").is_err());
}

#[test]
fn stale_installers_are_cleaned_after_an_update() {
    let dir = std::env::temp_dir().join(format!("apiaxess-updater-clean-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "APIaxess-0.1.1-windows-x64.msi",
        "APIaxess-0.1.2-windows-x64.msi",
        "x.msi.partial",
        "notes.txt",
    ] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    clean_updates_dir(&dir, &semver::Version::parse("0.1.1").unwrap());
    let mut left: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["APIaxess-0.1.2-windows-x64.msi", "notes.txt"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_install_report_only_claims_an_update_that_happened() {
    let result = |version: &str, exit_code| handoff::InstallResult {
        version: version.to_owned(),
        exit_code,
        log: None,
    };
    let current = semver::Version::parse("0.1.1").unwrap();
    let done = last_install_report(result("0.1.1", 0), &current);
    assert!(done.succeeded);
    assert_eq!(done.message, "APIaxess was updated to 0.1.1.");
    let rebooting = last_install_report(result("0.1.1", 3010), &current);
    assert!(rebooting.succeeded);
    let unchanged = last_install_report(result("0.1.2", 0), &current);
    assert!(!unchanged.succeeded);
    assert!(
        unchanged.message.contains("still 0.1.1, not 0.1.2"),
        "{}",
        unchanged.message
    );
    let failed = last_install_report(result("0.1.2", 1603), &current);
    assert!(!failed.succeeded);
    assert!(
        failed.message.contains("exit code 1603"),
        "{}",
        failed.message
    );
}
