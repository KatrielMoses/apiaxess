use std::sync::atomic::AtomicUsize;

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use sha2::{Digest as _, Sha256};

use super::*;

/// A tiny payload shaped like the analysis runtime: an emulator, an AVD
/// pointer with the assembly machine's absolute path, and a version file.
fn payload_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut add = |path: &str, body: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, path, body).unwrap();
    };
    add("emulator/emulator.exe", b"emulator");
    add(
        "avd/apiaxess-android-10.ini",
        b"avd.ini.encoding=UTF-8\npath=C:\\build\\analysis-runtime\\avd\\apiaxess-android-10.avd\ntarget=android-29\n",
    );
    add(
        "avd/apiaxess-android-10.avd/config.ini",
        b"image.sysdir.1=system-images\\android-29\\default\\x86_64\\\n",
    );
    add("analysis-runtime-version.txt", b"1.0.0-android10\n");
    let tar = builder.into_inner().unwrap();
    zstd::encode_all(tar.as_slice(), 3).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    crate::verify::hex(&Sha256::digest(bytes))
}

/// One recorded request: path and `Range` header.
type Hit = (String, Option<String>);

#[derive(Clone)]
struct Server {
    catalog: Arc<Mutex<Vec<u8>>>,
    artifact: Arc<Vec<u8>>,
    hits: Arc<Mutex<Vec<Hit>>>,
    /// Stop sending after this many bytes (simulates a dropped connection).
    cut_after: Arc<AtomicUsize>,
}

async fn serve(State(server): State<Server>, headers: HeaderMap, request: Request) -> Response {
    let path = request.uri().path().to_owned();
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    server
        .hits
        .lock()
        .unwrap()
        .push((path.clone(), range.clone()));
    match path.as_str() {
        "/assets/index.json" => server.catalog.lock().unwrap().clone().into_response(),
        "/assets/analysis-runtime/1.0.0-android10/analysis-runtime-test.tar.zst" => {
            let cut = server.cut_after.load(Ordering::SeqCst);
            let offset = range
                .as_deref()
                .and_then(|range| range.strip_prefix("bytes="))
                .and_then(|range| range.trim_end_matches('-').parse::<usize>().ok());
            match offset {
                Some(offset) => (
                    StatusCode::PARTIAL_CONTENT,
                    server.artifact[offset..].to_vec(),
                )
                    .into_response(),
                None if cut > 0 => server.artifact[..cut].to_vec().into_response(),
                None => server.artifact.to_vec().into_response(),
            }
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn start(artifact: Vec<u8>) -> (Server, Url) {
    let server = Server {
        catalog: Arc::new(Mutex::new(Vec::new())),
        artifact: Arc::new(artifact),
        hits: Arc::new(Mutex::new(Vec::new())),
        cut_after: Arc::new(AtomicUsize::new(0)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(get(serve))
        .with_state(server.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        server,
        Url::parse(&format!("http://{address}/assets/index.json")).unwrap(),
    )
}

fn catalog_json(origin: &Url, sha256: &str, size: usize) -> Vec<u8> {
    let origin = origin.origin().ascii_serialization();
    format!(
        r#"{{"assets":{{"analysis-runtime":{{"name":"Android analysis runtime","purpose":"Dynamic APK analysis","version":"1.0.0-android10",
        "platforms":{{"test-platform":{{"url":"{origin}/assets/analysis-runtime/1.0.0-android10/analysis-runtime-test.tar.zst","sha256":"{sha256}","size":{size},"installed_size":1000}}}}}}}}}}"#
    )
    .into_bytes()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("apiaxess-assets-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(
    url: Url,
    dir: &Path,
    env_key: &'static str,
    free: fn(&Path) -> Option<u64>,
) -> AssetConfig {
    let install_dir = dir.join("data").join("analysis-runtime");
    let resolved = install_dir.clone();
    AssetConfig {
        catalog_url: url,
        user_agent: "apiaxess/0.1.0 (test)".to_owned(),
        public_key: Ok(None),
        platform: Some("test-platform"),
        download_dir: dir.join("data").join("downloads"),
        free_space: free,
        slots: vec![AddonSlot {
            slug: "analysis-runtime",
            name: "Android analysis runtime",
            purpose: "Dynamic APK analysis",
            env_key,
            install_dir,
            resolved: Box::new(move || resolved.clone()),
            present: Box::new(|root| {
                root.join("emulator/emulator.exe").is_file()
                    && root.join("avd/apiaxess-android-10.ini").is_file()
            }),
            outdated: Box::new(|_| None),
            runtime_free_bytes: Box::new(|| 0),
        }],
    }
}

const UNSET: &str = "APIAXESS_TEST_UNSET_OVERRIDE_VARIABLE";

async fn wait_done(service: &AssetService) -> JobState {
    for _ in 0..400 {
        let job = service.status().addons[0].job.clone();
        if !job.is_active() {
            return job;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("the install did not finish");
}

#[tokio::test]
async fn a_download_installs_verified_and_relocated_and_lights_the_feature_up() {
    let archive = payload_archive();
    let (server, url) = start(archive.clone()).await;
    *server.catalog.lock().unwrap() = catalog_json(&url, &hex(&archive), archive.len());
    let dir = scratch("install");
    let service = AssetService::new(config(url, &dir, UNSET, |_| None));

    let before = service.status();
    assert!(!before.addons[0].installed);
    assert!(
        before.catalog_fetched.is_none(),
        "nothing is fetched until asked"
    );
    assert!(server.hits.lock().unwrap().is_empty());

    service.start_install("analysis-runtime").await.unwrap();
    assert_eq!(
        wait_done(&service).await,
        JobState::Installed {
            version: "1.0.0-android10".to_owned()
        }
    );
    let view = &service.status().addons[0];
    assert!(view.installed);
    assert_eq!(view.installed_version.as_deref(), Some("1.0.0-android10"));
    assert_eq!(view.available.as_ref().unwrap().size, archive.len() as u64);

    let root = dir.join("data").join("analysis-runtime");
    let ini = std::fs::read_to_string(root.join("avd/apiaxess-android-10.ini")).unwrap();
    let expected = format!(
        "path={}",
        root.join("avd").join("apiaxess-android-10.avd").display()
    );
    assert!(ini.lines().any(|line| line == expected), "{ini}");
    assert!(!ini.contains("C:\\build"), "{ini}");
    assert!(root.join(RECEIPT_FILE).is_file());
    // The artifact is removed once installed; no staging is left behind.
    assert_eq!(
        std::fs::read_dir(dir.join("data").join("downloads"))
            .unwrap()
            .count(),
        0
    );
    assert!(!dir.join("data").join("analysis-runtime.staging").exists());

    let paths: Vec<String> = server
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|(path, _)| path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            "/assets/index.json",
            "/assets/analysis-runtime/1.0.0-android10/analysis-runtime-test.tar.zst"
        ]
    );

    // Installing again replaces the old copy in place.
    service.start_install("analysis-runtime").await.unwrap();
    assert!(matches!(
        wait_done(&service).await,
        JobState::Installed { .. }
    ));
    assert!(!dir.join("data").join("analysis-runtime.previous").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_tampered_artifact_installs_nothing_and_cleans_up() {
    let archive = payload_archive();
    let (server, url) = start(archive.clone()).await;
    *server.catalog.lock().unwrap() = catalog_json(&url, &"ab".repeat(32), archive.len());
    let dir = scratch("tampered");
    let service = AssetService::new(config(url, &dir, UNSET, |_| None));
    service.start_install("analysis-runtime").await.unwrap();
    let JobState::Failed { message, resumable } = wait_done(&service).await else {
        panic!("a wrong hash must fail");
    };
    assert!(
        message.contains("does not match its published SHA-256"),
        "{message}"
    );
    assert!(!resumable, "a wrong hash keeps nothing to resume");
    assert!(!dir.join("data").join("analysis-runtime").exists());
    assert_eq!(
        std::fs::read_dir(dir.join("data").join("downloads"))
            .unwrap()
            .count(),
        0
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_interrupted_download_resumes_with_a_range_request() {
    let archive = payload_archive();
    let (server, url) = start(archive.clone()).await;
    *server.catalog.lock().unwrap() = catalog_json(&url, &hex(&archive), archive.len());
    let dir = scratch("resume");
    let service = AssetService::new(config(url, &dir, UNSET, |_| None));
    let half = archive.len() / 2;
    server.cut_after.store(half, Ordering::SeqCst);
    service.start_install("analysis-runtime").await.unwrap();
    let JobState::Failed { resumable, .. } = wait_done(&service).await else {
        panic!("a short download must fail");
    };
    assert!(resumable);
    let partial = dir
        .join("data")
        .join("downloads")
        .join("analysis-runtime-test.tar.zst.partial");
    assert_eq!(std::fs::metadata(&partial).unwrap().len(), half as u64);

    server.cut_after.store(0, Ordering::SeqCst);
    service.start_install("analysis-runtime").await.unwrap();
    assert!(matches!(
        wait_done(&service).await,
        JobState::Installed { .. }
    ));
    let ranges: Vec<Option<String>> = server
        .hits
        .lock()
        .unwrap()
        .iter()
        .map(|(_, range)| range.clone())
        .collect();
    assert!(
        ranges.contains(&Some(format!("bytes={half}-"))),
        "{ranges:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn an_override_low_disk_or_unknown_platform_refuses_before_downloading() {
    let archive = payload_archive();
    let (server, url) = start(archive.clone()).await;
    *server.catalog.lock().unwrap() = catalog_json(&url, &hex(&archive), archive.len());
    let dir = scratch("refuse");

    // PATH is always set: stands in for an operator's APIAXESS_* override.
    let managed = AssetService::new(config(url.clone(), &dir, "PATH", |_| None));
    let why = managed.start_install("analysis-runtime").await.unwrap_err();
    assert!(why.contains("managed outside the app"), "{why}");
    assert_eq!(
        managed.status().addons[0].overridden_by.as_deref(),
        Some("PATH")
    );
    assert!(
        server.hits.lock().unwrap().is_empty(),
        "an override makes no request"
    );

    let full = AssetService::new(config(url.clone(), &dir, UNSET, |_| Some(10)));
    let why = full.start_install("analysis-runtime").await.unwrap_err();
    assert!(why.contains("free on the drive"), "{why}");
    assert_eq!(
        server.hits.lock().unwrap().len(),
        1,
        "only the catalog was fetched"
    );

    let mut badly_keyed = config(url.clone(), &dir, UNSET, |_| None);
    badly_keyed.public_key = Err("the update public key is not base64".to_owned());
    let why = AssetService::new(badly_keyed)
        .start_install("analysis-runtime")
        .await
        .unwrap_err();
    assert!(
        why.contains("not base64"),
        "a bad key trusts nothing: {why}"
    );

    let mut elsewhere = config(url, &dir, UNSET, |_| None);
    elsewhere.platform = Some("other-platform");
    let why = AssetService::new(elsewhere)
        .start_install("analysis-runtime")
        .await
        .unwrap_err();
    assert!(why.contains("not published for other-platform"), "{why}");
    assert!(!dir.join("data").join("analysis-runtime").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_catalog_must_stay_on_its_origin_and_ship_tar_zst() {
    let origin = Url::parse("https://apiaxess.dev/assets/index.json").unwrap();
    let good = catalog_json(&origin, &"ab".repeat(32), 10);
    let catalog = Catalog::parse(&good, &origin).unwrap();
    assert_eq!(
        catalog.assets["analysis-runtime"].platforms["test-platform"].installed_size,
        1000
    );
    let text = String::from_utf8(good).unwrap();
    for bad in [
        text.replace("https://apiaxess.dev", "https://mirror.example"),
        text.replace(".tar.zst", ".exe"),
        text.replace(&"ab".repeat(32), "abc"),
        "not json".to_owned(),
    ] {
        assert!(Catalog::parse(bad.as_bytes(), &origin).is_err(), "{bad}");
    }
}

/// A tar whose single entry has a raw (unvalidated) name and optional link.
fn raw_archive(name: &[u8], kind: tar::EntryType, link: Option<&str>) -> PathBuf {
    let mut header = tar::Header::new_gnu();
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.set_entry_type(kind);
    header.set_size(if kind == tar::EntryType::Regular {
        3
    } else {
        0
    });
    if let Some(link) = link {
        header.set_link_name(link).unwrap();
    }
    header.set_mode(0o644);
    header.set_cksum();
    let mut tar = header.as_bytes().to_vec();
    if kind == tar::EntryType::Regular {
        let mut block = vec![0_u8; 512];
        block[..3].copy_from_slice(b"bad");
        tar.extend(block);
    }
    tar.extend(vec![0_u8; 1024]);
    let path = std::env::temp_dir().join(format!(
        "apiaxess-raw-{}-{}.tar.zst",
        std::process::id(),
        hex(name).get(..8).unwrap_or_default()
    ));
    std::fs::write(&path, zstd::encode_all(tar.as_slice(), 3).unwrap()).unwrap();
    path
}

#[test]
fn hostile_archives_are_refused_and_write_nothing_outside() {
    let dir = scratch("hostile");
    let staging = dir.join("staging");
    let (read, cancel) = (AtomicU64::new(0), AtomicBool::new(false));
    for (name, kind, link) in [
        (&b"../escaped.txt"[..], tar::EntryType::Regular, None),
        (b"ok/../../escaped.txt", tar::EntryType::Regular, None),
        (b"link", tar::EntryType::Symlink, Some("../../outside")),
        (b"abs", tar::EntryType::Symlink, Some("/etc/passwd")),
        (b"device", tar::EntryType::Char, None),
    ] {
        let archive = raw_archive(name, kind, link);
        let result = extract_archive(&archive, &staging, &read, &cancel);
        assert!(
            result.is_err(),
            "{} must be refused",
            String::from_utf8_lossy(name)
        );
        let _ = std::fs::remove_file(archive);
    }
    assert!(!dir.join("escaped.txt").exists());
    assert!(!std::env::temp_dir().join("escaped.txt").exists());
    let inside = raw_archive(b"lib/libc.so", tar::EntryType::Symlink, Some("libc.so.1"));
    assert!(extract_archive(&inside, &staging, &read, &cancel).is_ok());
    let _ = std::fs::remove_file(inside);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn installed_version_reads_the_payload_file_then_the_receipt() {
    let dir = scratch("version");
    assert_eq!(installed_version("android-target", &dir), None);
    std::fs::write(dir.join(RECEIPT_FILE), br#"{"version":"1.0.0"}"#).unwrap();
    assert_eq!(
        installed_version("android-target", &dir).as_deref(),
        Some("1.0.0")
    );
    std::fs::write(dir.join("android-target-version.txt"), b"1.1.0-android13\n").unwrap();
    assert_eq!(
        installed_version("android-target", &dir).as_deref(),
        Some("1.1.0-android13")
    );
    let _ = std::fs::remove_dir_all(dir);
}
