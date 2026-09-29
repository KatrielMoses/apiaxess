//! Bundled, host-independent ffuf resolution (Phase 11.2).
//!
//! ffuf is a statically-linked Go binary with no runtime, so `APIaxess` bundles
//! the per-platform binary and invokes it by absolute path from the install
//! layout — the same posture as the bundled Chromium and the bundled Java
//! runtime + apktool/jadx (Phase 11.1). Discovery therefore needs no host ffuf.
//!
//! The launch also carries a controlled environment that confines ffuf's
//! config/history to an `APIaxess`-owned directory instead of the per-user
//! default config location, keeping runs self-contained and predictable.
//!
//! `APIAXESS_FFUF` remains an advanced override; the default requires nothing on
//! the host.

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

/// A resolved way to launch ffuf plus the environment that keeps its config and
/// history inside `APIaxess`-controlled directories.
pub(crate) struct FfufLaunch {
    /// Absolute path (or, for an operator override, name) of the ffuf binary.
    pub executable: String,
    /// Environment overrides applied to the ffuf process so it uses our data
    /// directories, not the per-user default config location.
    pub environment: Vec<(String, String)>,
    /// The bundled binary whose absence is an install-integrity failure. `None`
    /// when an operator supplied `APIAXESS_FFUF`.
    pub bundled_component: Option<BundledComponent>,
}

/// A component `APIaxess` bundles and owns, checked before ffuf is launched.
pub(crate) struct BundledComponent {
    /// Stable component label used in the diagnostic context.
    pub label: &'static str,
    /// Absolute path whose absence is an install-integrity failure.
    pub path: PathBuf,
}

/// Resolves ffuf from the install layout, honoring the `APIAXESS_FFUF` override.
pub(crate) fn resolve_ffuf() -> FfufLaunch {
    resolve_ffuf_with(env::var_os("APIAXESS_FFUF"), &resource_base())
}

/// The resolved ffuf executable path and whether an `APIAXESS_FFUF` override is in
/// effect. Exposed for the settings tool-availability panel so an operator can
/// see, before a run, whether the bundled discovery binary is present.
#[must_use]
pub fn resolved_ffuf() -> (String, bool) {
    let launch = resolve_ffuf();
    (launch.executable, launch.bundled_component.is_none())
}

/// Pure resolution: an explicit override wins; otherwise ffuf is the bundled
/// binary under `<base>/tools/ffuf/`. Separated from the environment lookups so
/// it is deterministically testable.
fn resolve_ffuf_with(override_path: Option<OsString>, base: &Path) -> FfufLaunch {
    let environment = controlled_environment();
    if let Some(configured) = override_path {
        return FfufLaunch {
            executable: PathBuf::from(configured).display().to_string(),
            environment,
            bundled_component: None,
        };
    }
    let bundled = base.join("tools").join("ffuf").join(ffuf_binary_name());
    FfufLaunch {
        executable: bundled.display().to_string(),
        environment,
        bundled_component: Some(BundledComponent {
            label: "ffuf",
            path: bundled,
        }),
    }
}

/// Points ffuf's config directory at an `APIaxess`-owned location. ffuf 2.x
/// derives it from `github.com/adrg/xdg`'s `ConfigHome`, which honours
/// `XDG_CONFIG_HOME` first on every platform (Windows, macOS and Linux) before
/// falling back to `%LOCALAPPDATA%`, `~/Library/Application Support` or
/// `~/.config`. Setting that one variable for the child confines ffuf's
/// `ffufrc`, history, scraper and autocalibration state without disturbing the
/// host's own ffuf.
fn controlled_environment() -> Vec<(String, String)> {
    let config_dir = apiaxess_install_layout::data_dir_or_temp().join("ffuf");
    // Best-effort: ffuf creates what it needs, but pre-creating keeps the path
    // present and predictable.
    let _ = std::fs::create_dir_all(&config_dir);
    vec![(
        CONFIG_HOME_VARIABLE.to_owned(),
        config_dir.display().to_string(),
    )]
}

/// The variable ffuf's config-directory lookup reads on every platform.
const CONFIG_HOME_VARIABLE: &str = "XDG_CONFIG_HOME";

/// The directory holding `tools/`: the shared install layout's resource base.
pub(crate) fn resource_base() -> PathBuf {
    apiaxess_install_layout::resource_base().unwrap_or_else(|| PathBuf::from("."))
}

fn ffuf_binary_name() -> &'static str {
    if cfg!(windows) { "ffuf.exe" } else { "ffuf" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_resolution_is_the_absolute_bundled_binary() {
        let base = Path::new(if cfg!(windows) {
            r"C:\opt\apiaxess"
        } else {
            "/opt/apiaxess"
        });
        let launch = resolve_ffuf_with(None, base);
        let component = launch
            .bundled_component
            .expect("bundled default carries an install-integrity component");
        assert_eq!(component.label, "ffuf");
        assert!(Path::new(&launch.executable).is_absolute());
        let expected_suffix = format!("tools/ffuf/{}", ffuf_binary_name());
        assert!(
            launch
                .executable
                .replace('\\', "/")
                .ends_with(expected_suffix.as_str())
        );
        assert_eq!(launch.executable, component.path.display().to_string());
    }

    #[test]
    fn override_replaces_the_binary_and_clears_the_integrity_component() {
        let base = Path::new("/opt/apiaxess");
        let launch = resolve_ffuf_with(Some(OsString::from("/usr/local/bin/ffuf")), base);
        assert_eq!(launch.executable, "/usr/local/bin/ffuf");
        assert!(
            launch.bundled_component.is_none(),
            "an operator override is not an install-integrity component"
        );
    }

    #[test]
    fn resolution_confines_ffuf_config_to_an_owned_directory() {
        let launch = resolve_ffuf_with(None, Path::new("/opt/apiaxess"));
        let (key, value) = launch
            .environment
            .iter()
            .find(|(key, _)| key == CONFIG_HOME_VARIABLE)
            .expect("controlled config directory is set");
        assert_eq!(key, CONFIG_HOME_VARIABLE);
        assert_eq!(
            PathBuf::from(value),
            apiaxess_install_layout::data_dir_or_temp().join("ffuf")
        );
        assert_eq!(
            launch.environment.len(),
            1,
            "only the config home is overridden; ffuf does not read APPDATA"
        );
    }

    /// Clean-host proof (Phase 11.2): the default `resolve_ffuf()` path runs a
    /// real directory-discovery sweep through the tool boundary using only the
    /// bundled binary by absolute path. Gated by `APIAXESS_BUNDLED_VERIFY=1`
    /// because it needs the staged ffuf binary (produced by
    /// `packaging/assets/fetch-ffuf.ps1`).
    #[test]
    #[allow(clippy::too_many_lines)]
    fn bundled_ffuf_runs_real_discovery() {
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        use apiaxess_external_tools::{
            ExternalToolRunner, ProcessToolRunner, ToolProbeRequest, ToolProcessRequest,
            ToolRequirement, ToolVersion,
        };

        if !matches!(
            std::env::var("APIAXESS_BUNDLED_VERIFY").as_deref(),
            Ok("1" | "true" | "yes")
        ) {
            eprintln!("skipping: set APIAXESS_BUNDLED_VERIFY=1 to run the bundled ffuf discovery");
            return;
        }

        // Stage the bundled binary at the default resolved location so this
        // exercises the real current_exe resolution, not an override.
        let launch = resolve_ffuf();
        let bundled = launch
            .bundled_component
            .as_ref()
            .expect("default resolution has a bundled component")
            .path
            .clone();
        if !bundled.is_file() {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/packaging")
                .join(if cfg!(windows) {
                    "ffuf-windows_x64"
                } else {
                    "ffuf-linux_x64"
                })
                .join(ffuf_binary_name());
            if !source.is_file() {
                eprintln!(
                    "skipping: staged ffuf not found at {} or {}; run fetch-ffuf.ps1",
                    bundled.display(),
                    source.display()
                );
                return;
            }
            std::fs::create_dir_all(bundled.parent().unwrap()).expect("create tools/ffuf");
            std::fs::copy(&source, &bundled).expect("stage ffuf binary");
        }

        // A tiny local target: 200 for /admin and /login, 404 otherwise.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local target");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("nonblocking listener");
            while !stop_server.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        std::thread::spawn(move || handle_probe(stream));
                    }
                    Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        let words = std::env::temp_dir().join(format!("apiaxess-ffuf-verify-{port}.txt"));
        std::fs::write(&words, "admin\nlogin\nnope\nsecret\n").expect("write wordlist");
        let output = std::env::temp_dir().join(format!("apiaxess-ffuf-verify-{port}.json"));
        let _ = std::fs::remove_file(&output);

        let runner = ProcessToolRunner;
        let probe = runner
            .probe(&ToolProbeRequest {
                tool_id: "ffuf".to_owned(),
                executable: launch.executable.clone(),
                version_arguments: vec!["-V".to_owned()],
                requirement: ToolRequirement {
                    minimum: ToolVersion {
                        major: 2,
                        minor: 0,
                        patch: 0,
                    },
                },
            })
            .expect("bundled ffuf probes");
        let process = runner
            .spawn(&ToolProcessRequest {
                probe,
                arguments: vec![
                    "-u".to_owned(),
                    format!("http://127.0.0.1:{port}/FUZZ"),
                    "-w".to_owned(),
                    words.display().to_string(),
                    "-of".to_owned(),
                    "json".to_owned(),
                    "-o".to_owned(),
                    output.display().to_string(),
                    "-noninteractive".to_owned(),
                    "-mc".to_owned(),
                    "200".to_owned(),
                ],
                working_directory: None,
                environment: launch.environment,
            })
            .expect("bundled ffuf spawns");
        let deadline = Instant::now() + Duration::from_secs(60);
        while process.is_running() {
            assert!(Instant::now() < deadline, "ffuf run exceeded its deadline");
            std::thread::sleep(Duration::from_millis(50));
        }
        stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", port));
        let _ = server.join();

        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output).expect("ffuf wrote json output"))
                .expect("ffuf json parses");
        let mut found: Vec<String> = parsed["results"]
            .as_array()
            .expect("results array")
            .iter()
            .filter_map(|entry| entry["input"]["FUZZ"].as_str().map(str::to_owned))
            .collect();
        found.sort();
        let _ = std::fs::remove_file(&words);
        let _ = std::fs::remove_file(&output);
        assert_eq!(
            found,
            vec!["admin".to_owned(), "login".to_owned()],
            "bundled ffuf must discover exactly the 200-status paths"
        );
        eprintln!(
            "bundled ffuf discovery OK: found {found:?} via {}",
            launch.executable
        );
    }

    fn handle_probe(mut stream: std::net::TcpStream) {
        use std::io::{Read, Write};
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer).unwrap_or(0);
        let request = String::from_utf8_lossy(&buffer[..read]);
        let path = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/");
        let status = if path == "/admin" || path == "/login" {
            "200 OK"
        } else {
            "404 Not Found"
        };
        let body = "x";
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}
