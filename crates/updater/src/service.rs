//! The update service the engine runs: the daily check, the verified download,
//! and staging an install.
//!
//! Privacy contract (restated on the Trust page): when checks are on, the only
//! request is a plain `GET` of the static manifest, once at startup and once
//! every 24 hours, carrying nothing but `User-Agent: apiaxess/<version>
//! (<os>-<arch>)` — no query, no cookie, no identifier. When checks are off, the
//! service makes no request at all. Redirects are followed only within the
//! manifest's own origin, and failures are silent (retried on the next tick).

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use url::Url;

use crate::{
    channel::InstallChannel,
    fetch::{Download, Fetcher},
    handoff::{self, InstallHandoff, InstallWhen},
    manifest::{self, ReleaseAsset, ReleaseManifest},
    verify,
};

/// Where the release manifest is published.
pub const DEFAULT_MANIFEST_URL: &str = "https://apiaxess.dev/releases/latest.json";

/// How often the check repeats.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Everything the service needs to know about this install.
#[derive(Clone, Debug)]
pub struct UpdateConfig {
    /// The manifest URL; assets and redirects must stay on its origin.
    pub manifest_url: Url,
    /// The check interval.
    pub interval: Duration,
    /// The running version.
    pub current_version: semver::Version,
    /// How this copy was installed.
    pub channel: InstallChannel,
    /// Where downloads and the install handoff live.
    pub updates_dir: PathBuf,
    /// The key manifests must be signed with, once one is embedded.
    pub public_key: Option<[u8; 32]>,
    /// The only header the check sends.
    pub user_agent: String,
}

impl UpdateConfig {
    /// The production configuration for `current_version`, with the test-only
    /// overrides `APIAXESS_UPDATE_MANIFEST_URL` (an `https` URL, or `http` on a
    /// loopback address) and `APIAXESS_UPDATE_INTERVAL_SECS` (at least 10).
    ///
    /// # Errors
    ///
    /// Returns why the version, an override, or the public key is unusable.
    pub fn from_env(current_version: &str) -> Result<Self, String> {
        let manifest_url = match std::env::var("APIAXESS_UPDATE_MANIFEST_URL") {
            Ok(value) if !value.trim().is_empty() => parse_manifest_url(value.trim())?,
            _ => Url::parse(DEFAULT_MANIFEST_URL).map_err(|error| error.to_string())?,
        };
        let interval = match std::env::var("APIAXESS_UPDATE_INTERVAL_SECS") {
            Ok(value) if !value.trim().is_empty() => value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|seconds| *seconds >= 10)
                .map(Duration::from_secs)
                .ok_or(
                    "APIAXESS_UPDATE_INTERVAL_SECS must be a whole number of seconds, at least 10",
                )?,
            _ => DEFAULT_INTERVAL,
        };
        let current_version = semver::Version::parse(current_version).map_err(|error| {
            format!("the running version {current_version:?} is not semver: {error}")
        })?;
        Ok(Self {
            manifest_url,
            interval,
            user_agent: user_agent(&current_version),
            current_version,
            channel: InstallChannel::detect(),
            updates_dir: handoff::updates_dir(),
            public_key: verify::manifest_public_key()?,
        })
    }
}

/// `apiaxess/<version> (<os>-<arch>)`: what the server needs to pick an asset,
/// and nothing that identifies the machine or the person.
#[must_use]
pub fn user_agent(version: &semver::Version) -> String {
    format!(
        "apiaxess/{version} ({}-{})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Parses a test-only URL override from `variable`: `https`, or `http` on a
/// loopback address (a local test server).
pub(crate) fn parse_test_url(variable: &str, value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|error| format!("{variable}: {error}"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(name)) => name == "localhost",
        None => false,
    };
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(format!(
            "{variable} must be https (http only on a loopback address)"
        )),
    }
}

fn parse_manifest_url(value: &str) -> Result<Url, String> {
    parse_test_url("APIAXESS_UPDATE_MANIFEST_URL", value)
}

/// Whether the manifest was signature-checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    /// No release key is embedded yet: the manifest is trusted on HTTPS alone
    /// (the downloaded asset's SHA-256 is still required).
    NotRequired,
    /// A release key is embedded: a manifest is trusted only once its ed25519
    /// signature verifies against it (a failure shows as the check's error).
    Required,
}

/// The newer release the last check found.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableUpdate {
    /// Its version.
    pub version: String,
    /// Its release date.
    pub released: Option<String>,
    /// What changed, in a line.
    pub summary: Option<String>,
    /// The release notes.
    pub notes_url: Option<String>,
    /// Whether this version can update to it in place (`min_supported`).
    pub supported: bool,
    /// The asset for this install's channel, when the release has one.
    pub asset: Option<AssetView>,
}

/// An asset as the GUI shows it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetView {
    /// Its file name.
    pub name: String,
    /// Its URL.
    pub url: String,
    /// Its published SHA-256.
    pub sha256: String,
    /// Its size in bytes (`0` when unpublished).
    pub size: u64,
}

/// Progress of the in-app download.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum DownloadState {
    /// Nothing downloaded.
    Idle,
    /// Downloading.
    Downloading {
        /// Bytes received.
        received: u64,
        /// Bytes expected (`0` when unknown).
        total: u64,
    },
    /// Downloaded and SHA-256-verified.
    Ready {
        /// The verified file.
        path: String,
    },
    /// The download failed or did not verify; nothing was kept.
    Failed {
        /// What went wrong.
        message: String,
    },
}

/// The outcome of the last in-app install, reported once after the relaunch.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastInstall {
    /// The version installed.
    pub version: String,
    /// Whether it installed.
    pub succeeded: bool,
    /// What to tell the operator.
    pub message: String,
}

/// Everything the Settings line and the banner show.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    /// Whether update checks are on.
    pub enabled: bool,
    /// The running version.
    pub current_version: String,
    /// How this copy was installed.
    pub channel: InstallChannel,
    /// Whether a check is running now.
    pub checking: bool,
    /// When the last check ran (this launch).
    pub last_checked: Option<DateTime<Utc>>,
    /// Why the last check failed, if it did.
    pub last_error: Option<String>,
    /// Whether the manifest's signature was checked.
    pub signature: SignatureState,
    /// The newer release, when there is one.
    pub available: Option<AvailableUpdate>,
    /// The download's progress.
    pub download: DownloadState,
    /// The command that updates this install, for package-manager channels.
    pub command: Option<String>,
    /// Whether an install is scheduled for when this session ends.
    pub scheduled: bool,
    /// The last in-app install's outcome, once, after it ran.
    pub last_install: Option<LastInstall>,
    /// What is running that an install would interrupt (filled in by the API).
    pub busy: Vec<String>,
}

struct State {
    checking: bool,
    last_checked: Option<DateTime<Utc>>,
    last_error: Option<String>,
    signature: SignatureState,
    manifest: Option<ReleaseManifest>,
    download: DownloadState,
    scheduled: bool,
    last_install: Option<LastInstall>,
}

struct Inner {
    config: Option<UpdateConfig>,
    enabled: Box<dyn Fn() -> bool + Send + Sync>,
    state: Mutex<State>,
    wake: tokio::sync::Notify,
    exit: tokio::sync::watch::Sender<Option<i32>>,
}

/// The engine's update service. Cheap to clone; all clones share state.
#[derive(Clone)]
pub struct UpdateService {
    inner: Arc<Inner>,
}

impl UpdateService {
    /// A service for `config`, checking only while `enabled` returns `true`.
    /// Reports the previous in-app install's outcome and clears leftovers from
    /// it (partial downloads, installers for versions already installed).
    #[must_use]
    pub fn new(config: UpdateConfig, enabled: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        let last_install = handoff::take_install_result(&config.updates_dir)
            .map(|result| last_install_report(result, &config.current_version));
        clean_updates_dir(&config.updates_dir, &config.current_version);
        let scheduled = handoff::read_handoff(&config.updates_dir)
            .is_some_and(|pending| pending.when == InstallWhen::Deferred);
        Self::build(Some(config), Box::new(enabled), last_install, scheduled)
    }

    /// A service that never checks (routers built without the engine's
    /// composition root, such as in tests).
    #[must_use]
    pub fn inert() -> Self {
        Self::build(None, Box::new(|| false), None, false)
    }

    fn build(
        config: Option<UpdateConfig>,
        enabled: Box<dyn Fn() -> bool + Send + Sync>,
        last_install: Option<LastInstall>,
        scheduled: bool,
    ) -> Self {
        let signature = if config
            .as_ref()
            .is_some_and(|config| config.public_key.is_some())
        {
            SignatureState::Required
        } else {
            SignatureState::NotRequired
        };
        Self {
            inner: Arc::new(Inner {
                config,
                enabled,
                state: Mutex::new(State {
                    checking: false,
                    last_checked: None,
                    last_error: None,
                    signature,
                    manifest: None,
                    download: DownloadState::Idle,
                    scheduled,
                    last_install,
                }),
                wake: tokio::sync::Notify::new(),
                exit: tokio::sync::watch::channel(None).0,
            }),
        }
    }

    /// Whether checks are on (always off for an inert service).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.inner.config.is_some() && (self.inner.enabled)()
    }

    /// The current status (with `busy` empty; the API fills it in).
    #[must_use]
    pub fn status(&self) -> UpdateStatus {
        let enabled = self.enabled();
        let (current_version, channel) = self.inner.config.as_ref().map_or_else(
            || (env_version(), InstallChannel::Source),
            |config| (config.current_version.to_string(), config.channel),
        );
        let Ok(state) = self.inner.state.lock() else {
            return UpdateStatus {
                enabled,
                current_version,
                channel,
                checking: false,
                last_checked: None,
                last_error: Some("update state is unavailable".to_owned()),
                signature: SignatureState::NotRequired,
                available: None,
                download: DownloadState::Idle,
                command: None,
                scheduled: false,
                last_install: None,
                busy: Vec::new(),
            };
        };
        let available = self.available_from(state.manifest.as_ref());
        let downloaded = match &state.download {
            DownloadState::Ready { path } => Some(PathBuf::from(path)),
            _ => None,
        };
        let command = available
            .as_ref()
            .and_then(|_| channel.update_command(downloaded.as_deref()));
        UpdateStatus {
            enabled,
            current_version,
            channel,
            checking: state.checking,
            last_checked: state.last_checked,
            last_error: state.last_error.clone(),
            signature: state.signature,
            available,
            download: state.download.clone(),
            command,
            scheduled: state.scheduled,
            last_install: state.last_install.clone(),
            busy: Vec::new(),
        }
    }

    fn available_from(&self, manifest: Option<&ReleaseManifest>) -> Option<AvailableUpdate> {
        let config = self.inner.config.as_ref()?;
        let manifest = manifest?;
        if !manifest.is_newer_than(&config.current_version) {
            return None;
        }
        let asset = self.channel_asset(manifest).and_then(|(asset, url)| {
            Some(AssetView {
                name: manifest::asset_file_name(&url)?,
                url: asset.url.clone(),
                sha256: asset.sha256.to_ascii_lowercase(),
                size: asset.size,
            })
        });
        Some(AvailableUpdate {
            version: manifest.version.clone(),
            released: manifest.released.clone(),
            summary: manifest.summary.clone(),
            notes_url: manifest.notes_url.clone(),
            supported: manifest.supports_update_from(&config.current_version),
            asset,
        })
    }

    fn channel_asset<'a>(&self, manifest: &'a ReleaseManifest) -> Option<(&'a ReleaseAsset, Url)> {
        let config = self.inner.config.as_ref()?;
        let asset = manifest.assets.get(config.channel.asset_key()?)?;
        let url = manifest::same_origin_url(&asset.url, &config.manifest_url).ok()?;
        Some((asset, url))
    }

    /// Re-evaluates the schedule now (checks were switched on or off).
    pub fn wake(&self) {
        self.inner.wake.notify_one();
    }

    /// Runs the check at startup and then every interval while checks are on.
    /// Switching checks on (see [`Self::wake`]) checks right away when one is
    /// due. Needs a Tokio runtime.
    pub fn spawn_scheduler(&self) {
        let Some(interval) = self.inner.config.as_ref().map(|config| config.interval) else {
            return;
        };
        let service = self.clone();
        tokio::spawn(async move {
            let mut last_attempt: Option<Instant> = None;
            loop {
                let due = last_attempt.is_none_or(|at| at.elapsed() >= interval);
                if due && service.enabled() {
                    service.check().await;
                    last_attempt = Some(Instant::now());
                }
                let wait =
                    last_attempt.map_or(interval, |at| interval.saturating_sub(at.elapsed()));
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = service.inner.wake.notified() => {}
                }
            }
        });
    }

    /// Checks now, on request. Makes no request when checks are off.
    ///
    /// # Errors
    ///
    /// Returns why no check ran.
    pub async fn check_now(&self) -> Result<UpdateStatus, String> {
        if !self.enabled() {
            return Err(
                "Update checks are off. Turn on \"Check for updates\" in Settings first."
                    .to_owned(),
            );
        }
        self.check().await;
        Ok(self.status())
    }

    async fn check(&self) {
        let Some(config) = self.inner.config.clone() else {
            return;
        };
        {
            let Ok(mut state) = self.inner.state.lock() else {
                return;
            };
            if state.checking {
                return;
            }
            state.checking = true;
        }
        let outcome = fetch_manifest(&config).await;
        let Ok(mut state) = self.inner.state.lock() else {
            return;
        };
        let previous = state
            .manifest
            .as_ref()
            .map(|manifest| manifest.version.clone());
        state.checking = false;
        state.last_checked = Some(Utc::now());
        match outcome {
            Ok(manifest) => {
                state.last_error = None;
                if previous.as_deref() != Some(manifest.version.as_str())
                    && !matches!(state.download, DownloadState::Downloading { .. })
                {
                    state.download = DownloadState::Idle;
                }
                state.manifest = Some(manifest);
            }
            // Offline-quiet: remembered for the Settings line, never raised.
            Err(why) => state.last_error = Some(why),
        }
    }

    /// Starts downloading and verifying this channel's asset in the background.
    /// A file already downloaded and matching its SHA-256 is reused.
    ///
    /// # Errors
    ///
    /// Returns why no download can start.
    pub fn start_download(&self) -> Result<(), String> {
        let config = self
            .inner
            .config
            .clone()
            .ok_or("updates are not available in this build")?;
        if !self.enabled() {
            return Err("Update checks are off.".to_owned());
        }
        if !config.channel.downloads_in_app() {
            return Err("This install is updated outside the app.".to_owned());
        }
        let (asset, url) = {
            let mut state = self
                .inner
                .state
                .lock()
                .map_err(|_| "update state is unavailable")?;
            let manifest = state
                .manifest
                .clone()
                .ok_or("No update has been found yet.")?;
            let available = self
                .available_from(Some(&manifest))
                .ok_or("APIaxess is up to date.")?;
            if !available.supported {
                return Err(format!(
                    "{} cannot update to {} in place; install it from apiaxess.dev.",
                    config.current_version, available.version
                ));
            }
            match state.download {
                DownloadState::Downloading { .. } | DownloadState::Ready { .. } => return Ok(()),
                DownloadState::Idle | DownloadState::Failed { .. } => {}
            }
            let (asset, url) = self
                .channel_asset(&manifest)
                .ok_or("The release has no package for this install.")?;
            state.download = DownloadState::Downloading {
                received: 0,
                total: asset.size,
            };
            (asset.clone(), url)
        };
        let service = self.clone();
        tokio::spawn(async move {
            let outcome = download_asset(&config, &asset, &url, |received| {
                if let Ok(mut state) = service.inner.state.lock() {
                    state.download = DownloadState::Downloading {
                        received,
                        total: asset.size,
                    };
                }
            })
            .await;
            if let Ok(mut state) = service.inner.state.lock() {
                state.download = match outcome {
                    Ok(path) => DownloadState::Ready {
                        path: path.display().to_string(),
                    },
                    Err(message) => DownloadState::Failed { message },
                };
            }
        });
        Ok(())
    }

    /// Writes the install handoff for the verified download.
    ///
    /// # Errors
    ///
    /// Returns why the update cannot be installed from the app.
    pub fn stage_install(
        &self,
        when: InstallWhen,
        resume_session: Option<PathBuf>,
    ) -> Result<InstallHandoff, String> {
        let config = self
            .inner
            .config
            .as_ref()
            .ok_or("updates are not available in this build")?;
        if !config.channel.installs_in_app() {
            return Err("This install is updated outside the app.".to_owned());
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "update state is unavailable")?;
        let DownloadState::Ready { path } = &state.download else {
            return Err("The update has not finished downloading and verifying.".to_owned());
        };
        let manifest = state
            .manifest
            .as_ref()
            .ok_or("No update has been found yet.")?;
        let asset = self
            .channel_asset(manifest)
            .map(|(asset, _)| asset.clone())
            .ok_or("The release has no package for this install.")?;
        let pending = InstallHandoff {
            version: manifest.version.clone(),
            installer: PathBuf::from(path),
            sha256: asset.sha256.to_ascii_lowercase(),
            resume_session,
            when,
        };
        handoff::write_handoff(&config.updates_dir, &pending)
            .map_err(|error| format!("the install could not be scheduled: {error}"))?;
        state.scheduled = when == InstallWhen::Deferred;
        Ok(pending)
    }

    /// Cancels a scheduled install.
    pub fn cancel_scheduled(&self) {
        if let Some(config) = &self.inner.config {
            handoff::clear_handoff(&config.updates_dir);
        }
        if let Ok(mut state) = self.inner.state.lock() {
            state.scheduled = false;
        }
    }

    /// The updates directory, when the service is configured.
    #[must_use]
    pub fn updates_dir(&self) -> Option<&Path> {
        self.inner
            .config
            .as_ref()
            .map(|config| config.updates_dir.as_path())
    }

    /// Asks the engine to shut down and exit with `code`.
    pub fn request_exit(&self, code: i32) {
        self.inner.exit.send_replace(Some(code));
    }

    /// The exit code requested through [`Self::request_exit`], if any.
    #[must_use]
    pub fn requested_exit(&self) -> Option<i32> {
        *self.inner.exit.borrow()
    }

    /// Resolves once an exit is requested.
    pub async fn exit_requested(&self) {
        let mut receiver = self.inner.exit.subscribe();
        let _ = receiver.wait_for(Option::is_some).await;
    }
}

/// What to tell the operator about the installer run recorded before this
/// launch: it only counts as updated when this version is the one installed.
fn last_install_report(result: handoff::InstallResult, current: &semver::Version) -> LastInstall {
    let installed =
        semver::Version::parse(&result.version).is_ok_and(|version| &version <= current);
    let log = result
        .log
        .as_ref()
        .map(|log| format!(" Installer log: {}", log.display()))
        .unwrap_or_default();
    let message = match (result.succeeded(), installed) {
        (true, true) => format!("APIaxess was updated to {}.", result.version),
        (true, false) => format!(
            "Windows Installer finished, but APIaxess is still {current}, not {}. Download the update again from Settings, or install it from apiaxess.dev.{log}",
            result.version
        ),
        (false, _) => format!(
            "The update to {} did not install (Windows Installer exit code {}). The previous version is still installed.{log}",
            result.version, result.exit_code
        ),
    };
    LastInstall {
        succeeded: result.succeeded() && installed,
        message,
        version: result.version,
    }
}

fn env_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Removes partial downloads and installers for versions already installed.
fn clean_updates_dir(dir: &Path, current: &semver::Version) {
    let pending = handoff::read_handoff(dir).map(|pending| pending.installer);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let stale_partial = name.ends_with(".partial");
        let installed = [".msi", ".deb", ".zip"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
            && file_version(&name).is_some_and(|version| &version <= current);
        if (stale_partial || installed) && pending.as_deref() != Some(path.as_path()) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The version in a release file name (`APIaxess-0.1.1-windows-x64.msi`,
/// `apiaxess_0.1.1_amd64.deb`).
fn file_version(name: &str) -> Option<semver::Version> {
    name.split(['-', '_'])
        .find_map(|part| semver::Version::parse(part).ok())
}

/// Fetches the manifest (and, when a key is embedded, its signature), and
/// trusts its contents only after the signature verifies.
async fn fetch_manifest(config: &UpdateConfig) -> Result<ReleaseManifest, String> {
    let fetcher = Fetcher::new(&config.manifest_url, &config.user_agent)?;
    let bytes = fetcher
        .fetch_signed(
            &config.manifest_url,
            manifest::MAX_MANIFEST_BYTES,
            config.public_key.as_ref(),
        )
        .await?;
    ReleaseManifest::parse(&bytes, &config.manifest_url).map_err(|error| error.to_string())
}

/// Downloads `asset` to the updates directory, kept only when its SHA-256
/// matches the manifest.
async fn download_asset(
    config: &UpdateConfig,
    asset: &ReleaseAsset,
    url: &Url,
    progress: impl Fn(u64),
) -> Result<PathBuf, String> {
    let fetcher = Fetcher::new(&config.manifest_url, &config.user_agent)?;
    fetcher
        .download(
            Download {
                url,
                sha256: &asset.sha256,
                size: asset.size,
                dir: &config.updates_dir,
                resumable: false,
            },
            progress,
            None,
        )
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
