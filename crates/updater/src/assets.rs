//! On-demand add-ons from apiaxess.dev: the analysis runtime and the Android
//! target, each a single pre-assembled `.tar.zst` per platform.
//!
//! The release pipeline assembles each add-on from its pinned upstream parts,
//! uploads the finished artifact, and publishes `assets/index.json`. The app
//! only ever talks to apiaxess.dev: it fetches the catalog when the operator
//! clicks Download (never in the background), downloads the one artifact with
//! progress (resumable), keeps it only when its SHA-256 matches, extracts it
//! beside the destination, points the AVD at its new home, and swaps it into
//! place in one rename. An explicit `APIAXESS_*` override means the operator
//! manages that add-on themselves: the app never downloads over it.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    fetch::{Download, DownloadError, Fetcher},
    manifest,
};

/// Where the add-on catalog is published.
pub const DEFAULT_CATALOG_URL: &str = "https://apiaxess.dev/assets/index.json";

/// Largest catalog read.
pub const MAX_CATALOG_BYTES: usize = 256 * 1024;

/// The receipt an in-app install leaves in the add-on root.
pub const RECEIPT_FILE: &str = "apiaxess-asset.json";

/// `assets/index.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Catalog {
    /// Add-ons keyed by slug (`analysis-runtime`, `android-target`).
    pub assets: BTreeMap<String, CatalogAsset>,
}

/// One add-on in the catalog.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CatalogAsset {
    /// Display name.
    pub name: String,
    /// What it is for.
    #[serde(default)]
    pub purpose: Option<String>,
    /// The add-on's own version (independent of the app's).
    pub version: String,
    /// One artifact per platform (`windows-x64`, `linux-amd64`).
    #[serde(default)]
    pub platforms: BTreeMap<String, PlatformArtifact>,
}

/// One downloadable add-on artifact.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlatformArtifact {
    /// Where to download it; always on the catalog's own origin.
    pub url: String,
    /// Lowercase hex SHA-256 of the artifact. Required.
    pub sha256: String,
    /// Artifact size in bytes.
    #[serde(default)]
    pub size: u64,
    /// Size once extracted, in bytes (`0` when unpublished).
    #[serde(default)]
    pub installed_size: u64,
}

impl Catalog {
    /// Parses and validates the raw catalog bytes fetched from `origin`: every
    /// artifact must be a `.tar.zst` on the catalog's origin with a SHA-256.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the catalog.
    pub fn parse(bytes: &[u8], origin: &Url) -> Result<Self, String> {
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err("the add-on catalog is too large".to_owned());
        }
        let catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("the add-on catalog is not valid JSON: {error}"))?;
        for (slug, asset) in &catalog.assets {
            for (platform, artifact) in &asset.platforms {
                let url = manifest::same_origin_url(&artifact.url, origin)
                    .map_err(|error| format!("{slug} ({platform}): {error}"))?;
                if artifact.sha256.len() != 64
                    || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(format!("{slug} ({platform}) has no valid SHA-256"));
                }
                let name = manifest::asset_file_name(&url)
                    .ok_or_else(|| format!("{slug} ({platform}) has no safe file name"))?;
                if !name.ends_with(".tar.zst") {
                    return Err(format!("{slug} ({platform}) is not a .tar.zst artifact"));
                }
            }
        }
        Ok(catalog)
    }
}

/// The catalog's name for this platform, when add-ons exist for it.
#[must_use]
pub const fn platform_key() -> Option<&'static str> {
    if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-amd64")
    } else {
        None
    }
}

/// A question the engine answers about an add-on root.
pub type RootCheck<T> = Box<dyn Fn(&Path) -> T + Send + Sync>;

/// What the engine knows about one add-on it can download.
pub struct AddonSlot {
    /// Catalog slug.
    pub slug: &'static str,
    /// Display name, before the catalog is fetched.
    pub name: &'static str,
    /// What it is for.
    pub purpose: &'static str,
    /// The override variable that means "the operator manages this one".
    pub env_key: &'static str,
    /// Where a download installs it.
    pub install_dir: PathBuf,
    /// Where the engine resolves it right now.
    pub resolved: Box<dyn Fn() -> PathBuf + Send + Sync>,
    /// Whether a usable payload is at a root.
    pub present: RootCheck<bool>,
    /// When the payload at a root is too old for this engine, its version.
    pub outdated: RootCheck<Option<String>>,
    /// Free space the add-on needs to run once installed (the emulator's
    /// userdata), in bytes.
    pub runtime_free_bytes: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// Everything the service needs.
pub struct AssetConfig {
    /// The catalog URL; artifacts and redirects must stay on its origin.
    pub catalog_url: Url,
    /// The only header requests send.
    pub user_agent: String,
    /// The key the catalog must be signed with, once one is embedded. An
    /// unusable configured key is an error, and then no catalog is trusted.
    pub public_key: Result<Option<[u8; 32]>, String>,
    /// This platform's catalog key.
    pub platform: Option<&'static str>,
    /// Where artifacts download to before extraction.
    pub download_dir: PathBuf,
    /// Free bytes on the volume holding a path.
    pub free_space: fn(&Path) -> Option<u64>,
    /// The downloadable add-ons.
    pub slots: Vec<AddonSlot>,
}

impl AssetConfig {
    /// The catalog URL: the default, or the test-only
    /// `APIAXESS_ASSET_CATALOG_URL` (https, or http on loopback).
    ///
    /// # Errors
    ///
    /// Returns why the override is unusable.
    pub fn catalog_url_from_env() -> Result<Url, String> {
        match std::env::var("APIAXESS_ASSET_CATALOG_URL") {
            Ok(value) if !value.trim().is_empty() => {
                crate::service::parse_test_url("APIAXESS_ASSET_CATALOG_URL", value.trim())
            }
            _ => Url::parse(DEFAULT_CATALOG_URL).map_err(|error| error.to_string()),
        }
    }
}

/// What an add-on is doing right now.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "phase")]
pub enum JobState {
    /// Nothing running.
    Idle,
    /// Downloading the artifact (verifying it as it arrives).
    Downloading {
        /// Bytes held.
        received: u64,
        /// Bytes expected.
        total: u64,
    },
    /// Extracting it beside its destination.
    Extracting {
        /// Artifact bytes read.
        read: u64,
        /// Artifact size.
        total: u64,
    },
    /// Swapping it into place.
    Installing,
    /// Installed by this run.
    Installed {
        /// The installed version.
        version: String,
    },
    /// Stopped; `resumable` when a partial download was kept.
    Failed {
        /// What went wrong, and that nothing was installed.
        message: String,
        /// Whether the next Download continues where this one stopped.
        resumable: bool,
    },
}

/// One add-on as the Add-ons panel shows it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddonView {
    /// Catalog slug.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// What it is for.
    pub purpose: String,
    /// Whether a usable payload is where the engine looks.
    pub installed: bool,
    /// Its version, when installed.
    pub installed_version: Option<String>,
    /// When the installed payload is too old for this engine.
    pub outdated: bool,
    /// Where the engine looks.
    pub path: String,
    /// Where a download installs it.
    pub install_dir: String,
    /// The override variable, when set (the operator manages this add-on).
    pub overridden_by: Option<String>,
    /// The catalog's offer for this platform, once the catalog is fetched.
    pub available: Option<AvailableAddon>,
    /// What it is doing.
    pub job: JobState,
}

/// The catalog's offer for one add-on on this platform.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableAddon {
    /// Its version.
    pub version: String,
    /// Artifact size in bytes.
    pub size: u64,
    /// Extracted size in bytes (`0` when unpublished).
    pub installed_size: u64,
    /// The artifact URL.
    pub url: String,
    /// Its published SHA-256.
    pub sha256: String,
}

/// The Add-ons panel's data.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetsStatus {
    /// This platform's catalog key (`None`: no add-ons for this platform).
    pub platform: Option<String>,
    /// The catalog URL, for the "downloads only from" line.
    pub catalog_url: String,
    /// When the catalog was last fetched (this run).
    pub catalog_fetched: Option<DateTime<Utc>>,
    /// Why the last catalog fetch failed.
    pub catalog_error: Option<String>,
    /// Whether the catalog must be signed.
    pub signature_required: bool,
    /// The add-ons.
    pub addons: Vec<AddonView>,
}

struct Job {
    state: JobState,
    cancel: Arc<AtomicBool>,
}

/// The catalog as last fetched this run.
#[derive(Clone, Default)]
struct CatalogState {
    catalog: Option<Catalog>,
    fetched: Option<DateTime<Utc>>,
    error: Option<String>,
}

struct Inner {
    config: AssetConfig,
    catalog: Mutex<CatalogState>,
    jobs: Mutex<BTreeMap<&'static str, Job>>,
}

/// The engine's add-on service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct AssetService {
    inner: Arc<Inner>,
}

impl AssetService {
    /// A service over `config`. Nothing is fetched until asked.
    #[must_use]
    pub fn new(config: AssetConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                catalog: Mutex::new(CatalogState::default()),
                jobs: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn slot(&self, slug: &str) -> Option<&AddonSlot> {
        self.inner
            .config
            .slots
            .iter()
            .find(|slot| slot.slug == slug)
    }

    /// The Add-ons panel's data.
    #[must_use]
    pub fn status(&self) -> AssetsStatus {
        let config = &self.inner.config;
        let CatalogState {
            catalog,
            fetched,
            error,
        } = self.inner.catalog.lock().map_or_else(
            |_| CatalogState {
                error: Some("add-on state is unavailable".to_owned()),
                ..CatalogState::default()
            },
            |guard| guard.clone(),
        );
        let jobs = self.inner.jobs.lock().ok();
        let addons = config
            .slots
            .iter()
            .map(|slot| {
                let root = (slot.resolved)();
                let installed = (slot.present)(&root);
                let offer = catalog.as_ref().and_then(|catalog| {
                    let asset = catalog.assets.get(slot.slug)?;
                    let artifact = asset.platforms.get(config.platform?)?;
                    Some((asset, artifact))
                });
                AddonView {
                    slug: slot.slug.to_owned(),
                    name: offer
                        .map_or(slot.name, |(asset, _)| asset.name.as_str())
                        .to_owned(),
                    purpose: offer
                        .and_then(|(asset, _)| asset.purpose.clone())
                        .unwrap_or_else(|| slot.purpose.to_owned()),
                    installed,
                    installed_version: installed
                        .then(|| installed_version(slot.slug, &root))
                        .flatten(),
                    outdated: installed && (slot.outdated)(&root).is_some(),
                    path: root.display().to_string(),
                    install_dir: slot.install_dir.display().to_string(),
                    overridden_by: std::env::var_os(slot.env_key).map(|_| slot.env_key.to_owned()),
                    available: offer.map(|(asset, artifact)| AvailableAddon {
                        version: asset.version.clone(),
                        size: artifact.size,
                        installed_size: artifact.installed_size,
                        url: artifact.url.clone(),
                        sha256: artifact.sha256.to_ascii_lowercase(),
                    }),
                    job: jobs
                        .as_ref()
                        .and_then(|jobs| jobs.get(slot.slug).map(|job| job.state.clone()))
                        .unwrap_or(JobState::Idle),
                }
            })
            .collect();
        AssetsStatus {
            platform: config.platform.map(str::to_owned),
            catalog_url: config.catalog_url.to_string(),
            catalog_fetched: fetched,
            catalog_error: error,
            signature_required: !matches!(config.public_key, Ok(None)),
            addons,
        }
    }

    /// Fetches the catalog from apiaxess.dev (the operator asked for it).
    ///
    /// # Errors
    ///
    /// Returns why the catalog could not be fetched or trusted.
    pub async fn refresh_catalog(&self) -> Result<(), String> {
        let config = &self.inner.config;
        let outcome = async {
            let key = config.public_key.clone()?;
            let fetcher = Fetcher::new(&config.catalog_url, &config.user_agent)?;
            let bytes = fetcher
                .fetch_signed(&config.catalog_url, MAX_CATALOG_BYTES, key.as_ref())
                .await?;
            Catalog::parse(&bytes, &config.catalog_url)
        }
        .await;
        let mut guard = self
            .inner
            .catalog
            .lock()
            .map_err(|_| "add-on state is unavailable")?;
        match outcome {
            Ok(catalog) => {
                *guard = CatalogState {
                    catalog: Some(catalog),
                    fetched: Some(Utc::now()),
                    error: None,
                };
                Ok(())
            }
            Err(why) => {
                guard.fetched = Some(Utc::now());
                guard.error = Some(why.clone());
                Err(why)
            }
        }
    }

    /// Starts downloading and installing `slug` in the background. Fetches the
    /// catalog first when this run has not.
    ///
    /// # Errors
    ///
    /// Returns why the install cannot start (nothing is changed).
    pub async fn start_install(&self, slug: &str) -> Result<(), String> {
        let slot = self
            .slot(slug)
            .ok_or_else(|| format!("{slug} is not an add-on"))?;
        if std::env::var_os(slot.env_key).is_some() {
            return Err(format!(
                "{} is set, so this add-on is managed outside the app; unset it to download {} here.",
                slot.env_key, slot.name
            ));
        }
        let platform = self
            .inner
            .config
            .platform
            .ok_or("Add-ons are not published for this platform.")?;
        let has_catalog = self
            .inner
            .catalog
            .lock()
            .map(|guard| guard.catalog.is_some())
            .unwrap_or(false);
        if !has_catalog {
            self.refresh_catalog().await?;
        }
        let (version, artifact) = {
            let guard = self
                .inner
                .catalog
                .lock()
                .map_err(|_| "add-on state is unavailable")?;
            let asset = guard
                .catalog
                .as_ref()
                .and_then(|catalog| catalog.assets.get(slug))
                .ok_or_else(|| format!("apiaxess.dev does not offer {} yet.", slot.name))?;
            let artifact = asset
                .platforms
                .get(platform)
                .ok_or_else(|| format!("{} is not published for {platform}.", slot.name))?;
            (asset.version.clone(), artifact.clone())
        };
        self.preflight_space(slot, &artifact)?;
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut jobs = self
                .inner
                .jobs
                .lock()
                .map_err(|_| "add-on state is unavailable")?;
            if jobs.get(slot.slug).is_some_and(|job| job.state.is_active()) {
                return Ok(());
            }
            jobs.insert(
                slot.slug,
                Job {
                    state: JobState::Downloading {
                        received: 0,
                        total: artifact.size,
                    },
                    cancel: Arc::clone(&cancel),
                },
            );
        }
        let service = self.clone();
        let slug = slot.slug;
        tokio::spawn(async move {
            let outcome = service
                .run_install(slug, &version, &artifact, &cancel)
                .await;
            service.set_state(
                slug,
                match outcome {
                    Ok(()) => JobState::Installed { version },
                    Err(DownloadError::Cancelled) => JobState::Failed {
                        message: "Cancelled. The downloaded part is kept, so Download continues where it stopped.".to_owned(),
                        resumable: true,
                    },
                    Err(DownloadError::Failed(message)) => {
                        let resumable = service.partial_exists(&artifact);
                        JobState::Failed { message, resumable }
                    }
                },
            );
        });
        Ok(())
    }

    /// Stops a running download or extraction.
    pub fn cancel(&self, slug: &str) {
        if let Ok(jobs) = self.inner.jobs.lock()
            && let Some(job) = jobs.get(slug)
        {
            job.cancel.store(true, Ordering::Release);
        }
    }

    /// Whether any add-on job is running.
    #[must_use]
    pub fn busy(&self) -> bool {
        self.inner
            .jobs
            .lock()
            .is_ok_and(|jobs| jobs.values().any(|job| job.state.is_active()))
    }

    fn set_state(&self, slug: &'static str, state: JobState) {
        if let Ok(mut jobs) = self.inner.jobs.lock()
            && let Some(job) = jobs.get_mut(slug)
        {
            job.state = state;
        }
    }

    fn partial_exists(&self, artifact: &PlatformArtifact) -> bool {
        Url::parse(&artifact.url)
            .ok()
            .and_then(|url| manifest::asset_file_name(&url))
            .is_some_and(|name| {
                self.inner
                    .config
                    .download_dir
                    .join(format!("{name}.partial"))
                    .is_file()
            })
    }

    /// Refuses an install the disk cannot hold: the download, the extracted
    /// payload beside it, and the room the emulator needs to run afterwards.
    fn preflight_space(&self, slot: &AddonSlot, artifact: &PlatformArtifact) -> Result<(), String> {
        let extracted = if artifact.installed_size > 0 {
            artifact.installed_size
        } else {
            artifact.size.saturating_mul(3)
        };
        let needed = artifact
            .size
            .saturating_add(extracted)
            .saturating_add((slot.runtime_free_bytes)());
        let Some(free) = (self.inner.config.free_space)(&slot.install_dir) else {
            return Ok(());
        };
        if free < needed {
            return Err(format!(
                "{} needs about {} free on the drive holding {} (the download, the installed add-on, and room for the emulator to run); {} is free. Free up space, or install it elsewhere and point {} at it.",
                slot.name,
                gigabytes(needed),
                slot.install_dir.display(),
                gigabytes(free),
                slot.env_key
            ));
        }
        Ok(())
    }

    async fn run_install(
        &self,
        slug: &'static str,
        version: &str,
        artifact: &PlatformArtifact,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), DownloadError> {
        let config = &self.inner.config;
        let slot = self
            .slot(slug)
            .ok_or_else(|| DownloadError::Failed(format!("{slug} is not an add-on")))?;
        let fetcher = Fetcher::new(&config.catalog_url, &config.user_agent)?;
        let url = fetcher.same_origin(&artifact.url)?;
        let archive = fetcher
            .download(
                Download {
                    url: &url,
                    sha256: &artifact.sha256,
                    size: artifact.size,
                    dir: &config.download_dir,
                    resumable: true,
                },
                |received| {
                    self.set_state(
                        slug,
                        JobState::Downloading {
                            received,
                            total: artifact.size,
                        },
                    );
                },
                Some(cancel),
            )
            .await?;
        self.unpack_and_swap(slot, version, artifact, &archive, cancel)
            .await
    }

    /// Extracts a verified artifact beside the add-on's destination, checks it
    /// is complete, records the receipt, and swaps it into place.
    async fn unpack_and_swap(
        &self,
        slot: &AddonSlot,
        version: &str,
        artifact: &PlatformArtifact,
        archive: &Path,
        cancel: &Arc<AtomicBool>,
    ) -> Result<(), DownloadError> {
        let slug = slot.slug;
        let archive = archive.to_path_buf();
        let destination = slot.install_dir.clone();
        let staging = sibling(&destination, "staging");
        let read = Arc::new(AtomicU64::new(0));
        let size = artifact.size;
        let progress = {
            let service = self.clone();
            let read = Arc::clone(&read);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    let now = read.load(Ordering::Relaxed);
                    if now == u64::MAX {
                        break;
                    }
                    service.set_state(
                        slug,
                        JobState::Extracting {
                            read: now,
                            total: size,
                        },
                    );
                }
            })
        };
        self.set_state(
            slug,
            JobState::Extracting {
                read: 0,
                total: size,
            },
        );
        let extract = {
            let (archive, staging, destination, read, cancel) = (
                archive.clone(),
                staging.clone(),
                destination.clone(),
                Arc::clone(&read),
                Arc::clone(cancel),
            );
            tokio::task::spawn_blocking(move || {
                let outcome = extract_archive(&archive, &staging, &read, &cancel)
                    .and_then(|()| relocate_avds(&staging, &destination));
                read.store(u64::MAX, Ordering::Relaxed);
                outcome
            })
        };
        let extracted = extract
            .await
            .map_err(|error| DownloadError::Failed(format!("extraction stopped: {error}")))?;
        let _ = progress.await;
        if let Err(error) = extracted {
            let _ = std::fs::remove_dir_all(&staging);
            // A cancelled extraction keeps the verified download for next time.
            if cancel.load(Ordering::Acquire) {
                return Err(DownloadError::Cancelled);
            }
            let _ = std::fs::remove_file(&archive);
            return Err(DownloadError::Failed(format!(
                "the add-on could not be unpacked: {error}; nothing was installed"
            )));
        }
        if !(slot.present)(&staging) {
            let _ = std::fs::remove_dir_all(&staging);
            let _ = std::fs::remove_file(&archive);
            return Err(DownloadError::Failed(format!(
                "the downloaded artifact is not a complete {}; nothing was installed",
                slot.name
            )));
        }
        let receipt = serde_json::json!({
            "slug": slug,
            "version": version,
            "sha256": artifact.sha256.to_ascii_lowercase(),
            "source": artifact.url,
            "installedAt": Utc::now(),
        });
        let _ = std::fs::write(
            staging.join(RECEIPT_FILE),
            serde_json::to_vec_pretty(&receipt).unwrap_or_default(),
        );
        self.set_state(slug, JobState::Installing);
        let swapped = {
            let (staging, destination) = (staging.clone(), destination.clone());
            tokio::task::spawn_blocking(move || swap_into_place(&staging, &destination))
                .await
                .map_err(|error| DownloadError::Failed(error.to_string()))?
        };
        if let Err(error) = swapped {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(DownloadError::Failed(format!(
                "the add-on could not be moved into {} ({error}); the previous state was kept. Close anything using it (a running emulator) and try again.",
                destination.display()
            )));
        }
        // The multi-GB artifact is not needed once it is installed.
        let _ = std::fs::remove_file(&archive);
        Ok(())
    }
}

impl JobState {
    const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Downloading { .. } | Self::Extracting { .. } | Self::Installing
        )
    }
}

fn gigabytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // A display rounding.
    let value = bytes as f64 / 1_073_741_824.0;
    format!("{value:.1} GB")
}

/// The installed payload's version (`<slug>-version.txt`, which every
/// assembled payload carries), else the in-app receipt's.
#[must_use]
pub fn installed_version(slug: &str, root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join(format!("{slug}-version.txt")))
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .or_else(|| {
            let receipt: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join(RECEIPT_FILE)).ok()?).ok()?;
            receipt.get("version")?.as_str().map(str::to_owned)
        })
}

/// `<dir>.<suffix>` beside `dir`, on the same volume so the final rename is
/// atomic.
fn sibling(dir: &Path, suffix: &str) -> PathBuf {
    let name = dir.file_name().map_or_else(
        || "addon".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    dir.with_file_name(format!("{name}.{suffix}"))
}

/// Counts bytes read through it, for extraction progress, and stops the read
/// when cancelled.
struct Counting<'a, R> {
    inner: R,
    read: &'a AtomicU64,
    cancel: &'a AtomicBool,
}

impl<R: Read> Read for Counting<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.cancel.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        let read = self.inner.read(buffer)?;
        self.read.fetch_add(read as u64, Ordering::Relaxed);
        Ok(read)
    }
}

/// Whether an archive path stays inside the extraction root.
fn contained(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

/// Unpacks a `.tar.zst` into a fresh `staging` directory. Entries must be
/// plain files, directories, or symlinks whose path and link target stay
/// inside the root; anything else refuses the whole archive.
///
/// # Errors
///
/// Returns why the archive was refused or could not be written.
pub fn extract_archive(
    archive: &Path,
    staging: &Path,
    read: &AtomicU64,
    cancel: &AtomicBool,
) -> std::io::Result<()> {
    if staging.exists() {
        std::fs::remove_dir_all(staging)?;
    }
    std::fs::create_dir_all(staging)?;
    let file = std::fs::File::open(archive)?;
    let counting = Counting {
        inner: std::io::BufReader::new(file),
        read,
        cancel,
    };
    let decoder = zstd::stream::read::Decoder::new(counting)?;
    let mut tar = tar::Archive::new(decoder);
    tar.set_preserve_permissions(cfg!(unix));
    tar.set_overwrite(true);
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let refuse = |why: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} {why}", path.display()),
            )
        };
        if !contained(&path) {
            return Err(refuse("points outside the add-on"));
        }
        match entry.header().entry_type() {
            tar::EntryType::Regular | tar::EntryType::Directory => {}
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .ok_or_else(|| refuse("is a symlink with no target"))?;
                let resolved = path.parent().unwrap_or(Path::new("")).join(&target);
                if target.is_absolute() || !stays_inside(&resolved) {
                    return Err(refuse("links outside the add-on"));
                }
            }
            // PAX/GNU metadata records are consumed by the reader itself.
            tar::EntryType::XHeader | tar::EntryType::XGlobalHeader => continue,
            _ => return Err(refuse("is not a plain file, directory, or symlink")),
        }
        if !entry.unpack_in(staging)? {
            return Err(refuse("points outside the add-on"));
        }
    }
    Ok(())
}

/// Whether a relative path that may contain `..` still resolves inside its
/// root.
fn stays_inside(path: &Path) -> bool {
    let mut depth: i64 = 0;
    for component in path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Points each AVD's `<name>.ini` at its final home: `avdmanager` records an
/// absolute `path=`, which was the assembly machine's.
///
/// # Errors
///
/// Returns the write error.
pub fn relocate_avds(staging: &Path, destination: &Path) -> std::io::Result<()> {
    let avd_dir = staging.join("avd");
    let Ok(entries) = std::fs::read_dir(&avd_dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let ini = entry.path();
        if ini.extension().is_none_or(|extension| extension != "ini") {
            continue;
        }
        let Some(name) = ini
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
        else {
            continue;
        };
        let text = std::fs::read_to_string(&ini)?;
        let home = destination.join("avd").join(format!("{name}.avd"));
        let mut lines: Vec<String> = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("path="))
            .map(str::to_owned)
            .collect();
        lines.push(format!("path={}", home.display()));
        std::fs::write(&ini, format!("{}\n", lines.join("\n")))?;
    }
    Ok(())
}

/// Replaces `destination` with `staging` by renames: the old copy moves aside
/// first and is restored when the swap fails, then deleted.
fn swap_into_place(staging: &Path, destination: &Path) -> std::io::Result<()> {
    let previous = sibling(destination, "previous");
    if previous.exists() {
        std::fs::remove_dir_all(&previous)?;
    }
    let had_previous = destination.exists();
    if had_previous {
        std::fs::rename(destination, &previous)?;
    }
    if let Err(error) = std::fs::rename(staging, destination) {
        if had_previous {
            let _ = std::fs::rename(&previous, destination);
        }
        return Err(error);
    }
    if had_previous {
        let _ = std::fs::remove_dir_all(&previous);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
