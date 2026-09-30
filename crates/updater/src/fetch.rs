//! The one network path for everything the app pulls from apiaxess.dev: the
//! release manifest, the add-on catalog, and the files they point at.
//!
//! A [`Fetcher`] is pinned to one origin: redirects that leave it are refused,
//! it sends no referer or cookie, and its only identifying header is the
//! `User-Agent` it was built with. Signed documents are trusted only after
//! their detached signature verifies (once a key is embedded), and downloads
//! are kept only when their SHA-256 matches.

use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{manifest, verify};

/// Largest detached signature file read.
const MAX_SIGNATURE_BYTES: usize = 1024;

/// How long a small document request may take in total.
const DOCUMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a download may stall between chunks.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);

/// Largest file downloaded when the publisher gave no size.
const MAX_UNSIZED_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Why a download stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum DownloadError {
    /// The operator cancelled it; a resumable partial file is kept.
    Cancelled,
    /// It failed; the message says why and what was kept.
    Failed(String),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("the download was cancelled"),
            Self::Failed(why) => formatter.write_str(why),
        }
    }
}

impl From<String> for DownloadError {
    fn from(why: String) -> Self {
        Self::Failed(why)
    }
}

/// One file to download and verify.
#[derive(Clone, Copy, Debug)]
pub struct Download<'a> {
    /// Where it is (already checked to be on the fetcher's origin).
    pub url: &'a Url,
    /// Its published lowercase-hex SHA-256.
    pub sha256: &'a str,
    /// Its published size in bytes (`0` when unknown).
    pub size: u64,
    /// The directory to save it in.
    pub dir: &'a Path,
    /// Continue an interrupted `.partial` file with an HTTP range request, and
    /// keep it on a network failure or cancel so the next attempt resumes.
    pub resumable: bool,
}

/// An HTTP client pinned to one origin.
#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    origin: Url,
}

impl Fetcher {
    /// A fetcher for `origin`'s scheme, host and port, sending `user_agent`.
    ///
    /// # Errors
    ///
    /// Returns why the HTTP client could not start.
    pub fn new(origin: &Url, user_agent: &str) -> Result<Self, String> {
        let pinned = origin.origin();
        let client = reqwest::Client::builder()
            .user_agent(user_agent)
            .referer(false)
            .https_only(origin.scheme() == "https")
            .connect_timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else if attempt.url().origin() == pinned {
                    attempt.follow()
                } else {
                    attempt.error("a redirect left apiaxess.dev")
                }
            }))
            .build()
            .map_err(|error| format!("the download client could not start: {error}"))?;
        Ok(Self {
            client,
            origin: origin.clone(),
        })
    }

    /// Parses `candidate` and requires it to be on this fetcher's origin.
    ///
    /// # Errors
    ///
    /// Returns why the URL is refused.
    pub fn same_origin(&self, candidate: &str) -> Result<Url, String> {
        manifest::same_origin_url(candidate, &self.origin).map_err(|error| error.to_string())
    }

    async fn get(&self, url: &Url, range_from: Option<u64>) -> Result<reqwest::Response, String> {
        let mut request = self.client.get(url.clone());
        if let Some(offset) = range_from {
            request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
        }
        let response = request.send().await.map_err(|error| {
            format!(
                "could not reach {}: {error}",
                url.host_str().unwrap_or("the server")
            )
        })?;
        if !response.status().is_success() {
            return Err(format!("{url} answered {}", response.status()));
        }
        Ok(response)
    }

    /// Fetches a small document (at most `limit` bytes). With `public_key`,
    /// also fetches `<url>.sig` and returns the bytes only when the ed25519
    /// signature over exactly those bytes verifies.
    ///
    /// # Errors
    ///
    /// Returns why the document was not fetched or not trusted.
    pub async fn fetch_signed(
        &self,
        url: &Url,
        limit: usize,
        public_key: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, String> {
        let fetch = async {
            let bytes = read_capped(self.get(url, None).await?, limit).await?;
            if let Some(key) = public_key {
                let mut signature_url = url.clone();
                signature_url.set_path(&format!("{}.sig", url.path()));
                let signature =
                    read_capped(self.get(&signature_url, None).await?, MAX_SIGNATURE_BYTES).await?;
                verify::verify_manifest_signature(&bytes, &signature, key)?;
            }
            Ok(bytes)
        };
        tokio::time::timeout(DOCUMENT_TIMEOUT, fetch)
            .await
            .map_err(|_| "apiaxess.dev did not answer in time".to_owned())?
    }

    /// Downloads `download` into its directory through a `.partial` file,
    /// hashing as it goes, and renames it into place only when its SHA-256
    /// matches. A file already there with the right hash is reused. A wrong
    /// hash deletes everything; a network failure or cancel keeps the partial
    /// file only when the download is resumable. `progress` gets the bytes
    /// held so far; `cancel` stops the download when set.
    ///
    /// # Errors
    ///
    /// Returns [`DownloadError::Cancelled`] or why it failed.
    pub async fn download(
        &self,
        download: Download<'_>,
        progress: impl Fn(u64),
        cancel: Option<&AtomicBool>,
    ) -> Result<PathBuf, DownloadError> {
        let name = manifest::asset_file_name(download.url).ok_or_else(|| {
            DownloadError::Failed("the download has no safe file name".to_owned())
        })?;
        std::fs::create_dir_all(download.dir)
            .map_err(|error| format!("{}: {error}", download.dir.display()))?;
        let destination = download.dir.join(&name);
        let expected = download.sha256.to_ascii_lowercase();
        if destination.is_file() {
            if hash_file(&destination)
                .await
                .is_some_and(|actual| actual == expected)
            {
                progress(download.size);
                return Ok(destination);
            }
            let _ = std::fs::remove_file(&destination);
        }
        let partial = download.dir.join(format!("{name}.partial"));
        if !download.resumable {
            let _ = std::fs::remove_file(&partial);
        }
        match self
            .stream(download, &partial, &expected, &progress, cancel)
            .await
        {
            Ok(()) => std::fs::rename(&partial, &destination)
                .map(|()| destination)
                .map_err(|error| {
                    let _ = std::fs::remove_file(&partial);
                    DownloadError::Failed(format!(
                        "the verified download could not be saved: {error}"
                    ))
                }),
            Err(Stop::Mismatch(why)) => {
                let _ = std::fs::remove_file(&partial);
                Err(DownloadError::Failed(why))
            }
            Err(Stop::Interrupted(error)) => {
                if !download.resumable {
                    let _ = std::fs::remove_file(&partial);
                }
                Err(error)
            }
        }
    }

    async fn stream(
        &self,
        download: Download<'_>,
        partial: &Path,
        expected: &str,
        progress: &impl Fn(u64),
        cancel: Option<&AtomicBool>,
    ) -> Result<(), Stop> {
        let limit = if download.size > 0 {
            download.size
        } else {
            MAX_UNSIZED_BYTES
        };
        // Resume: hash what is already on disk, then ask for the rest.
        let mut hasher = Sha256::new();
        let mut held: u64 = 0;
        if download.resumable && partial.is_file() {
            let existing = partial.to_path_buf();
            let prefix = tokio::task::spawn_blocking(move || hash_prefix(&existing))
                .await
                .ok()
                .and_then(Result::ok);
            match prefix {
                Some((prefix_hasher, length)) if length > 0 && length < limit => {
                    hasher = prefix_hasher;
                    held = length;
                }
                _ => {
                    let _ = std::fs::remove_file(partial);
                }
            }
        }
        let mut response = self
            .get(download.url, (held > 0).then_some(held))
            .await
            .map_err(|why| Stop::Interrupted(DownloadError::Failed(why)))?;
        let resumed = held > 0 && response.status() == reqwest::StatusCode::PARTIAL_CONTENT;
        if !resumed {
            // The server sent the whole file: start over.
            hasher = Sha256::new();
            held = 0;
        }
        if response
            .content_length()
            .is_some_and(|length| held + length > limit)
        {
            return Err(Stop::Mismatch(
                "the download is larger than published; it was deleted and nothing was installed"
                    .to_owned(),
            ));
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(resumed)
            .truncate(!resumed)
            .open(partial)
            .map_err(|error| interrupted(format!("{}: {error}", partial.display())))?;
        progress(held);
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                let _ = file.sync_all();
                return Err(Stop::Interrupted(DownloadError::Cancelled));
            }
            let chunk = tokio::time::timeout(CHUNK_TIMEOUT, response.chunk())
                .await
                .map_err(|_| interrupted("the download stalled".to_owned()))?
                .map_err(|error| interrupted(format!("the download failed: {error}")))?;
            let Some(chunk) = chunk else {
                break;
            };
            held += chunk.len() as u64;
            if held > limit {
                return Err(Stop::Mismatch(
                    "the download is larger than published; it was deleted and nothing was installed"
                        .to_owned(),
                ));
            }
            hasher.update(&chunk);
            file.write_all(&chunk).map_err(|error| {
                interrupted(format!("the download could not be written: {error}"))
            })?;
            progress(held);
        }
        file.sync_all()
            .map_err(|error| interrupted(format!("the download could not be written: {error}")))?;
        if download.size > 0 && held != download.size {
            return Err(interrupted(format!(
                "the download ended early ({held} of {} bytes)",
                download.size
            )));
        }
        let actual = verify::hex(&hasher.finalize());
        if actual != expected {
            return Err(Stop::Mismatch(format!(
                "the download does not match its published SHA-256 (expected {expected}, got {actual}); it was deleted and nothing was installed"
            )));
        }
        Ok(())
    }
}

/// How a stream stopped short.
enum Stop {
    /// The bytes are wrong: never keep them.
    Mismatch(String),
    /// The transfer stopped: keep the bytes when resumable.
    Interrupted(DownloadError),
}

fn interrupted(why: String) -> Stop {
    Stop::Interrupted(DownloadError::Failed(why))
}

/// Reads a response body, refusing more than `limit` bytes.
async fn read_capped(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("the connection to apiaxess.dev failed: {error}"))?
    {
        if body.len() + chunk.len() > limit {
            return Err("apiaxess.dev sent more than expected".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The SHA-256 of a whole file, off the async threads.
async fn hash_file(path: &Path) -> Option<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || verify::sha256_file(&path))
        .await
        .ok()
        .and_then(Result::ok)
}

/// A hasher primed with a partial file's bytes, and how many there were.
fn hash_prefix(path: &Path) -> std::io::Result<(Sha256, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1 << 20];
    let mut length = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        length += read as u64;
    }
    Ok((hasher, length))
}
