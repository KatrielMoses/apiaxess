//! `latest.json`: the one release manifest the website and the app share.
//!
//! The same file drives the Download page, so version, asset URLs and SHA-256
//! values can never disagree between the two. Unknown fields are ignored, so a
//! newer manifest stays readable by an older app.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

/// The release manifest as published at `/releases/latest.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// The newest released version (semver).
    pub version: String,
    /// Release date, `YYYY-MM-DD`.
    #[serde(default)]
    pub released: Option<String>,
    /// The release-notes page for this version.
    #[serde(default)]
    pub notes_url: Option<String>,
    /// A one-line summary of what changed.
    #[serde(default)]
    pub summary: Option<String>,
    /// The oldest version that can update to this one in place.
    #[serde(default)]
    pub min_supported: Option<String>,
    /// Downloadable assets keyed by platform and package kind
    /// (`windows-x64-msi`, `windows-x64-zip`, `linux-amd64-deb`).
    #[serde(default)]
    pub assets: BTreeMap<String, ReleaseAsset>,
}

/// One downloadable release file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseAsset {
    /// Where to download it; always on the manifest's own origin.
    pub url: String,
    /// Lowercase hex SHA-256 of the file. Required: a download that does not
    /// match it is discarded.
    pub sha256: String,
    /// Size in bytes (`0` when the publisher did not record it).
    #[serde(default)]
    pub size: u64,
}

/// Largest manifest the app will read. The real file is well under 4 KiB.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// Why a manifest was refused.
#[derive(Debug, PartialEq, Eq)]
pub struct ManifestError(pub String);

impl std::fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ManifestError {}

impl ReleaseManifest {
    /// Parses and validates the raw manifest bytes fetched from `origin`.
    ///
    /// Every URL in it (assets and the notes link) must be `https` on the
    /// manifest's own origin, every asset needs a 64-hex-digit SHA-256 and a
    /// file name that is safe to write, and the versions must be semver.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the manifest.
    pub fn parse(bytes: &[u8], origin: &Url) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError(
                "the release manifest is too large".to_owned(),
            ));
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| {
            ManifestError(format!("the release manifest is not valid JSON: {error}"))
        })?;
        manifest.parsed_version()?;
        if let Some(minimum) = &manifest.min_supported {
            semver::Version::parse(minimum).map_err(|error| {
                ManifestError(format!(
                    "min_supported {minimum:?} is not a version: {error}"
                ))
            })?;
        }
        if let Some(notes) = &manifest.notes_url {
            same_origin_url(notes, origin)?;
        }
        for (key, asset) in &manifest.assets {
            let url = same_origin_url(&asset.url, origin)
                .map_err(|ManifestError(why)| ManifestError(format!("asset {key}: {why}")))?;
            if asset.sha256.len() != 64
                || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ManifestError(format!("asset {key} has no valid SHA-256")));
            }
            asset_file_name(&url)
                .ok_or_else(|| ManifestError(format!("asset {key} has no safe file name")))?;
        }
        Ok(manifest)
    }

    /// The manifest's version.
    ///
    /// # Errors
    ///
    /// Returns an error when it is not semver.
    pub fn parsed_version(&self) -> Result<semver::Version, ManifestError> {
        semver::Version::parse(&self.version).map_err(|error| {
            ManifestError(format!(
                "version {:?} is not a version: {error}",
                self.version
            ))
        })
    }

    /// Whether this manifest names a version newer than `current`.
    #[must_use]
    pub fn is_newer_than(&self, current: &semver::Version) -> bool {
        self.parsed_version()
            .is_ok_and(|version| &version > current)
    }

    /// Whether `current` can update to this release in place (it is at least
    /// `min_supported`, or no minimum is published).
    #[must_use]
    pub fn supports_update_from(&self, current: &semver::Version) -> bool {
        self.min_supported
            .as_deref()
            .and_then(|minimum| semver::Version::parse(minimum).ok())
            .is_none_or(|minimum| current >= &minimum)
    }
}

/// Parses `candidate` and requires it to share `origin`'s scheme, host and
/// port, so it is `https` on `apiaxess.dev` whenever the manifest is.
///
/// # Errors
///
/// Returns why the URL is refused.
pub fn same_origin_url(candidate: &str, origin: &Url) -> Result<Url, ManifestError> {
    let url = Url::parse(candidate)
        .map_err(|error| ManifestError(format!("{candidate:?} is not a URL: {error}")))?;
    if url.origin() != origin.origin() {
        return Err(ManifestError(format!(
            "{candidate} is not on {}",
            origin.origin().ascii_serialization()
        )));
    }
    Ok(url)
}

/// The last path segment of an asset URL, when it is a plain file name
/// (letters, digits, `.`, `_`, `-`) that is safe to create in the updates
/// directory.
#[must_use]
pub fn asset_file_name(url: &Url) -> Option<String> {
    let name = url.path_segments()?.next_back()?;
    let safe = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    safe.then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Url {
        Url::parse("https://apiaxess.dev/releases/latest.json").unwrap()
    }

    fn sample(url: &str) -> String {
        format!(
            r#"{{"version":"0.1.1","released":"2026-10-07","notes_url":"https://apiaxess.dev/release-notes#0.1.1","summary":"Fixes","min_supported":"0.1.0","future_field":1,
            "assets":{{"windows-x64-msi":{{"url":"{url}","sha256":"{}","size":10}}}}}}"#,
            "ab".repeat(32)
        )
    }

    #[test]
    fn parses_the_published_schema_and_ignores_unknown_fields() {
        let manifest = ReleaseManifest::parse(
            sample("https://apiaxess.dev/dl/0.1.1/APIaxess-0.1.1-windows-x64.msi").as_bytes(),
            &origin(),
        )
        .unwrap();
        assert_eq!(manifest.version, "0.1.1");
        assert_eq!(manifest.assets["windows-x64-msi"].size, 10);
        let current = semver::Version::parse("0.1.0").unwrap();
        assert!(manifest.is_newer_than(&current));
        assert!(manifest.supports_update_from(&current));
        assert!(!manifest.is_newer_than(&semver::Version::parse("0.1.1").unwrap()));
        assert!(!manifest.supports_update_from(&semver::Version::parse("0.0.9").unwrap()));
    }

    #[test]
    fn refuses_assets_off_the_manifest_origin() {
        for url in [
            "https://evil.example/APIaxess.msi",
            "http://apiaxess.dev/dl/0.1.1/APIaxess.msi",
            "https://apiaxess.dev.evil.example/APIaxess.msi",
            "https://apiaxess.dev:8443/dl/APIaxess.msi",
        ] {
            let error = ReleaseManifest::parse(sample(url).as_bytes(), &origin()).unwrap_err();
            assert!(
                error.0.contains("is not on https://apiaxess.dev"),
                "{url}: {error}"
            );
        }
    }

    #[test]
    fn refuses_bad_hashes_versions_and_file_names() {
        let bad_hash = sample("https://apiaxess.dev/dl/a.msi").replace(&"ab".repeat(32), "abc");
        assert!(ReleaseManifest::parse(bad_hash.as_bytes(), &origin()).is_err());
        let bad_version =
            sample("https://apiaxess.dev/dl/a.msi").replace("\"0.1.1\"", "\"latest\"");
        assert!(ReleaseManifest::parse(bad_version.as_bytes(), &origin()).is_err());
        assert!(
            ReleaseManifest::parse(sample("https://apiaxess.dev/dl/").as_bytes(), &origin())
                .is_err()
        );
        assert!(ReleaseManifest::parse(b"not json", &origin()).is_err());
        assert!(ReleaseManifest::parse(&vec![b' '; MAX_MANIFEST_BYTES + 1], &origin()).is_err());
    }

    #[test]
    fn asset_file_names_are_plain() {
        let name = |url: &str| asset_file_name(&Url::parse(url).unwrap());
        assert_eq!(
            name("https://apiaxess.dev/dl/0.1.1/apiaxess_0.1.1_amd64.deb").as_deref(),
            Some("apiaxess_0.1.1_amd64.deb")
        );
        assert_eq!(name("https://apiaxess.dev/dl/0.1.1/%2e%2e%5cx.msi"), None);
        assert_eq!(name("https://apiaxess.dev/dl/.hidden"), None);
    }
}
