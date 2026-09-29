//! How this copy of `APIaxess` was installed, which decides what "Update" does.
//!
//! Each package writes a one-word `install-channel` marker into its resource
//! base at install time (see `packaging/`): the MSI build stages `msi`, the
//! portable zip `portable`, Scoop's `post_install` rewrites it to `scoop`, the
//! Chocolatey install script to `chocolatey`, and the `.deb` ships `deb`. A
//! build with no marker (a source checkout) never offers an install.

use std::path::Path;

use serde::Serialize;

/// The file name of the marker, in the install's resource base.
pub const MARKER_FILE: &str = "install-channel";

/// How this install is updated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallChannel {
    /// The Windows MSI: the app downloads, verifies and runs the new MSI.
    Msi,
    /// The portable zip, unpacked by hand: the operator replaces it.
    Portable,
    /// The portable zip installed by Scoop: `scoop update apiaxess`.
    Scoop,
    /// The MSI installed by Chocolatey: `choco upgrade apiaxess`.
    Chocolatey,
    /// The Debian package: the app verifies the new `.deb`, the operator runs
    /// `apt` (the app never escalates privileges).
    Deb,
    /// No marker: a source or development build.
    Source,
}

impl InstallChannel {
    /// Parses a marker's contents.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "msi" => Some(Self::Msi),
            "portable" | "zip" => Some(Self::Portable),
            "scoop" => Some(Self::Scoop),
            "chocolatey" | "choco" => Some(Self::Chocolatey),
            "deb" => Some(Self::Deb),
            "source" => Some(Self::Source),
            _ => None,
        }
    }

    /// Reads the marker under `resource_base`; [`Self::Source`] when absent.
    #[must_use]
    pub fn read_from(resource_base: &Path) -> Self {
        std::fs::read_to_string(resource_base.join(MARKER_FILE))
            .ok()
            .and_then(|marker| Self::parse(&marker))
            .unwrap_or(Self::Source)
    }

    /// This install's channel. `APIAXESS_INSTALL_CHANNEL` overrides the marker
    /// (for testing a channel's flow from a development build).
    #[must_use]
    pub fn detect() -> Self {
        if let Some(value) = std::env::var_os("APIAXESS_INSTALL_CHANNEL")
            && let Some(channel) = value.to_str().and_then(Self::parse)
        {
            return channel;
        }
        apiaxess_install_layout::resource_base().map_or(Self::Source, |base| Self::read_from(&base))
    }

    /// The `latest.json` asset this channel downloads or points at, for this
    /// platform. `None` when the channel has no asset (a source build).
    #[must_use]
    pub const fn asset_key(self) -> Option<&'static str> {
        match self {
            Self::Msi | Self::Chocolatey => Some("windows-x64-msi"),
            Self::Portable | Self::Scoop => Some("windows-x64-zip"),
            Self::Deb => Some("linux-amd64-deb"),
            Self::Source => None,
        }
    }

    /// Whether "Update" downloads and verifies the asset in the app (the MSI,
    /// which the app then installs, and the `.deb`, which the operator installs
    /// with the command shown).
    #[must_use]
    pub const fn downloads_in_app(self) -> bool {
        matches!(self, Self::Msi | Self::Deb)
    }

    /// Whether the app installs the update itself.
    #[must_use]
    pub const fn installs_in_app(self) -> bool {
        matches!(self, Self::Msi)
    }

    /// The command the operator runs to update, for channels owned by a
    /// package manager. `downloaded` is the verified `.deb`, when there is one.
    #[must_use]
    pub fn update_command(self, downloaded: Option<&Path>) -> Option<String> {
        match self {
            Self::Scoop => Some("scoop update apiaxess".to_owned()),
            Self::Chocolatey => Some("choco upgrade apiaxess".to_owned()),
            Self::Deb => downloaded.map(|path| {
                format!(
                    "sudo apt install {}",
                    shell_quote(&path.display().to_string())
                )
            }),
            Self::Msi | Self::Portable | Self::Source => None,
        }
    }
}

/// Quotes a path for a POSIX shell when it needs it.
fn shell_quote(path: &str) -> String {
    if path
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_parse_and_default_to_source() {
        assert_eq!(InstallChannel::parse("msi\r\n"), Some(InstallChannel::Msi));
        assert_eq!(InstallChannel::parse("Scoop"), Some(InstallChannel::Scoop));
        assert_eq!(
            InstallChannel::parse("choco"),
            Some(InstallChannel::Chocolatey)
        );
        assert_eq!(InstallChannel::parse("flatpak"), None);
        let missing = std::env::temp_dir().join("apiaxess-no-such-install-root");
        assert_eq!(InstallChannel::read_from(&missing), InstallChannel::Source);
    }

    #[test]
    fn package_manager_channels_show_their_command() {
        assert_eq!(
            InstallChannel::Scoop.update_command(None).as_deref(),
            Some("scoop update apiaxess")
        );
        assert_eq!(
            InstallChannel::Chocolatey.update_command(None).as_deref(),
            Some("choco upgrade apiaxess")
        );
        let deb = Path::new("/home/op/.local/share/apiaxess/updates/apiaxess_0.1.1_amd64.deb");
        assert_eq!(
            InstallChannel::Deb.update_command(Some(deb)).as_deref(),
            Some(
                "sudo apt install /home/op/.local/share/apiaxess/updates/apiaxess_0.1.1_amd64.deb"
            )
        );
        assert_eq!(
            InstallChannel::Deb
                .update_command(Some(Path::new("/home/o p/x.deb")))
                .as_deref(),
            Some("sudo apt install '/home/o p/x.deb'")
        );
        assert_eq!(InstallChannel::Msi.update_command(None), None);
        assert!(InstallChannel::Msi.installs_in_app());
        assert!(!InstallChannel::Deb.installs_in_app());
    }
}
