//! Where an installed `APIaxess` keeps its bundled resources and per-user data.
//!
//! Every component that resolves a bundled tool (the Java runtime,
//! apktool/jadx, ffuf, Chromium, the analysis runtime, the Android target
//! add-on, the GUI) or the per-user data directory goes through this crate, so
//! each platform's layout is defined once:
//!
//! | Layout | Resources, relative to the executable | Per-user data |
//! |---|---|---|
//! | Windows (MSI) | `bin\..` | `%LOCALAPPDATA%\apiaxess` |
//! | macOS (`.app`) | `Contents/MacOS/../Resources` | `~/Library/Application Support/APIaxess` |
//! | Linux / other Unix (`.deb`) | `bin/../share/apiaxess` | `$XDG_DATA_HOME/apiaxess`, else `~/.local/share/apiaxess` |
//!
//! `APIAXESS_*` overrides stay with the components that own them; this crate
//! only answers where the install puts things.

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

/// A platform install layout. The compiled platform uses [`Layout::CURRENT`];
/// the others exist so every layout can be tested on any host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    /// MSI layout: resources beside `bin\`, data under `%LOCALAPPDATA%`.
    Windows,
    /// `.app` bundle layout: resources in `Contents/Resources`, data under
    /// `~/Library/Application Support`.
    MacOs,
    /// Unix prefix layout: resources under `share/apiaxess`, data under the
    /// XDG data home.
    Unix,
}

impl Layout {
    /// The layout of the platform this binary was compiled for.
    pub const CURRENT: Self = if cfg!(windows) {
        Self::Windows
    } else if cfg!(target_os = "macos") {
        Self::MacOs
    } else {
        Self::Unix
    };

    /// The directory holding `runtime/`, `tools/` and the optional add-ons, for
    /// an executable that lives in `bin`.
    #[must_use]
    pub fn resource_base_in(self, bin: &Path) -> PathBuf {
        match self {
            Self::Windows => bin.join(".."),
            Self::MacOs => bin.join("..").join("Resources"),
            Self::Unix => bin.join("..").join("share").join("apiaxess"),
        }
    }

    /// The directory the installer stages `gui/` under, for an executable that
    /// lives in `bin`. Both the MSI and the `.deb` put it in `share/apiaxess`;
    /// the `.app` keeps it with the other resources. `None` when `bin` has no
    /// parent.
    #[must_use]
    pub fn gui_base_in(self, bin: &Path) -> Option<PathBuf> {
        let install_root = bin.parent()?;
        Some(match self {
            Self::MacOs => install_root.join("Resources"),
            Self::Windows | Self::Unix => install_root.join("share").join("apiaxess"),
        })
    }

    /// The per-user `APIaxess` data directory, read from the platform's
    /// standard environment variables through `var`.
    #[must_use]
    pub fn data_dir_with(self, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
        match self {
            Self::Windows => var("LOCALAPPDATA")
                .or_else(|| var("APPDATA"))
                .map(PathBuf::from)
                .or_else(|| {
                    var("USERPROFILE")
                        .map(|profile| PathBuf::from(profile).join("AppData").join("Local"))
                })
                .map(|root| root.join("apiaxess")),
            Self::MacOs => var("HOME").map(|home| {
                PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("APIaxess")
            }),
            Self::Unix => var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .or_else(|| {
                    var("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
                })
                .map(|root| root.join("apiaxess")),
        }
    }
}

/// The directory holding the running executable.
#[must_use]
pub fn executable_directory() -> Option<PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// The installed resource base for this platform (see the crate docs), or
/// `None` when the running executable cannot be located.
#[must_use]
pub fn resource_base() -> Option<PathBuf> {
    executable_directory().map(|bin| Layout::CURRENT.resource_base_in(&bin))
}

/// The per-user `APIaxess` data directory for this platform, or `None` when
/// none of its environment variables are set.
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    Layout::CURRENT.data_dir_with(|key| env::var_os(key))
}

/// [`data_dir`], falling back to an `apiaxess` directory under the system
/// temp directory. The fallback effectively never applies on a real desktop
/// session, but callers that must always have a path use it.
#[must_use]
pub fn data_dir_or_temp() -> PathBuf {
    data_dir().unwrap_or_else(|| env::temp_dir().join("apiaxess"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), OsString::from(value)))
            .collect();
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        }
    }

    #[test]
    fn resource_bases_follow_each_install_layout() {
        let bin = Path::new("root").join("bin");
        assert_eq!(Layout::Windows.resource_base_in(&bin), bin.join(".."));
        assert_eq!(
            Layout::Unix.resource_base_in(&bin),
            bin.join("..").join("share").join("apiaxess")
        );
        let macos = Path::new("APIaxess.app").join("Contents").join("MacOS");
        assert_eq!(
            Layout::MacOs.resource_base_in(&macos),
            macos.join("..").join("Resources")
        );
    }

    #[test]
    fn gui_is_under_share_on_msi_and_deb_and_in_resources_in_the_app() {
        let root = Path::new("root");
        let bin = root.join("bin");
        let share = root.join("share").join("apiaxess");
        assert_eq!(Layout::Windows.gui_base_in(&bin), Some(share.clone()));
        assert_eq!(Layout::Unix.gui_base_in(&bin), Some(share));
        assert_eq!(
            Layout::MacOs.gui_base_in(&bin),
            Some(root.join("Resources"))
        );
    }

    #[test]
    fn windows_data_dir_prefers_local_app_data_then_app_data_then_profile() {
        let all = vars(&[
            ("LOCALAPPDATA", "local"),
            ("APPDATA", "roaming"),
            ("USERPROFILE", "profile"),
        ]);
        assert_eq!(
            Layout::Windows.data_dir_with(all),
            Some(Path::new("local").join("apiaxess"))
        );
        let roaming = vars(&[("APPDATA", "roaming"), ("USERPROFILE", "profile")]);
        assert_eq!(
            Layout::Windows.data_dir_with(roaming),
            Some(Path::new("roaming").join("apiaxess"))
        );
        let profile = vars(&[("USERPROFILE", "profile")]);
        assert_eq!(
            Layout::Windows.data_dir_with(profile),
            Some(
                Path::new("profile")
                    .join("AppData")
                    .join("Local")
                    .join("apiaxess")
            )
        );
        assert_eq!(Layout::Windows.data_dir_with(vars(&[])), None);
    }

    #[test]
    fn unix_data_dir_prefers_xdg_then_home() {
        let both = vars(&[("XDG_DATA_HOME", "xdg"), ("HOME", "home")]);
        assert_eq!(
            Layout::Unix.data_dir_with(both),
            Some(Path::new("xdg").join("apiaxess"))
        );
        let home = vars(&[("HOME", "home")]);
        assert_eq!(
            Layout::Unix.data_dir_with(home),
            Some(
                Path::new("home")
                    .join(".local")
                    .join("share")
                    .join("apiaxess")
            )
        );
        assert_eq!(Layout::Unix.data_dir_with(vars(&[])), None);
    }

    #[test]
    fn macos_data_dir_is_application_support_and_ignores_xdg() {
        let env = vars(&[("XDG_DATA_HOME", "xdg"), ("HOME", "home")]);
        assert_eq!(
            Layout::MacOs.data_dir_with(env),
            Some(
                Path::new("home")
                    .join("Library")
                    .join("Application Support")
                    .join("APIaxess")
            )
        );
        assert_eq!(Layout::MacOs.data_dir_with(vars(&[])), None);
    }
}
