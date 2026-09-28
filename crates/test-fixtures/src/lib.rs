//! Shared resolution for gitignored local test fixtures.
//!
//! The capstone APK is a third-party artifact kept out of the repository for
//! size and licensing reasons. Tests that need it resolve it here and skip
//! when it is absent, so a fresh clone and CI stay green while a machine with
//! the fixture still runs them for real.
//!
//! A skip is not a pass: [`skip`] writes straight to the process's stderr
//! rather than through `eprintln!`, which libtest captures and hides for
//! passing tests, so every skip shows up in an ordinary `cargo test` run.

use std::{
    fmt::Display,
    io::Write as _,
    path::{Path, PathBuf},
};

/// Environment variable that points tests at a capstone APK elsewhere.
pub const CAPSTONE_APK_ENV: &str = "APIAXESS_CAPSTONE_APK";

/// Default capstone APK location, relative to the workspace root.
pub const CAPSTONE_APK_DEFAULT: &str = "fixtures/capstone/feeder-2.22.0-4050.apk";

/// Returns the workspace root.
///
/// # Panics
///
/// Panics if this crate is no longer two levels below the workspace root.
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root above crates/test-fixtures")
        .to_path_buf()
}

/// Resolves where the capstone APK is expected, whether or not it exists.
///
/// The first set variable among `overrides`, then [`CAPSTONE_APK_ENV`], wins;
/// otherwise [`CAPSTONE_APK_DEFAULT`]. Relative values resolve against the
/// workspace root so they mean the same thing from every crate's tests.
#[must_use]
pub fn capstone_apk_path(overrides: &[&str]) -> PathBuf {
    let root = workspace_root();
    overrides
        .iter()
        .chain(std::iter::once(&CAPSTONE_APK_ENV))
        .find_map(std::env::var_os)
        .map_or_else(
            || root.join(CAPSTONE_APK_DEFAULT),
            |value| {
                let path = PathBuf::from(value);
                if path.is_absolute() {
                    path
                } else {
                    root.join(path)
                }
            },
        )
}

/// Returns the capstone APK when present, or visibly skips `test` and returns
/// `None` so the caller can `return` early.
#[must_use]
pub fn capstone_apk(test: &str, overrides: &[&str]) -> Option<PathBuf> {
    let path = capstone_apk_path(overrides);
    if path.is_file() {
        Some(path)
    } else {
        skip(
            test,
            format_args!(
                "capstone APK fixture not present at {} (gitignored); set {CAPSTONE_APK_ENV} \
                 or drop it at {CAPSTONE_APK_DEFAULT} to run",
                path.display()
            ),
        );
        None
    }
}

/// Reports that `test` was skipped, bypassing libtest output capture.
pub fn skip(test: &str, reason: impl Display) {
    let _ = writeln!(std::io::stderr().lock(), "SKIPPED {test}: {reason}");
}
