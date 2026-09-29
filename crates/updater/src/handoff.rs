//! The install handoff between the engine and whatever outlives it.
//!
//! The engine downloads and verifies the MSI, but it cannot run it: the MSI
//! replaces the engine's own files, and under the desktop shell the engine
//! lives in a Job Object that is killed with the shell. So the engine writes
//! `updates/install.json` and exits; the desktop shell (or, for headless
//! `serve`, the engine itself as it exits) consumes the handoff, re-checks the
//! installer's SHA-256, and starts a detached helper that waits for the app to
//! exit, runs the MSI, records the result, and relaunches the app.

use std::{
    fmt::Write as _,
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// When a staged update is installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallWhen {
    /// Right away: the app exits, installs, and relaunches.
    Now,
    /// When this session ends: as the app exits, or on its next launch if it
    /// did not get the chance.
    Deferred,
}

/// A verified installer waiting to be run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallHandoff {
    /// The version being installed.
    pub version: String,
    /// The downloaded, verified MSI.
    pub installer: PathBuf,
    /// Its expected SHA-256 (from the manifest), checked again before running.
    pub sha256: String,
    /// The session artifact to reopen after the relaunch.
    #[serde(default)]
    pub resume_session: Option<PathBuf>,
    /// When to install.
    pub when: InstallWhen,
}

/// What the installer helper recorded about its run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    /// The version it installed.
    pub version: String,
    /// Windows Installer's exit code (`0`, `3010` and `1641` are success).
    pub exit_code: i64,
    /// The verbose installer log.
    #[serde(default)]
    pub log: Option<PathBuf>,
}

impl InstallResult {
    /// Whether Windows Installer reported success.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.exit_code, 0 | 3010 | 1641)
    }
}

/// Where downloads, the handoff, and install results live.
#[must_use]
pub fn updates_dir() -> PathBuf {
    apiaxess_install_layout::data_dir_or_temp().join("updates")
}

fn handoff_path(dir: &Path) -> PathBuf {
    dir.join("install.json")
}

fn result_path(dir: &Path) -> PathBuf {
    dir.join("last-install.json")
}

/// Writes the handoff (atomically: a reader never sees half a file).
///
/// # Errors
///
/// Returns the write error.
pub fn write_handoff(dir: &Path, handoff: &InstallHandoff) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let bytes = serde_json::to_vec_pretty(handoff).map_err(io::Error::other)?;
    let temporary = dir.join("install.json.tmp");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(temporary, handoff_path(dir))
}

/// The pending handoff, if any.
#[must_use]
pub fn read_handoff(dir: &Path) -> Option<InstallHandoff> {
    let bytes = std::fs::read(handoff_path(dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Removes the pending handoff (cancelled, or consumed).
pub fn clear_handoff(dir: &Path) {
    let _ = std::fs::remove_file(handoff_path(dir));
}

/// Reads and removes the pending handoff, so a failing install is attempted
/// once and never loops across launches.
#[must_use]
pub fn take_handoff(dir: &Path) -> Option<InstallHandoff> {
    let handoff = read_handoff(dir);
    clear_handoff(dir);
    handoff
}

/// Reads and removes the last install result the helper recorded.
#[must_use]
pub fn take_install_result(dir: &Path) -> Option<InstallResult> {
    let bytes = std::fs::read(result_path(dir)).ok()?;
    let _ = std::fs::remove_file(result_path(dir));
    // PowerShell 5.1's WriteAllText may lead with a BOM; tolerate it.
    let text = String::from_utf8_lossy(&bytes);
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

/// Checks the staged installer against the handoff's SHA-256, so a file that
/// changed on disk after the engine verified it is never run.
///
/// # Errors
///
/// Returns why the installer is refused.
pub fn verify_installer(handoff: &InstallHandoff) -> io::Result<()> {
    let actual = crate::verify::sha256_file(&handoff.installer)?;
    if actual.eq_ignore_ascii_case(&handoff.sha256) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} no longer matches its verified SHA-256 (expected {}, found {actual}); not installing it",
                handoff.installer.display(),
                handoff.sha256
            ),
        ))
    }
}

/// Quotes a string for a `PowerShell` single-quoted literal.
fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// A path as Windows tools expect it: Windows Installer cannot open a package
/// path written with forward slashes (exit code 1619), which a data directory
/// taken from the environment can contain.
fn windows_path(path: &Path) -> String {
    path.display().to_string().replace('/', "\\")
}

/// The helper script: wait for `wait_pid` to exit, run the MSI passively
/// (progress only, no prompts, no reboot), record the result for the next
/// launch, then start `relaunch` (reopening the handoff's session) if given.
#[must_use]
pub fn msi_helper_script(
    handoff: &InstallHandoff,
    wait_pid: u32,
    dir: &Path,
    relaunch: Option<&Path>,
) -> String {
    let log = dir.join(format!("install-{}.log", handoff.version));
    let mut script = format!(
        "$ErrorActionPreference = 'Continue'\n\
         try {{ Wait-Process -Id {wait_pid} -Timeout 120 -ErrorAction SilentlyContinue }} catch {{}}\n\
         $msi = {msi}\n\
         $log = {log}\n\
         $code = -1\n\
         try {{\n\
         \x20 $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\msiexec.exe') -ArgumentList @('/i', ('\"' + $msi + '\"'), '/passive', '/norestart', 'MSIFASTINSTALL=1', '/l*v', ('\"' + $log + '\"')) -Wait -PassThru\n\
         \x20 $code = $p.ExitCode\n\
         }} catch {{ $code = -2 }}\n\
         $json = @{{ version = {version}; exitCode = $code; log = $log }} | ConvertTo-Json -Compress\n\
         [System.IO.File]::WriteAllText({result}, $json)\n",
        msi = ps_literal(&windows_path(&handoff.installer)),
        log = ps_literal(&windows_path(&log)),
        version = ps_literal(&handoff.version),
        result = ps_literal(&windows_path(&result_path(dir))),
    );
    if let Some(executable) = relaunch {
        if let Some(session) = &handoff.resume_session {
            let _ = writeln!(
                script,
                "$env:APIAXESS_SESSION_FILE = {}",
                ps_literal(&windows_path(session))
            );
        }
        let _ = writeln!(
            script,
            "Start-Process -FilePath {}",
            ps_literal(&windows_path(executable))
        );
    }
    script
}

/// Verifies the staged MSI and starts the detached installer helper. It waits
/// for `wait_pid` (the process that is about to exit) before installing, and
/// relaunches `relaunch` afterwards when given.
///
/// # Errors
///
/// Returns the verification failure, or the error starting the helper (always
/// an error on platforms without MSI).
pub fn launch_msi_installer(
    handoff: &InstallHandoff,
    wait_pid: u32,
    dir: &Path,
    relaunch: Option<&Path>,
) -> io::Result<()> {
    // Only an MSI the updater itself downloaded into the updates directory is
    // ever run, whatever a handoff file names.
    let staged = handoff
        .installer
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("msi"))
        && handoff
            .installer
            .parent()
            .zip(std::fs::canonicalize(dir).ok())
            .and_then(|(parent, dir)| Some(std::fs::canonicalize(parent).ok()? == dir))
            .unwrap_or(false);
    if !staged {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is not an installer the updater downloaded; not running it",
                handoff.installer.display()
            ),
        ));
    }
    verify_installer(handoff)?;
    if !cfg!(windows) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MSI updates install only on Windows",
        ));
    }
    let script = msi_helper_script(handoff, wait_pid, dir, relaunch);
    let encoded = {
        use base64::Engine as _;
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        base64::engine::general_purpose::STANDARD.encode(utf16)
    };
    let powershell = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    apiaxess_external_tools::spawn_detached(
        &powershell,
        [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            &encoded,
        ],
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("apiaxess-handoff-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn handoff(dir: &Path, sha256: String) -> InstallHandoff {
        InstallHandoff {
            version: "0.1.1".to_owned(),
            installer: dir.join("APIaxess-0.1.1-windows-x64.msi"),
            sha256,
            resume_session: Some(dir.join("it's a session.apiaxess.json")),
            when: InstallWhen::Now,
        }
    }

    #[test]
    fn a_handoff_is_consumed_once() {
        let dir = scratch("take");
        let pending = handoff(&dir, "00".repeat(32));
        write_handoff(&dir, &pending).unwrap();
        assert_eq!(read_handoff(&dir), Some(pending.clone()));
        assert_eq!(take_handoff(&dir), Some(pending));
        assert_eq!(take_handoff(&dir), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_changed_installer_is_refused() {
        let dir = scratch("verify");
        std::fs::write(dir.join("APIaxess-0.1.1-windows-x64.msi"), b"abc").unwrap();
        let good = handoff(
            &dir,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
        );
        assert!(verify_installer(&good).is_ok());
        let bad = handoff(&dir, "00".repeat(32));
        let error = verify_installer(&bad).unwrap_err();
        assert!(error.to_string().contains("not installing it"), "{error}");
        assert!(launch_msi_installer(&bad, 1, &dir, None).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_a_staged_msi_is_ever_run() {
        let dir = scratch("staged");
        let elsewhere = scratch("elsewhere");
        std::fs::write(elsewhere.join("other.msi"), b"abc").unwrap();
        std::fs::write(dir.join("payload.exe"), b"abc").unwrap();
        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned();
        for installer in [elsewhere.join("other.msi"), dir.join("payload.exe")] {
            let planted = InstallHandoff {
                installer,
                ..handoff(&dir, sha.clone())
            };
            let error = launch_msi_installer(&planted, 1, &dir, None).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        }
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(elsewhere);
    }

    #[test]
    fn the_helper_quotes_paths_and_relaunches_the_session() {
        let dir = Path::new(r"C:\Users\o'brien\AppData\Local\apiaxess\updates");
        let script = msi_helper_script(
            &handoff(dir, "00".repeat(32)),
            4242,
            dir,
            Some(Path::new(
                r"C:\Users\o'brien\AppData\Local\Programs\APIaxess\bin\apiaxess-desktop.exe",
            )),
        );
        assert!(script.contains("Wait-Process -Id 4242"));
        assert!(script.contains(r"$msi = 'C:\Users\o''brien\AppData\Local\apiaxess\updates"));
        assert!(script.contains("'/passive', '/norestart'"));
        assert!(script.contains("$env:APIAXESS_SESSION_FILE = "));
        assert!(script.contains("it''s a session.apiaxess.json"));
        assert!(script.trim_end().ends_with(r"bin\apiaxess-desktop.exe'"));
        // A data directory from the environment may use forward slashes, which
        // msiexec cannot open.
        let mixed = Path::new("C:/Users/op/AppData/Local/apiaxess/updates");
        let normalized = msi_helper_script(&handoff(mixed, "00".repeat(32)), 1, mixed, None);
        assert!(!normalized.contains("C:/"), "{normalized}");
        assert!(normalized.contains(
            r"'C:\Users\op\AppData\Local\apiaxess\updates\APIaxess-0.1.1-windows-x64.msi'"
        ));
        let no_relaunch = msi_helper_script(&handoff(dir, "00".repeat(32)), 1, dir, None);
        assert!(!no_relaunch.contains("Start-Process -FilePath '"));
    }

    #[test]
    fn install_results_round_trip_with_a_bom() {
        let dir = scratch("result");
        std::fs::write(
            result_path(&dir),
            "\u{feff}{\"version\":\"0.1.1\",\"exitCode\":1603,\"log\":\"C:\\\\x.log\"}",
        )
        .unwrap();
        let result = take_install_result(&dir).unwrap();
        assert_eq!(result.exit_code, 1603);
        assert!(!result.succeeded());
        assert!(take_install_result(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
