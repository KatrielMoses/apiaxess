//! Client-scoped browser trust provisioning and recoverable exceptional installs.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use apiaxess_external_tools::{
    ExternalToolRunner, ProcessToolRunner, ToolInvocation, ToolInvocationRequest, ToolProbe,
    ToolVersion,
};
use serde::{Deserialize, Serialize};

use crate::SessionCa;

const STATE_LOG_VERSION: u32 = 1;
const NSS_TOOL_ID: &str = "nss.certutil";
const OWNED_PROFILE_MARKER: &str = ".apiaxess-owned-profile";
const NSS_MODERN_MINIMUM_VERSION: &str = "3.14.0";

/// The trust scope a caller explicitly selected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustScope {
    /// A dedicated browser profile; the host system store is untouched.
    ClientProfile,
    /// An exceptional platform store install, requiring a recovery record.
    SystemStore,
}

/// Browser family whose profile database is being provisioned.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BrowserKind {
    /// Firefox and its NSS profile database.
    Firefox,
    /// Chromium-family browser using an NSS profile database on Linux.
    Chromium,
}

/// Platform-specific trust behavior relevant to browser provisioning.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BrowserPlatform {
    /// NSS profile provisioning is supported for Firefox and Chromium-family browsers.
    Linux,
    /// Firefox has an NSS profile path; Chromium has no portable client-scoped
    /// trust store and uses Windows/Chrome-managed trust inputs.
    Windows,
    /// No client-scoped browser adapter is available in this build.
    Unsupported,
}

impl BrowserPlatform {
    /// Detects the host platform used by the browser adapter.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unsupported
        }
    }
}

/// A client-profile CA material receipt with exact teardown information.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrustProvisionReceipt {
    /// CA fingerprint.
    pub fingerprint: String,
    /// Profile-local public certificate staging path.
    pub certificate_path: PathBuf,
    /// Selected trust scope.
    pub scope: TrustScope,
    /// NSS database directory, when an NSS profile was provisioned.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_path: Option<PathBuf>,
    /// Exact NSS nickname used for teardown and audit.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_nickname: Option<String>,
    /// Browser family used for this receipt.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserKind>,
    /// Platform used for this receipt.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<BrowserPlatform>,
    /// Whether `APIaxess` created the NSS database and may remove its files.
    #[serde(default)]
    pub database_created: bool,
    /// Whether `APIaxess` created a browser-specific NSS database directory.
    #[serde(default)]
    pub database_directory_created: bool,
    /// Whether `APIaxess` created the entire profile directory.
    #[serde(default)]
    pub profile_created: bool,
    /// NSS certutil executable used for this receipt.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certutil: Option<PathBuf>,
}

/// Dedicated profile target. It is never the user's primary browser profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientProfile {
    /// Dedicated profile directory owned by the client context.
    pub directory: PathBuf,
}

/// Removes a freshly created isolated profile directory on drop unless disarmed.
///
/// [`ClientProfile`] is `Clone` and is also constructed over borrowed fixture
/// paths, so cleanup cannot live in its own `Drop`. This scoped guard instead
/// owns the disposable directory's lifetime for the window between
/// [`ClientProfile::isolated`] and the point provisioning hands the profile to
/// the session — guaranteeing the directory is not leaked if any exit path in
/// between (including a future one) returns early. Mirrors the intake and other
/// scratch guards.
struct IsolatedProfileGuard {
    directory: Option<PathBuf>,
}

impl IsolatedProfileGuard {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory: Some(directory),
        }
    }

    /// Transfers ownership away from the guard (the directory now persists).
    fn disarm(&mut self) {
        self.directory = None;
    }
}

impl Drop for IsolatedProfileGuard {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            // Best-effort: a leftover directory must never mask the real result,
            // and explicit teardown on the error paths already handles the NSS
            // records; this only backstops the directory removal.
            let _ = fs::remove_dir_all(directory);
        }
    }
}

impl ClientProfile {
    /// Creates a new disposable profile directory under the host temp area.
    ///
    /// # Errors
    ///
    /// Returns a profile diagnostic if the isolated directory cannot be created.
    pub fn isolated() -> Result<Self, Diagnostic> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let directory = std::env::temp_dir().join(format!("apiaxess-browser-profile-{nonce}"));
        fs::create_dir(&directory)
            .map_err(|error| profile_unavailable_diagnostic(&directory, error.to_string()))?;
        fs::write(
            directory.join(OWNED_PROFILE_MARKER),
            b"APIaxess disposable browser profile\n",
        )
        .map_err(|error| profile_unavailable_diagnostic(&directory, error.to_string()))?;
        Ok(Self { directory })
    }

    /// Provisions Firefox using the host platform and NSS `certutil`.
    ///
    /// # Errors
    ///
    /// Returns a typed diagnostic when NSS tooling, the profile, or the
    /// database operation is unavailable.
    pub fn provision(&self, ca: &SessionCa) -> Result<TrustProvisionReceipt, Diagnostic> {
        self.provision_browser(ca, BrowserKind::Firefox)
    }

    /// Provisions a browser profile through the production external-tool port.
    ///
    /// # Errors
    ///
    /// Returns a browser/platform, NSS-tool, profile, or provisioning diagnostic.
    pub fn provision_browser(
        &self,
        ca: &SessionCa,
        browser: BrowserKind,
    ) -> Result<TrustProvisionReceipt, Diagnostic> {
        let runner = ProcessToolRunner;
        let certutil = std::env::var_os("APIAXESS_NSS_CERTUTIL")
            .map_or_else(|| PathBuf::from("certutil"), PathBuf::from);
        self.provision_browser_with_runner(
            ca,
            browser,
            BrowserPlatform::current(),
            certutil,
            &runner,
        )
    }

    /// Provisions an existing or dedicated profile with an injected runner and platform.
    ///
    /// # Errors
    ///
    /// Returns a typed diagnostic and never attempts an OS trust-store install.
    pub fn provision_browser_with_runner(
        &self,
        ca: &SessionCa,
        browser: BrowserKind,
        platform: BrowserPlatform,
        certutil: impl Into<PathBuf>,
        runner: &dyn ExternalToolRunner,
    ) -> Result<TrustProvisionReceipt, Diagnostic> {
        self.provision_inner(ca, browser, platform, certutil.into(), runner, true)
    }

    /// Returns the NSS database directory the selected browser will consult
    /// when launched against this isolated client context.
    #[must_use]
    pub fn nss_directory(&self, browser: BrowserKind) -> PathBuf {
        match browser {
            BrowserKind::Firefox => self.directory.clone(),
            BrowserKind::Chromium => self.directory.join(".pki").join("nssdb"),
        }
    }

    /// Returns environment overrides required to keep Chromium's Linux NSS
    /// shared database inside this isolated client context.
    #[must_use]
    pub fn browser_environment(&self, browser: BrowserKind) -> Vec<(String, String)> {
        match browser {
            BrowserKind::Firefox => Vec::new(),
            BrowserKind::Chromium => vec![
                ("HOME".to_owned(), self.directory.display().to_string()),
                (
                    "XDG_DATA_HOME".to_owned(),
                    self.directory.join(".local").display().to_string(),
                ),
            ],
        }
    }

    /// Provisions only an already-existing browser profile.
    ///
    /// # Errors
    ///
    /// Returns `proxy.browser-profile-unavailable` when the profile is absent,
    /// malformed, or locked by a browser process.
    pub fn provision_existing_browser_with_runner(
        &self,
        ca: &SessionCa,
        browser: BrowserKind,
        platform: BrowserPlatform,
        certutil: impl Into<PathBuf>,
        runner: &dyn ExternalToolRunner,
    ) -> Result<TrustProvisionReceipt, Diagnostic> {
        self.provision_inner(ca, browser, platform, certutil.into(), runner, false)
    }

    /// Tears down exactly the NSS record named by a receipt.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic if the exact record cannot be removed or
    /// owned ephemeral profile state cannot be cleaned up.
    pub fn teardown(&self, receipt: &TrustProvisionReceipt) -> Result<(), Diagnostic> {
        let runner = ProcessToolRunner;
        self.teardown_with_runner(receipt, &runner)
    }

    /// Teardown form with an injected external-tool runner.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic on any unverified removal.
    pub fn teardown_with_runner(
        &self,
        receipt: &TrustProvisionReceipt,
        runner: &dyn ExternalToolRunner,
    ) -> Result<(), Diagnostic> {
        let Some(database_path) = receipt.database_path.as_ref() else {
            return remove_staged_certificate(receipt);
        };
        let Some(nickname) = receipt.certificate_nickname.as_deref() else {
            return Err(teardown_diagnostic(
                &self.directory,
                "receipt has no NSS certificate nickname",
            ));
        };
        let certutil = receipt
            .certutil
            .clone()
            .unwrap_or_else(|| PathBuf::from("certutil"));
        let database = nss_database(database_path);
        let removal = invoke_certutil(
            runner,
            &certutil,
            vec![
                "-D".to_owned(),
                "-d".to_owned(),
                database.clone(),
                "-n".to_owned(),
                nickname.to_owned(),
            ],
            Duration::from_secs(30),
        )
        .map_err(|error| teardown_diagnostic(database_path, error.to_string()))?;
        if removal.exit_code != Some(0) {
            return Err(teardown_diagnostic(
                database_path,
                format!("certutil delete exited with {:?}", removal.exit_code),
            ));
        }
        let verification = invoke_certutil(
            runner,
            &certutil,
            vec![
                "-L".to_owned(),
                "-d".to_owned(),
                database,
                "-n".to_owned(),
                nickname.to_owned(),
            ],
            Duration::from_secs(30),
        )
        .map_err(|error| teardown_diagnostic(database_path, error.to_string()))?;
        if verification.exit_code == Some(0) {
            return Err(teardown_diagnostic(
                database_path,
                "certutil still finds the APIaxess nickname after deletion",
            ));
        }
        remove_staged_certificate(receipt)?;
        if receipt.database_created {
            remove_owned_database(database_path)?;
        }
        if receipt.database_directory_created && database_path != &self.directory {
            fs::remove_dir_all(database_path)
                .map_err(|error| teardown_diagnostic(database_path, error.to_string()))?;
            if let Some(parent) = database_path.parent() {
                if parent.file_name().and_then(|name| name.to_str()) == Some(".pki")
                    && parent
                        .read_dir()
                        .map(|mut entries| entries.next().is_none())
                        .unwrap_or(false)
                {
                    let _ = fs::remove_dir(parent);
                }
            }
        }
        if receipt.profile_created {
            let marker = self.directory.join(OWNED_PROFILE_MARKER);
            if marker.exists() {
                fs::remove_file(&marker)
                    .map_err(|error| teardown_diagnostic(&marker, error.to_string()))?;
            }
            fs::remove_dir_all(&self.directory)
                .map_err(|error| teardown_diagnostic(&self.directory, error.to_string()))?;
            if self.directory.exists() {
                return Err(teardown_diagnostic(
                    &self.directory,
                    "owned isolated profile directory still exists after removal",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn provision_inner(
        &self,
        ca: &SessionCa,
        browser: BrowserKind,
        platform: BrowserPlatform,
        certutil: PathBuf,
        runner: &dyn ExternalToolRunner,
        create_directory: bool,
    ) -> Result<TrustProvisionReceipt, Diagnostic> {
        ensure_supported(browser, platform)?;
        let profile_created = if self.directory.exists() {
            if !self.directory.is_dir() {
                return Err(profile_unavailable_diagnostic(
                    &self.directory,
                    "profile path is not a directory",
                ));
            }
            self.directory.join(OWNED_PROFILE_MARKER).exists()
        } else if create_directory {
            fs::create_dir_all(&self.directory).map_err(|error| {
                profile_unavailable_diagnostic(&self.directory, error.to_string())
            })?;
            fs::write(
                self.directory.join(OWNED_PROFILE_MARKER),
                b"APIaxess disposable browser profile\n",
            )
            .map_err(|error| profile_unavailable_diagnostic(&self.directory, error.to_string()))?;
            true
        } else {
            return Err(profile_unavailable_diagnostic(
                &self.directory,
                "existing profile directory was not found",
            ));
        };
        if let Some(lock) = profile_lock(&self.directory, browser) {
            return Err(profile_unavailable_diagnostic(
                &lock,
                "profile is locked by a running browser",
            ));
        }
        let database_directory = self.nss_directory(browser);
        let database_directory_created = if database_directory.exists() {
            false
        } else {
            fs::create_dir_all(&database_directory).map_err(|error| {
                profile_unavailable_diagnostic(&database_directory, error.to_string())
            })?;
            true
        };
        let cert9 = database_directory.join("cert9.db");
        let key4 = database_directory.join("key4.db");
        let database_created = !cert9.exists() && !key4.exists();
        let help = invoke_certutil(
            runner,
            &certutil,
            vec!["-H".to_owned()],
            Duration::from_secs(30),
        )
        .map_err(|error| {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            nss_tool_diagnostic(&certutil, error.to_string())
        })?;
        // NSS certutil versions commonly return a non-zero status for `-H`
        // and some write their complete help to stderr. The stable
        // discriminator is the NSS-specific `-A` command, not the help
        // command's exit code or output stream.
        if !help.stdout.contains("-A") && !help.stderr.contains("-A") {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            return Err(nss_tool_diagnostic(
                &certutil,
                "executable did not identify itself as NSS certutil",
            ));
        }
        let help_output = format!("{}\n{}", help.stdout, help.stderr);
        if !help_output.contains("-N") {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            return Err(nss_version_unsupported_diagnostic(
                &certutil,
                "certutil help does not expose the modern -N SQL database operation",
            ));
        }
        if let Err(diagnostic) = verify_modern_nss_database(&database_directory, &certutil, runner)
        {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            return Err(diagnostic);
        }
        if cert9.exists() != key4.exists() {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            return Err(profile_provisioning_diagnostic(
                &self.directory,
                "profile has an incomplete NSS cert9.db/key4.db pair",
            ));
        }
        let certificate_path = self
            .nss_directory(browser)
            .join(format!("apiaxess-session-ca-{}.pem", ca.fingerprint()));
        if let Err(error) = fs::write(&certificate_path, ca.root_certificate_pem()) {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                None,
                database_created,
                profile_created,
            );
            return Err(profile_provisioning_diagnostic(
                &certificate_path,
                error.to_string(),
            ));
        }
        let database = nss_database(&database_directory);
        let nickname = format!("APIaxess Session CA {}", ca.fingerprint());
        if database_created {
            let password_file = database_directory.join(".apiaxess-empty-password");
            if let Err(error) = fs::write(&password_file, b"\n") {
                cleanup_failed_provision(
                    &self.directory,
                    &certutil,
                    runner,
                    Some(&certificate_path),
                    database_created,
                    profile_created,
                );
                return Err(profile_provisioning_diagnostic(
                    &password_file,
                    error.to_string(),
                ));
            }
            let initialized = match invoke_certutil(
                runner,
                &certutil,
                vec![
                    "-N".to_owned(),
                    "-d".to_owned(),
                    database.clone(),
                    "-f".to_owned(),
                    password_file.display().to_string(),
                ],
                Duration::from_secs(30),
            ) {
                Ok(value) => value,
                Err(error) => {
                    cleanup_failed_provision(
                        &self.directory,
                        &certutil,
                        runner,
                        Some(&certificate_path),
                        database_created,
                        profile_created,
                    );
                    return Err(profile_provisioning_or_tool_diagnostic(
                        &self.directory,
                        &error,
                    ));
                }
            };
            let _ = fs::remove_file(&password_file);
            if initialized.exit_code != Some(0) {
                cleanup_failed_provision(
                    &self.directory,
                    &certutil,
                    runner,
                    Some(&certificate_path),
                    database_created,
                    profile_created,
                );
                return Err(profile_provisioning_diagnostic(
                    &self.directory,
                    format!(
                        "certutil database initialization exited with {:?}",
                        initialized.exit_code
                    ),
                ));
            }
        }
        let imported = match invoke_certutil(
            runner,
            &certutil,
            vec![
                "-A".to_owned(),
                "-d".to_owned(),
                database.clone(),
                "-n".to_owned(),
                nickname.clone(),
                "-t".to_owned(),
                "C,,".to_owned(),
                "-i".to_owned(),
                certificate_path.display().to_string(),
            ],
            Duration::from_secs(30),
        ) {
            Ok(value) => value,
            Err(error) => {
                cleanup_failed_provision(
                    &self.directory,
                    &certutil,
                    runner,
                    Some(&certificate_path),
                    database_created,
                    profile_created,
                );
                return Err(profile_provisioning_or_tool_diagnostic(
                    &self.directory,
                    &error,
                ));
            }
        };
        if imported.exit_code != Some(0) {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                Some(&certificate_path),
                database_created,
                profile_created,
            );
            return Err(profile_provisioning_diagnostic(
                &self.directory,
                format!(
                    "certutil certificate import exited with {:?}",
                    imported.exit_code
                ),
            ));
        }
        if !cert9.is_file() || !key4.is_file() {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                Some(&certificate_path),
                database_created,
                profile_created,
            );
            return Err(profile_provisioning_diagnostic(
                &self.directory,
                "NSS certutil reported success but cert9.db/key4.db are absent",
            ));
        }
        let verified = match invoke_certutil(
            runner,
            &certutil,
            vec![
                "-L".to_owned(),
                "-d".to_owned(),
                database,
                "-n".to_owned(),
                nickname.clone(),
            ],
            Duration::from_secs(30),
        ) {
            Ok(value) => value,
            Err(error) => {
                cleanup_failed_provision(
                    &self.directory,
                    &certutil,
                    runner,
                    Some(&certificate_path),
                    database_created,
                    profile_created,
                );
                return Err(profile_provisioning_or_tool_diagnostic(
                    &self.directory,
                    &error,
                ));
            }
        };
        if verified.exit_code != Some(0) {
            cleanup_failed_provision(
                &self.directory,
                &certutil,
                runner,
                Some(&certificate_path),
                database_created,
                profile_created,
            );
            return Err(profile_provisioning_diagnostic(
                &self.directory,
                "certutil could not verify the imported session CA nickname",
            ));
        }
        Ok(TrustProvisionReceipt {
            fingerprint: ca.fingerprint().to_owned(),
            certificate_path,
            scope: TrustScope::ClientProfile,
            database_path: Some(database_directory),
            certificate_nickname: Some(nickname),
            browser: Some(browser),
            platform: Some(platform),
            database_created,
            database_directory_created,
            profile_created,
            certutil: Some(certutil),
        })
    }
}

/// Public browser-trust status returned by the local workbench API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserTrustStatus {
    /// Whether browser trust has been provisioned for this session.
    pub provisioned: bool,
    /// Disposable profile to pass to the launched browser.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_directory: Option<PathBuf>,
    /// Provisioning receipt, when active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<TrustProvisionReceipt>,
}

#[derive(Clone, Debug)]
struct ActiveBrowserTrust {
    profile: ClientProfile,
    receipt: TrustProvisionReceipt,
    marker: String,
}

/// Session-scoped browser CA provisioning and teardown controller.
#[derive(Debug)]
pub struct BrowserTrustController {
    ca: std::sync::RwLock<Option<SessionCa>>,
    active: std::sync::Mutex<Option<ActiveBrowserTrust>>,
    state_path: PathBuf,
}

impl Default for BrowserTrustController {
    fn default() -> Self {
        Self::new()
    }
}

impl BrowserTrustController {
    /// Creates an empty controller; the active session CA must be configured
    /// before the GUI provisioning action can run.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ca: std::sync::RwLock::new(None),
            active: std::sync::Mutex::new(None),
            state_path: std::env::var_os("APIAXESS_CA_STATE_LOG").map_or_else(
                || std::env::temp_dir().join("apiaxess-ca-state.json"),
                PathBuf::from,
            ),
        }
    }

    /// Binds this controller to the in-memory CA of the active session.
    pub fn configure_ca(&self, ca: SessionCa) {
        if let Ok(mut configured) = self.ca.write() {
            *configured = Some(ca);
        }
    }

    /// Provisions Firefox against a fresh disposable profile.
    ///
    /// # Errors
    ///
    /// Returns the existing NSS/profile diagnostic unchanged and removes the
    /// disposable profile if provisioning cannot complete.
    pub fn provision_firefox(&self) -> Result<BrowserTrustStatus, Diagnostic> {
        self.provision_browser(BrowserKind::Firefox)
    }

    /// Provisions a supported browser against a fresh disposable profile.
    ///
    /// Chromium is supported only on Linux; the platform capability check is
    /// deliberately performed before any browser process is launched.
    ///
    /// # Errors
    ///
    /// Returns a browser-platform, profile, NSS, persistence, or teardown
    /// diagnostic when the isolated profile cannot be prepared.
    pub fn provision_browser(
        &self,
        browser: BrowserKind,
    ) -> Result<BrowserTrustStatus, Diagnostic> {
        if let Ok(active) = self.active.lock() {
            if let Some(active) = active.as_ref() {
                return Ok(status_for(active));
            }
        }
        let ca = self
            .ca
            .read()
            .ok()
            .and_then(|configured| configured.clone())
            .ok_or_else(|| {
                profile_provisioning_diagnostic(
                    Path::new("session-ca"),
                    "the active session CA is not configured",
                )
            })?;
        let profile = ClientProfile::isolated()?;
        // Guarantee the disposable profile directory is removed on every exit
        // path between here and the point it is handed to the session-owned
        // `ActiveBrowserTrust` below — including any future early-return that
        // forgets to clean up. Disarmed once ownership transfers so the profile
        // persists for the session (torn down later by `teardown`).
        let mut profile_guard = IsolatedProfileGuard::new(profile.directory.clone());
        let receipt = profile.provision_browser(&ca, browser)?;
        let marker = browser_profile_marker(&profile, &receipt);
        let mut state = match CaStateLog::load(&self.state_path) {
            Ok(state) => state,
            Err(diagnostic) => {
                let _ = profile.teardown(&receipt);
                return Err(diagnostic);
            }
        };
        if let Err(diagnostic) = state.record_browser_profile(
            &self.state_path,
            BrowserProfileInstall {
                marker: marker.clone(),
                profile_directory: profile.directory.clone(),
                receipt: receipt.clone(),
            },
        ) {
            let _ = profile.teardown(&receipt);
            return Err(diagnostic);
        }
        let status = BrowserTrustStatus {
            provisioned: true,
            profile_directory: Some(profile.directory.clone()),
            receipt: Some(receipt.clone()),
        };
        let Ok(mut active) = self.active.lock() else {
            let _ = profile.teardown(&receipt);
            let _ = state.confirm_browser_profile_removed(&self.state_path, &marker);
            return Err(teardown_diagnostic(
                &profile.directory,
                "browser trust state lock was poisoned",
            ));
        };
        if let Some(existing) = active.as_ref() {
            let existing_status = status_for(existing);
            profile.teardown(&receipt)?;
            state.confirm_browser_profile_removed(&self.state_path, &marker)?;
            return Ok(existing_status);
        }
        *active = Some(ActiveBrowserTrust {
            profile,
            receipt,
            marker,
        });
        // Ownership of the profile directory has transferred to the session; it
        // must survive for the session, so stop the guard from removing it.
        profile_guard.disarm();
        Ok(status)
    }

    /// Reports whether the session currently has a provisioned Firefox profile.
    #[must_use]
    pub fn status(&self) -> BrowserTrustStatus {
        self.active
            .lock()
            .ok()
            .and_then(|active| active.as_ref().map(status_for))
            .unwrap_or(BrowserTrustStatus {
                provisioned: false,
                profile_directory: None,
                receipt: None,
            })
    }

    /// Removes the exact session CA and deletes the disposable profile.
    ///
    /// # Errors
    ///
    /// Returns a teardown diagnostic when the exact NSS entry or ephemeral
    /// profile cannot be removed and verified.
    pub fn teardown(&self) -> Result<(), Diagnostic> {
        let active = self
            .active
            .lock()
            .map_err(|_| teardown_diagnostic(Path::new("browser-trust"), "state lock poisoned"))?
            .take();
        let Some(active) = active else { return Ok(()) };
        active.profile.teardown(&active.receipt)?;
        let mut state = CaStateLog::load(&self.state_path)?;
        state.confirm_browser_profile_removed(&self.state_path, &active.marker)
    }
}

fn browser_profile_marker(profile: &ClientProfile, receipt: &TrustProvisionReceipt) -> String {
    format!(
        "apiaxess:browser:{}:{}",
        receipt.fingerprint,
        profile.directory.display()
    )
}

fn status_for(active: &ActiveBrowserTrust) -> BrowserTrustStatus {
    BrowserTrustStatus {
        provisioned: true,
        profile_directory: Some(active.profile.directory.clone()),
        receipt: Some(active.receipt.clone()),
    }
}

fn ensure_supported(browser: BrowserKind, platform: BrowserPlatform) -> Result<(), Diagnostic> {
    if matches!(
        (browser, platform),
        (
            BrowserKind::Firefox,
            BrowserPlatform::Linux | BrowserPlatform::Windows
        ) | (BrowserKind::Chromium, BrowserPlatform::Linux)
    ) {
        return Ok(());
    }
    let mut context = DiagnosticContext::new();
    context.insert(
        "browser".to_owned(),
        DiagnosticValue::String(format!("{browser:?}").to_ascii_lowercase()),
    );
    context.insert(
        "platform".to_owned(),
        DiagnosticValue::String(format!("{platform:?}").to_ascii_lowercase()),
    );
    context.insert(
        "reason".to_owned(),
        DiagnosticValue::String(
            if matches!(
                (browser, platform),
                (BrowserKind::Chromium, BrowserPlatform::Windows)
            ) {
                "Chromium on Windows has no portable client-scoped trust store; its documented Windows trust inputs are the platform/Chrome stores or managed CACertificates policy, neither of which is an APIaxess disposable profile adapter"
            } else {
                "no supported client-scoped NSS browser adapter exists"
            }
            .to_owned(),
        ),
    );
    Err(catalogue::PROXY_BROWSER_PLATFORM_UNSUPPORTED.instantiate(context))
}

fn profile_lock(directory: &Path, browser: BrowserKind) -> Option<PathBuf> {
    let names: &[&str] = match browser {
        BrowserKind::Firefox => &[".parentlock", "parent.lock", "lock"],
        BrowserKind::Chromium => &["SingletonLock", "SingletonCookie", "SingletonSocket"],
    };
    names
        .iter()
        .map(|name| directory.join(name))
        .find(|path| path.exists())
}

fn nss_database(directory: &Path) -> String {
    format!("sql:{}", directory.display())
}

fn invoke_certutil(
    runner: &dyn ExternalToolRunner,
    executable: &Path,
    arguments: Vec<String>,
    timeout: Duration,
) -> Result<ToolInvocation, apiaxess_external_tools::ExternalToolError> {
    let probe = ToolProbe {
        tool_id: NSS_TOOL_ID.to_owned(),
        executable: executable.display().to_string(),
        version: ToolVersion {
            major: 0,
            minor: 0,
            patch: 0,
        },
        raw_output: "NSS certutil configured through the external-tools boundary".to_owned(),
    };
    runner.invoke(&ToolInvocationRequest {
        probe,
        arguments,
        working_directory: None,
        environment: Vec::new(),
        timeout,
    })
}

fn remove_staged_certificate(receipt: &TrustProvisionReceipt) -> Result<(), Diagnostic> {
    if receipt.certificate_path.exists() {
        fs::remove_file(&receipt.certificate_path)
            .map_err(|error| teardown_diagnostic(&receipt.certificate_path, error.to_string()))?;
    }
    Ok(())
}

fn remove_owned_database(directory: &Path) -> Result<(), Diagnostic> {
    for name in ["cert9.db", "key4.db", "pkcs11.txt"] {
        let path = directory.join(name);
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| teardown_diagnostic(&path, error.to_string()))?;
        }
    }
    Ok(())
}

fn cleanup_failed_provision(
    directory: &Path,
    certutil: &Path,
    runner: &dyn ExternalToolRunner,
    certificate_path: Option<&Path>,
    database_created: bool,
    profile_created: bool,
) {
    let database_directory = certificate_path.and_then(Path::parent).unwrap_or(directory);
    if let Some(certificate_path) = certificate_path {
        if let Some(file_name) = certificate_path.file_name().and_then(|name| name.to_str()) {
            if let Some(fingerprint) = file_name
                .strip_prefix("apiaxess-session-ca-")
                .and_then(|name| name.strip_suffix(".pem"))
            {
                let _ = invoke_certutil(
                    runner,
                    certutil,
                    vec![
                        "-D".to_owned(),
                        "-d".to_owned(),
                        nss_database(database_directory),
                        "-n".to_owned(),
                        format!("APIaxess Session CA {fingerprint}"),
                    ],
                    Duration::from_secs(30),
                );
            }
        }
        let _ = fs::remove_file(certificate_path);
    }
    if database_created {
        let _ = remove_owned_database(database_directory);
        if database_directory != directory && database_directory.exists() {
            let _ = fs::remove_dir_all(database_directory);
        }
    }
    if profile_created {
        let _ = fs::remove_file(directory.join(OWNED_PROFILE_MARKER));
        let _ = fs::remove_dir_all(directory);
    }
}

fn profile_unavailable_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    catalogue::PROXY_BROWSER_PROFILE_UNAVAILABLE.instantiate(path_context(path, error))
}

fn profile_provisioning_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    catalogue::PROXY_BROWSER_PROFILE_PROVISIONING_FAILED.instantiate(path_context(path, error))
}

fn profile_provisioning_or_tool_diagnostic(
    path: &Path,
    error: &apiaxess_external_tools::ExternalToolError,
) -> Diagnostic {
    if matches!(
        error,
        apiaxess_external_tools::ExternalToolError::Start { .. }
            | apiaxess_external_tools::ExternalToolError::Unsupported { .. }
    ) {
        let mut context = path_context(path, error.to_string());
        context.insert(
            "tool_id".to_owned(),
            DiagnosticValue::String(NSS_TOOL_ID.to_owned()),
        );
        catalogue::PROXY_NSS_TOOL_UNAVAILABLE.instantiate(context)
    } else {
        profile_provisioning_diagnostic(path, error.to_string())
    }
}

fn nss_tool_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    let mut context = path_context(path, error);
    context.insert(
        "tool_id".to_owned(),
        DiagnosticValue::String(NSS_TOOL_ID.to_owned()),
    );
    catalogue::PROXY_NSS_TOOL_UNAVAILABLE.instantiate(context)
}

fn nss_version_unsupported_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    let mut context = path_context(path, error);
    context.insert(
        "detected_version".to_owned(),
        DiagnosticValue::String("legacy/unknown (modern SQL capability probe failed)".to_owned()),
    );
    context.insert(
        "required_version".to_owned(),
        DiagnosticValue::String(NSS_MODERN_MINIMUM_VERSION.to_owned()),
    );
    context.insert(
        "profile_format".to_owned(),
        DiagnosticValue::String("cert9.db/key4.db".to_owned()),
    );
    context.insert(
        "tool_id".to_owned(),
        DiagnosticValue::String(NSS_TOOL_ID.to_owned()),
    );
    catalogue::PROXY_NSS_VERSION_UNSUPPORTED.instantiate(context)
}

fn verify_modern_nss_database(
    parent: &Path,
    certutil: &Path,
    runner: &dyn ExternalToolRunner,
) -> Result<(), Diagnostic> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let probe_directory = parent.join(format!(".apiaxess-nss-probe-{nonce}"));
    fs::create_dir(&probe_directory)
        .map_err(|error| profile_provisioning_diagnostic(&probe_directory, error.to_string()))?;
    let password_file = probe_directory.join(".empty-password");
    let result = (|| {
        fs::write(&password_file, b"\n")
            .map_err(|error| profile_provisioning_diagnostic(&password_file, error.to_string()))?;
        let database = nss_database(&probe_directory);
        let initialized = invoke_certutil(
            runner,
            certutil,
            vec![
                "-N".to_owned(),
                "-d".to_owned(),
                database.clone(),
                "-f".to_owned(),
                password_file.display().to_string(),
            ],
            Duration::from_secs(30),
        )
        .map_err(|error| profile_provisioning_or_tool_diagnostic(&probe_directory, &error))?;
        if initialized.exit_code != Some(0) {
            return Err(nss_version_unsupported_diagnostic(
                certutil,
                format!(
                    "modern SQL database initialization exited with {:?}: {}",
                    initialized.exit_code,
                    invocation_output(&initialized)
                ),
            ));
        }
        let cert9 = probe_directory.join("cert9.db");
        let key4 = probe_directory.join("key4.db");
        if !cert9.is_file() || !key4.is_file() {
            return Err(nss_version_unsupported_diagnostic(
                certutil,
                "certutil reported success but did not create cert9.db and key4.db",
            ));
        }
        let listing = invoke_certutil(
            runner,
            certutil,
            vec!["-L".to_owned(), "-d".to_owned(), database],
            Duration::from_secs(30),
        )
        .map_err(|error| profile_provisioning_or_tool_diagnostic(&probe_directory, &error))?;
        if listing.exit_code != Some(0) {
            return Err(nss_version_unsupported_diagnostic(
                certutil,
                format!(
                    "cert9.db/key4.db reopen probe exited with {:?}: {}",
                    listing.exit_code,
                    invocation_output(&listing)
                ),
            ));
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&probe_directory).map_err(|error| {
        profile_provisioning_diagnostic(
            &probe_directory,
            format!("modern NSS capability probe cleanup failed: {error}"),
        )
    });
    match result {
        Err(diagnostic) => match cleanup {
            Err(cleanup_diagnostic) => Err(cleanup_diagnostic),
            Ok(()) => Err(diagnostic),
        },
        Ok(()) => cleanup,
    }
}

fn invocation_output(invocation: &ToolInvocation) -> String {
    let stdout = invocation.stdout.trim();
    let stderr = invocation.stderr.trim();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "no output".to_owned(),
        (false, true) => stdout.to_owned(),
        (true, false) => stderr.to_owned(),
        (false, false) => format!("{stdout}; stderr: {stderr}"),
    }
}

fn teardown_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    catalogue::PROXY_BROWSER_PROFILE_TEARDOWN_FAILED.instantiate(path_context(path, error))
}

fn path_context(path: &Path, error: impl Into<String>) -> DiagnosticContext {
    let mut context = DiagnosticContext::new();
    context.insert(
        "path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    context.insert("error".to_owned(), DiagnosticValue::String(error.into()));
    context
}

/// Exact record retained for every exceptional system trust-store install.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemCaInstall {
    /// Unique marker used by recovery sweeps.
    pub marker: String,
    /// CA SHA-256 fingerprint.
    pub fingerprint: String,
    /// Certificate serial recorded by the platform adapter.
    pub serial: String,
    /// Exact platform store location or identifier.
    pub store_location: String,
}

/// Exact record retained for an isolated browser-profile trust install.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BrowserProfileInstall {
    /// Unique recovery marker.
    pub marker: String,
    /// Profile directory containing the NSS database.
    pub profile_directory: PathBuf,
    /// Provisioning receipt with exact nickname and database ownership.
    pub receipt: TrustProvisionReceipt,
}

/// Persistent recovery state for trust installs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CaStateLog {
    /// State-log schema version.
    pub schema_version: u32,
    /// Exact system installs not yet confirmed removed.
    pub installs: Vec<SystemCaInstall>,
    /// Exact client-profile installs not yet confirmed removed.
    #[serde(default)]
    pub browser_profiles: Vec<BrowserProfileInstall>,
}

impl Default for CaStateLog {
    fn default() -> Self {
        Self {
            schema_version: STATE_LOG_VERSION,
            installs: Vec::new(),
            browser_profiles: Vec::new(),
        }
    }
}

impl CaStateLog {
    /// Loads a state log or returns an empty log when the path does not exist.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic for malformed or unreadable state.
    pub fn load(path: &Path) -> Result<Self, Diagnostic> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| state_log_diagnostic(path, error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(state_log_diagnostic(path, error.to_string())),
        }
    }

    /// Adds or replaces an exact system-store install record and persists the log.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic when the state cannot be encoded or written.
    pub fn record_install(
        &mut self,
        path: &Path,
        install: SystemCaInstall,
    ) -> Result<(), Diagnostic> {
        self.ensure_version(path)?;
        self.installs
            .retain(|existing| existing.marker != install.marker);
        self.installs.push(install);
        self.save(path)
    }

    /// Adds or replaces an exact browser-profile record and persists the log.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic when the state cannot be encoded or written.
    pub fn record_browser_profile(
        &mut self,
        path: &Path,
        install: BrowserProfileInstall,
    ) -> Result<(), Diagnostic> {
        self.ensure_version(path)?;
        self.browser_profiles
            .retain(|existing| existing.marker != install.marker);
        self.browser_profiles.push(install);
        self.save(path)
    }

    /// Persists the current state log.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic when the state cannot be encoded or written.
    pub fn save(&self, path: &Path) -> Result<(), Diagnostic> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| state_log_diagnostic(path, error.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| state_log_diagnostic(path, error.to_string()))?;
        }
        fs::write(path, bytes).map_err(|error| state_log_diagnostic(path, error.to_string()))
    }

    /// Removes one system-store record after its adapter confirms removal.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic if the marker is not present or state cannot persist.
    pub fn confirm_removed(&mut self, path: &Path, marker: &str) -> Result<(), Diagnostic> {
        let before = self.installs.len();
        self.installs.retain(|install| install.marker != marker);
        if before == self.installs.len() {
            return Err(state_log_diagnostic(
                path,
                "CA recovery marker was not recorded",
            ));
        }
        self.save(path)
    }

    /// Purges all recorded browser profiles and removes records only after
    /// exact certificate deletion and profile cleanup succeed.
    ///
    /// # Errors
    ///
    /// Returns the first teardown or state-log diagnostic and leaves any
    /// unprocessed records in the log for another recovery attempt.
    pub fn purge_browser_profiles_with(
        &mut self,
        path: &Path,
        runner: &dyn ExternalToolRunner,
    ) -> Result<usize, Diagnostic> {
        let records = self.browser_profiles.clone();
        let mut removed = 0;
        for record in records {
            let profile = ClientProfile {
                directory: record.profile_directory.clone(),
            };
            profile.teardown_with_runner(&record.receipt, runner)?;
            let before = self.browser_profiles.len();
            self.browser_profiles
                .retain(|item| item.marker != record.marker);
            if before == self.browser_profiles.len() {
                return Err(state_log_diagnostic(
                    path,
                    "browser-profile recovery marker was not recorded",
                ));
            }
            self.save(path)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Purges all recorded browser profiles through the production tool runner.
    ///
    /// # Errors
    ///
    /// Returns the first browser-profile teardown or state-log diagnostic.
    pub fn purge_browser_profiles(&mut self, path: &Path) -> Result<usize, Diagnostic> {
        self.purge_browser_profiles_with(path, &ProcessToolRunner)
    }

    /// Removes one browser-profile record after its adapter confirms removal.
    ///
    /// # Errors
    ///
    /// Returns a purge diagnostic if the marker is not present or state cannot
    /// be persisted.
    pub fn confirm_browser_profile_removed(
        &mut self,
        path: &Path,
        marker: &str,
    ) -> Result<(), Diagnostic> {
        let before = self.browser_profiles.len();
        self.browser_profiles
            .retain(|install| install.marker != marker);
        if before == self.browser_profiles.len() {
            return Err(state_log_diagnostic(
                path,
                "browser-profile recovery marker was not recorded",
            ));
        }
        self.save(path)
    }

    /// Runs the standalone system-store purge operation through an adapter.
    ///
    /// # Errors
    ///
    /// Returns the stable trust-purge diagnostic if an adapter refuses removal.
    pub fn purge_with<P: SystemStorePurger>(
        &mut self,
        path: &Path,
        purger: &P,
    ) -> Result<usize, Diagnostic> {
        let installs = self.installs.clone();
        let mut removed = 0;
        for install in installs {
            purger.remove(&install)?;
            self.confirm_removed(path, &install.marker)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn ensure_version(&self, path: &Path) -> Result<(), Diagnostic> {
        if self.schema_version == STATE_LOG_VERSION {
            Ok(())
        } else {
            Err(state_log_diagnostic(
                path,
                "unsupported CA state-log version",
            ))
        }
    }
}

/// Platform adapter used only for explicit system-store recovery.
pub trait SystemStorePurger {
    /// Removes the exact certificate identified by the recorded marker,
    /// fingerprint, serial, and store location.
    ///
    /// # Errors
    ///
    /// Returns a trust-purge diagnostic when the platform store refuses or
    /// cannot verify removal.
    fn remove(&self, install: &SystemCaInstall) -> Result<(), Diagnostic>;
}

fn state_log_diagnostic(path: &Path, error: impl Into<String>) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "path".to_owned(),
        DiagnosticValue::String(path.display().to_string()),
    );
    context.insert("error".to_owned(), DiagnosticValue::String(error.into()));
    catalogue::PROXY_TRUST_PURGE_FAILED.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserKind, BrowserPlatform, CaStateLog, ClientProfile, IsolatedProfileGuard, TrustScope,
    };
    use crate::SessionCa;
    use apiaxess_external_tools::{
        ExternalToolError, ExternalToolRunner, ToolInvocation, ToolInvocationRequest, ToolProbe,
    };
    use std::{
        path::Path,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("apiaxess-{name}-{nonce}"))
    }

    #[test]
    fn isolated_profile_guard_removes_on_drop_unless_disarmed() {
        // Armed: dropping the guard removes the disposable directory, so a caller
        // that returns early without teardown cannot leak the profile.
        let leaked = temporary_path("profile-guard-armed");
        std::fs::create_dir_all(&leaked).expect("create dir");
        {
            let _guard = IsolatedProfileGuard::new(leaked.clone());
        }
        assert!(
            !leaked.exists(),
            "armed guard must remove the directory on drop"
        );

        // Disarmed: ownership transferred, so the directory survives for the
        // session and is torn down later by the controller.
        let kept = temporary_path("profile-guard-disarmed");
        std::fs::create_dir_all(&kept).expect("create dir");
        {
            let mut guard = IsolatedProfileGuard::new(kept.clone());
            guard.disarm();
        }
        assert!(
            kept.exists(),
            "disarmed guard must leave the directory in place"
        );
        std::fs::remove_dir_all(&kept).expect("cleanup");
    }

    #[derive(Debug)]
    struct FakeNssRunner {
        calls: Mutex<Vec<Vec<String>>>,
        modern_help: bool,
    }

    impl Default for FakeNssRunner {
        fn default() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                modern_help: true,
            }
        }
    }

    impl ExternalToolRunner for FakeNssRunner {
        fn probe(
            &self,
            _request: &apiaxess_external_tools::ToolProbeRequest,
        ) -> Result<ToolProbe, ExternalToolError> {
            Err(ExternalToolError::Unsupported {
                tool_id: "fake".to_owned(),
                detail: "not used".to_owned(),
            })
        }

        fn invoke(
            &self,
            request: &ToolInvocationRequest,
        ) -> Result<ToolInvocation, ExternalToolError> {
            self.calls
                .lock()
                .expect("calls")
                .push(request.arguments.clone());
            if request.arguments.iter().any(|argument| argument == "-H") {
                return Ok(ToolInvocation {
                    stdout: if self.modern_help {
                        "-A -N NSS certutil help".to_owned()
                    } else {
                        "-A NSS certutil legacy help".to_owned()
                    },
                    stderr: String::new(),
                    exit_code: Some(0),
                    duration: std::time::Duration::ZERO,
                });
            }
            let database = request
                .arguments
                .iter()
                .find_map(|argument| argument.strip_prefix("sql:"));
            let Some(database) = database else {
                return Err(ExternalToolError::Unsupported {
                    tool_id: "fake".to_owned(),
                    detail: "database missing".to_owned(),
                });
            };
            let directory = Path::new(database);
            if request.arguments.iter().any(|argument| argument == "-N") {
                std::fs::write(directory.join("cert9.db"), b"fake").expect("cert9");
                std::fs::write(directory.join("key4.db"), b"fake").expect("key4");
            }
            if request.arguments.iter().any(|argument| argument == "-A") {
                std::fs::write(directory.join("fake-nss-record"), b"present").expect("record");
            }
            if request.arguments.iter().any(|argument| argument == "-D") {
                let _ = std::fs::remove_file(directory.join("fake-nss-record"));
            }
            let listing = request.arguments.iter().any(|argument| argument == "-L");
            let specific_listing = request.arguments.iter().any(|argument| argument == "-n");
            let found = directory.join("fake-nss-record").exists();
            Ok(ToolInvocation {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: Some(i32::from(listing && specific_listing && !found)),
                duration: std::time::Duration::ZERO,
            })
        }
    }

    #[test]
    fn nss_profile_imports_and_tears_down_without_private_key_or_system_store() {
        let ca = SessionCa::generate().expect("CA");
        let directory = temporary_path("nss-profile");
        let runner = FakeNssRunner::default();
        let profile = ClientProfile {
            directory: directory.clone(),
        };
        let receipt = profile
            .provision_browser_with_runner(
                &ca,
                BrowserKind::Firefox,
                BrowserPlatform::Linux,
                "fake-certutil",
                &runner,
            )
            .expect("NSS provision");
        assert_eq!(receipt.scope, TrustScope::ClientProfile);
        assert!(directory.join("cert9.db").is_file());
        assert!(directory.join("key4.db").is_file());
        assert!(!directory.join("apiaxess-session-ca-key.pem").exists());
        assert!(
            runner
                .calls
                .lock()
                .expect("calls")
                .iter()
                .any(|call| call.iter().any(|arg| arg == "-A"))
        );
        profile
            .teardown_with_runner(&receipt, &runner)
            .expect("NSS teardown");
        assert!(!directory.exists());
    }

    #[test]
    fn chromium_windows_is_rejected_without_creating_a_profile_or_touching_os_store() {
        let ca = SessionCa::generate().expect("CA");
        let directory = temporary_path("chromium-windows");
        let runner = FakeNssRunner::default();
        let result = ClientProfile {
            directory: directory.clone(),
        }
        .provision_browser_with_runner(
            &ca,
            BrowserKind::Chromium,
            BrowserPlatform::Windows,
            "fake-certutil",
            &runner,
        );
        let diagnostic = result.expect_err("unsupported path");
        assert_eq!(diagnostic.id.as_ref(), "proxy.browser-platform-unsupported");
        assert!(diagnostic.fix.contains("use Firefox"));
        assert!(diagnostic.why.contains("CACertificates"));
        assert!(!directory.exists());
        assert!(runner.calls.lock().expect("calls").is_empty());
    }

    #[test]
    fn legacy_nss_is_rejected_before_touching_the_profile() {
        let ca = SessionCa::generate().expect("CA");
        let directory = temporary_path("legacy-nss");
        let runner = FakeNssRunner {
            modern_help: false,
            ..FakeNssRunner::default()
        };
        let result = ClientProfile {
            directory: directory.clone(),
        }
        .provision_browser_with_runner(
            &ca,
            BrowserKind::Firefox,
            BrowserPlatform::Windows,
            "legacy-certutil",
            &runner,
        );
        let diagnostic = result.expect_err("legacy NSS must be rejected");
        assert_eq!(diagnostic.id.as_ref(), "proxy.nss-version-unsupported");
        assert!(diagnostic.fix.contains("3.14"));
        assert!(!directory.exists());
    }

    #[test]
    fn chromium_linux_uses_isolated_home_nss_shared_database() {
        let ca = SessionCa::generate().expect("CA");
        let directory = temporary_path("chromium-linux");
        let runner = FakeNssRunner::default();
        let profile = ClientProfile {
            directory: directory.clone(),
        };
        let receipt = profile
            .provision_browser_with_runner(
                &ca,
                BrowserKind::Chromium,
                BrowserPlatform::Linux,
                "fake-certutil",
                &runner,
            )
            .expect("NSS provision");
        assert_eq!(
            receipt.database_path.as_deref(),
            Some(directory.join(".pki").join("nssdb")).as_deref()
        );
        assert!(
            profile
                .browser_environment(BrowserKind::Chromium)
                .iter()
                .any(|(key, value)| key == "HOME" && value == &directory.display().to_string())
        );
        profile
            .teardown_with_runner(&receipt, &runner)
            .expect("NSS teardown");
        assert!(!directory.exists());
    }

    #[test]
    fn locked_or_missing_existing_profile_is_diagnostic() {
        let ca = SessionCa::generate().expect("CA");
        let runner = FakeNssRunner::default();
        let missing = ClientProfile {
            directory: temporary_path("missing-profile"),
        };
        assert_eq!(
            missing
                .provision_existing_browser_with_runner(
                    &ca,
                    BrowserKind::Firefox,
                    BrowserPlatform::Linux,
                    "fake",
                    &runner
                )
                .expect_err("missing")
                .id
                .as_ref(),
            "proxy.browser-profile-unavailable"
        );
        let directory = temporary_path("locked-profile");
        std::fs::create_dir_all(&directory).expect("profile");
        std::fs::write(directory.join(".parentlock"), b"lock").expect("lock");
        assert_eq!(
            ClientProfile {
                directory: directory.clone()
            }
            .provision_existing_browser_with_runner(
                &ca,
                BrowserKind::Firefox,
                BrowserPlatform::Linux,
                "fake",
                &runner
            )
            .expect_err("locked")
            .id
            .as_ref(),
            "proxy.browser-profile-unavailable"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn state_log_round_trips_browser_profile_records() {
        let path = temporary_path("ca-state.json");
        let receipt = super::TrustProvisionReceipt {
            fingerprint: "a".repeat(64),
            certificate_path: temporary_path("cert.pem"),
            scope: TrustScope::ClientProfile,
            database_path: Some(temporary_path("profile")),
            certificate_nickname: Some("APIaxess Session CA".to_owned()),
            browser: Some(BrowserKind::Firefox),
            platform: Some(BrowserPlatform::Linux),
            database_created: true,
            database_directory_created: false,
            profile_created: true,
            certutil: Some("certutil".into()),
        };
        let mut log = CaStateLog::default();
        log.record_browser_profile(
            &path,
            super::BrowserProfileInstall {
                marker: "apiaxess:browser:one".to_owned(),
                profile_directory: temporary_path("profile"),
                receipt,
            },
        )
        .expect("state log");
        assert_eq!(
            CaStateLog::load(&path)
                .expect("load")
                .browser_profiles
                .len(),
            1
        );
        let _ = std::fs::remove_file(path);
    }
}
