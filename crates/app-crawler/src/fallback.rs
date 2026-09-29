//! Secondary-crawler fallback seam.
//!
//! The primary engine is the state-graph traverser in this crate. `DroidBot`
//! (MIT) is bundled as an *accelerator / reference / fallback* for the case the
//! primary traverser stalls early on a quiet or unusually structured app. This
//! module is the integration seam: a [`FallbackEngine`] the primary invokes when
//! it exhausts its frontier with little coverage.
//!
//! `DroidBot` is a host-side Python tool that drives the device over adb. Vendoring
//! its pinned Python runtime + deps (per the host-independence principle) and
//! wiring the live host-process invocation against the emulator serial is a
//! packaging step handled in the bundled-tools packaging phase, exactly like the
//! bundled JRE/apktool/jadx/ffuf tiers. Until that runtime is present,
//! [`DroidBotFallback::run`] resolves the bundled launcher by path and reports
//! honestly that it is not available, rather than pretending to have run.

use std::path::PathBuf;
use std::time::Duration;

use apiaxess_sandbox::SandboxControl;

/// A secondary crawler the primary engine can hand off to when it stalls.
pub trait FallbackEngine: Send {
    /// Drives the app with the secondary engine. Returns the number of extra
    /// interactions performed, or an explanatory message when it could not run
    /// (which the primary records as an honest note — never a silent no-op).
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the secondary engine is unavailable
    /// or could not complete; the primary surfaces it as a note.
    fn run(
        &mut self,
        control: &dyn SandboxControl,
        package: &str,
        budget: Duration,
    ) -> Result<usize, String>;

    /// Short name for telemetry/notes.
    fn name(&self) -> &'static str;
}

/// Bundled-`DroidBot` fallback. Resolves the vendored launcher relative to the
/// installed engine (mirroring the other bundled tools) or an explicit override.
pub struct DroidBotFallback {
    launcher_override: Option<PathBuf>,
}

impl Default for DroidBotFallback {
    fn default() -> Self {
        Self::new()
    }
}

impl DroidBotFallback {
    /// Creates a resolver that discovers the bundled `DroidBot` launcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            launcher_override: std::env::var_os("APIAXESS_DROIDBOT").map(PathBuf::from),
        }
    }

    /// Resolves the bundled `DroidBot` launcher path, if present in this build.
    #[must_use]
    pub fn resolve(&self) -> Option<PathBuf> {
        if let Some(explicit) = &self.launcher_override {
            return explicit.is_file().then(|| explicit.clone());
        }
        // Mirrors the resolver layout used by the other bundled analysis tools:
        // `runtime/droidbot/` in the MSI, `droidbot/` elsewhere.
        let base = apiaxess_install_layout::resource_base()?;
        let candidate = if cfg!(windows) {
            base.join("runtime").join("droidbot").join("droidbot.exe")
        } else {
            base.join("droidbot").join("droidbot")
        };
        candidate.is_file().then_some(candidate)
    }
}

impl FallbackEngine for DroidBotFallback {
    fn run(
        &mut self,
        _control: &dyn SandboxControl,
        _package: &str,
        _budget: Duration,
    ) -> Result<usize, String> {
        match self.resolve() {
            Some(path) => Err(format!(
                "bundled DroidBot found at {} but live host-process invocation is wired in the packaging phase; primary-engine coverage stands as reported",
                path.display()
            )),
            None => Err(
                "DroidBot fallback is not bundled in this build; primary-engine coverage stands as reported"
                    .to_owned(),
            ),
        }
    }

    fn name(&self) -> &'static str {
        "droidbot"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droidbot_reports_honestly_when_not_bundled() {
        // With no bundled launcher present, run() explains itself rather than
        // silently doing nothing. (The test environment sets no override and has
        // no vendored `DroidBot`, so resolve() returns None.)
        struct NoControl;
        impl SandboxControl for NoControl {
            fn command(
                &self,
                _a: &[String],
                _t: Duration,
            ) -> Result<apiaxess_sandbox::SandboxCommandOutput, apiaxess_diagnostics::Diagnostic>
            {
                unreachable!()
            }
            fn shell(
                &self,
                _a: &[String],
                _t: Duration,
            ) -> Result<apiaxess_sandbox::SandboxCommandOutput, apiaxess_diagnostics::Diagnostic>
            {
                unreachable!()
            }
            fn put(
                &self,
                _b: &[u8],
                _p: &str,
                _t: Duration,
            ) -> Result<apiaxess_sandbox::SandboxCommandOutput, apiaxess_diagnostics::Diagnostic>
            {
                unreachable!()
            }
            fn remove(
                &self,
                _p: &str,
                _t: Duration,
            ) -> Result<apiaxess_sandbox::SandboxCommandOutput, apiaxess_diagnostics::Diagnostic>
            {
                unreachable!()
            }
            fn install_apks(
                &self,
                _p: &[PathBuf],
                _t: Duration,
            ) -> Result<apiaxess_sandbox::SandboxCommandOutput, apiaxess_diagnostics::Diagnostic>
            {
                unreachable!()
            }
            fn transport_id(&self) -> &'static str {
                "none"
            }
        }
        let mut fallback = DroidBotFallback {
            launcher_override: None,
        };
        let result = fallback.run(&NoControl, "com.demo", Duration::from_secs(1));
        assert!(result.is_err());
        assert_eq!(fallback.name(), "droidbot");
    }
}
