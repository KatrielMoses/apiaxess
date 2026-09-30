//! The in-app updater: one small module for "fetch the release manifest,
//! verify it (signature once a key is embedded, SHA-256 always), download
//! with progress, and hand a verified installer to whatever installs it".
//!
//! The engine runs the [`service`] (one code path for the desktop app and
//! `serve`); the desktop shell only uses [`handoff`] to start the installer
//! helper after the engine exits. [`channel`] says which of those applies to
//! this install. The asset-delivery work reuses the same pieces.

#[cfg(feature = "client")]
pub mod assets;
pub mod channel;
#[cfg(feature = "client")]
pub mod fetch;
pub mod handoff;
pub mod manifest;
#[cfg(feature = "client")]
pub mod service;
pub mod verify;

pub use channel::InstallChannel;
pub use handoff::{InstallHandoff, InstallWhen};

/// The exit code the engine uses to tell the desktop shell "install the
/// staged update now": the shell then starts the installer helper and exits
/// instead of restarting the engine.
pub const INSTALL_EXIT_CODE: i32 = 75;
