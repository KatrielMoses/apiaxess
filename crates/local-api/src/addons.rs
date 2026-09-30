//! The Add-ons panel: the optional analysis runtime and Android target, which
//! the operator downloads on demand from apiaxess.dev.
//!
//! This module only tells the shared add-on service ([`AssetService`]) what
//! each add-on is to this engine: where it resolves, what makes it usable, and
//! how much room its emulator needs. Downloading, verifying and installing are
//! the service's.

use std::path::Path;

use apiaxess_updater::assets::{AddonSlot, AssetConfig, AssetService};

/// The engine's add-on service. Nothing is fetched until the operator asks.
pub(crate) fn addon_service() -> AssetService {
    // A malformed test override falls back to apiaxess.dev itself.
    let catalog_url = AssetConfig::catalog_url_from_env().unwrap_or_else(|_| default_catalog_url());
    let version = semver_or_zero(env!("CARGO_PKG_VERSION"));
    AssetService::new(AssetConfig {
        catalog_url,
        user_agent: apiaxess_updater::service::user_agent(&version),
        // The updater's key: an unusable one refuses every catalog.
        public_key: apiaxess_updater::verify::manifest_public_key(),
        platform: apiaxess_updater::assets::platform_key(),
        download_dir: apiaxess_install_layout::data_dir_or_temp().join("downloads"),
        free_space: apiaxess_sandbox::available_space,
        slots: vec![analysis_runtime_slot(), android_target_slot()],
    })
}

fn default_catalog_url() -> url::Url {
    url::Url::parse(apiaxess_updater::assets::DEFAULT_CATALOG_URL)
        .expect("the default catalog URL parses")
}

fn semver_or_zero(value: &str) -> semver::Version {
    semver::Version::parse(value).unwrap_or_else(|_| semver::Version::new(0, 0, 0))
}

fn analysis_runtime_slot() -> AddonSlot {
    AddonSlot {
        slug: "analysis-runtime",
        name: "Android analysis runtime",
        purpose: "Dynamic APK analysis: the emulator, an Android 10 image, and frida-server.",
        env_key: "APIAXESS_ANALYSIS_RUNTIME",
        install_dir: apiaxess_install_layout::addon_user_dir("analysis-runtime"),
        resolved: Box::new(apiaxess_sandbox::analysis_runtime_root),
        present: Box::new(analysis_runtime_present),
        outdated: Box::new(|_| None),
        runtime_free_bytes: Box::new(apiaxess_sandbox::emulator_min_free_bytes),
    }
}

/// Usable when its emulator and owned AVD are there (what the dynamic
/// backend's preflight checks).
fn analysis_runtime_present(root: &Path) -> bool {
    let config = apiaxess_sandbox::BundledEmulatorConfig::for_root(
        root,
        apiaxess_sandbox::AccelerationMode::Software,
    );
    config.emulator_executable.is_file()
        && config
            .avd_home
            .join(format!("{}.ini", config.avd_name))
            .is_file()
}

fn android_target_slot() -> AddonSlot {
    use apiaxess_sandbox::android_target::{
        AndroidTargetAddon, MANIFEST_FILE, android_target_root,
    };
    AddonSlot {
        slug: "android-target",
        name: "Android target (drivable device)",
        purpose: "An Android 13 device you drive in the app: install your APK, log in, and capture its traffic.",
        env_key: "APIAXESS_ANDROID_TARGET",
        install_dir: apiaxess_install_layout::addon_user_dir("android-target"),
        resolved: Box::new(android_target_root),
        present: Box::new(|root| root.join(MANIFEST_FILE).is_file()),
        outdated: Box::new(|root| {
            AndroidTargetAddon::resolve_at(root)
                .ok()
                .and_then(|addon| addon.outdated_version().map(str::to_owned))
        }),
        runtime_free_bytes: Box::new(apiaxess_sandbox::emulator_min_free_bytes),
    }
}
