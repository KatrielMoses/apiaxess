//! Operator settings: the environment knobs the hardening pass flagged, made
//! viewable and settable from the GUI.
//!
//! Settings persist to `<data-root>/apiaxess/settings.json`. The engine applies
//! them to its environment once at startup (see the composition root), so the
//! existing `APIAXESS_*` consumers honor them with no change — which is why every
//! settable knob is "restart to take effect". An environment variable set outside
//! the app still wins (the startup apply never overwrites an existing variable),
//! and the screen shows that precedence honestly.
//!
//! The launch-mode knob is special: it is read by the native shell before the
//! engine exists, so it is persisted to the shell's own `launch-mode.json`
//! (Phase 12.4), not the settings file.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use serde::{Deserialize, Serialize};

/// A single operator-configurable environment knob.
struct Knob {
    /// The `APIAXESS_*` environment variable it maps to.
    key: &'static str,
    /// Human label.
    label: &'static str,
    /// Grouping for the settings screen.
    group: &'static str,
    /// What the value is when neither an env override nor a saved value is set.
    default_display: &'static str,
    /// Advanced/dangerous (tool-path overrides that can break bundled resolution).
    advanced: bool,
    /// Whether a change needs an engine restart to take effect (all env knobs do).
    restart_required: bool,
    /// One-line description shown under the field.
    description: &'static str,
    /// Fixed choices, when the knob is an enumeration (empty = free text).
    choices: &'static [&'static str],
}

/// The operator-relevant knobs. Test/instrumentation/build variables
/// (`APIAXESS_CAPSTONE_*`, `APIAXESS_PROFILE_*`, Frida script signals, the
/// build-only `APIAXESS_FRIDA_DEVKIT`, etc.) are deliberately excluded.
const KNOBS: &[Knob] = &[
    Knob {
        key: "APIAXESS_LAUNCH_MODE",
        label: "Launch mode",
        group: "General",
        default_display: "prompt on first launch",
        advanced: false,
        restart_required: true,
        description: "How the desktop app opens: its own window (desktop) or your browser. Applied on the next launch.",
        choices: &["desktop", "browser"],
    },
    Knob {
        key: "APIAXESS_WORKBENCH_STORE_DIR",
        label: "Session store directory",
        group: "Storage",
        default_display: "platform data directory",
        advanced: false,
        restart_required: true,
        description: "Where durable session SQLite stores and artifacts are kept. Blank uses the per-user data directory.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_ALLOWED_TARGETS",
        label: "Allowed target hosts",
        group: "Scope",
        default_display: "none",
        advanced: false,
        restart_required: true,
        description: "Comma-separated advisory in-scope hosts (exact or *.domain). Advisory only — out-of-scope traffic is warned, never blocked.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_DISCOVERY_RATE",
        label: "Discovery rate (requests/second)",
        group: "Discovery",
        default_display: "20",
        advanced: false,
        restart_required: true,
        description: "Request rate for ffuf discovery sweeps.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_GUI_ADDRESS",
        label: "Workbench UI listener",
        group: "Network",
        default_display: "127.0.0.1:7777",
        advanced: false,
        restart_required: true,
        description: "Loopback address the UI/API binds for headless serve. The desktop app assigns a dynamic port and overrides this.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_PROXY_ADDRESS",
        label: "Intercepting proxy listener",
        group: "Network",
        default_display: "127.0.0.1:8080",
        advanced: false,
        restart_required: true,
        description: "Loopback address the intercepting proxy binds for headless serve. The desktop app assigns a dynamic port and overrides this.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_ANALYSIS_RUNTIME",
        label: "Analysis-runtime location",
        group: "Dynamic analysis",
        default_display: "beside the install",
        advanced: false,
        restart_required: true,
        description: "Path to the optional ~2 GB emulator runtime payload. Blank resolves it beside the install.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_JAVA",
        label: "Java runtime override",
        group: "Tool paths (advanced)",
        default_display: "bundled OpenJDK",
        advanced: true,
        restart_required: true,
        description: "Overrides the bundled Java runtime used by apktool/jadx. Blank uses the bundled runtime (recommended).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_APKTOOL",
        label: "apktool override",
        group: "Tool paths (advanced)",
        default_display: "bundled apktool.jar",
        advanced: true,
        restart_required: true,
        description: "Overrides the bundled apktool. A .jar runs through the resolved Java runtime. Blank uses the bundled tool (recommended).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_JADX",
        label: "jadx override",
        group: "Tool paths (advanced)",
        default_display: "bundled jadx",
        advanced: true,
        restart_required: true,
        description: "Overrides the bundled jadx. Blank uses the bundled tool (recommended).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_BUNDLETOOL",
        label: "bundletool override",
        group: "Tool paths (advanced)",
        default_display: "PATH bundletool",
        advanced: true,
        restart_required: true,
        description: "bundletool for the AAB path (not bundled). Blank uses a bundletool found on PATH.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_FFUF",
        label: "ffuf override",
        group: "Tool paths (advanced)",
        default_display: "bundled ffuf",
        advanced: true,
        restart_required: true,
        description: "Overrides the bundled ffuf discovery binary. Blank uses the bundled tool (recommended).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_CHROMIUM",
        label: "Chromium override",
        group: "Tool paths (advanced)",
        default_display: "bundled Chromium",
        advanced: true,
        restart_required: true,
        description: "Overrides the Chromium used for the manual capture browser. Blank uses the bundled snapshot (recommended).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_FIREFOX",
        label: "Firefox path",
        group: "Tool paths (advanced)",
        default_display: "firefox on PATH",
        advanced: true,
        restart_required: true,
        description: "Firefox executable for the optional Firefox capture browser.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_NSS_CERTUTIL",
        label: "NSS certutil path",
        group: "Tool paths (advanced)",
        default_display: "certutil on PATH",
        advanced: true,
        restart_required: true,
        description: "Mozilla NSS certutil for Firefox trust provisioning (not Windows' built-in certutil).",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_GUI_DIR",
        label: "GUI assets directory override",
        group: "Tool paths (advanced)",
        default_display: "installed GUI",
        advanced: true,
        restart_required: true,
        description: "Overrides where the engine serves the GUI from. For development only.",
        choices: &[],
    },
    Knob {
        key: "APIAXESS_CA_STATE_LOG",
        label: "CA state log path",
        group: "Tool paths (advanced)",
        default_display: "temp directory",
        advanced: true,
        restart_required: true,
        description: "Where the session-CA state log is written (used by --purge-cas).",
        choices: &[],
    },
];

const LAUNCH_MODE_KEY: &str = "APIAXESS_LAUNCH_MODE";

/// Where a setting's effective value comes from.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    /// Neither an override nor a saved value; the bundled/default behavior.
    Default,
    /// A value saved through this screen.
    Config,
    /// An environment variable set outside the app, which takes precedence.
    Environment,
}

/// One knob's current state for the settings screen.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingEntry {
    key: &'static str,
    label: &'static str,
    group: &'static str,
    value: String,
    default_display: &'static str,
    source: Source,
    advanced: bool,
    restart_required: bool,
    description: &'static str,
    choices: &'static [&'static str],
}

/// The full settings payload: knobs plus bundled-tool availability.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    settings: Vec<SettingEntry>,
    tools: Vec<apiaxess_engine_shell::BundledToolStatus>,
    config_path: String,
}

/// A settings update request from the GUI: key → value (empty string clears it).
#[derive(Deserialize)]
pub struct SettingsUpdate {
    values: BTreeMap<String, String>,
}

/// The per-user durable data root (mirrors the engine + shell logic).
fn data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env::var_os("LOCALAPPDATA")
            .or_else(|| env::var_os("APPDATA"))
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| {
            env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
        })
    }
}

fn settings_path() -> Option<PathBuf> {
    Some(data_root()?.join("apiaxess").join("settings.json"))
}

fn launch_mode_path() -> Option<PathBuf> {
    Some(data_root()?.join("apiaxess").join("launch-mode.json"))
}

/// Loads the saved settings map (`{}` when absent or unreadable).
fn load_settings() -> BTreeMap<String, String> {
    settings_path()
        .and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<BTreeMap<String, String>>(&bytes).ok())
        .unwrap_or_default()
}

/// The saved launch mode from the shell's config, if any.
fn load_launch_mode() -> Option<String> {
    #[derive(Deserialize)]
    struct LaunchConfig {
        mode: String,
    }
    let bytes = fs::read(launch_mode_path()?).ok()?;
    serde_json::from_slice::<LaunchConfig>(&bytes)
        .ok()
        .map(|config| config.mode)
}

/// The saved settings to apply to the process environment at startup, skipping
/// keys already set (an external environment override wins) and the launch-mode
/// knob (consumed by the shell, not the engine). Empty values are treated as
/// unset.
#[must_use]
pub fn persisted_env_overrides() -> Vec<(String, String)> {
    load_settings()
        .into_iter()
        .filter(|(key, value)| {
            key != LAUNCH_MODE_KEY && !value.trim().is_empty() && env::var_os(key).is_none()
        })
        .collect()
}

/// Builds the settings view: each knob's effective value + source, plus the
/// bundled-tool availability panel.
#[must_use]
pub fn settings_view() -> SettingsView {
    let saved = load_settings();
    let launch_mode = load_launch_mode();
    let settings = KNOBS
        .iter()
        .map(|knob| {
            let env_value = env::var(knob.key).ok();
            let config_value = if knob.key == LAUNCH_MODE_KEY {
                launch_mode.clone()
            } else {
                saved
                    .get(knob.key)
                    .cloned()
                    .filter(|v| !v.trim().is_empty())
            };
            let (value, source) = match (&env_value, &config_value) {
                // An env var equal to the saved value is our own startup apply.
                (Some(env), Some(config)) if env == config => (env.clone(), Source::Config),
                (Some(env), _) => (env.clone(), Source::Environment),
                (None, Some(config)) => (config.clone(), Source::Config),
                (None, None) => (String::new(), Source::Default),
            };
            SettingEntry {
                key: knob.key,
                label: knob.label,
                group: knob.group,
                value,
                default_display: knob.default_display,
                source,
                advanced: knob.advanced,
                restart_required: knob.restart_required,
                description: knob.description,
                choices: knob.choices,
            }
        })
        .collect();

    let config_path = settings_path()
        .map(|path| path.display().to_string())
        .unwrap_or_default();

    SettingsView {
        settings,
        tools: apiaxess_engine_shell::bundled_tool_status(),
        config_path,
    }
}

/// Validates and persists a settings update. Recognized knobs only; the
/// launch-mode knob is written to the shell's config, everything else to the
/// settings file. Returns a human-readable error on invalid input.
///
/// # Errors
///
/// Returns an error string when a value fails validation or the config cannot be
/// written.
pub fn update_settings(update: SettingsUpdate) -> Result<(), String> {
    let mut saved = load_settings();
    let mut launch_mode_change: Option<String> = None;

    for (key, raw) in update.values {
        let Some(knob) = KNOBS.iter().find(|knob| knob.key == key) else {
            return Err(format!("unknown setting: {key}"));
        };
        let value = raw.trim().to_owned();
        if !value.is_empty() {
            validate(knob, &value)?;
        }
        if key == LAUNCH_MODE_KEY {
            launch_mode_change = Some(value);
        } else if value.is_empty() {
            saved.remove(&key);
        } else {
            saved.insert(key, value);
        }
    }

    write_settings(&saved)?;
    if let Some(mode) = launch_mode_change {
        write_launch_mode(&mode)?;
    }
    Ok(())
}

/// Validates one knob's non-empty value.
fn validate(knob: &Knob, value: &str) -> Result<(), String> {
    if !knob.choices.is_empty() && !knob.choices.contains(&value) {
        return Err(format!(
            "{} must be one of: {}",
            knob.label,
            knob.choices.join(", ")
        ));
    }
    match knob.key {
        "APIAXESS_GUI_ADDRESS" | "APIAXESS_PROXY_ADDRESS" => {
            if value.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!("{} must be a host:port address", knob.label));
            }
        }
        "APIAXESS_DISCOVERY_RATE" => {
            if value.parse::<u32>().ok().filter(|rate| *rate > 0).is_none() {
                return Err(format!("{} must be a positive integer", knob.label));
            }
        }
        _ => {}
    }
    Ok(())
}

fn write_settings(saved: &BTreeMap<String, String>) -> Result<(), String> {
    let path = settings_path().ok_or("cannot resolve the settings directory")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(saved).map_err(|error| error.to_string())?;
    fs::write(&path, bytes).map_err(|error| error.to_string())
}

fn write_launch_mode(mode: &str) -> Result<(), String> {
    let path = launch_mode_path().ok_or("cannot resolve the launch-mode config directory")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    if mode.is_empty() {
        // Clearing the launch mode restores the first-run prompt.
        let _ = fs::remove_file(&path);
        return Ok(());
    }
    let body = serde_json::json!({ "mode": mode });
    let bytes = serde_json::to_vec_pretty(&body).map_err(|error| error.to_string())?;
    fs::write(&path, bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_and_rate_validation_rejects_bad_values() {
        let addr = KNOBS
            .iter()
            .find(|knob| knob.key == "APIAXESS_PROXY_ADDRESS")
            .unwrap();
        assert!(validate(addr, "127.0.0.1:8080").is_ok());
        assert!(validate(addr, "not-an-address").is_err());
        let rate = KNOBS
            .iter()
            .find(|knob| knob.key == "APIAXESS_DISCOVERY_RATE")
            .unwrap();
        assert!(validate(rate, "20").is_ok());
        assert!(validate(rate, "0").is_err());
        assert!(validate(rate, "fast").is_err());
    }

    #[test]
    fn launch_mode_is_an_enumeration() {
        let mode = KNOBS
            .iter()
            .find(|knob| knob.key == LAUNCH_MODE_KEY)
            .unwrap();
        assert!(validate(mode, "desktop").is_ok());
        assert!(validate(mode, "browser").is_ok());
        assert!(validate(mode, "carrier-pigeon").is_err());
    }

    #[test]
    fn every_knob_maps_to_an_apiaxess_variable() {
        for knob in KNOBS {
            assert!(knob.key.starts_with("APIAXESS_"), "{}", knob.key);
        }
    }
}
