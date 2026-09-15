//! Thin ADB-shell operations the crawler uses to drive the app.
//!
//! Every operation goes through [`SandboxControl`] so the whole crawl engine is
//! testable against a mock device with no emulator present.

use std::time::Duration;

use apiaxess_sandbox::SandboxControl;

/// A non-fatal device operation error, surfaced as a crawl note.
#[derive(Clone, Debug)]
pub struct DeviceError {
    /// The operation that failed.
    pub op: String,
    /// Detail (never contains a credential value — callers pass no secrets here).
    pub detail: String,
}

impl std::fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.op, self.detail)
    }
}

type DeviceResult<T> = Result<T, DeviceError>;

const UI_DUMP_PATH: &str = "/sdcard/apiaxess_uidump.xml";

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

fn run(
    control: &dyn SandboxControl,
    op: &str,
    parts: &[&str],
    timeout: Duration,
) -> DeviceResult<String> {
    let output = control
        .shell(&args(parts), timeout)
        .map_err(|diagnostic| DeviceError {
            op: op.to_owned(),
            detail: diagnostic.what.to_string(),
        })?;
    if output.exit_code.is_some_and(|code| code != 0) {
        return Err(DeviceError {
            op: op.to_owned(),
            detail: output.stderr.trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

/// Dumps the current view hierarchy XML.
///
/// `uiautomator dump` writes to a file; we then read it back. Both steps are
/// bounded and the file is overwritten each call.
pub fn dump_hierarchy(control: &dyn SandboxControl) -> DeviceResult<String> {
    let _ = run(
        control,
        "uiautomator dump",
        &["uiautomator", "dump", UI_DUMP_PATH],
        Duration::from_secs(20),
    )?;
    let xml = run(
        control,
        "read ui dump",
        &["cat", UI_DUMP_PATH],
        Duration::from_secs(10),
    )?;
    if xml.trim_start().starts_with('<') {
        Ok(xml)
    } else {
        Err(DeviceError {
            op: "read ui dump".to_owned(),
            detail: "dump did not produce XML".to_owned(),
        })
    }
}

/// Reads the foreground activity component (`pkg/activity`).
pub fn current_activity(control: &dyn SandboxControl) -> DeviceResult<String> {
    let output = run(
        control,
        "dumpsys activity",
        &["dumpsys", "activity", "activities"],
        Duration::from_secs(15),
    )?;
    parse_resumed_activity(&output).ok_or_else(|| DeviceError {
        op: "dumpsys activity".to_owned(),
        detail: "no resumed activity found".to_owned(),
    })
}

/// Taps at a point.
pub fn tap(control: &dyn SandboxControl, x: i32, y: i32) -> DeviceResult<String> {
    run(
        control,
        "tap",
        &["input", "tap", &x.to_string(), &y.to_string()],
        Duration::from_secs(10),
    )
}

/// Long-presses at a point via a zero-distance timed swipe.
pub fn long_press(control: &dyn SandboxControl, x: i32, y: i32) -> DeviceResult<String> {
    run(
        control,
        "long-press",
        &[
            "input",
            "swipe",
            &x.to_string(),
            &y.to_string(),
            &x.to_string(),
            &y.to_string(),
            "700",
        ],
        Duration::from_secs(10),
    )
}

/// Scrolls a container upward (toward more content) around a center point.
pub fn scroll_forward(
    control: &dyn SandboxControl,
    x: i32,
    y: i32,
    height: i32,
) -> DeviceResult<String> {
    let travel = (height / 3).clamp(200, 1200);
    let y1 = y + travel / 2;
    let y2 = y - travel / 2;
    run(
        control,
        "scroll",
        &[
            "input",
            "swipe",
            &x.to_string(),
            &y1.to_string(),
            &x.to_string(),
            &y2.to_string(),
            "300",
        ],
        Duration::from_secs(10),
    )
}

/// Presses the hardware BACK key.
pub fn press_back(control: &dyn SandboxControl) -> DeviceResult<String> {
    run(
        control,
        "back",
        &["input", "keyevent", "KEYCODE_BACK"],
        Duration::from_secs(10),
    )
}

/// Types text into the focused field. The value may be a credential — it is
/// escaped for the device shell but never logged by this function.
pub fn input_text(control: &dyn SandboxControl, text: &str) -> DeviceResult<String> {
    let escaped = escape_input_text(text);
    run(
        control,
        "input text",
        &["input", "text", &escaped],
        Duration::from_secs(15),
    )
}

/// Clears the focused text field (select-all then delete).
pub fn clear_focused(control: &dyn SandboxControl) -> DeviceResult<String> {
    // Move to end, select to start, delete. Best-effort.
    let _ = run(
        control,
        "sel-end",
        &["input", "keyevent", "KEYCODE_MOVE_END"],
        Duration::from_secs(8),
    );
    run(
        control,
        "clear",
        &[
            "input",
            "keyevent",
            "--longpress",
            "KEYCODE_DEL",
            "KEYCODE_DEL",
            "KEYCODE_DEL",
        ],
        Duration::from_secs(8),
    )
}

/// Launches the app's own main activity.
///
/// A debug build can register competing launcher entries (e.g. `LeakCanary`'s
/// `LeakLauncherActivity`), and `monkey -c LAUNCHER` may pick one of those
/// instead of the app — leaving the crawler exercising a debug tool while the
/// real UI never opens. So resolve the package's own MAIN/LAUNCHER activity and
/// start it explicitly, excluding known debug-tool activities; fall back to
/// `monkey` if the query is unavailable.
pub fn launch(control: &dyn SandboxControl, package: &str) -> DeviceResult<String> {
    let prefix = format!("{package}/");
    if let Ok(listing) = run(
        control,
        "query launcher activities",
        &[
            "cmd",
            "package",
            "query-activities",
            "--brief",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
        ],
        Duration::from_secs(15),
    ) {
        if let Some(component) = listing.lines().map(str::trim).find(|line| {
            line.starts_with(&prefix) && !line.to_ascii_lowercase().contains("leakcanary")
        }) {
            return run(
                control,
                "launch",
                &[
                    "am",
                    "start",
                    "-n",
                    component,
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.LAUNCHER",
                ],
                Duration::from_secs(30),
            );
        }
    }
    run(
        control,
        "launch",
        &[
            "monkey",
            "-p",
            package,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        Duration::from_secs(30),
    )
}

/// Force-stops the package (used to reset to a known launch state).
pub fn force_stop(control: &dyn SandboxControl, package: &str) -> DeviceResult<String> {
    run(
        control,
        "force-stop",
        &["am", "force-stop", package],
        Duration::from_secs(15),
    )
}

/// Best-effort pre-grant of the package's requested runtime permissions, so
/// permission dialogs don't block traffic. Failures are ignored (many
/// permissions aren't grantable, which is fine).
pub fn grant_runtime_permissions(control: &dyn SandboxControl, package: &str) -> Vec<String> {
    let mut granted = Vec::new();
    let Ok(output) = run(
        control,
        "dumpsys package",
        &["dumpsys", "package", package],
        Duration::from_secs(20),
    ) else {
        return granted;
    };
    for permission in parse_requested_permissions(&output) {
        if run(
            control,
            "pm grant",
            &["pm", "grant", package, &permission],
            Duration::from_secs(8),
        )
        .is_ok()
        {
            granted.push(permission);
        }
    }
    granted
}

/// Best-effort preparation of device *state* so state-gated screens make their
/// backend calls. Location is the common one: a weather/maps/discovery app calls
/// no API until it has a fix, so we enable the location providers and seed a
/// coordinate. Every step is best-effort — a step that is unavailable on the
/// runtime is skipped and noted, never fatal.
///
/// This is deliberately generic: it removes the *device-level* location gate
/// (services off, no fix). Deep, app-specific state — a chosen city typed into a
/// search box, a completed multi-step setup — is out of reach here and stays a
/// documented ceiling; the crawler's normal traversal is what exercises those.
pub fn prepare_location(control: &dyn SandboxControl) -> Vec<String> {
    let mut notes = Vec::new();
    // Turn location services on. `location_mode=3` (high accuracy) and the
    // provider list cover API 29; `cmd location set-location-enabled` is the
    // newer control. Any that the build rejects is simply skipped.
    let enabled = run(
        control,
        "enable location",
        &["cmd", "location", "set-location-enabled", "true"],
        Duration::from_secs(8),
    )
    .is_ok();
    let _ = run(
        control,
        "location mode",
        &["settings", "put", "secure", "location_mode", "3"],
        Duration::from_secs(8),
    );
    let providers = run(
        control,
        "location providers",
        &[
            "settings",
            "put",
            "secure",
            "location_providers_allowed",
            "+gps,network",
        ],
        Duration::from_secs(8),
    )
    .is_ok();
    // Seed a coordinate through the emulator console so an app reading GPS gets a
    // fix even without hardware. `adb emu geo fix` is a host-transport command
    // (not an Android shell command), so it goes through `command`, not `shell`.
    // The default is the emulator's own Mountain View locale — a real, land-based
    // coordinate any weather/location provider resolves.
    let seeded = control
        .command(
            &args(&["emu", "geo", "fix", "-122.084", "37.422"]),
            Duration::from_secs(8),
        )
        .is_ok_and(|output| output.exit_code.is_none_or(|code| code == 0));
    if enabled || providers {
        notes.push("Enabled device location services.".to_owned());
    }
    if seeded {
        notes.push("Seeded a GPS fix for location-gated screens.".to_owned());
    }
    if notes.is_empty() {
        notes.push(
            "Could not prepare device location (runtime did not accept the controls); location-gated screens may not call out.".to_owned(),
        );
    }
    notes
}

/// Escapes text for `adb shell input text`.
///
/// `input text` uses `%s` for spaces; every character special to the device
/// shell is backslash-escaped so the intended value reaches `input` verbatim.
/// Known limitation: a literal `%s` inside a value is converted to a space by
/// `input` (exotic; the documented extension point is a clipboard/IME injector).
#[must_use]
pub fn escape_input_text(text: &str) -> String {
    const SPECIAL: &[char] = &[
        '\\', '"', '\'', '$', '`', '!', '&', ';', '|', '<', '>', '(', ')', '{', '}', '[', ']', '*',
        '?', '~', '#', '=', '@', '^',
    ];
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        if ch == ' ' {
            out.push_str("%s");
        } else if SPECIAL.contains(&ch) {
            out.push('\\');
            out.push(ch);
        } else {
            out.push(ch);
        }
    }
    out
}

fn parse_resumed_activity(dump: &str) -> Option<String> {
    for line in dump.lines() {
        if line.contains("Resumed") {
            if let Some(component) = extract_component(line) {
                return Some(component);
            }
        }
    }
    // Fallback: any focused component line.
    for line in dump.lines() {
        if line.contains("mFocusedApp") || line.contains("mCurrentFocus") {
            if let Some(component) = extract_component(line) {
                return Some(component);
            }
        }
    }
    None
}

fn extract_component(line: &str) -> Option<String> {
    line.split(|c: char| c.is_whitespace() || c == '{' || c == '}')
        .find_map(|token| {
            let token = token.trim_matches(|c| c == ',' || c == ';');
            let (package, activity) = token.split_once('/')?;
            if package.contains('.') && !package.is_empty() && !activity.is_empty() {
                Some(token.to_owned())
            } else {
                None
            }
        })
}

/// Extracts grantable permission names from `dumpsys package <pkg>` output.
///
/// The real dump lists permissions several ways across its `requested`,
/// `install`, and `runtime permissions:` sections — bare names, and
/// `name: granted=false, flags=[ ... ]` lines with a trailing flags list. The
/// earlier parser only matched a bare `: granted=false` suffix and the
/// `android.permission.` prefix, so it missed the common `granted=false, flags=`
/// form and every vendor/GMS permission — leaving the dangerous runtime
/// permissions (location, storage, …) ungranted and their dialogs still blocking
/// the crawl. This takes the leading token of each line, accepts any
/// `*.permission.*` name, and skips ones already `granted=true`.
fn parse_requested_permissions(dump: &str) -> Vec<String> {
    let mut permissions = Vec::new();
    for line in dump.lines() {
        let line = line.trim();
        // Already-granted perms need no action; flags-continuation lines and
        // section headers are not permission names and fall out here.
        if line.contains("granted=true") {
            continue;
        }
        let token = line.split([':', ' ', '\t']).next().unwrap_or("").trim();
        if is_permission_name(token) {
            permissions.push(token.to_owned());
        }
    }
    permissions.sort();
    permissions.dedup();
    permissions
}

/// A dotted Android permission name (`android.permission.X`,
/// `com.google.android.gms.permission.X`, or a vendor namespace).
fn is_permission_name(token: &str) -> bool {
    token.contains(".permission.")
        && token.len() > ".permission.".len()
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_spaces_and_shell_specials() {
        assert_eq!(escape_input_text("p@ss w0rd!"), "p\\@ss%sw0rd\\!");
        assert_eq!(escape_input_text("plain"), "plain");
        assert_eq!(escape_input_text("a&b|c;d"), "a\\&b\\|c\\;d");
    }

    #[test]
    fn parses_resumed_activity_component() {
        let dump = "  mResumedActivity: ActivityRecord{9f2 u0 com.example.app/.MainActivity t42}";
        assert_eq!(
            parse_resumed_activity(dump).as_deref(),
            Some("com.example.app/.MainActivity")
        );
    }

    #[test]
    fn parses_topresumed_and_focus_fallback() {
        let dump = "topResumedActivity=ActivityRecord{a com.x.y/com.x.y.Home}";
        assert_eq!(
            parse_resumed_activity(dump).as_deref(),
            Some("com.x.y/com.x.y.Home")
        );
        let focus = "  mCurrentFocus=Window{a b com.z/com.z.Act}";
        assert_eq!(
            parse_resumed_activity(focus).as_deref(),
            Some("com.z/com.z.Act")
        );
    }

    #[test]
    fn parses_requested_permissions() {
        let dump = "requested permissions:\n      android.permission.INTERNET\n      android.permission.CAMERA: granted=false\n      android.permission.ACCESS_FINE_LOCATION";
        let perms = parse_requested_permissions(dump);
        assert!(perms.contains(&"android.permission.CAMERA".to_owned()));
        assert!(perms.contains(&"android.permission.ACCESS_FINE_LOCATION".to_owned()));
    }

    #[test]
    fn parses_real_runtime_permission_block_with_flags() {
        // The real `dumpsys package` runtime section: `granted=false, flags=[...]`
        // lines (the earlier parser missed these), GMS/vendor namespaces, and a
        // granted=true line that must be skipped.
        let dump = "runtime permissions:\n      android.permission.ACCESS_FINE_LOCATION: granted=false, flags=[ USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED ]\n      android.permission.WRITE_EXTERNAL_STORAGE: granted=false, flags=[ USER_SET ]\n      com.google.android.gms.permission.AD_ID: granted=false, flags=[ ]\n      android.permission.INTERNET: granted=true, flags=[ ]\n         USER_SENSITIVE_WHEN_GRANTED|USER_SENSITIVE_WHEN_DENIED";
        let perms = parse_requested_permissions(dump);
        assert!(perms.contains(&"android.permission.ACCESS_FINE_LOCATION".to_owned()));
        assert!(perms.contains(&"android.permission.WRITE_EXTERNAL_STORAGE".to_owned()));
        assert!(perms.contains(&"com.google.android.gms.permission.AD_ID".to_owned()));
        assert!(
            !perms.contains(&"android.permission.INTERNET".to_owned()),
            "already-granted permissions are skipped"
        );
        // The flags-continuation line is not a permission name.
        assert!(!perms.iter().any(|p| p.contains("USER_SENSITIVE")));
    }
}
