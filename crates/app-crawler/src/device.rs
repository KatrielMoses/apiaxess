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
    let output = control.shell(&args(parts), timeout).map_err(|diagnostic| DeviceError {
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
    let xml = run(control, "read ui dump", &["cat", UI_DUMP_PATH], Duration::from_secs(10))?;
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
            "input", "swipe", &x.to_string(), &y.to_string(), &x.to_string(), &y.to_string(), "700",
        ],
        Duration::from_secs(10),
    )
}

/// Scrolls a container upward (toward more content) around a center point.
pub fn scroll_forward(control: &dyn SandboxControl, x: i32, y: i32, height: i32) -> DeviceResult<String> {
    let travel = (height / 3).clamp(200, 1200);
    let y1 = y + travel / 2;
    let y2 = y - travel / 2;
    run(
        control,
        "scroll",
        &[
            "input", "swipe", &x.to_string(), &y1.to_string(), &x.to_string(), &y2.to_string(), "300",
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
    let _ = run(control, "sel-end", &["input", "keyevent", "KEYCODE_MOVE_END"], Duration::from_secs(8));
    run(
        control,
        "clear",
        &["input", "keyevent", "--longpress", "KEYCODE_DEL", "KEYCODE_DEL", "KEYCODE_DEL"],
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
        if let Some(component) = listing
            .lines()
            .map(str::trim)
            .find(|line| {
                line.starts_with(&prefix) && !line.to_ascii_lowercase().contains("leakcanary")
            })
        {
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
        &["monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
        Duration::from_secs(30),
    )
}

/// Force-stops the package (used to reset to a known launch state).
pub fn force_stop(control: &dyn SandboxControl, package: &str) -> DeviceResult<String> {
    run(control, "force-stop", &["am", "force-stop", package], Duration::from_secs(15))
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
        if run(control, "pm grant", &["pm", "grant", package, &permission], Duration::from_secs(8)).is_ok() {
            granted.push(permission);
        }
    }
    granted
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
        '\\', '"', '\'', '$', '`', '!', '&', ';', '|', '<', '>', '(', ')', '{', '}', '[', ']',
        '*', '?', '~', '#', '=', '@', '^',
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

fn parse_requested_permissions(dump: &str) -> Vec<String> {
    let mut permissions = Vec::new();
    for line in dump.lines() {
        let line = line.trim();
        // `dumpsys package` lists requested perms as `android.permission.X: ...`
        // or under `requested permissions:` as bare names.
        if let Some(name) = line.strip_suffix(": granted=false").map(str::trim) {
            if name.starts_with("android.permission.") {
                permissions.push(name.to_owned());
            }
        } else if line.starts_with("android.permission.") && !line.contains(' ') {
            permissions.push(line.to_owned());
        }
    }
    permissions.sort();
    permissions.dedup();
    permissions
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
        assert_eq!(parse_resumed_activity(dump).as_deref(), Some("com.x.y/com.x.y.Home"));
        let focus = "  mCurrentFocus=Window{a b com.z/com.z.Act}";
        assert_eq!(parse_resumed_activity(focus).as_deref(), Some("com.z/com.z.Act"));
    }

    #[test]
    fn parses_requested_permissions() {
        let dump = "requested permissions:\n      android.permission.INTERNET\n      android.permission.CAMERA: granted=false\n      android.permission.ACCESS_FINE_LOCATION";
        let perms = parse_requested_permissions(dump);
        assert!(perms.contains(&"android.permission.CAMERA".to_owned()));
        assert!(perms.contains(&"android.permission.ACCESS_FINE_LOCATION".to_owned()));
    }
}
