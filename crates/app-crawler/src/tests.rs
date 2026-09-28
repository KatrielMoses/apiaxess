//! End-to-end crawl tests against a mock device simulating a login-gated app.
//!
//! No emulator is required: [`MockDevice`] answers `uiautomator dump`, `dumpsys`,
//! and `input` shell calls to emulate a small four-screen app whose profile
//! screen sits behind a sign-in gate. This exercises the full engine — state
//! graph, BFS/backtracking, dialog/login detection, credential injection, and
//! split-coverage telemetry — deterministically.

use std::sync::Mutex;
use std::time::Duration;

use apiaxess_diagnostics::Diagnostic;
use apiaxess_sandbox::{SandboxCommandOutput, SandboxControl};
use apiaxess_session::ScopeDisposition;
use apiaxess_workbench_store::{FlowCapture, FlowOrigin, FlowRedactor, TrafficStore};
use chrono::Utc;

use super::*;

const HOME: &str = r#"<hierarchy><node package="com.demo" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.demo:id/refresh" class="android.widget.Button" text="Refresh feed" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
<node resource-id="com.demo:id/details" class="android.widget.Button" text="Open details" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
<node resource-id="com.demo:id/login" class="android.widget.Button" text="Account" clickable="true" enabled="true" bounds="[0,120][100,170]"/>
</node></hierarchy>"#;

const DETAILS: &str = r#"<hierarchy><node package="com.demo" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.demo:id/info" class="android.widget.Button" text="Info" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
</node></hierarchy>"#;

const LOGIN: &str = r#"<hierarchy><node package="com.demo" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.demo:id/username" class="android.widget.EditText" content-desc="Username" clickable="true" enabled="true" bounds="[0,280][100,330]"/>
<node resource-id="com.demo:id/password" class="android.widget.EditText" password="true" clickable="true" enabled="true" bounds="[0,340][100,390]"/>
<node resource-id="com.demo:id/signin" class="android.widget.Button" text="Sign in" clickable="true" enabled="true" bounds="[0,400][100,450]"/>
</node></hierarchy>"#;

const PROFILE: &str = r#"<hierarchy><node package="com.demo" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.demo:id/feed" class="android.widget.Button" text="Load feed" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
<node resource-id="com.demo:id/logout" class="android.widget.Button" text="Log out" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
</node></hierarchy>"#;

#[derive(Default)]
struct MockState {
    screen: Screen,
    focused: Option<Field>,
    typed_username: String,
    typed_password: String,
    typed_calls: Vec<String>,
    /// When set, the login form never advances even with valid input, modelling a
    /// stalled sign-in the crawler will revisit (used to prove no re-injection).
    sticky_login: bool,
}

#[derive(Clone, Copy, Default, PartialEq)]
enum Screen {
    #[default]
    Home,
    Details,
    Login,
    Profile,
}

#[derive(Clone, Copy, PartialEq)]
enum Field {
    Username,
    Password,
}

struct MockDevice {
    state: Mutex<MockState>,
}

impl MockDevice {
    fn new() -> Self {
        Self {
            state: Mutex::new(MockState::default()),
        }
    }

    fn sticky_login() -> Self {
        Self {
            state: Mutex::new(MockState {
                sticky_login: true,
                ..MockState::default()
            }),
        }
    }

    // Always succeeds, but returns `Result` to match the `SandboxControl` arm
    // shape its callers dispatch through.
    #[allow(clippy::unnecessary_wraps)]
    fn ok(stdout: &str) -> Result<SandboxCommandOutput, Diagnostic> {
        Ok(SandboxCommandOutput {
            stdout: stdout.to_owned(),
            stderr: String::new(),
            exit_code: Some(0),
        })
    }

    fn screen_xml(screen: Screen) -> &'static str {
        match screen {
            Screen::Home => HOME,
            Screen::Details => DETAILS,
            Screen::Login => LOGIN,
            Screen::Profile => PROFILE,
        }
    }

    fn activity(screen: Screen) -> &'static str {
        match screen {
            Screen::Home => "com.demo/.HomeActivity",
            Screen::Details => "com.demo/.DetailsActivity",
            Screen::Login => "com.demo/.LoginActivity",
            Screen::Profile => "com.demo/.ProfileActivity",
        }
    }
}

impl SandboxControl for MockDevice {
    fn command(
        &self,
        arguments: &[String],
        timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        self.shell(arguments, timeout)
    }

    fn shell(
        &self,
        arguments: &[String],
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let mut state = self.state.lock().unwrap();
        // Several arms intentionally return the same empty output as the wildcard;
        // they are kept explicit to document which adb commands the mock models.
        #[allow(clippy::match_same_arms)]
        match args.as_slice() {
            ["uiautomator", "dump", _] => Self::ok("dumped"),
            ["cat", _] => Self::ok(Self::screen_xml(state.screen)),
            ["dumpsys", "activity", "activities"] => Self::ok(&format!(
                "  mResumedActivity: ActivityRecord{{a u0 {} t1}}",
                Self::activity(state.screen)
            )),
            ["dumpsys", "package", _] => Self::ok(
                "requested permissions:\n  android.permission.INTERNET\n  android.permission.CAMERA: granted=false",
            ),
            ["pm", "grant", ..] => Self::ok(""),
            ["monkey", ..] => {
                state.screen = Screen::Home;
                Self::ok("")
            }
            ["am", "force-stop", _] => {
                state.screen = Screen::Home;
                Self::ok("")
            }
            ["input", "tap", x, y] => {
                let _ = x.parse::<i32>();
                let y: i32 = y.parse().unwrap_or(0);
                Self::ok(&handle_tap(&mut state, y))
            }
            ["input", "text", value] => {
                state.typed_calls.push((*value).to_owned());
                match state.focused {
                    Some(Field::Username) => state.typed_username = (*value).to_owned(),
                    Some(Field::Password) => state.typed_password = (*value).to_owned(),
                    None => {}
                }
                Self::ok("")
            }
            ["input", "swipe", ..] => Self::ok(""),
            ["input", "keyevent", ..] => {
                // BACK returns to home in this single-level app; clears clear a field.
                if args.contains(&"KEYCODE_BACK") {
                    state.screen = Screen::Home;
                }
                Self::ok("")
            }
            _ => Self::ok(""),
        }
    }

    fn put(
        &self,
        _bytes: &[u8],
        _remote_path: &str,
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        Self::ok("")
    }

    fn remove(
        &self,
        _remote_path: &str,
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        Self::ok("")
    }

    fn install_apks(
        &self,
        _apk_paths: &[std::path::PathBuf],
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        Self::ok("Success")
    }

    fn transport_id(&self) -> &'static str {
        "mock"
    }
}

fn handle_tap(state: &mut MockState, y: i32) -> String {
    match state.screen {
        Screen::Home => {
            if (0..50).contains(&y) {
                // Refresh: a network call, no UI change.
            } else if (60..110).contains(&y) {
                state.screen = Screen::Details;
            } else if (120..170).contains(&y) {
                state.screen = Screen::Login;
            }
        }
        Screen::Details => {
            // Info: no navigation (self-loop, gets exhausted).
        }
        Screen::Login => {
            if (280..330).contains(&y) {
                state.focused = Some(Field::Username);
            } else if (340..390).contains(&y) {
                state.focused = Some(Field::Password);
            } else if (400..450).contains(&y) {
                // Sign in only advances when both fields have values, and never
                // when the login is modelled as stalled.
                if !state.sticky_login
                    && !state.typed_username.is_empty()
                    && !state.typed_password.is_empty()
                {
                    state.screen = Screen::Profile;
                }
            }
        }
        Screen::Profile => {
            if (0..50).contains(&y) {
                // Load feed: network call, no UI change.
            } else if (60..110).contains(&y) {
                state.screen = Screen::Home;
            }
        }
    }
    String::new()
}

struct CannedProvider {
    pre_run: PreRunMode,
    login: LoginMode,
    username: &'static str,
    password: &'static str,
}

#[derive(Clone, Copy)]
enum PreRunMode {
    TryAnyway,
    Skip,
}

#[derive(Clone, Copy)]
enum LoginMode {
    Provide,
    Continue,
}

impl CredentialProvider for CannedProvider {
    fn pre_run(&mut self, _package: &str) -> PreRunDecision {
        match self.pre_run {
            PreRunMode::TryAnyway => PreRunDecision::TryAnyway,
            PreRunMode::Skip => PreRunDecision::Skip,
        }
    }

    fn on_login_gate(&mut self, request: &CredentialRequest) -> CredentialDecision {
        match self.login {
            LoginMode::Continue => CredentialDecision::Continue,
            LoginMode::Provide => {
                let values = request
                    .fields
                    .iter()
                    .map(|field| {
                        let value = match field.kind {
                            CredentialKind::Password => self.password,
                            _ => self.username,
                        };
                        (field.name.clone(), Secret::from_text(value))
                    })
                    .collect();
                CredentialDecision::Provide(CredentialAnswer { values })
            }
        }
    }

    fn on_otp(&mut self, _request: &CredentialRequest) -> Option<Secret> {
        None
    }
}

fn fast_config() -> CrawlConfig {
    let mut config = CrawlConfig::new("com.demo");
    config.settle_delay = Duration::ZERO;
    config.time_budget = Duration::from_secs(30);
    config
}

#[test]
fn crawls_pre_auth_then_credential_assisted_post_auth() {
    let device = MockDevice::new();
    let redactor = Arc::new(CredentialRedactor::new());
    let provider = Box::new(CannedProvider {
        pre_run: PreRunMode::TryAnyway,
        login: LoginMode::Provide,
        username: "alice",
        password: "s3cr3t!pw",
    });
    let mut crawler = AppCrawler::new(&device, fast_config(), provider, Arc::clone(&redactor));
    let report = crawler.run();

    // Real coverage of the app graph, not random tapping.
    assert!(
        report.actions_fired >= 5,
        "should fire real actions: {}",
        report.summary_line()
    );
    assert!(
        report.states_visited >= 3,
        "home, details, profile: {}",
        report.summary_line()
    );

    // Credential-assisted crossing of the auth wall.
    assert_eq!(report.credentials.login_gates_encountered, 1);
    assert!(
        report.credentials.post_auth_reached,
        "post-auth surface reached"
    );
    assert!(
        report.post_auth.actions_fired >= 1,
        "post-auth actions fired"
    );
    assert!(report.pre_auth.actions_fired >= 3, "pre-auth actions fired");
    assert_eq!(report.credentials.credential_values_injected, 2);
    assert!(report.credentials.redaction_active);

    // The crawler registered the exact injected values with the redactor.
    assert_eq!(redactor.registered_count(), 2);
    // And those values are scrubbed from a captured login flow.
    let mut flow = FlowCapture {
        id: 1,
        captured_at: Utc::now(),
        protocol: "http/1.1".to_owned(),
        method: Some("POST".to_owned()),
        host: Some("api.demo".to_owned()),
        url: Some("https://api.demo/login?u=alice".to_owned()),
        path: Some("/login".to_owned()),
        status: Some(200),
        duration_ms: Some(5),
        request_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        response_headers: Vec::new(),
        request_body: Some(br#"{"user":"alice","password":"s3cr3t!pw"}"#.to_vec()),
        response_body: None,
        scope: ScopeDisposition::InScope,
        provenance: "test".to_owned(),
        origin: FlowOrigin::Capture,
    };
    redactor.redact(&mut flow);
    let body = String::from_utf8(flow.request_body.clone().unwrap()).unwrap();
    assert!(
        !body.contains("s3cr3t!pw"),
        "injected password must be scrubbed: {body}"
    );
    assert!(
        !flow.url.as_ref().unwrap().contains("alice=") && !body.contains("\"alice\""),
        ""
    );
}

#[test]
fn stalled_login_is_injected_once_not_re_submitted_on_revisit() {
    // A login that never advances keeps the crawler on the login screen across
    // many loop iterations (and it is deliberately not walled, so an OTP step
    // could still appear). Without per-screen injection tracking the top-of-loop
    // login handler would re-inject — re-submitting the form and, for phone→OTP
    // flows, re-triggering OTP delivery — on every iteration. It must inject once.
    let device = MockDevice::sticky_login();
    let redactor = Arc::new(CredentialRedactor::new());
    let provider = Box::new(CannedProvider {
        pre_run: PreRunMode::TryAnyway,
        login: LoginMode::Provide,
        username: "alice",
        password: "s3cr3t!pw",
    });
    let mut crawler = AppCrawler::new(&device, fast_config(), provider, Arc::clone(&redactor));
    let report = crawler.run();

    // The sign-in never advances, so post-auth is never reached...
    assert!(
        !report.credentials.post_auth_reached,
        "a stalled login must not report post-auth reached"
    );
    // ...yet the credential gate was seen and injected exactly once.
    assert_eq!(
        report.credentials.credential_values_injected, 2,
        "exactly the two credential fields, injected once — not re-injected on revisit"
    );
    assert_eq!(
        redactor.registered_count(),
        2,
        "each credential registered once"
    );
    let state = device.state.lock().unwrap();
    // `input text` shell-escapes `!`, so match on a stable substring of the value.
    let password_types = state
        .typed_calls
        .iter()
        .filter(|call| call.contains("s3cr3t"))
        .count();
    assert_eq!(
        password_types, 1,
        "password typed exactly once despite staying on the login screen: {:?}",
        state.typed_calls
    );
}

#[test]
fn injected_credentials_never_reach_the_store_on_disk() {
    // The strongest no-leak check: write a flow carrying the credential (raw in
    // the body/header, percent-encoded in the query) into a REAL on-disk store
    // with the redactor armed, then grep every file under the store root. The
    // value must appear nowhere — sqlite metadata or content-addressed blobs.
    let secret = "SuperSecretPw!42";
    let dir = std::env::temp_dir().join(format!(
        "apiaxess-crawler-noleak-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store = Arc::new(TrafficStore::open(&dir, "session:noleak").expect("store"));
    let redactor = Arc::new(CredentialRedactor::new());
    store.set_redactor(Arc::clone(&redactor) as Arc<dyn FlowRedactor>);
    // Register BEFORE the flow is written, exactly as the crawler does.
    redactor.register(&Secret::from_text(secret));

    let flow = FlowCapture {
        id: 7,
        captured_at: Utc::now(),
        protocol: "http/1.1".to_owned(),
        method: Some("POST".to_owned()),
        host: Some("api.demo".to_owned()),
        url: Some("https://api.demo/login?pw=SuperSecretPw%2142".to_owned()),
        path: Some("/login".to_owned()),
        status: Some(200),
        duration_ms: Some(9),
        request_headers: vec![("x-auth".to_owned(), secret.to_owned())],
        response_headers: Vec::new(),
        request_body: Some(format!("{{\"password\":\"{secret}\"}}").into_bytes()),
        response_body: None,
        scope: ScopeDisposition::InScope,
        provenance: "test".to_owned(),
        origin: FlowOrigin::Capture,
    };
    store.upsert(&flow).expect("upsert");

    // Read back through the API: redacted.
    let read = store.get(7).expect("get").expect("present");
    let body =
        String::from_utf8_lossy(read.request_body.as_deref().unwrap_or_default()).into_owned();
    assert!(!body.contains(secret), "API read leaks credential: {body}");

    // Grep every byte on disk under the store root.
    let leaked = file_tree_contains(store.root(), secret.as_bytes());
    assert!(
        !leaked,
        "credential value found on disk under {}",
        store.root().display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Recursively checks whether any file under `root` contains `needle`.
fn file_tree_contains(root: &std::path::Path, needle: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if file_tree_contains(&path, needle) {
                return true;
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            if bytes.windows(needle.len()).any(|window| window == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn continue_without_credentials_leaves_wall_and_no_post_auth() {
    let device = MockDevice::new();
    let redactor = Arc::new(CredentialRedactor::new());
    let provider = Box::new(CannedProvider {
        pre_run: PreRunMode::TryAnyway,
        login: LoginMode::Continue,
        username: "alice",
        password: "pw",
    });
    let mut crawler = AppCrawler::new(&device, fast_config(), provider, Arc::clone(&redactor));
    let report = crawler.run();

    assert_eq!(report.credentials.login_gates_encountered, 1);
    assert!(!report.credentials.post_auth_reached);
    assert_eq!(report.post_auth.actions_fired, 0);
    assert!(
        report.unreached_behind_wall >= 1,
        "login left as a wall: {}",
        report.summary_line()
    );
    assert_eq!(
        redactor.registered_count(),
        0,
        "no credential registered when continuing without"
    );
}

struct QuietDevice;

impl SandboxControl for QuietDevice {
    fn command(&self, a: &[String], t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        self.shell(a, t)
    }
    fn shell(
        &self,
        arguments: &[String],
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
        match args.as_slice() {
            ["cat", _] => MockDevice::ok(
                r#"<hierarchy><node package="com.quiet" class="android.widget.TextView" text="Welcome" clickable="false" enabled="true" bounds="[0,0][100,50]"/></hierarchy>"#,
            ),
            ["dumpsys", "activity", "activities"] => {
                MockDevice::ok("  mResumedActivity: ActivityRecord{a u0 com.quiet/.Main t1}")
            }
            ["dumpsys", "package", _] => MockDevice::ok("requested permissions:"),
            _ => MockDevice::ok(""),
        }
    }
    fn put(&self, _b: &[u8], _p: &str, _t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn remove(&self, _p: &str, _t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn install_apks(
        &self,
        _p: &[std::path::PathBuf],
        _t: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn transport_id(&self) -> &'static str {
        "quiet"
    }
}

#[test]
fn quiet_app_hands_off_to_the_fallback_engine() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct RecordingFallback {
        called: Arc<AtomicBool>,
    }
    impl FallbackEngine for RecordingFallback {
        fn run(
            &mut self,
            _control: &dyn SandboxControl,
            _package: &str,
            _budget: Duration,
        ) -> Result<usize, String> {
            self.called.store(true, Ordering::SeqCst);
            Ok(5)
        }
        fn name(&self) -> &'static str {
            "mock"
        }
    }

    let device = QuietDevice;
    let redactor = Arc::new(CredentialRedactor::new());
    let provider = Box::new(CannedProvider {
        pre_run: PreRunMode::TryAnyway,
        login: LoginMode::Continue,
        username: "",
        password: "",
    });
    let called = Arc::new(AtomicBool::new(false));
    let mut crawler = AppCrawler::new(&device, fast_config(), provider, redactor).with_fallback(
        Box::new(RecordingFallback {
            called: Arc::clone(&called),
        }),
    );
    let report = crawler.run();
    assert!(
        report.actions_fired < 3,
        "quiet app yields little coverage: {}",
        report.summary_line()
    );
    assert!(called.load(Ordering::SeqCst), "fallback engine was invoked");
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("fallback 'mock' performed 5"))
    );
}

// --- Phone → OTP flow (the Openly/PlayRoom shape: phone number → SMS code) ---

const OTP_HOME: &str = r#"<hierarchy><node package="com.playroom" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.playroom:id/account" class="android.widget.Button" text="Account" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
</node></hierarchy>"#;

const OTP_PHONE: &str = r#"<hierarchy><node package="com.playroom" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.playroom:id/phone" class="android.widget.EditText" content-desc="Phone number" clickable="true" enabled="true" bounds="[0,100][100,150]"/>
<node resource-id="com.playroom:id/getotp" class="android.widget.Button" text="Get OTP" clickable="true" enabled="true" bounds="[0,200][100,250]"/>
</node></hierarchy>"#;

const OTP_CODE: &str = r#"<hierarchy><node package="com.playroom" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.playroom:id/otp" class="android.widget.EditText" content-desc="Verification code" clickable="true" enabled="true" bounds="[0,100][100,150]"/>
<node resource-id="com.playroom:id/verify" class="android.widget.Button" text="Verify" clickable="true" enabled="true" bounds="[0,200][100,250]"/>
</node></hierarchy>"#;

const OTP_PROFILE: &str = r#"<hierarchy><node package="com.playroom" class="android.widget.FrameLayout" bounds="[0,0][1080,1920]">
<node resource-id="com.playroom:id/feed" class="android.widget.Button" text="Load feed" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
<node resource-id="com.playroom:id/logout" class="android.widget.Button" text="Log out" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
</node></hierarchy>"#;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum OtpScreen {
    #[default]
    Home,
    Phone,
    Otp,
    Profile,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum OtpField {
    Phone,
    Otp,
}

#[derive(Default)]
struct OtpState {
    screen: OtpScreen,
    focused: Option<OtpField>,
    typed_phone: String,
    typed_otp: String,
    log: Vec<String>,
}

struct OtpFlowDevice {
    state: Mutex<OtpState>,
}

impl OtpFlowDevice {
    fn new() -> Self {
        Self {
            state: Mutex::new(OtpState::default()),
        }
    }

    fn screen_xml(screen: OtpScreen) -> &'static str {
        match screen {
            OtpScreen::Home => OTP_HOME,
            OtpScreen::Phone => OTP_PHONE,
            OtpScreen::Otp => OTP_CODE,
            OtpScreen::Profile => OTP_PROFILE,
        }
    }

    fn activity(screen: OtpScreen) -> &'static str {
        match screen {
            OtpScreen::Home => "com.playroom/.HomeActivity",
            OtpScreen::Phone => "com.playroom/.LoginActivity",
            OtpScreen::Otp => "com.playroom/.OtpActivity",
            OtpScreen::Profile => "com.playroom/.ProfileActivity",
        }
    }
}

impl SandboxControl for OtpFlowDevice {
    fn command(&self, a: &[String], t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        self.shell(a, t)
    }

    #[allow(clippy::match_same_arms)]
    fn shell(
        &self,
        arguments: &[String],
        _timeout: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let mut state = self.state.lock().unwrap();
        match args.as_slice() {
            ["uiautomator", "dump", _] => MockDevice::ok("dumped"),
            ["cat", _] => MockDevice::ok(Self::screen_xml(state.screen)),
            ["dumpsys", "activity", "activities"] => MockDevice::ok(&format!(
                "  mResumedActivity: ActivityRecord{{a u0 {} t1}}",
                Self::activity(state.screen)
            )),
            ["dumpsys", "package", _] => MockDevice::ok("requested permissions:"),
            ["input", "tap", _x, y] => {
                let y: i32 = y.parse().unwrap_or(0);
                match state.screen {
                    OtpScreen::Home => {
                        if (0..50).contains(&y) {
                            state.screen = OtpScreen::Phone;
                        }
                    }
                    OtpScreen::Phone => {
                        if (100..150).contains(&y) {
                            state.focused = Some(OtpField::Phone);
                        } else if (200..250).contains(&y) && !state.typed_phone.is_empty() {
                            state.screen = OtpScreen::Otp;
                            state.focused = None;
                        }
                    }
                    OtpScreen::Otp => {
                        if (100..150).contains(&y) {
                            state.focused = Some(OtpField::Otp);
                        } else if (200..250).contains(&y) && !state.typed_otp.is_empty() {
                            state.screen = OtpScreen::Profile;
                            state.focused = None;
                        }
                    }
                    OtpScreen::Profile => {}
                }
                MockDevice::ok("")
            }
            ["input", "text", value] => {
                let screen = state.screen;
                let focused = state.focused;
                state.log.push(format!(
                    "type {value:?} focus={focused:?} screen={screen:?}"
                ));
                match focused {
                    Some(OtpField::Phone) => state.typed_phone = (*value).to_owned(),
                    Some(OtpField::Otp) => state.typed_otp = (*value).to_owned(),
                    None => {}
                }
                MockDevice::ok("")
            }
            _ => MockDevice::ok(""),
        }
    }

    fn put(&self, _b: &[u8], _p: &str, _t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn remove(&self, _p: &str, _t: Duration) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn install_apks(
        &self,
        _p: &[std::path::PathBuf],
        _t: Duration,
    ) -> Result<SandboxCommandOutput, Diagnostic> {
        MockDevice::ok("")
    }
    fn transport_id(&self) -> &'static str {
        "otp"
    }
}

/// Supplies staged phone + OTP credentials up front, as the pipeline does from a
/// pre-run operator prompt (keyed by semantic kind, not screen resource-id).
struct StagedPhoneOtpProvider;

impl CredentialProvider for StagedPhoneOtpProvider {
    fn pre_run(&mut self, _package: &str) -> PreRunDecision {
        PreRunDecision::FeedNow(CredentialAnswer {
            values: vec![
                ("phone".to_owned(), Secret::from_text("8888888888")),
                ("otp".to_owned(), Secret::from_text("0000")),
            ],
        })
    }
    fn on_login_gate(&mut self, _request: &CredentialRequest) -> CredentialDecision {
        CredentialDecision::Continue
    }
    fn on_otp(&mut self, _request: &CredentialRequest) -> Option<Secret> {
        None
    }
}

#[test]
fn phone_otp_flow_crosses_the_gate_with_staged_credentials() {
    // The Openly/PlayRoom shape: a phone-number screen ("Get OTP") followed by a
    // one-time-code screen ("Verify"). Pre-run staged phone+OTP must drive both
    // steps and land in the post-auth surface — proving the crawler reaches the
    // app's real API, not just its pre-login calls.
    let device = OtpFlowDevice::new();
    let redactor = Arc::new(CredentialRedactor::new());
    let mut config = CrawlConfig::new("com.playroom");
    config.settle_delay = Duration::ZERO;
    config.time_budget = Duration::from_secs(30);
    let mut crawler = AppCrawler::new(
        &device,
        config,
        Box::new(StagedPhoneOtpProvider),
        Arc::clone(&redactor),
    );
    let report = crawler.run();

    assert!(
        report.credentials.post_auth_reached,
        "phone→OTP gate crossed into post-auth: {}",
        report.summary_line()
    );
    assert!(
        report.credentials.login_gates_encountered >= 1,
        "the phone screen is detected as a login gate: {}",
        report.summary_line()
    );
    assert!(
        report.credentials.otp_prompts >= 1,
        "the OTP screen is detected: {}",
        report.summary_line()
    );
    // Phone and OTP both registered with the redactor (never re-typed on revisit).
    assert!(
        report.credentials.credential_values_injected >= 2,
        "phone and OTP both injected: {}",
        report.summary_line()
    );
    // The profile screen behind the gate was actually reached.
    let state = device.state.lock().unwrap();
    assert_eq!(
        state.screen,
        OtpScreen::Profile,
        "landed on the post-auth screen"
    );
    assert_eq!(state.typed_phone, "8888888888", "log: {:#?}", state.log);
    assert_eq!(state.typed_otp, "0000", "log: {:#?}", state.log);
}

#[test]
fn pre_run_skip_does_no_crawl() {
    let device = MockDevice::new();
    let redactor = Arc::new(CredentialRedactor::new());
    let provider = Box::new(CannedProvider {
        pre_run: PreRunMode::Skip,
        login: LoginMode::Provide,
        username: "a",
        password: "b",
    });
    let mut crawler = AppCrawler::new(&device, fast_config(), provider, Arc::clone(&redactor));
    let report = crawler.run();
    assert_eq!(report.actions_fired, 0);
    assert!(report.termination.contains("skipped"));
}
