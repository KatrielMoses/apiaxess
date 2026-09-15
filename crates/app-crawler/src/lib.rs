//! Autonomous state-graph UI crawler that drives an installed Android app to
//! surface the maximum number of API-triggering interactions.
//!
//! The crawler drives the UI over ADB (`uiautomator dump` + `input`); traffic is
//! captured out-of-band by the workbench proxy. It maintains a graph of screen
//! *states* and the *(state, action)* pairs it has tried, methodically exercising
//! every interactive element rather than tapping at random — the failure mode of
//! the Monkey exerciser it replaces.
//!
//! It is API-surface-tuned (network-triggering controls are explored first),
//! budgeted (time / per-state / per-activity), robust (dialog handling, stall
//! recovery, path replay), and credential-aware (login gates are crossed with
//! operator-supplied, in-memory-only, redacted-from-capture credentials).

mod credentials;
mod device;
mod fallback;
mod heuristics;
mod hierarchy;
mod report;
mod state;

pub use credentials::{
    CredentialAnswer, CredentialDecision, CredentialField, CredentialKind, CredentialPromptReason,
    CredentialProvider, CredentialRedactor, CredentialRequest, PreRunDecision, Secret,
};
pub use fallback::{DroidBotFallback, FallbackEngine};
pub use report::{CoverageSlice, CrawlReport, CredentialTelemetry};
pub use state::{Action, ActionVerb, StateSignature};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apiaxess_sandbox::SandboxControl;

use hierarchy::Hierarchy;

/// Per-run crawl budget and pacing. Defaults favor thoroughness over speed.
#[derive(Clone, Debug)]
pub struct CrawlConfig {
    /// Package under crawl.
    pub package: String,
    /// Total wall-clock budget for the whole crawl.
    pub time_budget: Duration,
    /// Hard cap on interactions fired (a safety bound; time is the usual limit).
    pub max_total_actions: usize,
    /// Max interactions fired from any single screen state.
    pub per_state_action_budget: usize,
    /// Max interactions fired within any single activity.
    pub per_activity_budget: usize,
    /// Max times a scrollable is scrolled while it keeps yielding new content.
    pub max_scroll_repeats: usize,
    /// Max active picks from one state (loop safety).
    pub state_revisit_cap: usize,
    /// Delay after an action before re-dumping, letting the UI settle.
    pub settle_delay: Duration,
    /// Pre-grant the app's runtime permissions before crawling.
    pub pre_grant_permissions: bool,
    /// Prepare device location state (services on + a seeded GPS fix) before
    /// crawling, so location-gated screens make their backend calls.
    pub seed_location: bool,
}

impl CrawlConfig {
    /// Config for a package with thorough defaults.
    #[must_use]
    pub fn new(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            time_budget: Duration::from_secs(600),
            max_total_actions: 2_000,
            per_state_action_budget: 40,
            per_activity_budget: 200,
            max_scroll_repeats: 8,
            state_revisit_cap: 12,
            settle_delay: Duration::from_millis(900),
            pre_grant_permissions: true,
            seed_location: true,
        }
    }
}

/// A screen state node in the traversal graph.
struct ScreenState {
    activity: String,
    actions: Vec<Action>,
    tried: HashSet<String>,
    scroll_counts: HashMap<String, usize>,
    /// How this state was first reached: (parent hash, action key).
    parent: Option<(String, String)>,
    fired: usize,
    visits: usize,
}

impl ScreenState {
    fn untried_action(&self, budget: usize) -> Option<&Action> {
        if self.fired >= budget {
            return None;
        }
        self.actions
            .iter()
            .find(|action| !self.tried.contains(&action.key()))
    }

    fn has_untried(&self, budget: usize) -> bool {
        self.untried_action(budget).is_some()
    }
}

/// The autonomous crawler.
pub struct AppCrawler<'a> {
    control: &'a dyn SandboxControl,
    config: CrawlConfig,
    provider: Box<dyn CredentialProvider>,
    redactor: Arc<CredentialRedactor>,
    fallback: Option<Box<dyn FallbackEngine>>,
    states: HashMap<String, ScreenState>,
    staged_credentials: Option<CredentialAnswer>,
    authenticated: bool,
    // Phase accounting.
    pre_states: HashSet<String>,
    post_states: HashSet<String>,
    pre_activities: HashSet<String>,
    post_activities: HashSet<String>,
    pre_actions: usize,
    post_actions: usize,
    actions_fired: usize,
    activity_actions: HashMap<String, usize>,
    login_gates: usize,
    otp_prompts: usize,
    /// Runtime permissions pre-granted before the crawl (state-prep telemetry).
    permissions_granted: usize,
    /// Whether device location state was prepared for location-gated screens.
    location_prepared: bool,
    /// Login activities credentials have already been typed into. A login screen
    /// is injected at most once, so revisiting it (a stalled sign-in, or a BACK to
    /// it after auth) never re-submits the login form.
    login_injected: HashSet<String>,
    /// OTP activities a code has already been submitted into. Prevents re-firing
    /// a verification on revisit, which would re-trigger OTP delivery.
    otp_injected: HashSet<String>,
    walls: HashSet<String>,
    notes: Vec<String>,
    /// The (parent hash, action key) that produced the screen we're about to
    /// observe, used to record the BFS parent edge of a newly discovered state.
    pending_edge: Option<(String, String)>,
    started: Instant,
}

impl<'a> AppCrawler<'a> {
    /// Creates a crawler. The redactor must already be installed on the traffic
    /// store/observer so any credential registered here is scrubbed from capture.
    pub fn new(
        control: &'a dyn SandboxControl,
        config: CrawlConfig,
        provider: Box<dyn CredentialProvider>,
        redactor: Arc<CredentialRedactor>,
    ) -> Self {
        Self {
            control,
            config,
            provider,
            redactor,
            fallback: None,
            states: HashMap::new(),
            staged_credentials: None,
            authenticated: false,
            pre_states: HashSet::new(),
            post_states: HashSet::new(),
            pre_activities: HashSet::new(),
            post_activities: HashSet::new(),
            pre_actions: 0,
            post_actions: 0,
            actions_fired: 0,
            activity_actions: HashMap::new(),
            login_gates: 0,
            otp_prompts: 0,
            permissions_granted: 0,
            location_prepared: false,
            login_injected: HashSet::new(),
            otp_injected: HashSet::new(),
            walls: HashSet::new(),
            notes: Vec::new(),
            pending_edge: None,
            started: Instant::now(),
        }
    }

    /// Installs a secondary crawler invoked when the primary engine stalls early
    /// with little coverage (e.g. a quiet app). `DroidBot` is the intended engine.
    #[must_use]
    pub fn with_fallback(mut self, fallback: Box<dyn FallbackEngine>) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Runs the crawl to its budget and returns an honest coverage report.
    #[must_use]
    pub fn run(&mut self) -> CrawlReport {
        self.started = Instant::now();
        match self.provider.pre_run(&self.config.package) {
            PreRunDecision::Skip => {
                self.notes
                    .push("Dynamic crawl skipped by operator (app requires sign-in).".to_owned());
                return self.build_report("skipped by operator");
            }
            PreRunDecision::FeedNow(answer) => {
                self.notes
                    .push("Operator supplied credentials before the run.".to_owned());
                self.staged_credentials = Some(answer);
            }
            PreRunDecision::TryAnyway => {}
        }

        if self.config.pre_grant_permissions {
            let granted = device::grant_runtime_permissions(self.control, &self.config.package);
            self.permissions_granted = granted.len();
            self.notes.push(format!(
                "Pre-granted {} runtime permission(s).",
                granted.len()
            ));
        }

        // Prepare device state (location) before launch so a location-gated app
        // has a fix ready on its first screen rather than stalling on an empty map.
        if self.config.seed_location {
            let notes = device::prepare_location(self.control);
            self.location_prepared = notes.iter().any(|note| note.starts_with("Enabled"));
            for note in notes {
                self.notes.push(note);
            }
        }

        if let Err(error) = device::launch(self.control, &self.config.package) {
            self.notes.push(format!("Could not launch app: {error}"));
            return self.build_report("launch failed");
        }
        // Wait out the splash so traversal starts on the first real screen.
        self.await_first_screen();
        // Walk a bounded onboarding/intro carousel to the first input surface —
        // its near-identical slides collapse to one state signature, which would
        // otherwise keep normal traversal from advancing to the login gate.
        self.advance_through_intro();

        let termination = self.traverse();
        self.maybe_run_fallback();
        self.build_report(&termination)
    }

    /// When the primary engine surfaced almost nothing (a quiet or unusually
    /// structured app), hand off to the secondary crawler if one is installed.
    fn maybe_run_fallback(&mut self) {
        const LOW_COVERAGE_ACTIONS: usize = 3;
        if self.actions_fired >= LOW_COVERAGE_ACTIONS {
            return;
        }
        let Some(mut fallback) = self.fallback.take() else {
            return;
        };
        let remaining = self
            .config
            .time_budget
            .saturating_sub(self.started.elapsed());
        match fallback.run(self.control, &self.config.package, remaining) {
            Ok(extra) => self.notes.push(format!(
                "Primary engine stalled early; fallback '{}' performed {extra} extra interactions.",
                fallback.name()
            )),
            Err(reason) => self.notes.push(format!(
                "Primary engine stalled early; fallback '{}' unavailable: {reason}",
                fallback.name()
            )),
        }
    }

    /// The main traversal loop. Returns the termination reason.
    #[allow(clippy::too_many_lines)] // One cohesive traversal state machine; splitting obscures it.
    fn traverse(&mut self) -> String {
        let mut consecutive_backs = 0_usize;
        let mut consecutive_failures = 0_usize;
        loop {
            if self.started.elapsed() >= self.config.time_budget {
                return "time budget reached".to_owned();
            }
            if self.actions_fired >= self.config.max_total_actions {
                return "action cap reached".to_owned();
            }
            if consecutive_failures > 16 {
                return "navigation stalled".to_owned();
            }

            let Some(xml) = self.dump() else {
                // Dump failed — usually a transient animation/transition (splash,
                // Compose, keyboard). Be patient: wait and retry rather than
                // restart (a restart discards progress and bounces to the
                // splash). A BACK every few failures escapes a genuinely stuck
                // surface without leaving the app.
                consecutive_failures += 1;
                self.settle();
                if consecutive_failures % 4 == 0 {
                    let _ = device::press_back(self.control);
                    self.settle();
                }
                continue;
            };
            let hierarchy = Hierarchy::parse(&xml);
            // The edge that produced this screen, if we arrived via a tracked
            // forward action (dropped after any BACK/restart/replay/gate).
            let edge = self.pending_edge.take();

            // Foreground guard: if we've left the target package, come back.
            let activity = device::current_activity(self.control).unwrap_or_else(|_| {
                hierarchy
                    .package
                    .clone()
                    .unwrap_or_else(|| self.config.package.clone())
            });
            if let Some(package) = &hierarchy.package {
                if !package.starts_with(&self.config.package) && !package.contains("permission") {
                    let _ = device::press_back(self.control);
                    self.settle();
                    consecutive_failures += 1;
                    continue;
                }
            }

            // 1. Dialogs first — keep traffic flowing.
            if let Some(dialog) = heuristics::classify_dialog(&hierarchy) {
                // Only auto-handle when it's clearly a dialog, not a full screen
                // we can explore; classify_dialog already gates dismissals.
                if Self::should_autohandle_dialog(&hierarchy, &dialog) {
                    let _ = device::tap(self.control, dialog.point.0, dialog.point.1);
                    self.record_fired(&activity);
                    self.notes_once(format!("Handled dialog: {}", dialog.label));
                    self.settle();
                    consecutive_backs = 0;
                    consecutive_failures = 0;
                    continue;
                }
            }

            // 2. OTP gate.
            if !self.walls_contains(&activity) && !self.otp_injected.contains(&activity) {
                if let Some(request) =
                    heuristics::detect_otp(&hierarchy, &self.config.package, &activity)
                {
                    if self.handle_otp(&hierarchy, &request) {
                        consecutive_backs = 0;
                        consecutive_failures = 0;
                        continue;
                    }
                }
            }

            // 3. Login gate. Skip once credentials have been typed into this
            // screen (crossed or not): re-injecting on a revisit would re-submit
            // the login form and can re-trigger OTP delivery.
            if !self.authenticated
                && !self.walls.contains(&activity)
                && !self.login_injected.contains(&activity)
            {
                if let Some(request) =
                    heuristics::detect_login(&hierarchy, &self.config.package, &activity)
                {
                    if self.handle_login(&hierarchy, &request) {
                        consecutive_backs = 0;
                        consecutive_failures = 0;
                        continue;
                    }
                    // Not passed: record as a wall but keep exploring this screen
                    // (forgot-password / register buttons can still yield traffic).
                }
            }

            // 4. Normal state traversal.
            let signature = StateSignature::compute(&activity, &hierarchy);
            self.register_state(&signature, &activity, &hierarchy, edge);
            self.account_phase(&signature.hash, &activity);

            if let Some(action) = self.pick_action(&signature.hash, &activity) {
                let is_scroll = action.verb == ActionVerb::ScrollForward;
                self.pending_edge = Some((signature.hash.clone(), action.key()));
                self.perform(&action);
                self.record_fired(&activity);
                self.mark_tried(&signature.hash, &action, is_scroll, &xml);
                self.settle();
                consecutive_backs = 0;
                consecutive_failures = 0;
                continue;
            }

            // 5. No untried actions here → navigate to a state that has some.
            if !self.any_state_has_untried() {
                return "frontier exhausted".to_owned();
            }
            if consecutive_backs < 3 {
                let _ = device::press_back(self.control);
                consecutive_backs += 1;
                self.settle();
                continue;
            }
            // BACK isn't reaching new frontier; jump to the nearest untried state.
            if self.replay_to_untried() {
                consecutive_backs = 0;
                consecutive_failures = 0;
            } else {
                consecutive_failures += 1;
            }
            self.settle();
        }
    }

    fn should_autohandle_dialog(hierarchy: &Hierarchy, dialog: &heuristics::DialogAction) -> bool {
        // Always handle permission grants. For other dialogs, only when the
        // screen is small (a modal) so we don't dismiss real app UI.
        dialog.is_permission || hierarchy.actionable().len() <= 4
    }

    fn walls_contains(&self, activity: &str) -> bool {
        self.walls.contains(activity)
    }

    fn handle_login(&mut self, hierarchy: &Hierarchy, request: &CredentialRequest) -> bool {
        self.login_gates += 1;
        // Clone rather than take: a pre-run credential feed covers the whole
        // login flow, so the staged answer must remain available for a following
        // OTP screen (see `handle_otp`). It is cleared on a failed sign-in below.
        let answer = match self.staged_credentials.clone() {
            Some(staged) => staged,
            None => match self.provider.on_login_gate(request) {
                CredentialDecision::Provide(answer) => answer,
                CredentialDecision::Continue => {
                    self.walls
                        .insert(request_activity(&request.screen_summary, hierarchy));
                    self.notes
                        .push("Login gate left uncrossed (no credentials).".to_owned());
                    return false;
                }
            },
        };
        if !answer.has_values() {
            self.walls
                .insert(request_activity(&request.screen_summary, hierarchy));
            return false;
        }
        // Record the injection before submitting so a stalled sign-in (which is
        // deliberately not walled, to keep exploring for an OTP step) is never
        // re-injected on a later revisit.
        self.login_injected
            .insert(request_activity(&request.screen_summary, hierarchy));
        self.inject_fields(hierarchy, &request.fields, &answer);
        self.settle();
        // The submit button (e.g. "Get OTP") is commonly disabled until valid
        // input, so it isn't present/actionable in the pre-injection dump. Re-dump
        // after typing so the now-enabled affordance is found and tapped.
        let refreshed = self.dump().map(|xml| Hierarchy::parse(&xml));
        let submit_target = refreshed.as_ref().unwrap_or(hierarchy);
        self.tap_submit(submit_target, heuristics::SIGN_IN_AFFORDANCES);
        self.settle();
        // Confirm we advanced off the login screen.
        if let Some(xml) = self.dump() {
            let advanced_hierarchy = Hierarchy::parse(&xml);
            let advanced_activity = device::current_activity(self.control)
                .unwrap_or_else(|_| self.config.package.clone());
            // Advancing to the OTP step counts as a successful sign-in step, not a
            // stuck login screen — otherwise the broadened "Get OTP"/"Verify"
            // affordances would make the OTP screen look like an un-crossed gate
            // and discard the staged OTP.
            let reached_otp = heuristics::detect_otp(
                &advanced_hierarchy,
                &self.config.package,
                &advanced_activity,
            )
            .is_some();
            let still_login = !reached_otp
                && heuristics::detect_login(
                    &advanced_hierarchy,
                    &self.config.package,
                    &advanced_activity,
                )
                .is_some();
            if still_login {
                // Don't wall the activity or drop the staged answer: phone→OTP
                // flows keep the OTP step in the SAME activity, so walling it
                // would also block OTP handling, and the staged answer still
                // carries the OTP. Just report and let traversal continue.
                self.notes_once("Sign-in did not advance past the login screen.".to_owned());
                return false;
            }
        }
        self.authenticated = true;
        self.notes.push(
            "Credentials injected and redacted from capture; post-auth crawl begins.".to_owned(),
        );
        true
    }

    fn handle_otp(&mut self, hierarchy: &Hierarchy, request: &CredentialRequest) -> bool {
        self.otp_prompts += 1;
        // The pre-run credential feed covers the whole login flow: resolve the
        // OTP for this field from the staged answer (by field id or `otp` kind)
        // first, then fall back to a live provider prompt.
        let code = self
            .staged_credentials
            .as_ref()
            .and_then(|answer| {
                request
                    .fields
                    .first()
                    .and_then(|field| resolve_value(answer, field).cloned())
            })
            .or_else(|| self.provider.on_otp(request));
        let Some(code) = code else {
            self.walls
                .insert(request_activity(&request.screen_summary, hierarchy));
            self.notes.push("OTP gate left uncrossed.".to_owned());
            return false;
        };
        if code.is_empty() {
            return false;
        }
        // Record this OTP screen as handled so a revisit does not re-submit the
        // code and re-trigger delivery. Done before typing (idempotent even if the
        // submit below is retried within this same handling).
        self.otp_injected
            .insert(request_activity(&request.screen_summary, hierarchy));
        // Register BEFORE typing so the verification request is scrubbed.
        self.redactor.register(&code);
        let plain = code.reveal();
        // PIN-style OTP screens split the code across one box per digit. When the
        // number of enabled input boxes matches the code length, type one digit
        // into each (left-to-right); otherwise type the whole code into one field.
        let mut boxes: Vec<&hierarchy::UiNode> = hierarchy
            .nodes
            .iter()
            .filter(|node| node.editable && node.enabled && node.bounds.is_tappable())
            .collect();
        boxes.sort_by_key(|node| node.bounds.center().0);
        if boxes.len() >= 2 && boxes.len() == plain.chars().count() {
            for (node, digit) in boxes.iter().zip(plain.chars()) {
                let (x, y) = node.bounds.center();
                let _ = device::tap(self.control, x, y);
                let _ = device::clear_focused(self.control);
                let _ = device::input_text(self.control, &digit.to_string());
            }
        } else {
            if let Some(field) = request.fields.first() {
                self.focus_field_by_name(hierarchy, &field.name);
            }
            let _ = device::clear_focused(self.control);
            let _ = device::input_text(self.control, &plain);
        }
        self.tap_submit(
            hierarchy,
            &["verify", "submit", "continue", "confirm", "next", "ok"],
        );
        self.settle();
        // A verified OTP is the final sign-in step of a phone→OTP flow. If we
        // advanced off the OTP (and login) screen, mark post-auth reached — without
        // this the crawl would keep attributing the whole post-sign-in surface to
        // the pre-auth phase and report the gate as never crossed.
        if !self.authenticated {
            if let Some(xml) = self.dump() {
                let advanced = Hierarchy::parse(&xml);
                let activity = device::current_activity(self.control)
                    .unwrap_or_else(|_| self.config.package.clone());
                let still_otp =
                    heuristics::detect_otp(&advanced, &self.config.package, &activity).is_some();
                let still_login =
                    heuristics::detect_login(&advanced, &self.config.package, &activity).is_some();
                if !still_otp && !still_login {
                    self.authenticated = true;
                    self.notes
                        .push("OTP verified and redacted; post-auth crawl begins.".to_owned());
                }
            }
        }
        true
    }

    fn inject_fields(
        &mut self,
        hierarchy: &Hierarchy,
        fields: &[CredentialField],
        answer: &CredentialAnswer,
    ) {
        for field in fields {
            let Some(secret) = resolve_value(answer, field) else {
                continue;
            };
            if secret.is_empty() {
                continue;
            }
            // Register BEFORE typing: no capture window exists where the raw
            // value could be persisted unredacted.
            self.redactor.register(secret);
            self.focus_field_by_name(hierarchy, &field.name);
            let _ = device::clear_focused(self.control);
            let _ = device::input_text(self.control, &secret.reveal());
        }
    }

    fn focus_field_by_name(&self, hierarchy: &Hierarchy, name: &str) {
        if let Some(node) = hierarchy.nodes.iter().find(|node| {
            node.editable && (node.resource_id == name || format!("field-{}", node.index) == name)
        }) {
            let (x, y) = node.bounds.center();
            let _ = device::tap(self.control, x, y);
        }
    }

    fn tap_submit(&self, hierarchy: &Hierarchy, labels: &[&str]) {
        if let Some(node) = hierarchy.actionable().iter().find(|node| {
            node.clickable && {
                let text = if node.text.is_empty() {
                    node.content_desc.to_ascii_lowercase()
                } else {
                    node.text.to_ascii_lowercase()
                };
                labels
                    .iter()
                    .any(|label| text.trim() == *label || text.contains(label))
            }
        }) {
            let (x, y) = node.bounds.center();
            let _ = device::tap(self.control, x, y);
        }
    }

    fn register_state(
        &mut self,
        signature: &StateSignature,
        activity: &str,
        hierarchy: &Hierarchy,
        edge: Option<(String, String)>,
    ) {
        if let Some(existing) = self.states.get_mut(&signature.hash) {
            existing.visits += 1;
            return;
        }
        // Record the shortest known path edge on first discovery (BFS/DFS parent).
        let parent = edge.filter(|(parent_hash, _)| *parent_hash != signature.hash);
        self.states.insert(
            signature.hash.clone(),
            ScreenState {
                activity: activity.to_owned(),
                actions: state::actions_for(hierarchy),
                tried: HashSet::new(),
                scroll_counts: HashMap::new(),
                parent,
                fired: 0,
                visits: 1,
            },
        );
    }

    fn account_phase(&mut self, hash: &str, activity: &str) {
        if self.authenticated {
            self.post_states.insert(hash.to_owned());
            self.post_activities.insert(activity.to_owned());
        } else {
            self.pre_states.insert(hash.to_owned());
            self.pre_activities.insert(activity.to_owned());
        }
    }

    fn pick_action(&self, hash: &str, activity: &str) -> Option<Action> {
        if self
            .activity_actions
            .get(activity)
            .is_some_and(|count| *count >= self.config.per_activity_budget)
        {
            return None;
        }
        let state = self.states.get(hash)?;
        if state.visits > self.config.state_revisit_cap
            && !state.has_untried(self.config.per_state_action_budget)
        {
            return None;
        }
        state
            .untried_action(self.config.per_state_action_budget)
            .cloned()
    }

    fn perform(&self, action: &Action) {
        let (x, y) = action.point;
        match action.verb {
            ActionVerb::Tap | ActionVerb::FocusInput => {
                let _ = device::tap(self.control, x, y);
            }
            ActionVerb::LongPress => {
                let _ = device::long_press(self.control, x, y);
            }
            ActionVerb::ScrollForward => {
                let _ = device::scroll_forward(self.control, x, y, 900);
            }
        }
    }

    fn mark_tried(&mut self, hash: &str, action: &Action, is_scroll: bool, before_xml: &str) {
        let capped = {
            let Some(state) = self.states.get_mut(hash) else {
                return;
            };
            state.fired += 1;
            if !is_scroll {
                state.tried.insert(action.key());
                return;
            }
            // Scroll-to-exhaust with a repeat cap: keep the action open until it
            // stops yielding change or the cap is hit.
            let count = state.scroll_counts.entry(action.key()).or_insert(0);
            *count += 1;
            *count >= self.config.max_scroll_repeats
        };
        let unchanged = self.dump().is_some_and(|after| after == before_xml);
        if capped || unchanged {
            if let Some(state) = self.states.get_mut(hash) {
                state.tried.insert(action.key());
            }
        }
    }

    fn record_fired(&mut self, activity: &str) {
        self.actions_fired += 1;
        *self
            .activity_actions
            .entry(activity.to_owned())
            .or_insert(0) += 1;
        if self.authenticated {
            self.post_actions += 1;
        } else {
            self.pre_actions += 1;
        }
    }

    fn any_state_has_untried(&self) -> bool {
        self.states.values().any(|state| {
            state.has_untried(self.config.per_state_action_budget)
                && self
                    .activity_actions
                    .get(&state.activity)
                    .is_none_or(|count| *count < self.config.per_activity_budget)
        })
    }

    /// Restarts the app and replays the shortest known path to a state that
    /// still has untried actions. Returns whether it reached such a state.
    fn replay_to_untried(&mut self) -> bool {
        let Some(target) = self.nearest_untried_state() else {
            return false;
        };
        let path = self.path_to(&target);
        self.restart();
        self.settle();
        for action_key in path {
            let Some(xml) = self.dump() else {
                return false;
            };
            let hierarchy = Hierarchy::parse(&xml);
            let activity = device::current_activity(self.control)
                .unwrap_or_else(|_| self.config.package.clone());
            let signature = StateSignature::compute(&activity, &hierarchy);
            let Some(state) = self.states.get(&signature.hash) else {
                break;
            };
            let Some(action) = state
                .actions
                .iter()
                .find(|candidate| candidate.key() == action_key)
                .cloned()
            else {
                break;
            };
            self.perform(&action);
            self.record_fired(&activity);
            self.settle();
        }
        true
    }

    fn nearest_untried_state(&self) -> Option<String> {
        let budget = self.config.per_state_action_budget;
        self.states
            .iter()
            .filter(|(_, state)| {
                state.has_untried(budget)
                    && self
                        .activity_actions
                        .get(&state.activity)
                        .is_none_or(|count| *count < self.config.per_activity_budget)
            })
            .min_by_key(|(hash, _)| self.path_to(hash).len())
            .map(|(hash, _)| hash.clone())
    }

    fn path_to(&self, target: &str) -> Vec<String> {
        let mut path = Vec::new();
        let mut cursor = Some(target.to_owned());
        let mut guard = 0;
        while let Some(hash) = cursor {
            guard += 1;
            if guard > 256 {
                break;
            }
            let Some(state) = self.states.get(&hash) else {
                break;
            };
            match &state.parent {
                Some((parent_hash, action_key)) => {
                    path.push(action_key.clone());
                    cursor = Some(parent_hash.clone());
                }
                None => break,
            }
        }
        path.reverse();
        path
    }

    fn dump(&self) -> Option<String> {
        // `uiautomator dump` transiently fails (null root / "not idle") while a
        // screen is animating — common on splash and Compose transitions. Retry
        // a few times before treating it as a real failure.
        for attempt in 0..5 {
            if let Some(xml) = device::dump_hierarchy(self.control)
                .ok()
                .filter(|xml| xml.contains("<node"))
            {
                return Some(xml);
            }
            if attempt < 4 {
                std::thread::sleep(Duration::from_millis(900));
            }
        }
        None
    }

    /// Waits for the app's first usable screen after launch. Apps commonly show
    /// an animated splash for several seconds during which no actionable UI is
    /// dumpable; without this, traversal counts those empty dumps as failures
    /// and stalls on the splash before the real UI appears.
    fn await_first_screen(&self) {
        let deadline = Instant::now() + Duration::from_secs(18);
        while Instant::now() < deadline {
            if let Some(xml) = self.dump() {
                let hierarchy = Hierarchy::parse(&xml);
                let in_package = hierarchy.package.as_deref().is_none_or(|package| {
                    package.starts_with(&self.config.package) || package.contains("permission")
                });
                if in_package && !hierarchy.actionable().is_empty() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1200));
        }
    }

    /// Walks a bounded onboarding/intro carousel to the first input surface by
    /// repeatedly tapping the bottom-most call-to-action (Next/Continue/Get
    /// Started). Intro slides commonly share a view structure, so their state
    /// signatures collapse and normal traversal will not keep advancing them.
    /// Gated to intro-looking screens and always stops at the first editable, so
    /// login-first (e.g. a phone-entry screen) and home-first apps are untouched.
    fn advance_through_intro(&mut self) {
        for _ in 0..8 {
            let Some(xml) = self.dump() else {
                break;
            };
            let hierarchy = Hierarchy::parse(&xml);
            // Reached an input surface — hand off to normal traversal (login/OTP).
            if hierarchy.nodes.iter().any(|node| node.editable) {
                break;
            }
            let activity = device::current_activity(self.control).unwrap_or_default();
            let activity_lc = activity.to_ascii_lowercase();
            let looks_like_intro = activity_lc.contains("welcome")
                || activity_lc.contains("onboard")
                || activity_lc.contains("intro")
                || activity_lc.contains("splash")
                || activity_lc.contains("walkthrough")
                || hierarchy.nodes.iter().any(|node| {
                    let text = format!("{} {}", node.text, node.content_desc).to_ascii_lowercase();
                    [
                        "next",
                        "skip",
                        "get started",
                        "continue",
                        "let's go",
                        "swipe",
                    ]
                    .iter()
                    .any(|needle| text.contains(needle))
                });
            if !looks_like_intro {
                break;
            }
            let Some(node) = hierarchy
                .actionable()
                .into_iter()
                .filter(|node| node.clickable && node.bounds.is_tappable())
                .max_by_key(|node| node.bounds.center().1)
            else {
                break;
            };
            let (x, y) = node.bounds.center();
            let _ = device::tap(self.control, x, y);
            self.notes_once("Advanced through an onboarding/intro carousel.".to_owned());
            self.settle();
        }
    }

    fn restart(&self) {
        let _ = device::force_stop(self.control, &self.config.package);
        let _ = device::launch(self.control, &self.config.package);
        // Relaunch replays the splash; wait for the first real screen so the
        // caller does not immediately re-stall dumping the splash.
        self.await_first_screen();
    }

    fn settle(&self) {
        if !self.config.settle_delay.is_zero() {
            std::thread::sleep(self.config.settle_delay);
        }
    }

    fn notes_once(&mut self, note: String) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    fn build_report(&self, termination: &str) -> CrawlReport {
        let skipped_actions: usize = self
            .states
            .values()
            .map(|state| {
                state
                    .actions
                    .iter()
                    .filter(|action| !state.tried.contains(&action.key()))
                    .count()
            })
            .sum();
        let mut visited_activities: Vec<String> = self
            .pre_activities
            .union(&self.post_activities)
            .cloned()
            .collect();
        visited_activities.sort();
        CrawlReport {
            package: self.config.package.clone(),
            termination: termination.to_owned(),
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            pre_auth: CoverageSlice {
                states_visited: self.pre_states.len(),
                activities_visited: self.pre_activities.len(),
                actions_fired: self.pre_actions,
            },
            post_auth: CoverageSlice {
                states_visited: self.post_states.len(),
                activities_visited: self.post_activities.len(),
                actions_fired: self.post_actions,
            },
            states_visited: self.states.len(),
            activities_visited: visited_activities.len(),
            actions_fired: self.actions_fired,
            unreached_behind_wall: self.walls.len(),
            skipped_actions,
            permissions_granted: self.permissions_granted,
            location_prepared: self.location_prepared,
            credentials: CredentialTelemetry {
                login_gates_encountered: self.login_gates,
                credential_values_injected: self.redactor.registered_count(),
                otp_prompts: self.otp_prompts,
                redaction_active: self.redactor.is_active(),
                post_auth_reached: self.authenticated,
            },
            visited_activities,
            notes: self.notes.clone(),
        }
    }
}

fn resolve_value<'answer>(
    answer: &'answer CredentialAnswer,
    field: &CredentialField,
) -> Option<&'answer Secret> {
    answer
        .get(&field.name)
        .or_else(|| answer.get(kind_key(field.kind)))
}

const fn kind_key(kind: CredentialKind) -> &'static str {
    match kind {
        CredentialKind::Username => "username",
        CredentialKind::Password => "password",
        CredentialKind::Email => "email",
        CredentialKind::Phone => "phone",
        CredentialKind::Pin => "pin",
        CredentialKind::Otp => "otp",
        CredentialKind::Generic => "generic",
    }
}

fn request_activity(summary: &str, hierarchy: &Hierarchy) -> String {
    summary
        .split(" — ")
        .next()
        .map(str::to_owned)
        .or_else(|| hierarchy.package.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
