//! Honest split-coverage telemetry.
//!
//! Coverage is reported as concrete facts from the state graph — states and
//! activities actually visited, actions actually fired — split into pre-auth and
//! post-auth (credential-assisted) phases. It never infers a "% of API": the
//! tool has no ground truth for the full surface, so any percentage would be a
//! fabrication.

use serde::{Deserialize, Serialize};

/// Concrete coverage for one phase of the crawl.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSlice {
    /// Distinct screen states entered in this phase.
    pub states_visited: usize,
    /// Distinct activities entered in this phase.
    pub activities_visited: usize,
    /// Interactions actually performed in this phase.
    pub actions_fired: usize,
}

/// Credential-assistance telemetry (counts only — never any value).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialTelemetry {
    /// Sign-in gates the crawler detected.
    pub login_gates_encountered: usize,
    /// Distinct credential values injected (never the values themselves).
    pub credential_values_injected: usize,
    /// OTP prompts raised to the operator.
    pub otp_prompts: usize,
    /// Whether the redactor was armed for this run.
    pub redaction_active: bool,
    /// Whether the crawl passed an auth wall into post-auth surface.
    pub post_auth_reached: bool,
}

/// The complete, honest outcome of a crawl.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrawlReport {
    /// Package crawled.
    pub package: String,
    /// Why the crawl ended (budget, exhausted frontier, skipped, error).
    pub termination: String,
    /// Wall-clock duration.
    pub duration_ms: u64,
    /// Coverage reached before any credential was injected.
    pub pre_auth: CoverageSlice,
    /// Coverage reached after credential-assisted sign-in (zero if never signed in).
    pub post_auth: CoverageSlice,
    /// Total distinct screen states visited across the whole run.
    pub states_visited: usize,
    /// Total distinct activities visited across the whole run.
    pub activities_visited: usize,
    /// Total interactions fired across the whole run.
    pub actions_fired: usize,
    /// Login gates detected but left uncrossed (no credentials supplied).
    pub unreached_behind_wall: usize,
    /// Known interactive (state, action) pairs left untried when the run ended.
    pub skipped_actions: usize,
    /// Credential-assistance summary.
    pub credentials: CredentialTelemetry,
    /// Activities visited, for the operator's inspection.
    pub visited_activities: Vec<String>,
    /// Free-text, per-run notes (e.g. "dynamic skipped by operator").
    pub notes: Vec<String>,
}

impl CrawlReport {
    /// A one-line honest summary for a diagnostic/log (no fabricated percentages).
    #[must_use]
    pub fn summary_line(&self) -> String {
        format!(
            "crawl of {}: {} states, {} activities, {} actions fired ({} pre-auth / {} post-auth); {} login gate(s), {} value(s) injected, post-auth {}; {} action(s) left untried; ended: {}",
            self.package,
            self.states_visited,
            self.activities_visited,
            self.actions_fired,
            self.pre_auth.actions_fired,
            self.post_auth.actions_fired,
            self.credentials.login_gates_encountered,
            self.credentials.credential_values_injected,
            if self.credentials.post_auth_reached { "reached" } else { "not reached" },
            self.skipped_actions,
            self.termination,
        )
    }
}
