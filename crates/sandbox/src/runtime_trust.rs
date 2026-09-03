//! Offline, policy-driven runtime trust evaluation.
//!
//! The evaluator deliberately knows only posture facts and boolean policy
//! expressions. Vulnerability IDs, fixed patch levels, exploitability
//! preconditions, and VEX justifications live in the embedded policy bundle.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs::OpenOptions,
    io::Write,
    path::Path,
};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const POLICY_BUNDLE: &str = include_str!("../policies/runtime-trust.json");
const POLICY_BUNDLE_SHA256: &str = include_str!("../policies/runtime-trust.json.sha256");

/// A policy bundle loaded from signed/versioned offline policy data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTrustPolicy {
    /// Stable policy identifier.
    pub policy_id: String,
    /// Monotonic policy version.
    pub version: u32,
    /// VEX-compatible vulnerability records.
    pub vulnerabilities: Vec<VulnerabilityRecord>,
}

/// One vulnerability reachability record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilityRecord {
    /// Finding/CVE identifier.
    pub finding_id: String,
    /// Patch level that fixes the finding, when shipped by the image.
    pub fixed_in_patch: String,
    /// Boolean expression describing the exploitability precondition.
    pub exploitability: String,
    /// Boolean expression describing controls that close the precondition.
    pub mitigation: String,
    /// OpenVEX-compatible justification name.
    pub vex_justification: String,
}

/// Runtime posture facts collected immediately before lease handoff.
// These independent booleans are the serialized posture contract consumed by
// the policy expressions; grouping them would obscure individual controls.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTrustFacts {
    /// Selected sandbox tier.
    pub sandbox_tier: String,
    /// Android security patch level as reported by the runtime.
    pub security_patch: Option<String>,
    /// Configured image reference digest.
    pub image_digest: String,
    /// Digest expected by the immutable image pin.
    pub expected_image_digest: String,
    /// Whether optional image signature/provenance verification succeeded.
    pub image_signature_verified: bool,
    /// Whether optional signature verification was attempted.
    pub image_signature_checked: bool,
    /// Whether the container/VM containment check succeeded.
    pub containment_verified: bool,
    /// ADB is published only on 127.0.0.1.
    pub adb_loopback_only: bool,
    /// ADB uses the per-lease host key.
    pub adb_key_authenticated: bool,
    /// The ADB endpoint and key are lease-scoped and removed at teardown.
    pub adb_ephemeral: bool,
    /// Integrity of the embedded policy bundle.
    pub policy_bundle_verified: bool,
}

impl RuntimeTrustFacts {
    fn expression_facts(&self) -> BTreeMap<String, bool> {
        BTreeMap::from([
            ("adb.exposed".to_owned(), !self.adb_loopback_only),
            ("adb.loopback_only".to_owned(), self.adb_loopback_only),
            (
                "adb.key_authenticated".to_owned(),
                self.adb_key_authenticated,
            ),
            ("adb.ephemeral".to_owned(), self.adb_ephemeral),
            ("containment.verified".to_owned(), self.containment_verified),
        ])
    }
}

/// Explicit trust-gate outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTrustOutcome {
    /// Runtime is trusted under the evaluated policy.
    Allow,
    /// Runtime may proceed and findings remain visible to callers.
    AllowWithFindings,
    /// Runtime may proceed only after a matching explicit acceptance.
    RequireAcceptance,
    /// Runtime cannot proceed, including for non-overridable integrity gaps.
    Deny,
}

/// VEX-style finding retained with a trust decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTrustFinding {
    /// Stable finding identifier.
    pub finding_id: String,
    /// Whether the finding was mitigated, unresolved, or informational.
    pub status: String,
    /// VEX-compatible justification when applicable.
    pub vex_justification: Option<String>,
    /// Human-readable rationale.
    pub rationale: String,
    /// Whether this finding can never be overridden.
    pub non_overridable: bool,
}

/// Explained decision emitted by the runtime trust gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTrustDecision {
    /// Policy identity and version used for evaluation.
    pub policy: String,
    /// Final outcome.
    pub outcome: RuntimeTrustOutcome,
    /// Stable posture summary.
    pub facts: RuntimeTrustFacts,
    /// Findings and VEX resolutions.
    pub findings: Vec<RuntimeTrustFinding>,
    /// Ordered rationale retained for audit/UI display.
    pub rationale: Vec<String>,
}

/// Structured, scoped risk acceptance for one or more findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeTrustAcceptance {
    /// Exact finding IDs being accepted.
    pub finding_ids: BTreeSet<String>,
    /// Exact image digest to which the acceptance applies.
    pub image_digest: String,
    /// Exact sandbox profile/tier to which it applies.
    pub profile: String,
    /// User-provided reason.
    pub reason: String,
    /// User-provided threat model.
    pub threat_model: String,
    /// User identity.
    pub user: String,
    /// Absolute expiry; acceptance never auto-renews.
    pub expires_at: DateTime<Utc>,
}

/// Loads and verifies the embedded offline policy bundle.
pub fn default_policy() -> Result<RuntimeTrustPolicy, String> {
    let policy: RuntimeTrustPolicy =
        serde_json::from_str(POLICY_BUNDLE).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(POLICY_BUNDLE.as_bytes());
    let observed = digest.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(&mut output, "{byte:02x}");
        output
    });
    if observed != POLICY_BUNDLE_SHA256.trim()
        || policy.policy_id.trim().is_empty()
        || policy.version == 0
    {
        return Err("embedded runtime-trust policy integrity metadata is invalid".to_owned());
    }
    Ok(policy)
}

/// Evaluates posture against offline policy data and an optional acceptance.
#[must_use]
// The policy evaluation intentionally mirrors the ordered trust decision.
#[allow(clippy::too_many_lines)]
pub fn evaluate(
    facts: RuntimeTrustFacts,
    policy: &RuntimeTrustPolicy,
    acceptance: Option<&RuntimeTrustAcceptance>,
) -> RuntimeTrustDecision {
    let mut findings = Vec::new();
    let mut rationale = vec![format!(
        "evaluated policy {} v{} for {}",
        policy.policy_id, policy.version, facts.sandbox_tier
    )];

    if facts.image_digest != facts.expected_image_digest {
        findings.push(integrity_finding(
            "integrity.image-digest-mismatch",
            "configured image digest does not match the observed immutable image pin",
        ));
    }
    if facts.image_signature_checked && !facts.image_signature_verified {
        findings.push(integrity_finding(
            "integrity.image-signature-invalid",
            "image signature/provenance verification failed",
        ));
    } else if !facts.image_signature_checked {
        findings.push(RuntimeTrustFinding {
            finding_id: "integrity.image-signature-unverified".to_owned(),
            status: "unverified".to_owned(),
            vex_justification: None,
            rationale: "optional offline image signature verification was not supplied".to_owned(),
            non_overridable: false,
        });
    }
    if !facts.containment_verified {
        findings.push(integrity_finding(
            "integrity.containment-failure",
            "runtime containment could not be verified",
        ));
    }
    if !facts.policy_bundle_verified {
        findings.push(integrity_finding(
            "integrity.policy-bundle-failure",
            "offline runtime-trust policy integrity could not be verified",
        ));
    }

    let expressions = facts.expression_facts();
    for record in &policy.vulnerabilities {
        let patched = facts
            .security_patch
            .as_deref()
            .is_some_and(|patch| valid_patch(patch) && patch >= record.fixed_in_patch.as_str());
        if patched {
            rationale.push(format!(
                "{} is resolved by runtime patch level {}",
                record.finding_id,
                facts.security_patch.as_deref().unwrap_or_default()
            ));
            continue;
        }
        let reachable = expression_true(&record.exploitability, &expressions);
        let mitigated = expression_true(&record.mitigation, &expressions);
        if !reachable || mitigated {
            let justification = if mitigated {
                record.vex_justification.clone()
            } else {
                "vulnerable_code_not_in_execute_path".to_owned()
            };
            findings.push(RuntimeTrustFinding {
                finding_id: record.finding_id.clone(),
                status: "present_but_mitigated".to_owned(),
                vex_justification: Some(justification.clone()),
                rationale: format!(
                    "{} is not reachable under the declared runtime controls ({justification})",
                    record.finding_id
                ),
                non_overridable: false,
            });
            rationale.push(format!(
                "{} is present but its exploitability precondition is closed by the runtime profile",
                record.finding_id
            ));
        } else {
            findings.push(RuntimeTrustFinding {
                finding_id: record.finding_id.clone(),
                status: "unmitigated".to_owned(),
                vex_justification: None,
                rationale: format!(
                    "{} remains reachable because its exploitability precondition is true and mitigation is incomplete",
                    record.finding_id
                ),
                non_overridable: false,
            });
        }
    }

    let non_overridable = findings.iter().any(|finding| finding.non_overridable);
    let unresolved = findings
        .iter()
        .filter(|finding| finding.status == "unmitigated")
        .map(|finding| finding.finding_id.clone())
        .collect::<BTreeSet<_>>();
    let accepted = acceptance.is_some_and(|value| {
        value.expires_at > Utc::now()
            && value.image_digest == facts.image_digest
            && value.profile == facts.sandbox_tier
            && !value.reason.trim().is_empty()
            && !value.threat_model.trim().is_empty()
            && !value.user.trim().is_empty()
            && unresolved.is_subset(&value.finding_ids)
    });
    let outcome = if non_overridable {
        RuntimeTrustOutcome::Deny
    } else if !unresolved.is_empty() && !accepted {
        RuntimeTrustOutcome::RequireAcceptance
    } else if findings.is_empty() {
        RuntimeTrustOutcome::Allow
    } else {
        RuntimeTrustOutcome::AllowWithFindings
    };
    RuntimeTrustDecision {
        policy: format!("{}@{}", policy.policy_id, policy.version),
        outcome,
        facts,
        findings,
        rationale,
    }
}

/// Appends a scoped acceptance to an audit JSONL file.
pub fn append_acceptance_audit(
    path: &Path,
    acceptance: &RuntimeTrustAcceptance,
    decision: &RuntimeTrustDecision,
) -> Result<(), String> {
    if !matches!(
        decision.outcome,
        RuntimeTrustOutcome::AllowWithFindings | RuntimeTrustOutcome::Allow
    ) {
        return Err("only an accepted runtime-trust decision can be audited".to_owned());
    }
    let record = serde_json::json!({
        "event": "runtime-trust.acceptance",
        "occurred_at": Utc::now(),
        "acceptance": acceptance,
        "decision": decision,
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    writeln!(file, "{record}").map_err(|error| error.to_string())?;
    file.flush().map_err(|error| error.to_string())
}

/// Renders the decision through the canonical diagnostics catalogue.
#[must_use]
pub fn diagnostics(decision: &RuntimeTrustDecision) -> Vec<Diagnostic> {
    let mut context = DiagnosticContext::new();
    context.insert(
        "policy".to_owned(),
        DiagnosticValue::String(decision.policy.clone()),
    );
    context.insert(
        "outcome".to_owned(),
        DiagnosticValue::String(format!("{:?}", decision.outcome).to_ascii_lowercase()),
    );
    context.insert(
        "rationale".to_owned(),
        DiagnosticValue::StringList(decision.rationale.clone()),
    );
    context.insert(
        "findings".to_owned(),
        DiagnosticValue::StringList(
            decision
                .findings
                .iter()
                .map(|finding| finding.finding_id.clone())
                .collect(),
        ),
    );
    context.insert(
        "facts".to_owned(),
        DiagnosticValue::String(
            serde_json::to_string(&decision.facts).unwrap_or_else(|_| "{}".to_owned()),
        ),
    );
    let definition = match decision.outcome {
        RuntimeTrustOutcome::Allow => return Vec::new(),
        RuntimeTrustOutcome::AllowWithFindings => catalogue::SANDBOX_RUNTIME_TRUST_FINDINGS,
        RuntimeTrustOutcome::RequireAcceptance => {
            catalogue::SANDBOX_RUNTIME_TRUST_ACCEPTANCE_REQUIRED
        }
        RuntimeTrustOutcome::Deny => catalogue::SANDBOX_RUNTIME_TRUST_DENIED,
    };
    vec![definition.instantiate(context)]
}

fn integrity_finding(id: &str, rationale: &str) -> RuntimeTrustFinding {
    RuntimeTrustFinding {
        finding_id: id.to_owned(),
        status: "integrity_failure".to_owned(),
        vex_justification: None,
        rationale: rationale.to_owned(),
        non_overridable: true,
    }
}

fn valid_patch(patch: &str) -> bool {
    patch.len() == 10
        && patch.as_bytes()[4] == b'-'
        && patch.as_bytes()[7] == b'-'
        && patch
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn expression_true(expression: &str, facts: &BTreeMap<String, bool>) -> bool {
    expression
        .split("||")
        .any(|term| term.split("&&").all(|atom| atom_value(atom.trim(), facts)))
}

fn atom_value(atom: &str, facts: &BTreeMap<String, bool>) -> bool {
    let atom = atom.trim_matches(['(', ')', ' ']);
    if let Some(name) = atom.strip_prefix('!') {
        !facts.get(name.trim()).copied().unwrap_or(false)
    } else {
        facts.get(atom).copied().unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn facts() -> RuntimeTrustFacts {
        RuntimeTrustFacts {
            sandbox_tier: "sandbox.avd".to_owned(),
            security_patch: Some("2024-03-01".to_owned()),
            image_digest: "sha256:approved".to_owned(),
            expected_image_digest: "sha256:approved".to_owned(),
            image_signature_verified: false,
            image_signature_checked: false,
            containment_verified: true,
            adb_loopback_only: true,
            adb_key_authenticated: true,
            adb_ephemeral: true,
            policy_bundle_verified: true,
        }
    }

    #[test]
    fn old_patch_with_isolated_adb_is_allow_with_findings() {
        let decision = evaluate(facts(), &default_policy().unwrap(), None);
        assert_eq!(decision.outcome, RuntimeTrustOutcome::AllowWithFindings);
        assert!(
            decision
                .findings
                .iter()
                .any(|finding| finding.finding_id == "CVE-2026-0073"
                    && finding.status == "present_but_mitigated")
        );
    }

    #[test]
    fn reachable_risk_requires_scoped_acceptance() {
        let mut posture = facts();
        posture.adb_loopback_only = false;
        posture.adb_key_authenticated = false;
        posture.adb_ephemeral = false;
        let policy = default_policy().unwrap();
        let denied = evaluate(posture.clone(), &policy, None);
        assert_eq!(denied.outcome, RuntimeTrustOutcome::RequireAcceptance);
        let acceptance = RuntimeTrustAcceptance {
            finding_ids: BTreeSet::from(["CVE-2026-0073".to_owned()]),
            image_digest: posture.image_digest.clone(),
            profile: posture.sandbox_tier.clone(),
            reason: "isolated test host".to_owned(),
            threat_model: "ADB exposure is limited to this disposable host".to_owned(),
            user: "tester".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };
        let accepted = evaluate(posture, &policy, Some(&acceptance));
        assert_eq!(accepted.outcome, RuntimeTrustOutcome::AllowWithFindings);
    }

    #[test]
    fn integrity_failures_are_not_overridable_and_audit_is_append_only() {
        let mut posture = facts();
        posture.image_digest = "sha256:unexpected".to_owned();
        let decision = evaluate(posture.clone(), &default_policy().unwrap(), None);
        assert_eq!(decision.outcome, RuntimeTrustOutcome::Deny);
        let path = std::env::temp_dir().join(format!(
            "apiaxess-runtime-trust-{}.jsonl",
            std::process::id()
        ));
        let acceptance = RuntimeTrustAcceptance {
            finding_ids: BTreeSet::from(["integrity.image-digest-mismatch".to_owned()]),
            image_digest: posture.image_digest,
            profile: posture.sandbox_tier,
            reason: "test".to_owned(),
            threat_model: "test".to_owned(),
            user: "tester".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };
        assert!(append_acceptance_audit(&path, &acceptance, &decision).is_err());
        let _ = fs::remove_file(path);
    }
}
