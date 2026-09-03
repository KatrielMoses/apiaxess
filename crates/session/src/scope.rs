//! Declared engagement scope and deterministic advisory assessment.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{invariant, validate_nonempty, validate_stable_key};
use apiaxess_diagnostics::Diagnostic;

/// One stable identifier for the session target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetIdentifier {
    /// Identifier vocabulary, such as `artifact.sha256` or `android.package`.
    pub kind: String,
    /// Exact identifier value as declared by the user or artifact importer.
    pub value: String,
}

impl TargetIdentifier {
    fn validate(&self, path: &str) -> Result<(), Diagnostic> {
        validate_stable_key(&format!("{path}.kind"), &self.kind)?;
        validate_nonempty(&format!("{path}.value"), &self.value)
    }
}

/// Target identity that remains extensible across `APK`, web, executable, and package targets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetIdentity {
    /// Stable target-type interface ID, such as `apk`, `web`, `exe`, or `deb`.
    pub target_type: String,
    /// Identity used as the primary session key, preferably a content digest.
    pub primary: TargetIdentifier,
    /// Additional identities, such as an Android package name.
    pub aliases: Vec<TargetIdentifier>,
}

impl TargetIdentity {
    /// Validates target type and unique identifier kinds.
    ///
    /// # Errors
    ///
    /// Returns a canonical invariant diagnostic for malformed or duplicate identifiers.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        validate_stable_key("engagement_scope.target.target_type", &self.target_type)?;
        self.primary.validate("engagement_scope.target.primary")?;
        let mut kinds = BTreeSet::from([self.primary.kind.as_str()]);
        for (index, alias) in self.aliases.iter().enumerate() {
            alias.validate(&format!("engagement_scope.target.aliases[{index}]"))?;
            if !kinds.insert(&alias.kind) {
                return Err(invariant(
                    &format!("engagement_scope.target.aliases[{index}].kind"),
                    "identifier kinds must be unique within a target identity",
                ));
            }
        }
        Ok(())
    }
}

/// Host matching semantics for one allowed network target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostMatch {
    /// Match only this normalized host name or IP literal.
    Exact {
        /// Lowercase DNS name or IP literal.
        host: String,
    },
    /// Match a DNS domain and any label-boundary subdomain below it.
    DomainSuffix {
        /// Lowercase ASCII DNS suffix without a leading dot.
        domain: String,
    },
}

impl HostMatch {
    fn validate(&self, path: &str) -> Result<(), Diagnostic> {
        let value = match self {
            Self::Exact { host } => host,
            Self::DomainSuffix { domain } => domain,
        };
        validate_host(path, value)
    }

    fn matches(&self, candidate: &str) -> bool {
        match self {
            Self::Exact { host } => candidate == host,
            Self::DomainSuffix { domain } => {
                candidate == domain
                    || candidate
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// One named allowed-target rule in an engagement declaration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AllowedNetworkTarget {
    /// Stable rule ID retained by historical audit records.
    pub id: String,
    /// Host or domain matching rule.
    pub host: HostMatch,
    /// Allowed ports; an empty set means all ports on the matched host.
    pub ports: Vec<u16>,
}

impl AllowedNetworkTarget {
    fn validate(&self, index: usize) -> Result<(), Diagnostic> {
        validate_stable_key(
            &format!("engagement_scope.allowed_targets[{index}].id"),
            &self.id,
        )?;
        self.host
            .validate(&format!("engagement_scope.allowed_targets[{index}].host"))?;
        let mut ports = BTreeSet::new();
        for port in &self.ports {
            if *port == 0 || !ports.insert(*port) {
                return Err(invariant(
                    &format!("engagement_scope.allowed_targets[{index}].ports"),
                    "ports must be non-zero and unique",
                ));
            }
        }
        Ok(())
    }

    fn matches(&self, host: &str, port: Option<u16>) -> bool {
        self.host.matches(host)
            && (self.ports.is_empty() || port.is_some_and(|value| self.ports.contains(&value)))
    }
}

/// User-declared, session-scoped authorization record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EngagementScope {
    /// Time at which the scope was declared.
    pub declared_at: DateTime<Utc>,
    /// Target identity covered by the engagement.
    pub target: TargetIdentity,
    /// Network hosts/domains the target is authorized to exercise.
    pub allowed_targets: Vec<AllowedNetworkTarget>,
}

impl EngagementScope {
    /// Validates target identity and unique allowed-target rules.
    ///
    /// # Errors
    ///
    /// Returns a canonical invariant diagnostic for malformed target or rule data.
    pub fn validate(&self) -> Result<(), Diagnostic> {
        self.target.validate()?;
        let mut ids = BTreeSet::new();
        for (index, target) in self.allowed_targets.iter().enumerate() {
            target.validate(index)?;
            if !ids.insert(&target.id) {
                return Err(invariant(
                    &format!("engagement_scope.allowed_targets[{index}].id"),
                    "allowed-target rule IDs must be unique",
                ));
            }
        }
        Ok(())
    }

    /// Assesses an action target without granting, denying, or blocking it.
    #[must_use]
    pub fn assess(&self, target: &ActionTarget) -> ScopeAssessment {
        match target {
            ActionTarget::SessionTarget => ScopeAssessment {
                disposition: ScopeDisposition::InScope,
                matched_rule_id: None,
                explanation: "the action addresses the session's declared target".to_owned(),
            },
            ActionTarget::Network { host, port } => {
                let Some(normalized) = normalize_host(host) else {
                    return ScopeAssessment {
                        disposition: ScopeDisposition::Undetermined,
                        matched_rule_id: None,
                        explanation: "the network host is empty or not normalized as a host"
                            .to_owned(),
                    };
                };
                if let Some(rule) = self
                    .allowed_targets
                    .iter()
                    .find(|rule| rule.matches(&normalized, *port))
                {
                    ScopeAssessment {
                        disposition: ScopeDisposition::InScope,
                        matched_rule_id: Some(rule.id.clone()),
                        explanation: "the network target matches a declared allowed-target rule"
                            .to_owned(),
                    }
                } else {
                    ScopeAssessment {
                        disposition: ScopeDisposition::OutsideDeclaredScope,
                        matched_rule_id: None,
                        explanation:
                            "no declared allowed-target rule matches the network host and port"
                                .to_owned(),
                    }
                }
            }
            ActionTarget::Unresolved { .. } => ScopeAssessment {
                disposition: ScopeDisposition::Undetermined,
                matched_rule_id: None,
                explanation: "the action target has no comparable network or session identity"
                    .to_owned(),
            },
            ActionTarget::NotApplicable => ScopeAssessment {
                disposition: ScopeDisposition::NotApplicable,
                matched_rule_id: None,
                explanation: "the action does not address an engagement target".to_owned(),
            },
        }
    }
}

/// Target recorded for an attempted action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionTarget {
    /// The declared artifact/application itself.
    SessionTarget,
    /// A network endpoint contacted by or on behalf of the session target.
    Network {
        /// Host name or IP literal.
        host: String,
        /// Known destination port, if available.
        port: Option<u16>,
    },
    /// A target vocabulary not yet understood by the scope assessor.
    Unresolved {
        /// Stable target vocabulary.
        target_type: String,
        /// Exact recorded identity.
        value: String,
    },
    /// An action, such as local serialization, with no engagement target.
    NotApplicable,
}

/// Persisted result of comparing one action target to the declared scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDisposition {
    /// The action matches the declared target or an allowed-target rule.
    InScope,
    /// A concrete target does not match any declared rule.
    OutsideDeclaredScope,
    /// The target lacks enough identity to make a reliable decision.
    Undetermined,
    /// The action has no engagement target.
    NotApplicable,
}

/// Complete, durable advisory scope decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopeAssessment {
    /// Recorded scope disposition.
    pub disposition: ScopeDisposition,
    /// Stable allowed-target rule that matched, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,
    /// Human-readable reasoning retained for audit review.
    pub explanation: String,
}

fn normalize_host(value: &str) -> Option<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.chars().any(char::is_whitespace)
        || normalized.contains("//")
        || normalized.contains('/')
    {
        None
    } else {
        Some(normalized)
    }
}

fn validate_host(path: &str, value: &str) -> Result<(), Diagnostic> {
    match normalize_host(value) {
        Some(normalized) if normalized == value => Ok(()),
        _ => Err(invariant(
            path,
            "host must be normalized lowercase ASCII without a scheme, path, whitespace, or trailing dot",
        )),
    }
}
