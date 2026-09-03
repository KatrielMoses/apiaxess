//! Append-only action audit records with persisted scope assessment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{ActionTarget, ScopeAssessment, validate_nonempty, validate_stable_key};
use apiaxess_diagnostics::Diagnostic;

/// Actor responsible for an audited action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditActor {
    /// Direct user action.
    User,
    /// `APIaxess` engine action.
    Engine,
    /// Action requested by a negotiated plugin.
    Plugin {
        /// Stable plugin package ID.
        plugin_id: String,
    },
    /// Action performed through an external-tool adapter.
    ExternalTool {
        /// Stable external-tool adapter ID.
        tool_id: String,
    },
}

/// Stable action kind plus display summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    /// Stable machine action kind, such as `session.serialize`.
    pub kind: String,
    /// Human-readable occurrence summary; diagnostics remain structured separately.
    pub summary: String,
}

/// Recorded outcome of one action attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcome {
    /// The action completed as requested.
    Completed,
    /// The action failed with one or more structured diagnostics.
    Failed,
    /// The action was cancelled before completion.
    Cancelled,
}

/// Caller-supplied action facts before scope assessment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRecordInput {
    /// Stable event ID unique within the session.
    pub id: String,
    /// Time the outcome was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Responsible actor.
    pub actor: AuditActor,
    /// Stable action identity and summary.
    pub action: ActionDescriptor,
    /// Concrete target used for advisory scope assessment.
    pub target: ActionTarget,
    /// Completed, failed, or cancelled result.
    pub outcome: ActionOutcome,
    /// Structured operational diagnostics, excluding automatic scope warnings.
    pub diagnostics: Vec<Diagnostic>,
}

/// Append-only action record persisted with the session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Stable event ID unique within the session.
    pub id: String,
    /// Time the outcome was recorded.
    pub occurred_at: DateTime<Utc>,
    /// Responsible actor.
    pub actor: AuditActor,
    /// Stable action identity and display summary.
    pub action: ActionDescriptor,
    /// Recorded action target.
    pub target: ActionTarget,
    /// Scope decision made at record time.
    pub scope: ScopeAssessment,
    /// Completed, failed, or cancelled result.
    pub outcome: ActionOutcome,
    /// Operational diagnostics and automatic scope warnings.
    pub diagnostics: Vec<Diagnostic>,
}

impl AuditRecord {
    pub(crate) fn validate(&self, index: usize) -> Result<(), Diagnostic> {
        validate_stable_key(&format!("audit_trail[{index}].id"), &self.id)?;
        validate_stable_key(
            &format!("audit_trail[{index}].action.kind"),
            &self.action.kind,
        )?;
        validate_nonempty(
            &format!("audit_trail[{index}].action.summary"),
            &self.action.summary,
        )?;
        validate_nonempty(
            &format!("audit_trail[{index}].scope.explanation"),
            &self.scope.explanation,
        )?;
        match &self.actor {
            AuditActor::Plugin { plugin_id } => {
                validate_stable_key(&format!("audit_trail[{index}].actor.plugin_id"), plugin_id)?;
            }
            AuditActor::ExternalTool { tool_id } => {
                validate_stable_key(&format!("audit_trail[{index}].actor.tool_id"), tool_id)?;
            }
            AuditActor::User | AuditActor::Engine => {}
        }
        for diagnostic in &self.diagnostics {
            diagnostic.validate().map_err(|error| {
                crate::invariant(
                    &format!("audit_trail[{index}].diagnostics"),
                    error.to_string(),
                )
            })?;
        }
        Ok(())
    }
}
