//! Session-scoped state, engagement records, and durable persistence.
//!
//! A session owns one declared target/scope, the canonical phase 0.2 API model,
//! an append-only action audit trail, and an opaque slot reserved for the future
//! workbench schema. Scope assessment is advisory by design: outside-scope work
//! is warned and recorded, never blocked by this crate.

mod audit;
mod document;
mod scope;
mod session;

pub use audit::{ActionDescriptor, ActionOutcome, ActionRecordInput, AuditActor, AuditRecord};
pub use document::{CURRENT_SESSION_FORMAT_VERSION, SessionDocument};
pub use scope::{
    ActionTarget, AllowedNetworkTarget, EngagementScope, HostMatch, ScopeAssessment,
    ScopeDisposition, TargetIdentifier, TargetIdentity,
};
pub use session::{
    AnalysisPipelineState, CURRENT_SESSION_CHECKPOINT_FORMAT_VERSION, SandboxHandle, Session,
    SessionCheckpoint, SessionId, SessionLifecycle, WorkbenchStateSlot,
};

use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue, catalogue::SESSION_INVARIANT_FAILED,
};

pub(crate) fn invariant(path: &str, reason: impl Into<String>) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert("path".to_owned(), DiagnosticValue::String(path.to_owned()));
    context.insert("reason".to_owned(), DiagnosticValue::String(reason.into()));
    SESSION_INVARIANT_FAILED.instantiate(context)
}

pub(crate) fn validate_stable_key(path: &str, value: &str) -> Result<(), Diagnostic> {
    let valid = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b':')
        })
        && value.bytes().any(|byte| byte.is_ascii_lowercase());
    if valid {
        Ok(())
    } else {
        Err(invariant(
            path,
            "must contain lowercase ASCII segments separated only by '.', '-', '_', or ':'",
        ))
    }
}

pub(crate) fn validate_nonempty(path: &str, value: &str) -> Result<(), Diagnostic> {
    if value.trim().is_empty() {
        Err(invariant(path, "must not be empty"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
