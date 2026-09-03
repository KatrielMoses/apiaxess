//! Engine-facing plugin-host seam.
//!
//! The canonical language-neutral contract is under `contracts/plugin`. This
//! crate will own tier adapters and must remain the only route from the engine to
//! implementations. It deliberately does not redefine the contract as public
//! Rust traits or structs.

use apiaxess_diagnostics::{
    Diagnostic, DiagnosticContext, DiagnosticValue, catalogue::PLUGIN_PERMISSION_DENIED,
};

/// Host-side record of a permission rejected during plugin negotiation or use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionDenial {
    /// Stable plugin package ID.
    pub plugin_id: String,
    /// Stable permission ID from the language-neutral contract.
    pub permission_id: String,
    /// Requested permission scope rendered for audit review.
    pub requested_scope: String,
    /// Exact reason the grant was absent or insufficient.
    pub reason: String,
    /// Exact user action that can resolve the denial.
    pub remediation: String,
}

impl PermissionDenial {
    /// Converts the denial into the canonical plugin-capability diagnostic.
    #[must_use]
    pub fn to_diagnostic(&self) -> Diagnostic {
        let mut context = DiagnosticContext::new();
        context.insert(
            "plugin_id".to_owned(),
            DiagnosticValue::String(self.plugin_id.clone()),
        );
        context.insert(
            "permission_id".to_owned(),
            DiagnosticValue::String(self.permission_id.clone()),
        );
        context.insert(
            "requested_scope".to_owned(),
            DiagnosticValue::String(self.requested_scope.clone()),
        );
        let mut diagnostic = PLUGIN_PERMISSION_DENIED.instantiate(context);
        diagnostic.why = format!(
            "Plugin `{}` requires `{}` for `{}`: {}",
            self.plugin_id, self.permission_id, self.requested_scope, self.reason
        )
        .into_boxed_str();
        diagnostic.fix = if self.remediation.trim().is_empty() {
            "Grant the named permission with the requested scope or choose a plugin that does not require it."
                .into()
        } else {
            self.remediation.clone().into_boxed_str()
        };
        diagnostic
    }
}

/// Placeholder plugin-host facade. Runtime adapters remain out of scope in 0.3.
#[derive(Debug, Default)]
pub struct PluginHost {
    _private: (),
}

impl PluginHost {
    /// Creates an empty phase 0.1 host.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

#[cfg(test)]
mod tests {
    use super::PermissionDenial;
    use apiaxess_diagnostics::catalogue::PLUGIN_PERMISSION_DENIED;

    #[test]
    fn permission_denial_names_plugin_permission_scope_and_fix() {
        let denial = PermissionDenial {
            plugin_id: "community.frida-helper".to_owned(),
            permission_id: "instrumentation.frida.attach".to_owned(),
            requested_scope: "device:emulator-5554".to_owned(),
            reason: "the user did not grant device attach".to_owned(),
            remediation: "Grant attach access to emulator-5554 and retry initialization."
                .to_owned(),
        };
        let diagnostic = denial.to_diagnostic();

        assert_eq!(diagnostic.id.as_ref(), PLUGIN_PERMISSION_DENIED.id);
        assert_eq!(diagnostic.fix.as_ref(), denial.remediation);
        assert!(diagnostic.why.contains("instrumentation.frida.attach"));
    }
}
