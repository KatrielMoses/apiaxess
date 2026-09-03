//! Robustness heuristics: dialog handling and login/OTP detection.

use crate::credentials::{CredentialField, CredentialKind, CredentialPromptReason, CredentialRequest};
use crate::hierarchy::{Hierarchy, UiNode};

/// A dialog button the crawler should press to keep making progress.
#[derive(Clone, Debug)]
pub struct DialogAction {
    /// Tap point.
    pub point: (i32, i32),
    /// Human-readable description for telemetry.
    pub label: String,
    /// Whether this is a permission grant (vs. an onboarding/rate/crash dismiss).
    pub is_permission: bool,
}

/// Buttons that advance permission/consent dialogs (press to proceed).
const ALLOW_LABELS: &[&str] = &[
    "allow", "allow all the time", "while using the app", "only this time",
    "accept", "accept all", "agree", "i agree", "ok", "okay", "got it",
    "continue", "grant", "yes", "enable", "turn on", "next", "done",
];

/// Buttons that dismiss onboarding/update/rate/crash dialogs.
const DISMISS_LABELS: &[&str] = &[
    "not now", "later", "maybe later", "no thanks", "no, thanks", "skip",
    "skip for now", "dismiss", "close", "cancel", "deny", "don't allow",
    "remind me later", "no",
];

/// Android system permission-dialog button resource-ids.
const PERMISSION_ALLOW_IDS: &[&str] = &[
    "permission_allow_button",
    "permission_allow_foreground_only_button",
    "permission_allow_one_time_button",
    "button1",
];

/// Finds a dialog button to press. Prefers a permission-allow (keep traffic
/// flowing), then a positive/continue button, then a dismiss button for
/// nuisance dialogs. Returns `None` when no dialog-like control is present.
#[must_use]
pub fn classify_dialog(hierarchy: &Hierarchy) -> Option<DialogAction> {
    let actionable = hierarchy.actionable();
    // 1. System permission dialog by resource-id.
    for node in &actionable {
        let id = node.resource_id.rsplit('/').next().unwrap_or("");
        if PERMISSION_ALLOW_IDS.contains(&id) && node.clickable {
            return Some(DialogAction {
                point: node.bounds.center(),
                label: format!("grant permission ({})", node_text(node)),
                is_permission: true,
            });
        }
    }
    // 2. Positive/allow button by label.
    if let Some(node) = actionable
        .iter()
        .find(|node| node.clickable && label_matches(node, ALLOW_LABELS))
    {
        let permission = looks_like_permission(hierarchy);
        return Some(DialogAction {
            point: node.bounds.center(),
            label: format!("confirm dialog ({})", node_text(node)),
            is_permission: permission,
        });
    }
    // 3. Dismiss button for nuisance dialogs (only when the screen is dialog-shaped).
    if is_dialog_shaped(hierarchy) {
        if let Some(node) = actionable
            .iter()
            .find(|node| node.clickable && label_matches(node, DISMISS_LABELS))
        {
            return Some(DialogAction {
                point: node.bounds.center(),
                label: format!("dismiss dialog ({})", node_text(node)),
                is_permission: false,
            });
        }
    }
    None
}

/// Button/link labels that advance a sign-in — including phone/OTP flows whose
/// primary action is "Get OTP" / "Send code" rather than a literal "Login".
pub const SIGN_IN_AFFORDANCES: &[&str] = &[
    "login",
    "log in",
    "sign in",
    "signin",
    "continue",
    "next",
    "submit",
    "get otp",
    "send otp",
    "request otp",
    "get code",
    "send code",
    "verify",
    "proceed",
    "get started",
    "sign up",
];

/// Detects a sign-in gate and describes the credential fields to fill.
///
/// A screen is treated as a login gate when it exposes at least one text field
/// and either a password field or a sign-in affordance. This intentionally also
/// matches registration screens — the operator can still choose to supply
/// values or continue without.
#[must_use]
pub fn detect_login(hierarchy: &Hierarchy, package: &str, activity: &str) -> Option<CredentialRequest> {
    let editables: Vec<&UiNode> = hierarchy
        .nodes
        .iter()
        .filter(|node| node.editable && node.enabled && node.bounds.is_tappable())
        .collect();
    if editables.is_empty() {
        return None;
    }
    let has_password = editables.iter().any(|node| node.password);
    let has_signin_affordance = hierarchy.actionable().iter().any(|node| {
        node.clickable && label_matches(node, SIGN_IN_AFFORDANCES)
    });
    // A login/OTP/auth-named activity with an input field is a login gate even
    // when its submit button is disabled until valid input (so it isn't yet a
    // clickable affordance) — the common phone-number → "Get OTP" pattern.
    let activity_lc = activity.to_ascii_lowercase();
    let activity_is_auth = ["login", "signin", "sign_in", "sign-in", "otp", "auth", "register"]
        .iter()
        .any(|needle| activity_lc.contains(needle));
    if !has_password && !has_signin_affordance && !activity_is_auth {
        return None;
    }
    let fields = editables
        .iter()
        .enumerate()
        .map(|(index, node)| field_from_node(node, index))
        .collect::<Vec<_>>();
    let hints = fields
        .iter()
        .map(|field| field.label.clone())
        .collect::<Vec<_>>()
        .join(", ");
    Some(CredentialRequest {
        package: package.to_owned(),
        screen_summary: format!("{activity} — fields: {hints}"),
        fields,
        reason: CredentialPromptReason::LoginGate,
    })
}

/// Detects an OTP/verification-code gate: an enabled text field whose identity
/// signals a one-time code, with no password field present.
#[must_use]
pub fn detect_otp(hierarchy: &Hierarchy, package: &str, activity: &str) -> Option<CredentialRequest> {
    let otp_node = hierarchy.nodes.iter().find(|node| {
        node.editable && node.enabled && node.bounds.is_tappable() && infer_kind(node) == CredentialKind::Otp
    })?;
    // If a password field is present it is a login gate, not an OTP gate.
    if hierarchy.nodes.iter().any(|node| node.editable && node.password) {
        return None;
    }
    let field = field_from_node(otp_node, 0);
    Some(CredentialRequest {
        package: package.to_owned(),
        screen_summary: format!("{activity} — one-time code: {}", field.label),
        fields: vec![field],
        reason: CredentialPromptReason::Otp,
    })
}

/// Builds a [`CredentialField`] describing one input for the operator.
#[must_use]
pub fn field_from_node(node: &UiNode, index: usize) -> CredentialField {
    let kind = infer_kind(node);
    let name = if node.resource_id.is_empty() {
        format!("field-{index}")
    } else {
        node.resource_id.clone()
    };
    let label = field_label(node);
    CredentialField {
        name,
        label,
        kind,
        secret: kind.is_sensitive(),
    }
}

fn field_label(node: &UiNode) -> String {
    let raw = if !node.content_desc.is_empty() {
        node.content_desc.clone()
    } else if !node.text.is_empty() && !node.password {
        node.text.clone()
    } else if !node.resource_id.is_empty() {
        node.resource_id.rsplit('/').next().unwrap_or("field").to_owned()
    } else {
        "field".to_owned()
    };
    let trimmed: String = raw.chars().take(48).collect();
    if trimmed.is_empty() {
        "field".to_owned()
    } else {
        trimmed
    }
}

/// Infers the semantic kind of an input field from its identity.
#[must_use]
pub fn infer_kind(node: &UiNode) -> CredentialKind {
    if node.password {
        // Distinguish a numeric PIN from a password by id/hint.
        if identity_contains(node, &["pin"]) {
            return CredentialKind::Pin;
        }
        return CredentialKind::Password;
    }
    if identity_contains(node, &["otp", "one-time", "one time", "verification", "verify", "2fa", "code"]) {
        return CredentialKind::Otp;
    }
    if identity_contains(node, &["email", "e-mail"]) {
        return CredentialKind::Email;
    }
    if identity_contains(node, &["phone", "mobile", "tel"]) {
        return CredentialKind::Phone;
    }
    if identity_contains(node, &["pin"]) {
        return CredentialKind::Pin;
    }
    if identity_contains(node, &["pass", "pwd"]) {
        return CredentialKind::Password;
    }
    if identity_contains(node, &["user", "login", "account", "handle", "name"]) {
        return CredentialKind::Username;
    }
    CredentialKind::Generic
}

fn identity_contains(node: &UiNode, needles: &[&str]) -> bool {
    let haystack = format!(
        "{} {} {} {}",
        node.resource_id.to_ascii_lowercase(),
        node.content_desc.to_ascii_lowercase(),
        node.text.to_ascii_lowercase(),
        node.class.to_ascii_lowercase()
    );
    needles.iter().any(|needle| haystack.contains(needle))
}

fn label_matches(node: &UiNode, labels: &[&str]) -> bool {
    let text = node_text(node).to_ascii_lowercase();
    let text = text.trim();
    labels.iter().any(|label| text == *label || text.starts_with(label))
}

fn node_text(node: &UiNode) -> String {
    if node.text.is_empty() {
        node.content_desc.clone()
    } else {
        node.text.clone()
    }
}

/// A screen is "dialog-shaped" when it has few actionable elements — the mark of
/// a modal rather than a full app view — so we don't dismiss real UI as a dialog.
fn is_dialog_shaped(hierarchy: &Hierarchy) -> bool {
    hierarchy.actionable().len() <= 4
}

fn looks_like_permission(hierarchy: &Hierarchy) -> bool {
    hierarchy.nodes.iter().any(|node| {
        node.package.contains("permissioncontroller")
            || node.package.contains("packageinstaller")
            || node.resource_id.contains("permission")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_system_permission_dialog() {
        let xml = r#"<hierarchy>
<node package="com.android.permissioncontroller" resource-id="com.android.permissioncontroller:id/permission_allow_button" class="android.widget.Button" text="Allow" clickable="true" enabled="true" bounds="[500,900][700,980]"/>
<node package="com.android.permissioncontroller" resource-id="com.android.permissioncontroller:id/permission_deny_button" class="android.widget.Button" text="Deny" clickable="true" enabled="true" bounds="[300,900][480,980]"/>
</hierarchy>"#;
        let dialog = classify_dialog(&Hierarchy::parse(xml)).expect("permission dialog");
        assert!(dialog.is_permission);
        assert_eq!(dialog.point, (600, 940));
    }

    #[test]
    fn dismisses_rate_us_dialog() {
        let xml = r#"<hierarchy>
<node class="android.widget.TextView" text="Rate this app!" bounds="[0,0][100,50]"/>
<node class="android.widget.Button" text="Rate now" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
<node class="android.widget.Button" text="No thanks" clickable="true" enabled="true" bounds="[0,120][100,170]"/>
</hierarchy>"#;
        // "Rate now" is not in ALLOW; the dismiss path picks "No thanks".
        let dialog = classify_dialog(&Hierarchy::parse(xml)).expect("dismiss");
        assert!(!dialog.is_permission);
        assert!(dialog.label.to_lowercase().contains("no thanks"));
    }

    #[test]
    fn detects_login_screen_with_password() {
        let xml = r#"<hierarchy>
<node resource-id="com.x:id/username" class="android.widget.EditText" content-desc="Username" clickable="true" enabled="true" bounds="[0,100][100,150]"/>
<node resource-id="com.x:id/password" class="android.widget.EditText" password="true" clickable="true" enabled="true" bounds="[0,200][100,250]"/>
<node resource-id="com.x:id/go" class="android.widget.Button" text="Sign in" clickable="true" enabled="true" bounds="[0,300][100,350]"/>
</hierarchy>"#;
        let request = detect_login(&Hierarchy::parse(xml), "com.x", "com.x/.Login").expect("login");
        assert_eq!(request.fields.len(), 2);
        assert_eq!(request.fields[0].kind, CredentialKind::Username);
        assert_eq!(request.fields[1].kind, CredentialKind::Password);
        assert!(request.fields[1].secret);
    }

    #[test]
    fn detects_otp_screen() {
        let xml = r#"<hierarchy>
<node resource-id="com.x:id/otp" class="android.widget.EditText" content-desc="Verification code" clickable="true" enabled="true" bounds="[0,100][100,150]"/>
<node resource-id="com.x:id/verify" class="android.widget.Button" text="Verify" clickable="true" enabled="true" bounds="[0,200][100,250]"/>
</hierarchy>"#;
        let request = detect_otp(&Hierarchy::parse(xml), "com.x", "com.x/.Otp").expect("otp");
        assert_eq!(request.reason, CredentialPromptReason::Otp);
        assert_eq!(request.fields[0].kind, CredentialKind::Otp);
    }

    #[test]
    fn plain_screen_is_not_a_login() {
        let xml = r#"<hierarchy>
<node class="android.widget.Button" text="Home" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
</hierarchy>"#;
        assert!(detect_login(&Hierarchy::parse(xml), "com.x", "act").is_none());
    }
}
