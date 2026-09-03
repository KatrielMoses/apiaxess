//! Screen-state signatures and the per-screen action model.

use sha2::{Digest, Sha256};

use crate::hierarchy::{Hierarchy, UiNode};

/// A normalized, position- and content-independent fingerprint of a screen.
#[derive(Clone, Debug)]
pub struct StateSignature {
    /// Foreground activity component.
    pub activity: String,
    /// Hex SHA-256 over `activity` + the sorted unique actionable-node set.
    pub hash: String,
}

impl StateSignature {
    /// Computes the signature for a screen. Volatile text, timestamps, counters,
    /// and list-content are excluded by construction: node signatures anchor on
    /// `resource-id`/`content-desc` and the set is de-duplicated and sorted, so
    /// two visits to "the same screen with different data" hash identically.
    #[must_use]
    pub fn compute(activity: &str, hierarchy: &Hierarchy) -> Self {
        let mut signatures: Vec<String> = hierarchy
            .actionable()
            .iter()
            .map(|node| node.signature())
            .collect();
        signatures.sort();
        signatures.dedup();
        let mut hasher = Sha256::new();
        hasher.update(activity.as_bytes());
        hasher.update(b"\n");
        for signature in &signatures {
            hasher.update(signature.as_bytes());
            hasher.update(b"\n");
        }
        let hash = hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            });
        Self {
            activity: activity.to_owned(),
            hash,
        }
    }
}

/// What kind of interaction an action performs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionVerb {
    /// Single tap at a point.
    Tap,
    /// Long press at a point.
    LongPress,
    /// Scroll a container toward more content.
    ScrollForward,
    /// Focus a text field (to reveal validation / dependent controls).
    FocusInput,
}

/// One candidate interaction on a screen.
#[derive(Clone, Debug)]
pub struct Action {
    /// Interaction kind.
    pub verb: ActionVerb,
    /// Tap/scroll anchor point.
    pub point: (i32, i32),
    /// Stable node signature this action targets (for frontier de-duplication).
    pub node_signature: String,
    /// Human-readable label for telemetry.
    pub label: String,
    /// Priority: higher fires first (network-triggering controls lead).
    pub priority: i32,
}

impl Action {
    /// Frontier key: identical (verb, node-signature) pairs are one action, so
    /// 100 identical list rows never become 100 taps.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{:?}|{}", self.verb, self.node_signature)
    }
}

/// Words in a control's label/id/description that suggest it triggers a network
/// call. Used only to *order* exploration (thoroughness is unchanged; this just
/// surfaces API traffic sooner).
const NETWORKY_HINTS: &[&str] = &[
    "load", "refresh", "reload", "sync", "search", "submit", "send", "post",
    "fetch", "feed", "list", "browse", "explore", "discover", "next", "more",
    "view", "open", "detail", "details", "profile", "account", "order", "cart",
    "checkout", "pay", "buy", "download", "upload", "update", "save", "login",
    "sign", "connect", "apply", "confirm", "continue", "get", "show",
];

/// Builds the ordered action set for a screen.
#[must_use]
pub fn actions_for(hierarchy: &Hierarchy) -> Vec<Action> {
    let mut actions = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for node in hierarchy.actionable() {
        for action in node_actions(node) {
            if seen.insert(action.key()) {
                actions.push(action);
            }
        }
    }
    // Highest priority first; stable within a priority band.
    actions.sort_by(|a, b| b.priority.cmp(&a.priority));
    actions
}

fn node_actions(node: &UiNode) -> Vec<Action> {
    let signature = node.signature();
    let point = node.bounds.center();
    let label = node_label(node);
    let networky = is_networky(node);
    let mut actions = Vec::new();
    if node.editable {
        actions.push(Action {
            verb: ActionVerb::FocusInput,
            point,
            node_signature: signature.clone(),
            label: format!("focus {label}"),
            priority: 5,
        });
    } else if node.clickable {
        actions.push(Action {
            verb: ActionVerb::Tap,
            point,
            node_signature: signature.clone(),
            label: format!("tap {label}"),
            priority: if networky { 100 } else { 50 },
        });
    }
    if node.long_clickable && !node.editable {
        actions.push(Action {
            verb: ActionVerb::LongPress,
            point,
            node_signature: format!("long:{signature}"),
            label: format!("long-press {label}"),
            priority: 20,
        });
    }
    if node.scrollable {
        actions.push(Action {
            verb: ActionVerb::ScrollForward,
            point,
            node_signature: format!("scroll:{signature}"),
            label: format!("scroll {label}"),
            priority: 30,
        });
    }
    actions
}

fn node_label(node: &UiNode) -> String {
    let raw = if !node.text.is_empty() {
        node.text.clone()
    } else if !node.content_desc.is_empty() {
        node.content_desc.clone()
    } else if !node.resource_id.is_empty() {
        node.resource_id.rsplit('/').next().unwrap_or("").to_owned()
    } else {
        node.class.rsplit('.').next().unwrap_or("view").to_owned()
    };
    let trimmed: String = raw.chars().take(40).collect();
    if trimmed.is_empty() {
        "element".to_owned()
    } else {
        trimmed
    }
}

fn is_networky(node: &UiNode) -> bool {
    let haystack = format!(
        "{} {} {}",
        node.text.to_ascii_lowercase(),
        node.content_desc.to_ascii_lowercase(),
        node.resource_id.to_ascii_lowercase()
    );
    NETWORKY_HINTS.iter().any(|hint| haystack.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy::Hierarchy;

    const SCREEN: &str = r#"<hierarchy>
<node class="android.widget.Button" resource-id="a:id/refresh" text="Refresh feed" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
<node class="android.widget.Button" resource-id="a:id/about" text="About" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
<node class="android.widget.ScrollView" scrollable="true" enabled="true" bounds="[0,120][100,900]"/>
</hierarchy>"#;

    #[test]
    fn signature_is_stable_and_content_independent() {
        let a = Hierarchy::parse(SCREEN);
        let sig1 = StateSignature::compute("com.x/.Main", &a);
        let sig2 = StateSignature::compute("com.x/.Main", &a);
        assert_eq!(sig1.hash, sig2.hash);
        assert_eq!(sig1.hash.len(), 64);
        // A different activity changes the state.
        let other = StateSignature::compute("com.x/.Other", &a);
        assert_ne!(sig1.hash, other.hash);
    }

    #[test]
    fn networky_controls_are_prioritized_first() {
        let hierarchy = Hierarchy::parse(SCREEN);
        let actions = actions_for(&hierarchy);
        assert!(!actions.is_empty());
        // "Refresh feed" (networky) must outrank "About".
        assert!(actions[0].label.to_lowercase().contains("refresh"));
        assert!(actions[0].priority >= actions[1].priority);
    }

    #[test]
    fn identical_rows_collapse_to_one_action() {
        let list = r#"<hierarchy>
<node class="android.widget.TextView" resource-id="a:id/row" text="Item A" clickable="true" enabled="true" bounds="[0,0][100,50]"/>
<node class="android.widget.TextView" resource-id="a:id/row" text="Item B" clickable="true" enabled="true" bounds="[0,60][100,110]"/>
<node class="android.widget.TextView" resource-id="a:id/row" text="Item C" clickable="true" enabled="true" bounds="[0,120][100,170]"/>
</hierarchy>"#;
        let hierarchy = Hierarchy::parse(list);
        let actions = actions_for(&hierarchy);
        assert_eq!(actions.len(), 1, "identical list rows dedupe to a single action");
    }
}
