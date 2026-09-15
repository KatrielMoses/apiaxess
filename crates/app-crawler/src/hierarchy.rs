//! Parsing of `uiautomator dump` view hierarchies into an actionable node set.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Pixel bounds of a node: `[x1,y1][x2,y2]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bounds {
    /// Left.
    pub x1: i32,
    /// Top.
    pub y1: i32,
    /// Right (exclusive).
    pub x2: i32,
    /// Bottom (exclusive).
    pub y2: i32,
}

impl Bounds {
    /// Center point, the tap target.
    #[must_use]
    pub fn center(&self) -> (i32, i32) {
        (
            i32::midpoint(self.x1, self.x2),
            i32::midpoint(self.y1, self.y2),
        )
    }

    /// Whether the node has positive area (a tappable region).
    #[must_use]
    pub fn is_tappable(&self) -> bool {
        self.x2 > self.x1 && self.y2 > self.y1
    }
}

/// One parsed view-hierarchy node.
#[derive(Clone, Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // Mirrors uiautomator's boolean node attributes 1:1.
pub struct UiNode {
    /// Stable index in the flat traversal order.
    pub index: usize,
    /// Nesting depth.
    pub depth: usize,
    /// Widget class, e.g. `android.widget.Button`.
    pub class: String,
    /// `resource-id`, when present.
    pub resource_id: String,
    /// Visible text.
    pub text: String,
    /// `content-desc` accessibility label.
    pub content_desc: String,
    /// Owning package.
    pub package: String,
    /// Directly clickable.
    pub clickable: bool,
    /// Long-clickable.
    pub long_clickable: bool,
    /// Scrollable container.
    pub scrollable: bool,
    /// Toggle/checkbox.
    pub checkable: bool,
    /// Accepts text input.
    pub editable: bool,
    /// Password field (masked input).
    pub password: bool,
    /// Enabled for interaction.
    pub enabled: bool,
    /// Focused.
    pub focused: bool,
    /// Screen bounds.
    pub bounds: Bounds,
}

impl UiNode {
    /// Whether the node is worth firing an action at (and is enabled).
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.enabled
            && self.bounds.is_tappable()
            && (self.clickable || self.long_clickable || self.scrollable || self.editable)
    }

    /// A stable, position-independent signature of this node's identity, used to
    /// build the state signature. Volatile text is included only for controls
    /// whose label defines their function (buttons), not for content rows.
    #[must_use]
    pub fn signature(&self) -> String {
        let role = if self.editable {
            "edit"
        } else if self.scrollable {
            "scroll"
        } else if self.clickable {
            "click"
        } else if self.long_clickable {
            "long"
        } else {
            "node"
        };
        // resource-id is the most stable identity; fall back to content-desc,
        // then to a short, stable slice of the label for id-less buttons.
        let identity = if !self.resource_id.is_empty() {
            self.resource_id.clone()
        } else if !self.content_desc.is_empty() {
            self.content_desc.clone()
        } else if self.clickable && !self.text.is_empty() && self.text.len() <= 24 {
            self.text.clone()
        } else {
            String::new()
        };
        format!("{role}|{}|{identity}", self.class)
    }
}

/// A parsed hierarchy: the actionable nodes plus the package that owns the root.
#[derive(Clone, Debug, Default)]
pub struct Hierarchy {
    /// Every parsed node in traversal order.
    pub nodes: Vec<UiNode>,
    /// The foreground package, inferred from the topmost node with a package.
    pub package: Option<String>,
}

impl Hierarchy {
    /// Parses a `uiautomator dump` XML document. Never fails hard: a malformed
    /// or truncated dump yields whatever nodes parsed cleanly.
    #[must_use]
    pub fn parse(xml: &str) -> Self {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(false);
        let mut nodes = Vec::new();
        let mut depth = 0_usize;
        let mut package = None;
        loop {
            match reader.read_event() {
                Ok(Event::Start(element)) if element.name().as_ref() == b"node" => {
                    let node = parse_node(&element, depth, nodes.len());
                    if package.is_none() && !node.package.is_empty() {
                        package = Some(node.package.clone());
                    }
                    nodes.push(node);
                    depth += 1;
                }
                Ok(Event::Empty(element)) if element.name().as_ref() == b"node" => {
                    let node = parse_node(&element, depth, nodes.len());
                    if package.is_none() && !node.package.is_empty() {
                        package = Some(node.package.clone());
                    }
                    nodes.push(node);
                }
                Ok(Event::End(element)) if element.name().as_ref() == b"node" => {
                    depth = depth.saturating_sub(1);
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
        }
        Self { nodes, package }
    }

    /// The actionable nodes in traversal order.
    #[must_use]
    pub fn actionable(&self) -> Vec<&UiNode> {
        self.nodes
            .iter()
            .filter(|node| node.is_actionable())
            .collect()
    }
}

fn parse_node(element: &quick_xml::events::BytesStart<'_>, depth: usize, index: usize) -> UiNode {
    let mut node = UiNode {
        index,
        depth,
        enabled: true,
        ..UiNode::default()
    };
    for attribute in element.attributes().flatten() {
        let raw = String::from_utf8_lossy(&attribute.value);
        let value = quick_xml::escape::unescape(&raw)
            .map_or_else(|_| raw.clone().into_owned(), std::borrow::Cow::into_owned);
        match attribute.key.as_ref() {
            b"class" => node.class = value,
            b"resource-id" => node.resource_id = value,
            b"text" => node.text = value,
            b"content-desc" => node.content_desc = value,
            b"package" => node.package = value,
            b"clickable" => node.clickable = value == "true",
            b"long-clickable" => node.long_clickable = value == "true",
            b"scrollable" => node.scrollable = value == "true",
            b"checkable" => node.checkable = value == "true",
            b"password" => node.password = value == "true",
            b"enabled" => node.enabled = value == "true",
            b"focused" => node.focused = value == "true",
            b"bounds" => node.bounds = parse_bounds(&value),
            _ => {}
        }
    }
    // An EditText (or any password field) accepts text input.
    if node.class.contains("EditText") || node.password {
        node.editable = true;
    }
    node
}

/// Parses `[x1,y1][x2,y2]` into [`Bounds`]. Returns a zero box on malformed input.
fn parse_bounds(value: &str) -> Bounds {
    let mut numbers = value
        .split(|c: char| !c.is_ascii_digit() && c != '-')
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.parse::<i32>().ok());
    Bounds {
        x1: numbers.next().unwrap_or(0),
        y1: numbers.next().unwrap_or(0),
        x2: numbers.next().unwrap_or(0),
        y2: numbers.next().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version='1.0' encoding='UTF-8'?>
<hierarchy rotation="0">
  <node index="0" class="android.widget.FrameLayout" package="com.example.app" bounds="[0,0][1080,1920]">
    <node index="0" resource-id="com.example.app:id/title" class="android.widget.TextView" text="Home" clickable="false" bounds="[0,0][1080,100]"/>
    <node index="1" resource-id="com.example.app:id/login" class="android.widget.Button" text="Sign in" clickable="true" enabled="true" bounds="[40,200][300,280]"/>
    <node index="2" resource-id="com.example.app:id/user" class="android.widget.EditText" text="" clickable="true" enabled="true" bounds="[40,300][1040,360]"/>
    <node index="3" class="android.widget.ScrollView" scrollable="true" bounds="[0,400][1080,1900]"/>
  </node>
</hierarchy>"#;

    #[test]
    fn parses_actionable_nodes_and_package() {
        let hierarchy = Hierarchy::parse(SAMPLE);
        assert_eq!(hierarchy.package.as_deref(), Some("com.example.app"));
        let actionable = hierarchy.actionable();
        // login button, edit text, scroll view (the title TextView is not actionable).
        assert_eq!(actionable.len(), 3);
        let button = actionable
            .iter()
            .find(|node| node.resource_id.ends_with("login"))
            .unwrap();
        assert_eq!(button.bounds.center(), (170, 240));
        assert!(button.clickable);
        let edit = actionable.iter().find(|node| node.editable).unwrap();
        assert!(edit.class.contains("EditText"));
    }

    #[test]
    fn bounds_parse_is_robust_to_malformed_input() {
        assert_eq!(
            parse_bounds("[10,20][30,40]"),
            Bounds {
                x1: 10,
                y1: 20,
                x2: 30,
                y2: 40
            }
        );
        assert_eq!(parse_bounds("garbage"), Bounds::default());
    }

    #[test]
    fn signature_prefers_resource_id_and_is_stable_across_volatile_text() {
        let mut a = UiNode {
            resource_id: "com.x:id/go".to_owned(),
            class: "android.widget.Button".to_owned(),
            text: "Buy (3)".to_owned(),
            clickable: true,
            enabled: true,
            bounds: Bounds {
                x1: 0,
                y1: 0,
                x2: 10,
                y2: 10,
            },
            ..UiNode::default()
        };
        let sig_a = a.signature();
        a.text = "Buy (7)".to_owned();
        assert_eq!(
            sig_a,
            a.signature(),
            "resource-id anchored signature ignores volatile text"
        );
    }
}
