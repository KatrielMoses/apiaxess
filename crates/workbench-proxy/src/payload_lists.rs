//! Bundled predefined payload lists ("Add from list").
//!
//! Per "necessity has no dependency", `APIaxess` ships its own small curated
//! pack rather than fetching lists at runtime. Each list is compiled into the
//! binary via `include_str!`, so the feature always works — in development, in
//! tests, and in a stripped install — with no install-integrity failure mode.
//!
//! For operator extension and inspection, the same files are also staged into
//! the install tree under `<resource base>/payloads/`, and an operator may point
//! `APIAXESS_PAYLOADS` at their own directory of `<id>.txt` files. Resolution
//! prefers the operator override, then the install tree, then the embedded copy,
//! so a customized or updated pack wins while the embedded copy guarantees the
//! feature never simply disappears.

use std::{env, fs, path::PathBuf};

use apiaxess_diagnostics::{Diagnostic, DiagnosticContext, DiagnosticValue, catalogue};
use serde::Serialize;

use crate::bundled::resource_base;

/// A curated list bundled with the product.
struct BundledList {
    /// Stable identifier used by the API and the override filename (`<id>.txt`).
    id: &'static str,
    /// Human-readable label shown in the GUI.
    label: &'static str,
    /// Grouping category (fuzzing, usernames, passwords, discovery, injection).
    category: &'static str,
    /// The compiled-in copy, used when no override or install file is present.
    embedded: &'static str,
}

/// The curated pack. Small on purpose; operators extend it via the override dir.
const LISTS: &[BundledList] = &[
    BundledList {
        id: "fuzzing-quick",
        label: "Quick fuzzing strings",
        category: "fuzzing",
        embedded: include_str!("../assets/payloads/fuzzing-quick.txt"),
    },
    BundledList {
        id: "usernames-common",
        label: "Common usernames",
        category: "usernames",
        embedded: include_str!("../assets/payloads/usernames-common.txt"),
    },
    BundledList {
        id: "passwords-common",
        label: "Common passwords",
        category: "passwords",
        embedded: include_str!("../assets/payloads/passwords-common.txt"),
    },
    BundledList {
        id: "directories-common",
        label: "Common directories & API paths",
        category: "discovery",
        embedded: include_str!("../assets/payloads/directories-common.txt"),
    },
    BundledList {
        id: "xss-probes",
        label: "XSS probes",
        category: "injection",
        embedded: include_str!("../assets/payloads/xss-probes.txt"),
    },
    BundledList {
        id: "sqli-probes",
        label: "SQL injection probes",
        category: "injection",
        embedded: include_str!("../assets/payloads/sqli-probes.txt"),
    },
];

/// One bundled list as advertised to the GUI's "Add from list" picker.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadListInfo {
    /// Stable identifier passed back to fetch the list's values.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Grouping category.
    pub category: String,
    /// Number of usable values (comment and blank lines excluded).
    pub count: usize,
}

/// Enumerates the bundled payload lists with their resolved value counts.
#[must_use]
pub fn bundled_payload_lists() -> Vec<PayloadListInfo> {
    LISTS
        .iter()
        .map(|list| PayloadListInfo {
            id: list.id.to_owned(),
            label: list.label.to_owned(),
            category: list.category.to_owned(),
            count: parse_lines(&resolve_content(list)).len(),
        })
        .collect()
}

/// Reads one bundled list's values, comment (`#`) and blank lines removed.
///
/// # Errors
///
/// Returns a configuration diagnostic when `id` names no bundled list.
pub fn read_payload_list(id: &str) -> Result<Vec<String>, Diagnostic> {
    let list = LISTS
        .iter()
        .find(|list| list.id == id)
        .ok_or_else(|| unknown_list(id))?;
    Ok(parse_lines(&resolve_content(list)))
}

/// Resolves a list's raw text: operator override, then install tree, then the
/// embedded copy (which always succeeds).
fn resolve_content(list: &BundledList) -> String {
    let file = format!("{}.txt", list.id);
    if let Some(dir) = env::var_os("APIAXESS_PAYLOADS") {
        if let Ok(text) = fs::read_to_string(PathBuf::from(dir).join(&file)) {
            return text;
        }
    }
    if let Ok(text) = fs::read_to_string(resource_base().join("payloads").join(&file)) {
        return text;
    }
    list.embedded.to_owned()
}

/// Splits list text into usable values: trims each line and drops blank lines
/// and `#` comment lines, matching how the GUI loads a payload file.
fn parse_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn unknown_list(id: &str) -> Diagnostic {
    let mut context = DiagnosticContext::new();
    context.insert(
        "operation".to_owned(),
        DiagnosticValue::String("payload_list".to_owned()),
    );
    context.insert(
        "error".to_owned(),
        DiagnosticValue::String(format!("no bundled payload list '{id}'")),
    );
    catalogue::PROXY_FUZZER_CONFIG_INVALID.instantiate(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_lists_are_all_resolvable_and_non_empty() {
        // With no override and no install tree (the test environment), every list
        // must still resolve from its embedded copy.
        let lists = bundled_payload_lists();
        assert_eq!(lists.len(), LISTS.len());
        for info in &lists {
            assert!(info.count > 0, "{} is empty", info.id);
            let values = read_payload_list(&info.id).expect("list resolves");
            assert_eq!(values.len(), info.count);
        }
    }

    #[test]
    fn comment_and_blank_lines_are_stripped() {
        let values = read_payload_list("fuzzing-quick").expect("list resolves");
        assert!(values.iter().all(|value| !value.starts_with('#')));
        assert!(values.iter().all(|value| !value.is_empty()));
        // A representative payload survives.
        assert!(values.iter().any(|value| value == "../"));
    }

    #[test]
    fn unknown_list_is_a_diagnostic() {
        assert!(read_payload_list("does-not-exist").is_err());
    }
}
