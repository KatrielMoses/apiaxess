//! Repository-local policy checks and release tooling.

mod release_signing;

use std::{collections::HashSet, env, error::Error, fs, path::Path};

use syn::{Expr, ExprCall, ExprMacro, ExprMethodCall, Item, ItemUse, UseTree, visit::Visit};

const COMMAND_METHODS: &[&str] = &["new", "spawn", "status", "output", "wait", "kill"];
const POPEN_METHODS: &[&str] = &["create", "create_child"];
const KNOWN_PROCESS_MODULES: &[&[&str]] = &[
    &["std", "process"],
    &["tokio", "process"],
    &["async_process"],
    &["async_process", "process"],
    &["command_group"],
];

fn main() -> Result<(), Box<dyn Error>> {
    let command = env::args().nth(1).unwrap_or_default();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask must remain directly below the workspace root")?;

    match command.as_str() {
        "boundaries" => check_boundaries(root),
        "contracts" => check_contracts(root),
        "foundations" => check_foundations(root),
        "update-keygen" => release_signing::keygen(&env::args().skip(2).collect::<Vec<_>>()),
        "sign-manifest" => release_signing::sign(&env::args().skip(2).collect::<Vec<_>>()),
        _ => Err(
            "usage: cargo xtask <boundaries|contracts|foundations|update-keygen|sign-manifest>"
                .into(),
        ),
    }
}

fn check_foundations(root: &Path) -> Result<(), Box<dyn Error>> {
    let required_files = [
        "crates/diagnostics/src/lib.rs",
        "crates/session/src/scope.rs",
        "crates/session/src/audit.rs",
        "crates/session/src/session.rs",
        "crates/session/src/document.rs",
        "docs/diagnostics/catalogue.md",
        "docs/architecture/0008-session-diagnostics-and-scope.md",
    ];
    let diagnostic_ids = [
        "scope.outside-declaration",
        "scope.assessment-undetermined",
        "host-capability.requirement-unsatisfied",
        "plugin-capability.permission-denied",
        "session.invalid-transition",
        "session.invariant-failed",
        "session.api-model-invalid",
        "persistence.session-format-unsupported",
        "persistence.session-json-invalid",
        "persistence.session-unknown-fields",
    ];
    let mut violations = Vec::new();
    for relative in required_files {
        if !root.join(relative).is_file() {
            violations.push(format!("missing phase 0.4 foundation `{relative}`"));
        }
    }

    let catalogue_source = fs::read_to_string(root.join("crates/diagnostics/src/lib.rs"))?;
    let catalogue_docs = fs::read_to_string(root.join("docs/diagnostics/catalogue.md"))?;
    for diagnostic_id in diagnostic_ids {
        if !catalogue_source.contains(diagnostic_id) {
            violations.push(format!("diagnostic catalogue code omits `{diagnostic_id}`"));
        }
        if !catalogue_docs.contains(diagnostic_id) {
            violations.push(format!(
                "diagnostic catalogue documentation omits `{diagnostic_id}`"
            ));
        }
    }

    let session_source = fs::read_to_string(root.join("crates/session/src/session.rs"))?;
    for owned_field in [
        "engagement_scope: EngagementScope",
        "api_document: ApiDocument",
        "audit_trail: Vec<AuditRecord>",
        "workbench_state: Option<WorkbenchStateSlot>",
    ] {
        if !session_source.contains(owned_field) {
            violations.push(format!("canonical session omits `{owned_field}`"));
        }
    }
    let document_source = fs::read_to_string(root.join("crates/session/src/document.rs"))?;
    for persistence_rule in [
        "CURRENT_SESSION_FORMAT_VERSION",
        "collect_extra_fields",
        "self.session.validate()?",
    ] {
        if !document_source.contains(persistence_rule) {
            violations.push(format!("session persistence omits `{persistence_rule}`"));
        }
    }

    if violations.is_empty() {
        println!(
            "foundation check passed: scope, diagnostics, session, and persistence are canonical"
        );
        Ok(())
    } else {
        for violation in &violations {
            eprintln!("{violation}");
        }
        Err(format!("{} phase 0.4 foundation violation(s)", violations.len()).into())
    }
}

fn check_boundaries(root: &Path) -> Result<(), Box<dyn Error>> {
    let allowed = root.join("crates/external-tools");
    let mut violations = Vec::new();

    for source_root in [root.join("apps"), root.join("crates"), root.join("plugins")] {
        inspect_tree(&source_root, &allowed, &mut violations)?;
    }

    if violations.is_empty() {
        println!("boundary check passed: child-process ownership is isolated");
        Ok(())
    } else {
        for violation in &violations {
            eprintln!("{violation}");
        }
        Err(format!("{} architecture boundary violation(s)", violations.len()).into())
    }
}

fn check_contracts(root: &Path) -> Result<(), Box<dyn Error>> {
    let contract_root = root.join("contracts/plugin");
    let required_files = [
        "apiaxess/plugin/v1/common.proto",
        "apiaxess/plugin/v1/capabilities.proto",
        "apiaxess/plugin/v1/handshake.proto",
        "apiaxess/plugin/discovery_brain/v1/discovery_brain.proto",
        "apiaxess/plugin/target_type/v1/target_type.proto",
        "apiaxess/plugin/protocol_decoder/v1/protocol_decoder.proto",
        "apiaxess/plugin/artifact_generator/v1/artifact_generator.proto",
        "apiaxess/plugin/pinning_bypass/v1/pinning_bypass.proto",
        "apiaxess/plugin/instrumentation_orchestrator/v1/instrumentation_orchestrator.proto",
    ];
    let mut violations = Vec::new();
    for relative in required_files {
        if !contract_root.join(relative).is_file() {
            violations.push(format!("missing required plugin contract `{relative}`"));
        }
    }

    let registry = fs::read_to_string(contract_root.join("INTERFACES.md"))?;
    for interface_id in [
        "apiaxess.discovery-brain",
        "apiaxess.target-type",
        "apiaxess.protocol-decoder",
        "apiaxess.artifact-generator",
        "apiaxess.pinning-bypass",
        "apiaxess.instrumentation-orchestrator",
    ] {
        if !registry.contains(interface_id) {
            violations.push(format!("interface registry omits `{interface_id}`"));
        }
    }

    let mut proto_files = Vec::new();
    collect_files(&contract_root, "proto", &mut proto_files)?;
    for path in proto_files {
        let source = fs::read_to_string(&path)?;
        if !source.starts_with("syntax = \"proto3\";") {
            violations.push(format!("{} is not canonical proto3", path.display()));
        }
        if !source.contains("package apiaxess.plugin") {
            violations.push(format!(
                "{} is outside the canonical package",
                path.display()
            ));
        }
        let services = source.matches("service ").count();
        let service_gates = source.matches("service_evolution").count();
        if services > service_gates {
            violations.push(format!(
                "{} has an ungated service declaration",
                path.display()
            ));
        }
        let methods = source.matches("  rpc ").count();
        let method_gates = source.matches("method_evolution").count();
        if methods > method_gates {
            violations.push(format!("{} has an ungated RPC method", path.display()));
        }
        for (line_number, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("bytes ") && !trimmed.contains("sha256") {
                violations.push(format!(
                    "{}:{} embeds bytes instead of using an artifact/stream reference",
                    path.display(),
                    line_number + 1
                ));
            }
            if trimmed.starts_with("required ") {
                violations.push(format!(
                    "{}:{} uses a non-additive required field",
                    path.display(),
                    line_number + 1
                ));
            }
        }
    }

    if violations.is_empty() {
        println!("contract check passed: one gated, reference-based plugin IDL");
        Ok(())
    } else {
        for violation in &violations {
            eprintln!("{violation}");
        }
        Err(format!("{} plugin contract violation(s)", violations.len()).into())
    }
}

fn collect_files(
    directory: &Path,
    extension: &str,
    files: &mut Vec<std::path::PathBuf>,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, extension, files)?;
        } else if path.extension().is_some_and(|found| found == extension) {
            files.push(path);
        }
    }
    Ok(())
}

fn inspect_tree(
    directory: &Path,
    allowed: &Path,
    violations: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    if !directory.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            inspect_tree(&path, allowed, violations)?;
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && !path.starts_with(allowed)
        {
            let source = fs::read_to_string(&path)?;
            violations.extend(inspect_source(&path, &source)?);
        }
    }

    Ok(())
}

fn inspect_source(path: &Path, source: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let syntax = syn::parse_file(source).map_err(|error| {
        format!(
            "{} could not be parsed for process-boundary inspection: {error}",
            path.display()
        )
    })?;
    let mut inspector = ProcessInspector::new(path);
    inspector.collect_imports(&syntax.items);
    inspector.visit_file(&syntax);
    Ok(inspector.violations)
}

struct ProcessInspector<'a> {
    path: &'a Path,
    command_names: HashSet<String>,
    command_modules: HashSet<String>,
    popen_names: HashSet<String>,
    command_group_names: HashSet<String>,
    command_variables: HashSet<String>,
    violations: Vec<String>,
}

impl<'a> ProcessInspector<'a> {
    fn new(path: &'a Path) -> Self {
        Self {
            path,
            command_names: HashSet::new(),
            command_modules: HashSet::new(),
            popen_names: HashSet::new(),
            command_group_names: HashSet::new(),
            command_variables: HashSet::new(),
            violations: Vec::new(),
        }
    }

    fn collect_imports(&mut self, items: &[Item]) {
        for item in items {
            if let Item::Use(item_use) = item {
                self.collect_use(item_use);
            }
        }
    }

    fn collect_use(&mut self, item_use: &ItemUse) {
        let mut leaves = Vec::new();
        collect_use_leaves(&item_use.tree, &mut Vec::new(), &mut leaves);
        for (full_path, local_name) in leaves {
            if full_path.last().is_some_and(|segment| segment == "Command") {
                let parent = &full_path[..full_path.len() - 1];
                if is_known_process_module(parent, &self.command_modules)
                    || parent.last().is_some_and(|segment| segment == "process")
                {
                    self.command_names.insert(local_name);
                }
            } else if is_known_process_module(&full_path, &self.command_modules) {
                self.command_modules.insert(local_name);
            } else if full_path.last().is_some_and(|segment| segment == "Popen") {
                self.popen_names.insert(local_name);
            } else if full_path
                .last()
                .is_some_and(|segment| segment == "CommandGroup")
            {
                self.command_group_names.insert(local_name);
            }
        }
    }

    fn report(&mut self, construct: &str) {
        self.violations.push(format!(
            "{} uses process execution `{construct}` outside crates/external-tools",
            self.path.display()
        ));
    }

    fn is_command_constructor(&self, path: &[String]) -> bool {
        let Some(method) = path.last() else {
            return false;
        };
        if !COMMAND_METHODS.contains(&method.as_str()) || path.len() < 2 {
            return false;
        }
        let type_name = &path[path.len() - 2];
        if !self.command_names.contains(type_name) && type_name != "Command" {
            return false;
        }
        let parent = &path[..path.len() - 2];
        parent.is_empty()
            || is_known_process_module(parent, &self.command_modules)
            || parent.last().is_some_and(|segment| {
                self.command_modules.contains(segment) || segment == "process"
            })
    }

    fn is_popen_constructor(&self, path: &[String]) -> bool {
        let Some(method) = path.last() else {
            return false;
        };
        let Some(type_name) = path.get(path.len().saturating_sub(2)) else {
            return false;
        };
        POPEN_METHODS.contains(&method.as_str())
            && (self.popen_names.contains(type_name) || type_name == "Popen")
    }

    fn is_command_group_constructor(&self, path: &[String]) -> bool {
        path.last().is_some_and(|method| method == "new")
            && path
                .get(path.len().saturating_sub(2))
                .is_some_and(|type_name| {
                    self.command_group_names.contains(type_name) || type_name == "CommandGroup"
                })
    }
}

impl Visit<'_> for ProcessInspector<'_> {
    fn visit_expr_call(&mut self, expression: &ExprCall) {
        if let Expr::Path(function) = expression.func.as_ref() {
            let path = path_segments(&function.path);
            if self.is_command_constructor(&path)
                || self.is_popen_constructor(&path)
                || self.is_command_group_constructor(&path)
            {
                self.report(&path.join("::"));
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_macro(&mut self, expression: &ExprMacro) {
        let path = path_segments(&expression.mac.path);
        if path.first().is_some_and(|segment| segment == "duct")
            && path.last().is_some_and(|segment| segment == "cmd")
        {
            self.report(&path.join("::"));
        }
        syn::visit::visit_expr_macro(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &ExprMethodCall) {
        let method = expression.method.to_string();
        if ["spawn", "status", "output", "wait", "kill"].contains(&method.as_str())
            && matches!(expression.receiver.as_ref(), Expr::Path(path) if path.path.segments.len() == 1
                && self.command_variables.contains(&path.path.segments[0].ident.to_string()))
        {
            self.report(&format!("Command::{method}"));
        }
        syn::visit::visit_expr_method_call(self, expression);
    }

    fn visit_local(&mut self, local: &syn::Local) {
        if let syn::Pat::Ident(pattern) = &local.pat
            && local
                .init
                .as_ref()
                .and_then(|init| match init.expr.as_ref() {
                    Expr::Call(call) => call.func.as_ref().as_expr_path(),
                    _ => None,
                })
                .is_some_and(|path| self.is_command_constructor(&path_segments(path)))
        {
            self.command_variables.insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, local);
    }
}

trait ExprPathExt {
    fn as_expr_path(&self) -> Option<&syn::Path>;
}

impl ExprPathExt for Expr {
    fn as_expr_path(&self) -> Option<&syn::Path> {
        match self {
            Self::Path(path) => Some(&path.path),
            _ => None,
        }
    }
}

fn path_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn collect_use_leaves(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    leaves: &mut Vec<(Vec<String>, String)>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_leaves(&path.tree, prefix, leaves);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let mut full_path = prefix.clone();
            full_path.push(name.ident.to_string());
            leaves.push((full_path, name.ident.to_string()));
        }
        UseTree::Rename(rename) => {
            let mut full_path = prefix.clone();
            full_path.push(rename.ident.to_string());
            leaves.push((full_path, rename.rename.to_string()));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_leaves(item, prefix, leaves);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn is_known_process_module(path: &[String], aliases: &HashSet<String>) -> bool {
    KNOWN_PROCESS_MODULES.iter().any(|known| {
        known.len() == path.len()
            && known
                .iter()
                .zip(path)
                .all(|(expected, found)| expected == found)
    }) || (path.len() == 1 && aliases.contains(&path[0]))
}

#[cfg(test)]
mod tests {
    use super::{check_boundaries, check_contracts, check_foundations, inspect_source};
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn comments_and_strings_do_not_trigger_process_boundary_detection() {
        let source = r#"
            // std::process::Command::new("comment-only")
            /// Hidden ffuf subprocess documentation.
            const TEXT: &str = "tokio::process::Command::new(\"string-only\")";
        "#;
        let violations = inspect_source(Path::new("fixture.rs"), source).expect("parsed");
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn genuine_aliased_and_reexported_process_execution_is_detected() {
        let source = r#"
            use std::process::Command as SpawnCommand;
            pub use std::process::Command as ReexportedCommand;

            fn wrapped() {
                let command = SpawnCommand::new("tool");
                let _ = command.spawn();
            }

            fn through_reexport() {
                let _ = ReexportedCommand::new("tool").status();
            }
        "#;
        let violations = inspect_source(Path::new("fixture.rs"), source).expect("parsed");
        assert!(
            violations.len() >= 2,
            "expected process violations: {violations:?}"
        );
    }

    #[test]
    fn boundary_check_rejects_a_real_out_of_boundary_process_execution() {
        let root = std::env::temp_dir().join(format!(
            "apiaxess-boundary-fixture-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let source_path = root.join("crates/bad/src/lib.rs");
        fs::create_dir_all(source_path.parent().expect("parent")).expect("fixture directory");
        fs::write(
            &source_path,
            "use std::process::Command; pub fn breach() { let _ = Command::new(\"tool\"); }",
        )
        .expect("fixture source");

        let result = check_boundaries(&root);
        assert!(result.is_err(), "real process execution was not rejected");
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn current_workspace_boundary_check_is_green() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        check_boundaries(root).expect("current workspace boundary check");
    }

    #[test]
    fn canonical_plugin_contract_passes_repository_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        check_contracts(root).unwrap();
    }

    #[test]
    fn phase_0_4_foundations_pass_repository_policy() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        check_foundations(root).unwrap();
    }
}
