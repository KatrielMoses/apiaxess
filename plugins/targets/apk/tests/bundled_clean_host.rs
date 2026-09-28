//! Clean-host proof for Phase 11.1: a real APK unpacks and decompiles using
//! only the bundled Java runtime + bundled apktool + bundled jadx, resolved by
//! absolute path, with nothing required on the host.
//!
//! This exercises the exact resolution the installed product uses
//! (`resolve_from_resource_base`), against a staged install tree, so it doubles
//! as the APK intake+unpack+decompile path the hardening host could not run
//! (that host had no apktool).
//!
//! Gated by `APIAXESS_BUNDLED_VERIFY=1` because it needs the staged runtime,
//! which is produced by the packaging fetch step (or, in development, by the
//! `docs/testing/phase-11.1-bundled-jre-clean-host.md` procedure). The bundled
//! Java tools are launched by absolute path and consult neither `PATH` nor
//! `JAVA_HOME`, so a passing run demonstrates host-independent intake.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use apiaxess_external_tools::ProcessToolRunner;
use apiaxess_target_apk::{ApkIntakeConfig, ApkTarget, resolve_from_resource_base};

const VERIFY_ENV: &str = "APIAXESS_BUNDLED_VERIFY";
const DEFAULT_BASE: &str = "target/verify-install";

fn workspace_root() -> PathBuf {
    // plugins/targets/apk -> repository root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root above plugins/targets/apk")
        .to_path_buf()
}

fn enabled(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok("1" | "true" | "yes"))
}

#[test]
fn real_apk_unpacks_and_decompiles_on_bundled_runtime() {
    if !enabled(VERIFY_ENV) {
        apiaxess_test_fixtures::skip(
            "bundled_clean_host::real_apk_unpacks_and_decompiles_on_bundled_runtime",
            format_args!("set {VERIFY_ENV}=1 to run the bundled clean-host verification"),
        );
        return;
    }
    let root = workspace_root();
    let base = std::env::var_os("APIAXESS_BUNDLED_BASE")
        .map_or_else(|| root.join(DEFAULT_BASE), PathBuf::from);
    let Some(fixture) = apiaxess_test_fixtures::capstone_apk(
        "bundled_clean_host::real_apk_unpacks_and_decompiles_on_bundled_runtime",
        &["APIAXESS_BUNDLED_APK"],
    ) else {
        return;
    };

    assert!(
        base.join("tools")
            .join("apktool")
            .join("apktool.jar")
            .is_file(),
        "staged apktool jar missing under {}; run the packaging fetch step first",
        base.display()
    );

    let tools = resolve_from_resource_base(&base);
    // The bundled toolchain must resolve every Java tool to the one bundled
    // runtime by absolute path.
    assert!(
        Path::new(&tools.apktool.executable).is_absolute(),
        "apktool must run through an absolute-path Java runtime, got {:?}",
        tools.apktool.executable
    );
    assert_eq!(
        tools.apktool.executable, tools.jadx.executable,
        "apktool and jadx must share the one bundled Java runtime"
    );
    assert!(
        !tools.bundled_components.is_empty(),
        "bundled components must be tracked for install-integrity checks"
    );

    let output_root = root.join("target").join("bundled-verify-out");
    let _ = std::fs::remove_dir_all(&output_root);
    let config = ApkIntakeConfig {
        output_root,
        tool_timeout: Duration::from_secs(900),
        tools,
    };
    let target = ApkTarget::new(Arc::new(ProcessToolRunner), config);

    let artifact = target
        .intake(&fixture)
        .unwrap_or_else(|failure| panic!("bundled intake failed: {}", failure.diagnostic));

    // apktool authoritative output: at least one smali root and a manifest.
    let smali_roots: usize = artifact
        .structural_outputs
        .iter()
        .map(|output| output.smali_roots.len())
        .sum();
    assert!(
        smali_roots > 0,
        "apktool produced no smali roots on the bundled runtime"
    );
    for output in &artifact.structural_outputs {
        assert!(
            Path::new(&output.manifest).is_file(),
            "apktool manifest missing for {}",
            output.apk_id
        );
    }

    // jadx convenience source tree: at least one decompiled .java file.
    let java_files: usize = artifact
        .decompiled_source_roots
        .iter()
        .map(|source_root| count_java_files(Path::new(source_root)))
        .sum();
    assert!(
        java_files > 0,
        "jadx produced no decompiled sources on the bundled runtime"
    );

    // DEX access must have been established from the same resolved APK set.
    assert!(
        !artifact.dex_access.dex_files.is_empty(),
        "no DEX files were materialized"
    );

    eprintln!(
        "bundled clean-host intake OK: format={:?} smali_roots={} java_files={} dex_files={}",
        artifact.input_format,
        smali_roots,
        java_files,
        artifact.dex_access.dex_files.len()
    );

    target
        .cleanup(&artifact)
        .expect("intake workspace cleanup succeeds");
}

fn count_java_files(root: &Path) -> usize {
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(path) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "java") {
                count += 1;
            }
        }
    }
    count
}
