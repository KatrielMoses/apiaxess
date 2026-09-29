//! Resolution of the bundled, host-independent Android toolchain.
//!
//! `APIaxess` owns and ships its Java runtime, apktool, and jadx exactly the way
//! it already ships Chromium: as private application components discovered by
//! absolute path relative to the installed executable, never as host
//! prerequisites found on `PATH`. This module turns the install layout into the
//! concrete launch recipes the intake pipeline invokes.
//!
//! Both Java tools are driven through the one bundled runtime:
//!
//! * apktool  -> `<runtime>/bin/java -jar <tools>/apktool/apktool.jar ...`
//! * jadx     -> `<runtime>/bin/java <jvm-opts> -cp <tools>/jadx/lib/*-all.jar
//!   jadx.cli.JadxCLI ...`
//!
//! The jadx path mirrors the vendored `bin/jadx` launcher (same entrypoint and
//! the JVM options that matter for correctness) rather than reimplementing the
//! decompiler, so it stays faithful to the tool while binding it to the bundled
//! runtime instead of a host JVM.
//!
//! Operator overrides (`APIAXESS_JAVA`, `APIAXESS_APKTOOL`, `APIAXESS_JADX`)
//! remain available as advanced escapes, but the default requires nothing on the
//! host.

use std::{
    env,
    path::{Path, PathBuf},
};

use super::{ApkToolchainConfig, ToolLaunch};

/// JVM options mirrored from the jadx launcher so direct invocation behaves
/// like the vendored `bin/jadx` script. `IgnoreUnrecognizedVMOptions` keeps the
/// set forward-compatible across runtime versions; the zip64 validation switch
/// is the correctness-relevant flag jadx sets to read certain APK archives.
const JADX_JVM_OPTIONS: &[&str] = &[
    "-XX:+IgnoreUnrecognizedVMOptions",
    "-Djdk.util.zip.disableZip64ExtraFieldValidation=true",
    "--enable-native-access=ALL-UNNAMED",
    "-XX:MaxRAMPercentage=70.0",
];

/// jadx CLI entrypoint on the classpath.
const JADX_MAIN_CLASS: &str = "jadx.cli.JadxCLI";

/// A component `APIaxess` bundles and owns, checked for presence before intake so
/// a corrupt or incomplete install surfaces as one clear install-integrity
/// diagnostic instead of a silent failure deep in the pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundledComponent {
    /// Stable component label used in the diagnostic context.
    pub label: &'static str,
    /// Absolute path whose absence is an install-integrity failure.
    pub path: PathBuf,
}

/// Resolves the toolchain from the installed executable location.
///
/// This never fails: when the installation cannot be located or a component is
/// absent, the returned configuration still names the expected paths so the
/// intake preflight can report exactly which bundled component is missing.
#[must_use]
pub fn resolve_default_toolchain() -> ApkToolchainConfig {
    resolve_from_resource_base(&resource_base())
}

/// Resolves the toolchain from an explicit resource base (the directory that
/// contains `runtime/` and `tools/`). Used by the clean-host verification test
/// to point at a staged install tree without relying on the executable path.
#[must_use]
pub fn resolve_from_resource_base(base: &Path) -> ApkToolchainConfig {
    let mut config = ApkToolchainConfig::minimums();

    // The one shared runtime. An explicit override makes the runtime a host
    // responsibility and removes it from the install-integrity checks.
    let java_override = env::var_os("APIAXESS_JAVA").map(PathBuf::from);
    let bundled_java = base
        .join("runtime")
        .join("java")
        .join(platform_dir())
        .join("bin")
        .join(java_executable_name());
    let java = java_override
        .clone()
        .unwrap_or_else(|| bundled_java.clone());
    let java_display = java.display().to_string();

    let mut components = Vec::new();

    // apktool: `java -jar apktool.jar`, unless overridden.
    let apktool_jar = base.join("tools").join("apktool").join("apktool.jar");
    config.apktool = if let Some(value) = env::var_os("APIAXESS_APKTOOL") {
        override_launch(&PathBuf::from(value), &java_display, ClasspathMode::Jar)
    } else {
        components.push(BundledComponent {
            label: "apktool",
            path: apktool_jar.clone(),
        });
        ToolLaunch {
            executable: java_display.clone(),
            launch_prefix: vec!["-jar".to_owned(), apktool_jar.display().to_string()],
        }
    };

    // jadx: `java <jvm-opts> -cp <all-jar> jadx.cli.JadxCLI`, unless overridden.
    let jadx_lib = base.join("tools").join("jadx").join("lib");
    let jadx_jar = resolve_jadx_all_jar(&jadx_lib);
    config.jadx = if let Some(value) = env::var_os("APIAXESS_JADX") {
        override_launch(
            &PathBuf::from(value),
            &java_display,
            ClasspathMode::JadxClasspath,
        )
    } else {
        components.push(BundledComponent {
            label: "jadx",
            // When the all-jar cannot be located the directory is named so the
            // integrity error points at the component, not a guess.
            path: jadx_jar.clone().unwrap_or_else(|| jadx_lib.clone()),
        });
        let mut prefix: Vec<String> = JADX_JVM_OPTIONS
            .iter()
            .map(|opt| (*opt).to_owned())
            .collect();
        prefix.push("-cp".to_owned());
        prefix.push(
            jadx_jar
                .unwrap_or_else(|| jadx_lib.join("jadx-all.jar"))
                .display()
                .to_string(),
        );
        prefix.push(JADX_MAIN_CLASS.to_owned());
        ToolLaunch {
            executable: java_display.clone(),
            launch_prefix: prefix,
        }
    };

    // bundletool is only reached for the AAB branch and is not bundled in this
    // sub-phase; it keeps its established override-or-PATH behavior so the AAB
    // route does not silently change.
    config.bundletool = match env::var_os("APIAXESS_BUNDLETOOL") {
        Some(value) => ToolLaunch::command(PathBuf::from(value).display().to_string()),
        None => ToolLaunch::command("bundletool"),
    };

    // The shared runtime is an install-integrity component only when it is
    // actually referenced: if both tools were overridden to self-contained host
    // launchers, the bundled runtime is unused and must not be required. A `.jar`
    // override still routes through it, so this checks real usage, not overrides.
    if java_override.is_none()
        && (config.apktool.executable == java_display || config.jadx.executable == java_display)
    {
        components.insert(
            0,
            BundledComponent {
                label: "java-runtime",
                path: bundled_java,
            },
        );
    }

    config.bundled_components = components;
    config
}

/// How an operator override should be launched when it is a jar rather than a
/// self-contained executable.
#[derive(Clone, Copy)]
enum ClasspathMode {
    /// Run as `java -jar <value>`.
    Jar,
    /// Run as `java <jvm-opts> -cp <value> jadx.cli.JadxCLI`.
    JadxClasspath,
}

/// Builds a launch recipe for an operator override. A `.jar` value is run
/// through the resolved Java runtime; anything else is treated as a
/// self-contained launcher that locates its own JVM.
fn override_launch(value: &Path, java_display: &str, mode: ClasspathMode) -> ToolLaunch {
    let is_jar = value
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jar"));
    if !is_jar {
        return ToolLaunch::command(value.display().to_string());
    }
    match mode {
        ClasspathMode::Jar => ToolLaunch {
            executable: java_display.to_owned(),
            launch_prefix: vec!["-jar".to_owned(), value.display().to_string()],
        },
        ClasspathMode::JadxClasspath => {
            let mut prefix: Vec<String> = JADX_JVM_OPTIONS
                .iter()
                .map(|opt| (*opt).to_owned())
                .collect();
            prefix.push("-cp".to_owned());
            prefix.push(value.display().to_string());
            prefix.push(JADX_MAIN_CLASS.to_owned());
            ToolLaunch {
                executable: java_display.to_owned(),
                launch_prefix: prefix,
            }
        }
    }
}

/// Locates the jadx all-in-one jar (`*-all.jar`) inside the distribution's
/// `lib` directory. Matching by suffix keeps the resolver working across jadx
/// version bumps without a code change.
fn resolve_jadx_all_jar(lib: &Path) -> Option<PathBuf> {
    let mut matches: Vec<PathBuf> = std::fs::read_dir(lib)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    let lower = name.to_ascii_lowercase();
                    lower.ends_with("-all.jar") && lower.contains("jadx")
                })
        })
        .collect();
    matches.sort();
    matches.into_iter().next_back()
}

/// The directory holding `runtime/` and `tools/`, relative to the installed
/// executable (the shared install layout: beside `bin/` on Windows, in the
/// `.app`'s `Resources/` on macOS, under `share/apiaxess/` on Linux).
fn resource_base() -> PathBuf {
    // current_exe should not fail on supported platforms; fall back to the
    // working directory so the preflight still reports concrete paths.
    apiaxess_install_layout::resource_base().unwrap_or_else(|| PathBuf::from("."))
}

/// The per-platform directory under `runtime/java/` that the Java runtime
/// fetch stages for this host.
fn platform_dir() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn java_executable_name() -> &'static str {
    if cfg!(windows) { "java.exe" } else { "java" }
}
