//! Build wiring for the optional `frida-embedded` feature.
//!
//! When `frida-embedded` is enabled, the `frida-sys` crate emits
//! `cargo:rustc-link-lib=frida-core` and generates its bindings with `bindgen`.
//! Two things must be supplied by the build environment for that to link against
//! the bundled, pinned frida-core devkit (the one whose version matches the
//! device-side `frida-server` in `packaging/assets/frida.toml`, currently
//! 17.17.0), rather than frida-sys's default of the crate manifest directory:
//!
//! 1. The devkit directory (containing `frida-core.lib`/`libfrida-core.a`) must
//!    be on the linker search path. This script adds it, resolved from
//!    `APIAXESS_FRIDA_DEVKIT` (set by the Phase-12 packaging build after
//!    `fetch-frida.ps1` stages the devkit) — so the final link finds the pinned
//!    static library.
//! 2. `bindgen` (run inside `frida-sys`'s own build script, which executes
//!    before this one) must find `frida-core.h` and a working `libclang`. Those
//!    are provided by the build environment via `BINDGEN_EXTRA_CLANG_ARGS`
//!    (`-I<devkit>`) and `LIBCLANG_PATH`; a downstream build script cannot inject
//!    them into an already-run dependency build, so the packaging build sets them
//!    as environment variables. This script re-exports the devkit include hint on
//!    a rebuild so incremental builds stay consistent.
//!
//! With the feature off (the default workspace build), this script is inert: no
//! devkit, `libclang`, or network access is required.

use std::{env, path::PathBuf};

fn main() {
    // Only do anything when the linked-frida feature is actually enabled.
    if env::var_os("CARGO_FEATURE_FRIDA_EMBEDDED").is_none() {
        return;
    }

    println!("cargo:rerun-if-env-changed=APIAXESS_FRIDA_DEVKIT");

    let Some(devkit) = resolve_devkit() else {
        // Leave linking to frida-sys's defaults / the build environment. Emit a
        // warning so a devkit-less `frida-embedded` build fails with an
        // actionable message rather than an opaque linker error.
        println!(
            "cargo:warning=frida-embedded is enabled but APIAXESS_FRIDA_DEVKIT is not set; \
             the linker must otherwise be able to find frida-core (see packaging/assets/frida.toml)."
        );
        return;
    };

    // Add the pinned devkit to the link search so `-l frida-core` resolves to the
    // bundled static library that matches the device-side frida-server version.
    println!("cargo:rustc-link-search=native={}", devkit.display());
}

/// Resolves the bundled devkit directory from the packaging-provided override.
fn resolve_devkit() -> Option<PathBuf> {
    let configured = env::var_os("APIAXESS_FRIDA_DEVKIT")?;
    let path = PathBuf::from(configured);
    path.is_dir().then_some(path)
}
