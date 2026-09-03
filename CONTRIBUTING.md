# Contributing

The architecture records in `docs/architecture/` are normative. In particular:

1. Feature crates do not launch child processes. Add an adapter to
   `crates/external-tools` and call it through the tool-runner port.
2. Feature crates do not call Docker, a sandbox, or a remote execution host
   directly. They call the sandbox port in `crates/sandbox`.
3. The engine does not import a target implementation or brain implementation.
   It reaches them only through `crates/plugin-host`.
4. The GUI uses only the versioned loopback API. It never imports Rust-generated
   internals or reads engine storage directly.
5. A host-dependent feature declares its required capabilities before execution
   and presents an explicit unavailable/degraded result when requirements fail.
6. Feature actions are recorded through the session audit boundary with a scope
   assessment. An outside-scope warning is never repurposed as an enforcement claim.
7. Anticipated failures use a stable entry in the diagnostic catalogue with
   what/why/fix and typed context; GUI text and bare strings are not error models.

Run `cargo xtask boundaries`, `cargo xtask contracts`, and
`cargo xtask foundations` before submitting a change.

Windows builds use the Rust toolchain's bundled `rust-lld.exe` linker for the
MSVC target. Dev and test profiles keep line tables (`debug = 1`) for source
stepping and backtraces without generating the much larger full-variable PDBs;
release packaging profiles are unchanged. Use Cargo's normal parallel build
jobs on Windows; the former serial-build environment override is not required.
