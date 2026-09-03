# ADR 0001: Language and workload split

**Status:** accepted for 0.1

## Decision

Rust owns the core engine, analysis orchestration, future fusion/model logic,
plugin host, host-capability evaluation, sandbox coordination, and workbench
proxy core. The local GUI is TypeScript compiled to static web assets and served
by the Rust engine over a loopback API.

The Rust workspace is a set of narrow crates rather than a monolith. The GUI is
a separate package and may be rebuilt or replaced without linking to engine
internals.

## Pressure test

This split supports the two governing goals:

- Correctness: Rust makes concurrency, ownership, and untrusted-byte handling
  explicit in the trusted engine and high-throughput proxy path. Unsafe Rust is
  forbidden workspace-wide unless a future ADR narrows and justifies an exception.
- Expansion: target implementations, brains, tool adapters, sandbox backends,
  and the UI are all outside the core engine's dependency direction.
- Operations: one native process can own lifecycle, bind only to loopback, serve
  the GUI, and transparently manage optional runtimes.

The principal risks are a Rust-specific plugin ABI, UI/API drift, and placing
blocking external-tool work on async request threads. The layout counters them
with a plugin-host seam whose language boundary remains open, a versioned local
API, and a dedicated external-tool runtime. No material reason was found to
deviate from the intended Rust/TypeScript direction.

## Dependency rule

`apps/engine` is the composition root. Business orchestration belongs in
`crates/engine-shell`; transport in `crates/local-api`; interception/TLS in
`crates/workbench-proxy`; external process ownership in `crates/external-tools`.
The GUI and plugin implementations never become dependencies of the engine core.

