# Open decisions

## OD-001: Plugin language boundary — resolved

**Decision:** ADR 0007 adopts one Protobuf logical contract with trusted in-core
Rust, WASM/WASI, and supervised process-RPC tier adapters.

Two viable options remain:

| Choice | Strengths | Costs and correctness risks |
| --- | --- | --- |
| Rust-only, in-process plugins | Simple typed contracts, low latency, easy access to engine types, smaller operational surface | Rust compiler/ABI coupling, plugins can crash or corrupt engine state through bugs, weak isolation, excludes other ecosystems unless wrapped |
| Supervised process plugins in any language | Language-neutral expansion, crash/resource isolation, independent release cadence, natural remote/sandbox execution | Protocol/version design, serialization and process overhead, harder cancellation/streaming, more packaging and observability work |

A hybrid is possible only if one semantic contract and conformance suite govern
both paths; otherwise behavior will diverge. Phase 0.3 must decide isolation and
trust requirements, version negotiation, lifecycle, cancellation, streaming,
resource limits, schema ownership, compatibility tests, and distribution before
adding executable plugin code.

The engine still sees only `plugin-host`; execution tier is an adapter choice and
does not create a second interface. Hard containment is unavailable in-process,
so third-party code and plugins requiring hard isolation use WASM or process RPC.
