# ADR 0007: Unified plugin contract

**Status:** accepted for 0.3

## Decision

APIaxess has one logical plugin system with three tier adapters: trusted
first-party in-core Rust, WASM/WASI components, and supervised process RPC. The
canonical third-party boundary is the language-neutral Protobuf IDL under
`contracts/plugin`; generated Rust types or traits are adapter details and are
never the public source of truth. Protobuf is the logical schema, not a mandate
to use gRPC as every transport.

Each kind is an independently versioned narrow service: discovery brain, target
type, protocol decoder, artifact generator, pinning bypass, and instrumentation
orchestrator. All share the lifecycle, permissions, resource, artifact-reference,
diagnostic, and telemetry messages. Public snapshots and proposal/inventory
batches are versioned artifacts; internal engine/data-model types never cross.

## Initialization and compatibility

Initialization follows the LSP shape: host `Initialize`, plugin
`InitializeResult`, host `Initialized`. The final message records the intersection
of compatible protocol/interface versions, feature IDs, permission grants, host
capabilities, resource limits, and containment mode. Kind methods are illegal
before completion.

Major versions must match. The lower compatible minor is selected. Features and
capability IDs are opt-in strings; unknown optional IDs and protobuf fields are
ignored. Unknown required capabilities remain ungranted and cause an explicit
denied/degraded state. Implementation version strings are diagnostic metadata,
never feature detection.

## Authority and host capabilities

There is no ambient authority. Plugins request scoped `fs.read`, `fs.write`,
`network.connect`, `process.spawn`, `device.adb`,
`instrumentation.frida.attach`, `secret.read`, `artifact.read`, and
`artifact.write`. A grant records narrowed scopes, consent source, and expiry.
Omission means denial. The request declares host-capability dependencies; the
existing host detector reports supported, degraded, unavailable, or unknown with
evidence/remediation. Required unavailable dependencies cannot activate silently.

## Resources and containment

CPU time, wall time, memory, per-message/output bytes, concurrency, cancellation,
health, bounded structured logs, crash reports, restart policy inputs, and
graceful shutdown are contract-level. WASM and process runtimes must enforce hard
limits before advertising hard containment.

An in-process Rust thread cannot be safely killed, memory-isolated, or guaranteed
not to abort/OOM/hang the host. That settled tier is therefore restricted to
trusted first-party code and advertises cooperative containment. A plugin that
requires hard containment is denied in-core and must use WASM or process RPC.
This is an explicit correctness constraint, not a silent weakening of isolation.

## Large data

APKs, blobs, snapshots, decoded frames, proposals, inventories, scripts, and
outputs cross by immutable content-checked `ArtifactRef`, bounded slice, or
capability-bound stream lease. The host owns local storage. References contain no
host path. Small control messages remain Protobuf.

## Evolution discipline

Wire/JSON compatibility is additive-only within a major version. Field and enum
numbers are never reused; removed values are reserved. Evolution annotations
model WIT's `since`, `unstable`, and `deprecated` gates. SemVer is backed by Buf
lint/breaking rules, handshake negotiation, and the defined common golden corpus.
The corpus harness implementation is deferred, not its required cases.

## Prior-art findings

- Nushell currently launches executable plugins over stdio (with an optional
  local socket) and exchanges an encoding choice plus `Hello` protocol/version
  information. We copy the lifecycle idea, not its wire format.
- LSP initialization remains the capability-negotiation template.
- HashiCorp go-plugin demonstrates supervised local process RPC, logs, version
  mismatch diagnostics, and host crash isolation. We do not adopt Go or gRPC.
- Zellij permissions currently include application-state, open-file, command,
  environment, and web-related grants; APIaxess uses similarly legible but
  security-tool-specific scoped permission IDs.
- Zed currently builds extensions for `wasm32-wasip2` from manifest-backed
  packages. APIaxess uses WASI components only as one adapter.
- WIT currently specifies `@since`, opt-in `@unstable`, and `@deprecated` gates.
  WASI/Component Model work continues incrementally, including async/thread work;
  therefore canonical semantics stay transport-neutral Protobuf rather than WIT.
- Frida scripts execute inside an instrumented target with memory/hooking access.
  They are payloads behind process-tier Frida grants, never treated as sandboxed
  WASM plugins.

