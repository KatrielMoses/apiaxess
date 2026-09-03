# ADR 0008: Session, diagnostics, scope, and durable artifact

**Status:** accepted for 0.4

## Decision

`crates/session` is the unit-of-work aggregate. It owns one engagement scope
(including the target identity), the canonical 0.2 `ApiDocument`, an append-only
action audit trail, and an optional opaque workbench-state slot. The engine shell
consumes this aggregate; transports and later features must not create parallel
session DTOs.

`crates/diagnostics` is the canonical failure/warning representation. Every
anticipated operational failure carries a stable ID, category, severity,
what/why/fix prose, and typed context. The same value is suitable for GUI
rendering, structured logs, audit records, and integrations. A raw stack trace
may be retained internally for developers, but it never replaces the diagnostic.

## Authorization truth

Scope is a structured declaration and audit instrument, not an enforcement or
attestation claim. A target identity contains a target-type ID, a primary
identifier (normally an artifact hash), and typed aliases such as an Android
package name. Allowed network targets use explicit exact-host or DNS
domain-and-subdomain matching, with optional port restrictions.

Every feature action must enter through the session audit recorder with a
concrete target. The recorder deterministically stores `in_scope`,
`outside_declared_scope`, `undetermined`, or `not_applicable`. Outside and
undetermined actions receive canonical warnings but are still appended and
allowed. Loading recomputes each decision and requires the appropriate warning,
so a serialized record cannot quietly claim a different classification.

The declared scope is immutable through the current session API. A future scope
amendment, if required, must be an explicit audited model addition preserving the
scope applicable to earlier actions. Enforcement, blocking, authorization
attestation, and claims about remote systems are expressly out of scope.

## Lifecycle

The runtime lifecycle is `created -> active -> closed`:

- `created`: aggregate exists but feature/workbench actions cannot attach;
- `active`: live in-process unit to which later workbench and analysis work attach;
- `closed`: explicitly finalized and terminal.

Serialization is orthogonal to lifecycle rather than a fake fourth service
state. Created, active, or closed sessions may be snapshot to a
`SessionDocument`; an active snapshot can be loaded in a later process and
continue as the live session. Process exit leaves no background service. A
closed snapshot remains closed.

## Persistence

`SessionDocument` is the sole durable session envelope. It has its own exact
format version and snapshot timestamp and embeds the 0.2 `ApiDocument` with its
independent format version. Encoding validates first; decoding rejects malformed
JSON, unsupported versions, unknown fields that could be lost, invalid session
invariants, and invalid nested model invariants with canonical diagnostics.

Scope, audit diagnostics, every model candidate/evidence/provenance link, and the
opaque workbench payload round-trip losslessly. The workbench slot has a schema
ID and version but is deliberately opaque to this crate; Phase 2 owns its
contents and validation. `SessionDocument` produces/consumes bytes. A future
filesystem adapter must use safe atomic replacement appropriate to the host; OS
write policy is not smuggled into the portable model.

## Catalogue extension law

Later phases add a catalogue definition before shipping an anticipated failure.
IDs are permanent lowercase namespaced keys. Definitions must answer all three
questions, attach typed occurrence context, and have catalogue tests. New IDs
are additive; changing an ID means a new failure identity. Host-capability gaps
and plugin permission denials adapt their existing IDs/statuses into this one
diagnostic model rather than defining competing error types.

The human-readable catalogue is indexed in
`docs/diagnostics/catalogue.md`; `cargo xtask foundations` checks that the phase
0.4 entries remain present in code and documentation.

## Explicit non-goals

No analysis, discovery, capture, proxy, authorization enforcement, attestation,
workbench behavior, workbench payload schema, persistent daemon, or automatic
format migration is introduced by this decision.
