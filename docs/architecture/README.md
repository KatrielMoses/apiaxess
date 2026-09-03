# Architecture records

These versioned records are the architecture source of truth. Later phases may refine a
boundary by adding a new record, but must not move it implicitly.

1. [Language and workload split](0001-language-and-workload-split.md)
2. [Orchestration over reimplementation](0002-external-tool-orchestration.md)
3. [Communication boundaries](0003-communication-boundaries.md)
4. [Host capabilities and dynamic tiers](0004-host-capabilities-and-tiers.md)
5. [Packaging and asset delivery](0005-packaging-and-assets.md)
6. [Core data model](0006-core-data-model.md)
7. [Unified plugin contract](0007-unified-plugin-contract.md)
8. [Session, diagnostics, scope, and durable artifact](0008-session-diagnostics-and-scope.md)
9. [Repository map](repository-map.md)
10. [Open decisions](open-decisions.md)

## Phase boundary

Version 0.4 defines the recovered-API model, plugin contract, advisory engagement
scope, structured diagnostics, session aggregate, and durable session artifact.
It does not implement plugin runtimes, authorization enforcement, attestation,
analysis, capture, proxy, sandbox, inference, workbench behavior, or GUI features.
