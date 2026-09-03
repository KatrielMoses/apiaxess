# Interface registry

IDs and major versions are permanent. Minor versions advance only for additive,
opt-in surface. Plugin kinds are public projection boundaries; core Rust types
and storage layouts never cross them.

| Interface ID | Version | Service | Implementations/examples |
| --- | --- | --- | --- |
| `apiaxess.discovery-brain` | 1.0 | `DiscoveryBrainService` | deterministic code reasoner; future AI-key brain |
| `apiaxess.target-type` | 1.0 | `TargetTypeService` | APK; future web, EXE, DEB |
| `apiaxess.protocol-decoder` | 1.0 | `ProtocolDecoderService` | pure binary/application protocol decoders |
| `apiaxess.artifact-generator` | 1.0 | `ArtifactGeneratorService` | reports, replay artifacts, future export adapters |
| `apiaxess.pinning-bypass` | 1.0 | `PinningBypassService` | Declarative pinning techniques with automated rooted, patch, Flutter, and Xamarin lanes |
| `apiaxess.instrumentation-orchestrator` | 1.0 | `InstrumentationOrchestratorService` | Versioned Frida substrate, health/watchdog evidence, and session-scoped stealth orchestration |
| `apiaxess.sandbox-backend` | 1.0 | `SandboxBackendService` | AVD, redroid, and secured remote-offload runtime lifecycle |

The discovery request accepts a versioned public surface snapshot by reference
and returns a proposal batch by reference. The same service is used for both
code and AI implementations. The target service probes and inspects an opaque
artifact reference and reports a stable target type ID. Adding `web`, `exe`, or
`deb` therefore adds implementations, not methods or engine dependencies.
