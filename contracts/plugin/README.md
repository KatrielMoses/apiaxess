# APIaxess plugin contract

This directory is the canonical third-party contract. Protocol Buffers is used
as a language-neutral IDL because it provides stable field numbers, tolerant
unknown-field readers, broad language tooling, and transport independence. The
IDL is not a commitment to gRPC. In-core Rust, WASI Component Model, and process
RPC adapters all map to the same logical services defined here.

The current protocol is `1.0`. Each plugin interface has its own version in
[INTERFACES.md](INTERFACES.md). A package advertises one execution tier, but tier
never changes the service it implements.

## Normative rules

- Readers ignore unknown protobuf fields, unknown optional feature IDs, and
  unknown optional capability IDs. A required unknown capability remains
  ungranted and produces a denial/degradation diagnostic.
- Existing field numbers and enum numbers are permanent. Removed fields/numbers
  are reserved. Stable fields and methods are never changed incompatibly within
  a major version.
- Additions begin behind an `unstable_feature` evolution gate. Stabilization sets
  `since`; deprecation adds `deprecated_since` and a replacement without removal.
- Host and plugin use `Initialize`, `InitializeResult`, then `Initialized`. No
  kind-specific operation may run before `Initialized`.
- The effective interface, feature, permission, host-capability, and resource set
  is the intersection explicitly returned in `Initialized`.
- No permission is ambient. Absence from `grants` means denied.
- Payloads larger than the negotiated message/output bound use `ArtifactRef`,
  `ArtifactSliceRef`, or `StreamRef` and a granted artifact capability.
- SemVer labels releases; Buf `WIRE_JSON` breaking checks, evolution annotations,
  handshake negotiation, and the future conformance corpus establish compatibility.

`buf lint` validates the IDL. Once a release baseline exists, release CI must run
`buf breaking --against` against the latest compatible release or descriptor
image; changing the comparison baseline requires architecture review.

## Security truth for execution tiers

WASM and process tiers can promise hard containment when the runtime reports it.
Trusted first-party in-core Rust is cooperative: deadlines, cancellation,
concurrency, message bounds, and allocator accounting can be observed, but a
hung thread, abort, OOM, unsafe-code fault, or hostile plugin cannot be forcibly
contained inside the same process. The handshake therefore reports
`CONTAINMENT_MODE_COOPERATIVE`. A plugin requiring hard containment must run as
WASM or a supervised process. Third-party plugins are never admitted in-core.

This qualification prevents the contract from claiming a guarantee the operating
system cannot enforce while retaining the trusted hot-path tier.

