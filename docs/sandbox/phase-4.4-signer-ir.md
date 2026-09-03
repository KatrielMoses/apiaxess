# APIaxess Phase 4.4: Signer IR and Reusable Artifact

Phase 4.4 closes the crypto-observation path by packaging the 4.1 primitive,
4.2 scheme shortcut, and 4.3 canonicalization result into a portable signer
artifact. The IR is defined in `api-model::signer` and emitted by
`apiaxess-crypto-signer-ir`, so Phase 6 can generate language-specific SDK code
without depending on the Rust inference implementation.

## Artifact contents

Each `SignerArtifact` carries the scheme, honest mode, confidence, covered
request components, ordered canonicalization operations, primitive/hash,
credential boundary, output encoding and wire placement, timestamp/nonce
runtime contract, fixtures, ranked alternatives, provenance, and a language-
neutral `sign(request, credential_provider, clock, nonce_source)` interface.
Device-oracle artifacts additionally expose the original-runtime callback type.

The key boundary is structural: `SignerKeySource` contains only a
`secret_ref`, external provider reference, or device callback. It has no field
that can carry recovered key bytes. Exportability in the capture is used only
to choose the credential or device-oracle boundary.

## Honest modes

- `reproducible` is emitted only when 4.3 reports held-out replay success and a
  credential reference is available.
- `partial_hypothesis` retains ranked alternatives and fixtures and is marked
  for review.
- `observed_only` records the primitive without pretending canonicalization was
  recovered.
- `device_oracle` takes precedence when the key is non-exportable,
  hardware-backed, or explicitly white-box/runtime-only; its reproduction text
  is `requires original runtime`.

Blocked 4.3 inference emits no fake signer artifact and produces a
`crypto.signer-not-recoverable` diagnostic. Real-app end-to-end replay remains
on the Hermes live-validation list.
