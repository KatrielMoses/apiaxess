# APIaxess Phase 4.3: Canonicalization Inference

Phase 4.3 consumes the exact preimage and ordered `update()` chunks from Phase
4.1, plus an optional known-scheme shortcut from Phase 4.2. It produces ranked
canonicalization hypotheses rather than claiming that a finite capture set has
proved the target's complete signing behavior.

## Evidence flow

1. `CanonicalizationCapture` joins a raw `RequestSnapshot` to one
   `CryptoCaptureRecord`.
2. Ordered update chunks are correlated first. Chunks that equal a method,
   path, query, headers, body, timestamp, nonce, or an encoded form of one are
   retained as ordered components; unmatched chunks remain explicit literals
   and force human review.
3. If chunk correlation is insufficient, small explainable field plans test
   method/path/query/header/body combinations with raw, percent, form, hex, and
   Base64 encodings.
4. `build_differential_experiments` compares captures one property at a time
   and records whether the preimage and output changed. Multiple changes are
   retained as `multiple`, never misrepresented as a clean experiment.
5. A `ReplayOracle` validates candidate canonical bytes against the primitive
   output on held-out captures. The oracle is deliberately supplied by the
   primitive/key owner because 4.3 does not reimplement arbitrary crypto or
   Keystore behavior.

## Outcome contract

The result has one of four states: `reproducible` when held-out replay succeeds,
`partial_hypothesis` when candidates exist but review or more captures are
needed, `observed_only` when a primitive was seen without recoverable
canonicalization, and `blocked` when anti-hooking or observability prevented
reliable evidence. Every hypothesis retains training and held-out counts,
confidence, source provenance, and request/canonical-bytes/output fixtures.

The output is intentionally upstream of Phase 4.4's signer IR. Bespoke
multi-stage transforms, conditional branches not exercised in captures,
device/account behavior, and custom native serialization remain
`human_assist_needed`; no outcome claims those branches are recovered.

## Live validation

Unit tests cover ordered chunk correlation, field fallback, differential
classification, held-out replay, fixture retention, shortcut propagation, and
the blocked/observed-only states. Real-app validation against custom-signing
Hermes targets remains live-untested until enough differential captures are
available.
