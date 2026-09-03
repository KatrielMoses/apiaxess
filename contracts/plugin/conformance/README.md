# Plugin conformance harness definition

The harness implementation is deferred, but every SDK and plugin must eventually
run the same transport-independent cases and kind-specific golden corpus.

## Universal cases

1. Initialize 1.0 with unknown fields, optional capabilities, and optional
   feature flags; known intersections activate and unknown optional IDs are ignored.
2. Reject a protocol/interface major mismatch with a stable diagnostic; negotiate
   the lower compatible minor without parsing implementation version strings.
3. Deny or explicitly degrade when a required permission, host capability, hard
   containment mode, or resource minimum is unavailable.
4. Prove deny-by-default by attempting filesystem, network, process, device,
   Frida, secret, and artifact writes outside granted scopes.
5. Enforce CPU/wall deadline, memory, message/output, and concurrency limits;
   acknowledge cancellation within the negotiated grace bound.
6. Return an oversize result by artifact/stream reference and verify digest,
   length, range, and lease scope; no full payload appears in an RPC message.
7. Emit valid structured logs. Simulate panic/trap/crash/hang, collect a crash
   report, restart when policy permits, and prove the engine remains responsive.
   In-core Rust runs the cooperative subset and must advertise that limitation.
8. Round-trip messages containing future unknown fields without treating them as
   fatal. Prove removed/renumbered fields fail schema compatibility checks.
9. Verify the manifest has a free/open-source SPDX expression and source URL.

## Kind corpora

- `discovery-brain`: identical surface/proposal fixtures for deterministic and
  AI-backed test doubles; proposal order is not treated as semantic.
- `target-type`: APK positives/negatives plus opaque future target IDs proving no
  APK assumption exists in the host.
- `protocol-decoder`: truncated, malformed, adversarial, and streaming payloads.
- `artifact-generator`: deterministic inputs, bounded outputs, and artifact-write
  scope failures.
- `pinning-bypass` and `instrumentation-orchestrator`: fake sandbox/device/Frida
  services proving grants and host-capability degradation without live devices.

Golden inputs belong under `conformance/corpus/<interface-id>/<major>/`. Expected
results include canonical protobuf JSON, artifact digests, diagnostics, resource
accounting, and allowed nondeterminism declarations. The later harness runs every
tier adapter against the same logical cases.

