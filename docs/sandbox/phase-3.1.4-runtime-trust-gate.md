# Phase 3.1.4 — Policy-Driven Runtime-Trust Gate

Phase 3.1.4 replaces the scenario-specific Android patch-date rejection with
an offline, explained runtime-trust policy evaluation.

## Gate model

- Runtime posture is represented by typed facts: security patch, expected and
  observed image digest, optional image-signature status, containment, sandbox
  tier, and ADB loopback/key/ephemeral controls.
- The default policy is data in
  `crates/sandbox/policies/runtime-trust.json`. Vulnerability records carry a
  fixed patch level, exploitability expression, mitigation expression, and an
  OpenVEX-compatible justification. The evaluator supports the bounded CEL-
  class boolean subset needed for offline posture decisions.
- Outcomes are `allow`, `allow_with_findings`, `require_acceptance`, and
  `deny`. Digest mismatch, failed signature verification, containment failure,
  and policy-integrity failure are non-overridable denies.
- A risk acceptance is scoped to exact finding IDs, image digest, profile,
  reason, threat model, user, and expiry. Accepted decisions can be appended
  to an audit JSONL file; there is no global ignore switch.
- Lease callers can inspect `SandboxLease::trust_diagnostics()` to retain the
  explained finding with the session/runtime record.

## Capstone consequence

The HQarroum API-33 posture of `2024-03-01` with loopback-only,
key-authenticated, ephemeral ADB evaluates to `allow_with_findings` for
`CVE-2026-0073`, with the VEX justification
`inline_mitigations_already_exist`. A genuinely reachable old-runtime risk
requires scoped acceptance; digest/containment/integrity failures cannot be
waived.

## Validation

The sandbox trust tests cover:

1. old patch + isolated ADB → `allow_with_findings`;
2. reachable risk → `require_acceptance`, then scoped acceptance;
3. image digest mismatch → non-overridable `deny`, with acceptance audit
   rejection.
