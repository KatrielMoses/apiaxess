# Phase 4.2 signing-scheme detection

Phase 4.2 consumes Phase 4.1 operation records plus a request envelope and
static Phase 1 indicators. It recognizes known schemes before generic
canonicalization inference:

- AWS SigV4
- OAuth 1.0 HMAC
- JWT/JWS
- HTTP Message Signatures / RFC 9421
- custom HMAC request headers
- RSA/ECDSA request signatures

Each scheme is an independent SchemeTemplate. A registry evaluates all
templates, retains matched indicators with static or dynamic SourceType
provenance, and computes a bounded confidence from their weights. A strong
multi-indicator match is recognized; close high-confidence candidates remain
ambiguous; weak or absent matches are explicitly unrecognized.

Recognized results carry a ReproductionShortcut for Phase 4.3: the SigV4
canonical request and signing-key chain, OAuth 1.0 base string, JWS signing
input, RFC 9421 component serialization, or a public-key output-shape
description. Custom HMAC keeps its canonicalization unresolved. No Phase 4.2
result claims to infer bespoke canonicalization.

The registry accepts community/plugin templates through SchemeTemplate and
SchemeRegistry::register. The detector does not require a central scheme
switch for new siblings.
