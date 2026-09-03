# ADR 0006: Core data model

**Status:** accepted for 0.2

## Decision

The canonical API surface is an independent, versioned Rust model in
`crates/api-model`. OpenAPI, HAR, Postman collections, decompiler output, and
capture formats are edge adapters. None is the persisted backbone.

Facts are multi-candidate containers. Every candidate points to one or more
provenance entities; every fact records a current candidate and the field-class
policy that selected it. Candidates are append-only evidence: resolution changes
the current selection but does not erase alternatives.

The provenance registry borrows W3C PROV vocabulary—entity, activity, agent,
`generated_by`, `attributed_to`, and `derived_from`—without RDF or ontology
machinery. Each entity also records source type, tool/agent ID, run ID, timestamp,
and a non-zero sample count. Derived entities form an acyclic graph back to leaf
static or dynamic evidence.

## Merge semantics

Every merge is explicitly classified:

- `gap_fill`: one source is silent and the other asserts; silence has no negative
  meaning.
- `refinement`: a narrower assertion is selected or derived without deleting the
  broader candidate.
- `true_conflict`: incompatible candidates remain available while policy selects
  a current result.
- `agreement`: both sources support the same candidate.

Policies are constrained by field class: authentication uses dynamic-authoritative
resolution; schema/type shapes use union-or-widen; presence uses static completeness
with dynamic confirmation; path templates prefer declared routes over inferred
fallbacks; requiredness is sample-gated. There is no last-writer or global
dynamic-wins policy.

Authentication validation requires a current candidate supported by dynamic
evidence whenever dynamic evidence exists. Presence has no “not observed means
absent” value. A dynamic miss therefore cannot delete a statically established
endpoint or parameter.

## Endpoint identity

Endpoint identity is exactly normalized HTTP method plus a path template. The
template cannot contain a query or fragment. Query parameters live in endpoint
metadata and do not affect identity. The selected path-template assertion must
match the identity key and records whether it was declared or inferred.

## Schemas and samples

A schema slot holds a multi-candidate shape fact plus zero or more inline or
artifact-backed observed samples. Recursive object properties have their own
shape and requiredness facts. Union shapes are native model values, so an
orchestrated inference adapter can retain individual candidates and publish a
widened current result.

Dynamic requiredness evidence is an observation tally, not a Boolean. Evaluation
requires a caller-supplied minimum sample threshold; below it the result is
inconclusive. The tally remains durable so policy can be recalibrated.

## Confidence

Confidence is never serialized. The baseline policy traverses a selected
candidate's provenance graph to leaf evidence, then returns both a scalar and its
inputs: total samples, source agreement, and true-conflict count. The transparent
formula is provisional and replaceable; retained evidence is authoritative.
Dempster-Shafer belief masses are deliberately not used.

## Serialization and evolution

The durable JSON document carries a format version. Loading and saving validate
the entire model: identifiers, provenance references and acyclicity, activity
times, unique endpoint identities, fact candidates/resolutions, merge shapes,
field policies, selected templates, parameter uniqueness, recursive schemas, and
sample references. Unknown fields and unsupported versions fail explicitly so an
older reader cannot silently discard evidence. Future format changes require a
migration, not an implicit serde reshaping.

## Verified research leads

Baazizi et al.'s published work does exist and provides useful conceptual
background for schema languages with controllable precision. It does not define
this model or its fusion policy. Akita was acquired by Postman in 2023; the
current official product is Postman Insights, whose agent observes traffic and
infers endpoints. It is prior-art context only and is not a format or dependency.

