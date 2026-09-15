# Incremental session checkpointing

The canonical `session.json` remains the portable, evidence-complete authority.
It is atomically/recoverably replaced on explicit save, clean shutdown, and each
analysis-document commit. SQLite remains the immediate authority for live
capture, resend, and fuzzer runtime rows.

Between full saves, `SessionRuntime` writes a sibling
`session.checkpoint.json`. Each accepted in-memory mutation marks the runtime
dirty; one worker flushes the latest compact state at most once every two
seconds. The checkpoint has its own exact format version and session identity and contains
only engagement scope, append-only audit metadata, sandbox attachment metadata,
and analysis progress. It intentionally excludes the API evidence document and
workbench traffic snapshot, preventing frequent rewrites of a 100 MB+ session.

On restart, the reader:

1. validates the full session artifact and its exact format version;
2. opens the existing per-session SQLite store, hydrating it from the portable
   workbench snapshot only when the local store is empty;
3. validates the checkpoint's exact version and identity; and
4. applies it only when it represents a newer session mutation.

Writes use a synced temporary file and recoverable previous-file rename. If a
process dies during replacement, startup can read the previous valid file rather
than accepting a partial JSON document. A successful full save removes the now
redundant compact checkpoint.

Residual boundary: a hard kill can lose the session mutation currently being
written, at most two seconds of accepted metadata, and computation or
external-tool output that has not yet crossed a typed session commit. Already
committed SQLite traffic and the last completed metadata checkpoint survive.
This is bounded state-change durability, not per-instruction transactional
attestation.
