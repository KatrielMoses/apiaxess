# ADR 0002: Orchestration over reimplementation

**Status:** accepted; architectural law

## Decision

APIaxess does not reimplement mature external tools. Decompilers (for example
jadx and apktool), instrumentation systems (Frida), fuzzers (ffuf), platform SDK
tools, and the Android sandbox remain independently installed or managed tools.
APIaxess drives them through stable adapters owned by `crates/external-tools`.

Direct child-process APIs are forbidden outside that crate and mechanically
checked by `cargo xtask boundaries`. A future adapter may use a process, library,
daemon, or remote transport, but callers see only the tool-runner port.

## Adapter lifecycle

Every adapter will implement the same semantic lifecycle; the concrete Rust
contract is intentionally deferred to phase 0.3/0.4 dependencies:

1. **Describe:** stable tool ID, role, supported adapter revision, and provenance.
2. **Probe:** locate explicit configuration first, then managed installation,
   then `PATH`; execute a bounded version probe; parse and retain raw output.
3. **Plan:** validate version constraints and host capabilities before starting.
4. **Invoke:** use an argument vector, a controlled environment, explicit working
   and temporary directories, deadlines, cancellation, and bounded output capture.
   Shell command strings are not an invocation format.
5. **Collect:** preserve stdout, stderr, exit status/signal, duration, adapter/tool
   versions, and declared output artifacts as evidence. Partial output is not
   silently promoted to success.
6. **Report:** surface absent, incompatible, timed-out, cancelled, crashed,
   malformed-output, and policy-denied states distinctly. Shared error envelopes
   are designed in 0.4.

Adapters translate tool-specific behavior at one edge. Analysis code uses stable
intent-level operations and never parses a tool's console text. Version probes
and invocation results are recorded so findings remain reproducible.

## Swappability

Selection is by stable capability/tool ID plus policy, not executable name.
Multiple adapters may satisfy one intent. Configuration chooses or pins an
adapter; the engine records the selected adapter and detected tool version.
Replacing jadx, ffuf, Docker, or a transport therefore does not change callers.

## Sandboxes

Sandbox orchestration is a separate port in `crates/sandbox`. Its local Docker
backend will use the same controlled runtime mechanisms; no feature code calls
Docker. Users never need to issue Docker commands. A remote backend implements
the same sandbox lifecycle and returns evidence/results to local storage.

