# Phase 11 closeout — Linux clean-host verification + CI gate

Date: 2026-08-29

Closes the two caveats carried by Phase 11.1/11.2/11.3: Linux was never executed
(the prior hosts were Windows), and the workspace `clippy -D warnings` gate was
red. Both are now green.

Environment: WSL2 Ubuntu 24.04 (plain Linux, no KVM). Rust 1.88.0. The repo was
built natively in the WSL filesystem; the Linux bundled artifacts were produced
by the same pinned fetch scripts used on Windows (run under PowerShell 7 on
Linux — the scripts are separator-portable). A host JRE exists in the distro but
**no** host JDK/jlink, apktool, jadx, or ffuf — matching the "nothing on the
host" premise; where a host tool did exist it was actively neutralised.

## Task 1 — Linux clean-host verification

### 11.1 — shared JRE + apktool + jadx

`fetch-java-runtime.ps1 -Platform linux_x64` downloaded the pinned Temurin 21 JDK
and ran its own `jlink` to a **72 MB** trimmed Linux runtime; `fetch-apk-tools.ps1`
staged apktool 3.0.3 + jadx 1.5.5. A real APK
(`fixtures/capstone/feeder-2.22.0-4050.apk`) was run through the built Linux
`apiaxess analyze` from an install-shaped dir (`bin/` + `share/apiaxess/…`) with a
**scrubbed environment**: a refusing "poison" `java` placed first on `PATH` (so
any host-Java use exits 97), a bogus `JAVA_HOME`, and no `APIAXESS_*` overrides.

Result: **completed, 12 endpoints, exit 0** — identical to the Windows run. The
poison-java "REFUSED" line never appeared, proving the bundled runtime (invoked
by absolute path) was used, not host Java. The jadx exit-3 warning is the normal
partial-decompile path. APK static analysis is host-independent on Linux.

### 11.2 — ffuf

`fetch-ffuf.ps1 -Platform linux_x64` produced the Linux binary; `file` confirms
**statically linked** (no interpreter), and the script's own PT_INTERP check
passed. With no host ffuf on `PATH`, the gated `bundled_ffuf_runs_real_discovery`
test ran a real directory-discovery sweep through the tool boundary using the
default-resolved bundled path (`…/share/apiaxess/tools/ffuf/ffuf`) →
**found `["admin","login"]`**, excluding the 404s. Passed.

### 11.3 — proxy (hudsucker, pure Rust)

Nothing to bundle; the proxy is compiled in. On Linux, with no host
Python/mitmproxy: `hudsucker_http2` (4 tests — TLS-ALPN h2, h2 multiplexing, gRPC
trailers, h2 capture into the store) and the workbench-proxy lib suite (26 tests
— h1 capture into the store + per-flow intercept forward/modify/drop/timeout) all
**pass on Linux**. HTTPS capture (h1 + h2) works host-independently; the
mitmdump removal did not break Linux capture.

## Task 2 — CI clippy gate (`-D warnings`)

The gate had a **chain** of pre-existing issues (from the earlier hardening pass)
that a first-error-abort had hidden — not just the one flagged:

1. `crates/workbench-proxy/src/intruder.rs::run_native` — `too_many_lines`
   (102/100). Refactored under the limit by extracting `dispatch_batch`
   (batch dispatch: stateful in-order vs. stateless fan-out + rate limiting) and
   `record_batch` (ordinal recording, scope/diff/filter, persistence). Pure
   refactor — the intruder native-tier tests still pass (5/5).
2. `crates/engine-shell/src/lib.rs::launch_bundled_chromium` — `missing_errors_doc`.
   Added the `# Errors` section.
3. `apps/engine/src/main.rs` — `print_literal` (a `println!` with a `"Bundled
   Chromium"` literal argument). Inlined it.

`cargo clippy --workspace --all-targets -- -D warnings` now **exits 0**. All
touched-crate tests pass and rustfmt is clean.

## Status

Phase 11.1, 11.2, and 11.3 are now fully verified on **both** Windows and Linux,
and the CI `-D warnings` gate is green. Requirement 6 (clean-host verification,
both platforms) is closed for all three completed bundlings.

Out of scope (next): Frida (11.4) and the emulator (11.5) — the dynamic path,
which needs the virtualization environment; installers (Phase 12).
