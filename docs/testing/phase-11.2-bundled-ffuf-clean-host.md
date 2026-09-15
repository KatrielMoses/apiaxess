# Phase 11.2 — bundled ffuf, clean-host verification

Date: 2026-08-29

Phase 11.2 bundles the ffuf discovery/fuzzing binary and invokes it by absolute
path from the install layout, so discovery needs no host ffuf. ffuf is a
statically-linked Go binary with no runtime — a pure drop-in.

## What ships

- **ffuf 2.2.1** per platform under `tools/ffuf/` (`ffuf.exe` on Windows, `ffuf`
  on Linux), pinned by SHA-256 in [`ffuf.toml`](../../packaging/assets/ffuf.toml)
  to the values published in the release `checksums.txt`.
- The Linux binary is verified **statically linked** — `file` reports
  "statically linked" and the ELF has no `PT_INTERP` (no dynamic loader).
  `fetch-ffuf.ps1` re-checks this at packaging time and refuses a dynamic build.
- MIT `LICENSE` travels with the payload; `ffuf-sbom.json` is emitted beside it.

## Invocation model

Discovery routes through the fuzzer's ffuf tier (`crates/workbench-proxy/src/
fuzzer.rs::run_ffuf`), which now resolves ffuf via
`crate::bundled::resolve_ffuf()`:

- Default: `<resource_base>/tools/ffuf/ffuf[.exe]`, absolute, from `current_exe`
  (Windows `<bin>/..`, Linux `<bin>/../share/apiaxess` — same resolver shape as
  Phase 11.1 and bundled Chromium).
- `APIAXESS_FFUF` remains an advanced override (clears the install-integrity
  component).
- **Self-contained config**: the ffuf process is given a controlled environment
  that points its user-config directory (`APPDATA` on Windows, `XDG_CONFIG_HOME`
  on Linux — what Go's `os.UserConfigDir()` reads) at an APIaxess-owned
  `…/apiaxess/ffuf` directory, so ffuf's config/history never touches the
  per-user default location.
- **Install-integrity**: before ffuf is probed, a missing bundled binary yields
  the `install.component-missing` diagnostic (shared with Phase 11.1), not a
  silent failure.

## Verification

Automated (`crates/workbench-proxy/src/bundled.rs` tests):

- Unit: default resolution is the absolute bundled `tools/ffuf/` binary with an
  install-integrity component; an override replaces it and clears the component;
  the controlled environment confines the config directory.
- **Clean-host discovery** (gated `APIAXESS_BUNDLED_VERIFY=1`): stages the
  bundled binary at the default resolved path, starts a local HTTP target
  (200 for `/admin` and `/login`, 404 otherwise), and runs a real
  directory-discovery sweep through the external-tool boundary using the default
  `resolve_ffuf()` path. Result: **passed** — `found ["admin", "login"]` via
  `…/target/debug/deps/../tools/ffuf/ffuf.exe`, correctly excluding the 404s.

Manual sanitized run: the bundled `ffuf.exe` performed the same directory sweep
with a scrubbed environment (no host ffuf on `PATH`), found `admin`+`login`, and
wrote parseable JSON.

Both the fetch script (`fetch-ffuf.ps1 -Platform windows_x64` and
`-Platform linux_x64`) produce verified payloads; the Linux static-ELF check
passes cross-platform.

## Out of scope (per Phase 11.2)

the proxy backend (11.3 — dropped mitmdump for hudsucker), Frida (11.4),
emulator (11.5); installers (Phase 12).
Linux verification is **done** — see
[phase-11-linux-verification.md](phase-11-linux-verification.md): the Linux ffuf
binary (statically linked) ran a real clean-host discovery sweep and found
results with no host ffuf.
