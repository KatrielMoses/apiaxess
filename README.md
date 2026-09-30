# APIaxess

**Reconstruct an application's real, reachable API surface — from the code it ships
and the traffic it makes — with zero setup.**

APIaxess is an open-source security workbench that reverse-engineers an app's API
from *evidence*, never guesswork, and reports honest coverage for whatever it can't
confirm. Point it at a web app or an Android APK: it captures live traffic through a
bundled browser, analyzes the APK statically and dynamically, and fuses everything
into one auditable API surface you can resend, fuzz, and export.

Everything is bundled — Chromium, a Java runtime, apktool, jadx, ffuf, Frida, and an
Android emulator — so there is nothing to install and wire up. It all runs locally on
`127.0.0.1`, and your captures and sessions are never sent anywhere. The app's only calls
out are an optional, identifier-free update check to apiaxess.dev (off with one setting)
and add-on downloads when you click them.

[Website](https://apiaxess.dev) · [License](LICENSE) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## What you get

- **Zero-setup capture** — a bundled browser + MITM proxy covering HTTPS, WebSocket,
  SSE, gRPC-Web, and GraphQL.
- **APK analysis** — static extraction plus a dynamic sandbox pass, fused into one surface.
- **Workbenches** — Resend (a cleaner Repeater) and Fuzz (Burp-Intruder-class attack
  types, payload engine, and grep).
- **Honest output** — a fused API surface with per-endpoint evidence (confirmed vs
  inferred) and coverage it never overstates.
- **Export** — OpenAPI 3.1, Postman, HAR 1.2, and a runnable Python (httpx) SDK.
- **Local & auditable** — loopback-only, a durable session with an append-only audit
  trail; scope is advisory and honest — it warns, it never silently blocks.

## Install

APIaxess ships for **Windows and Linux** today (macOS is on the roadmap). Downloads and
one-line install commands are on **[apiaxess.dev](https://apiaxess.dev)**. Builds are
currently **unsigned** — published **SHA-256 checksums** let you verify integrity, and
on Windows the first run shows a SmartScreen "unknown publisher" prompt (More info →
Run anyway). We sign once the project earns the traction to justify it.

**Windows — Scoop:**

```powershell
scoop bucket add apiaxess https://github.com/KatrielMoses/scoop-apiaxess
scoop install apiaxess/apiaxess
```

**Windows — installer:** download `APIaxess-<version>-windows-x64.msi` from the
[latest release](https://github.com/KatrielMoses/apiaxess/releases/latest) and run it
(per-user, no admin needed). A Chocolatey package is in community review.

**Linux (Debian/Ubuntu 24.04+):** download `apiaxess_<version>_amd64.deb` from the
[latest release](https://github.com/KatrielMoses/apiaxess/releases/latest), then:

```bash
sudo apt install ./apiaxess_*.deb
```

**Verify a download** against the release's `SHA256SUMS`:

```bash
sha256sum -c SHA256SUMS --ignore-missing          # Linux
```

```powershell
Get-FileHash .\APIaxess-*.msi -Algorithm SHA256   # Windows: compare with SHA256SUMS
```

To build from source instead, see *Run the product* below.

## Architecture at a glance

- Rust owns the trusted engine, orchestration, plugin host, proxy core, pipeline,
  and artifact emitters.
- A TypeScript local web UI is built separately and served by the Rust process.
- Target support and discovery brains have separate plugin seams under `plugins/`.
- The canonical model retains per-fact candidates, provenance, merge semantics,
  recomputable confidence inputs, schema samples, and versioned durable JSON.
- One Protobuf contract spans trusted Rust, WASM/WASI, and process-RPC plugins
  with explicit handshake, permissions, host capabilities, and resource limits.
- A session owns the engagement scope, API document, append-only action audit,
  and opaque future-workbench slot in one versioned durable JSON artifact.
- Scope is advisory and honest: every action records its classification;
  outside-scope work warns but is never blocked or presented as attested.
- Stable structured diagnostics always carry what happened, why, the exact fix,
  and typed context for GUI, logs, audit, and future integrations.
- Mature security tools and sandboxes are always orchestrated behind adapters;
  they are never reimplemented or invoked directly from feature code.
- Host capabilities are explicit and tiered. Unsupported work reports why and
  what rung is available; it never silently disappears.

Start with [the architecture index](docs/architecture/README.md) and
[the repository map](docs/architecture/repository-map.md).

## Run the product

Prerequisites: Rust 1.88+, Node.js 22+, and pnpm 11+.

```text
pnpm install --frozen-lockfile
pnpm ui:build
cargo run -p apiaxess
```

Open `http://127.0.0.1:7777`. The same process owns the session proxy at
`127.0.0.1:8080`; captured traffic feeds the live GUI queue and session SQLite
store, and that listener is also the resend/fuzzer transport. Both listeners
are loopback-only. Override them with `APIAXESS_GUI_ADDRESS` and
`APIAXESS_PROXY_ADDRESS`; non-loopback values are rejected. Declare comma-separated
exact hosts or `*.domain` suffixes with `APIAXESS_ALLOWED_TARGETS` for advisory
scope classification. The GUI shows live traffic, pipeline progress,
diagnostics, and the read-only unified API surface.

The CLI/API are the v1 analysis entry points. Run a static analysis and persist
the session, then inspect or export its result:

```text
apiaxess analyze path/to/app.apk --static-only --output session.json --allow-target api.example.com
apiaxess inspect session.json
apiaxess export session.json --format all --out artifacts/
```

The local API provides the corresponding session, pipeline status/surface, and
export routes under `/api/v1/`. `POST /api/v1/pipeline` starts a run,
`GET /api/v1/pipeline/{run_id}` reports progress, `GET
/api/v1/pipeline/{run_id}/surface` retrieves the completed surface, and
`POST /api/v1/export` writes selected artifacts. All actions are session-scoped
and recorded in the durable audit trail; scope warnings are advisory and never
block an action.

Release boundary: static analysis and the assembled downstream surface are
available on the Windows path. Dynamic breadth across Flutter, Xamarin/.NET,
hardened/RASP, native-Linux redroid, and remote-offload environments remains
environment-gated validation; the product reports those host-capability limits
instead of implying coverage. Real packed-sample protection true positives are
also pending authorized samples, as recorded in
[the verification manifest](docs/protection/corpus/verification-manifest.toml).

The proxy creates a fresh in-memory session CA and never installs it in the host
system store. HTTPS browser trust is E2E-verified on Linux with Firefox 154.0.1
and the current Ubuntu `libnss3-tools` certutil. On Windows, the same
disposable Firefox/NSS mechanism is implemented and guarded, but requires a
user-provided current Mozilla NSS `certutil` with modern SQL database support
(NSS 3.14.0 or newer; do not use legacy 3.12.x archives). APIaxess probes that
the tool can create and reopen Firefox's
`cert9.db`/`key4.db` format before provisioning. Set `APIAXESS_NSS_CERTUTIL` to
the Mozilla executable when it is not the first `certutil` found on `PATH` —
Windows' built-in `certutil.exe` is not the NSS tool. The exact workflow is described in
[the browser trust matrix](docs/workbench-proxy/browser-trust.md). Override the
development asset directory with `APIAXESS_GUI_DIR`; native packages resolve the
immutable GUI under `share/apiaxess/gui/` relative to the installed executable.

Traffic capture is committed to the per-session SQLite store as flows arrive.
The complete canonical session JSON is committed on explicit save, clean
shutdown, and analysis-document stage commits. Between those larger writes, a
versioned compact `*.checkpoint.json` sidecar is marked dirty after every
structured session mutation and flushed on a two-second cadence; it contains
scope, audit, sandbox, and pipeline metadata but
does not duplicate the potentially 100 MB+ evidence document or SQLite traffic.
Opening a session applies a newer valid checkpoint over the full artifact and
keeps the existing SQLite store. A hard kill can therefore lose only the
mutation currently in flight, up to two seconds of accepted metadata, or
external-tool work that has not yet produced a session mutation. It does not
guarantee recovery of an instruction interrupted
between its side effect and its checkpoint.

## Launch modes and headless serve

The same engine backs three front-ends — pick by how you want to view it, not by
what is reachable:

- **Native desktop app.** The installed product launches `apiaxess-desktop`, a
  native window (Tauri) hosting the branded GUI against the local engine. On the
  first launch a small chooser asks *Desktop app* vs *Open in browser*; the choice
  is remembered. Re-prompt with `apiaxess-desktop --choose`, or force a mode with
  `APIAXESS_LAUNCH_MODE=desktop|browser`.
- **Browser mode.** The chooser's "Open in browser" starts the engine, opens your
  default browser at its URL, and keeps a small control window open — closing it
  stops the engine.
- **Headless serve.** For VMs, servers, and LTS hosts with no desktop:

  ```text
  apiaxess serve --port 7777
  ```

  This runs the engine and serves the GUI + API on the port until `Ctrl-C`
  (graceful shutdown) — no native window, no browser launched. It prints the URL;
  open it from a browser. This is the deployment mode used on headless test hosts.

  **Accessing the port.** `serve` binds loopback (`127.0.0.1`) by default. To reach
  it from another machine, the recommended path is an SSH tunnel
  (`ssh -L 7777:127.0.0.1:7777 host`), which also keeps the browser origin on
  loopback — the live control/telemetry WebSocket requires the loopback origin.
  You may instead bind a routable address as a **deliberate** exposure:

  ```text
  apiaxess serve --host 0.0.0.0 --port 7777
  ```

  This prints a warning and is your responsibility to secure (firewall/VPN);
  APIaxess is a local-bind-by-default tool and never exposes itself implicitly.

## Packaging & reproducible builds

The per-user x64 MSI (no elevation required) and the Debian `.deb` are built from the
inputs under `packaging/`. Reproducible build instructions, the private Node/pnpm
runtime policy, and the installed-product verification command are documented in
[Windows MSI packaging](packaging/windows/README.md) and
[Debian packaging](packaging/debian/README.md). Bundled tools are fetched and
SHA-256-verified at build time; the optional dynamic-analysis Android runtime is a
separate download, not part of the base installer.

## Verify boundaries

```text
cargo xtask boundaries
cargo xtask contracts
cargo xtask foundations
cargo test --workspace
pnpm ui:check
pnpm ui:build
```
