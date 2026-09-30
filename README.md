# APIaxess

**See what an app actually talks to.** Point APIaxess at a web app or an Android APK and it recovers the
app's real, reachable API surface — from the traffic it makes and the code it ships — then lets you
resend, fuzz, and export it. Zero setup, everything bundled, runs entirely on your machine.

[Website](https://apiaxess.dev) · [Download](#install) · [License](LICENSE) · [Security](SECURITY.md)

## The problem

Mapping an app's API is mostly setup. You stand up a proxy, install a CA, fight cert pinning, decompile
the APK by hand, spin up an emulator, and glue a pile of tools together — and after all that you still
can't be sure you've actually seen everything the app hits.

## What it does

Give it a target. It captures and analyzes, then hands you **one honest API surface** — every endpoint,
labeled by evidence (confirmed vs. inferred) and first/third-party, with the coverage it *couldn't*
confirm shown plainly instead of guessed at.

- **Web** — a bundled browser through a MITM proxy: HTTP/1.1 & 2, WebSocket, SSE, gRPC-Web, GraphQL.
- **Android** — unpack and decompile statically, drive the app in a bundled emulator, capture the live
  traffic, and fuse both into one surface.
- **Work it** — Resend (Repeater, cleaner), Fuzz (Burp-Intruder-class), Intercept.
- **Export** — OpenAPI 3.1, Postman, HAR, and a runnable Python (httpx) SDK.

Everything it needs is bundled — Chromium, a Java runtime, apktool, jadx, ffuf, Frida, an Android
emulator — so there's nothing to install and wire up. It all runs on `127.0.0.1`; the only thing it ever
sends out is an optional update check you can turn off.

## Demo

<!-- placeholders — drop the GIFs at docs/demo/*.gif (see docs/demo/README.md) -->

| Web capture → surface | Fuzz |
| --- | --- |
| ![Web capture to API surface](docs/demo/web-capture.gif) | ![Fuzz workbench](docs/demo/fuzz.gif) |
| **Android target** | **Export** |
| ![Drivable Android target](docs/demo/android.gif) | ![Export formats](docs/demo/export.gif) |

## Install

Windows and Linux today (macOS is on the way). Builds are **unsigned for now** — verify the published
**SHA-256 checksums**; on Windows the first run shows SmartScreen's "unknown publisher → Run anyway".

**Windows**

```bash
scoop bucket add apiaxess https://github.com/KatrielMoses/scoop-apiaxess
scoop install apiaxess/apiaxess
```

…or `choco install apiaxess`, or grab the MSI from [apiaxess.dev](https://apiaxess.dev).

**Linux (Debian/Ubuntu)**

```bash
sudo apt install ./apiaxess_*.deb
```

Downloads and checksums are at [apiaxess.dev](https://apiaxess.dev) and on the
[releases page](https://github.com/KatrielMoses/apiaxess/releases/latest). The app updates itself
(optional, identifier-free — turn it off in Settings).

## Build from source

Rust 1.88+, Node 22+, pnpm 11+.

```bash
pnpm install --frozen-lockfile
pnpm ui:build
cargo run -p apiaxess
```

Then open `http://127.0.0.1:7777`. Start with [architecture.md](architecture.md) and
[docs/architecture/](docs/architecture/) for the lay of the land.

## Where things live

- `apps/` — engine (`apps/engine`), desktop shell (`apps/desktop`), the GUI (`apps/gui`), Android client.
- `crates/` — the Rust engine: proxy, analysis pipeline, workbenches, exporters.
- `plugins/` — target support (APK).
- `packaging/` — MSI, `.deb`, Scoop, Chocolatey.

## Honest by design

Local-first: the engine, capture proxy, and session store all run on loopback. No telemetry, analytics,
or license calls — just one optional, identifier-free update check (a plain GET of a static file on
apiaxess.dev, served via Cloudflare like any website), which you can switch off. Scope is advisory: it
records and warns, and never silently authorizes more than you told it to.

## Contributing & security

PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability? Please report it privately
via [SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).
