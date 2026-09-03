# ADR 0005: Packaging and asset delivery

**Status:** accepted as packaging direction

## Goal

APIaxess ends as a clean native install: APT/`.deb` on Linux and MSI or a native
installer on Windows. The package contains the Rust binaries, built GUI assets,
licenses, configuration defaults, and adapter metadata. It does not contain
Android system images or other heavyweight, update-heavy assets.

## Asset policy

Heavy assets are content-addressed and downloaded on first use or explicit
preparation. A future asset manager verifies publisher metadata, cryptographic
digests/signatures, compatibility, disk space, and resumable download state before
atomic activation. Multiple versions may coexist and are garbage-collected only
with explicit retention policy. These mechanics are not implemented in 0.1.

GUI assets are small and ship with the native package. Development uses
`APIAXESS_GUI_DIR`; the native engine resolves installed GUI assets from
`share/apiaxess/gui/` relative to its executable without changing the API server.
The Windows MSI implements this layout today; a future `.deb` must preserve the
same conceptual `bin/` and `share/apiaxess/gui/` split.

## Optional runtimes

Static analysis and the workbench do not require Docker. The dynamic tier probes
Docker only when a selected local sandbox backend requires it. The binary handles
container lifecycle transparently. The alternative remote backend has equal
standing and does not require local Docker.

The `packaging/` tree is separated by platform and from `assets/`, preventing
installer scripts, downloaded images, or runtime state from leaking into engine
crates. Runtime state will use platform-appropriate data/cache directories, never
the installation directory.
