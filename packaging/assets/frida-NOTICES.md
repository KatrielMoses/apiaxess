# APIaxess bundled Frida notices

APIaxess embeds **Frida** as a linked library (`frida-core`, via the first-party
Rust bindings) and bundles the device-side `frida-server`. Both are **unmodified**
official upstream releases, pinned by SHA-256 in `frida.toml` and recorded in
`frida-sbom.json`.

## License — wxWindows Library Licence, Version 3.1

Frida is distributed under the **wxWindows Library Licence 3.1** — LGPL-2.1 with
a binary/static-linking exception. The exception explicitly permits linking the
library into a program (including a proprietary or differently-licensed product)
and distributing that program under the program's own terms, provided:

- the Frida library itself is not modified (APIaxess ships it unmodified), and
- its license and notices travel with the distribution (this file), and
- access to the Frida source is not obstructed.

The upstream Frida source is at <https://github.com/frida/frida>. APIaxess does
not obstruct access to it; the exact pinned version is recorded in `frida.toml`
and `frida-sbom.json`.

This is one of the two non-trivial licenses in the bundle (the other is the
OpenJDK GPLv2+CE). The static-link exception makes commercial bundling
straightforward, but a counsel skim before release is prudent.

## Version alignment

`frida-core` (host devkit, linked into the Rust backend), the `frida` Rust crate
(`frida-embedded` feature), and the device-side `frida-server` are all pinned to
the **same** Frida release; they must match to interoperate.
