# APIaxess bundled Android tools notices

APIaxess bundles two **unmodified** upstream Android analysis tools and runs
both through the shared trimmed OpenJDK runtime. The exact versions, archive
SHA-256 values, and the per-file SBOM are generated beside the installed tools
and bound to `apk-tools.toml`.

## apktool

apktool is distributed under the **Apache License 2.0**. It bundles its own
per-OS native `aapt`/`aapt2` inside its jar and extracts them at runtime; those
native components carry their own notices within the jar. The bundled artifact
is the unmodified upstream executable jar.

## jadx

jadx itself is distributed under the **Apache License 2.0**. However, the jadx
**distribution** ships third-party dependencies with mixed licenses and notices,
including LGPL/EPL logback logging components. The payload is therefore **not**
labeled merely "Apache."

The complete upstream `LICENSE`/`NOTICE` files that ship inside the jadx
distribution **must** be preserved in the installed `tools/jadx` tree; they are
the authoritative notice set for jadx and its distributed dependencies. A
version-locked license/SBOM scan of the pinned jadx release is recorded in
`apk-tools-sbom.json`.

## Legal review note

The GPLv2+CE OpenJDK runtime (see the shared Java runtime notices) and the jadx
mixed distributed-dependency notices are the only non-trivial licensing items in
this payload. The unmodified-bundle posture — ship the binaries, keep every
upstream notice, modify nothing — keeps redistribution straightforward, and is
worth a counsel skim before release.
