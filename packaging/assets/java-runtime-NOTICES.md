# APIaxess shared Java runtime notices

APIaxess bundles one shared Java runtime built from an **unmodified** Eclipse
Temurin (Adoptium) OpenJDK release, trimmed with that JDK's own `jlink`. The
exact release, archive SHA-256, the module set, the `jlink` flags, and the
per-file SBOM are generated beside the installed runtime and bound to
`java-runtime.toml`.

OpenJDK is distributed under the **GNU General Public License, version 2, with
the Classpath Exception** (GPLv2+CE). Bundling an unmodified runtime and
retaining its notices keeps this in "ship the binary, keep the notices"
territory: APIaxess does not modify the runtime, and the upstream legal notices
travel with it.

The trimmed image emitted by `jlink` contains a `legal/` directory with the
per-module upstream notices. That directory **must** be preserved in the
installed runtime; it is the authoritative notice set for the bundled OpenJDK.
The `release` file inside the image records the exact OpenJDK version and the
included modules.

The Classpath Exception permits APIaxess to invoke and link against this runtime
as a private application component without the rest of APIaxess becoming subject
to the GPL. The runtime is invoked only by absolute path as a bundled component;
it is never a modified derivative work.
