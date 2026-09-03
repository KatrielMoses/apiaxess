# APIaxess bundled ffuf notices

APIaxess bundles the **unmodified** official ffuf release binary per platform and
invokes it by absolute path. The exact version, archive SHA-256, and the
per-file SBOM are generated beside the installed binary and bound to `ffuf.toml`.

ffuf is distributed under the **MIT License** — clean to redistribute. The
upstream `LICENSE` from the release archive travels with the payload in
`tools/ffuf/` and is the authoritative notice for the bundled binary.

ffuf's "sponsorware" model grants sponsors 30-day early access to some features;
it does **not** affect redistribution of released binaries, which are MIT.

The Linux binary is a statically-linked Go build (`CGO_ENABLED=0`) with no
program interpreter or dynamic library dependencies; `fetch-ffuf.ps1` verifies
this at packaging time.
