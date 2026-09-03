# Protection sample corpus

This directory holds the Phase 7.4 sample-verification record. The detector's
clean-room implementation evidence remains in
[`../clean-room-ledger.md`](../clean-room-ledger.md); it is not the same thing
as verification against a real commercial-packed APK.

## Current state

There are no positive commercial-packer samples in this checkout. The only
real APK admitted to the protection verification record is the project-
designated Feeder F-Droid fixture:

`fixtures/capstone/feeder-2.22.0-4050.apk`

It is an authorization-clean, unpacked negative control with SHA-256
`1066f08e9e773fe0a5a4cd35d8e308634d8c4fbe9d3390be0095cbdaf0a39c`; it is not
evidence that any commercial packer signature is correct. Its detector output
and the seven pending packer rows are in
[`verification-manifest.toml`](verification-manifest.toml).

The APKM and other artifacts under the capstone history are not promoted into
this corpus: their protection provenance and authorization basis are not
recorded as positive packer samples. Build output under `target/` is never a
corpus source.

## Authorization-first addition procedure

1. Pack the Feeder app or a throwaway app owned by the project with an
   authorized SDK/trial. Preserve the exact input APK, packer name/version,
   license or trial basis, and pack command outside the detector source tree.
2. If self-packing is unavailable, use only a research corpus for which the
   project has accepted the access agreement. Record the corpus/sample ID and
   access basis. Do not copy samples from unvetted “packed APK” repositories.
3. Keep a sample under `fixtures/protection/samples/` only when its license,
   redistribution permission, and size permit it. Otherwise keep it in a
   separately provisioned local corpus and record exact obtain/place
   instructions in the manifest; never substitute a path in `target/`.
4. Record the SHA-256, packer/version, detector version, verification date,
   expected signature, and the archive member paths plus marker strings that
   produced the signal. A positive claim also needs a clean unpacked or
   different-packer control where available.
5. Run the detector through the normal normalized static-archive path and
   review the result. Change the status to `verified` only when the sample is
   authorized and the expected signature fires; if it misses or misfires,
   fix the clean-room signature from the sample's independently observed
   structure and document the change before re-verifying.

The manifest intentionally records `pending` rather than inferring coverage
from the synthetic structural-signature fixture. This is the release-facing
truth: seven commercial signatures are implemented, zero have real positive
sample verification in the current environment, and the negative-control run
is reproducible with:

```text
cargo test -p apiaxess-protection-detector checked_in_feeder_fixture_is_a_reproducible_unpacked_negative_control -- --nocapture
```
