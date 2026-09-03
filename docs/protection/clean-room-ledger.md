# Clean-room protection detector ledger

This ledger is the gate for every enabled protection signature. The detector
does not import, inspect, or derive from GPL-licensed rule databases or source.
Entries are limited to independently recorded structural facts from the
in-house fixture corpus and permissively licensed reference documentation.

The entries below are clean-room implementation evidence. They establish what
each signature looks for; they do not claim that a commercial packer has been
observed in a real APK. Real-sample verification is tracked separately in
[`corpus/verification-manifest.toml`](corpus/verification-manifest.toml), and
the coverage table below is the Phase 7.4 release-state summary.

The checked-in corpus fixture is intentionally small and reviewable. Production
sample APK hashes and byte offsets must be added here before a new signature is
enabled; an unlogged signature is rejected by the detector seam.

| Signature ID | Signal class | Corpus sample | Sample hash | Byte offset | Independent source | License/provenance |
| --- | --- | --- | --- | ---: | --- | --- |
| `r8.compiler-marker` | compiler marker | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 192 | Android Open Source R8/D8 documentation | BSD-3-Clause/AOSP; marker independently recorded |
| `jiagu.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 219 | in-house structural corpus fixture | in-house clean-room observation |
| `legu.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 257 | in-house structural corpus fixture | in-house clean-room observation |
| `bangcle.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 303 | in-house structural corpus fixture | in-house clean-room observation |
| `aliprotect.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 346 | in-house structural corpus fixture | in-house clean-room observation |
| `ijiami.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 394 | in-house structural corpus fixture | in-house clean-room observation |
| `dexprotector.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 438 | in-house structural corpus fixture | in-house clean-room observation |
| `baidu.native-loader` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 496 | in-house structural corpus fixture | in-house clean-room observation |
| `android.dynamic-loader` | dynamic loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 546 | Android `InMemoryDexClassLoader` API reference | Android Developers content license |
| `android.native-loader-api` | native loader | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 626 | Android `System.loadLibrary` API contract | Android SDK permissive reference |
| `payload.opaque-asset` | opaque payload | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 653 | in-house structural corpus fixture | in-house clean-room observation |
| `rasp.integrity-marker` | packing/RASP | `structural-signatures-v1.txt` | `sha256:DFAC64646E0373F5D4C4F561471164ACAB15ED72B6D46201D542B6023AD7580B` | 708 | permissively licensed academic protection literature | CC-BY research reference |

The fixture hash and exact byte offsets above are verified against the checked-in
structural corpus. Those offsets are synthetic corpus observations, not offsets
from commercial-packed APKs. No positive commercial-packer sample is checked in
or referenced by this checkout as of 2026-08-26.

## Phase 7.4 real-sample coverage

This is an authorization-first inventory. `Pending` means the signature is
implemented from clean-room structural understanding, but no authorized real
sample was available in this validation environment. It is not a claim that the
packer can never be sourced. No unvetted sample repository was admitted merely
to turn a pending row green.

| Packer signature | Status | Real sample / reason | Positive evidence |
| --- | --- | --- | --- |
| `jiagu.native-loader` / 360 Jiagu | **Pending** | No authorized Jiagu SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `legu.native-loader` / Tencent Legu | **Pending** | No authorized Legu SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `bangcle.native-loader` / Bangcle SecShell | **Pending** | No authorized Bangcle SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `aliprotect.native-loader` / Alibaba Aliprotect | **Pending** | No authorized Aliprotect SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `ijiami.native-loader` / iJiami | **Pending** | No authorized iJiami SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `dexprotector.native-loader` / DexProtector | **Pending** | No authorized DexProtector trial/license output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |
| `baidu.native-loader` / Baidu Protect | **Pending** | No authorized Baidu Protect SDK/trial output or research-corpus access was available in this checkout. | None; synthetic structural evidence only |

### Available real-APK control

The authorized Feeder F-Droid APK is a reproducible unpacked negative control,
not a packed positive sample. On 2026-08-26, detector version `clean-room-1`
scanned the APK through the normal bounded static-archive corpus path. SHA-256
is `1066f08e9e773fe0a5a4cd35d8e308634d8c4fbe9d3390be0095cbdaf0a39c`; no named
commercial-packer marker or identity was produced. Generic signals were found
at the archive members recorded in the manifest, so this control must not be
described as “no signals”; it specifically establishes no named-packer false
positive for this fixture.

Reproduce it with:

```text
cargo test -p apiaxess-protection-detector checked_in_feeder_fixture_is_a_reproducible_unpacked_negative_control -- --nocapture
```

To add a positive sample, use a self-packed authorization-clean app first. If a
licensed/corpus sample cannot be committed because of size or licensing, keep
it outside the repository, record its stable path or obtain-instructions,
SHA-256, packer/version, matched archive members and markers, verification date,
and access basis in `corpus/verification-manifest.toml`. A sample becomes
`Verified` only after the detector output and the authorization record are both
reproducible.

Safe references used for the process include the [AOSP R8/D8 repository](https://android.googlesource.com/platform/external/r8/), the [Android D8 documentation](https://developer.android.com/tools/d8), and the [Android InMemoryDexClassLoader API](https://developer.android.com/reference/dalvik/system/InMemoryDexClassLoader).
