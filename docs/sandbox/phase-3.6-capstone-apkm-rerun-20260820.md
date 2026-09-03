# Phase 3.6 capstone APKM rerun — 2026-08-20

## Headline

The full dynamic-tier claim is **not closed by this rerun**. The stable
artifact and local prerequisites were present, and the previous 1.1 GB
SignatureCorpus retention defect did not reproduce: the Rust static process
stayed roughly 16–30 MiB while traversing the unpacked app. The run was
stopped after an extended Windows filesystem-bound static pass before the
harness returned its static report. No emulator container was started, so no
traffic, pinning, dynamic-model, or teardown claim is made.

Artifact: C:\APIaxess\fixtures\capstone\play-store.apkm
SHA-256:
C887883291FDAB8722014CE506E5A20D2CC153FB78391D62F0D3CE524298525B

## Environment evidence

- WSL2 Ubuntu: Linux 6.18.33.2-microsoft-standard-WSL2
- WSL Rust: rustc 1.88.0, cargo 1.88.0
- /dev/kvm: present as root:kvm, mode 660
- Docker Desktop: Linux engine 29.0.1 on the WSL2 kernel
- jadx: bundled 1.5.5
- apktool: 2.9.3
- HQarroum image present at the previously validated digest
  sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95

## Stage evidence

| Stage | Result | Observed evidence |
|---|---|---|
| 1. Intake and resolution | **Incomplete in final retry** | Content-based APKM intake ran the toolchain successfully enough to materialize all 29 split workspaces and 130,000+ output files. The harness did not return the normalized artifact summary before the bounded run was stopped, so the final retry does not claim a completed intake handoff. |
| 2. Static discovery | **Finding: bounded but not completed** | jadx produced the large base source tree. Protection detection, routing, and extraction used bounded per-document reads; the Rust process remained approximately 16–30 MiB. The Windows filesystem traversal remained operationally slow and did not return an API map, library list, protection roll-up, or committed static handoff during the run. |
| 3. Sandbox install | **Not run** | The harness never reached sandbox startup after the static stage. |
| 4. Traffic routing and CA trust | **Not run** | No emulator lease or installed app existed in this rerun. |
| 5. Pinning bypass | **Not run** | No app process reached an instrumentation lane. |
| 6. Dynamic capture/model | **Not run** | No real traffic or dynamic facts were produced; scope-gate behavior was not observed in this run. |
| 7. Teardown | **Pre-emulator cleanup only** | No container, emulator CA, app install, port lease, or dynamic session was created. The generated intake workspaces remain untouched because the shell safety policy rejected the recursive cleanup command. |

## Fixes made during the rerun

- External tool capture now gives noninteractive child processes null stdin,
  fixing the Windows apktool.bat version-probe pause.
- ProtectionCorpus now retains metadata only, reads one document at a time,
  caps a document at 16 MiB, and reports deferred read/size failures.
- Built-in protection marker signatures share one streaming corpus pass.
- SignatureCorpus caches marker hit vectors so detector-specific searches do
  not reread the complete unpacked tree.

## Validation

- cargo test --workspace: passed; the real capstone integration test remains
  ignored by default.
- cargo test --workspace --doc: passed.
- cargo check --workspace --all-targets: passed.
- Focused routing, protection, extraction, external-tool, and APK-target tests
  passed.

## Carry-forward

The next capstone attempt should use a Linux-native materialized intake/tree
or an indexed static scan path before asserting the emulator stages. The
Hermes/native-Linux breadth, Flutter/Xamarin/hardened targets, alternate
pinning implementations, remote offload, and unclean teardown remain
environment-gated and unvalidated here.
