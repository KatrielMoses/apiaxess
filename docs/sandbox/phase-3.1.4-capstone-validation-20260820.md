# Phase 3.1.4 — Tusky capstone validation

Validation ran from the WSL-native checkout `/home/katriel/APIaxess-tusky-linux`
against the Tusky APK and the pinned HQarroum `api-33` image
`sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`.

## Observed result

- Stage 1 passed: the APK was resolved and classified as `Tier1StockR8`.
- Stage 2 passed: `networking_present=true`, the expected networking libraries
  were detected, `endpoints=0`, `loose_findings=7163`, `handoffs=4`,
  `static_diagnostics=7178`.
- Stage 3 preflight passed: `runnable=true diagnostics=[]`.
- The former hardcoded patch-floor rejection did not occur. The runtime trust
  evaluator accepted the image posture as `allow_with_findings` under the
  loopback-only, key-authenticated, ephemeral ADB profile.
- Stage 3 later stopped at the pre-existing HQarroum system-preparation probe:
  `sandbox.hqarroum-system-not-writable` (`system CA write probe exited with
  Some(1)`). This is separate from runtime-trust evaluation and prevented the
  install and later dynamic stages from running.

The capstone test returned failure because of that CA/remount boundary, not
because of the old Android patch level. The test's intake teardown ran and the
WSL container and intake directory were removed after the run.

