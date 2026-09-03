# Phase 3.1.2.1 — Writable-system CA sequence validation

The pinned HQarroum API-33 image was tested from the WSL-native checkout with
`EXTRA_FLAGS=-writable-system` and digest
`sha256:0804f0c30234db0fb711910c569f13312bc3cfa354cb66c8e0db6a4e66edfb95`.

## Image-level validation

The image reported that `adb remount` would disable verity and require a
reboot. The explicit sequence was then verified successfully:

1. `adb root`;
2. `adb disable-verity`;
3. reboot and wait for `sys.boot_completed=1`;
4. `adb root`;
5. `adb remount`;
6. verify `/system/etc/security/cacerts` with `test -w` and an actual `touch`.

The resulting mount was an `overlay` mount with `rw` status. Both the
writability and touch probes returned exit code 0.

## Capstone validation

The WSL Tusky capstone then completed Stage 3:

- Stage 2 completed with the previously observed static result;
- Stage 3 preflight reported `runnable=true diagnostics=[]`;
- Stage 3 sandbox startup passed;
- Tusky installed successfully as a single APK;
- Stage 7 runtime and intake teardown both returned `Ok(())`.

The harness's later traffic stages are intentionally outside this capstone
test. The trust-provisioning code now uploads the CA in DER form, verifies
presence and exact content, checks `0644 root:root` metadata, and verifies the
system cacerts SELinux label for the writable-system path.

