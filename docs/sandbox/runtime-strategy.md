# Native-host runtime strategy and redroid control contract

Phase 3.1.1 fixes the host/runtime decision at the existing
`SandboxBackend` boundary. The planner reports a default, an optional fast
tier, and a secured fallback; it does not silently substitute one isolation
model for another.

## Selection matrix

| Host posture | Default | Optional fast tier | Fallback |
|---|---|---|---|
| Native Linux with usable AVD acceleration | AVD | redroid, when Docker privileged mode and binder/ashmem-or-memfd are confirmed | remote-offload |
| Native Windows x86_64 with Docker, host ADB, and WHPX | HQarroum-backed AVD | none | remote-offload |
| Windows 11 + WSL2 with Docker and writable `/dev/kvm` | HQarroum-backed AVD | none | remote-offload |
| Native Windows x86_64 with AEHD only | HQarroum-backed AVD with transitional warning | none | remote-offload |
| Windows Home, Windows-on-ARM, missing nested KVM, or TCG fallback | remote-offload | none | remote-offload |
| Linux with no usable AVD acceleration but a valid redroid contract | remote-offload | redroid | remote-offload |

The AVD path is the digest-pinned, headless HQarroum image. It passes
`/dev/kvm`, starts with `EXTRA_FLAGS=-writable-system` and `SKIP_AUTH=false`,
and rejects a lease unless the container demonstrates an active KVM VM/vCPU
descriptor. Linux capability detection verifies readable/writable `/dev/kvm`;
Windows probes WSL2 when present and uses WHPX as the durable native path while
treating AEHD as transitional. VM detection is supplemental guidance and never
relies on a CPUID-only gate.

redroid is native-Linux-only. Its preflight requires Docker, a verified
privileged-container capability, and binder/binderfs plus ashmem or a kernel
with the required memfd floor. Windows Docker Desktop is not treated as a
redroid host.

## Host-side ADB contract

The redroid backend does not assume an ADB client exists inside the official
container image. For each lease it:

1. creates a lease-scoped host `adbkey`;
2. starts the privileged container with Docker's published port set to
   `127.0.0.1::5555`, allowing Docker to allocate an ephemeral host port;
3. obtains the published port using `docker port` and rejects anything other
   than `127.0.0.1:<port>`;
4. connects the host ADB client with the lease key, waits for
   `sys.boot_completed=1`, and verifies the Android security patch level;
5. exposes only the host ADB control object to the lease; and
6. disconnects ADB and removes the container, named volume, and key during
   teardown.

There is no `0.0.0.0` bind and no unauthenticated raw ADB fallback. The
wireless-ADB mitigation floor is an Android security patch level of
`2026-05-01` or later, corresponding to the CVE-2026-0073 fix. If the patch
level or host-key authentication cannot be verified, startup fails with a
distinct diagnostic. The HQarroum AVD path additionally performs the
userdebug/root/remount/reboot/remount and CA-directory write sequence before
returning a lease; teardown removes the container and both lease key files,
with no persistent writable volume or snapshot.

This change fixes the code-level F36-REDROID-001 contract. Native Linux image,
kernel, boot, and real-app validation remain environment-gated Phase 3.6 work.
