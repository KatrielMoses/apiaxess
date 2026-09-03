# Diagnostic catalogue

This is the human-readable index of stable diagnostic IDs. Code definitions in
`apiaxess_diagnostics::catalogue` are normative. Later phases add entries before
shipping an anticipated failure and include typed occurrence context plus a
catalogue test.

| Stable ID | Category | Meaning |
| --- | --- | --- |
| `scope.outside-declaration` | authorization scope | Concrete action target matches no allowed-target rule; warn and record, never block. |
| `scope.assessment-undetermined` | authorization scope | Target identity is insufficient for a reliable scope comparison; warn and record. |
| `host-capability.requirement-unsatisfied` | host capability | Required host capability is degraded, unavailable, or unknown; context names evidence, remedy, and fallback. |
| `plugin-capability.permission-denied` | plugin capability | Plugin grant is absent or narrower than the requested permission scope. |
| `session.invalid-transition` | session | Caller requested a lifecycle edge other than created-to-active or active-to-closed. |
| `session.invariant-failed` | session | Session, scope, audit, lifecycle, or workbench-slot structure is invalid. |
| `session.api-model-invalid` | data model | Embedded 0.2 API document version or invariant is invalid. |
| `persistence.session-format-unsupported` | persistence | Reader does not support the exact durable session version. |
| `persistence.session-json-invalid` | persistence | Session artifact cannot be encoded or decoded as canonical JSON. |
| `persistence.session-unknown-fields` | persistence | Reading would silently discard fields unknown to this build. |
| `artifact.unsupported-format` | external tool | Input is not a supported APK, AAB, APKS, APKM, XAPK, or split-ZIP route. |
| `artifact.malformed-archive` | external tool | Archive is corrupt or contains an unsafe extraction path. |
| `artifact.bundle-resolution-failed` | external tool | AAB/APKS could not resolve to valid installable APKs. |
| `external-tool.missing` | external tool | Required executable is absent or cannot start. |
| `install.component-missing` | external tool | A bundled runtime component APIaxess ships (Java runtime, apktool, jadx, or ffuf) is missing or corrupt; reinstall. |
| `external-tool.version-incompatible` | external tool | Detected executable is below the adapter minimum. |
| `external-tool.invocation-failed` | external tool | Tool exited, timed out, or returned an unusable result. |
| `artifact.unpack-failed` | external tool | apktool did not produce complete authoritative output. |
| `artifact.decompilation-failed` | external tool | jadx did not produce its convenience source tree. |
| `artifact.decompilation-partial` | external tool | jadx finished with errors; its Java source tree is partial (best-effort, supplementary to authoritative apktool smali). |
| `artifact.dex-access-unavailable` | external tool | No DEX parser handoff could be established. |
| `artifact.protection-unhandled` | external tool | Protection was detected but is not handled downstream. |
| `artifact.protection-detector-unavailable` | external tool | The in-house protection detector could not provide a result. |
| `artifact.protection-detected` | static analysis | The clean-room detector identified a protection system. |
| `artifact.protection-suspected` | static analysis | Protection is suspected but did not meet the orthogonal identity gate. |
| `artifact.protection-heavy` | static analysis | Quantified protection signals materially limit static recovery. |
| `artifact.protection-ledger-gap` | static analysis | A signature was rejected because its clean-room provenance ledger is incomplete. |
| `intake.resolution-unavailable` | sandbox | The normalized artifact could not be routed to an install strategy. |
| `intake.base-only-splits-missing` | sandbox | A base APK required ABI/density splits that were not supplied. |
| `intake.split-set-incomplete` | sandbox | A supplied split set was present but did not match its base APK. |
| `intake.no-matching-abi` | sandbox | The package has no native ABI matching the selected emulator. |
| `intake.android-api-too-old` | sandbox | The package requires a newer Android API level than the runtime. |
| `intake.signature-invalid` | sandbox | Package signature or APK verification failed. |
| `intake.storage-insufficient` | sandbox | The runtime lacks enough storage for installation. |
| `intake.install-failed` | sandbox | A resolved package set was rejected after installer-signal translation. |
| `networking.usage-unidentified` | static analysis | Generic networking usage was detected without a reliable supported-library identity. |
| `networking.protection-obscures-map` | static analysis | Protection metadata indicates that static networking localization may be incomplete. |
| `networking.artifact-location-unavailable` | static analysis | A normalized smali, source, or DEX location needed for routing is unavailable. |
| `networking.signature-ambiguous` | static analysis | A library signature is present but its structural localization is ambiguous. |
| `extraction.partial-recovery` | static analysis | Bounded extraction found a call site but runtime composition escaped the supported boundary. |
| `extraction.unbound-string-candidate` | static analysis | A plaintext networking string was retained without endpoint binding. |
| `extraction.loose-findings-filtered` | static analysis | Packaged resource/metadata noise was classified and omitted from loose findings; counts and examples remain in context. |
| `extraction.decoder-deferred` | static analysis | A routed decoder has no Phase 1.3 extractor on this host. |
| `extraction.model-invalid` | static analysis | The assembled extraction document failed canonical API-model validation. |
| `static-pass.dynamic-handoff` | static analysis | Static analysis marked a boundary for dynamic capture. |
| `static-pass.protection-limit` | static analysis | Protection metadata limits the completeness of the static pass. |
| `static-pass.native-logic` | static analysis | Networking logic was identified in native code outside the static pass. |
| `static-pass.coverage-limit` | static analysis | Static coverage is incomplete or silent for part of the target. |
| `proxy.port-in-use` | session | The session-scoped loopback listener could not bind. |
| `proxy.backend-start-failed` | session | The embedded proxy backend failed to start or stay alive. |
| `proxy.session-not-active` | session | Proxy startup was requested outside an active session. |
| `proxy.ca-generation-failed` | session | The ephemeral per-session CA or a leaf certificate could not be generated. |
| `proxy.ca-export-failed` | session | An explicit CA export or purge failed. |
| `proxy.upstream-unreachable` | session | The upstream target could not be reached. |
| `proxy.tls-handshake-failed` | session | A client or upstream TLS handshake failed. |
| `proxy.alpn-mismatch` | session | Negotiated ALPN did not match the requested protocol. |
| `proxy.protocol-unsupported` | session | The embedded proxy backend cannot handle the observed protocol case. |
| `proxy.websocket-http2-unsupported` | session | RFC 8441 WebSocket-over-HTTP/2 was detected; this known limitation is diagnosed explicitly and is not silently treated as supported. |
| `proxy.client-profile-provisioning-failed` | session | A dedicated client profile could not receive the public session CA. |
| `proxy.nss-tool-unavailable` | host capability | NSS certutil is missing or failed to execute; no system-store fallback is attempted. |
| `proxy.nss-version-unsupported` | host capability | NSS certutil is too old or lacks modern `cert9.db`/`key4.db` SQL support for current Firefox. |
| `proxy.browser-platform-unsupported` | host capability | The browser/platform combination has no supported client-scoped trust path. |
| `proxy.browser-profile-unavailable` | session | The isolated browser profile is missing, malformed, or locked by a running browser. |
| `proxy.browser-profile-provisioning-failed` | session | NSS certutil could not import and verify the session CA in the profile database. |
| `proxy.browser-profile-teardown-failed` | critical | The exact session CA or ephemeral isolated profile state could not be removed. |
| `proxy.bundled-browser-launch-failure` | host capability | The verified APIaxess Chromium runtime or its process boundary could not be started. |
| `proxy.cdp-connect-failure` | session | The browser did not publish or accept its loopback DevTools endpoint. |
| `proxy.capture-not-flowing` | session | A launched browser request did not reach the session capture observer. |
| `proxy.teardown-incomplete` | critical | The dedicated browser process boundary or disposable profile was not fully removed. |
| `proxy.trust-purge-failed` | session | A recorded exceptional trust-store install could not be purged. |
| `proxy.live-transport-failed` | session | The live workbench transport failed. |
| `proxy.live-auth-rejected` | session | The live workbench authentication token was rejected. |
| `proxy.live-origin-rejected` | session | The live workbench Origin was rejected. |
| `proxy.intercept-timeout` | session | A paused request reached the live intercept timeout. |
| `proxy.intercept-edit-invalid` | session | A live intercept edit was rejected as malformed. |
| `proxy.telemetry-backpressure` | session | The live telemetry channel shed or coalesced flow updates. |
| `proxy.live-desync` | session | The GUI and engine disagreed about a live intercept action. |
| `proxy.store-open-failed` | persistence | The session traffic store could not be opened. |
| `proxy.store-corrupt` | persistence | The durable traffic store failed its integrity check. |
| `proxy.store-write-failed` | persistence | Captured traffic could not be committed to the durable store. |
| `proxy.store-session-commit-failed` | persistence | Traffic could not be committed to the canonical JSON session. |
| `proxy.har-interchange-failed` | persistence | HAR traffic interchange failed. |
| `proxy.store-resume-failed` | persistence | The traffic runtime could not resume from the canonical session. |
| `proxy.repeater-request-failed` | session | The repeater request was rejected or could not be sent. |
| `proxy.repeater-history-failed` | persistence | The repeater revision could not be saved. |
| `proxy.repeater-outside-scope` | scope | The repeater request targets outside the declared engagement scope. |
| `proxy.repeater-transport-unavailable` | transport | The repeater has no running session proxy transport. |
| `proxy.intruder-ffuf-unavailable` | external-tool | The stateless intruder engine is unavailable. |
| `proxy.intruder-ffuf-failed` | external-tool | The stateless intruder process failed. |
| `proxy.intruder-config-invalid` | session | The intruder attack configuration is invalid. |
| `proxy.intruder-sequence-failed` | session | The stateful intruder sequence stopped before completion. |
| `proxy.intruder-cancelled` | session | The intruder job was stopped. |
| `proxy.intruder-outside-scope` | scope | The intruder attack targets outside the declared engagement scope. |
| `proxy.intruder-persistence-failed` | persistence | The intruder job or result could not be saved. |
| `sandbox.virtualization-unavailable` | host capability | AVD hardware acceleration is unavailable; the diagnostic names the missing provider and remote fallback. |
| `sandbox.hypervisor-driver-missing` | host capability | Windows has neither a usable WHPX platform nor AEHD. |
| `sandbox.docker-unavailable` | host capability | Docker is absent or its daemon cannot be used for redroid. |
| `sandbox.docker-privilege-unavailable` | host capability | The required redroid `--privileged` contract is not available. |
| `sandbox.image-acquisition-failed` | external tool | The on-demand AVD or redroid image could not be acquired or verified. |
| `sandbox.boot-failed` | sandbox | The selected local or remote Android runtime failed during boot. |
| `sandbox.insufficient-disk` | sandbox | The runtime volume lacks the free space the emulator needs to write a fresh userdata image at boot. |
| `sandbox.readiness-timeout` | sandbox | Android did not become boot-complete before the configured deadline. |
| `sandbox.adb-unreachable` | sandbox | ADB could not reach the ready runtime through its approved control channel. |
| `sandbox.remote-unreachable` | sandbox | The encrypted remote sandbox host could not be reached. |
| `sandbox.remote-auth-failed` | sandbox | SSH authentication or strict host-key verification failed. |
| `sandbox.remote-transport-insecure` | critical | Raw unauthenticated ADB or another unsafe remote control path was rejected. |
| `sandbox.teardown-failed` | critical | Runtime processes, containers, volumes, or remote leases could not be removed completely. |
| `sandbox.snapshot-revert-failed` | critical | The AVD clean baseline snapshot could not be restored. |
| `sandbox.session-not-active` | session | A sandbox lease was requested outside an active session. |
| `sandbox.backend-unavailable` | sandbox | The selected tier cannot run and no usable fallback was selected. |
| `sandbox.acceleration-check-failed` | host capability | The emulator's functional KVM/WHPX acceleration probe did not confirm a usable local AVD path. |
| `sandbox.aehd-transitional` | host capability | Windows is using the transitional AEHD accelerator instead of durable WHPX. |
| `sandbox.vm-guidance` | host capability | Supplemental evidence indicates a virtualized or nested host posture; remote-offload is the recommended fallback. |
| `sandbox.redroid-kernel-unavailable` | host capability | Native Linux binder and ashmem/memfd prerequisites for redroid were not confirmed. |
| `sandbox.redroid-windows-unsupported` | host capability | redroid is intentionally unavailable on Windows. |
| `sandbox.redroid-adb-contract-failed` | sandbox | The redroid host-ADB endpoint was not established as a per-lease loopback-only transport. |
| `sandbox.adb-auth-unavailable` | critical | Per-lease host-key ADB authentication could not be established. |
| `sandbox.adb-cve-mitigation-unsatisfiable` | critical | The Android image did not prove the required security patch floor for wireless-ADB CVE mitigation. |
| `sandbox.windows-home-unsupported` | host capability | Windows Home cannot provide the durable local WHPX/Hyper-V AVD path. |
| `sandbox.windows-arm-unsupported` | host capability | Windows-on-ARM is outside the supported local AVD matrix. |
| `sandbox.runtime-selected` | host capability | The runtime planner recorded the default, opt-in, and fallback selection from functional evidence. |
| `sandbox.analysis-runtime-missing` | host capability | The optional, separately-downloaded Android-emulator analysis runtime is not installed. |
| `sandbox.accelerated-mode-active` | host capability | Host virtualization is available; the bundled emulator runs accelerated. |
| `sandbox.software-mode-active` | host capability | No host virtualization; the bundled emulator runs in slow-but-correct software (TCG) mode — a graceful, honest fallback. |
| `sandbox.hqarroum-image-digest-mismatch` | critical | The HQarroum image did not resolve to the configured immutable digest. |
| `sandbox.hqarroum-tcg-fallback` | critical | The HQarroum container did not demonstrate an active KVM VM/vCPU path. |
| `sandbox.hqarroum-root-unavailable` | critical | The HQarroum image was not userdebug/rootable as required. |
| `sandbox.hqarroum-system-not-writable` | critical | The writable-system remount or CA-directory write probe failed. |
| `sandbox.hqarroum-adb-failed` | critical | Authenticated host-side loopback ADB could not be established. |
| `sandbox.l3-redirection-unavailable` | host capability | The runtime has no usable iptables/nftables transparent-routing mechanism. |
| `sandbox.l3-redirection-setup-failed` | sandbox | Transparent TCP redirection or its session rules could not be installed. |
| `sandbox.l3-redirection-teardown-failed` | critical | Session packet-filter rules could not be removed or verified. |
| `sandbox.quic-drop-unavailable` | sandbox | UDP/443 could not be dropped to force an interceptable TCP fallback. |
| `sandbox.quic-downgrade-failed` | sandbox | QUIC attempts were not confirmed as downgraded; capture is not silently called complete. |
| `sandbox.ca-system-store-unavailable` | host capability | The selected runtime cannot provide system-level Android CA trust. |
| `sandbox.ca-remount-failed` | sandbox | AVD remount or redroid overlay preparation failed. |
| `sandbox.ca-injection-failed` | sandbox | The hashed session CA could not be installed or permissioned. |
| `sandbox.ca-trust-verification-failed` | sandbox | The installed system CA did not verify in the Android trust path. |
| `sandbox.ca-teardown-failed` | critical | The exact CA file or disposable overlay state could not be removed. |
| `sandbox.remote-traffic-stream-failed` | sandbox | Remote traffic could not reach the local proxy over encrypted SSH forwarding. |
| `sandbox.proxy-unreachable` | sandbox | The sandbox could not reach the session proxy endpoint through its secured control path. |
| `sandbox.capture-bridge-failed` | sandbox | The topology-specific guest-to-proxy capture bridge could not be started or torn down. |
| `sandbox.capture-endpoint-unreachable` | sandbox | The Android guest could not reach the guest-visible capture endpoint. |
| `sandbox.guest-fetch-preflight-failed` | sandbox | The guest could not prove a completed outbound captured flow before app launch. |
| `sandbox.no-decryptable-traffic` | sandbox | No decryptable flow was observed; app silence is not asserted and pinning remains a later-phase possibility. |
| `sandbox.bypass.frida-server-deploy-failed` | sandbox | Rooted Frida server deployment failed. |
| `sandbox.bypass.spawn-gate-failed` | sandbox | The target could not be started under the early Frida spawn gate. |
| `sandbox.bypass.unpinner-script-failed` | sandbox | The declarative universal unpinner could not be loaded or applied. |
| `sandbox.bypass.decompile-failed` | external tool | The no-root lane could not decode an APK or split. |
| `sandbox.bypass.patch-failed` | sandbox | The manifest, trust configuration, gadget, or specialized native rewrite failed. |
| `sandbox.bypass.rebuild-failed` | external tool | The patched APK could not be rebuilt. |
| `sandbox.bypass.zipalign-failed` | external tool | The patched APK could not be zip-aligned. |
| `sandbox.bypass.resign-failed` | external tool | The patched base APK could not be re-signed. |
| `sandbox.bypass.split-signing-failed` | external tool | One or more split APKs could not be signed consistently. |
| `sandbox.bypass.install-failed` | sandbox | The session-signed patched package could not be installed. |
| `sandbox.bypass.framework-offset-miss` | sandbox | A Flutter native or Xamarin/Mono specialized mapping was not covered. |
| `sandbox.bypass.escalation-boundary` | sandbox | A known automation boundary requires manual reverse-engineering. |
| `sandbox.bypass.teardown-failed` | sandbox | Session-scoped bypass state could not be removed completely. |
| `sandbox.bypass.no-decryptable-traffic` | sandbox | Bypass completed without decryptable traffic; this is distinct from Phase 3.2 routing/CA failure and app silence. |
| `instrumentation.frida-server-deploy-failed` | sandbox | The session Frida server could not be deployed. |
| `instrumentation.frida-server-health-failed` | sandbox | Frida server IPC or host transport health failed. |
| `instrumentation.spawn-gate-failed` | sandbox | The target did not become instrumented before app initialization. |
| `instrumentation.attach-failed` | sandbox | Attach mode could not reach the requested running target. |
| `instrumentation.script-load-failed` | sandbox | The substrate or later-phase payload script could not be loaded. |
| `instrumentation.class-loader-resolution-failed` | sandbox | A usable Java class loader was not exposed. |
| `instrumentation.dex-resolution-failed` | sandbox | Loaded DEX/class enumeration did not pass its readiness gate. |
| `instrumentation.watchdog-degraded` | sandbox | The health watchdog detected a degraded or dead instrumentation session. |
| `instrumentation.crash-correlated` | sandbox | A target crash or fatal signal was correlated with instrumentation. |
| `instrumentation.teardown-failed` | sandbox | Frida processes, artifacts, or workspace state could not be removed completely. |
| `crypto.hook-install-failed` | sandbox | A Phase 4.1 Java, native, encoder, or request-correlation hook could not be installed. |
| `crypto.native-symbol-unavailable` | sandbox | A native crypto symbol or Conscrypt JNI boundary was unavailable. |
| `crypto.anti-hooking-detected` | sandbox | The target showed evidence of anti-hooking during crypto capture. |
| `crypto.capture-runtime-failed` | sandbox | The Phase 4.1 crypto capture runtime reported a failure. |
| `crypto.key-non-exportable` | sandbox | A valid Keystore or hardware-backed key could not export encoded bytes. |
| `crypto.scheme-recognized` | data model | A known request-signing scheme was recognized. |
| `crypto.scheme-ambiguous` | data model | Multiple request-signing scheme templates remain plausible. |
| `crypto.scheme-unrecognized` | data model | No registered request-signing scheme was recognized. |
| `crypto.canonicalization-recovered` | data model | Canonicalization reproduced on held-out captures. |
| `crypto.canonicalization-hypothesis-needs-review` | data model | Canonicalization remains a ranked hypothesis requiring review. |
| `crypto.canonicalization-not-recoverable` | data model | A primitive was observed but canonicalization was not recoverable. |
| `crypto.canonicalization-blocked` | sandbox | Canonicalization inference was blocked by insufficient observability. |
| `crypto.signer-emitted` | data model | A reusable signer artifact was emitted. |
| `crypto.signer-needs-review` | data model | A signer artifact was emitted as a partial hypothesis. |
| `crypto.signer-device-oracle` | sandbox | The signer requires the original app/device runtime. |
| `crypto.signer-not-recoverable` | data model | No reusable signer was recovered from the available evidence. |
| `fusion.invalid-input` | data model | Static and dynamic facts could not be fused because the input model is invalid. |
| `fusion.identity-collision` | data model | Fusion found duplicate endpoint identities. |
| `fusion.contradictory-provenance` | data model | Fusion found a candidate with unusable provenance. |
| `fusion.model-commit-failed` | data model | The fused API model failed canonical validation. |
| `confidence.invalid-input` | data model | Confidence recomputation could not consume the API model. |
| `confidence.handoff-resolved` | data model | A static-to-dynamic handoff was resolved by captured evidence. |
| `confidence.handoff-open` | data model | A static-to-dynamic handoff remains open because dynamic evidence did not land. |
| `confidence.low-fact` | data model | A fused fact is below the configured confidence review threshold. |
| `confidence.true-conflict` | data model | A fused fact retains incompatible source assertions and uncertain confidence. |
| `confidence.model-commit-failed` | data model | The recomputed confidence summary failed canonical model validation. |
| `openapi.invalid-input` | data model | The OpenAPI document could not be emitted from the unified surface. |
| `openapi.unrepresentable` | data model | A unified API fact cannot be represented as a valid OpenAPI 3.1 element. |
| `openapi.auth-needs-review` | data model | Authentication metadata was emitted with an OpenAPI review caveat. |
| `openapi.incomplete-evidence` | data model | The OpenAPI document contains a validity-preserving placeholder. |
| `python-sdk.invalid-input` | data model | The Python SDK could not be generated from the unified surface. |
| `python-sdk.signer-needs-review` | data model | A non-reproducible signer was emitted as a review-only SDK artifact. |
| `python-sdk.signer-device-oracle` | data model | A device-bound signer was emitted as an explicit callback shape. |
| `python-sdk.no-recovered-auth` | data model | An SDK endpoint has no recovered authentication contract. |
| `python-sdk.low-confidence-schema` | data model | A low-confidence inferred schema was emitted with a conservative Python type. |
| `collections.invalid-input` | data model | Postman/HAR artifacts could not be emitted from the unified surface. |
| `collections.signer-needs-review` | data model | A Postman signer was emitted as a review-only script. |
| `collections.signer-device-oracle` | data model | A Postman signer requires the original device/runtime. |
| `collections.no-captured-traffic` | data model | The HAR export contains no captured traffic entries. |
| `stealth.bundle-invalid` | host capability | The selected stealth bundle lacks valid version/provenance metadata. |
| `stealth.deploy-failed` | sandbox | Versioned stealth infrastructure could not be deployed. |
| `stealth.root-hiding-failed` | sandbox | Root-hiding infrastructure failed to activate. |
| `stealth.integrity-fix-failed` | sandbox | Integrity/attestation-fix infrastructure failed to activate. |
| `stealth.frida-concealment-failed` | sandbox | Frida artifact or port concealment failed. |
| `stealth.emulator-fingerprint-failed` | sandbox | Emulator-fingerprint mitigation was incomplete. |
| `stealth.detection-boundary` | sandbox | The target exceeds standard stealth coverage and requires manual mitigation/RE. |
| `stealth.teardown-failed` | sandbox | Session-scoped stealth state could not be removed completely. |
| `dynamic.capture-source-unavailable` | data model | The Phase-2 traffic store or capture path could not be read. |
| `dynamic.invalid-flow` | data model | A captured flow lacks a usable HTTP method or path. |
| `dynamic.template-match-ambiguous` | data model | A captured request matched multiple static route templates. |
| `dynamic.unresolved-route` | data model | Static matching and fallback path-template inference could not identify a route. |
| `dynamic.payload-parse-failed` | data model | A structured payload could not be parsed as JSON. |
| `dynamic.schema-inference-failed` | data model | A structured payload could not be represented as a schema fact. |
| `dynamic.fact-extraction-failed` | data model | A captured flow could not be represented as a dynamic model fact. |
| `dynamic.model-commit-failed` | data model | Dynamic facts failed canonical model or session commit validation. |
| `dynamic.coverage-partial` | data model | The capture run exercised only part of the endpoint inventory. |
| `dynamic.no-observations` | data model | The run produced no usable endpoint observations. |

## What/why/fix rule

Every catalogue entry must provide:

1. **What:** the failed or degraded operation, without a stack trace.
2. **Why:** the detected cause; occurrence context names exact IDs, scopes,
   versions, paths, and evidence.
3. **Fix:** a concrete remedy. Capability adapters replace the generic catalogue
   remedy with the exact detector- or negotiation-specific action.

Diagnostics are serializable data. Rendering may add presentation, but must not
discard the stable ID, category, severity, remedy, or typed context.
