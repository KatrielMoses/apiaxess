# Phase 4.1 crypto-primitive capture

Phase 4.1 is a capture layer, not a signer inference layer. The payload is
loaded through the Phase 3 early-spawn Frida substrate using
InstrumentationRequest::spawn_crypto_capture. It does not deploy a second
instrumentation runtime or perform pinning bypass.

The apiaxess-crypto-capture crate owns the versioned interchange and the
stateful CryptoCaptureCollector. Java lifecycle events are keyed by primitive
family and crypto-object identity. Ordered update chunks preserve the source
offset, source length, and ByteBuffer origin; finalize output and output-buffer
returns are retained separately. Init, first update, and finalize/sign/digest
stack traces are recorded.

Every record carries request and flow correlation fields. A proxy adapter can
send request_context_event(flow_id, thread_id, active) before the crypto
operation; the collector applies that context at operation start and again at
finalize. Wire observations can arrive after finalize and are attached to the
completed operation.

Key bytes are retained only when the provider exports them. A null
getEncoded() result is recorded as non_exportable with a first-class
crypto.key-non-exportable info diagnostic, together with Keystore alias,
purposes, security level, and hardware-backed evidence when Android exposes it.

Native exports are best-effort because BoringSSL has no stable ABI. Conscrypt
JNI names, late-loaded modules, and exported HMAC/EVP/RSA/ECDSA functions are
observed when available; missing symbols produce
crypto.native-symbol-unavailable and do not invalidate Java-layer records.
Stripped symbols remain an explicit later validation boundary.
