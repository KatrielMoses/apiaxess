# APIaxess Android Client (Phase C3)

The thin, rooted-Android capture client — the v0.1.0 product surface. You open it,
pick one installed app, connect to the workbench over adb, and that app's HTTPS
traffic is captured and decrypted in the workbench (via the system CA that Phase
C2 installed) and shows up in the workbench store/UI.

It is a **thin client**: it does no decryption or analysis itself. It transparently
captures the chosen app's TCP and relays it to the workbench's existing
explicit-CONNECT MITM, which runs the proven (concurrent-safe) analysis pipeline.

## How capture works

```
   ┌── chosen app (uid N) ──┐
   │  TCP to host:443       │
   └────────┬───────────────┘
            │  iptables -t nat OUTPUT -m owner --uid-owner N -j REDIRECT --to-ports 28080
            ▼
   ┌── on-device relay (127.0.0.1:28080) ──┐
   │  SO_ORIGINAL_DST → learns host:443     │
   │  CONNECT host:443  ─────────────────┐  │
   └──────────────────────────────────── │ ─┘
            adb reverse tcp:8080 tcp:8080 │  (Phase C2 tunnel; device loopback → workbench loopback)
                                          ▼
   ┌── workbench MITM proxy (127.0.0.1:8080) ──┐
   │  terminates TLS with a leaf for `host`,    │
   │  signed by the session CA the device trusts │
   │  → decrypts → captures → fuses              │
   └─────────────────────────────────────────────┘
```

- **Per-app by construction.** The redirect is scoped by `-m owner --uid-owner`,
  so *only* the chosen app is captured — never the whole device. No proxy setting
  is set, so proxy-ignoring apps are still caught, and there is no VPN-detection
  surface on the primary path.
- **QUIC/HTTP-3 is blocked.** A companion `filter OUTPUT` rule REJECTs the app's
  UDP/443 so it falls back to interceptable TLS-over-TCP. Without this, HTTP/3
  traffic silently vanishes. Non-negotiable.
- **VpnService fallback** (`ApiaxessVpnService`) for devices where iptables owner
  matching / NAT is constrained. It establishes a **per-app** tunnel
  (`addAllowedApplication`) to the same relay. See *Residuals*.

## Contract with the workbench (C1 + C2)

| Concern | Endpoint / mechanism | Default |
|---|---|---|
| Session CA trust | Installed system-wide by C2 (adb) — the client does nothing | — |
| Pairing → session token | `POST /api/v1/pairing/exchange` `{pairingToken}` → `{sessionToken}` (C1) | `127.0.0.1:7777` |
| Authenticated control channel | `ws://…/api/v1/workbench/ws/device/control?token=<sessionToken>` (C1, token-auth, not origin) | `127.0.0.1:7777` |
| Traffic relay target | explicit `CONNECT` to the workbench MITM proxy | `127.0.0.1:8080` |
| Transport | adb-reverse tunnel established by C2 | device loopback → workbench loopback |

### Pairing (Phase C5)

Two ways to connect; QR is primary, manual is the fallback:

- **QR (primary):** the workbench's *Pair a device* screen shows a QR encoding
  `{host, controlPort, proxyPort, pairingToken, caFingerprintSha256}`. The client
  scans it (`ConnectScreen` → ZXing) → `PairingQr.parse` fills the config → it
  **pins the workbench** by fetching `GET /pairing/ca` and checking the CA's
  SHA-256 against the QR's fingerprint (`WorkbenchClient.verifyCaFingerprint`), so
  a rogue server can't MITM the pairing.
- **Manual (fallback):** paste host/port + pairing token (no fingerprint → no pin).

Either way the client then enters the **accept/decline gate**: it POSTs
`/pairing/exchange` (→ a pending request id) and polls `/pairing/exchange/{id}`
(`WorkbenchClient.requestPairing`/`pollPairing`) while showing *"Waiting for the
operator to accept."* On **accept** the workbench provisions the device (C2) and
issues the session token → capture proceeds. On **decline** the client shows a
clear *"server declined."* Nothing is provisioned without an explicit accept —
this closes the C2 ungated-provisioning gap.

### Resilience (requirement 5)

Foreground service + partial wakelock (survives sleep); exponential-backoff
auto-reconnect of the control channel re-presenting the session token (and
re-exchanging the pairing token if the session token expired); the redirect is
re-applied on network change. The traffic path is independent of the control
channel, so a control blip never drops in-flight capture — over adb/USB it is
effectively seamless.

## Layout

```
app/src/main/
  cpp/original_dst.c            SO_ORIGINAL_DST reader (JNI; the one native piece)
  java/com/apiaxess/client/
    core/        Config, legible what/why/fix diagnostics
    root/        su execution
    apps/        installed-app inventory + UID resolution
    capture/     IptablesRedirector, Relay, OriginalDst, CaptureController,
                 NetworkMonitor, ApiaxessVpnService (fallback), CaptureState
    control/     WorkbenchClient (pairing exchange + control WebSocket)
    service/     CaptureService (foreground + wakelock), CaptureManager
    ui/          Compose UI + identity-kit theme + the mark
```

## Build

Requires the Android SDK (API 34) + NDK (for the JNI shim). This project is **not**
part of the Cargo/pnpm workspaces and does not affect their CI gates.

```bash
cd apps/android
# The wrapper JAR is a binary and is not committed; generate the wrapper once:
gradle wrapper --gradle-version 8.9
./gradlew assembleDebug        # -> app/build/outputs/apk/debug/app-debug.apk
```

Or open `apps/android` in Android Studio and Run.

## Verify (on a rooted device/emulator, workbench provisioned by C2)

1. Provision the device from the workbench (Phase C2): adb-reverse tunnel up +
   session CA installed system-wide.
2. `adb install app-debug.apk`.
3. Mint a pairing token on the workbench; open the client; auto-detect (adb) keeps
   the loopback defaults; paste the token; **Choose an app**.
4. Pick a real non-pinned app; grant superuser when prompted.
5. Use the app; its HTTPS requests appear decrypted in the workbench store/UI.
6. Confirm **per-app scoping** (only that app's traffic is captured), the
   **QUIC block** (no silent HTTP/3 loss), and **resilience** (lock/sleep the
   device, toggle Wi-Fi — capture resumes without re-pairing).

## Residuals (honest)

- **Cannot be built or device-verified in this repo's CI** (no Android
  toolchain). The source is complete and self-consistent; end-to-end verification
  on real rooted hardware is deferred, exactly as flagged.
- **Certificate-pinned apps** (including Flutter/native-pinned) are **not**
  captured by C3 alone — they need the Frida bypass (Phase C4). The C2
  frida-server is running on the device; C3 does not attach to it.
- **VpnService fallback**: the service owns the full per-app VPN lifecycle, socket
  protection, and teardown; the userspace TCP/IP reassembly engine that turns tun
  packets into per-flow `CONNECT`s (a tun2socks-style stack) is the one remaining
  piece and is isolated in `ApiaxessVpnService.forwardTunnel`. The **primary
  iptables path needs none of it** and is complete.
- **Aggressive anti-instrumentation apps** may still resist capture.

## Brand

Dark by default (identity kit "reversed / dark UI"): Ink `#0D0D0D`, Accent
`#2D7FF9`, the mark drawn from the kit geometry (`ui/ApiaxessMark.kt`), Outfit
weights/tracking (system-font fallback until the Outfit `.ttf`s are dropped into
`res/font` — see `ui/theme/Type.kt`).
