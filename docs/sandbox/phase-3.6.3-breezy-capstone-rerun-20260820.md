# Breezy Weather capstone rerun — 2026-08-20

## Setup

- APK copied from the Windows build target into the WSL2-native checkout at
  `/home/katriel/APIaxess-tusky-linux/fixtures/capstone/breezy-weather-60201.apk`.
- Package: `org.breezyweather`.
- SHA-256:
  `ac2715f6165b42fb34a6bfd2bfe4fb5812e74fbf23397fd872710f362082741e`.
- The harness granted coarse, fine, and background location permissions; all
  three `pm grant` commands returned exit 0, and `settings put secure
  location_mode 3` returned exit 0.
- The emulator-console GPS fix (`adb emu geo fix`) returned exit 1. Therefore
  no concrete default coordinate can be claimed as installed.

## Network answer

The emulator had outbound network connectivity while the capture session and
L3 routing were active:

- route: `10.0.2.0/24 dev wlan0`, source `10.0.2.16`;
- `ping 10.0.2.2`: passed;
- `ping 1.1.1.1`: passed;
- `ping example.com`: passed, including DNS resolution.

The in-session HTTP probe reported
`APIAXESS_NETWORK_PROBE=ICMP_PASS_HTTP_UNAVAILABLE`: this Android image has no
`wget`, and its `toybox nc` lacks the probe option initially used. Thus basic
emulator internet is confirmed, but an HTTP/TCP request being captured through
the workbench is not independently confirmed by this probe. The workbench
proxy itself started successfully.

## Capstone stages

| Stage | Result | Evidence |
|---|---|---|
| 1. Intake/resolution | **Pass** | One Breezy APK resolved on ext4. |
| 2. Static discovery | **Pass** | `endpoints=0`, `loose_findings=6649`, `handoffs=3`, `static_diagnostics=6658`; no filesystem stall. |
| 3. Sandbox/install | **Pass with finding** | HQarroum started and APK installed. JADX emitted its existing partial-decompilation warning. Location permission/mode setup passed; GPS fix failed with exit 1. |
| 4. Traffic capture | **Finding** | Proxy setup passed (`0.0.0.0:38771`), app launch returned exit 0, but the workbench contained `0` flow summaries and `0` completed decryptable HTTP flows. Android reported `not connected` in the monkey network stats. |
| 5. Pinning bypass | **Finding** | `PrimaryFrida` was selected, but no `frida-server` artifact was available: `sandbox.bypass.frida-server-deploy-failed`. No pinning behavior can be classified as pinned or unpinned because no app flow was captured. |
| 6. Dynamic model | **Finding, not closed** | `0` observed endpoints, `0` inferred endpoints, `0` resolved handoffs, `3` open handoffs, `1` diagnostic, `0` scope warnings. No dynamic facts landed. |
| 7. Teardown | **Normal teardown pass** | Traffic teardown and intake teardown both returned `Ok(())`; the unclean SIGKILL check remains not run. |

## Conclusion

The emulator's basic outbound internet works. The Breezy run did not reach the
weather API because no usable concrete location was installed and no HTTP flow
was observed. The dynamic thesis therefore remains unproven for this run; the
next required fix is a supported emulator location injection/default-city
interaction, followed by a capture-path TCP/HTTPS probe and rerun with a
compatible `frida-server` if pinning is encountered.

## Isolated capture-path verification (Phase 3.2.1)

The original failure was the Docker double boundary, not Breezy: Android's
`10.0.2.2` pointed at the emulator container namespace, while the old
`REDIRECT --to-ports 18080` rule did not target the host proxy's ephemeral
listener. The implementation now starts a pinned `alpine/socat` sidecar in the
HQarroum container's network namespace and DNATs guest TCP traffic to the
sidecar's `10.0.2.2:18080` endpoint. The sidecar forwards to
`host.docker.internal:<actual-proxy-port>`; the emulator remains on ordinary
container networking and no host-network mode is used.

Live evidence from the bridge-enabled run:

- bridge sidecar startup/readiness: pass;
- guest endpoint probe to `10.0.2.2:18080`: pass;
- emulator network probe through the installed rules: `TCP_PASS`;
- installed NAT rule: `-A OUTPUT -p tcp -j DNAT --to-destination 10.0.2.2:18080`;
- one bridge run delivered two partial flow summaries to the workbench store,
  proving the request reached the host proxy; completion/decryption remained
  zero for that origin-form probe because the listener had not yet normalized
  transparent origin-form HTTP.

The listener now reconstructs an absolute upstream URI from the request's
mandatory `Host` header. A wire-level regression test confirms that both
origin-form and absolute-form requests return `HTTP/1.1 200 OK` and produce
paired request/response observations.

The capstone app result is therefore still an app-level finding: Breezy made no
completed weather flow, and no Breezy-specific partial request was present.
The two partial summaries came from the forced probe, which executes before
app launch. The network boundary and origin-form handling are now covered; the
remaining app run needs a concrete location/API interaction before Stage 4-6
can be called closed.
