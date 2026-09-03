# Phase 3.6.3.1 — Guest-fetch preflight and Feeder capstone

## Implementation

The capstone harness now treats guest fetchability as a hard stage-4
precondition:

1. It records the current traffic-store high-water flow ID.
2. It probes guest network state at the moment capture is about to begin.
3. It sends a forced origin-form HTTP request through the guest routing path.
4. It waits for a new store row with both an HTTP method and response status.
5. Only after that completed flow exists does it launch the target app.

Failure emits `sandbox.guest-fetch-preflight-failed`, records the network and
forced-probe evidence, skips app launch/stages 5–6, and performs normal traffic
and intake teardown. Preflight traffic uses a disposable, separate store, so it
cannot become a false dynamic fact in the app's model run.

The regression test covers the gate distinction: an old flow, a partial new
flow, and a response-only record are rejected; only a new request/response pair
passes.

## Feeder fixture

The default capstone input is now:

`fixtures/capstone/feeder-2.22.0-4050.apk`

- package: `com.nononsenseapps.feeder`
- version: `2.22.0` / versionCode `4050`
- SHA-256: `1066f08e9e773fe0a5a4cd35d8e308634d8c4fbe9d3390be0095cbdaf0a39c`
- WSL copy: `/home/katriel/APIaxess-tusky-linux/fixtures/capstone/feeder-2.22.0-4050.apk`

The harness seeds an OPML feed using the Android external-storage content URI
and defaults to `https://planet.gnome.org/atom.xml`; both are configurable with
`APIAXESS_CAPSTONE_FEED_URL` and `APIAXESS_CAPSTONE_ALLOWED_DOMAIN`.

## Validation status

- Preflight gating regression: pass.
- Diagnostics catalogue test: pass.
- Targeted capstone compile: pass.
- Feeder intake on Windows: pass; APK resolved as one installable APK and
  networking libraries were detected.
- The live Windows attempt reached static routing but remained CPU-bound in the
  Windows filesystem extraction pass for more than the bounded validation
  window, so it was stopped before stage 3/4. No stage 4–6 result is claimed
  from that attempt.

The dynamic thesis remains open until the Feeder run reaches the new preflight,
launch, and stages 4–6 on the Linux-native checkout.
