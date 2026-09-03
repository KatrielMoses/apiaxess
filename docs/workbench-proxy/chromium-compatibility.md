# Bundled Chromium compatibility checklist

Run this checklist whenever the bundled Chromium snapshot changes:

1. Launch the owned browser through a web session and verify HTTPS capture
   reaches the durable flow store. Confirm the launcher still supplies
   `--ignore-certificate-errors` and the session SPKI pin.
2. Verify the DevTools/CDP handshake, including navigation to the target and
   the Chromium-version-specific loopback WebSocket behavior (no `Origin`
   header).
3. Close the browser and verify process teardown removes the disposable
   profile, temporary CDP state, and proxy runtime residue.
4. Repeat the browser E2E on Windows and Linux with an authorized HTTPS
   target.

The engine regression suite guards the launch trust arguments and CDP request
format in `engine-shell` browser tests. A snapshot bump must keep those tests
green; the cross-platform live checks above remain release-gate verification.
