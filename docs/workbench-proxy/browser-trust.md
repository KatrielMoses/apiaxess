# Web capture browser trust

Web-mode capture uses the APIaxess-owned bundled Chromium exclusively. The
launcher creates a disposable profile, routes it through the session proxy,
and applies the session CA pin for that capture process. The profile and
browser process are removed when capture stops.

Firefox is not a supported capture browser. APIaxess does not require or
invoke a user-installed browser, Mozilla NSS `certutil`, or Firefox profile
provisioning for web capture. There is no browser-selection fallback in the
GUI, CLI, or local API.

The capture browser is isolated from the user's normal browser and should be
used only for an authorized web session. Start a web session first, then use
`POST /api/v1/workbench/browser` to launch bundled Chromium and
`DELETE /api/v1/workbench/browser` to stop it.
