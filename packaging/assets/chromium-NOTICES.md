# APIaxess Browser notices

APIaxess Browser packages an unmodified official Chromium snapshot. The exact
snapshot revision, archive SHA-256, a pointer to the runtime's
`about:credits` page, and the release SBOM/license-scan record are generated
beside the installed runtime and bound to `chromium.toml`.

Chromium is distributed under the BSD 3-Clause License and includes additional
third-party components with their own notices. The complete upstream notices
from the pinned snapshot must be copied into the installed Chromium runtime.
