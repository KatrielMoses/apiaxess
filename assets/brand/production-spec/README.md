# apiaxess desktop — production design spec

Eight sheets. Open any `.dc.html` in a browser (Chrome/Edge/Safari); no build step, no server.
Pan and zoom the canvas; each sheet is a single page.

## Contents

| File | What it specifies |
| --- | --- |
| `01 Shell tokens components` | Shell anatomy with dimensioned callouts, region table (size + resize behaviour), full token sheet, every component at real size in every state, and the **new-surface template** with slots A–E and the ten rules for adding a page |
| `02 Capture surfaces` | Start · APK analysis · Web capture · Android target · Devices |
| `03 Analyse and deliver surfaces` | Workbench · API surface · Export · Session & audit · Settings · About |
| `04 Window sizes and pane resizing` | 1920 / 1440 / 1280 / 1024 / 860 at true size, collapse order, breakpoints, and per-pane min / default / max with handle and shortcut behaviour |

Each sheet exists twice: `- Light` and `- Dark`. Same geometry, same markup, inverted tokens.

## How to build from this

1. **Tokens first.** Every colour in the sheets is a CSS variable (`--s-*`). Ship one stylesheet
   with two `:root` blocks — the light values are in sheet 01, the dark values are the same
   variables in the Dark file's `:root`. No component should hard-code a colour.
2. **Geometry is fixed where it is stated.** Title bar 32, rail 48, status bar 24, document tabs 30,
   surface toolbar 32, row height 25 (22 compact), structural rule 2px, hairline 1px, radius 0.
3. **Panes are user-resizable** per sheet 04: 6px hit area on every splitter, double-click resets to
   the default, ⌘B / ⌘J / ⌘⌥I toggle sidebar / dock / inspector, and sizes persist per session.
4. **Streaming containers stay mounted** when a pane is hidden or a view switches — live traffic,
   intercept and diagnostics must never lose their socket on a layout change.
5. **A new surface** adds one sidebar row inside a phase group and fills slots A–D only; everything
   else is inherited. Sheet 01 section 04 is the skeleton and the rules.

## Type and colour

- UI: **Archivo** (400/500/600). Data, paths, ids, counts, fingerprints: **IBM Plex Mono**.
  Both are loaded from Google Fonts by each sheet; substitute self-hosted copies in the product.
- Brand: ink `#0D0D0D`, accent `#2D7FF9`, paper `#FFFFFF` (identity kit v2.1). Red `#B0230C`
  (light) / `#E8735C` (dark) is reserved for failure — never for pending, live or selected.

## Also included

- `support.js` — the runtime the sheets use to render. Keep it beside them.
- `_ds/modernist-…/` — the Modernist design-system stylesheet, bundle and guide the sheets link.
