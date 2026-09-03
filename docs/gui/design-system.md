# GUI design system

The APIaxess GUI is styled entirely from a central token system. This document
records where the brand values came from, how the layers fit together, and the
rules that keep the identity consistent as the app grows.

## Source of truth

The identity kit (`Identity kit / v2.1`) lives at
`assets/brand/Apiaxess Logo Kit.html`. It is **referenced locally and never
committed** — `/assets/brand/*.html` is gitignored. Everything the GUI needs has
been extracted from it into committed files:

| Extracted asset | Committed at |
| --- | --- |
| Palette, typography, spacing, radii, motion | `apps/gui/src/styles/tokens.css` |
| Outfit variable font (latin, latin-ext) | `apps/gui/public/fonts/*.woff2` |
| Mark, wordmark, primary lockup | `apps/gui/src/brand/logo.ts` |
| Favicon (kit's 32 px simplification) | `apps/gui/public/favicon.svg` |

The font is bundled, not fetched from a CDN: the GUI is served from
`127.0.0.1` and must render identically with no network access.

### Palette

Kit values, verbatim:

| Token | Value | Role |
| --- | --- | --- |
| `--brand-ink` | `#0D0D0D` | Text, rules, inverse surfaces |
| `--brand-signal-blue` | `#2D7FF9` | Primary accent |
| `--brand-signal-green` | `#00E676` | Success |
| `--brand-neutral-700` | `#4A4A4A` | Muted text |
| `--brand-neutral-500` | `#8A8A8A` | Subtle text, micro-labels |
| `--brand-neutral-400` | `#C9C9C9` | Strong rules, control borders |
| `--brand-neutral-300` | `#E8E8E8` | Hairline rules |
| `--brand-neutral-200` | `#F4F4F4` | Sunken surfaces |
| `--brand-paper` | `#FFFFFF` | Base surface |

The kit defines no cautionary or destructive colour. `--brand-signal-red`
(`#F9382D`) and `--brand-signal-amber` (`#F9A62D`) are **derived**: they are
built to sit in the same saturation register as Signal Blue, and are marked as
derived in `tokens.css` so they are never mistaken for kit values.

### Typography

Outfit is the primary family; a system monospace stack carries code, traffic,
paths, and identifiers. The kit's signature treatments are encoded as classes in
`base.css`:

- `.t-display` / `.t-title` — Outfit 500 at the kit's negative tracking
  (`-0.05em` / `-0.03em`).
- `.t-label` — the wide-tracked uppercase micro-label (`0.24em`, subtle grey).
- `.t-mono` — technical values.

## Layer order

`apps/gui/src/styles/index.css` imports four layers, in this order:

1. `tokens.css` — the vocabulary. Colour, type, space, radii, elevation, motion,
   layout. **Nothing else in the GUI may hardcode these values.**
2. `base.css` — bundled `@font-face`, reset, and the typography hierarchy.
3. `components.css` — panels, buttons, fields, badges, metrics, progress, lists,
   tables, states, notices, diagnostics, overlays.
4. `surfaces.css` — the app shell and the layout of each view.

## Rules

- **Consume tokens, never literals.** A new component reads `var(--space-4)`,
  not `1rem`. Retuning the identity should mean editing `tokens.css` only.
- **Icons come from `brand/icons.ts`.** Every glyph shares the mark's geometry:
  a 24-unit box with a 1.75-unit round-capped stroke — the same 7% stroke ratio
  the kit uses for the mark (14 units in a 200 box). Static markup declares
  `data-icon="name"` and `hydrateIcons()` renders it.
- **Empty, loading, and error states are first-class.** Use `stateBlock()` from
  `ui/dom.ts` rather than leaving a container blank.
- **Diagnostics keep their shape.** The engine's what / why / fix triple is
  rendered by `ui/diagnostics.ts` and never flattened into a bare string. The
  severity tone is a display heuristic over the diagnostic ID and is never used
  for control flow.
- **Gates are the app's, not the browser's.** `window.confirm` / `window.prompt`
  are replaced by `confirmDialog` / `promptDialog` in `ui/overlay.ts`. The
  decision and its consequences are unchanged; only the surface is branded.
- **Views stay mounted.** `ui/nav.ts` toggles `hidden` on `[data-view]` sections
  so element identity — and therefore every wired listener and live region — is
  stable for the life of the session. `[hidden]` is forced to `display: none` in
  `base.css` so components that set their own `display` cannot override it.

## Layout

The shell is a sticky header over a single main region. `--shell-header-height`
is kept in sync with the header's measured height at runtime (`trackHeaderHeight`
in `main.ts`), because the header wraps to a second row on narrow windows and
the layers anchored beneath it — the full-height workbench column and the
diagnostics drawer — have to follow.

Breakpoints: `1400px` folds the workbench to two columns, `1100px` stacks the
header and returns the workbench to document flow, `860px` goes single column.
