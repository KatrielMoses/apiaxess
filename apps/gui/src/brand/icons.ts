/**
 * The APIaxess icon system.
 *
 * Every glyph shares the geometry of the brand mark: a 24-unit square, round
 * caps and joins, and a 1.75-unit stroke — the same 7% stroke-to-box ratio the
 * kit uses for the mark (14 units in a 200 box). Icons are stroke-only and
 * inherit `currentColor`, so tone is always decided by the token system.
 */

const PATHS = {
  /* Input types */
  apk: '<path d="M12 2.75 20 7v10l-8 4.25L4 17V7Z"/><path d="M4 7l8 4.25L20 7"/><path d="M12 11.25V21.25"/>',
  web: '<circle cx="12" cy="12" r="9.25"/><path d="M2.75 12h18.5"/><path d="M12 2.75c2.4 2.6 3.6 5.7 3.6 9.25S14.4 18.65 12 21.25c-2.4-2.6-3.6-5.7-3.6-9.25S9.6 5.35 12 2.75Z"/>',

  /* Navigation */
  pipeline: '<path d="M3 6.5h5"/><circle cx="10.5" cy="6.5" r="2.5"/><path d="M13 6.5h8"/><path d="M3 17.5h8"/><circle cx="13.5" cy="17.5" r="2.5"/><path d="M16 17.5h5"/>',
  traffic: '<path d="M3 5.5h18"/><path d="M3 12h12"/><path d="M3 18.5h15"/><circle cx="18.5" cy="12" r="1.6"/>',
  surface: '<path d="m12 3 8.5 4.5L12 12 3.5 7.5Z"/><path d="m3.5 12 8.5 4.5 8.5-4.5"/><path d="m3.5 16.5 8.5 4.5 8.5-4.5"/>',
  discovery: '<circle cx="11" cy="11" r="6.75"/><path d="M11 4.25v13.5M4.25 11h13.5"/><path d="m16.2 16.2 4.3 4.3"/>',
  session: '<path d="M4.75 4.75h10.5L19.25 8.75v10.5H4.75Z"/><path d="M8.5 4.75v5h6v-5"/><path d="M8 19.25v-5.5h8v5.5"/>',
  export: '<path d="M12 3.5v11"/><path d="m7.75 10.25 4.25 4.25 4.25-4.25"/><path d="M4.5 16.5v2.25a1.75 1.75 0 0 0 1.75 1.75h11.5a1.75 1.75 0 0 0 1.75-1.75V16.5"/>',
  settings:
    '<circle cx="12" cy="12" r="3"/><path d="M19.4 14.5a1.6 1.6 0 0 0 .32 1.77l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.6 1.6 0 0 0-1.77-.32 1.6 1.6 0 0 0-.97 1.47V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1.05-1.47 1.6 1.6 0 0 0-1.77.32l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.6 1.6 0 0 0 .32-1.77 1.6 1.6 0 0 0-1.47-.97H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.47-1.05 1.6 1.6 0 0 0-.32-1.77l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.6 1.6 0 0 0 1.77.32H9a1.6 1.6 0 0 0 .97-1.47V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 .97 1.47 1.6 1.6 0 0 0 1.77-.32l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.6 1.6 0 0 0-.32 1.77V9a1.6 1.6 0 0 0 1.47.97H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.47.97Z"/>',

  /* Actions */
  play: '<path d="M7.5 4.75 19 12 7.5 19.25Z"/>',
  pause: '<path d="M9 5.5v13M15 5.5v13"/>',
  stop: '<rect x="5.75" y="5.75" width="12.5" height="12.5" rx="1"/>',
  send: '<path d="M20.5 3.5 10.75 13.25"/><path d="M20.5 3.5 14.25 20.5 10.75 13.25 3.5 9.75Z"/>',
  refresh:
    '<path d="M20.25 12a8.25 8.25 0 1 1-2.42-5.83"/><path d="M20.25 3.75v4.5h-4.5"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  check: '<path d="m4.75 12.5 4.75 4.75 9.75-11"/>',
  chevronRight: '<path d="m9.5 5.5 6.5 6.5-6.5 6.5"/>',
  chevronDown: '<path d="m5.5 9.5 6.5 6.5 6.5-6.5"/>',
  arrowRight: '<path d="M4 12h16"/><path d="m14 6 6 6-6 6"/>',
  folder:
    '<path d="M3.5 6.25A1.75 1.75 0 0 1 5.25 4.5h3.6l2 2.5h7.9a1.75 1.75 0 0 1 1.75 1.75v9A1.75 1.75 0 0 1 18.75 19.5H5.25A1.75 1.75 0 0 1 3.5 17.75Z"/>',
  save: '<path d="M4.75 4.75h10.5L19.25 8.75v10.5H4.75Z"/><path d="M8.5 4.75v5h6v-5"/>',
  browser:
    '<rect x="3" y="4.5" width="18" height="15" rx="1.75"/><path d="M3 9.25h18"/><path d="M6.5 6.9h.01M9.25 6.9h.01"/>',
  copy: '<rect x="8.5" y="8.5" width="11.75" height="11.75" rx="1.5"/><path d="M15.5 5.75V5.25A1.5 1.5 0 0 0 14 3.75H5.25a1.5 1.5 0 0 0-1.5 1.5V14a1.5 1.5 0 0 0 1.5 1.5h.5"/>',

  /* States and meaning */
  shield:
    '<path d="M12 3 19.5 6v6c0 4.2-3 7.6-7.5 9-4.5-1.4-7.5-4.8-7.5-9V6Z"/><path d="m9 12 2.25 2.25L15.25 10"/>',
  alert: '<path d="M12 3.75 21.5 20.25H2.5Z"/><path d="M12 10v4.25"/><path d="M12 17.4h.01"/>',
  info: '<circle cx="12" cy="12" r="9.25"/><path d="M12 11v5.5"/><path d="M12 7.6h.01"/>',
  help: '<circle cx="12" cy="12" r="9.25"/><path d="M9.5 9.4a2.6 2.6 0 1 1 3.4 2.48c-.55.2-.9.73-.9 1.32v.55"/><path d="M12 17.2h.01"/>',
  lock: '<rect x="4.75" y="10" width="14.5" height="10" rx="1.75"/><path d="M8.25 10V7.25a3.75 3.75 0 0 1 7.5 0V10"/>',
  clock: '<circle cx="12" cy="12" r="9.25"/><path d="M12 6.75V12l3.5 2"/>',
  spark: '<path d="M12 3v3.5M12 17.5V21M21 12h-3.5M6.5 12H3"/><path d="m18.36 5.64-2.47 2.47M8.11 15.89l-2.47 2.47M18.36 18.36l-2.47-2.47M8.11 8.11 5.64 5.64"/>',

  /* Theme */
  sun: '<circle cx="12" cy="12" r="4.25"/><path d="M12 2.75v2.1M12 19.15v2.1M21.25 12h-2.1M4.85 12h-2.1"/><path d="m17.9 6.1-1.5 1.5M7.6 16.4l-1.5 1.5M17.9 17.9l-1.5-1.5M7.6 7.6 6.1 6.1"/>',
  moon: '<path d="M20.5 14.4A8.75 8.75 0 0 1 9.6 3.5a8.75 8.75 0 1 0 10.9 10.9Z"/>',
} as const;

export type IconName = keyof typeof PATHS;

interface IconOptions {
  /** Rendered edge length in pixels. */
  readonly size?: number;
  /** Accessible label; omit for decorative icons beside visible text. */
  readonly title?: string;
  /** Extra class names appended to `icon`. */
  readonly className?: string;
}

/** Renders an icon as an SVG string for the app's string-built markup. */
export function icon(
  name: IconName,
  { size = 16, title, className = "" }: IconOptions = {},
): string {
  const label =
    title === undefined
      ? ' aria-hidden="true" focusable="false"'
      : ` role="img" aria-label="${title}"`;
  const classes = className === "" ? "icon" : `icon ${className}`;
  return `<svg class="${classes}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"${label}>${PATHS[name]}</svg>`;
}
