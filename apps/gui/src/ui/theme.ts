/**
 * Theme control.
 *
 * APIaxess opens dark — the kit's Ink ground, which is the register the
 * product is designed in. Light is the kit's Paper ground, kept complete and
 * selectable. Both are entire mappings in `tokens.css`; this module only
 * decides which one is active and remembers the choice.
 *
 * The attribute is written on <html> by an inline script in `index.html`
 * before first paint, so a light-mode operator never sees a dark flash. This
 * module re-reads the same storage key and keeps every control in sync.
 */

import { icon } from "../brand/icons";

export type Theme = "dark" | "light";

const STORAGE_KEY = "apiaxess.theme";
const DEFAULT_THEME: Theme = "dark";

/** The browser UI colour that matches each ground (kit Ink / kit Paper). */
const THEME_COLOR: Record<Theme, string> = {
  dark: "#0d0d0d",
  light: "#ffffff",
};

function isTheme(value: string | null): value is Theme {
  return value === "dark" || value === "light";
}

function readStored(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return isTheme(stored) ? stored : DEFAULT_THEME;
  } catch {
    // Private modes and locked-down WebViews can refuse storage entirely; the
    // default theme is still correct, it simply will not persist.
    return DEFAULT_THEME;
  }
}

export function activeTheme(): Theme {
  const attribute = document.documentElement.dataset.theme ?? null;
  return isTheme(attribute) ? attribute : readStored();
}

export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  document
    .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", THEME_COLOR[theme]);
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* see readStored — persistence is a convenience, not a requirement */
  }
  document
    .querySelectorAll<HTMLElement>("[data-theme-toggle]")
    .forEach((control) => syncToggle(control, theme));
  document
    .querySelectorAll<HTMLInputElement>('[data-theme-option]')
    .forEach((input) => {
      input.checked = input.dataset.themeOption === theme;
    });
}

export function toggleTheme(): Theme {
  const next: Theme = activeTheme() === "dark" ? "light" : "dark";
  setTheme(next);
  return next;
}

/**
 * Points a quick-toggle control at the theme it will switch *to*, so its icon
 * and label describe the action rather than the current state.
 */
function syncToggle(control: HTMLElement, theme: Theme): void {
  const target = theme === "dark" ? "light" : "dark";
  const label = target === "light" ? "Switch to light theme" : "Switch to dark theme";
  control.setAttribute("title", label);
  control.setAttribute("aria-label", label);
  control.setAttribute("aria-pressed", String(theme === "light"));
  control.dataset.themeTarget = target;
  const glyph = control.querySelector<HTMLElement>("[data-theme-glyph]");
  // Written directly rather than through `data-icon`: the glyph is re-rendered
  // on every switch, and icon hydration is a one-shot pass over static markup.
  if (glyph !== null) {
    glyph.innerHTML = icon(target === "light" ? "sun" : "moon", { size: 18 });
  }
}

/**
 * Wires every `[data-theme-toggle]` and `[data-theme-option]` control in the
 * document. Delegated, so controls rendered later — the settings screen — are
 * live without re-registration.
 */
export function initTheme(): void {
  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const toggle = target.closest<HTMLElement>("[data-theme-toggle]");
    if (toggle === null) return;
    event.preventDefault();
    toggleTheme();
  });

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    const choice = target.dataset.themeOption;
    if (!isTheme(choice ?? null) || !target.checked) return;
    setTheme(choice as Theme);
  });

  setTheme(activeTheme());
}
