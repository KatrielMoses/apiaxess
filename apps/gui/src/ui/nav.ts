/**
 * View routing for the app shell.
 *
 * Every surface stays mounted in the document and is toggled with `hidden`,
 * so element identity — and therefore every wired listener and every live
 * region the engine writes into — is stable for the life of the session.
 */

export type ViewName =
  | "start"
  | "apk"
  | "web"
  | "workbench"
  | "surface"
  | "export"
  | "session"
  | "settings"
  | "about";

const VIEWS: readonly ViewName[] = [
  "start",
  "apk",
  "web",
  "workbench",
  "surface",
  "export",
  "session",
  "settings",
  "about",
];

const TITLES: Record<ViewName, string> = {
  start: "APIaxess",
  apk: "APK analysis · APIaxess",
  web: "Web capture · APIaxess",
  workbench: "Workbench · APIaxess",
  surface: "API surface · APIaxess",
  export: "Export · APIaxess",
  session: "Session · APIaxess",
  settings: "Settings · APIaxess",
  about: "About · APIaxess",
};

function isViewName(value: string): value is ViewName {
  return (VIEWS as readonly string[]).includes(value);
}

let current: ViewName = "start";
const listeners: ((view: ViewName) => void)[] = [];

/** Registers a callback invoked whenever the active view changes. */
export function onViewChange(listener: (view: ViewName) => void): void {
  listeners.push(listener);
}

export function showView(view: ViewName): void {
  current = view;
  document.querySelectorAll<HTMLElement>("[data-view]").forEach((section) => {
    section.hidden = section.dataset.view !== view;
  });
  document.querySelectorAll<HTMLElement>(".app-nav__item").forEach((item) => {
    if (item.dataset.nav === view) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  });
  document.title = TITLES[view];
  if (window.location.hash !== `#${view}`) {
    window.history.replaceState(null, "", `#${view}`);
  }
  if (view !== "workbench") window.scrollTo({ top: 0 });
  listeners.forEach((listener) => listener(view));
}

/**
 * Marks the nav rail when its content is wider than the rail itself.
 *
 * The responsive ladder is sized so the rail always fits, but a long
 * translation or an unusual font fallback could still overflow it. Overflow
 * that scrolls without saying so is the failure mode worth guarding against,
 * so the class drives a visible edge fade rather than being purely cosmetic.
 */
export function trackNavOverflow(): void {
  const rail = document.querySelector<HTMLElement>("#app-nav");
  if (rail === null) return;
  const sync = (): void => {
    rail.classList.toggle("is-scrollable", rail.scrollWidth > rail.clientWidth + 1);
  };
  sync();
  new ResizeObserver(sync).observe(rail);
}

/** Wires every `[data-nav]` trigger and restores the view from the URL hash. */
export function initNavigation(): void {
  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const trigger = target.closest<HTMLElement>("[data-nav]");
    if (trigger === null) return;
    const view = trigger.dataset.nav ?? "";
    if (!isViewName(view)) return;
    event.preventDefault();
    showView(view);
  });

  window.addEventListener("hashchange", () => {
    const view = window.location.hash.replace("#", "");
    if (isViewName(view) && view !== current) showView(view);
  });

  const initial = window.location.hash.replace("#", "");
  showView(isViewName(initial) ? initial : "start");
}
