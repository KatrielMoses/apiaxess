/**
 * Desktop shell behaviour.
 *
 * The shell chrome — title bar, rail, sidebar, dock, status bar — is persistent
 * for the life of the session; only the content pane swaps surfaces. This module
 * keeps that chrome in sync with the active view, hosts the shared bottom dock,
 * and gives the panes an editor's resize/toggle behaviour with per-session
 * layout persistence, all without ever remounting a streaming container.
 */

import { icon, type IconName } from "../brand/icons";
import { onViewChange, showView, type ViewName } from "./nav";

/** Which workspace phase (rail cell) owns each surface. */
const VIEW_PHASE: Record<ViewName, string> = {
  start: "capture",
  web: "capture",
  apk: "capture",
  android: "capture",
  devices: "capture",
  workbench: "bench",
  surface: "surface",
  export: "deliver",
  session: "deliver",
  settings: "settings",
  about: "",
};

/** The status-bar surface-name cell (first cell, on accent). */
const VIEW_STATUS: Record<ViewName, string> = {
  start: "START",
  web: "WEB CAPTURE",
  apk: "APK ANALYSIS",
  android: "ANDROID TARGET",
  devices: "DEVICES",
  workbench: "WORKBENCH",
  surface: "API SURFACE",
  export: "EXPORT",
  session: "SESSION & AUDIT",
  settings: "SETTINGS",
  about: "ABOUT",
};

/** Surfaces reachable from the command palette, in menu order. */
const PALETTE_ITEMS: { view: ViewName; label: string; icon: IconName; group: string }[] = [
  { view: "web", label: "Web capture", icon: "web", group: "CAPTURE" },
  { view: "apk", label: "APK analysis", icon: "apk", group: "CAPTURE" },
  { view: "android", label: "Android target", icon: "apk", group: "CAPTURE" },
  { view: "devices", label: "Devices", icon: "shield", group: "CAPTURE" },
  { view: "workbench", label: "Workbench", icon: "traffic", group: "ANALYSE" },
  { view: "surface", label: "API surface", icon: "surface", group: "ANALYSE" },
  { view: "export", label: "Export", icon: "export", group: "DELIVER" },
  { view: "session", label: "Session & audit", icon: "session", group: "DELIVER" },
  { view: "settings", label: "Settings", icon: "settings", group: "DELIVER" },
  { view: "start", label: "Start", icon: "spark", group: "" },
  { view: "about", label: "About", icon: "help", group: "" },
];

const PANE_DEFAULTS = { sidebar: 192, inspector: 340, dock: 132 } as const;
const PANE_LIMITS = {
  sidebar: { min: 160, max: 320 },
  inspector: { min: 280, max: 520 },
  // The dock is a real working pane (traffic queue, diagnostics); let it grow to
  // roughly two-thirds of a 900px viewport so it is genuinely usable, not a sliver.
  dock: { min: 88, max: 620 },
} as const;

let shell: HTMLElement;

/** Reads the id of the active session so layout persists per session, not globally. */
function sessionKey(): string {
  const id = document.querySelector<HTMLElement>("#header-session")?.textContent?.trim() ?? "";
  return id === "" || /no session/i.test(id) ? "default" : id;
}

interface Layout {
  sidebar?: number;
  inspector?: number;
  dock?: number;
  sidebarOpen?: boolean;
  dockOpen?: boolean;
  inspectorOpen?: boolean;
}

function readLayout(): Layout {
  try {
    return JSON.parse(window.localStorage.getItem(`apiaxess.layout.${sessionKey()}`) ?? "{}") as Layout;
  } catch {
    return {};
  }
}
function writeLayout(patch: Layout): void {
  try {
    const next = { ...readLayout(), ...patch };
    window.localStorage.setItem(`apiaxess.layout.${sessionKey()}`, JSON.stringify(next));
  } catch {
    /* storage is a convenience; the live layout still holds */
  }
}

function setPane(pane: "sidebar" | "inspector" | "dock", px: number, persist = true): void {
  const { min, max } = PANE_LIMITS[pane];
  const clamped = Math.max(min, Math.min(max, Math.round(px)));
  const varName = pane === "sidebar" ? "--sidebar-w" : pane === "inspector" ? "--inspector-w" : "--dock-h";
  shell.style.setProperty(varName, `${clamped}px`);
  if (persist) writeLayout({ [pane]: clamped });
}

function toggle(attr: "sidebar" | "dock" | "inspector", force?: boolean): void {
  const key = `data-${attr}` as const;
  const open = force ?? shell.getAttribute(key) === "collapsed";
  shell.setAttribute(key, open ? "open" : "collapsed");
  writeLayout({ [`${attr}Open`]: open });
  syncStatusAffordances();
}

/** Shows a status-bar affordance for each collapsed pane so nothing hides silently. */
function syncStatusAffordances(): void {
  const sidebarCell = document.querySelector<HTMLElement>("#statusbar-sidebar");
  const dockCell = document.querySelector<HTMLElement>("#statusbar-dock");
  if (sidebarCell !== null) sidebarCell.hidden = shell.getAttribute("data-sidebar") !== "collapsed";
  if (dockCell !== null) dockCell.hidden = shell.getAttribute("data-dock") !== "collapsed";
}

/* ------------------------------------------------------------------ *
 * Rail / sidebar / status-bar sync
 * ------------------------------------------------------------------ */

function syncActiveView(view: ViewName): void {
  const phase = VIEW_PHASE[view];
  shell.querySelectorAll<HTMLElement>(".rail__cell").forEach((cell) => {
    cell.classList.toggle("is-active", cell.dataset.phase === phase);
    if (cell.dataset.phase === phase) cell.setAttribute("aria-current", "true");
    else cell.removeAttribute("aria-current");
  });
  shell.querySelectorAll<HTMLElement>(".modrow").forEach((row) => {
    const active = row.dataset.nav === view;
    row.classList.toggle("is-active", active);
    if (active) row.setAttribute("aria-current", "page");
    else row.removeAttribute("aria-current");
  });
  const surfaceCell = document.querySelector<HTMLElement>("#statusbar-surface");
  if (surfaceCell !== null) surfaceCell.textContent = VIEW_STATUS[view];
}

/* ------------------------------------------------------------------ *
 * Bottom dock
 * ------------------------------------------------------------------ */

/** Relocates the intercept queue into the shared bottom dock. Resend and Fuzz
 *  are full Workbench tools (Repeater/Intruder register), so they stay in the
 *  Workbench — only the queue and diagnostics are dock-resident. Moving (not
 *  cloning) keeps element identity and every wired socket/listener intact. */
function adoptDock(): void {
  const move = (id: string, into: string): void => {
    const node = document.getElementById(id);
    const host = document.getElementById(into);
    if (node !== null && host !== null) host.appendChild(node);
  };
  move("queue-list", "dock-queue");
  document.getElementById("queue-list")?.removeAttribute("hidden");

  const tabs = Array.from(shell.querySelectorAll<HTMLElement>(".dock__tab"));
  const panels = Array.from(shell.querySelectorAll<HTMLElement>(".dock__panel"));
  const select = (name: string): void => {
    tabs.forEach((t) => {
      const on = t.dataset.docktab === name;
      t.classList.toggle("is-active", on);
      t.setAttribute("aria-selected", String(on));
    });
    panels.forEach((p) => p.classList.toggle("is-active", p.dataset.dockpanel === name));
  };
  tabs.forEach((tab) => tab.addEventListener("click", () => select(tab.dataset.docktab ?? "queue")));

  // Keep the dock queue badge and the status-bar count live off the real list.
  const queue = document.getElementById("queue-list");
  const badge = document.getElementById("dock-queue-badge");
  if (queue !== null && badge !== null) {
    const sync = (): void => {
      const n = queue.querySelectorAll(".queue-item, [data-queue-item], li, .list__row").length;
      badge.textContent = String(n);
      badge.hidden = n === 0;
    };
    new MutationObserver(sync).observe(queue, { childList: true, subtree: true });
    sync();
  }
}

/* ------------------------------------------------------------------ *
 * Resizing
 * ------------------------------------------------------------------ */

function currentPx(pane: "sidebar" | "inspector" | "dock"): number {
  const varName = pane === "sidebar" ? "--sidebar-w" : pane === "inspector" ? "--inspector-w" : "--dock-h";
  return parseInt(getComputedStyle(shell).getPropertyValue(varName), 10) || PANE_DEFAULTS[pane];
}

type Pane = "sidebar" | "dock" | "inspector";

/** Adds the inspector splitter into the workbench grid so region 7 is resizable
 *  like the other panes. It is workbench-local, so it is injected rather than
 *  living in the shared shell markup. */
function injectInspectorSplitter(): void {
  const grid = document.querySelector<HTMLElement>(".workbench__grid");
  const detail = document.querySelector<HTMLElement>(".workbench__pane--detail");
  if (grid === null || detail === null || grid.querySelector(".splitter--inspector") !== null) return;
  const splitter = document.createElement("div");
  splitter.className = "splitter splitter--inspector";
  splitter.dataset.splitter = "inspector";
  splitter.setAttribute("role", "separator");
  splitter.setAttribute("aria-orientation", "vertical");
  splitter.setAttribute("aria-label", "Resize inspector");
  splitter.tabIndex = 0;
  grid.insertBefore(splitter, detail);
}

function initSplitters(): void {
  shell.querySelectorAll<HTMLElement>(".splitter").forEach((splitter) => {
    const pane = splitter.dataset.splitter as Pane | undefined;
    if (pane === undefined) return;
    const horizontal = pane === "sidebar" || pane === "inspector";

    splitter.addEventListener("dblclick", (event) => {
      if (event.altKey) resetAllPanes();
      else setPane(pane, PANE_DEFAULTS[pane]);
    });

    splitter.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      splitter.setPointerCapture(event.pointerId);
      const startPos = horizontal ? event.clientX : event.clientY;
      const startSize = currentPx(pane);
      const move = (e: PointerEvent): void => {
        // Sidebar grows to the right, inspector to the left, dock upward.
        const delta =
          pane === "sidebar" ? e.clientX - startPos : pane === "inspector" ? startPos - e.clientX : startPos - e.clientY;
        setPane(pane, startSize + delta, false);
      };
      const up = (): void => {
        splitter.releasePointerCapture(event.pointerId);
        splitter.removeEventListener("pointermove", move);
        splitter.removeEventListener("pointerup", up);
        setPane(pane, currentPx(pane));
      };
      splitter.addEventListener("pointermove", move);
      splitter.addEventListener("pointerup", up);
    });

    splitter.addEventListener("keydown", (event) => {
      const step = event.shiftKey ? 24 : 8;
      if (pane === "sidebar" && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
        setPane("sidebar", currentPx("sidebar") + (event.key === "ArrowRight" ? step : -step));
        event.preventDefault();
      } else if (pane === "inspector" && (event.key === "ArrowLeft" || event.key === "ArrowRight")) {
        setPane("inspector", currentPx("inspector") + (event.key === "ArrowLeft" ? step : -step));
        event.preventDefault();
      } else if (pane === "dock" && (event.key === "ArrowUp" || event.key === "ArrowDown")) {
        setPane("dock", currentPx("dock") + (event.key === "ArrowUp" ? step : -step));
        event.preventDefault();
      }
    });
  });
}

/** Auto-manages pane visibility across the sheet-04 breakpoints without ever
 *  overwriting the operator's persisted preference above the breakpoint. */
function initResponsive(): void {
  const cramped = window.matchMedia("(max-width: 1119px)");
  const narrow = window.matchMedia("(max-width: 899px)");
  const apply = (): void => {
    shell.classList.toggle("is-cramped", cramped.matches);
    shell.classList.toggle("is-narrow", narrow.matches);
    const layout = readLayout();
    shell.setAttribute("data-sidebar", cramped.matches || layout.sidebarOpen === false ? "collapsed" : "open");
    shell.setAttribute("data-dock", narrow.matches || layout.dockOpen === false ? "collapsed" : "open");
    syncStatusAffordances();
  };
  cramped.addEventListener("change", apply);
  narrow.addEventListener("change", apply);
  apply();
}

function resetAllPanes(): void {
  setPane("sidebar", PANE_DEFAULTS.sidebar);
  setPane("inspector", PANE_DEFAULTS.inspector);
  setPane("dock", PANE_DEFAULTS.dock);
  toggle("sidebar", true);
  toggle("dock", true);
  toggle("inspector", true);
}

function restoreLayout(): void {
  const layout = readLayout();
  if (layout.sidebar !== undefined) setPane("sidebar", layout.sidebar, false);
  if (layout.inspector !== undefined) setPane("inspector", layout.inspector, false);
  if (layout.dock !== undefined) setPane("dock", layout.dock, false);
  if (layout.sidebarOpen === false) shell.setAttribute("data-sidebar", "collapsed");
  if (layout.dockOpen === false) shell.setAttribute("data-dock", "collapsed");
  if (layout.inspectorOpen === false) shell.setAttribute("data-inspector", "collapsed");
  syncStatusAffordances();
}

/* ------------------------------------------------------------------ *
 * Command palette
 * ------------------------------------------------------------------ */

let paletteEl: HTMLElement | null = null;
let lastFocus: HTMLElement | null = null;

function openPalette(): void {
  if (paletteEl !== null) return;
  lastFocus = document.activeElement as HTMLElement | null;
  const scrim = document.createElement("div");
  scrim.className = "palette__scrim";
  scrim.innerHTML = `
    <div class="palette" role="dialog" aria-modal="true" aria-label="Command palette">
      <input class="palette__input" type="text" placeholder="Go to surface, flow, endpoint or command" autocomplete="off" spellcheck="false" aria-label="Command palette" />
      <div class="palette__list" role="listbox"></div>
    </div>`;
  document.body.appendChild(scrim);
  paletteEl = scrim;
  const input = scrim.querySelector<HTMLInputElement>(".palette__input");
  const list = scrim.querySelector<HTMLElement>(".palette__list");
  if (input === null || list === null) return;

  let active = 0;
  const render = (): void => {
    const q = input.value.trim().toLowerCase();
    const matches = PALETTE_ITEMS.filter((i) => i.label.toLowerCase().includes(q));
    active = Math.min(active, Math.max(0, matches.length - 1));
    list.innerHTML = matches
      .map(
        (m, i) =>
          `<button class="palette__item${i === active ? " is-active" : ""}" role="option" data-view="${m.view}">${icon(m.icon, { size: 15 })}<span>${m.label}</span>${m.group === "" ? "" : `<span class="palette__item-group">${m.group}</span>`}</button>`,
      )
      .join("");
    list.querySelectorAll<HTMLElement>(".palette__item").forEach((el, i) => {
      el.addEventListener("mouseenter", () => {
        active = i;
        markActive();
      });
      el.addEventListener("click", () => choose(el.dataset.view as ViewName));
    });
  };
  const markActive = (): void => {
    list.querySelectorAll<HTMLElement>(".palette__item").forEach((el, i) => {
      el.classList.toggle("is-active", i === active);
      if (i === active) el.scrollIntoView({ block: "nearest" });
    });
  };
  const choose = (view: ViewName | undefined): void => {
    closePalette();
    if (view !== undefined) showView(view);
  };
  input.addEventListener("input", render);
  input.addEventListener("keydown", (event) => {
    const items = list.querySelectorAll<HTMLElement>(".palette__item");
    if (event.key === "ArrowDown") {
      active = Math.min(active + 1, items.length - 1);
      markActive();
      event.preventDefault();
    } else if (event.key === "ArrowUp") {
      active = Math.max(active - 1, 0);
      markActive();
      event.preventDefault();
    } else if (event.key === "Enter") {
      choose(items[active]?.dataset.view as ViewName | undefined);
      event.preventDefault();
    } else if (event.key === "Escape") {
      closePalette();
      event.preventDefault();
    }
  });
  scrim.addEventListener("pointerdown", (event) => {
    if (event.target === scrim) closePalette();
  });
  render();
  input.focus();
}

function closePalette(): void {
  paletteEl?.remove();
  paletteEl = null;
  lastFocus?.focus();
}

/* ------------------------------------------------------------------ *
 * Menu bar (real dropdown menus)
 * ------------------------------------------------------------------ */

interface MenuItem {
  label: string;
  hint?: string;
  run: () => void;
}
type MenuEntry = MenuItem | "separator";
interface Menu {
  id: string;
  label: string;
  items: MenuEntry[];
}

/** Triggers an existing surface control by id, so menu items reuse the real
 *  actions rather than re-implementing them. */
function clickId(id: string): void {
  document.getElementById(id)?.click();
}

function menuModel(): Menu[] {
  return [
    {
      id: "file",
      label: "File",
      items: [
        { label: "New session", run: () => { showView("session"); clickId("session-new"); } },
        { label: "Open session…", run: () => { showView("session"); clickId("session-open"); } },
        { label: "Save session", run: () => { showView("session"); clickId("session-save"); } },
        "separator",
        { label: "Export artifacts…", run: () => showView("export") },
        "separator",
        { label: "Settings", run: () => showView("settings") },
      ],
    },
    {
      id: "capture",
      label: "Capture",
      items: [
        { label: "Web capture", run: () => showView("web") },
        { label: "APK analysis", run: () => showView("apk") },
        { label: "Android target", run: () => showView("android") },
        { label: "Devices", run: () => showView("devices") },
      ],
    },
    {
      id: "view",
      label: "View",
      items: [
        { label: "Workbench", run: () => showView("workbench") },
        { label: "API surface", run: () => showView("surface") },
        { label: "Session & audit", run: () => showView("session") },
        "separator",
        { label: "Toggle sidebar", hint: "⌘B", run: () => toggle("sidebar") },
        { label: "Toggle dock", hint: "⌘J", run: () => toggle("dock") },
        { label: "Toggle inspector", hint: "⌘⌥I", run: () => toggle("inspector") },
        "separator",
        { label: "Command palette", hint: "⌘K", run: () => openPalette() },
      ],
    },
    {
      id: "help",
      label: "Help",
      items: [{ label: "About APIaxess", run: () => showView("about") }],
    },
  ];
}

let openMenuId: string | null = null;

function initMenubar(): void {
  const bar = document.getElementById("menubar");
  if (bar === null) return;
  const model = menuModel();
  bar.innerHTML = model
    .map(
      (m) =>
        `<button class="menubar__item" type="button" data-menu="${m.id}" aria-haspopup="true" aria-expanded="false">${m.label}</button>`,
    )
    .join("");

  const closeMenu = (): void => {
    openMenuId = null;
    bar.querySelectorAll<HTMLElement>(".menubar__item").forEach((b) => b.setAttribute("aria-expanded", "false"));
    document.getElementById("menu-dropdown")?.remove();
  };

  const openAt = (menu: Menu, trigger: HTMLElement): void => {
    closeMenu();
    openMenuId = menu.id;
    trigger.setAttribute("aria-expanded", "true");
    const drop = document.createElement("div");
    drop.className = "menu-dropdown";
    drop.id = "menu-dropdown";
    drop.setAttribute("role", "menu");
    drop.innerHTML = menu.items
      .map((entry) =>
        entry === "separator"
          ? `<div class="menu-dropdown__sep" role="separator"></div>`
          : `<button class="menu-dropdown__item" type="button" role="menuitem">${entry.label}${entry.hint === undefined ? "" : `<span class="menu-dropdown__hint">${entry.hint}</span>`}</button>`,
      )
      .join("");
    const rect = trigger.getBoundingClientRect();
    drop.style.left = `${Math.round(rect.left)}px`;
    drop.style.top = `${Math.round(rect.bottom)}px`;
    document.body.appendChild(drop);
    const actions = menu.items.filter((entry): entry is MenuItem => entry !== "separator");
    drop.querySelectorAll<HTMLElement>(".menu-dropdown__item").forEach((el, index) => {
      el.addEventListener("click", () => {
        closeMenu();
        actions[index]?.run();
      });
    });
  };

  bar.querySelectorAll<HTMLElement>(".menubar__item").forEach((trigger) => {
    const menu = model.find((m) => m.id === trigger.dataset.menu);
    if (menu === undefined) return;
    trigger.addEventListener("click", (event) => {
      event.stopPropagation();
      if (openMenuId === menu.id) closeMenu();
      else openAt(menu, trigger);
    });
    // Once a menu is open, hovering a sibling switches to it — the standard
    // desktop menu-bar behaviour.
    trigger.addEventListener("mouseenter", () => {
      if (openMenuId !== null && openMenuId !== menu.id) openAt(menu, trigger);
    });
  });

  document.addEventListener("click", (event) => {
    const target = event.target as Element | null;
    if (openMenuId !== null && target?.closest("#menu-dropdown, .menubar__item") === null) closeMenu();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && openMenuId !== null) closeMenu();
  });
}

/* ------------------------------------------------------------------ *
 * Window controls (native under the desktop shell, inert in a browser)
 * ------------------------------------------------------------------ */

function initWindowControls(): void {
  const tauri = (window as unknown as { __TAURI__?: { window?: { appWindow?: Record<string, () => void> } } }).__TAURI__;
  const appWindow = tauri?.window?.appWindow;
  shell.querySelectorAll<HTMLButtonElement>(".wincontrol").forEach((btn) => {
    const which = btn.dataset.win;
    if (appWindow === undefined) {
      btn.title = "Window controls — active in the desktop app";
      return;
    }
    btn.addEventListener("click", () => {
      if (which === "min") appWindow.minimize?.();
      else if (which === "max") appWindow.toggleMaximize?.();
      else if (which === "close") appWindow.close?.();
    });
  });
}

/* ------------------------------------------------------------------ *
 * Init
 * ------------------------------------------------------------------ */

export function initShell(): void {
  const el = document.getElementById("shell");
  if (el === null) return;
  shell = el;

  adoptDock();
  initMenubar();
  injectInspectorSplitter();
  initSplitters();
  restoreLayout();
  initResponsive();
  initWindowControls();

  // Brand lockup returns to Start.
  document.getElementById("header-lockup")?.addEventListener("click", () => showView("start"));

  // Status-bar affordances and the omnibox.
  document.querySelectorAll<HTMLElement>("[data-toggle]").forEach((cell) =>
    cell.addEventListener("click", () => toggle(cell.dataset.toggle as "sidebar" | "dock")),
  );
  document.getElementById("omnibox")?.addEventListener("click", openPalette);
  document.getElementById("statusbar-diag")?.addEventListener("click", () =>
    document.getElementById("diagnostics-toggle")?.click(),
  );

  // Keyboard: pane toggles, palette, and jump-to-module.
  document.addEventListener("keydown", (event) => {
    const mod = event.metaKey || event.ctrlKey;
    if (mod && event.key.toLowerCase() === "k") {
      openPalette();
      event.preventDefault();
    } else if (mod && event.altKey && event.key.toLowerCase() === "i") {
      toggle("inspector");
      event.preventDefault();
    } else if (mod && event.key.toLowerCase() === "b") {
      toggle("sidebar");
      event.preventDefault();
    } else if (mod && event.key.toLowerCase() === "j") {
      toggle("dock");
      event.preventDefault();
    } else if (mod && /^[1-9]$/.test(event.key)) {
      const rows = shell.querySelectorAll<HTMLElement>(".modrow");
      rows[Number(event.key) - 1]?.click();
      event.preventDefault();
    }
  });

  onViewChange(syncActiveView);
}
