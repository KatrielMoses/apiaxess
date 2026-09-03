import { escapeHtml, stateBlock } from "./dom";

/** The engine's canonical diagnostic shape: what happened, why, and the fix. */
export interface Diagnostic {
  readonly id: string;
  readonly what: string;
  readonly why: string;
  readonly fix: string;
}

/**
 * Presentation tone only. The engine does not send a severity, so this is a
 * display heuristic over the diagnostic ID and is never used for control flow.
 */
function tone(diagnostic: Diagnostic): "danger" | "caution" | "info" {
  const id = diagnostic.id.toLowerCase();
  if (/failed|unavailable|invalid|denied/.test(id)) return "danger";
  if (/required|missing|not-found|degraded/.test(id)) return "caution";
  return "info";
}

/** Renders one diagnostic as the what / why / fix block used everywhere. */
export function diagnosticHtml(diagnostic: Diagnostic): string {
  return `<article class="diagnostic diagnostic--${tone(diagnostic)}">
<p class="diagnostic__id">${escapeHtml(diagnostic.id)}</p>
<p class="diagnostic__what">${escapeHtml(diagnostic.what)}</p>
<div class="diagnostic__line"><span>Why</span><p>${escapeHtml(diagnostic.why)}</p></div>
<div class="diagnostic__line"><span>Fix</span><p>${escapeHtml(diagnostic.fix)}</p></div>
</article>`;
}

/**
 * Renders a list of diagnostics, or a branded empty state when there are none.
 * Null entries — how the engine encodes "no diagnostic" inside a collection —
 * are dropped rather than rendered as empty blocks.
 */
export function diagnosticListHtml(
  entries: readonly (Diagnostic | null | undefined)[],
  emptyBody: string,
): string {
  const diagnostics = entries.filter(
    (entry): entry is Diagnostic => entry !== null && entry !== undefined,
  );
  if (diagnostics.length === 0) {
    return stateBlock({
      icon: "check",
      title: "Nothing reported",
      body: emptyBody,
      compact: true,
    });
  }
  return diagnostics.map(diagnosticHtml).join("");
}

/**
 * The session-wide diagnostics log, surfaced in the header drawer. Entries are
 * deduplicated on identity plus cause so a polling loop cannot flood it.
 */
export class DiagnosticsLog {
  readonly #entries: Diagnostic[] = [];
  #seen = 0;

  get entries(): readonly Diagnostic[] {
    return this.#entries;
  }

  /** Records a diagnostic. Returns true when it was new to this session. */
  push(diagnostic: Diagnostic): boolean {
    const duplicate = this.#entries.some(
      (entry) => entry.id === diagnostic.id && entry.why === diagnostic.why,
    );
    if (duplicate) return false;
    this.#entries.push(diagnostic);
    this.render();
    return true;
  }

  clear(): void {
    this.#entries.length = 0;
    this.#seen = 0;
    this.render();
  }

  /** Marks everything currently logged as read, clearing the header count. */
  markRead(): void {
    this.#seen = this.#entries.length;
    this.render();
  }

  render(): void {
    const list = document.querySelector<HTMLElement>("#diagnostic-text");
    const count = document.querySelector<HTMLElement>("#diagnostics-count");
    const summary = document.querySelector<HTMLElement>("#diagnostics-summary");
    const toggle = document.querySelector<HTMLElement>("#diagnostics-toggle");

    if (list !== null) {
      list.innerHTML =
        this.#entries.length === 0
          ? stateBlock({
              icon: "check",
              title: "No diagnostics",
              body: "Anything the engine cannot do, or can only do partially, is reported here with its cause and its fix.",
              compact: true,
            })
          : [...this.#entries].reverse().map(diagnosticHtml).join("");
    }

    const unread = Math.max(0, this.#entries.length - this.#seen);
    if (count !== null) {
      count.textContent = unread > 99 ? "99+" : String(unread);
      count.hidden = unread === 0;
    }
    if (summary !== null) {
      summary.textContent =
        this.#entries.length === 0
          ? "No diagnostics"
          : `${this.#entries.length} diagnostic${this.#entries.length === 1 ? "" : "s"} this session`;
    }
    if (toggle !== null) {
      toggle.title =
        this.#entries.length === 0
          ? "Diagnostics"
          : `Diagnostics — ${this.#entries.length} recorded`;
    }
  }
}

/** Wires the drawer's open, close, and clear controls. */
export function initDiagnosticsDrawer(log: DiagnosticsLog): void {
  const drawer = document.querySelector<HTMLElement>("#diagnostics-drawer");
  const toggle = document.querySelector<HTMLButtonElement>("#diagnostics-toggle");
  const close = document.querySelector<HTMLButtonElement>("#diagnostics-close");
  const clear = document.querySelector<HTMLButtonElement>("#diagnostics-clear");
  if (drawer === null || toggle === null) return;

  const setOpen = (open: boolean): void => {
    drawer.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) log.markRead();
  };

  toggle.addEventListener("click", () => setOpen(drawer.hidden));
  close?.addEventListener("click", () => setOpen(false));
  clear?.addEventListener("click", () => log.clear());
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !drawer.hidden) setOpen(false);
  });
}
