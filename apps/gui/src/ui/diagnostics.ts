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
 * Renders diagnostics grouped by cause (their `id`), newest cause first. A single
 * pass can raise the same cause many times with a different `why` each — e.g. one
 * static-analysis note per unbound endpoint — so one card per cause with an
 * occurrence count and its distinct reasons is legible where dozens of near-
 * identical cards are not. The what and fix are stable per cause; only the reasons vary.
 */
export function aggregatedDiagnosticsHtml(entries: readonly Diagnostic[]): string {
  const groups = new Map<string, Diagnostic[]>();
  for (const entry of entries) {
    const group = groups.get(entry.id);
    if (group === undefined) groups.set(entry.id, [entry]);
    else group.push(entry);
  }
  return [...groups.values()]
    .reverse()
    .map((group) => {
      const head = group[0];
      if (head === undefined) return "";
      const reasons = [...new Set(group.map((entry) => entry.why).filter((why) => why !== ""))];
      const count = group.length;
      const whyBlock =
        reasons.length <= 1
          ? `<div class="diagnostic__line"><span>Why</span><p>${escapeHtml(head.why)}</p></div>`
          : `<div class="diagnostic__line"><span>Why</span><ul class="diagnostic__causes">${reasons
              .slice(0, 5)
              .map((why) => `<li>${escapeHtml(why)}</li>`)
              .join("")}${reasons.length > 5 ? `<li class="t-subtle">+${reasons.length - 5} more</li>` : ""}</ul></div>`;
      return `<article class="diagnostic diagnostic--${tone(head)}">
<p class="diagnostic__id">${escapeHtml(head.id)}${count > 1 ? `<span class="diagnostic__count">×${count}</span>` : ""}</p>
<p class="diagnostic__what">${escapeHtml(head.what)}</p>
${whyBlock}
<div class="diagnostic__line"><span>Fix</span><p>${escapeHtml(head.fix)}</p></div>
</article>`;
    })
    .join("");
}

/** A diagnostic with its typed context (engine `DiagnosticValue`s). */
export interface ContextualDiagnostic extends Diagnostic {
  readonly context?: Readonly<Record<string, { readonly type?: string; readonly value?: unknown }>>;
}

/**
 * Surface diagnostics grouped by cause, each card saying how many times it
 * was raised and naming what it concerns — the endpoint and the kind of fact
 * from its context — so hundreds of identical cards become one actionable one.
 */
export function groupedSurfaceDiagnosticsHtml(
  entries: readonly (ContextualDiagnostic | null | undefined)[],
  emptyBody: string,
): string {
  const diagnostics = entries.filter(
    (entry): entry is ContextualDiagnostic => entry !== null && entry !== undefined,
  );
  if (diagnostics.length === 0) {
    return stateBlock({ icon: "check", title: "Nothing reported", body: emptyBody, compact: true });
  }
  const text = (entry: ContextualDiagnostic, key: string): string => {
    const value = entry.context?.[key]?.value;
    return typeof value === "string" ? value : "";
  };
  const groups = new Map<string, ContextualDiagnostic[]>();
  for (const entry of diagnostics) {
    const group = groups.get(entry.id);
    if (group === undefined) groups.set(entry.id, [entry]);
    else group.push(entry);
  }
  return [...groups.values()]
    .sort((a, b) => b.length - a.length)
    .map((group) => {
      const head = group[0]!;
      // What each occurrence is about: "GET host/path · query parameter".
      const subjects = new Map<string, number>();
      for (const entry of group) {
        const endpoint = text(entry, "endpoint");
        const fact = text(entry, "fact");
        const subject = [endpoint, fact].filter((part) => part !== "").join(" · ") || text(entry, "path");
        if (subject !== "") subjects.set(subject, (subjects.get(subject) ?? 0) + 1);
      }
      const named = [...subjects.entries()].sort((a, b) => b[1] - a[1]);
      const subjectBlock = named.length === 0
        ? ""
        : `<div class="diagnostic__line"><span>About</span><ul class="diagnostic__causes">${named
            .slice(0, 8)
            .map(([subject, count]) => `<li><span class="t-mono">${escapeHtml(subject)}</span>${count > 1 ? ` <span class="t-subtle">×${count}</span>` : ""}</li>`)
            .join("")}${named.length > 8 ? `<li class="t-subtle">+${named.length - 8} more</li>` : ""}</ul></div>`;
      return `<article class="diagnostic diagnostic--${tone(head)}">
<p class="diagnostic__id">${escapeHtml(head.id)}${group.length > 1 ? `<span class="diagnostic__count">×${group.length}</span>` : ""}</p>
<p class="diagnostic__what">${escapeHtml(head.what)}</p>
<div class="diagnostic__line"><span>Why</span><p>${escapeHtml(head.why)}</p></div>
${subjectBlock}
<div class="diagnostic__line"><span>Fix</span><p>${escapeHtml(head.fix)}</p></div>
</article>`;
    })
    .join("");
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
  /** Causes (diagnostic ids) the operator has seen in the drawer. Every badge
   *  counts causes, so unread is counted in causes too. */
  readonly #seenCauses = new Set<string>();

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
    this.#seenCauses.clear();
    this.render();
  }

  /** Marks everything currently logged as read, clearing the header count. */
  markRead(): void {
    this.#entries.forEach((entry) => this.#seenCauses.add(entry.id));
    this.render();
  }

  render(): void {
    const list = document.querySelector<HTMLElement>("#diagnostic-text");
    const dockList = document.querySelector<HTMLElement>("#dock-diagnostics");
    const dockCount = document.querySelector<HTMLElement>("#dock-diag-count");
    const statusCell = document.querySelector<HTMLElement>("#statusbar-diag");
    const count = document.querySelector<HTMLElement>("#diagnostics-count");
    const summary = document.querySelector<HTMLElement>("#diagnostics-summary");
    const toggle = document.querySelector<HTMLElement>("#diagnostics-toggle");
    const total = this.#entries.length;

    // Count distinct causes, not raw events: the cards are grouped by cause, so
    // the badges must agree with what the operator actually sees.
    const causes = new Set(this.#entries.map((entry) => entry.id)).size;
    const body =
      total === 0
        ? stateBlock({
            icon: "check",
            title: "No diagnostics",
            body: "Anything the engine cannot do, or can only do partially, is reported here with its cause and its fix.",
            compact: true,
          })
        : aggregatedDiagnosticsHtml(this.#entries);
    if (list !== null) list.innerHTML = body;
    if (dockList !== null) dockList.innerHTML = body;

    // The dock badge and the status-bar cell are failure indicators: they carry
    // red and appear only when there is something to show — never at zero.
    if (dockCount !== null) {
      dockCount.textContent = String(causes);
      dockCount.hidden = causes === 0;
    }
    if (statusCell !== null) {
      statusCell.textContent = `${causes} DIAGNOSTIC${causes === 1 ? "" : "S"}`;
      statusCell.hidden = causes === 0;
    }

    const unread = new Set(this.#entries.map((entry) => entry.id).filter((id) => !this.#seenCauses.has(id))).size;
    if (count !== null) {
      count.textContent = unread > 99 ? "99+" : String(unread);
      count.hidden = unread === 0;
    }
    if (summary !== null) {
      summary.textContent = causes === 0 ? "No diagnostics" : `${causes} cause${causes === 1 ? "" : "s"} this session`;
    }
    if (toggle !== null) {
      toggle.title = causes === 0 ? "Diagnostics" : `Diagnostics — ${causes} cause${causes === 1 ? "" : "s"}${unread === 0 ? "" : `, ${unread} new`}`;
    }
    const clear = document.querySelector<HTMLButtonElement>("#diagnostics-clear");
    if (clear !== null) clear.disabled = total === 0;
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
