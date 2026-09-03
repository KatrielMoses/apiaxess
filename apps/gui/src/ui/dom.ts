import { type IconName, icon } from "../brand/icons";

/** Escapes text for interpolation into the app's string-built markup. */
export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Replaces every `[data-icon]` placeholder inside `root` with its rendered
 * glyph. Static markup declares which icon it wants; the icon system decides
 * how it looks, so the two never drift.
 */
export function hydrateIcons(root: ParentNode = document): void {
  root.querySelectorAll<HTMLElement>("[data-icon]").forEach((host) => {
    const name = host.dataset.icon as IconName | undefined;
    if (name === undefined) return;
    const size = Number(host.dataset.iconSize ?? "16");
    host.insertAdjacentHTML(
      "afterbegin",
      icon(name, { size: Number.isFinite(size) ? size : 16 }),
    );
    host.removeAttribute("data-icon");
  });
}

/**
 * Renders a branded empty/loading/error state.
 */
export function stateBlock(options: {
  readonly icon: IconName;
  readonly title: string;
  readonly body: string;
  readonly compact?: boolean;
}): string {
  const compact = options.compact === true ? " state--compact" : "";
  return `<div class="state${compact}"><span class="state__icon">${icon(options.icon, { size: 26 })}</span><p class="state__title">${escapeHtml(options.title)}</p><p class="state__body">${escapeHtml(options.body)}</p></div>`;
}

/** Formats a byte count for display without pretending to more precision. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Local, human-readable timestamp for audit and history rows. */
export function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
