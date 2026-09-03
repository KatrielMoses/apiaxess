import { icon, type IconName } from "../brand/icons";
import { escapeHtml } from "./dom";

type ToastTone = "info" | "success" | "danger";

const TONE_ICON: Record<ToastTone, IconName> = {
  info: "info",
  success: "check",
  danger: "alert",
};

/**
 * Transient confirmation of something that completed. Toasts never carry the
 * only copy of a diagnostic — those go to the diagnostics drawer, which
 * persists — so dismissing one loses nothing.
 */
export function toast(message: string, tone: ToastTone = "info"): void {
  const stack = document.querySelector<HTMLElement>("#toast-stack");
  if (stack === null) return;
  const node = document.createElement("div");
  node.className = tone === "info" ? "toast" : `toast toast--${tone}`;
  node.innerHTML = `<span class="toast__icon">${icon(TONE_ICON[tone], { size: 18 })}</span><span class="toast__body">${escapeHtml(message)}</span>`;
  stack.append(node);
  window.setTimeout(() => node.remove(), 6000);
}
