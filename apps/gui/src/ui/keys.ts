/* Keyboard-shortcut labels in the host platform's own terms: the Mac glyphs
 * (⌘ ⌥ ⇧) on macOS, and Ctrl / Alt / Shift everywhere else — where the same
 * shortcuts are bound (the handler accepts Ctrl or ⌘). Pure helpers, no DOM
 * state beyond the elements they are given. */

/** Whether this host labels modifiers with the Mac glyphs. */
export const IS_MAC = /Mac|iPhone|iPad/i.test(
  (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform ?? navigator.userAgent,
);

/** `⌘⌥I` → `Ctrl+Alt+I` off macOS; unchanged on macOS. */
export function shortcutLabel(hint: string): string {
  if (IS_MAC) return hint;
  return hint.replaceAll("⌘", "Ctrl+").replaceAll("⌥", "Alt+").replaceAll("⇧", "Shift+");
}

/** Relabels every `[data-shortcut]` element (static markup) for this host. */
export function localizeShortcuts(root: ParentNode = document): void {
  root.querySelectorAll<HTMLElement>("[data-shortcut]").forEach((element) => {
    element.textContent = shortcutLabel(element.dataset.shortcut ?? element.textContent ?? "");
  });
}

/** The app's keyboard shortcuts, for the About page. */
export const SHORTCUTS: readonly { readonly action: string; readonly keys: string }[] = [
  { action: "Command palette", keys: "⌘K" },
  { action: "Toggle sidebar", keys: "⌘B" },
  { action: "Toggle dock", keys: "⌘J" },
  { action: "Toggle inspector", keys: "⌘⌥I" },
  { action: "Go to surface 1–9 (rail order)", keys: "⌘1–9" },
  { action: "Send the request (Resend editor)", keys: "⌘Enter" },
  { action: "Close a dialog, menu, or palette", keys: "Esc" },
  { action: "Confirm a dialog", keys: "Enter" },
];
