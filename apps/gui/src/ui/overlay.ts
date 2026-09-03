import { icon, type IconName } from "../brand/icons";
import { escapeHtml, hydrateIcons } from "./dom";

/**
 * Branded replacements for `window.confirm` and `window.prompt`.
 *
 * The gates themselves are unchanged — the same decision, with the same
 * consequences, is still required before anything happens. Only the surface is
 * the app's rather than the browser's, so authorization moments read in the
 * product's voice instead of as unstyled OS chrome.
 */

const overlayRoot = (): HTMLElement => {
  const existing = document.querySelector<HTMLElement>("#overlay-root");
  if (existing !== null) return existing;
  const created = document.createElement("div");
  created.id = "overlay-root";
  document.body.append(created);
  return created;
};

interface DialogAction {
  readonly key: string;
  readonly label: string;
  readonly tone?: "default" | "danger" | "primary";
}

interface DialogOptions {
  readonly eyebrow: string;
  readonly title: string;
  /** Pre-escaped markup for the body. Callers build it with `escapeHtml`. */
  readonly bodyHtml: string;
  readonly confirmLabel: string;
  readonly cancelLabel?: string;
  readonly tone?: "default" | "danger";
  readonly wide?: boolean;
  /**
   * When set, replaces the default confirm/cancel footer with these buttons.
   * The dialog resolves to `{ action, value }` where `value` is `readValue`.
   * Escape/backdrop still resolve to `null`.
   */
  readonly actions?: readonly DialogAction[];
}

/** Resolution of a multi-action dialog. */
export interface DialogChoice {
  readonly action: string;
  readonly value: unknown;
}

function present(
  options: DialogOptions,
  onMount?: (modal: HTMLElement) => void,
  readValue?: (modal: HTMLElement) => unknown,
): Promise<unknown> {
  return new Promise((resolve) => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    scrim.innerHTML = `<div class="modal${options.wide === true ? " modal--wide" : ""}" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
<div class="modal__header">
  <div>
    <p class="modal__eyebrow">${escapeHtml(options.eyebrow)}</p>
    <h2 class="modal__title" id="dialog-title">${escapeHtml(options.title)}</h2>
  </div>
  <button class="btn btn--quiet btn--icon" type="button" data-dialog="cancel"><span class="visually-hidden">Close</span>${icon("close", { size: 18 })}</button>
</div>
<div class="modal__body">${options.bodyHtml}</div>
<div class="modal__footer">
${
  options.actions === undefined
    ? `  <button class="btn" type="button" data-dialog="cancel">${escapeHtml(options.cancelLabel ?? "Cancel")}</button>
  <button class="btn ${options.tone === "danger" ? "btn--danger" : "btn--primary"}" type="button" data-dialog="confirm">${escapeHtml(options.confirmLabel)}</button>`
    : options.actions
        .map(
          (action) =>
            `  <button class="btn ${action.tone === "danger" ? "btn--danger" : action.tone === "primary" ? "btn--primary" : ""}" type="button" data-action="${escapeHtml(action.key)}">${escapeHtml(action.label)}</button>`,
        )
        .join("\n")
}
</div>
</div>`;

    const modal = scrim.querySelector<HTMLElement>(".modal");
    if (modal === null) {
      resolve(null);
      return;
    }
    hydrateIcons(modal);
    onMount?.(modal);

    let settled = false;
    const settle = (value: unknown): void => {
      if (settled) return;
      settled = true;
      document.removeEventListener("keydown", onKeyDown, true);
      scrim.remove();
      previouslyFocused?.focus?.();
      resolve(value);
    };

    const confirm = (): void =>
      settle(readValue === undefined ? true : readValue(modal));

    const primaryActionKey = (): string | undefined =>
      options.actions?.find((action) => action.tone === "primary")?.key
      ?? options.actions?.[0]?.key;

    const fireAction = (key: string): void =>
      settle({ action: key, value: readValue?.(modal) } satisfies DialogChoice);

    function onKeyDown(event: KeyboardEvent): void {
      if (event.key === "Escape") {
        event.preventDefault();
        settle(null);
        return;
      }
      if (event.key === "Enter" && !(event.target instanceof HTMLTextAreaElement)) {
        event.preventDefault();
        if (options.actions === undefined) confirm();
        else {
          const key = primaryActionKey();
          if (key !== undefined) fireAction(key);
        }
      }
    }

    modal.querySelectorAll<HTMLButtonElement>("[data-dialog]").forEach((button) => {
      button.addEventListener("click", () => {
        if (button.dataset.dialog === "confirm") confirm();
        else settle(null);
      });
    });
    modal.querySelectorAll<HTMLButtonElement>("[data-action]").forEach((button) => {
      button.addEventListener("click", () => {
        const key = button.dataset.action;
        if (key !== undefined) fireAction(key);
      });
    });
    scrim.addEventListener("mousedown", (event) => {
      if (event.target === scrim) settle(null);
    });
    document.addEventListener("keydown", onKeyDown, true);

    overlayRoot().append(scrim);
    const focusTarget =
      modal.querySelector<HTMLElement>("input, textarea, select") ??
      modal.querySelector<HTMLElement>('[data-dialog="confirm"]');
    focusTarget?.focus();
  });
}

/**
 * A confirm-before-run gate. `lines` are shown as a fact list so the operator
 * sees exactly what is about to happen before agreeing to it.
 */
export async function confirmDialog(options: {
  readonly eyebrow: string;
  readonly title: string;
  readonly message: string;
  readonly facts?: readonly { readonly label: string; readonly value: string }[];
  readonly noticeTone?: "accent" | "caution" | "danger";
  readonly noticeIcon?: IconName;
  readonly notice?: string;
  readonly confirmLabel: string;
  readonly tone?: "default" | "danger";
}): Promise<boolean> {
  const facts =
    options.facts === undefined || options.facts.length === 0
      ? ""
      : `<dl class="kv">${options.facts
          .map(
            (fact) =>
              `<dt>${escapeHtml(fact.label)}</dt><dd>${escapeHtml(fact.value)}</dd>`,
          )
          .join("")}</dl>`;
  const notice =
    options.notice === undefined
      ? ""
      : `<div class="notice notice--${options.noticeTone ?? "caution"}"><span class="notice__icon">${icon(options.noticeIcon ?? "shield", { size: 18 })}</span><div class="notice__body"><p>${escapeHtml(options.notice)}</p></div></div>`;
  const result = await present({
    eyebrow: options.eyebrow,
    title: options.title,
    bodyHtml: `<p>${escapeHtml(options.message)}</p>${facts}${notice}`,
    confirmLabel: options.confirmLabel,
    tone: options.tone,
  });
  return result === true;
}

/** A single-value prompt. Resolves to `null` when dismissed. */
export async function promptDialog(options: {
  readonly eyebrow: string;
  readonly title: string;
  readonly message: string;
  readonly label: string;
  readonly value: string;
  readonly confirmLabel: string;
  readonly placeholder?: string;
}): Promise<string | null> {
  const result = await present(
    {
      eyebrow: options.eyebrow,
      title: options.title,
      bodyHtml: `<p>${escapeHtml(options.message)}</p><div class="field"><label class="field__label" for="dialog-input">${escapeHtml(options.label)}</label><input class="input input--mono" id="dialog-input" type="text" spellcheck="false" value="${escapeHtml(options.value)}" placeholder="${escapeHtml(options.placeholder ?? "")}" /></div>`,
      confirmLabel: options.confirmLabel,
    },
    (modal) => {
      const input = modal.querySelector<HTMLInputElement>("#dialog-input");
      input?.select();
    },
    (modal) => modal.querySelector<HTMLInputElement>("#dialog-input")?.value ?? "",
  );
  if (typeof result !== "string") return null;
  const trimmed = result.trim();
  return trimmed === "" ? null : trimmed;
}

/** A multi-choice gate. Resolves to the chosen action key, or `null`. */
export async function choiceDialog(options: {
  readonly eyebrow: string;
  readonly title: string;
  readonly message: string;
  readonly notice?: string;
  readonly noticeTone?: "accent" | "caution" | "danger";
  readonly choices: readonly { readonly key: string; readonly label: string; readonly tone?: "default" | "danger" | "primary" }[];
}): Promise<string | null> {
  const notice =
    options.notice === undefined
      ? ""
      : `<div class="notice notice--${options.noticeTone ?? "accent"}"><span class="notice__icon">${icon("shield", { size: 18 })}</span><div class="notice__body"><p>${escapeHtml(options.notice)}</p></div></div>`;
  const result = await present({
    eyebrow: options.eyebrow,
    title: options.title,
    bodyHtml: `<p>${escapeHtml(options.message)}</p>${notice}`,
    confirmLabel: "",
    actions: options.choices,
  });
  if (result !== null && typeof result === "object" && "action" in result) {
    return (result as DialogChoice).action;
  }
  return null;
}

/** One field to collect in a credential dialog. */
export interface CredentialDialogField {
  readonly name: string;
  readonly label: string;
  readonly kind: string;
  readonly secret: boolean;
}

/**
 * Collects login credentials from the operator. Sensitive fields use masked
 * inputs. Always states the security contract plainly, and offers a
 * "Continue without" escape. Resolves `null` if dismissed.
 *
 * Values are returned to the caller in memory only; the caller forwards them
 * over the loopback control channel and never persists or logs them.
 */
export async function credentialDialog(options: {
  readonly eyebrow: string;
  readonly title: string;
  readonly message: string;
  readonly fields: readonly CredentialDialogField[];
  readonly confirmLabel: string;
  readonly allowSkip: boolean;
}): Promise<{ readonly skip: boolean; readonly values: readonly [string, string][] } | null> {
  const inputs = options.fields
    .map((field, index) => {
      const id = `cred-field-${index}`;
      const type = field.secret ? "password" : "text";
      const autocomplete = field.secret ? "off" : "off";
      return `<div class="field"><label class="field__label" for="${id}">${escapeHtml(field.label)}${field.secret ? " (hidden)" : ""}</label><input class="input input--mono" id="${id}" data-cred-name="${escapeHtml(field.name)}" type="${type}" spellcheck="false" autocomplete="${autocomplete}" /></div>`;
    })
    .join("");
  const assurance = `<div class="notice notice--accent"><span class="notice__icon">${icon("shield", { size: 18 })}</span><div class="notice__body"><p>Credentials are used only to sign into the app during this run, held in memory, never saved, and redacted from captured traffic.</p></div></div>`;
  const actions: DialogAction[] = [{ key: "provide", label: options.confirmLabel, tone: "primary" }];
  if (options.allowSkip) actions.push({ key: "skip", label: "Continue without" });

  const result = await present(
    {
      eyebrow: options.eyebrow,
      title: options.title,
      bodyHtml: `<p>${escapeHtml(options.message)}</p>${inputs}${assurance}`,
      confirmLabel: options.confirmLabel,
      actions,
    },
    (modal) => modal.querySelector<HTMLInputElement>("input")?.focus(),
    (modal) =>
      Array.from(modal.querySelectorAll<HTMLInputElement>("input[data-cred-name]")).map(
        (input) => [input.dataset.credName ?? "", input.value] as [string, string],
      ),
  );
  if (result === null || typeof result !== "object" || !("action" in result)) return null;
  const choice = result as DialogChoice;
  if (choice.action === "skip") return { skip: true, values: [] };
  const values = (choice.value as [string, string][]).filter(([, value]) => value !== "");
  return { skip: false, values };
}
