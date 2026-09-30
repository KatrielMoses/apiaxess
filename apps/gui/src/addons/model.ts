// What the Add-ons panel (and the inline "not installed" states) say and
// offer, from the engine's /api/v1/addons. Pure, so every state is checked by
// scripts/check-addons-model.mjs.

export type AddonJob =
  | { readonly phase: "idle" }
  | { readonly phase: "downloading"; readonly received: number; readonly total: number }
  | { readonly phase: "extracting"; readonly read: number; readonly total: number }
  | { readonly phase: "installing" }
  | { readonly phase: "installed"; readonly version: string }
  | { readonly phase: "failed"; readonly message: string; readonly resumable: boolean };

export interface AddonView {
  readonly slug: string;
  readonly name: string;
  readonly purpose: string;
  readonly installed: boolean;
  readonly installedVersion: string | null;
  readonly outdated: boolean;
  readonly path: string;
  readonly installDir: string;
  readonly overriddenBy: string | null;
  readonly available: { readonly version: string; readonly size: number; readonly installedSize: number; readonly url: string; readonly sha256: string } | null;
  readonly job: AddonJob;
}

export interface AddonsStatus {
  readonly platform: string | null;
  readonly catalogUrl: string;
  readonly catalogFetched: string | null;
  readonly catalogError: string | null;
  readonly signatureRequired: boolean;
  readonly addons: readonly AddonView[];
}

export interface AddonAction {
  readonly kind: "download" | "cancel";
  readonly label: string;
  readonly primary?: boolean;
}

export interface AddonCard {
  readonly tone: "success" | "accent" | "caution" | "danger" | "neutral";
  readonly badge: string;
  /** Plain lines under the title. */
  readonly lines: readonly string[];
  /** 0–100 while a job runs, else null. */
  readonly progress: number | null;
  readonly actions: readonly AddonAction[];
}

/** `2.1 GB`-style sizes. */
export function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${Math.round(bytes / (1024 * 1024))} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function percent(done: number, total: number): number {
  return total > 0 ? Math.min(100, Math.floor((done / total) * 100)) : 0;
}

/** Whether any add-on job is running (the panel polls while so). */
export function anyActive(status: AddonsStatus): boolean {
  return status.addons.some((addon) => ["downloading", "extracting", "installing"].includes(addon.job.phase));
}

/** The Download button's label for an add-on that can be downloaded. */
function downloadLabel(view: AddonView, verb: string): string {
  return view.available === null ? verb : `${verb} (${formatSize(view.available.size)})`;
}

/** One add-on's card. */
export function addonCard(view: AddonView, platform: string | null): AddonCard {
  const job = view.job;
  if (job.phase === "downloading") {
    const total = job.total > 0 ? job.total : view.available?.size ?? 0;
    return { tone: "accent", badge: "downloading", progress: percent(job.received, total),
      lines: [`${percent(job.received, total)}% · ${formatSize(job.received)} of ${formatSize(total)} from apiaxess.dev, checked against its published SHA-256 as it arrives.`],
      actions: [{ kind: "cancel", label: "Cancel" }] };
  }
  if (job.phase === "extracting") {
    return { tone: "accent", badge: "unpacking", progress: percent(job.read, job.total),
      lines: ["Verified. Unpacking beside its destination; nothing changes until it is complete."],
      actions: [{ kind: "cancel", label: "Cancel" }] };
  }
  if (job.phase === "installing") {
    return { tone: "accent", badge: "installing", progress: 100, lines: ["Moving it into place…"], actions: [] };
  }
  if (view.overriddenBy !== null) {
    return view.installed
      ? { tone: "neutral", badge: `managed by ${view.overriddenBy}`, progress: null,
          lines: [`Using ${view.path}${view.installedVersion === null ? "" : ` (${view.installedVersion})`}. APIaxess never downloads over an ${view.overriddenBy} override.`], actions: [] }
      : { tone: "caution", badge: "override not found", progress: null,
          lines: [`${view.overriddenBy} points at ${view.path}, which has no usable ${view.name}. Fix the path, or unset ${view.overriddenBy} to download it here.`], actions: [] };
  }
  const failure = job.phase === "failed" ? [job.message] : [];
  const retryVerb = job.phase === "failed" && job.resumable ? "Resume download" : "Download";
  if (platform === null) {
    return { tone: "neutral", badge: "not available", progress: null, lines: ["Add-ons are not published for this platform yet."], actions: [] };
  }
  if (view.installed && !view.outdated) {
    const newer = view.available !== null && view.installedVersion !== null && view.available.version !== view.installedVersion;
    return { tone: "success", badge: `installed${view.installedVersion === null ? "" : ` · ${view.installedVersion}`}`, progress: null,
      lines: [`At ${view.path}.`, ...failure],
      actions: newer ? [{ kind: "download", label: downloadLabel(view, `Update to ${view.available!.version}`) }] : [] };
  }
  if (view.installed && view.outdated) {
    return { tone: "caution", badge: "out of date", progress: null,
      lines: [`Version ${view.installedVersion ?? "?"} at ${view.path} is too old for this APIaxess.`, ...failure],
      actions: [{ kind: "download", label: downloadLabel(view, job.phase === "failed" && job.resumable ? retryVerb : "Download the current version"), primary: true }] };
  }
  return { tone: failure.length > 0 ? "danger" : "neutral", badge: failure.length > 0 ? "not installed" : "not installed", progress: null,
    lines: [view.purpose, ...failure],
    actions: [{ kind: "download", label: downloadLabel(view, retryVerb), primary: true }] };
}

/** The confirmation shown before a multi-GB download starts. */
export function downloadConfirmation(view: AddonView): { readonly title: string; readonly message: string; readonly facts: readonly { readonly label: string; readonly value: string }[] } {
  const offer = view.available;
  const facts = offer === null ? [] : [
    { label: "Version", value: offer.version },
    { label: "Download", value: formatSize(offer.size) },
    ...(offer.installedSize > 0 ? [{ label: "Installed size", value: formatSize(offer.installedSize) }] : []),
    { label: "Installs to", value: view.installDir },
    { label: "SHA-256", value: offer.sha256 },
  ];
  return {
    title: `Download ${view.name}?`,
    message: "It downloads only from apiaxess.dev, is checked against its published SHA-256 before anything is installed, and sends nothing about you or your sessions. You can cancel and resume.",
    facts,
  };
}
