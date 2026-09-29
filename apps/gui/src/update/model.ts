// What the update banner and the Settings "Updates" panel say and offer, from
// the engine's /api/v1/update/status. Pure, so every state is checked by
// scripts/check-update-model.mjs. Copy is provisional until growth finalizes it.

export type InstallChannel = "msi" | "portable" | "scoop" | "chocolatey" | "deb" | "source";

export type DownloadState =
  | { readonly state: "idle" }
  | { readonly state: "downloading"; readonly received: number; readonly total: number }
  | { readonly state: "ready"; readonly path: string }
  | { readonly state: "failed"; readonly message: string };

export interface UpdateStatus {
  readonly enabled: boolean;
  readonly currentVersion: string;
  readonly channel: InstallChannel;
  readonly checking: boolean;
  readonly lastChecked: string | null;
  readonly lastError: string | null;
  readonly signature: "not_required" | "required";
  readonly available: {
    readonly version: string;
    readonly released: string | null;
    readonly summary: string | null;
    readonly notesUrl: string | null;
    readonly supported: boolean;
    readonly asset: { readonly name: string; readonly url: string; readonly sha256: string; readonly size: number } | null;
  } | null;
  readonly download: DownloadState;
  readonly command: string | null;
  readonly scheduled: boolean;
  readonly lastInstall: { readonly version: string; readonly succeeded: boolean; readonly message: string } | null;
  readonly busy: readonly string[];
}

export type UpdateActionKind =
  | "download"
  | "install-now"
  | "install-deferred"
  | "cancel-deferred"
  | "copy-command"
  | "open-url";

export interface UpdateAction {
  readonly kind: UpdateActionKind;
  readonly label: string;
  readonly primary?: boolean;
  readonly disabled?: boolean;
  /** Why the action is disabled, for its tooltip. */
  readonly reason?: string;
  /** The command to copy or the URL to open. */
  readonly value?: string;
}

export interface UpdateNotice {
  readonly tone: "accent" | "success" | "caution" | "danger";
  readonly title: string;
  readonly body: string;
  /** A command to show verbatim (package-manager channels). */
  readonly command: string | null;
  readonly actions: readonly UpdateAction[];
  /** Whether the banner offers "Later" (dismiss until the next version). */
  readonly dismissible: boolean;
}

export interface UpdateView {
  /** The workbench banner, or null when there is nothing to say. */
  readonly banner: UpdateNotice | null;
  /** The Settings panel's status notice (always present). */
  readonly panel: UpdateNotice;
  /** "Last checked …" for the Settings panel. */
  readonly lastChecked: string;
  /** Whether "Check now" is available. */
  readonly canCheck: boolean;
}

/** `1.2 MB`-style sizes. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

/** "Last checked just now / 12 min ago / 3 h ago / on 2026-10-07". */
export function lastCheckedText(status: UpdateStatus, now: Date): string {
  if (!status.enabled) return "Update checks are off.";
  if (status.checking) return "Checking now…";
  if (status.lastChecked === null) return "Not checked yet.";
  const at = new Date(status.lastChecked);
  const minutes = Math.floor((now.getTime() - at.getTime()) / 60_000);
  const when = minutes < 1 ? "just now"
    : minutes < 60 ? `${minutes} min ago`
    : minutes < 24 * 60 ? `${Math.floor(minutes / 60)} h ago`
    : `on ${at.toISOString().slice(0, 10)}`;
  return `Last checked ${when}.`;
}

/** An engine message as a sentence: capitalized, ending in a full stop. */
function sentence(text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return trimmed;
  const capital = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(capital) ? capital : `${capital}.`;
}

function notesAction(status: UpdateStatus): UpdateAction[] {
  const url = status.available?.notesUrl ?? null;
  return url === null ? [] : [{ kind: "open-url", label: "Release notes", value: url }];
}

function describeAvailable(status: UpdateStatus): UpdateNotice {
  const available = status.available!;
  const version = available.version;
  const summary = available.summary !== null && available.summary !== "" ? ` ${available.summary}` : "";
  const notes = notesAction(status);
  const base = { command: null, dismissible: true };
  if (!available.supported) {
    return { ...base, tone: "caution", title: `APIaxess ${version} is available`,
      body: `APIaxess ${status.currentVersion} is too old to update in place. Install ${version} from apiaxess.dev.${summary}`, actions: notes };
  }
  switch (status.channel) {
    case "scoop":
    case "chocolatey":
      return { ...base, tone: "accent", title: `APIaxess ${version} is available`,
        body: `Update it with your package manager.${summary}`, command: status.command,
        actions: [...(status.command === null ? [] : [{ kind: "copy-command" as const, label: "Copy command", primary: true, value: status.command }]), ...notes] };
    case "portable": {
      const asset = available.asset;
      return { ...base, tone: "accent", title: `APIaxess ${version} is available`,
        body: `Download the new portable zip and replace this folder with it.${asset === null ? "" : ` SHA-256 ${asset.sha256}.`}${summary}`,
        actions: [...(asset === null ? [] : [{ kind: "open-url" as const, label: "Download zip", primary: true, value: asset.url }]), ...notes] };
    }
    case "source":
      return { ...base, tone: "accent", title: `APIaxess ${version} is available`,
        body: `This is a development build; update it from source.${summary}`, actions: notes };
    case "msi":
    case "deb":
      return describeDownload(status, version, summary, notes);
  }
}

function describeDownload(status: UpdateStatus, version: string, summary: string, notes: UpdateAction[]): UpdateNotice {
  const download = status.download;
  const size = status.available?.asset?.size ?? 0;
  const sizeText = size > 0 ? ` (${formatBytes(size)})` : "";
  if (download.state === "downloading") {
    const total = download.total > 0 ? download.total : size;
    const progress = total > 0
      ? ` ${Math.floor((download.received / total) * 100)}% · ${formatBytes(download.received)} of ${formatBytes(total)}`
      : ` ${formatBytes(download.received)}`;
    return { tone: "accent", title: `Downloading APIaxess ${version}…`, body: `Verifying it against its published SHA-256 as it arrives.${progress}`,
      command: null, actions: [], dismissible: false };
  }
  if (download.state === "ready" && status.channel === "deb") {
    return { tone: "success", title: `APIaxess ${version} is downloaded and verified`,
      body: "Install it with apt (APIaxess never asks for administrator rights itself):", command: status.command,
      actions: [...(status.command === null ? [] : [{ kind: "copy-command" as const, label: "Copy command", primary: true, value: status.command }]), ...notes],
      dismissible: true };
  }
  if (download.state === "ready") {
    const busy = status.busy.length > 0;
    const busyText = busy ? ` Right now ${status.busy.join(", ")}.` : "";
    const restart: UpdateAction = { kind: "install-now", label: "Restart and update", primary: !status.scheduled || !busy,
      disabled: busy, reason: busy ? "Finish or stop what is running first." : undefined };
    if (status.scheduled) {
      return { tone: "success", title: "Update ready — installs when this session ends",
        body: `APIaxess ${version} is verified and installs when you close APIaxess (or on its next launch). Your session is saved first.${busyText}`,
        command: null, actions: [restart, { kind: "cancel-deferred", label: "Don't install on exit" }], dismissible: true };
    }
    return { tone: "success",
      title: busy ? "Update ready — installs when this session ends" : `APIaxess ${version} is ready to install`,
      body: busy
        ? `APIaxess ${version} is verified. It will not install in the middle of an engagement.${busyText}`
        : `APIaxess ${version} is verified. Restarting saves your session, installs the update, and reopens it.`,
      command: null,
      actions: busy
        ? [{ kind: "install-deferred", label: "Install on next launch", primary: true }, restart]
        : [restart, { kind: "install-deferred", label: "Install on next launch" }],
      dismissible: true };
  }
  const failed = download.state === "failed" ? download.message : null;
  return { tone: failed === null ? "accent" : "danger",
    title: failed === null ? `APIaxess ${version} is available` : `The update to ${version} was not downloaded`,
    body: failed === null ? `${summary.trim() === "" ? "A newer version is ready to download." : summary.trim()}` : sentence(failed),
    command: null,
    actions: [{ kind: "download", label: failed === null ? `Update${sizeText}` : "Try again", primary: true }, ...notes],
    dismissible: true };
}

/** The banner and Settings panel for `status`. `dismissed` is the version the
 *  operator chose "Later" for; the banner stays away until a newer one. */
export function updateView(status: UpdateStatus, now: Date, dismissed: string | null): UpdateView {
  const lastChecked = lastCheckedText(status, now);
  const canCheck = status.enabled && !status.checking;
  if (!status.enabled) {
    return { banner: null, lastChecked, canCheck,
      panel: { tone: "caution", title: "Update checks are off",
        body: `APIaxess ${status.currentVersion} makes no update requests. Turn on "Check for updates" above to hear about new versions.`,
        command: null, actions: [], dismissible: false } };
  }
  if (status.available === null) {
    const panel: UpdateNotice = status.lastError !== null && !status.checking
      ? { tone: "caution", title: "Could not check for updates", body: `${sentence(status.lastError)} APIaxess tries again in a day, or check now.`, command: null, actions: [], dismissible: false }
      : { tone: "success", title: status.lastChecked === null ? `APIaxess ${status.currentVersion}` : `APIaxess ${status.currentVersion} is up to date`,
          body: status.lastChecked === null ? "The first check runs shortly after startup." : "You have the latest version.", command: null, actions: [], dismissible: false };
    return { banner: null, panel, lastChecked, canCheck };
  }
  const notice = describeAvailable(status);
  const active = status.download.state === "downloading" || status.scheduled;
  const banner = active || dismissed !== status.available.version ? notice : null;
  return { banner, panel: { ...notice, dismissible: false }, lastChecked, canCheck };
}
