import "./styles/index.css";

import { toDataURL as qrToDataUrl } from "qrcode";

import { icon } from "./brand/icons";
import { lockupHtml, stackedLockupHtml } from "./brand/logo";
import {
  type Diagnostic,
  DiagnosticsLog,
  diagnosticListHtml,
  initDiagnosticsDrawer,
} from "./ui/diagnostics";
import {
  escapeHtml,
  formatBytes,
  formatTime,
  hydrateIcons,
  stateBlock,
} from "./ui/dom";
import { initNavigation, onViewChange, showView, trackNavOverflow } from "./ui/nav";
import { initShell } from "./ui/shell";
import { initTheme } from "./ui/theme";
import { type CredentialDialogField, choiceDialog, confirmDialog, credentialDialog, promptDialog } from "./ui/overlay";
import { toast } from "./ui/toast";

/* ==================================================================== *
 * Engine contracts. These mirror the local API's response shapes and are
 * unchanged by the identity work.
 * ==================================================================== */

interface SystemStatus { readonly apiVersion: string; readonly service: string; readonly state: "ready"; }
interface WorkbenchSession { readonly authToken: string; readonly interceptEnabled: boolean; }
interface WorkbenchHealth { readonly proxyRunning: boolean; readonly backend?: { readonly hudsuckerAvailable: boolean }; }
interface FlowSummary { readonly id: number; readonly method?: string | null; readonly host?: string | null; readonly url?: string | null; readonly path?: string | null; readonly status?: number | null; readonly durationMs?: number | null; readonly contentType?: string | null; readonly size?: number | null; }
interface FlowDetail { readonly summary: FlowSummary; readonly requestHeaders: readonly [string, string][]; readonly responseHeaders: readonly [string, string][]; readonly requestBody?: number[] | null; readonly responseBody?: number[] | null; }
interface ResendRequest { method: string; url: string; headers: [string, string][]; body?: number[] | null; }
interface ResendResponse { status: number; headers: readonly [string, string][]; body?: number[]; durationMs: number; }
interface ResendRevision { revision: number; sentAt: string; request: ResendRequest; response?: ResendResponse | null; diagnostic?: Diagnostic | null; scope: string; }
interface ResendContext { id: string; sourceFlowId?: number; createdAt: string; current: ResendRequest; history: ResendRevision[]; }
interface ResendSendResult { context: ResendContext; revision: ResendRevision; diagnostics: (Diagnostic | null)[]; }
interface FuzzerResult { ordinal: number; payloads: string[]; response?: { status: number; body?: number[] | null; durationMs: number } | null; matched: boolean; filtered: boolean; diff: { statusChanged: boolean; sizeChanged: boolean; sizeDelta: number; contentChanged: boolean }; diagnostic?: Diagnostic | null; }
type FuzzerLocation = "url" | "header" | "body";
interface FuzzerPosition { location: FuzzerLocation; headerName?: string | null; start: number; end: number; setIndex: number; }
interface FuzzerPayloadSet { name: string; values: string[]; }
interface FuzzerMatchFilter { statuses: number[]; minSize?: number | null; maxSize?: number | null; contains?: string | null; regex?: string | null; }
interface FuzzerConfig { baseRequest: ResendRequest; positions: FuzzerPosition[]; payloadSets: FuzzerPayloadSet[]; attackType: string; matchFilter: FuzzerMatchFilter; concurrency: number; ratePerSecond: number; maxResults: number; authPreflight?: ResendRequest | null; sequence?: unknown[]; }
interface FuzzerJob { id: string; tier: "ffuf" | "native"; state: string; config: FuzzerConfig; results: FuzzerResult[]; diagnostics: (Diagnostic | null)[]; }
interface CredentialPromptMsg { readonly id: number; readonly package: string; readonly screenSummary: string; readonly reason: string; readonly fields: readonly CredentialDialogField[]; }
interface LiveUpdate { readonly flows: readonly FlowSummary[]; readonly diagnostics: readonly Diagnostic[]; readonly prompts?: readonly CredentialPromptMsg[]; }
interface PipelineRun { readonly runId: string; readonly artifactPath: string; readonly stage: string; readonly status: "running" | "completed" | "failed"; readonly progressBasisPoints: number; readonly message: string; readonly diagnostics: (Diagnostic | null)[]; readonly dynamicRan: boolean; readonly updatedAt: string; readonly surfaceAvailable: boolean; }
/** Request/response essentials extracted from a fused endpoint for the expandable
 * detail and the send-to-resend/fuzzer actions. The surface is a normalized
 * model (header names and observed statuses, not raw bodies), so this is the
 * endpoint's shape, not a captured exchange. */
interface EndpointDetail {
  readonly baseUrl: string | null;
  readonly requestHeaders: readonly string[];
  readonly queryParams: readonly string[];
  readonly pathParams: readonly string[];
  readonly responses: readonly { readonly status: string; readonly headers: readonly string[] }[];
}
interface SurfaceEndpoint { readonly method: string; readonly pathTemplate: string; readonly baseUrl?: string | null; readonly evidenceSource?: string | null; readonly minimumFactConfidence?: number | null; readonly signerCount: number; readonly detail?: EndpointDetail }
interface SurfaceSummary { readonly schemaVersion: number; readonly assemblyRunId: string; readonly endpoints: readonly SurfaceEndpoint[]; readonly coverage: { readonly endpointCount: number; readonly confirmedEndpointCount: number; readonly inferredEndpointCount: number; readonly staticOnlyEndpointCount: number; readonly openHandoffCount: number; readonly resolvedHandoffCount: number }; readonly signerCount: number; readonly diagnostics: (Diagnostic | null)[]; }
interface DiscoveryEstimate { target: string; requestCount: number; ratePerSecond: number; estimatedLabel: string; }
interface BrowserLaunchStatus { running: boolean; browser?: string | null; target?: string | null; pid?: number | null; cdpConnected?: boolean; debugPort?: number | null; }
interface TargetIdentifier { readonly kind: string; readonly value: string; }
interface SessionStatus { readonly sessionId: string; readonly lifecycle: string; readonly artifactPath: string; readonly storePath: string; readonly flowCount: number; readonly resendCount: number; readonly fuzzerCount: number; readonly scopeConfigured: boolean; readonly recoveredFromCheckpoint: boolean; readonly lastCheckpointAt?: string | null; readonly scope?: { readonly declared_at?: string; readonly target?: { readonly target_type?: string; readonly primary?: TargetIdentifier } }; readonly analysisPipeline?: { readonly run_id?: string; readonly artifact_path?: string } | null; }
interface AuditActionDescriptor { readonly kind: string; readonly summary: string; }
interface AuditRecord { readonly id: string; readonly occurred_at: string; readonly action: AuditActionDescriptor; readonly outcome: string; readonly diagnostics: (Diagnostic | null)[]; }

/* Device pairing (Phase C5). These mirror the local API's pairing shapes. */
interface PairingDevice { readonly serial: string; readonly state: string; readonly description: string; }
interface PairingQrPayload { readonly host: string; readonly controlPort: number; readonly proxyPort: number; readonly pairingToken: string; readonly caFingerprintSha256: string; readonly expiresAtMs: number; }
interface PendingPairing { readonly id: string; readonly deviceName: string; readonly serial?: string | null; readonly requestedAgoMs: number; }

/* Android target panel (Phase D3). Mirrors engine-shell's AndroidTargetStatus. */
type AndroidPhase = "idle" | "booting" | "provisioning" | "streaming" | "ready" | "error";
interface AndroidTargetStatus {
  readonly phase: AndroidPhase;
  readonly message: string;
  readonly addonPresent: boolean;
  readonly serial: string | null;
  readonly wsScrcpyPort: number | null;
  readonly streaming: boolean;
  readonly clientApkInstalled: boolean;
  readonly fridaServerStarted: boolean;
  readonly androidSdk: number | null;
  readonly diagnostics: readonly Diagnostic[];
}

class ApiRequestError extends Error {}

/* ==================================================================== *
 * Element references
 * ==================================================================== */

const flowList = document.querySelector<HTMLElement>("#flow-list");
const queueList = document.querySelector<HTMLElement>("#queue-list");
const detail = document.querySelector<HTMLElement>("#flow-detail");
const detailActions = document.querySelector<HTMLElement>("#detail-actions");
const statusText = document.querySelector<HTMLElement>("#status-text");
const statusDot = document.querySelector<HTMLElement>("#status-dot");
const interceptToggle = document.querySelector<HTMLInputElement>("#intercept-toggle");
const hostFilter = document.querySelector<HTMLInputElement>("#host-filter");
const editor = document.querySelector<HTMLElement>("#editor");
const methodInput = document.querySelector<HTMLInputElement>("#edit-method");
const headersInput = document.querySelector<HTMLTextAreaElement>("#edit-headers");
const bodyInput = document.querySelector<HTMLTextAreaElement>("#edit-body");
const selectedLabel = document.querySelector<HTMLElement>("#selected-label");
const resendPanel = document.querySelector<HTMLElement>("#resend-panel");
const fuzzerPanel = document.querySelector<HTMLElement>("#fuzzer-panel");
const pipelineStatus = document.querySelector<HTMLElement>("#pipeline-status");
const pipelineProgress = document.querySelector<HTMLElement>("#pipeline-progress");
const pipelineDiagnostics = document.querySelector<HTMLElement>("#pipeline-diagnostics");
const pipelineDiagnosticsCount = document.querySelector<HTMLElement>("#pipeline-diagnostics-count");
const surfaceView = document.querySelector<HTMLElement>("#surface-view");
const webTarget = document.querySelector<HTMLInputElement>("#web-target");
const webAuthorize = document.querySelector<HTMLInputElement>("#web-authorize");
const webSessionStatus = document.querySelector<HTMLElement>("#web-session-status");
const webSessionBadge = document.querySelector<HTMLElement>("#web-session-badge");
const webAuthorization = document.querySelector<HTMLElement>("#web-authorization");
const webAuthorizedNote = document.querySelector<HTMLElement>("#web-authorized-note");
const browserState = document.querySelector<HTMLElement>("#browser-state");
const discoveryKind = document.querySelector<HTMLSelectElement>("#discovery-kind");
const discoveryWordlist = document.querySelector<HTMLSelectElement>("#discovery-wordlist");
const discoveryStatus = document.querySelector<HTMLElement>("#discovery-status");
const discoveryBadge = document.querySelector<HTMLElement>("#discovery-badge");
const discoveryEstimateView = document.querySelector<HTMLElement>("#discovery-estimate-view");
const discoveryProgress = document.querySelector<HTMLElement>("#discovery-progress");
const discoveryResults = document.querySelector<HTMLElement>("#discovery-results");
const discoveryResultsCount = document.querySelector<HTMLElement>("#discovery-results-count");
const workbenchCounts = document.querySelector<HTMLElement>("#workbench-counts");
const headerSession = document.querySelector<HTMLElement>("#header-session");
const sessionDetail = document.querySelector<HTMLElement>("#session-detail");
const sessionBadge = document.querySelector<HTMLElement>("#session-badge");
const sessionAudit = document.querySelector<HTMLElement>("#session-audit");
const auditCount = document.querySelector<HTMLElement>("#audit-count");
const exportResult = document.querySelector<HTMLElement>("#export-result");
const exportBadge = document.querySelector<HTMLElement>("#export-badge");
const exportDir = document.querySelector<HTMLInputElement>("#export-dir");
const apkPath = document.querySelector<HTMLInputElement>("#apk-path");
const apkFile = document.querySelector<HTMLInputElement>("#apk-file");
const apkRunId = document.querySelector<HTMLInputElement>("#apk-run-id");
const apkIntakeRoot = document.querySelector<HTMLInputElement>("#apk-intake-root");
const apkDynamic = document.querySelector<HTMLInputElement>("#apk-dynamic");
const apkStaticOnly = document.querySelector<HTMLInputElement>("#apk-static-only");
const captureHealth = document.querySelector<HTMLElement>("#capture-health");
const harImport = document.querySelector<HTMLButtonElement>("#har-import");
const harExport = document.querySelector<HTMLButtonElement>("#har-export");
const harFile = document.querySelector<HTMLInputElement>("#har-file");
const devicesList = document.querySelector<HTMLElement>("#devices-list");
const devicesCount = document.querySelector<HTMLElement>("#devices-count");
const pairingArmResult = document.querySelector<HTMLElement>("#pairing-arm-result");
const pairingArmBadge = document.querySelector<HTMLElement>("#pairing-arm-badge");
const pairingPending = document.querySelector<HTMLElement>("#pairing-pending");
const pairingPendingCount = document.querySelector<HTMLElement>("#pairing-pending-count");
const pairingCa = document.querySelector<HTMLElement>("#pairing-ca");
const androidLaunch = document.querySelector<HTMLButtonElement>("#android-launch");
const androidStop = document.querySelector<HTMLButtonElement>("#android-stop");
const androidPhaseBadge = document.querySelector<HTMLElement>("#android-phase-badge");
const androidStatus = document.querySelector<HTMLElement>("#android-status");
const androidInstallPanel = document.querySelector<HTMLElement>("#android-install-panel");
const androidApkPath = document.querySelector<HTMLInputElement>("#android-apk-path");
const androidApkBrowse = document.querySelector<HTMLButtonElement>("#android-apk-browse");
const androidApkFile = document.querySelector<HTMLInputElement>("#android-apk-file");
const androidApkInstall = document.querySelector<HTMLButtonElement>("#android-apk-install");
const androidScreen = document.querySelector<HTMLElement>("#android-screen");

/* ==================================================================== *
 * State
 * ==================================================================== */

const flows = new Map<number, FlowSummary>();
const pending = new Set<number>();
const diagnostics = new DiagnosticsLog();
let selectedFlow: FlowDetail | null = null;
let control: WebSocket | null = null;
let telemetry: WebSocket | null = null;
let reconnectTimer: number | undefined;
let reconnectDelay = 1000;
let selectedResend: ResendContext | null = null;
let selectedFuzzer: FuzzerJob | null = null;
let discoveryJob: FuzzerJob | null = null;
/** Resend queue (Repeater): every request sent here, newest first. */
const resendContexts = new Map<string, ResendContext>();
/** Fuzz queue (Intruder): manually-created attacks only (discovery excluded). */
const fuzzerJobsList = new Map<string, FuzzerJob>();
let activeWorkbenchTab: "live" | "resend" | "fuzz" = "live";
/** Endpoints of the currently rendered surface, so row expand and the
 * send-to-resend/fuzzer actions can resolve a clicked row by index. */
let lastSurfaceEndpoints: readonly SurfaceEndpoint[] = [];
let lastDiscoveryEstimate: DiscoveryEstimate | null = null;
let fuzzerPoll: number | undefined;
let pipelinePoll: number | undefined;
let discoveryPoll: number | undefined;
let browserPoll: number | undefined;
let flowsLoaded = false;
let latestHealth: WorkbenchHealth | null = null;
let latestBrowser: BrowserLaunchStatus | null = null;
let lastSessionStatus: SessionStatus | null = null;
/** GUI-observed hold start per intercepted flow, for the auto-forward countdown. */
const heldSince = new Map<number, number>();
let queueTicker: number | undefined;
/** Auto-forward timeout the intercept toggle installs on the backend. */
const INTERCEPT_TIMEOUT_MS = 30_000;
/** Operator bearer token, shared with the control channel; gates pairing calls. */
let operatorToken = "";
/** The most recently armed pairing payload, kept so its QR survives re-renders. */
let armedPairing: PairingQrPayload | null = null;
/** Verbatim JSON bytes of the armed payload; the QR must encode these unchanged. */
let armedPairingRaw: string | null = null;
/** Poll handle for the pending-pairing list; live only while the Devices view is shown. */
let pairingPoll: number | undefined;
/** Poll handle for the Android target status; live only while that view is shown. */
let androidPoll: number | undefined;
/** Whether the embedded ws-scrcpy screen is currently mounted, so a status poll
 * never reloads (and resets) a live stream by re-rendering the iframe. */
let androidScreenMounted = false;

/* ==================================================================== *
 * Status and diagnostics
 * ==================================================================== */

function setStatus(text: string, state: "ready" | "unavailable" | "working" = "working"): void {
  if (statusText !== null) statusText.textContent = text;
  if (statusDot !== null) statusDot.className = `dot dot--${state}`;
  // Narrow headers collapse the pill to its dot. The label stays in the
  // accessibility tree and the live region; the tooltip is what a sighted
  // operator gets in its place.
  statusText?.closest(".engine-status")?.setAttribute("title", text);
  document.body.dataset.engine = state;
}

/**
 * Records a diagnostic. Absent diagnostics arrive as `null` rather than as an
 * omitted key, so every entry point tolerates that instead of each caller
 * having to guard.
 */
function showDiagnostic(diagnostic: Diagnostic | null | undefined): void {
  if (diagnostic === null || diagnostic === undefined) return;
  diagnostics.push(diagnostic);
}

async function requireOk(response: Response, fallback: string): Promise<Response> {
  if (response.ok) return response;
  let diagnostic: Diagnostic | undefined;
  try {
    const candidate = (await response.json()) as Partial<Diagnostic>;
    if (typeof candidate.id === "string" && typeof candidate.what === "string" && typeof candidate.why === "string" && typeof candidate.fix === "string") diagnostic = candidate as Diagnostic;
  } catch {
    // Preserve the HTTP fallback when the server did not return a diagnostic.
  }
  if (diagnostic !== undefined) {
    showDiagnostic(diagnostic);
    throw new ApiRequestError(diagnostic.id + ": " + diagnostic.what);
  }
  throw new Error(fallback + " (" + response.status + ")");
}

/** Reports an unexpected failure once, in the diagnostic register. */
function reportUnexpected(error: unknown, diagnostic: Diagnostic): void {
  if (error instanceof ApiRequestError) return;
  showDiagnostic({ ...diagnostic, why: String(error) });
  toast(diagnostic.what, "danger");
}

function sendControl(message: unknown): void {
  if (control?.readyState === WebSocket.OPEN) control.send(JSON.stringify(message));
  else setStatus("Control channel unavailable", "unavailable");
}

/** Puts a button into a branded busy state for the length of an action. */
async function withBusy<T>(button: HTMLButtonElement | null, label: string, run: () => Promise<T>): Promise<T> {
  if (button === null) return run();
  const original = button.innerHTML;
  button.setAttribute("aria-busy", "true");
  button.disabled = true;
  button.innerHTML = `${icon("refresh", { size: 16, className: "spinner" })}<span>${escapeHtml(label)}</span>`;
  try {
    return await run();
  } finally {
    button.removeAttribute("aria-busy");
    button.disabled = false;
    button.innerHTML = original;
  }
}

/* ==================================================================== *
 * 7. Workbench — traffic list and intercept queue
 * ==================================================================== */

function statusClass(status: number | null | undefined): string {
  return status === null || status === undefined ? "" : String(Math.floor(status / 100));
}

function renderFlows(): void {
  if (flowList === null) return;
  if (flows.size === 0) {
    flowList.innerHTML = flowsLoaded
      ? stateBlock({
          icon: "traffic",
          title: "No traffic yet",
          body: "Launch the capture browser or point a client at the session proxy. Requests appear here as they are observed.",
        })
      : `<div class="state state--compact"><span class="state__icon">${icon("refresh", { size: 26, className: "spinner" })}</span><p class="state__body">Loading captured flows…</p></div>`;
    updateWorkbenchCounts();
    return;
  }
  flowList.replaceChildren();
  [...flows.values()].sort((a, b) => b.id - a.id).forEach((flow) => {
    const item = document.createElement("button");
    item.className = `list-row${flow.id === selectedFlow?.summary.id ? " is-selected" : ""}`;
    item.type = "button";
    item.style.gridTemplateColumns = "3.5rem minmax(0, 1fr) 3rem";
    const method = (flow.method ?? "").toUpperCase();
    item.innerHTML = `<span class="list-row__method" data-method="${escapeHtml(method)}">${escapeHtml(method === "" ? "—" : method)}</span><span class="list-row__target"><b>${escapeHtml(flow.host ?? "unknown")}</b>${escapeHtml(flow.path ?? "")}</span><span class="list-row__status" data-class="${statusClass(flow.status)}">${flow.status ?? "…"}</span>`;
    item.addEventListener("click", () => void selectFlow(flow.id));
    item.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      showFlowMenu(event.clientX, event.clientY, flow.id);
    });
    flowList.append(item);
  });
  updateWorkbenchCounts();
}

function updateWorkbenchCounts(): void {
  if (workbenchCounts === null) return;
  const held = pending.size === 0 ? "" : ` · ${pending.size} held`;
  workbenchCounts.textContent = `${flows.size} flow${flows.size === 1 ? "" : "s"}${held}`;
}

/** Seconds until the backend auto-forwards a held flow, from GUI-observed hold. */
function heldSecondsRemaining(flowId: number): number | null {
  const start = heldSince.get(flowId);
  if (start === undefined) return null;
  return Math.max(0, Math.ceil((INTERCEPT_TIMEOUT_MS - (Date.now() - start)) / 1000));
}

/**
 * Keeps the auto-forward countdown state in sync with the held set, and runs a
 * one-second ticker only while requests are actually held.
 */
function reconcileHeld(): void {
  const now = Date.now();
  pending.forEach((flowId) => { if (!heldSince.has(flowId)) heldSince.set(flowId, now); });
  [...heldSince.keys()].forEach((flowId) => { if (!pending.has(flowId)) heldSince.delete(flowId); });
  if (pending.size > 0 && queueTicker === undefined) {
    queueTicker = window.setInterval(() => { renderQueue(); updateDecisionControls(); }, 1000);
  } else if (pending.size === 0 && queueTicker !== undefined) {
    window.clearInterval(queueTicker);
    queueTicker = undefined;
  }
}

/** Gates the forward/modify/drop controls to genuinely held flows only. */
function updateDecisionControls(): void {
  const held = selectedFlow !== null && pending.has(selectedFlow.summary.id);
  [document.querySelector<HTMLButtonElement>("#forward"), document.querySelector<HTMLButtonElement>("#forward-modified"), document.querySelector<HTMLButtonElement>("#drop")]
    .forEach((button) => { if (button !== null) button.disabled = !held; });
  const note = document.querySelector<HTMLElement>("#intercept-note");
  if (note === null) return;
  note.className = "t-small t-subtle";
  note.style.color = "";
  if (selectedFlow === null) { note.textContent = ""; return; }
  if (!held) {
    note.textContent = "This request is not held. Forward, modify, and drop apply only to requests paused by intercept.";
    return;
  }
  const remaining = heldSecondsRemaining(selectedFlow.summary.id);
  if (remaining === null) { note.textContent = ""; return; }
  note.textContent = remaining === 0 ? "Auto-forwarding now…" : `Held — auto-forwards in ${remaining}s if no decision is made.`;
  if (remaining <= 5) note.style.color = "var(--color-danger-ink)";
}

function renderQueue(): void {
  if (queueList === null) return;
  if (pending.size === 0) {
    queueList.innerHTML = stateBlock({
      icon: "check",
      title: "No paused requests",
      body: "With intercept on, matching requests pause here until you forward, modify, or drop them.",
      compact: true,
    });
    updateWorkbenchCounts();
    return;
  }
  queueList.replaceChildren();
  [...pending].sort((a, b) => b - a).forEach((flowId) => {
    const flow = flows.get(flowId);
    const item = document.createElement("button");
    item.className = "list-row";
    item.type = "button";
    item.style.gridTemplateColumns = "minmax(0, 1fr) auto";
    const method = (flow?.method ?? "").toUpperCase();
    const remaining = heldSecondsRemaining(flowId);
    const countdown = remaining === null ? "" : remaining === 0 ? " · forwarding…" : ` · ${remaining}s`;
    const tone = remaining !== null && remaining <= 5 ? "badge--danger" : "badge--caution";
    item.innerHTML = `<span class="list-row__target"><b>${escapeHtml(method === "" ? "REQUEST" : method)}</b> ${escapeHtml(flow?.host ?? "")}${escapeHtml(flow?.path ?? "")}</span><span class="badge ${tone}">held #${flowId}${countdown}</span>`;
    item.addEventListener("click", () => void selectFlow(flowId));
    queueList.append(item);
  });
  updateWorkbenchCounts();
}

async function selectFlow(flowId: number): Promise<void> {
  try {
    const response = await fetch(`/api/v1/workbench/flows/${flowId}`);
    await requireOk(response, "flow detail unavailable");
    selectedFlow = (await response.json()) as FlowDetail;
    if (methodInput !== null) methodInput.value = selectedFlow.summary.method ?? "GET";
    if (headersInput !== null) headersInput.value = selectedFlow.requestHeaders.map(([name, value]) => `${name}: ${value}`).join("\n");
    if (bodyInput !== null) bodyInput.value = bytesToText(selectedFlow.requestBody);
    if (selectedLabel !== null) selectedLabel.textContent = `Flow #${flowId} · ${selectedFlow.summary.host ?? "unknown"}${selectedFlow.summary.path ?? ""}`;
    if (editor !== null) editor.hidden = false;
    if (detail !== null) detail.innerHTML = renderDetail(selectedFlow);
    renderDetailActions(flowId);
    updateDecisionControls();
    renderFlows();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.live-transport-failed", what: "Flow detail could not be loaded.", why: "", fix: "Reconnect the active session." });
  }
}

/** The send-to-resend / send-to-fuzzer affordances for the selected flow. */
function renderDetailActions(flowId: number): void {
  if (detailActions === null) return;
  detailActions.replaceChildren();

  const resend = document.createElement("button");
  resend.type = "button";
  resend.className = "btn btn--sm";
  resend.innerHTML = `${icon("send", { size: 14 })}<span>Resend</span>`;
  resend.addEventListener("click", () => void createResend(flowId));

  const fuzzer = document.createElement("button");
  fuzzer.type = "button";
  fuzzer.className = "btn btn--sm";
  fuzzer.innerHTML = `${icon("discovery", { size: 14 })}<span>Fuzz</span>`;
  fuzzer.addEventListener("click", () => void openFuzzer(flowId));

  detailActions.append(resend, fuzzer);
}

function renderDetailEmpty(): void {
  if (detail === null) return;
  detail.innerHTML = stateBlock({
    icon: "chevronRight",
    title: "No flow selected",
    body: "Choose a row from live traffic to inspect its request and response, then resend it or send it to the Fuzzer.",
  });
}

function renderDetail(flow: FlowDetail): string {
  const body = (bytes: number[] | null | undefined): string =>
    bytes === null || bytes === undefined
      ? "Body not retained by this backend."
      : `${formatBytes(bytes.length)} retained in memory.`;
  const summary = flow.summary;
  return `<div class="stack">
<dl class="kv">
  <dt>Method</dt><dd class="t-mono">${escapeHtml(summary.method ?? "—")}</dd>
  <dt>URL</dt><dd class="t-mono">${escapeHtml(summary.url ?? `${summary.host ?? ""}${summary.path ?? ""}`)}</dd>
  <dt>Status</dt><dd class="t-mono">${summary.status ?? "pending"}</dd>
  <dt>Duration</dt><dd class="t-mono">${summary.durationMs === null || summary.durationMs === undefined ? "—" : `${summary.durationMs} ms`}</dd>
  <dt>Type</dt><dd class="t-mono">${escapeHtml(summary.contentType ?? "—")}</dd>
</dl>
<hr class="rule" />
<div class="reqres">
  <section class="reqres__col stack stack--tight">
    <p class="section-label">Request</p>
    <pre class="code">${escapeHtml(formatHeaders(flow.requestHeaders))}</pre>
    <p class="t-small t-subtle">${escapeHtml(body(flow.requestBody))}</p>
  </section>
  <section class="reqres__col stack stack--tight">
    <p class="section-label">Response</p>
    <pre class="code">${escapeHtml(formatHeaders(flow.responseHeaders))}</pre>
    <p class="t-small t-subtle">${escapeHtml(body(flow.responseBody))}</p>
  </section>
</div>
</div>`;
}

async function refreshPending(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/intercept/pending");
    if (!response.ok) return;
    pending.clear();
    ((await response.json()) as number[]).forEach((flowId) => pending.add(flowId));
    reconcileHeld();
    renderQueue();
    updateDecisionControls();
  } catch {
    // The WebSocket diagnostic remains the authoritative transport signal.
  }
}

/**
 * Brings a workbench drawer into view. On the wide layout the drawer already
 * shares the fixed-height column with the traffic grid, so scrolling would only
 * push the grid out of sight; there, opening it is enough.
 */
function revealDrawer(panel: HTMLElement | null): void {
  if (panel === null) return;
  if (window.matchMedia("(max-width: 1100px)").matches) {
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

/* ==================================================================== *
 * 7. Workbench — fuzzer
 * ==================================================================== */

async function openFuzzer(flowId: number): Promise<void> {
  if (selectedFlow === null || selectedFlow.summary.id !== flowId) return;
  selectedFuzzer = {
    id: "", tier: "ffuf", state: "draft",
    config: {
      baseRequest: { method: selectedFlow.summary.method ?? "GET", url: selectedFlow.summary.url ?? "", headers: [...selectedFlow.requestHeaders], body: selectedFlow.requestBody ?? null },
      positions: [{ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }],
      payloadSets: [{ name: "set 1", values: [] }],
      attackType: "sniper",
      // Real defaults: a bounded status/size/content filter so a "matched" row
      // means the response actually matched, not merely "a response arrived".
      matchFilter: { statuses: [], minSize: null, maxSize: null, contains: null, regex: null },
      // Sane throughput against a real target: modest parallelism, throttled.
      concurrency: 5, ratePerSecond: 10, maxResults: 100, authPreflight: null, sequence: [],
    },
    results: [], diagnostics: [],
  };
  currentFuzzDraft = selectedFuzzer;
  renderFuzzer();
  renderFuzzList();
  showWorkbenchTab("fuzz");
}

/** Config is only editable before the job is created; the backend snapshots it. */
function fuzzerConfigLocked(): boolean {
  return selectedFuzzer !== null && selectedFuzzer.id !== "";
}

/** Text of the field a payload position substitutes into, for live preview. */
function positionFieldText(config: FuzzerConfig, position: FuzzerPosition): string {
  if (position.location === "url") return config.baseRequest.url;
  if (position.location === "body") return bytesToText(config.baseRequest.body);
  const name = (position.headerName ?? "").toLowerCase();
  return config.baseRequest.headers.find(([header]) => header.toLowerCase() === name)?.[1] ?? "";
}

/** Snapshots the current form inputs back into the draft config. */
function readFuzzerForm(): void {
  if (selectedFuzzer === null || fuzzerConfigLocked() || fuzzerPanel === null) return;
  const config = selectedFuzzer.config;

  const sets: FuzzerPayloadSet[] = [];
  fuzzerPanel.querySelectorAll<HTMLElement>("[data-set-row]").forEach((row) => {
    const j = row.dataset.setRow ?? "0";
    const name = valueOfFuzzer(`#set-name-${j}`).trim() || `set ${Number(j) + 1}`;
    const values = valueOfFuzzer(`#set-values-${j}`).split("\n").map((value) => value.trim()).filter(Boolean);
    sets.push({ name, values });
  });
  if (sets.length > 0) config.payloadSets = sets;

  const positions: FuzzerPosition[] = [];
  fuzzerPanel.querySelectorAll<HTMLElement>("[data-position-row]").forEach((row) => {
    const i = row.dataset.positionRow ?? "0";
    const location = (valueOfFuzzer(`#pos-location-${i}`) || "url") as FuzzerLocation;
    const headerName = location === "header" ? (valueOfFuzzer(`#pos-header-${i}`).trim() || null) : null;
    const start = Math.max(0, Math.floor(Number(valueOfFuzzer(`#pos-start-${i}`)) || 0));
    const end = Math.max(start, Math.floor(Number(valueOfFuzzer(`#pos-end-${i}`)) || 0));
    let setIndex = Math.floor(Number(valueOfFuzzer(`#pos-set-${i}`)) || 0);
    if (setIndex >= config.payloadSets.length) setIndex = Math.max(0, config.payloadSets.length - 1);
    positions.push({ location, headerName, start, end, setIndex });
  });
  if (positions.length > 0) config.positions = positions;

  config.attackType = valueOfFuzzer("#fuzzer-type") || "sniper";
  config.maxResults = Math.max(1, Math.floor(Number(valueOfFuzzer("#fuzzer-max")) || 100));
  config.concurrency = Math.max(1, Math.floor(Number(valueOfFuzzer("#fuzzer-concurrency")) || 1));
  config.ratePerSecond = Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-rate")) || 0));

  const statuses = valueOfFuzzer("#match-statuses").split(",").map((value) => Number(value.trim())).filter((value) => Number.isFinite(value) && value > 0);
  const parseSize = (raw: string): number | null => { const trimmed = raw.trim(); if (trimmed === "") return null; const n = Number(trimmed); return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : null; };
  const contains = valueOfFuzzer("#match-contains");
  const regex = valueOfFuzzer("#match-regex").trim();
  config.matchFilter = { statuses, minSize: parseSize(valueOfFuzzer("#match-min")), maxSize: parseSize(valueOfFuzzer("#match-max")), contains: contains === "" ? null : contains, regex: regex === "" ? null : regex };

  const seqRaw = valueOfFuzzer("#fuzzer-sequence").trim();
  if (seqRaw === "") { config.sequence = []; }
  else { try { const parsed: unknown = JSON.parse(seqRaw); if (Array.isArray(parsed)) config.sequence = parsed; } catch { /* validated on launch */ } }
}

function addFuzzerPosition(): void { if (selectedFuzzer === null) return; readFuzzerForm(); selectedFuzzer.config.positions.push({ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }); renderFuzzer(); }
function removeFuzzerPosition(index: number): void { if (selectedFuzzer === null) return; readFuzzerForm(); selectedFuzzer.config.positions.splice(index, 1); if (selectedFuzzer.config.positions.length === 0) selectedFuzzer.config.positions.push({ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }); renderFuzzer(); }
function addFuzzerSet(): void { if (selectedFuzzer === null) return; readFuzzerForm(); selectedFuzzer.config.payloadSets.push({ name: `set ${selectedFuzzer.config.payloadSets.length + 1}`, values: [] }); renderFuzzer(); }
function removeFuzzerSet(index: number): void { if (selectedFuzzer === null) return; readFuzzerForm(); const config = selectedFuzzer.config; config.payloadSets.splice(index, 1); if (config.payloadSets.length === 0) config.payloadSets.push({ name: "set 1", values: [] }); config.positions.forEach((position) => { if (position.setIndex >= config.payloadSets.length) position.setIndex = config.payloadSets.length - 1; }); renderFuzzer(); }

function renderFuzzerPositionRow(config: FuzzerConfig, position: FuzzerPosition, index: number, locked: boolean): string {
  const disabled = locked ? "disabled" : "";
  const opt = (value: string, label: string, selected: boolean): string => `<option value="${value}"${selected ? " selected" : ""}>${label}</option>`;
  const setOptions = config.payloadSets.map((set, j) => opt(String(j), escapeHtml(`${j + 1} · ${set.name}`), j === position.setIndex)).join("");
  const preview = position.end > position.start ? positionFieldText(config, position).slice(position.start, position.end) : "";
  const previewHtml = position.end > position.start
    ? `replaces <code class="t-mono">${escapeHtml(preview === "" ? "(range is outside the field)" : preview)}</code>`
    : `<span class="t-subtle">set Start/End to mark the bytes to replace</span>`;
  return `<div class="stack stack--tight" data-position-row="${index}" style="border:1px solid var(--border);border-radius:var(--radius-2);padding:var(--space-3)">
  <div class="split-4">
    <div class="field"><label class="field__label" for="pos-location-${index}">Location</label><select class="select" id="pos-location-${index}" ${disabled}>${opt("url", "URL", position.location === "url")}${opt("header", "Header", position.location === "header")}${opt("body", "Body", position.location === "body")}</select></div>
    <div class="field"${position.location === "header" ? "" : ' hidden'} data-pos-header><label class="field__label" for="pos-header-${index}">Header name</label><input class="input input--mono" id="pos-header-${index}" type="text" value="${escapeHtml(position.headerName ?? "")}" ${disabled} /></div>
    <div class="field"><label class="field__label" for="pos-start-${index}">Start</label><input class="input input--mono" id="pos-start-${index}" type="number" min="0" value="${position.start}" ${disabled} /></div>
    <div class="field"><label class="field__label" for="pos-end-${index}">End</label><input class="input input--mono" id="pos-end-${index}" type="number" min="0" value="${position.end}" ${disabled} /></div>
  </div>
  <div class="row">
    <div class="field"><label class="field__label" for="pos-set-${index}">Payload set</label><select class="select" id="pos-set-${index}" ${disabled}>${setOptions}</select></div>
    <span class="spacer"></span>
    ${locked ? "" : `<button class="btn btn--sm btn--quiet" type="button" data-remove-pos="${index}">${icon("close", { size: 12 })}<span>Remove position</span></button>`}
  </div>
  <p class="field__hint">${previewHtml}</p>
</div>`;
}

function renderFuzzerSetRow(set: FuzzerPayloadSet, index: number, locked: boolean): string {
  const disabled = locked ? "disabled" : "";
  return `<div class="stack stack--tight" data-set-row="${index}">
  <div class="row">
    <div class="field field--inline"><label class="field__label" for="set-name-${index}">Set ${index + 1}</label><input class="input input--mono" id="set-name-${index}" type="text" value="${escapeHtml(set.name)}" ${disabled} /></div>
    <span class="spacer"></span>
    ${locked ? "" : `<button class="btn btn--sm btn--quiet" type="button" data-remove-set="${index}">${icon("close", { size: 12 })}<span>Remove set</span></button>`}
  </div>
  <textarea class="textarea" id="set-values-${index}" spellcheck="false" placeholder="one payload per line" ${disabled}>${escapeHtml(set.values.join("\n"))}</textarea>
</div>`;
}

/** Resting state for the shared dock's Resend tab when no request is loaded. */
function seedResendEmpty(): void {
  if (resendPanel === null) return;
  resendPanel.hidden = false;
  resendPanel.innerHTML = stateBlock({
    icon: "refresh",
    title: "No request loaded",
    body: "Send a flow here from the traffic table or the API surface, then edit and resend it.",
    compact: true,
  });
}

/** Resting state for the shared dock's Fuzzer tab when no attack is loaded. */
function seedFuzzerEmpty(): void {
  if (fuzzerPanel === null) return;
  fuzzerPanel.hidden = false;
  fuzzerPanel.innerHTML = stateBlock({
    icon: "discovery",
    title: "No attack loaded",
    body: "Send a flow here from the traffic table or the API surface to mark positions and fuzz it.",
    compact: true,
  });
}

function renderFuzzer(): void {
  if (fuzzerPanel === null || selectedFuzzer === null) return;
  fuzzerPanel.hidden = false;
  const config = selectedFuzzer.config;
  const locked = fuzzerConfigLocked();
  const disabled = locked ? "disabled" : "";
  const filter = config.matchFilter;
  const sequence = Array.isArray(config.sequence) ? config.sequence : [];
  const launchLabel = locked && selectedFuzzer.state === "paused" ? "Resume" : locked ? "Start" : "Create attack";
  const sequencePlaceholder = escapeHtml('[{"name":"login","request":{"method":"POST","url":"https://target/login","headers":[]},"extractors":[]}]');
  const opt = (value: string, label: string, selected: boolean): string => `<option value="${value}"${selected ? " selected" : ""}>${label}</option>`;
  const attackHint = config.positions.length <= 1 || config.payloadSets.length <= 1
    ? "With a single position and set, all attack types are equivalent. Add positions/sets for Clusterbomb (every combination) or Pitchfork (paired by row)."
    : config.attackType === "clusterbomb" ? "Clusterbomb: every combination across sets."
    : config.attackType === "pitchfork" ? "Pitchfork: values paired by row across sets (shortest set wins)."
    : "Sniper: one position at a time using its set.";

  fuzzerPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("discovery", { size: 16 })}<h2>Fuzzer · ${escapeHtml(selectedFuzzer.id === "" ? "new attack" : selectedFuzzer.id.slice(-8))}</h2></div>
  <div class="row">
    <span class="badge">${escapeHtml(selectedFuzzer.tier)}</span>
    <span class="badge ${selectedFuzzer.state === "running" ? "badge--accent" : selectedFuzzer.state === "failed" ? "badge--danger" : ""}">${escapeHtml(selectedFuzzer.state)}</span>
    <button class="btn btn--quiet btn--icon" type="button" data-close-fuzzer><span class="visually-hidden">Close Fuzzer</span>${icon("close", { size: 16 })}</button>
  </div>
</div>
<div class="panel__body stack">
  <div class="stack stack--tight">
    <p class="section-label">Base request</p>
    <pre class="code">${escapeHtml(`${config.baseRequest.method} ${config.baseRequest.url}\n${formatHeaders(config.baseRequest.headers)}${bytesToText(config.baseRequest.body) === "" ? "" : `\n\n${bytesToText(config.baseRequest.body)}`}`)}</pre>
    <p class="field__hint">Positions are byte offsets into this request. Offsets are 0-based; End is exclusive.</p>
  </div>

  <div class="split-2">
    <div class="field">
      <label class="field__label" for="fuzzer-type">Attack type</label>
      <select class="select" id="fuzzer-type" ${disabled}>${opt("sniper", "Sniper", config.attackType === "sniper")}${opt("clusterbomb", "Clusterbomb", config.attackType === "clusterbomb")}${opt("pitchfork", "Pitchfork", config.attackType === "pitchfork")}</select>
      <p class="field__hint">${escapeHtml(attackHint)}</p>
    </div>
    <div class="split-3">
      <div class="field"><label class="field__label" for="fuzzer-concurrency">Concurrency</label><input class="input input--mono" id="fuzzer-concurrency" type="number" min="1" value="${config.concurrency}" ${disabled} /></div>
      <div class="field"><label class="field__label" for="fuzzer-rate">Rate/s</label><input class="input input--mono" id="fuzzer-rate" type="number" min="0" value="${config.ratePerSecond}" ${disabled} /><p class="field__hint">0 = unlimited</p></div>
      <div class="field"><label class="field__label" for="fuzzer-max">Max results</label><input class="input input--mono" id="fuzzer-max" type="number" min="1" value="${config.maxResults}" ${disabled} /></div>
    </div>
  </div>

  <div class="stack stack--tight">
    <div class="row"><p class="section-label">Payload positions</p><span class="spacer"></span>${locked ? "" : `<button class="btn btn--sm" type="button" data-add-pos>${icon("plus", { size: 12 })}<span>Add position</span></button>`}</div>
    ${config.positions.map((position, index) => renderFuzzerPositionRow(config, position, index, locked)).join("")}
  </div>

  <div class="stack stack--tight">
    <div class="row"><p class="section-label">Payload sets</p><span class="spacer"></span>${locked ? "" : `<button class="btn btn--sm" type="button" data-add-set>${icon("plus", { size: 12 })}<span>Add set</span></button>`}</div>
    ${config.payloadSets.map((set, index) => renderFuzzerSetRow(set, index, locked)).join("")}
  </div>

  <div class="stack stack--tight">
    <p class="section-label">Match filter</p>
    <p class="field__hint">A response is "matched" only when it satisfies these rules. Leave all blank to keep every response.</p>
    <div class="split-2">
      <div class="field"><label class="field__label" for="match-statuses">Status codes (comma-separated)</label><input class="input input--mono" id="match-statuses" type="text" value="${escapeHtml(filter.statuses.join(", "))}" placeholder="200, 301, 401" ${disabled} /></div>
      <div class="split-2">
        <div class="field"><label class="field__label" for="match-min">Min size</label><input class="input input--mono" id="match-min" type="number" min="0" value="${filter.minSize ?? ""}" ${disabled} /></div>
        <div class="field"><label class="field__label" for="match-max">Max size</label><input class="input input--mono" id="match-max" type="number" min="0" value="${filter.maxSize ?? ""}" ${disabled} /></div>
      </div>
    </div>
    <div class="split-2">
      <div class="field"><label class="field__label" for="match-contains">Body contains</label><input class="input input--mono" id="match-contains" type="text" value="${escapeHtml(filter.contains ?? "")}" ${disabled} /></div>
      <div class="field"><label class="field__label" for="match-regex">Body regex</label><input class="input input--mono" id="match-regex" type="text" value="${escapeHtml(filter.regex ?? "")}" ${disabled} /></div>
    </div>
  </div>

  <div class="field">
    <label class="field__label" for="fuzzer-sequence">Native token-chain sequence (JSON, optional)</label>
    <textarea class="textarea" id="fuzzer-sequence" spellcheck="false" placeholder="${sequencePlaceholder}" ${disabled}>${escapeHtml(sequence.length === 0 ? "" : JSON.stringify(sequence, null, 2))}</textarea>
    <p class="field__hint">Stateful native attacks: each step may extract <code class="t-mono">{{variable}}</code> values for later requests.</p>
  </div>

  <div class="row">
    ${selectedFuzzer.state === "running" ? "" : `<button class="btn btn--primary" id="fuzzer-launch" type="button">${icon("play", { size: 14 })}<span>${escapeHtml(launchLabel)}</span></button>`}
    <button class="btn" id="fuzzer-pause" type="button">${icon("pause", { size: 14 })}<span>Pause</span></button>
    <button class="btn btn--danger" id="fuzzer-stop" type="button">${icon("stop", { size: 14 })}<span>Stop</span></button>
  </div>

  <div id="fuzzer-results">${renderFuzzerResults(selectedFuzzer.results)}</div>
</div>`;

  fuzzerPanel.querySelector("#fuzzer-launch")?.addEventListener("click", () => void launchFuzzer());
  fuzzerPanel.querySelector("#fuzzer-pause")?.addEventListener("click", () => void pauseFuzzer());
  fuzzerPanel.querySelector("#fuzzer-stop")?.addEventListener("click", () => void stopFuzzer());
  fuzzerPanel.querySelector("[data-add-pos]")?.addEventListener("click", () => addFuzzerPosition());
  fuzzerPanel.querySelector("[data-add-set]")?.addEventListener("click", () => addFuzzerSet());
  fuzzerPanel.querySelectorAll<HTMLButtonElement>("[data-remove-pos]").forEach((button) => button.addEventListener("click", () => removeFuzzerPosition(Number(button.dataset.removePos))));
  fuzzerPanel.querySelectorAll<HTMLButtonElement>("[data-remove-set]").forEach((button) => button.addEventListener("click", () => removeFuzzerSet(Number(button.dataset.removeSet))));
  // A location change toggles the header-name field and refreshes the preview.
  fuzzerPanel.querySelectorAll<HTMLSelectElement>('[id^="pos-location-"]').forEach((select) => select.addEventListener("change", () => { readFuzzerForm(); renderFuzzer(); }));
  // Offset edits refresh their row's live preview without a full rebuild.
  fuzzerPanel.querySelectorAll<HTMLInputElement>('[id^="pos-start-"], [id^="pos-end-"]').forEach((input) => input.addEventListener("change", () => { readFuzzerForm(); renderFuzzer(); }));
  fuzzerPanel.querySelector("[data-close-fuzzer]")?.addEventListener("click", () => {
    if (fuzzerPoll !== undefined) { window.clearInterval(fuzzerPoll); fuzzerPoll = undefined; }
    selectedFuzzer = null;
    seedFuzzerEmpty();
  });
}

function renderFuzzerResults(results: readonly FuzzerResult[]): string {
  if (results.length === 0) {
    return stateBlock({
      icon: "discovery",
      title: "No results yet",
      body: "Mark a URL, body, or header range, supply payloads, then start the attack.",
      compact: true,
    });
  }
  const matchedCount = results.filter((result) => result.matched).length;
  const rows = [...results]
    .sort((a, b) => Number(b.matched) - Number(a.matched) || a.ordinal - b.ordinal)
    .map((result) => {
      const status = result.response?.status;
      return `<tr class="${result.matched ? "is-match" : ""}"><td>${result.ordinal}</td><td>${escapeHtml(result.payloads.join(" / "))}</td><td><span class="list-row__status" data-class="${statusClass(status)}">${status ?? escapeHtml(result.diagnostic?.id ?? "failed")}</span></td><td>${result.response?.body?.length ?? "—"}</td><td>${result.response?.durationMs ?? "—"}</td><td>${result.matched ? '<span class="badge badge--success">match</span>' : result.filtered ? '<span class="t-subtle">filtered</span>' : ""}</td></tr>`;
    })
    .join("");
  return `<div class="stack stack--tight"><p class="section-label">Results · ${results.length} · ${matchedCount} matched</p><div class="discovery-results"><table class="data-table"><thead><tr><th>#</th><th>Payload</th><th>Status</th><th>Length</th><th>Time</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}

async function launchFuzzer(): Promise<void> {
  if (selectedFuzzer === null) return;
  try {
    if (selectedFuzzer.id === "") {
      readFuzzerForm();
      const config = selectedFuzzer.config;
      // Validate the token-chain sequence JSON before committing the job.
      const seqRaw = valueOfFuzzer("#fuzzer-sequence").trim();
      if (seqRaw !== "") { try { const parsed: unknown = JSON.parse(seqRaw); if (!Array.isArray(parsed)) throw new Error("sequence must be a JSON array"); config.sequence = parsed; } catch (error) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "The token-chain sequence is invalid JSON.", why: String(error), fix: "Enter a JSON array of named request steps and retry." }); return; } }
      if (config.positions.length === 0) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "The attack has no payload positions.", why: "At least one marked position is required to substitute payloads.", fix: "Add a position and mark the bytes to replace, then start the attack." }); return; }
      if (config.payloadSets.every((set) => set.values.length === 0) && config.sequence?.length === 0) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "No payloads were supplied.", why: "Every payload set is empty, so there is nothing to send.", fix: "Enter at least one payload value, one per line." }); return; }
      const created = await fetch("/api/v1/workbench/fuzzer", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(config) });
      await requireOk(created, "fuzzer configuration failed");
      selectedFuzzer = (await created.json()) as FuzzerJob;
    }
    const action = selectedFuzzer.state === "paused" ? "resume" : "start";
    const started = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(selectedFuzzer.id) + "/" + action, { method: "POST" });
    await requireOk(started, "fuzzer " + action + " failed");
    selectedFuzzer = (await started.json()) as FuzzerJob;
    renderFuzzer();
    syncFuzzToList();
    if (fuzzerPoll !== undefined) window.clearInterval(fuzzerPoll);
    fuzzerPoll = window.setInterval(() => void refreshFuzzer(), 500);
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The Fuzzer job could not start.", why: "", fix: "Check payload positions, payloads, and the session proxy/tool configuration." });
  }
}

async function refreshFuzzer(): Promise<void> {
  if (selectedFuzzer === null || selectedFuzzer.id === "") return;
  try {
    const response = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(selectedFuzzer.id));
    await requireOk(response, "fuzzer status unavailable");
    selectedFuzzer = (await response.json()) as FuzzerJob;
    selectedFuzzer.diagnostics.forEach(showDiagnostic);
    renderFuzzer();
    syncFuzzToList();
    if (["completed", "failed", "stopped"].includes(selectedFuzzer.state) && fuzzerPoll !== undefined) { window.clearInterval(fuzzerPoll); fuzzerPoll = undefined; }
  } catch (error) {
    if (fuzzerPoll !== undefined) { window.clearInterval(fuzzerPoll); fuzzerPoll = undefined; }
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The Fuzzer status could not be loaded.", why: "", fix: "Check the active session and retry." });
  }
}

async function stopFuzzer(): Promise<void> {
  if (selectedFuzzer === null || selectedFuzzer.id === "") return;
  try {
    await requireOk(await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(selectedFuzzer.id) + "/stop", { method: "POST" }), "fuzzer stop failed");
    await refreshFuzzer();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The Fuzzer job could not stop.", why: "", fix: "Check the active session and retry." });
  }
}

async function pauseFuzzer(): Promise<void> {
  if (selectedFuzzer === null || selectedFuzzer.id === "") return;
  try {
    const response = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(selectedFuzzer.id) + "/pause", { method: "POST" });
    await requireOk(response, "fuzzer pause failed");
    selectedFuzzer = (await response.json()) as FuzzerJob;
    renderFuzzer();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The Fuzzer job could not pause.", why: "", fix: "Pause only at a request boundary while the job is running." });
  }
}

function valueOfFuzzer(selector: string): string { return fuzzerPanel?.querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(selector)?.value ?? ""; }

/* ==================================================================== *
 * 7. Workbench — resend
 * ==================================================================== */

async function createResend(flowId: number): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/resend", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ flowId }) });
    await requireOk(response, "resend context unavailable");
    registerResend((await response.json()) as ResendContext);
    renderResend();
    showView("workbench");
    showWorkbenchTab("resend");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "The Resend context could not be created.", why: "", fix: "Check the selected flow and session store, then retry." });
  }
}

function renderResend(): void {
  if (resendPanel === null || selectedResend === null) return;
  resendPanel.hidden = false;
  resendPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("send", { size: 16 })}<h2>Resend · ${escapeHtml(selectedResend.id.slice(-8))}</h2></div>
  <div class="row">
    <span class="panel__hint">append-only history</span>
    <button class="btn btn--quiet btn--icon" type="button" data-close-resend><span class="visually-hidden">Close Resend</span>${icon("close", { size: 16 })}</button>
  </div>
</div>
<div class="panel__body stack">
  <div class="split-2">
    <div class="field">
      <label class="field__label" for="resend-method">Method</label>
      <input class="input input--mono" id="resend-method" value="${escapeHtml(selectedResend.current.method)}" />
    </div>
    <div class="field">
      <label class="field__label" for="resend-url">URL</label>
      <input class="input input--mono" id="resend-url" value="${escapeHtml(selectedResend.current.url)}" />
    </div>
  </div>
  <div class="split-2">
    <div class="field">
      <label class="field__label" for="resend-headers">Headers</label>
      <textarea class="textarea" id="resend-headers" spellcheck="false">${escapeHtml(formatHeaders(selectedResend.current.headers))}</textarea>
    </div>
    <div class="field">
      <label class="field__label" for="resend-body">Body</label>
      <textarea class="textarea textarea--wrap" id="resend-body" spellcheck="false">${escapeHtml(bytesToText(selectedResend.current.body))}</textarea>
    </div>
  </div>
  <div class="row">
    <button class="btn btn--primary" id="resend-send" type="button">${icon("send", { size: 14 })}<span>Send request</span></button>
  </div>
  <div id="resend-response">${renderResendHistory(selectedResend.history)}</div>
</div>`;
  resendPanel.querySelector("#resend-send")?.addEventListener("click", () => void sendResend());
  resendPanel.querySelectorAll<HTMLButtonElement>("[data-derive]").forEach((button) => button.addEventListener("click", () => void deriveResend(Number(button.dataset.derive))));
  resendPanel.querySelector("[data-close-resend]")?.addEventListener("click", () => { selectedResend = null; seedResendEmpty(); });
}

function renderResendHistory(history: readonly ResendRevision[]): string {
  if (history.length === 0) {
    return stateBlock({
      icon: "clock",
      title: "No sends yet",
      body: "Edit the request and send it through the active session proxy. Every send is kept as an immutable revision.",
      compact: true,
    });
  }
  const entries = [...history].reverse().map((entry) => {
    const status = entry.response?.status;
    const response = entry.response ?? null;
    const note = response === null
      ? entry.diagnostic?.what ?? "No response"
      : `${response.durationMs} ms · ${formatBytes(response.body?.length ?? 0)}`;
    return `<article class="history__entry">
<div class="history__head">
  <span class="history__revision">#${entry.revision}</span>
  <span class="list-row__status" data-class="${statusClass(status)}">${status ?? escapeHtml(entry.diagnostic?.id ?? "failed")}</span>
  <span class="badge">${escapeHtml(entry.scope)}</span>
  <span class="spacer"></span>
  <span class="t-small t-subtle">${escapeHtml(formatTime(entry.sentAt))}</span>
  <button class="btn btn--sm" type="button" data-derive="${entry.revision}">Derive</button>
</div>
<pre class="code">${escapeHtml(formatHeaders(entry.response?.headers ?? []))}</pre>
<p class="t-small t-subtle">${escapeHtml(note)}</p>
</article>`;
  }).join("");
  return `<div class="stack stack--tight"><p class="section-label">History · ${history.length}</p><div class="history">${entries}</div></div>`;
}

async function sendResend(): Promise<void> {
  const resend = selectedResend;
  if (resend === null) return;
  const resendId = resend.id;
  const request: ResendRequest = { method: valueOf("#resend-method"), url: valueOf("#resend-url"), headers: parseHeaders(valueOf("#resend-headers")), body: [...new TextEncoder().encode(valueOf("#resend-body"))] };
  try {
    const update = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
    await requireOk(update, "resend edit failed");
    const sent = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId) + "/send", { method: "POST" });
    await requireOk(sent, "resend send failed");
    const result = (await sent.json()) as Partial<ResendSendResult>;
    let context = result.context;
    if (context === null || context === undefined || typeof context.id !== "string") {
      const refreshed = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId));
      await requireOk(refreshed, "resend history refresh failed");
      context = (await refreshed.json()) as ResendContext;
    }
    if (context === null || typeof context.id !== "string") throw new Error("resend response did not include a valid context");
    selectedResend = context;
    resendContexts.set(context.id, context);
    (result.diagnostics ?? []).forEach(showDiagnostic);
    showDiagnostic(result.revision?.diagnostic);
    renderResend();
    renderResendList();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-request-failed", what: "The resend send failed.", why: "", fix: "Review the request and confirm the session proxy is running." });
  }
}

async function deriveResend(revision: number): Promise<void> {
  if (selectedResend === null) return;
  try {
    const response = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(selectedResend.id) + "/derive/" + revision, { method: "POST" });
    await requireOk(response, "resend derivation failed");
    selectedResend = (await response.json()) as ResendContext;
    renderResend();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-request-failed", what: "The resend request could not be derived.", why: "", fix: "Check the selected revision and session store, then retry." });
  }
}

function valueOf(selector: string): string { return resendPanel?.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)?.value ?? ""; }

/* ==================================================================== *
 * 4. Analysis pipeline
 * ==================================================================== */

const pipelineStages = ["intake", "static", "dynamic", "signing", "fusion", "confidence", "surface", "completed"];

const STAGE_LABELS: Record<string, string> = {
  intake: "Intake",
  static: "Static",
  dynamic: "Dynamic",
  signing: "Signing",
  fusion: "Fusion",
  confidence: "Confidence",
  surface: "Surface",
};

function renderPipeline(run: PipelineRun): void {
  if (pipelineStatus === null || pipelineProgress === null) return;
  pipelineStatus.textContent = run.status + " · " + run.stage;
  const percent = Math.min(100, Math.max(0, run.progressBasisPoints / 100));
  const stageIndex = pipelineStages.indexOf(run.stage);
  const tone = run.status === "completed" ? " progress--success" : run.status === "failed" ? " progress--failed" : " progress--running";
  // A static-only run skips the dynamic and signing-recovery stages entirely, so
  // those stages must read "skipped" — never the same "done" as a stage that
  // actually ran. Marking them done would contradict the "not incorporated" fact
  // shown just below and overstate what the analysis did.
  const skipped = new Set<string>(run.dynamicRan ? [] : ["dynamic", "signing"]);
  const stages = pipelineStages.slice(0, -1).map((stage, index) => {
    const isSkipped = skipped.has(stage);
    const done = !isSkipped && (index < stageIndex || run.status === "completed");
    const active = !isSkipped && stage === run.stage && run.status === "running";
    const cls = isSkipped ? "is-skipped" : done ? "is-done" : active ? "is-active" : "";
    const label = escapeHtml(STAGE_LABELS[stage] ?? stage) + (isSkipped ? " · skipped" : "");
    return `<span class="stage ${cls}"><span class="stage__marker"></span>${label}</span>`;
  }).join("");

  pipelineProgress.innerHTML = `<div class="stack">
<dl class="kv">
  <dt>Run</dt><dd class="t-mono">${escapeHtml(run.runId)}</dd>
  <dt>Artifact</dt><dd class="t-mono">${escapeHtml(run.artifactPath)}</dd>
  <dt>Dynamic</dt><dd>${run.dynamicRan ? "facts incorporated" : "not incorporated"}</dd>
  <dt>Updated</dt><dd>${escapeHtml(formatTime(run.updatedAt))}</dd>
</dl>
<div class="progress${tone}" role="progressbar" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100">
  <div class="progress__meta"><span>${escapeHtml(run.message)}</span><span class="progress__value">${percent.toFixed(1)}%</span></div>
  <div class="progress__track"><div class="progress__fill" style="width:${percent}%"></div></div>
</div>
<div class="stages">${stages}</div>
${run.status === "completed" ? `<div class="row"><button class="btn btn--primary" type="button" data-nav="surface">${icon("surface", { size: 14 })}<span>View fused surface</span></button><button class="btn" type="button" data-nav="export">${icon("export", { size: 14 })}<span>Export</span></button></div>` : ""}
</div>`;

  if (pipelineDiagnostics !== null) {
    pipelineDiagnostics.innerHTML = diagnosticListHtml(run.diagnostics, "This run produced no diagnostics.");
  }
  if (pipelineDiagnosticsCount !== null) {
    pipelineDiagnosticsCount.textContent = run.diagnostics.length === 0 ? "none" : `${run.diagnostics.length} reported`;
  }
  run.diagnostics.forEach(showDiagnostic);
}

function renderPipelineEmpty(): void {
  if (pipelineProgress === null) return;
  pipelineProgress.innerHTML = stateBlock({
    icon: "pipeline",
    title: "No run loaded",
    body: "Choose an APK and start the pipeline. Progress, stages, and diagnostics stream here while it runs.",
  });
  if (pipelineDiagnostics !== null) {
    pipelineDiagnostics.innerHTML = diagnosticListHtml([], "Diagnostics from the current run appear here.");
  }
}

async function startPipeline(): Promise<void> {
  const artifactPath = apkPath?.value.trim() ?? "";
  if (artifactPath === "") {
    showDiagnostic({ id: "pipeline.artifact-path-required", what: "An APK path is required.", why: "The analysis pipeline reads the artifact directly from this machine's filesystem.", fix: "Enter the full path to the APK and start the run again." });
    apkPath?.focus();
    return;
  }
  const staticOnly = apkStaticOnly?.checked === true;
  const dynamic = !staticOnly && apkDynamic?.checked === true;
  const confirmed = await confirmDialog({
    eyebrow: "Confirm before run",
    title: "Start the analysis pipeline",
    message: dynamic
      ? "The dynamic pass executes the application in the sandbox, which lets it reach its own backends over the network."
      : "The pipeline will unpack and statically analyse the artifact. No traffic is generated.",
    facts: [
      { label: "Artifact", value: artifactPath },
      { label: "Passes", value: staticOnly ? "Static only" : dynamic ? "Static, dynamic, signing, fusion" : "Static, signing, fusion" },
    ],
    notice: dynamic
      ? "Confirm you are authorized to analyse this artifact and to let it contact its backends."
      : undefined,
    noticeTone: "accent",
    confirmLabel: "Start pipeline",
  });
  if (!confirmed) return;

  // Pre-run sign-in prompt (time-saver): if the operator knows the app is
  // auth-gated, they can feed credentials up front or skip the dynamic pass.
  let effectiveDynamic = dynamic;
  const credentials: { key: string; value: string }[] = [];
  if (dynamic) {
    const choice = await choiceDialog({
      eyebrow: "Sign-in",
      title: "Does this app require sign-in?",
      message: "Login-gated apps make no API calls until you sign in. If you know this app needs an account, feed credentials now to crawl the post-auth surface — or skip the dynamic pass to save a wasted crawl. If unsure, try anyway and you'll be prompted if the crawler stalls at a login screen.",
      notice: "Credentials are used only to sign into the app during this run, held in memory, never saved, and redacted from captured traffic.",
      noticeTone: "accent",
      choices: [
        { key: "feed", label: "Feed credentials now", tone: "primary" },
        { key: "try", label: "Try anyway, prompt me if stuck" },
        { key: "skip", label: "Skip dynamic for this run", tone: "danger" },
      ],
    });
    if (choice === null) return;
    if (choice === "skip") {
      effectiveDynamic = false;
    } else if (choice === "feed") {
      const collected = await credentialDialog({
        eyebrow: "Sign-in",
        title: "Credentials for this crawl",
        message: "The crawler types these into the app's sign-in screen when it reaches it. Leave a field blank if it does not apply.",
        fields: [
          { name: "username", label: "Username or account", kind: "username", secret: false },
          { name: "email", label: "Email", kind: "email", secret: false },
          { name: "password", label: "Password", kind: "password", secret: true },
        ],
        confirmLabel: "Use these credentials",
        allowSkip: false,
      });
      if (collected === null) return;
      collected.values.forEach(([key, value]) => credentials.push({ key, value }));
    }
  }

  const runId = apkRunId?.value.trim() ?? "";
  const intakeRoot = apkIntakeRoot?.value.trim() ?? "";
  const payload: Record<string, unknown> = { artifactPath, dynamic: effectiveDynamic, staticOnly };
  if (runId !== "") payload.runId = runId;
  if (intakeRoot !== "") payload.intakeOutputRoot = intakeRoot;
  if (credentials.length > 0) payload.credentials = credentials;

  const button = document.querySelector<HTMLButtonElement>("#apk-run");
  try {
    await withBusy(button, "Starting…", async () => {
      const response = await fetch("/api/v1/pipeline", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      await requireOk(response, "pipeline could not start");
      const run = (await response.json()) as PipelineRun;
      renderPipeline(run);
      toast(`Pipeline started · run ${run.runId}`, "success");
      if (pipelinePoll !== undefined) window.clearInterval(pipelinePoll);
      pipelinePoll = window.setInterval(() => void refreshPipeline(), 1000);
    });
  } catch (error) {
    reportUnexpected(error, { id: "pipeline.start-failed", what: "The analysis pipeline could not start.", why: "", fix: "Check that the artifact path exists and is readable by the engine, then retry." });
  }
}

/* ==================================================================== *
 * 8. Unified API surface
 * ==================================================================== */

/** Whether the surface currently loaded was built from web capture or an APK. */
let surfaceSource: "app" | "web" = "web";

/** Activates the API-surface source section; the section that matches the loaded
 *  surface shows it, the other explains how to build one. */
function showSurfaceSection(section: "app" | "web"): void {
  document.querySelectorAll<HTMLElement>(".surface-section").forEach((tab) => {
    const on = tab.dataset.surfaceSection === section;
    tab.classList.toggle("is-active", on);
    tab.setAttribute("aria-selected", String(on));
  });
  if (surfaceView === null) return;
  if (section === surfaceSource) {
    void refreshStoredSurface();
  } else {
    surfaceView.innerHTML = stateBlock({
      icon: section === "app" ? "apk" : "web",
      title: section === "app" ? "No app surface in this session" : "No web surface in this session",
      body:
        section === "app"
          ? "Run an APK analysis to reconstruct an application's API surface from what it ships and does."
          : "Start a web session and capture traffic; the web surface builds live as you browse.",
    });
  }
}

function renderSurface(surface: SurfaceSummary): void {
  if (surfaceView === null) return;
  // Tag the surface by its source (web capture vs APK) and activate that section.
  surfaceSource = lastSessionStatus?.scope?.target?.target_type === "web.url" ? "web" : "app";
  document.querySelectorAll<HTMLElement>(".surface-section").forEach((tab) => {
    const on = tab.dataset.surfaceSection === surfaceSource;
    tab.classList.toggle("is-active", on);
    tab.setAttribute("aria-selected", String(on));
  });
  const coverage = surface.coverage;
  // Demote static-inferred candidates below dynamic-confirmed endpoints so the
  // tester reads the real (observed) surface first; a stable sort preserves the
  // original order within each group. Row indices are taken from this sorted
  // array so expand / send-to-resend stay aligned.
  const rank = (endpoint: SurfaceEndpoint): number => (endpoint.evidenceSource === "static_inferred" ? 1 : 0);
  lastSurfaceEndpoints = [...surface.endpoints]
    .map((endpoint, index) => ({ endpoint, index }))
    .sort((a, b) => rank(a.endpoint) - rank(b.endpoint) || a.index - b.index)
    .map((entry) => entry.endpoint);
  const endpointRows = lastSurfaceEndpoints.map((entry, index) => {
    const confidence = entry.minimumFactConfidence;
    const percent = confidence === null || confidence === undefined ? null : Math.round(confidence * 100);
    const band = percent === null ? "" : percent >= 80 ? " confidence--high" : percent < 50 ? " confidence--low" : "";
    const confidenceHtml = percent === null
      ? '<span class="t-subtle">unscored</span>'
      : `<span class="confidence${band}" title="Minimum supporting fact confidence"><span class="confidence__track"><span class="confidence__fill" style="width:${percent}%"></span></span>${percent}%</span>`;
    const method = entry.method.toUpperCase();
    // The row is a real button so it is keyboard-focusable and expands on
    // click/Enter; a right-click (contextmenu) offers send-to-resend/fuzzer,
    // matching Burp/Caido. The detail region fills lazily on first expand.
    return `<div class="endpoint-item" data-ep="${index}">
<button class="endpoint-row" type="button" data-ep-toggle="${index}" aria-expanded="false" title="Click to expand · right-click to send to resend or fuzzer">
<span class="endpoint-row__caret" data-icon="chevronRight" aria-hidden="true"></span>
<span class="list-row__method" data-method="${escapeHtml(method)}">${escapeHtml(method)}</span>
<span class="endpoint-row__path" title="${escapeHtml(entry.pathTemplate)}">${escapeHtml(entry.pathTemplate)}</span>
<span class="endpoint-row__meta">${evidenceChipHtml(entry)}${partyChipHtml(entry)}${confidenceHtml}<span class="badge">${entry.signerCount} signer${entry.signerCount === 1 ? "" : "s"}</span></span>
</button>
<div class="endpoint-detail" data-ep-detail="${index}" hidden></div>
</div>`;
  }).join("");

  const unconfirmed = Math.max(0, coverage.endpointCount - coverage.confirmedEndpointCount);
  surfaceView.innerHTML = `<div class="stack stack--loose">
<div class="metric-grid">
  <div class="metric"><span class="metric__value">${coverage.endpointCount}</span><span class="metric__label">endpoints</span></div>
  <div class="metric metric--success"><span class="metric__value">${coverage.confirmedEndpointCount}</span><span class="metric__label">confirmed</span></div>
  <div class="metric"><span class="metric__value">${coverage.inferredEndpointCount}</span><span class="metric__label">inferred</span></div>
  <div class="metric"><span class="metric__value">${coverage.staticOnlyEndpointCount}</span><span class="metric__label">static only</span></div>
  <div class="metric metric--accent"><span class="metric__value">${surface.signerCount}</span><span class="metric__label">signers</span></div>
</div>

<div class="notice ${coverage.openHandoffCount > 0 || unconfirmed > 0 ? "notice--caution" : "notice--success"}">
  <span class="notice__icon">${icon(coverage.openHandoffCount > 0 || unconfirmed > 0 ? "alert" : "check", { size: 18 })}</span>
  <div class="notice__body">
    <p class="notice__title">Honest coverage</p>
    <p>${unconfirmed} endpoint${unconfirmed === 1 ? "" : "s"} not confirmed by observation · ${coverage.resolvedHandoffCount} handoff${coverage.resolvedHandoffCount === 1 ? "" : "s"} resolved · ${coverage.openHandoffCount} still open. Unconfirmed entries are reported as such rather than presented as fact.</p>
  </div>
</div>

<article class="panel">
  <div class="panel__header">
    <div class="panel__heading">${icon("surface", { size: 16 })}<h2>Endpoints</h2></div>
    <span class="panel__hint">${surface.endpoints.length} listed</span>
  </div>
  <div class="panel__body panel__body--flush surface-endpoints">${endpointRows === "" ? stateBlock({ icon: "surface", title: "No endpoints were produced", body: "Run the APK pipeline or fuse captured web traffic to assemble a surface.", compact: true }) : endpointRows}</div>
</article>

<article class="panel">
  <div class="panel__header">
    <div class="panel__heading">${icon("info", { size: 16 })}<h2>Provenance</h2></div>
  </div>
  <div class="panel__body">
    <dl class="kv">
      <dt>Assembly run</dt><dd class="t-mono">${escapeHtml(surface.assemblyRunId === "" ? "—" : surface.assemblyRunId)}</dd>
      <dt>Schema</dt><dd class="t-mono">v${surface.schemaVersion}</dd>
      <dt>Signers</dt><dd>${surface.signerCount} recovered request signer${surface.signerCount === 1 ? "" : "s"}</dd>
    </dl>
  </div>
</article>

<article class="panel">
  <div class="panel__header">
    <div class="panel__heading">${icon("alert", { size: 16 })}<h2>Surface diagnostics</h2></div>
    <span class="panel__hint">${surface.diagnostics.length === 0 ? "none" : `${surface.diagnostics.length} reported`}</span>
  </div>
  <div class="panel__body panel__body--flush scroll-region">${diagnosticListHtml(surface.diagnostics, "The assembled surface reported no boundaries or warnings.")}</div>
</article>
</div>`;
  hydrateIcons(surfaceView);
  wireSurfaceEndpoints();
  surface.diagnostics.forEach(showDiagnostic);
}

/** Wires each surface endpoint row: click/Enter expands its request/response
 * detail; right-click opens the send-to-resend/fuzzer menu. */
function wireSurfaceEndpoints(): void {
  if (surfaceView === null) return;
  surfaceView.querySelectorAll<HTMLButtonElement>("[data-ep-toggle]").forEach((button) => {
    const index = Number(button.dataset.epToggle);
    button.addEventListener("click", () => toggleEndpointDetail(index, button));
    button.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      showEndpointMenu(event.clientX, event.clientY, index);
    });
  });
}

/** Expands or collapses an endpoint's request/response detail. */
function toggleEndpointDetail(index: number, button: HTMLButtonElement): void {
  const detailRegion = surfaceView?.querySelector<HTMLElement>(`[data-ep-detail="${index}"]`);
  const endpoint = lastSurfaceEndpoints[index];
  if (detailRegion === null || detailRegion === undefined || endpoint === undefined) return;
  const open = detailRegion.hidden;
  if (open && detailRegion.childElementCount === 0) detailRegion.innerHTML = endpointDetailHtml(endpoint, index);
  detailRegion.hidden = !open;
  button.setAttribute("aria-expanded", String(open));
  button.closest(".endpoint-item")?.classList.toggle("is-open", open);
  if (open) {
    detailRegion.querySelector("[data-ep-resend]")?.addEventListener("click", () => void sendEndpointToResend(index));
    detailRegion.querySelector("[data-ep-fuzzer]")?.addEventListener("click", () => sendEndpointToFuzzer(index));
  }
}

/** The expanded request/response essentials, side by side. */
function endpointDetailHtml(endpoint: SurfaceEndpoint, _index: number): string {
  const detail = endpoint.detail;
  const url = endpointUrl(endpoint);
  const headerList = (names: readonly string[]): string =>
    names.length === 0
      ? '<li class="t-subtle">none observed</li>'
      : names.map((name) => `<li class="t-mono">${escapeHtml(name)}</li>`).join("");
  const params = detail === undefined ? [] : [...detail.pathParams, ...detail.queryParams];
  const requestSide = `<section class="endpoint-detail__col">
  <p class="section-label">Request</p>
  <dl class="kv kv--tight"><dt>Method</dt><dd class="t-mono">${escapeHtml(endpoint.method.toUpperCase())}</dd><dt>URL</dt><dd class="t-mono" style="word-break:break-all">${escapeHtml(url)}</dd></dl>
  <p class="t-label t-small">Headers</p><ul class="endpoint-detail__headers">${headerList(detail?.requestHeaders ?? [])}</ul>
  ${params.length === 0 ? "" : `<p class="t-label t-small">Parameters</p><ul class="endpoint-detail__headers">${params.map((name) => `<li class="t-mono">${escapeHtml(name)}</li>`).join("")}</ul>`}
</section>`;
  const responses = detail?.responses ?? [];
  const responseSide = `<section class="endpoint-detail__col">
  <p class="section-label">Response</p>
  ${responses.length === 0
    ? '<p class="t-subtle t-small">No response observed for this endpoint.</p>'
    : responses.map((response) => `<div class="stack stack--tight"><div class="row"><span class="list-row__status" data-class="${statusClass(Number(response.status))}">${escapeHtml(response.status)}</span></div><p class="t-label t-small">Headers</p><ul class="endpoint-detail__headers">${headerList(response.headers)}</ul></div>`).join('<hr class="rule" />')}
</section>`;
  return `<div class="endpoint-detail__grid">${requestSide}${responseSide}</div>
<div class="row endpoint-detail__actions">
  <button class="btn btn--sm" type="button" data-ep-resend>${icon("send", { size: 14 })}<span>Resend</span></button>
  <button class="btn btn--sm" type="button" data-ep-fuzzer>${icon("discovery", { size: 14 })}<span>Fuzz</span></button>
</div>`;
}

/** Floating right-click menu: resend the endpoint or open it in the Fuzzer. */
function showEndpointMenu(x: number, y: number, index: number): void {
  document.querySelector(".context-menu")?.remove();
  const menu = document.createElement("div");
  menu.className = "context-menu";
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.innerHTML = `<button class="context-menu__item" type="button" data-ep-resend>${icon("send", { size: 14 })}<span>Resend</span></button><button class="context-menu__item" type="button" data-ep-fuzzer>${icon("discovery", { size: 14 })}<span>Fuzz</span></button>`;
  const close = (): void => {
    menu.remove();
    document.removeEventListener("click", close);
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (event: KeyboardEvent): void => { if (event.key === "Escape") close(); };
  menu.querySelector("[data-ep-resend]")?.addEventListener("click", () => { close(); void sendEndpointToResend(index); });
  menu.querySelector("[data-ep-fuzzer]")?.addEventListener("click", () => { close(); sendEndpointToFuzzer(index); });
  document.body.append(menu);
  // Keep the menu inside the viewport if opened near an edge.
  const rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) menu.style.left = `${Math.max(4, window.innerWidth - rect.width - 4)}px`;
  if (rect.bottom > window.innerHeight) menu.style.top = `${Math.max(4, window.innerHeight - rect.height - 4)}px`;
  setTimeout(() => { document.addEventListener("click", close); document.addEventListener("keydown", onKey); }, 0);
}

/** Skeleton request built from an endpoint's shape: the operator fills header
 * values and body in Resend or the Fuzzer. */
function endpointRequest(endpoint: SurfaceEndpoint): ResendRequest {
  const headers: [string, string][] = (endpoint.detail?.requestHeaders ?? []).map((name) => [name, ""]);
  return { method: endpoint.method.toUpperCase() || "GET", url: endpointUrl(endpoint), headers, body: null };
}

/** Creates a Resend context from a surface endpoint and opens it in the workbench. */
async function sendEndpointToResend(index: number): Promise<void> {
  const endpoint = lastSurfaceEndpoints[index];
  if (endpoint === undefined) return;
  try {
    const response = await fetch("/api/v1/workbench/resend", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: endpointRequest(endpoint) }) });
    await requireOk(response, "resend context unavailable");
    registerResend((await response.json()) as ResendContext);
    renderResend();
    showView("workbench");
    showWorkbenchTab("resend");
    toast(`Sent ${endpoint.method.toUpperCase()} ${endpoint.pathTemplate} to Resend`, "success");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "The endpoint could not be sent to Resend.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

/** Opens the Fuzzer in the workbench seeded from a surface endpoint. */
function sendEndpointToFuzzer(index: number): void {
  const endpoint = lastSurfaceEndpoints[index];
  if (endpoint === undefined) return;
  const request = endpointRequest(endpoint);
  selectedFuzzer = {
    id: "", tier: "ffuf", state: "draft",
    config: {
      baseRequest: request,
      positions: [{ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }],
      payloadSets: [{ name: "set 1", values: [] }],
      attackType: "sniper",
      matchFilter: { statuses: [], minSize: null, maxSize: null, contains: null, regex: null },
      concurrency: 5, ratePerSecond: 10, maxResults: 100, authPreflight: null, sequence: [],
    },
    results: [], diagnostics: [],
  };
  currentFuzzDraft = selectedFuzzer;
  renderFuzzer();
  renderFuzzList();
  showView("workbench");
  showWorkbenchTab("fuzz");
  toast(`Loaded ${endpoint.method.toUpperCase()} ${endpoint.pathTemplate} into Fuzz`, "success");
}

/* ==================================================================== *
 * 7c. Workbench tools — Live traffic / Resend (Repeater) / Fuzz (Intruder)
 * ==================================================================== */

/** The in-progress, not-yet-run Fuzz attack (its own list row until it starts). */
let currentFuzzDraft: FuzzerJob | null = null;

/** Switches the Workbench between its three tools; nothing remounts. */
function showWorkbenchTab(name: "live" | "resend" | "fuzz"): void {
  activeWorkbenchTab = name;
  document.querySelectorAll<HTMLElement>(".wb-tab").forEach((tab) => {
    const on = tab.dataset.wbtab === name;
    tab.classList.toggle("is-active", on);
    tab.setAttribute("aria-selected", String(on));
  });
  document.querySelectorAll<HTMLElement>(".wb-workspace").forEach((panel) => {
    panel.hidden = panel.dataset.wbpanel !== name;
  });
}

/** METHOD host/path label for a Resend/Fuzz queue row. */
function requestRowLabel(method: string, url: string): string {
  let host = url;
  let path = "";
  try {
    const parsed = new URL(url);
    host = parsed.host;
    path = parsed.pathname + parsed.search;
  } catch {
    /* relative/template url — show as-is */
  }
  const m = method.toUpperCase() || "GET";
  return `<span class="qrow__method" data-method="${escapeHtml(m)}">${escapeHtml(m)}</span><span class="qrow__target"><b>${escapeHtml(host)}</b>${escapeHtml(path)}</span>`;
}

function registerResend(ctx: ResendContext): void {
  resendContexts.set(ctx.id, ctx);
  selectedResend = ctx;
  renderResendList();
}

function renderResendList(): void {
  const list = document.getElementById("resend-list");
  const count = document.getElementById("resend-tab-count");
  if (list === null) return;
  const items = [...resendContexts.values()].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  if (count !== null) {
    count.textContent = String(items.length);
    count.hidden = items.length === 0;
  }
  if (items.length === 0) {
    list.innerHTML = stateBlock({ icon: "send", title: "Resend queue is empty", body: "Right-click a request in Live traffic or the API surface and choose Resend.", compact: true });
    return;
  }
  list.innerHTML = items
    .map((ctx) => {
      const last = ctx.history[ctx.history.length - 1]?.response?.status;
      const active = selectedResend?.id === ctx.id;
      return `<button class="qrow${active ? " is-active" : ""}" type="button" data-resend-id="${escapeHtml(ctx.id)}">${requestRowLabel(ctx.current.method, ctx.current.url)}<span class="qrow__status">${last === undefined ? "—" : last}</span></button>`;
    })
    .join("");
  list.querySelectorAll<HTMLElement>("[data-resend-id]").forEach((row) => {
    row.addEventListener("click", () => {
      const ctx = resendContexts.get(row.dataset.resendId ?? "");
      if (ctx !== undefined) {
        selectedResend = ctx;
        renderResend();
        renderResendList();
      }
    });
  });
}

async function refreshResendList(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/resend");
    if (!response.ok) return;
    const contexts = (await response.json()) as ResendContext[];
    resendContexts.clear();
    contexts.forEach((ctx) => resendContexts.set(ctx.id, ctx));
    if (selectedResend !== null) selectedResend = resendContexts.get(selectedResend.id) ?? selectedResend;
    renderResendList();
  } catch {
    /* the list is a convenience; the detail pane still holds the selection */
  }
}

/** Keeps the Fuzz queue in sync with the selected job's persisted state. */
function syncFuzzToList(): void {
  if (selectedFuzzer !== null && selectedFuzzer.id !== "") {
    fuzzerJobsList.set(selectedFuzzer.id, selectedFuzzer);
    if (currentFuzzDraft !== null && currentFuzzDraft.id === "") currentFuzzDraft = null;
  }
  renderFuzzList();
}

function renderFuzzList(): void {
  const list = document.getElementById("fuzz-list");
  const count = document.getElementById("fuzz-tab-count");
  if (list === null) return;
  const rows: { key: string; job: FuzzerJob }[] = [];
  if (currentFuzzDraft !== null) rows.push({ key: "draft", job: currentFuzzDraft });
  [...fuzzerJobsList.values()].forEach((job) => rows.push({ key: job.id, job }));
  if (count !== null) {
    count.textContent = String(rows.length);
    count.hidden = rows.length === 0;
  }
  if (rows.length === 0) {
    list.innerHTML = stateBlock({ icon: "discovery", title: "Fuzz queue is empty", body: "Right-click a request in Live traffic or the API surface and choose Fuzz.", compact: true });
    return;
  }
  list.innerHTML = rows
    .map(({ key, job }) => {
      const active = key === "draft" ? selectedFuzzer?.id === "" : selectedFuzzer?.id === job.id;
      const req = job.config.baseRequest;
      const state = key === "draft" ? "draft" : job.state;
      return `<button class="qrow${active ? " is-active" : ""}" type="button" data-fuzz-key="${escapeHtml(key)}">${requestRowLabel(req.method, req.url)}<span class="qrow__status">${escapeHtml(state)}</span></button>`;
    })
    .join("");
  list.querySelectorAll<HTMLElement>("[data-fuzz-key]").forEach((row) => {
    row.addEventListener("click", () => {
      const key = row.dataset.fuzzKey ?? "";
      const job = key === "draft" ? currentFuzzDraft : fuzzerJobsList.get(key);
      if (job !== null && job !== undefined) {
        selectedFuzzer = job;
        renderFuzzer();
        renderFuzzList();
      }
    });
  });
}

async function refreshFuzzList(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/fuzzer");
    if (!response.ok) return;
    const jobs = (await response.json()) as FuzzerJob[];
    fuzzerJobsList.clear();
    // The discovery job belongs to Web capture, not the Fuzz tool.
    jobs.filter((job) => job.id !== discoveryJob?.id).forEach((job) => fuzzerJobsList.set(job.id, job));
    renderFuzzList();
  } catch {
    /* optional */
  }
}

/** Filters the Live-traffic list to rows matching the search box. */
function applyFlowSearch(): void {
  const query = (document.querySelector<HTMLInputElement>("#flow-search")?.value ?? "").trim().toLowerCase();
  document.querySelectorAll<HTMLElement>("#flow-list .list-row").forEach((row) => {
    row.hidden = query !== "" && !row.textContent?.toLowerCase().includes(query);
  });
}

function initWorkbenchTools(): void {
  document.querySelectorAll<HTMLElement>(".wb-tab").forEach((tab) => {
    tab.addEventListener("click", () => showWorkbenchTab((tab.dataset.wbtab as "live" | "resend" | "fuzz") ?? "live"));
  });
  document.querySelector<HTMLInputElement>("#flow-search")?.addEventListener("input", applyFlowSearch);
  initWorkbenchSplitters();
  renderResendList();
  renderFuzzList();
}

/** Right-click menu on a Live-traffic row: Resend or Fuzz that request. */
function showFlowMenu(x: number, y: number, flowId: number): void {
  document.querySelector(".context-menu")?.remove();
  const menu = document.createElement("div");
  menu.className = "context-menu";
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.innerHTML = `<button class="context-menu__item" type="button" data-flow-resend>${icon("send", { size: 14 })}<span>Resend</span></button><button class="context-menu__item" type="button" data-flow-fuzz>${icon("discovery", { size: 14 })}<span>Fuzz</span></button>`;
  const close = (): void => {
    menu.remove();
    document.removeEventListener("click", close);
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape") close();
  };
  menu.querySelector("[data-flow-resend]")?.addEventListener("click", () => {
    close();
    void createResend(flowId);
  });
  menu.querySelector("[data-flow-fuzz]")?.addEventListener("click", () => {
    close();
    void selectFlow(flowId).then(() => openFuzzer(flowId));
  });
  document.body.append(menu);
  const rect = menu.getBoundingClientRect();
  if (rect.right > window.innerWidth) menu.style.left = `${Math.max(4, window.innerWidth - rect.width - 4)}px`;
  if (rect.bottom > window.innerHeight) menu.style.top = `${Math.max(4, window.innerHeight - rect.height - 4)}px`;
  setTimeout(() => {
    document.addEventListener("click", close);
    document.addEventListener("keydown", onKey);
  }, 0);
}

/** Drag-resize the list|detail split in each Workbench tool (30–70%). */
function initWorkbenchSplitters(): void {
  document.querySelectorAll<HTMLElement>(".wb-split__gutter").forEach((gutter) => {
    const split = gutter.closest<HTMLElement>(".wb-split");
    if (split === null) return;
    const setRatio = (ratio: number): void => {
      const clamped = Math.max(0.3, Math.min(0.7, ratio));
      split.style.setProperty("--wb-list", `${(clamped * 100).toFixed(1)}%`);
    };
    gutter.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      gutter.setPointerCapture(event.pointerId);
      const move = (e: PointerEvent): void => {
        const rect = split.getBoundingClientRect();
        setRatio((e.clientX - rect.left) / rect.width);
      };
      const up = (): void => {
        gutter.releasePointerCapture(event.pointerId);
        gutter.removeEventListener("pointermove", move);
        gutter.removeEventListener("pointerup", up);
      };
      gutter.addEventListener("pointermove", move);
      gutter.addEventListener("pointerup", up);
    });
    gutter.addEventListener("dblclick", () => setRatio(0.5));
    gutter.addEventListener("keydown", (event) => {
      const current = parseFloat(getComputedStyle(split).getPropertyValue("--wb-list")) || 50;
      if (event.key === "ArrowLeft") { setRatio((current - 4) / 100); event.preventDefault(); }
      else if (event.key === "ArrowRight") { setRatio((current + 4) / 100); event.preventDefault(); }
    });
  });
}

function renderSurfaceEmpty(): void {
  if (surfaceView === null) return;
  surfaceView.innerHTML = stateBlock({
    icon: "surface",
    title: "No surface assembled yet",
    body: "Run the APK pipeline to completion, or capture web traffic and fuse it. The assembled surface, its coverage, and its provenance appear here.",
  });
}

/** Header names that are transport/CDN/date noise, not part of the API's own
 * contract — hidden from the endpoint detail so only meaningful headers
 * (content-type, authorization, api keys, cookies, …) show, per the "no
 * x-powered-by bs" ask. */
const NOISE_HEADERS = new Set([
  "date", "server", "connection", "keep-alive", "content-length", "content-encoding",
  "transfer-encoding", "vary", "via", "age", "x-powered-by", "x-aspnet-version",
  "x-cache", "x-served-by", "x-timer", "cf-ray", "cf-cache-status", "alt-svc",
  "strict-transport-security", "report-to", "nel", "x-amzn-requestid", "x-amz-cf-id",
  "x-amz-cf-pop", "expect-ct", "accept-ranges", "etag", "last-modified", "x-frame-options",
]);

function meaningfulHeaders(names: readonly string[]): string[] {
  return names.filter((name) => !NOISE_HEADERS.has(name.toLowerCase()));
}

/** Resolves a fused field object to its selected candidate value. */
function resolveFieldValue(field: unknown): string | null {
  const record = field as Record<string, unknown> | null | undefined;
  if (record === null || record === undefined) return null;
  const candidates = Array.isArray(record.candidates) ? (record.candidates as Record<string, unknown>[]) : [];
  const selected = (record.resolution as Record<string, unknown> | undefined)?.selected;
  const chosen = candidates.find((candidate) => candidate.id === selected) ?? candidates[0];
  const raw = chosen?.value;
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "object") {
    const template = (raw as Record<string, unknown>).template;
    return typeof template === "string" ? template : null;
  }
  return String(raw);
}

function fieldNames(list: unknown): string[] {
  return Array.isArray(list)
    ? list.map((item) => String((item as Record<string, unknown>).name ?? "")).filter((name) => name !== "")
    : [];
}

function extractEndpointDetail(endpoint: Record<string, unknown>): EndpointDetail {
  const responses = Array.isArray(endpoint.responses) ? (endpoint.responses as Record<string, unknown>[]) : [];
  return {
    baseUrl: resolveFieldValue(endpoint.base_url),
    requestHeaders: meaningfulHeaders(fieldNames(endpoint.headers)),
    queryParams: fieldNames(endpoint.query_parameters),
    pathParams: fieldNames(endpoint.path_parameters),
    responses: responses.map((response) => {
      const selector = response.selector as Record<string, unknown> | undefined;
      return {
        status: String(selector?.value ?? selector?.kind ?? "?"),
        headers: meaningfulHeaders(fieldNames(response.headers)),
      };
    }),
  };
}

/** Builds an absolute URL for an endpoint from its resolved base host + template. */
function endpointUrl(endpoint: SurfaceEndpoint): string {
  const base = endpoint.detail?.baseUrl ?? endpoint.baseUrl ?? "";
  const path = endpoint.pathTemplate.startsWith("/") ? endpoint.pathTemplate : `/${endpoint.pathTemplate}`;
  if (base === "") return path;
  if (base.startsWith("http://") || base.startsWith("https://")) return `${base.replace(/\/$/, "")}${path}`;
  return `https://${base}${path}`;
}

/** Well-known third-party SDK / analytics / tracker / payment host suffixes.
 * Mirrors the workbench's server-side list (engine-shell pipeline). A host ending
 * in one of these is external to the app's own backend — a labeling aid the tester
 * uses to tell the app's own API apart from the SDKs and trackers it also calls.
 * Every endpoint is still shown regardless; this only sets the chip. */
const THIRD_PARTY_HOST_SUFFIXES = [
  "facebook.com", "fbcdn.net", "google.com", "googleapis.com", "google-analytics.com",
  "googletagmanager.com", "gstatic.com", "doubleclick.net", "crashlytics.com",
  "app-measurement.com", "firebaseio.com", "clarity.ms", "appsflyer.com", "adjust.com",
  "branch.io", "sentry.io", "bugsnag.com", "mixpanel.com", "amplitude.com", "segment.io",
  "segment.com", "onesignal.com", "cloudflareinsights.com", "razorpay.com", "juspay.in",
  "cashfree.com", "phonepe.com", "paytm.in",
];

/** Extracts the bare host from an endpoint's base URL (scheme/port/path stripped). */
function endpointHost(endpoint: SurfaceEndpoint): string {
  const base = (endpoint.detail?.baseUrl ?? endpoint.baseUrl ?? "").trim();
  if (base === "") return "";
  const afterScheme = base.includes("://") ? base.slice(base.indexOf("://") + 3) : base;
  const authority = afterScheme.split(/[/?#]/)[0] ?? "";
  const hostPort = authority.includes("@") ? authority.slice(authority.indexOf("@") + 1) : authority;
  return hostPort.replace(/:\d+$/, "").replace(/\.$/, "").toLowerCase();
}

/** First- vs third-party label for an endpoint's host. Third-party when the host
 * matches a known SDK/tracker suffix; otherwise treated as the app's own surface.
 * Returns null when there is no host to classify (nothing to show). */
function endpointParty(endpoint: SurfaceEndpoint): "first" | "third" | null {
  const host = endpointHost(endpoint);
  if (host === "") return null;
  const isThird = THIRD_PARTY_HOST_SUFFIXES.some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
  return isThird ? "third" : "first";
}

/** Renders the confirmed/inferred evidence chip: "confirmed" when the app was
 * observed hitting the endpoint dynamically, "inferred" when it is a static-only
 * candidate (e.g. a bundled SDK base not observed being hit) — so an unconfirmed
 * candidate is never presented as confirmed surface. */
function evidenceChipHtml(endpoint: SurfaceEndpoint): string {
  const source = endpoint.evidenceSource;
  if (source === "confirmed") {
    return `<span class="party-chip party-chip--confirmed" title="Observed being hit in dynamic capture">confirmed</span>`;
  }
  if (source === "static_inferred") {
    return `<span class="party-chip party-chip--inferred" title="Static-inferred candidate — recovered from the app's code but not observed being hit. Treat as a lead, not a confirmed endpoint.">inferred</span>`;
  }
  return "";
}

/** Renders the first/third-party chip for an endpoint row, or "" when unknown. */
function partyChipHtml(endpoint: SurfaceEndpoint): string {
  const party = endpointParty(endpoint);
  if (party === null) return "";
  const host = escapeHtml(endpointHost(endpoint));
  return party === "third"
    ? `<span class="party-chip party-chip--third" title="Third-party SDK / analytics / tracker host the app calls (${host}) — real surface, but not the app's own backend">3rd party</span>`
    : `<span class="party-chip party-chip--first" title="The app's own backend host (${host})">1st party</span>`;
}

function normalizeFusedSurface(raw: unknown): SurfaceSummary {
  const value = raw as Record<string, unknown>;
  if (value.coverage !== null && value.coverage !== undefined && Array.isArray(value.endpoints)) return value as unknown as SurfaceSummary;
  const endpoints = Array.isArray(value.endpoints) ? value.endpoints.map((rawEndpoint) => {
    const entry = rawEndpoint as Record<string, unknown>;
    const endpoint = (entry.endpoint ?? entry) as Record<string, unknown>;
    const identity = (endpoint.identity ?? endpoint) as Record<string, unknown>;
    const facts = Array.isArray(entry.fact_confidence) ? entry.fact_confidence : [];
    const scores = facts.map((fact) => Number((fact as Record<string, unknown>).score)).filter(Number.isFinite);
    // Observed = at least one fact traces to dynamic capture (the app was seen
    // hitting it); otherwise it is a static-only inferred candidate.
    const observed = facts.some((fact) => {
      const sources = (fact as Record<string, unknown>).sources;
      return Array.isArray(sources) && sources.includes("dynamic_capture");
    });
    const detail = extractEndpointDetail(endpoint);
    return {
      method: String(identity.method ?? ""),
      pathTemplate: String(identity.path_template ?? identity.pathTemplate ?? ""),
      baseUrl: detail.baseUrl,
      evidenceSource: observed ? "confirmed" : "static_inferred",
      minimumFactConfidence: scores.length === 0 ? undefined : Math.min(...scores),
      signerCount: Array.isArray(entry.signers) ? entry.signers.length : 0,
      detail,
    };
  }) : [];
  const confidence = (value.confidence ?? {}) as Record<string, unknown>;
  const rawCoverage = (confidence.coverage ?? {}) as Record<string, unknown>;
  const number = (snake: string, camel: string, fallback: number): number => Number(rawCoverage[snake] ?? rawCoverage[camel] ?? fallback);
  return {
    schemaVersion: Number(value.schema_version ?? value.schemaVersion ?? 0),
    assemblyRunId: String(value.assembly_run_id ?? value.assemblyRunId ?? ""),
    endpoints,
    coverage: {
      endpointCount: number("endpoint_count", "endpointCount", endpoints.length),
      confirmedEndpointCount: number("confirmed_endpoint_count", "confirmedEndpointCount", 0),
      inferredEndpointCount: number("inferred_endpoint_count", "inferredEndpointCount", endpoints.length),
      staticOnlyEndpointCount: number("static_only_endpoint_count", "staticOnlyEndpointCount", 0),
      openHandoffCount: number("open_handoff_count", "openHandoffCount", 0),
      resolvedHandoffCount: number("resolved_handoff_count", "resolvedHandoffCount", 0),
    },
    signerCount: Array.isArray((value.surface as Record<string, unknown> | undefined)?.signers) ? ((value.surface as Record<string, unknown>).signers as unknown[]).length : 0,
    diagnostics: Array.isArray(value.diagnostics) ? value.diagnostics as Diagnostic[] : [],
  };
}

async function refreshPipeline(): Promise<void> {
  try {
    const response = await fetch("/api/v1/pipeline");
    if (response.status === 404) {
      // No analysis run exists in this session yet. That is the normal empty
      // state — not an error the operator can act on — so render it plainly and
      // stop polling rather than surfacing a "run not found" diagnostic on every
      // clean boot. A real run installs its own poll when it starts.
      renderPipelineEmpty();
      if (pipelinePoll !== undefined) {
        window.clearInterval(pipelinePoll);
        pipelinePoll = undefined;
      }
      return;
    }
    if (!response.ok) {
      await requireOk(response, "pipeline status unavailable");
      return;
    }
    const run = (await response.json()) as PipelineRun;
    renderPipeline(run);
    if (run.surfaceAvailable || run.status === "completed") {
      const surfaceResponse = await fetch("/api/v1/pipeline/" + encodeURIComponent(run.runId) + "/surface-summary");
      if (surfaceResponse.ok) renderSurface((await surfaceResponse.json()) as SurfaceSummary);
      else await requireOk(surfaceResponse, "pipeline surface unavailable");
    }
    if (run.status !== "running" && pipelinePoll !== undefined) {
      window.clearInterval(pipelinePoll);
      pipelinePoll = undefined;
      // A finished run commits the session's scope and counts (a completed APK
      // analysis declares its scope at fusion). Refresh the session once so the
      // title-bar scope pill and the session metrics reflect it without waiting
      // for the operator to visit the Session surface.
      void refreshSession();
    }
  } catch (error) {
    if (!(error instanceof ApiRequestError) && !String(error).includes("pipeline.run-not-found")) showDiagnostic({ id: "pipeline.status-unavailable", what: "Analysis status could not be loaded.", why: String(error), fix: "Check the local API and active session, then refresh the workbench." });
  }
}

async function refreshStoredSurface(): Promise<void> {
  try {
    const response = await fetch("/api/v1/surface");
    if (response.ok) renderSurface(normalizeFusedSurface(await response.json()));
  } catch {
    // Surface availability is optional while a session is still being built.
  }
}

/* ==================================================================== *
 * Live transport
 * ==================================================================== */

/**
 * Fetches a currently-valid operator token. On a reconnect the previous token
 * may be stale (the engine was restarted, so its per-run token changed), so the
 * token is re-read rather than reused.
 */
async function currentToken(): Promise<string | null> {
  try {
    const response = await fetch("/api/v1/workbench/session");
    if (!response.ok) return null;
    return ((await response.json()) as WorkbenchSession).authToken;
  } catch {
    return null;
  }
}

/**
 * Re-establishes the live channels after a drop, with capped exponential
 * backoff. A desktop app must survive an engine restart, a machine sleep, or a
 * transient socket blip without the operator reloading — the channels come back
 * on their own and the status bar narrates the wait honestly.
 */
function scheduleReconnect(): void {
  if (reconnectTimer !== undefined) return;
  setStatus("Reconnecting to the local engine…", "working");
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = undefined;
    void currentToken().then((token) => {
      if (token === null) {
        reconnectDelay = Math.min(reconnectDelay * 2, 15_000);
        scheduleReconnect();
        return;
      }
      connect({ authToken: token, interceptEnabled: false });
    });
  }, reconnectDelay);
}

function connect(session: WorkbenchSession): void {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  // Drop any prior sockets so a reconnect never leaks a half-open channel.
  try {
    control?.close();
  } catch {
    /* already closed */
  }
  try {
    telemetry?.close();
  } catch {
    /* already closed */
  }
  control = new WebSocket(`${scheme}://${location.host}/api/v1/workbench/ws/control?token=${encodeURIComponent(session.authToken)}`);
  telemetry = new WebSocket(`${scheme}://${location.host}/api/v1/workbench/ws/telemetry?token=${encodeURIComponent(session.authToken)}`);
  control.onopen = () => {
    reconnectDelay = 1000;
    setStatus("Live control connected", "ready");
  };
  control.onclose = () => {
    setStatus("Control channel closed", "unavailable");
    scheduleReconnect();
  };
  control.onmessage = (event) => {
    const message = JSON.parse(event.data) as { type?: string; diagnostic?: Diagnostic };
    if (message.diagnostic !== undefined) showDiagnostic(message.diagnostic);
  };
  telemetry.onmessage = (event) => {
    const update = JSON.parse(event.data) as LiveUpdate;
    update.flows.forEach((flow) => flows.set(flow.id, flow));
    update.diagnostics.forEach(showDiagnostic);
    (update.prompts ?? []).forEach((prompt) => void handleCredentialPrompt(prompt));
    renderFlows();
  };
  telemetry.onclose = () => scheduleReconnect();
}

const handledPrompts = new Set<number>();

/**
 * Handles a live credential prompt raised mid-crawl by the engine. Opens a
 * masked credential dialog and returns the operator's answer over the control
 * channel. Values are held only for the length of the send.
 */
async function handleCredentialPrompt(prompt: CredentialPromptMsg): Promise<void> {
  if (handledPrompts.has(prompt.id)) return;
  handledPrompts.add(prompt.id);
  const isOtp = prompt.reason === "otp";
  const result = await credentialDialog({
    eyebrow: isOtp ? "One-time code" : "Sign in to continue",
    title: isOtp ? "Enter the verification code" : "The app is asking you to sign in",
    message: isOtp
      ? `The crawler reached a verification step (${prompt.screenSummary}). Enter the code sent to your device so it can continue.`
      : `The crawler stalled at a sign-in screen (${prompt.screenSummary}). Provide credentials to crawl the post-auth surface, or continue without.`,
    fields: [...prompt.fields],
    confirmLabel: isOtp ? "Submit code" : "Sign in",
    allowSkip: true,
  });
  if (result === null || result.skip) {
    sendControl({ type: "answer_prompt", id: prompt.id, skip: true, values: [] });
  } else {
    sendControl({ type: "answer_prompt", id: prompt.id, skip: false, values: result.values });
  }
}

function editAction(action: "forward" | "drop" | "forward_modified"): void {
  if (selectedFlow === null) return;
  // The backend only accepts decisions for genuinely held flows; guard here so
  // the control doesn't look functional on a flow that was never paused.
  if (!pending.has(selectedFlow.summary.id)) {
    showDiagnostic({ id: "proxy.live-desync", what: "This request is not held.", why: "Forward, modify, and drop apply only to requests currently paused by intercept.", fix: "Enable intercept and wait for a matching request to pause in the queue, then decide." });
    return;
  }
  const message: Record<string, unknown> = { type: "decide", flow_id: selectedFlow.summary.id, action };
  if (action === "forward_modified") {
    message.method = methodInput?.value ?? "GET";
    message.headers = parseHeaders(headersInput?.value ?? "");
    message.body = [...new TextEncoder().encode(bodyInput?.value ?? "")];
  }
  sendControl(message);
}

/* ==================================================================== *
 * 5. Web session and capture browser
 * ==================================================================== */

async function startWebSession(): Promise<void> {
  const target = webTarget?.value.trim() ?? "";
  if (!target || !webAuthorize?.checked) {
    showDiagnostic({ id: "web.authorization-required", what: "Web authorization is required.", why: "Starting a web session actively establishes a target scope.", fix: "Enter the target and affirm that you are authorized to test it." });
    if (target === "") webTarget?.focus();
    else webAuthorize?.focus();
    return;
  }
  // Starting a web session replaces the active session. The engine saves the
  // current one to its artifact first, but the operator should know the active
  // context (and its captured work) is being switched out.
  const current = lastSessionStatus;
  const hasWork = current !== null && (current.flowCount > 0 || current.resendCount > 0 || current.fuzzerCount > 0 || current.scopeConfigured);
  if (hasWork && current !== null) {
    const confirmed = await confirmDialog({
      eyebrow: "Replace active session",
      title: "Start a new web session",
      message: "This replaces the active session. The current session is saved to its artifact first, then the active context switches to the new web target.",
      facts: [
        { label: "Current session", value: current.sessionId },
        { label: "Saved to", value: current.artifactPath },
        { label: "New target", value: target },
      ],
      notice: "The replaced session stays on disk but is no longer the active one.",
      noticeTone: "caution",
      confirmLabel: "Replace session",
      tone: "danger",
    });
    if (!confirmed) return;
  }
  const button = document.querySelector<HTMLButtonElement>("#web-start");
  const response = await withBusy(button, "Starting…", () =>
    fetch("/api/v1/session/web", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ target, authorizationAffirmed: true }) }),
  );
  try {
    await requireOk(response, "web session could not start");
    const status = await response.json() as { sessionId: string };
    if (webSessionStatus !== null) webSessionStatus.textContent = `Session ${status.sessionId} · scope set to ${target}.`;
    if (webAuthorization !== null) webAuthorization.hidden = true;
    if (webAuthorizedNote !== null) webAuthorizedNote.hidden = false;
    if (webSessionBadge !== null) webSessionBadge.textContent = "active";
    toast("Web session started", "success");
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "web.session-start-failed", what: "Web session could not start.", why: "", fix: "Check the target URL and local API." });
  }
}

function renderBrowserState(status: BrowserLaunchStatus | null, stopped = false): void {
  latestBrowser = status;
  if (browserState !== null) {
    if (stopped) {
      browserState.className = "notice";
      browserState.innerHTML = `<span class="notice__icon">${icon("info", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Browser stopped</p><p>Disposable browser state was removed. Captured flows remain in the session.</p></div>`;
    } else if (status === null || !status.running) {
      browserState.className = "notice";
      browserState.innerHTML = `<span class="notice__icon">${icon("info", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Browser not running</p><p>Start a session first, then launch the capture browser.</p></div>`;
    } else {
      browserState.className = "notice notice--success";
      browserState.innerHTML = `<span class="notice__icon">${icon("check", { size: 18 })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(status.browser ?? "Browser")} running</p><p>Capturing traffic for ${escapeHtml(status.target ?? "the session target")}${status.pid === null || status.pid === undefined ? "" : ` · pid ${status.pid}`}.</p></div>`;
    }
  }
  renderCaptureHealth();
}

/**
 * The meaningful capture-health signal now that web capture uses the bundled
 * Chromium with blanket certificate trust: is the MITM proxy up, is the browser
 * actually routed through it, and is traffic arriving? This makes "HTTPS
 * capture silently yields nothing" diagnosable rather than invisible.
 */
function renderCaptureHealth(): void {
  if (captureHealth === null) return;
  const backend = latestHealth?.backend;
  if (latestHealth === null && (latestBrowser === null || !latestBrowser.running)) { captureHealth.innerHTML = ""; return; }
  const proxyOk = latestHealth === null ? null : latestHealth.proxyRunning && (backend?.hudsuckerAvailable ?? false);
  const running = latestBrowser?.running === true;
  const routed = running ? (latestBrowser?.cdpConnected ?? false) : null;
  const flowCount = flows.size;
  const line = (ok: boolean | null, label: string, detail: string): string => {
    const tone = ok === null ? "" : ok ? "badge--success" : "badge--caution";
    const word = ok === null ? "unknown" : ok ? "ok" : "check";
    return `<div class="stack stack--tight"><div class="row"><span class="t-small">${escapeHtml(label)}</span><span class="spacer"></span><span class="badge ${tone}">${word}</span></div><p class="t-small t-subtle">${escapeHtml(detail)}</p></div>`;
  };
  const proxyDetail = latestHealth === null
    ? "Proxy health not yet reported."
    : proxyOk
      ? "Intercepting via the embedded hudsucker proxy."
      : "The session proxy is not confirmed healthy; HTTPS may not be intercepted.";
  const browserDetail = !running
    ? "Capture browser is not running."
    : routed === true
      ? "Routed through the session proxy (CDP connected)."
      : "Running but not confirmed routed through the proxy.";
  const trafficDetail = !running
    ? "Launch the capture browser and browse the target."
    : flowCount > 0
      ? `${flowCount} flow${flowCount === 1 ? "" : "s"} captured so far.`
      : "Browser is up but no traffic captured yet. Browse the target; if pages load but nothing appears here, TLS is not being intercepted.";
  captureHealth.innerHTML = `<div class="stack stack--tight" style="border:1px solid var(--border);border-radius:var(--radius-2);padding:var(--space-3)">
<p class="section-label">Capture health</p>
${line(proxyOk, "Session proxy", proxyDetail)}
${line(running ? routed : null, "Capture browser", browserDetail)}
${line(!running ? null : flowCount > 0, "Captured traffic", trafficDetail)}
</div>`;
}

async function refreshHealth(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/health");
    if (!response.ok) return;
    latestHealth = (await response.json()) as WorkbenchHealth;
    renderCaptureHealth();
  } catch {
    // Health is advisory; the boot path already reports hard failures.
  }
}

async function refreshBrowserStatus(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/browser");
    if (!response.ok) return;
    const status = (await response.json()) as BrowserLaunchStatus;
    renderBrowserState(status);
    if (status.running && browserPoll === undefined) browserPoll = window.setInterval(() => void refreshBrowserStatus(), 2000);
    if (!status.running && browserPoll !== undefined) { window.clearInterval(browserPoll); browserPoll = undefined; }
    // Build the API surface live while capturing, so the operator never has to
    // hit "Fuse" to see what has been observed — it is already assembled.
    if (status.running) {
      autoFuseTick += 1;
      if (autoFuseTick % 3 === 0) void autoFuseWebTraffic();
    }
  } catch {
    // Transient; the next poll re-reads the real process state.
  }
}

async function launchCaptureBrowser(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#capture-launch");
  const response = await withBusy(button, "Launching…", () => fetch("/api/v1/workbench/browser", { method: "POST" }));
  try {
    await requireOk(response, "capture browser could not launch");
    const status = await response.json() as BrowserLaunchStatus;
    renderBrowserState(status);
    if (webSessionStatus !== null && status.target !== null && status.target !== undefined) webSessionStatus.textContent = `${status.browser ?? "Browser"} running · ${status.target}`;
    toast("Capture browser launched", "success");
    // Poll so "Browser running" reflects reality after a manual window close.
    if (browserPoll !== undefined) window.clearInterval(browserPoll);
    browserPoll = window.setInterval(() => void refreshBrowserStatus(), 2000);
  } catch (error) {
    reportUnexpected(error, { id: "web.browser-launch-failed", what: "Capture browser could not launch.", why: "", fix: "Start an active web session and verify the proxy health." });
  }
}

async function stopCaptureBrowser(): Promise<void> {
  if (browserPoll !== undefined) { window.clearInterval(browserPoll); browserPoll = undefined; }
  await fetch("/api/v1/workbench/browser", { method: "DELETE" });
  renderBrowserState(null, true);
  toast("Capture browser stopped");
}

async function importHar(file: File): Promise<void> {
  try {
    const text = await file.text();
    const response = await fetch("/api/v1/workbench/har", { method: "POST", headers: { "content-type": "application/json" }, body: text });
    await requireOk(response, "HAR import failed");
    const imported = (await response.json()) as number;
    toast(`Imported ${imported} flow${imported === 1 ? "" : "s"} from ${file.name}`, "success");
    // Fold the imported flows into the live list immediately.
    try {
      const flowsResponse = await fetch("/api/v1/workbench/flows");
      if (flowsResponse.ok) { ((await flowsResponse.json()) as FlowSummary[]).forEach((flow) => flows.set(flow.id, flow)); renderFlows(); }
    } catch { /* the telemetry stream also carries new flows */ }
  } catch (error) {
    reportUnexpected(error, { id: "proxy.har-import-failed", what: "The HAR file could not be imported.", why: "", fix: "Confirm the file is a valid HAR export and that a session is active, then retry." });
  }
}

async function exportHar(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/har");
    await requireOk(response, "HAR export failed");
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `apiaxess-session-${new Date().toISOString().replace(/[:.]/g, "-")}.har`;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    toast("Session traffic exported as HAR", "success");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.har-export-failed", what: "The session HAR could not be exported.", why: "", fix: "Confirm a session is active with captured traffic, then retry." });
  }
}

/* ==================================================================== *
 * 6. Discovery
 * ==================================================================== */

/** An uploaded custom wordlist (.txt/.md), sent as `custom` on the request. */
let customWordlist: string[] | null = null;

function discoveryRequestBody(confirmed = false): string {
  const wordlist = discoveryWordlist?.value ?? "quick";
  const body: Record<string, unknown> = { kind: discoveryKind?.value ?? "directory", wordlist };
  if (wordlist === "custom" && customWordlist !== null) body.custom = customWordlist;
  if (confirmed) body.confirmed = true;
  return JSON.stringify(body);
}

interface WordlistInfo {
  id: string;
  label: string;
  kind: string;
  count: number;
  source: string;
}

/** Populates the discovery wordlist picker from the bundled catalogue, grouped
 *  by kind, plus any uploaded custom list. */
async function populateWordlists(): Promise<void> {
  if (discoveryWordlist === null) return;
  let catalogue: WordlistInfo[] = [];
  try {
    const response = await fetch("/api/v1/discovery/wordlists");
    if (response.ok) catalogue = (await response.json()) as WordlistInfo[];
  } catch {
    /* fall back to the built-ins below */
  }
  const previous = discoveryWordlist.value;
  const group = (kind: string, label: string): string => {
    const items = catalogue.filter((w) => w.kind === kind);
    if (items.length === 0) return "";
    return `<optgroup label="${escapeHtml(label)}">${items.map((w) => `<option value="${escapeHtml(w.id)}">${escapeHtml(w.label)} · ${w.count.toLocaleString()}</option>`).join("")}</optgroup>`;
  };
  const custom = customWordlist === null ? "" : `<optgroup label="Custom"><option value="custom">Uploaded list · ${customWordlist.length.toLocaleString()}</option></optgroup>`;
  const built =
    catalogue.length === 0
      ? `<option value="quick">Quick sample · 8</option><option value="medium">Medium · 18</option><option value="large">APIaxess curated</option>`
      : group("directory", "Directories / paths") + group("subdomain", "Subdomains");
  discoveryWordlist.innerHTML = built + custom;
  discoveryWordlist.value = customWordlist !== null ? "custom" : previous !== "" && Array.from(discoveryWordlist.options).some((o) => o.value === previous) ? previous : "common";
  updateWordlistHint();
}

function updateWordlistHint(): void {
  const hint = document.querySelector<HTMLElement>("#discovery-wordlist-hint");
  if (hint === null || discoveryWordlist === null) return;
  const opt = discoveryWordlist.selectedOptions[0];
  hint.textContent = discoveryWordlist.value === "custom" ? "Custom list uploaded — Estimate to see the request count." : `${opt?.textContent ?? ""}. Upload your own with the button, or pick a bundled SecLists list.`;
}

/** Reads an uploaded .txt/.md wordlist into the custom list and selects it. */
function loadCustomWordlist(file: File): void {
  const reader = new FileReader();
  reader.onload = (): void => {
    const text = typeof reader.result === "string" ? reader.result : "";
    const values = text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("#"));
    if (values.length === 0) {
      showDiagnostic({ id: "discovery.wordlist-empty", what: "The uploaded wordlist was empty.", why: "No non-comment, non-blank lines were found in the file.", fix: "Upload a .txt or .md file with one entry per line." });
      return;
    }
    customWordlist = values;
    void populateWordlists();
    toast(`Loaded ${values.length.toLocaleString()} entries from ${file.name}`, "success");
  };
  reader.readAsText(file);
}

function renderDiscoveryEstimate(estimate: DiscoveryEstimate): void {
  lastDiscoveryEstimate = estimate;
  if (discoveryEstimateView === null) return;
  discoveryEstimateView.innerHTML = `<div class="discovery-estimate">
<div class="discovery-estimate__item"><span class="metric__label">Target</span><span class="t-mono t-small">${escapeHtml(estimate.target)}</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Requests</span><span class="discovery-estimate__value">${estimate.requestCount.toLocaleString()}</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Rate</span><span class="discovery-estimate__value">${estimate.ratePerSecond}/s</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Duration</span><span class="discovery-estimate__value">${escapeHtml(estimate.estimatedLabel)}</span></div>
</div>`;
}

async function estimateDiscovery(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#discovery-estimate");
  const response = await withBusy(button, "Estimating…", () =>
    fetch("/api/v1/discovery/estimate", { method: "POST", headers: { "content-type": "application/json" }, body: discoveryRequestBody() }),
  );
  try {
    await requireOk(response, "discovery estimate unavailable");
    const estimate = await response.json() as DiscoveryEstimate;
    renderDiscoveryEstimate(estimate);
    if (discoveryStatus !== null) discoveryStatus.textContent = `${estimate.requestCount} requests · ${estimate.estimatedLabel} at ${estimate.ratePerSecond}/s`;
  } catch (error) {
    reportUnexpected(error, { id: "web.discovery-estimate-failed", what: "Discovery estimate unavailable.", why: "", fix: "Check the active web session and selected wordlist." });
  }
}

async function runDiscovery(): Promise<void> {
  const estimateResponse = await fetch("/api/v1/discovery/estimate", { method: "POST", headers: { "content-type": "application/json" }, body: discoveryRequestBody() });
  if (!estimateResponse.ok) { await requireOk(estimateResponse, "discovery estimate unavailable"); return; }
  const estimate = await estimateResponse.json() as DiscoveryEstimate;
  renderDiscoveryEstimate(estimate);

  // Same gate as before, in the product's own voice: nothing is probed until
  // the operator confirms the scale of what is about to be sent.
  const confirmed = await confirmDialog({
    eyebrow: "Confirm before run",
    title: "Run active discovery",
    message: `This actively probes ${estimate.target}. Requests are sent to the live target.`,
    facts: [
      { label: "Target", value: estimate.target },
      { label: "Requests", value: estimate.requestCount.toLocaleString() },
      { label: "Rate", value: `${estimate.ratePerSecond}/s` },
      { label: "Estimated", value: estimate.estimatedLabel },
    ],
    notice: "Confirm you are authorized to test this target.",
    noticeTone: "caution",
    confirmLabel: "Run discovery",
  });
  if (!confirmed) return;

  try {
    const response = await fetch("/api/v1/discovery/run", { method: "POST", headers: { "content-type": "application/json" }, body: discoveryRequestBody(true) });
    await requireOk(response, "discovery could not start");
    discoveryJob = await response.json() as FuzzerJob;
    renderDiscovery();
    if (discoveryPoll !== undefined) window.clearInterval(discoveryPoll);
    discoveryPoll = window.setInterval(() => void refreshDiscovery(), 500);
  } catch (error) {
    reportUnexpected(error, { id: "web.discovery-failed", what: "Discovery could not start.", why: "", fix: "Check ffuf availability and the active session." });
  }
}

function renderDiscovery(): void {
  const job = discoveryJob;
  if (job === null) return;
  // Result semantics differ by tier. The native runner records every attempt,
  // so `results` is a progress count. The ffuf runner records only what ffuf's
  // own matcher kept, so `results` is a hit count and says nothing about how
  // many candidates have been sent. Reporting one as the other would overstate
  // what the engine actually told us.
  const attemptsReported = job.tier === "native";
  const candidates = lastDiscoveryEstimate?.requestCount ?? 0;
  const hits = job.results.filter((result) => result.matched).length;
  const attempts = job.results.length;
  const running = job.state === "running";
  const rate = lastDiscoveryEstimate?.ratePerSecond ?? 0;

  if (discoveryBadge !== null) discoveryBadge.textContent = job.state;
  if (discoveryProgress !== null) {
    const outcome = job.state === "completed" ? " progress--success" : job.state === "failed" ? " progress--failed" : "";
    let tone: string;
    let percent: number;
    let label: string;
    let value: string;
    if (attemptsReported) {
      percent = candidates > 0 ? Math.min(100, (attempts / candidates) * 100) : 0;
      tone = outcome === "" && running ? " progress--running" : outcome;
      label = `${attempts.toLocaleString()}${candidates > 0 ? ` / ${candidates.toLocaleString()}` : ""} probed · ${hits} hit${hits === 1 ? "" : "s"}`;
      const remaining = Math.max(0, candidates - attempts);
      value = running && rate > 0 && candidates > 0 ? `${Math.ceil(remaining / rate)}s remaining` : job.state;
    } else {
      percent = running ? 0 : 100;
      tone = running ? " progress--indeterminate progress--running" : outcome;
      label = `${hits} hit${hits === 1 ? "" : "s"}${candidates > 0 ? ` · ${candidates.toLocaleString()} candidates` : ""}`;
      value = running
        ? rate > 0 && candidates > 0
          ? `~${Math.ceil(candidates / rate)}s`
          : "running"
        : job.state;
    }
    const progressAttributes = attemptsReported || !running
      ? ` aria-valuenow="${Math.round(percent)}" aria-valuemin="0" aria-valuemax="100"`
      : "";
    discoveryProgress.innerHTML = `<div class="progress${tone}" role="progressbar"${progressAttributes}>
<div class="progress__meta"><span>${escapeHtml(label)}</span><span class="progress__value">${escapeHtml(value)}</span></div>
<div class="progress__track"><div class="progress__fill" style="width:${percent}%"></div></div>
</div>`;
  }
  if (discoveryResultsCount !== null) discoveryResultsCount.textContent = `${hits} hit${hits === 1 ? "" : "s"}`;
  if (discoveryResults !== null) {
    const rows = job.results.filter((result) => result.matched).sort((a, b) => a.ordinal - b.ordinal);
    discoveryResults.innerHTML = rows.length === 0
      ? stateBlock({ icon: "discovery", title: "No hits yet", body: "Confirmed discoveries appear here as they are found. Non-matching probes are not listed.", compact: true })
      : `<table class="data-table"><thead><tr><th>#</th><th>Candidate</th><th>Status</th><th>Length</th></tr></thead><tbody>${rows.map((result) => `<tr class="is-match"><td>${result.ordinal}</td><td>${escapeHtml(result.payloads.join(" / "))}</td><td><span class="list-row__status" data-class="${statusClass(result.response?.status)}">${result.response?.status ?? "—"}</span></td><td>${result.response?.body?.length ?? "—"}</td></tr>`).join("")}</tbody></table>`;
  }
  if (discoveryStatus !== null) discoveryStatus.textContent = attemptsReported ? `${job.state} · ${attempts} probed · ${hits} hits` : `${job.state} · ${hits} hits reported by the ${job.tier} runner`;
  job.diagnostics.forEach(showDiagnostic);
}

function renderDiscoveryIdle(): void {
  if (discoveryResults !== null) {
    discoveryResults.innerHTML = stateBlock({
      icon: "discovery",
      title: "No discovery run yet",
      body: "Estimate first, then run discovery. Confirmed hits are listed here as they are found.",
      compact: true,
    });
  }
}

async function refreshDiscovery(): Promise<void> {
  if (discoveryJob === null) return;
  const response = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(discoveryJob.id));
  if (!response.ok) return;
  discoveryJob = await response.json() as FuzzerJob;
  renderDiscovery();
  if (["completed", "failed", "stopped"].includes(discoveryJob.state) && discoveryPoll !== undefined) {
    window.clearInterval(discoveryPoll);
    discoveryPoll = undefined;
  }
}

async function stopDiscovery(): Promise<void> {
  if (discoveryJob === null) return;
  await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(discoveryJob.id) + "/stop", { method: "POST" });
  await refreshDiscovery();
  toast("Discovery cancelled");
}

/* ==================================================================== *
 * Fusion
 * ==================================================================== */

/** Best-effort live fusion while capturing: keeps the API surface current with
 *  no toast and no navigation, so it is ready the instant the operator opens it. */
let autoFuseTick = 0;
async function autoFuseWebTraffic(): Promise<void> {
  try {
    const response = await fetch("/api/v1/web/fuse", { method: "POST" });
    if (response.ok) renderSurface(normalizeFusedSurface(await response.json()));
  } catch {
    /* the next tick retries; a fuse with no in-scope traffic simply no-ops */
  }
}

async function fuseWebTraffic(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#web-fuse");
  try {
    await withBusy(button, "Fusing…", async () => {
      const response = await fetch("/api/v1/web/fuse", { method: "POST" });
      await requireOk(response, "web fusion failed");
      renderSurface(normalizeFusedSurface(await response.json()));
      setStatus("Web traffic fused · observation-based coverage", "ready");
      toast("Captured traffic fused into a surface", "success");
      showView("surface");
    });
  } catch (error) {
    reportUnexpected(error, { id: "web.fusion-failed", what: "Captured web traffic could not be fused.", why: "", fix: "Capture at least one in-scope request and retry." });
  }
}

/* ==================================================================== *
 * 9. Artifact export
 * ==================================================================== */

function selectedFormats(): string[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>("[data-format]"))
    .filter((input) => input.checked)
    .map((input) => input.dataset.format ?? "")
    .filter((format) => format !== "");
}

async function runExport(): Promise<void> {
  const formats = selectedFormats();
  const outputDir = exportDir?.value.trim() ?? "";
  if (formats.length === 0) {
    showDiagnostic({ id: "export.format-required", what: "At least one export format is required.", why: "The exporter writes one artifact per selected format.", fix: "Select a format and run the export again." });
    return;
  }
  if (outputDir === "") {
    showDiagnostic({ id: "export.output-directory-required", what: "An output directory is required.", why: "Artifacts are written to a directory on this machine.", fix: "Enter an output directory and run the export again." });
    exportDir?.focus();
    return;
  }
  const button = document.querySelector<HTMLButtonElement>("#export-run");
  try {
    await withBusy(button, "Exporting…", async () => {
      const response = await fetch("/api/v1/export", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ formats, outputDir }) });
      await requireOk(response, "artifact export failed");
      setStatus("Artifacts exported", "ready");
      if (exportBadge !== null) exportBadge.textContent = "complete";
      if (exportResult !== null) {
        exportResult.innerHTML = `<div class="stack">
<div class="notice notice--success"><span class="notice__icon">${icon("check", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Export complete</p><p>${formats.length} artifact${formats.length === 1 ? "" : "s"} written.</p></div></div>
<dl class="kv"><dt>Directory</dt><dd class="t-mono">${escapeHtml(outputDir)}</dd><dt>Formats</dt><dd class="t-mono">${escapeHtml(formats.join(", "))}</dd></dl>
</div>`;
      }
      toast("Artifacts exported", "success");
    });
  } catch (error) {
    if (exportBadge !== null) exportBadge.textContent = "failed";
    if (exportResult !== null) {
      exportResult.innerHTML = `<div class="notice notice--danger"><span class="notice__icon">${icon("alert", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Export did not complete</p><p>The cause and its fix are recorded in diagnostics.</p></div></div>`;
    }
    reportUnexpected(error, { id: "export.failed", what: "Artifacts could not be exported.", why: "", fix: "Assemble or fuse a surface first, then retry the export." });
  }
}

function renderExportIdle(): void {
  if (exportResult === null) return;
  exportResult.innerHTML = stateBlock({
    icon: "export",
    title: "Nothing exported yet",
    body: "Choose formats and an output directory, then run the export. The written paths are reported here.",
  });
}

/* ==================================================================== *
 * 10. Session management
 * ==================================================================== */

function renderSession(status: SessionStatus): void {
  lastSessionStatus = status;
  if (headerSession !== null) {
    headerSession.textContent = status.sessionId;
    headerSession.title = status.artifactPath;
  }
  if (sessionBadge !== null) sessionBadge.textContent = status.lifecycle;
  updateScopePill(status);
  if (sessionDetail === null) return;
  sessionDetail.innerHTML = `<div class="stack">
<div class="metric-grid">
  <div class="metric"><span class="metric__value">${status.flowCount}</span><span class="metric__label">flows</span></div>
  <div class="metric"><span class="metric__value">${status.resendCount}</span><span class="metric__label">resends</span></div>
  <div class="metric"><span class="metric__value">${status.fuzzerCount}</span><span class="metric__label">fuzzer jobs</span></div>
</div>
<dl class="kv">
  <dt>Session</dt><dd class="t-mono">${escapeHtml(status.sessionId)}</dd>
  <dt>Lifecycle</dt><dd>${escapeHtml(status.lifecycle)}</dd>
  <dt>Target type</dt><dd>${escapeHtml(status.scope?.target?.target_type ?? "not declared")}</dd>
  <dt>Artifact</dt><dd class="t-mono">${escapeHtml(status.artifactPath)}</dd>
  <dt>Store</dt><dd class="t-mono">${escapeHtml(status.storePath)}</dd>
  <dt>Checkpoint</dt><dd>${status.lastCheckpointAt === undefined || status.lastCheckpointAt === null ? "none this run" : escapeHtml(formatTime(status.lastCheckpointAt))}</dd>
</dl>
${status.scopeConfigured ? "" : `<div class="notice notice--caution"><span class="notice__icon">${icon("shield", { size: 18 })}</span><div class="notice__body"><p class="notice__title">No network allow rules declared</p><p>Active work is gated on a declared scope. Start a web session, or run an APK analysis, to establish one.</p></div></div>`}
${status.recoveredFromCheckpoint ? `<div class="notice notice--accent"><span class="notice__icon">${icon("info", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Recovered from a checkpoint</p><p>Compact metadata newer than the full artifact was found and used. Save the session to write a full artifact again.</p></div></div>` : ""}
</div>`;
}

/**
 * Keeps the title-bar scope pill honest. The pill is the operator's at-a-glance
 * answer to "is active work authorized, and against what?" — so it reflects the
 * real declared scope, never a decorative constant. Unscoped sessions say so
 * plainly rather than implying authorization that has not been affirmed.
 */
function updateScopePill(status: SessionStatus): void {
  const pill = document.querySelector<HTMLElement>("#scope-pill");
  const host = document.querySelector<HTMLElement>("#scope-host");
  if (pill === null) return;
  const label = pill.querySelector<HTMLElement>(".scope-pill__label");
  pill.hidden = false;
  if (status.scopeConfigured) {
    pill.classList.remove("is-unscoped");
    if (label !== null) label.textContent = "AUTHORIZED";
    const primary = status.scope?.target?.primary?.value ?? "";
    let shown = "";
    if (primary !== "") {
      try {
        shown = new URL(primary).host;
      } catch {
        shown = primary;
      }
    }
    if (host !== null) host.textContent = shown;
    pill.title = shown === "" ? "Active scope is authorized" : `Authorized scope: ${shown}`;
  } else {
    pill.classList.add("is-unscoped");
    if (label !== null) label.textContent = "NO SCOPE";
    if (host !== null) host.textContent = "";
    pill.title = "No scope declared — start a web session or run an APK analysis to authorize active work";
  }
}

/**
 * Reflects durable session state back into the workflow surfaces. A resumed
 * session already carries its declared scope and its analysis run, so the
 * views should show that rather than an untouched form.
 */
function rehydrateWorkflows(status: SessionStatus): void {
  const targetType = status.scope?.target?.target_type;
  if (targetType === "web.url") {
    const origin = status.scope?.target?.primary?.value ?? "";
    if (webTarget !== null && webTarget.value.trim() === "") webTarget.value = origin;
    if (webAuthorize !== null) webAuthorize.checked = true;
    if (webAuthorization !== null) webAuthorization.hidden = true;
    if (webAuthorizedNote !== null) webAuthorizedNote.hidden = false;
    if (webSessionBadge !== null) webSessionBadge.textContent = "active";
    if (webSessionStatus !== null) {
      webSessionStatus.textContent = `Session ${status.sessionId}${origin === "" ? "" : ` · scope set to ${origin}`}.`;
    }
  }
  const artifact = status.analysisPipeline?.artifact_path ?? "";
  if (artifact !== "" && apkPath !== null && apkPath.value.trim() === "") apkPath.value = artifact;
}

function renderAudit(records: readonly AuditRecord[]): void {
  if (auditCount !== null) auditCount.textContent = `${records.length} record${records.length === 1 ? "" : "s"}`;
  if (sessionAudit === null) return;
  if (records.length === 0) {
    sessionAudit.innerHTML = stateBlock({
      icon: "clock",
      title: "No recorded actions",
      body: "Scope declarations, authorization affirmations, and every action taken against a target are appended here.",
      compact: true,
    });
    return;
  }
  sessionAudit.innerHTML = [...records].reverse().map((record) => {
    const tone = record.outcome === "completed" ? "badge--success" : record.outcome === "failed" ? "badge--danger" : "badge--caution";
    return `<div class="audit-row">
<span class="audit-row__time">${escapeHtml(formatTime(record.occurred_at))}</span>
<span class="audit-row__summary">${escapeHtml(record.action.summary)}<span class="audit-row__kind">${escapeHtml(record.action.kind)}</span></span>
<span class="badge ${tone}">${escapeHtml(record.outcome)}</span>
</div>`;
  }).join("");
}

async function refreshSession(): Promise<void> {
  try {
    const response = await fetch("/api/v1/session");
    if (!response.ok) return;
    const status = (await response.json()) as SessionStatus;
    renderSession(status);
    rehydrateWorkflows(status);
  } catch {
    // Session status is advisory here; the engine status carries connectivity.
  }
  try {
    const response = await fetch("/api/v1/session/audit");
    if (!response.ok) return;
    renderAudit((await response.json()) as AuditRecord[]);
  } catch {
    // The audit trail is durable; a transient read failure is not fatal.
  }
}

async function newSession(): Promise<void> {
  const confirmed = await confirmDialog({
    eyebrow: "Session",
    title: "Start a new session",
    message: "A new session replaces the active one in this runtime. Save the current session first if you want to return to it.",
    confirmLabel: "Start new session",
    tone: "danger",
  });
  if (!confirmed) return;
  const button = document.querySelector<HTMLButtonElement>("#session-new");
  try {
    await withBusy(button, "Creating…", async () => {
      const response = await fetch("/api/v1/session/new", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({}) });
      await requireOk(response, "new session could not be created");
      renderSession((await response.json()) as SessionStatus);
      toast("New session created", "success");
    });
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "session.new-failed", what: "A new session could not be created.", why: "", fix: "Check the local API and the session store directory, then retry." });
  }
}

async function openSession(): Promise<void> {
  const path = await promptDialog({
    eyebrow: "Session",
    title: "Open a saved session",
    message: "Enter the path to a session artifact on this machine. Captured traffic, resend history, fuzzer jobs, and the audit trail are restored with it.",
    label: "Session artifact path",
    value: "",
    placeholder: "artifacts/session.json",
    confirmLabel: "Open session",
  });
  if (path === null) return;
  const button = document.querySelector<HTMLButtonElement>("#session-open");
  try {
    await withBusy(button, "Opening…", async () => {
      const response = await fetch("/api/v1/session/open", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ path }) });
      await requireOk(response, "session could not be opened");
      renderSession((await response.json()) as SessionStatus);
      toast("Session opened", "success");
    });
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "session.open-failed", what: "The session could not be opened.", why: "", fix: "Check that the artifact path exists and was written by this version, then retry." });
  }
}

async function saveSession(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#session-save");
  try {
    await withBusy(button, "Saving…", async () => {
      const response = await fetch("/api/v1/session/save", { method: "POST" });
      await requireOk(response, "session could not be saved");
      renderSession((await response.json()) as SessionStatus);
      toast("Session saved", "success");
    });
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "session.save-failed", what: "The session could not be saved.", why: "", fix: "Check the session store path is writable, then retry." });
  }
}

/* ==================================================================== *
 * 19. About
 * ==================================================================== */

function renderAbout(status: SystemStatus | null): void {
  const host = document.querySelector<HTMLElement>("#about-build");
  if (host === null) return;
  host.innerHTML = `<dt>Service</dt><dd class="t-mono">${escapeHtml(status?.service ?? "unavailable")}</dd>
<dt>API</dt><dd class="t-mono">${escapeHtml(status?.apiVersion ?? "—")}</dd>
<dt>Endpoint</dt><dd class="t-mono">${escapeHtml(location.origin)}</dd>
<dt>Identity</dt><dd>Kit v2.1 · Outfit bundled locally</dd>`;
}

/* ==================================================================== *
 * Wiring
 * ==================================================================== */

interceptToggle?.addEventListener("change", () => sendControl({ type: "set_intercept", enabled: interceptToggle.checked, timeout_ms: INTERCEPT_TIMEOUT_MS }));
hostFilter?.addEventListener("change", () => sendControl({ type: "set_host_filter", hosts: hostFilter.value.split(",").map((host) => host.trim()).filter(Boolean) }));
document.querySelector("#forward")?.addEventListener("click", () => editAction("forward"));
document.querySelector("#forward-modified")?.addEventListener("click", () => editAction("forward_modified"));
document.querySelector("#drop")?.addEventListener("click", () => editAction("drop"));
document.querySelector("#web-start")?.addEventListener("click", () => void startWebSession());
document.querySelector("#capture-launch")?.addEventListener("click", () => void launchCaptureBrowser());
document.querySelector("#capture-stop")?.addEventListener("click", () => void stopCaptureBrowser());
harImport?.addEventListener("click", () => harFile?.click());
harExport?.addEventListener("click", () => void exportHar());
harFile?.addEventListener("change", () => { const file = harFile.files?.[0]; if (file !== undefined) void importHar(file); harFile.value = ""; });
document.querySelector("#discovery-estimate")?.addEventListener("click", () => void estimateDiscovery());
document.querySelector("#discovery-run")?.addEventListener("click", () => void runDiscovery());
document.querySelector("#discovery-stop")?.addEventListener("click", () => void stopDiscovery());
document.querySelector("#discovery-upload-btn")?.addEventListener("click", () => document.querySelector<HTMLInputElement>("#discovery-upload")?.click());
document.querySelector<HTMLInputElement>("#discovery-upload")?.addEventListener("change", (event) => {
  const file = (event.target as HTMLInputElement).files?.[0];
  if (file !== undefined) loadCustomWordlist(file);
  (event.target as HTMLInputElement).value = "";
});
discoveryWordlist?.addEventListener("change", updateWordlistHint);
document.querySelector("#web-fuse")?.addEventListener("click", () => void fuseWebTraffic());
document.querySelector("#web-export")?.addEventListener("click", () => showView("export"));
document.querySelector("#apk-run")?.addEventListener("click", () => void startPipeline());
document.querySelector("#apk-refresh")?.addEventListener("click", () => void refreshPipeline());
// "Static only" and the dynamic pass are opposite ends of one axis: static-only
// skips dynamic entirely. Keep the two checkboxes coherent so the form can never
// show both passes selected at once (the run logic already makes static-only win;
// this makes the displayed state match what will actually happen).
function syncApkPasses(): void {
  if (apkStaticOnly === null || apkDynamic === null) return;
  apkDynamic.disabled = apkStaticOnly.checked;
  apkDynamic.checked = !apkStaticOnly.checked;
}
apkStaticOnly?.addEventListener("change", syncApkPasses);
document.querySelector("#apk-browse")?.addEventListener("click", () => void browseForApk());
apkFile?.addEventListener("change", () => {
  const file = apkFile.files?.[0];
  if (file === undefined || apkPath === null) return;
  // Fallback path only (no native picker): browsers expose only the file name,
  // never the full path. Fill what is available and say so.
  apkPath.value = file.name;
  apkPath.focus();
  toast("Prefix the file name with its full directory path so the engine can read it.");
});

/**
 * Browse for an APK. On the desktop the engine opens the platform's native file
 * dialog, which returns the artifact's full disk path — so the field is filled
 * with a path the engine can actually read. Where no native picker is available
 * (a remote browser), fall back to the plain file input.
 */
async function browseForApk(): Promise<void> {
  try {
    const response = await fetch("/api/v1/pick-file", { method: "POST" });
    if (response.ok) {
      const result = (await response.json()) as { available: boolean; path: string | null };
      if (result.available) {
        // Native dialog handled it. A null path means the operator cancelled —
        // leave the field untouched rather than clearing a prior value.
        if (result.path !== null && result.path !== "" && apkPath !== null) {
          apkPath.value = result.path;
          apkPath.focus();
        }
        return;
      }
    }
  } catch {
    // Fall through to the browser file input below.
  }
  apkFile?.click();
}
document.querySelector("#export-run")?.addEventListener("click", () => void runExport());
document.querySelector("#session-new")?.addEventListener("click", () => void newSession());
document.querySelector("#session-open")?.addEventListener("click", () => void openSession());
document.querySelector("#session-save")?.addEventListener("click", () => void saveSession());
document.querySelector("#surface-refresh")?.addEventListener("click", () => void refreshStoredSurface());
document.querySelectorAll<HTMLElement>(".surface-section").forEach((tab) => {
  tab.addEventListener("click", () => showSurfaceSection((tab.dataset.surfaceSection as "app" | "web") ?? "web"));
});

/* ==================================================================== *
 * Boot
 * ==================================================================== */

/**
 * Keeps `--shell-header-height` equal to the header's real height. The header
 * wraps to a second row on narrow windows, and the layers anchored beneath it —
 * the workbench column and the diagnostics drawer — have to follow.
 */
function trackHeaderHeight(): void {
  const header = document.querySelector<HTMLElement>(".app-header");
  if (header === null) return;
  const sync = (): void => {
    document.documentElement.style.setProperty(
      "--shell-header-height",
      `${Math.round(header.getBoundingClientRect().height)}px`,
    );
  };
  sync();
  new ResizeObserver(sync).observe(header);
}

/* ==================================================================== *
 * Settings — operator configuration                                     *
 * ==================================================================== */

interface SettingEntry {
  readonly key: string;
  readonly label: string;
  readonly group: string;
  readonly value: string;
  readonly defaultDisplay: string;
  readonly source: "default" | "config" | "environment";
  readonly advanced: boolean;
  readonly restartRequired: boolean;
  readonly description: string;
  readonly choices: readonly string[];
}

interface ToolStatus {
  readonly label: string;
  readonly group: string;
  readonly path: string;
  readonly present: boolean;
  readonly overridden: boolean;
  readonly optional: boolean;
}

interface SettingsResponse {
  readonly settings: readonly SettingEntry[];
  readonly tools: readonly ToolStatus[];
  readonly configPath: string;
}

const SETTINGS_GROUP_ORDER: readonly string[] = [
  "General",
  "Storage",
  "Scope",
  "Discovery",
  "Network",
  "Dynamic analysis",
  "Tool paths (advanced)",
];

function settingSourceBadge(source: SettingEntry["source"]): string {
  if (source === "environment")
    return `<span class="badge badge--caution">environment override</span>`;
  if (source === "config") return `<span class="badge badge--accent">saved</span>`;
  return `<span class="badge">default</span>`;
}

function settingControl(entry: SettingEntry): string {
  const attrs = `data-setting="${escapeHtml(entry.key)}" data-original="${escapeHtml(entry.value)}"`;
  if (entry.choices.length > 0) {
    const options = entry.choices
      .map(
        (choice) =>
          `<option value="${escapeHtml(choice)}"${choice === entry.value ? " selected" : ""}>${escapeHtml(choice)}</option>`,
      )
      .join("");
    return `<select class="select" ${attrs}><option value="">${escapeHtml(entry.defaultDisplay)}</option>${options}</select>`;
  }
  return `<input class="input input--mono" type="text" spellcheck="false" ${attrs} value="${escapeHtml(entry.value)}" placeholder="${escapeHtml(entry.defaultDisplay)}" />`;
}

function settingField(entry: SettingEntry): string {
  const restart = entry.restartRequired ? " · takes effect on restart" : "";
  const envNote =
    entry.source === "environment"
      ? " An environment variable set outside the app takes precedence over a saved value."
      : "";
  return `<div class="field">
    <div class="row row--between">
      <label class="field__label">${escapeHtml(entry.label)}</label>
      ${settingSourceBadge(entry.source)}
    </div>
    ${settingControl(entry)}
    <p class="field__hint">${escapeHtml(entry.description)}<span class="t-subtle">${escapeHtml(restart)}${escapeHtml(envNote)}</span></p>
  </div>`;
}

function settingsToolRow(tool: ToolStatus): string {
  const badge = tool.present
    ? `<span class="badge badge--success">present</span>`
    : tool.optional
      ? `<span class="badge badge--caution">not installed</span>`
      : `<span class="badge badge--danger">missing</span>`;
  const override = tool.overridden ? `<span class="badge">override</span>` : "";
  return `<div class="tool-row">
    <span class="tool-row__name t-label">${escapeHtml(tool.label)}</span>
    <span class="tool-row__path">${escapeHtml(tool.path)}</span>
    <span class="tool-row__status">${override}${badge}</span>
  </div>`;
}

function renderSettings(data: SettingsResponse): void {
  const host = document.querySelector<HTMLElement>("#settings-body");
  if (host === null) return;

  const present = data.tools.filter((tool) => tool.present).length;
  const toolsPanel = `<article class="panel">
    <div class="panel__header">
      <div class="panel__heading"><span data-icon="info"></span><h2>Bundled tools</h2></div>
      <span class="panel__hint">${present} of ${data.tools.length} resolved</span>
    </div>
    <div class="panel__body stack">${data.tools.map(settingsToolRow).join('<hr class="rule" />')}</div>
  </article>`;

  const knownGroups = SETTINGS_GROUP_ORDER.filter((group) =>
    data.settings.some((entry) => entry.group === group),
  );
  const otherGroups = [...new Set(data.settings.map((entry) => entry.group))].filter(
    (group) => !SETTINGS_GROUP_ORDER.includes(group),
  );
  const panels = [...knownGroups, ...otherGroups]
    .map((group) => {
      const entries = data.settings.filter((entry) => entry.group === group);
      const warning = group.toLowerCase().includes("advanced")
        ? `<div class="notice notice--caution"><span class="notice__icon" data-icon="alert"></span><div class="notice__body"><p class="notice__title">Advanced overrides</p><p>These replace tools APIaxess resolves by absolute path from the install. Leave blank to keep the safe bundled defaults — a wrong path breaks bundled-tool resolution.</p></div></div>`
        : "";
      return `<article class="panel">
        <div class="panel__header"><div class="panel__heading"><span data-icon="settings"></span><h2>${escapeHtml(group)}</h2></div></div>
        <div class="panel__body stack">${warning}${entries.map(settingField).join("")}</div>
      </article>`;
    })
    .join("");

  host.innerHTML = `${toolsPanel}${panels}<p class="settings__foot t-small t-subtle">Saved settings live at <span class="t-mono">${escapeHtml(data.configPath)}</span>.</p>`;
  hydrateIcons(host);
}

async function refreshSettings(): Promise<void> {
  try {
    const response = await fetch("/api/v1/settings");
    if (!response.ok) return;
    renderSettings((await response.json()) as SettingsResponse);
  } catch (error) {
    reportUnexpected(error, {
      id: "settings.load",
      what: "Settings could not be loaded",
      why: "",
      fix: "Reload the app and try again.",
    });
  }
}

async function saveSettings(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#settings-save");
  const controls = document.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
    "#settings-body [data-setting]",
  );
  const values: Record<string, string> = {};
  controls.forEach((control) => {
    const key = control.dataset.setting ?? "";
    if (key !== "" && control.value !== (control.dataset.original ?? "")) {
      values[key] = control.value;
    }
  });
  if (Object.keys(values).length === 0) {
    toast("No changes to save", "info");
    return;
  }
  try {
    await withBusy(button, "Saving…", async () => {
      const response = await fetch("/api/v1/settings", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ values }),
      });
      await requireOk(response, "settings save failed");
      renderSettings((await response.json()) as SettingsResponse);
      toast("Settings saved — restart APIaxess to apply", "success");
    });
  } catch (error) {
    reportUnexpected(error, {
      id: "settings.save",
      what: "Settings could not be saved",
      why: "",
      fix: "Correct the highlighted value and try again.",
    });
  }
}

function paintShell(): void {
  const lockup = document.querySelector<HTMLElement>("#header-lockup");
  if (lockup !== null) lockup.innerHTML = lockupHtml(13);
  const aboutLockup = document.querySelector<HTMLElement>("#about-lockup");
  if (aboutLockup !== null) aboutLockup.innerHTML = stackedLockupHtml(34);
  hydrateIcons();
  initTheme();
  trackHeaderHeight();
  trackNavOverflow();

  // Register view-enter refreshes before initNavigation so a deep link (e.g.
  // opening straight to #settings) triggers the initial load. These surfaces are
  // cheap to re-read and the ones most likely to have changed while the operator
  // was elsewhere.
  onViewChange((view) => {
    if (view === "session") void refreshSession();
    if (view === "surface") void refreshStoredSurface();
    if (view === "web") void populateWordlists();
    if (view === "workbench") {
      void refreshResendList();
      void refreshFuzzList();
    }
    if (view === "settings") void refreshSettings();
    if (view === "devices") enterDevicesView();
    else leaveDevicesView();
    if (view === "android") enterAndroidView();
    else leaveAndroidView();
  });
  androidLaunch?.addEventListener("click", () => void launchAndroidTarget());
  androidStop?.addEventListener("click", () => void stopAndroidTarget());
  androidApkInstall?.addEventListener("click", () => void installTargetApk());
  androidApkBrowse?.addEventListener("click", () => void browseForAndroidApk());
  androidApkFile?.addEventListener("change", () => {
    const file = androidApkFile.files?.[0];
    if (file === undefined || androidApkPath === null) return;
    androidApkPath.value = file.name;
    androidApkPath.focus();
    toast("Prefix the file name with its full directory path so the engine can read it.");
  });
  document
    .querySelector<HTMLButtonElement>("#settings-save")
    ?.addEventListener("click", () => void saveSettings());
  document
    .querySelector<HTMLButtonElement>("#devices-refresh")
    ?.addEventListener("click", () => void refreshDevices());

  initShell();
  // Resend/Fuzz are Workbench tools now; seed each detail pane's resting empty
  // state and wire the tool tabs, lists, search, and split resizers.
  seedResendEmpty();
  seedFuzzerEmpty();
  initWorkbenchTools();
  initNavigation();
  initDiagnosticsDrawer(diagnostics);
  diagnostics.render();
  renderFlows();
  renderQueue();
  renderPipelineEmpty();
  renderSurfaceEmpty();
  renderDetailEmpty();
  renderDiscoveryIdle();
  renderExportIdle();
  renderBrowserState(null);
  renderAbout(null);
}

function dismissSplash(): void {
  const splash = document.querySelector<HTMLElement>("#splash");
  if (splash === null) return;
  splash.classList.add("is-leaving");
  window.setTimeout(() => { splash.hidden = true; }, 260);
}

/**
 * Reopens durable resend and fuzzer state after a reload. These jobs are
 * persisted with the session, so a resumed session should surface them rather
 * than leaving reachable state stranded. The most recent of each is restored
 * into its drawer; a live fuzzer job resumes polling.
 */
async function restoreWorkbench(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/resend");
    if (response.ok) {
      const contexts = (await response.json()) as ResendContext[];
      const latest = contexts.at(-1);
      if (latest !== undefined) { selectedResend = latest; renderResend(); }
    }
  } catch { /* durable state; a transient read failure is not fatal */ }
  try {
    const response = await fetch("/api/v1/workbench/fuzzer");
    if (response.ok) {
      const jobs = (await response.json()) as FuzzerJob[];
      const latest = jobs.at(-1);
      if (latest !== undefined) {
        selectedFuzzer = latest;
        renderFuzzer();
        if (latest.state === "running") {
          if (fuzzerPoll !== undefined) window.clearInterval(fuzzerPoll);
          fuzzerPoll = window.setInterval(() => void refreshFuzzer(), 500);
        }
      }
    }
  } catch { /* durable state; a transient read failure is not fatal */ }
}

async function boot(): Promise<void> {
  paintShell();
  try {
    const [statusResponse, sessionResponse, healthResponse, diagnosticsResponse] = await Promise.all([fetch("/api/v1/system/status"), fetch("/api/v1/workbench/session"), fetch("/api/v1/workbench/health"), fetch("/api/v1/workbench/diagnostics")]);
    if (diagnosticsResponse.ok) ((await diagnosticsResponse.json()) as Diagnostic[]).forEach(showDiagnostic);
    await requireOk(statusResponse, "local API unavailable");
    await requireOk(sessionResponse, "workbench session unavailable");
    await requireOk(healthResponse, "proxy health unavailable");
    const status = (await statusResponse.json()) as SystemStatus;
    const session = (await sessionResponse.json()) as WorkbenchSession;
    const health = (await healthResponse.json()) as WorkbenchHealth;
    operatorToken = session.authToken;
    // A deep link straight to #devices renders before the token is known; now
    // that it is, reload that view's operator-gated data.
    if (document.querySelector<HTMLElement>('[data-view="devices"]')?.hidden === false) {
      enterDevicesView();
    }
    // Same for a deep link straight to #android before the token was known.
    if (document.querySelector<HTMLElement>('[data-view="android"]')?.hidden === false) {
      enterAndroidView();
    }
    latestHealth = health;
    setStatus(`${status.service} ${status.apiVersion} · ready`, "ready");
    renderAbout(status);
    if (!health.proxyRunning) showDiagnostic({ id: "proxy.backend-start-failed", what: "The session proxy health is not ready.", why: "The local API has no completed backend health snapshot.", fix: "Restart the active session and inspect the resulting diagnostic." });
    if (interceptToggle !== null) interceptToggle.checked = session.interceptEnabled;
    const initial = (await (await fetch("/api/v1/workbench/flows")).json()) as FlowSummary[];
    initial.forEach((flow) => flows.set(flow.id, flow));
    flowsLoaded = true;
    renderFlows();
    renderCaptureHealth();
    connect(session);
    await refreshPending();
    await refreshSession();
    await refreshStoredSurface();
    await refreshPipeline();
    await refreshBrowserStatus();
    await restoreWorkbench();
    window.setInterval(() => void refreshPending(), 500);
    window.setInterval(() => void refreshHealth(), 5000);
    pipelinePoll = window.setInterval(() => void refreshPipeline(), 1000);
  } catch (error) {
    flowsLoaded = true;
    renderFlows();
    setStatus("Local engine unavailable", "unavailable");
    if (!(error instanceof ApiRequestError)) showDiagnostic({ id: "proxy.live-transport-failed", what: "The live workbench could not connect.", why: String(error), fix: "Start or reload the active local session." });
  } finally {
    dismissSplash();
  }
}

/* ==================================================================== *
 * 7b. Device pairing (Phase C5)
 *
 * The operator arms an attached device (transport + a one-time token), the
 * client scans the QR, and the operator accepts the ensuing request to
 * provision trust. The pairing endpoints are operator-gated, so every call
 * carries the workbench bearer token the control channel also uses.
 * ==================================================================== */

/** Header set for operator-gated pairing calls; `json` adds the request body type. */
function pairingHeaders(json = false): Record<string, string> {
  const headers: Record<string, string> = { authorization: `Bearer ${operatorToken}` };
  if (json) headers["content-type"] = "application/json";
  return headers;
}

/** Shown when the operator session token is not yet available. */
function renderDevicesUnavailable(): void {
  if (devicesCount !== null) devicesCount.textContent = "—";
  if (devicesList !== null) {
    devicesList.innerHTML = stateBlock({
      icon: "alert",
      title: "Operator session not ready",
      body: "The workbench session token is required to manage devices. It becomes available once the local engine is connected — reload if this persists.",
    });
  }
}

function renderDevices(devices: readonly PairingDevice[]): void {
  if (devicesList === null) return;
  if (devicesCount !== null) devicesCount.textContent = `${devices.length} attached`;
  if (devices.length === 0) {
    devicesList.innerHTML = stateBlock({
      icon: "apk",
      title: "No devices attached",
      body: "Connect a rooted Android device over adb, then refresh. Attached devices appear here to arm for pairing.",
    });
    return;
  }
  devicesList.replaceChildren();
  const list = document.createElement("div");
  list.className = "list";
  devices.forEach((device) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.style.gridTemplateColumns = "minmax(0, 1fr) auto";
    row.innerHTML = `<span class="list-row__target"><b>${escapeHtml(device.serial)}</b> <span class="badge">${escapeHtml(device.state)}</span><br><span class="t-small t-subtle">${escapeHtml(device.description)}</span></span>`;
    const arm = document.createElement("button");
    arm.type = "button";
    arm.className = "btn btn--sm btn--primary";
    arm.innerHTML = `${icon("shield", { size: 14 })}<span>Arm pairing</span>`;
    arm.addEventListener("click", () => void armDevice(device.serial, arm));
    row.append(arm);
    list.append(row);
  });
  devicesList.append(list);
}

async function refreshDevices(): Promise<void> {
  if (operatorToken === "") { renderDevicesUnavailable(); return; }
  try {
    const response = await fetch("/api/v1/pairing/devices", { headers: pairingHeaders() });
    await requireOk(response, "attached devices unavailable");
    renderDevices((await response.json()) as PairingDevice[]);
  } catch (error) {
    // A failed listing on entering this view is, most often, simply that no adb
    // device is attached yet — the expected state before pairing, not a hard
    // failure worth a danger toast. Show the calm guidance state in the panel;
    // the underlying diagnostic (recorded by requireOk when the engine returned
    // one) stays in the drawer for a genuine adb/transport fault.
    if (devicesCount !== null) devicesCount.textContent = "0 attached";
    if (devicesList !== null) {
      devicesList.innerHTML = stateBlock({
        icon: "apk",
        title: "No devices attached",
        body: "Connect a rooted Android device over adb, then refresh. If a device is connected but not listed, confirm adb is on PATH and the device is authorized.",
      });
    }
    if (!(error instanceof ApiRequestError)) {
      showDiagnostic({ id: "pairing.devices-unavailable", what: "Attached devices could not be listed.", why: String(error), fix: "Confirm adb is on PATH and a device is connected and authorized, then refresh." });
    }
  }
}

/**
 * Arms a device and captures the QR payload. The QR encodes the server's
 * response bytes verbatim — the Android client JSON-parses exactly this string,
 * so the raw text is kept and never re-serialized.
 */
async function armDevice(serial: string, button: HTMLButtonElement): Promise<void> {
  await withBusy(button, "Arming…", async () => {
    try {
      const response = await fetch("/api/v1/pairing/arm", { method: "POST", headers: pairingHeaders(true), body: JSON.stringify({ serial }) });
      await requireOk(response, "device arm failed");
      armedPairingRaw = await response.text();
      armedPairing = JSON.parse(armedPairingRaw) as PairingQrPayload;
      await renderArmed();
      revealDrawer(pairingArmResult);
      toast(`Armed ${serial}. Scan the pairing code on the device.`, "success");
    } catch (error) {
      reportUnexpected(error, { id: "pairing.arm-failed", what: "The device could not be armed for pairing.", why: "", fix: "Confirm the device is authorized over adb and that the reverse tunnel can be established, then retry." });
    }
  });
}

/** Renders the armed payload as a scannable QR plus a manual-entry fallback. */
async function renderArmed(): Promise<void> {
  if (pairingArmResult === null) return;
  const payload = armedPairing;
  const raw = armedPairingRaw;
  if (payload === null || raw === null) {
    if (pairingArmBadge !== null) pairingArmBadge.textContent = "not armed";
    pairingArmResult.innerHTML = stateBlock({
      icon: "shield",
      title: "No device armed",
      body: "Arm an attached device to generate a one-time pairing code. The client scans the QR to request pairing, then you accept it below.",
    });
    return;
  }
  if (pairingArmBadge !== null) pairingArmBadge.textContent = "armed";
  const expires = new Date(payload.expiresAtMs);
  const expiresText = Number.isNaN(expires.getTime()) ? String(payload.expiresAtMs) : expires.toLocaleTimeString();
  pairingArmResult.innerHTML = `<div class="stack">
  <div style="align-self:center;background:#ffffff;padding:12px;border-radius:var(--radius-2);line-height:0">
    <img id="pairing-qr" width="232" height="232" alt="Pairing QR code" />
  </div>
  <p class="t-small t-subtle">Scan with the APIaxess Android client. The client reads this exact payload — use the values below only if scanning is unavailable.</p>
  <dl class="kv">
    <dt>Host</dt><dd class="t-mono">${escapeHtml(payload.host)}:${payload.controlPort}</dd>
    <dt>Proxy port</dt><dd class="t-mono">${payload.proxyPort}</dd>
    <dt>Pairing token</dt><dd class="t-mono" style="word-break:break-all">${escapeHtml(payload.pairingToken)}</dd>
    <dt>CA fingerprint</dt><dd class="t-mono" style="word-break:break-all">${escapeHtml(payload.caFingerprintSha256)}</dd>
    <dt>Expires</dt><dd>${escapeHtml(expiresText)}</dd>
  </dl>
</div>`;
  try {
    // High-contrast, quiet-zoned, and error-corrected so a phone camera reads it
    // reliably against the dark UI. margin keeps the mandatory white quiet zone.
    const dataUrl = await qrToDataUrl(raw, { errorCorrectionLevel: "M", margin: 2, width: 232 });
    const img = pairingArmResult.querySelector<HTMLImageElement>("#pairing-qr");
    if (img !== null) img.src = dataUrl;
  } catch (error) {
    reportUnexpected(error, { id: "pairing.qr-render-failed", what: "The pairing QR code could not be rendered.", why: "", fix: "Enter the pairing token and CA fingerprint on the device manually instead." });
  }
}

function renderPendingPairing(list: readonly PendingPairing[]): void {
  if (pairingPending === null) return;
  if (pairingPendingCount !== null) pairingPendingCount.textContent = `${list.length} pending`;
  if (list.length === 0) {
    pairingPending.innerHTML = stateBlock({
      icon: "check",
      title: "No devices awaiting",
      body: "When an armed device scans its pairing code, its request appears here to accept or decline.",
      compact: true,
    });
    return;
  }
  pairingPending.replaceChildren();
  const container = document.createElement("div");
  container.className = "list";
  list.forEach((entry) => {
    const row = document.createElement("div");
    row.className = "list-row";
    row.style.gridTemplateColumns = "minmax(0, 1fr) auto";
    const ago = Math.max(0, Math.round(entry.requestedAgoMs / 1000));
    const serialNote = entry.serial === null || entry.serial === undefined || entry.serial === "" ? "" : ` · ${escapeHtml(entry.serial)}`;
    row.innerHTML = `<span class="list-row__target"><b>${escapeHtml(entry.deviceName)}</b>${serialNote}<br><span class="t-small t-subtle">requested ${ago}s ago</span></span>`;
    const actions = document.createElement("div");
    actions.className = "row";
    const accept = document.createElement("button");
    accept.type = "button";
    accept.className = "btn btn--sm btn--primary";
    accept.innerHTML = `${icon("check", { size: 14 })}<span>Accept</span>`;
    accept.addEventListener("click", () => void acceptPairing(entry.id, accept));
    const decline = document.createElement("button");
    decline.type = "button";
    decline.className = "btn btn--sm btn--danger";
    decline.innerHTML = `${icon("close", { size: 14 })}<span>Decline</span>`;
    decline.addEventListener("click", () => void declinePairing(entry.id, decline));
    actions.append(accept, decline);
    row.append(actions);
    container.append(row);
  });
  pairingPending.append(container);
}

async function refreshPendingPairing(): Promise<void> {
  if (operatorToken === "") return;
  try {
    const response = await fetch("/api/v1/pairing/pending", { headers: pairingHeaders() });
    if (!response.ok) return;
    renderPendingPairing((await response.json()) as PendingPairing[]);
  } catch {
    // Transient; the next poll retries. The diagnostics register stays quiet
    // so a brief blip does not flood it every two seconds.
  }
}

/** Accepts a pending device: provisions it (can take several seconds) and issues its token. */
async function acceptPairing(id: string, button: HTMLButtonElement): Promise<void> {
  await withBusy(button, "Provisioning…", async () => {
    try {
      const response = await fetch(`/api/v1/pairing/pending/${encodeURIComponent(id)}/accept`, { method: "POST", headers: pairingHeaders() });
      await requireOk(response, "device accept failed");
      toast("Device accepted and provisioned.", "success");
      await refreshPendingPairing();
    } catch (error) {
      reportUnexpected(error, { id: "pairing.accept-failed", what: "The device could not be accepted.", why: "", fix: "Provisioning failed or the request expired. Check the device over adb and pair again from the device." });
    }
  });
}

async function declinePairing(id: string, button: HTMLButtonElement): Promise<void> {
  await withBusy(button, "Declining…", async () => {
    try {
      const response = await fetch(`/api/v1/pairing/pending/${encodeURIComponent(id)}/decline`, { method: "POST", headers: pairingHeaders() });
      await requireOk(response, "device decline failed");
      toast("Device declined.", "info");
      await refreshPendingPairing();
    } catch (error) {
      reportUnexpected(error, { id: "pairing.decline-failed", what: "The device could not be declined.", why: "", fix: "The request may have already expired. Refresh the pending list." });
    }
  });
}

/** Reads the public CA endpoint and shows the fingerprint the client pins. */
async function refreshPairingCa(): Promise<void> {
  if (pairingCa === null) return;
  try {
    const response = await fetch("/api/v1/pairing/ca");
    await requireOk(response, "workbench CA unavailable");
    const fingerprint = response.headers.get("x-apiaxess-ca-fingerprint") ?? "unavailable";
    pairingCa.innerHTML = `<div class="stack stack--tight">
  <p class="t-small t-subtle">The client pins this certificate authority. Confirm the fingerprint the device displays matches this value before accepting.</p>
  <p class="t-mono" style="word-break:break-all">${escapeHtml(fingerprint)}</p>
</div>`;
  } catch (error) {
    reportUnexpected(error, { id: "pairing.ca-unavailable", what: "The workbench CA fingerprint could not be read.", why: "", fix: "The session CA is available only while a session is active. Start a session and retry." });
  }
}

/** Starts the Devices view: loads everything and polls the pending list. */
function enterDevicesView(): void {
  void refreshPairingCa();
  void refreshDevices();
  void renderArmed();
  void refreshPendingPairing();
  if (pairingPoll === undefined) {
    pairingPoll = window.setInterval(() => void refreshPendingPairing(), 2000);
  }
}

/** Stops the pending-pairing poll when the Devices view is left. */
function leaveDevicesView(): void {
  if (pairingPoll !== undefined) {
    window.clearInterval(pairingPoll);
    pairingPoll = undefined;
  }
}

/* ==================================================================== *
 * 7c. Android target panel (Phase D3)
 *
 * One authenticated workbench surface to launch the GUI Android target
 * (boot → C2/C5 provision → D2 stream), install the app to capture, and
 * drive it on the embedded ws-scrcpy screen — all on the engine origin, so
 * desktop (loopback) and VM (ip:port / SSH-tunnel) are one identical panel.
 * ==================================================================== */

const ANDROID_STEPS: readonly { readonly phase: AndroidPhase; readonly label: string }[] = [
  { phase: "booting", label: "Boot AVD (headless)" },
  { phase: "provisioning", label: "Provision · client app, session CA, instrumentation" },
  { phase: "streaming", label: "Start screen stream" },
];
/** Monotonic order of the launch phases, so the step list can mark done/active. */
const ANDROID_ORDER: Record<AndroidPhase, number> = { idle: 0, booting: 1, provisioning: 2, streaming: 3, ready: 4, error: 1 };

function androidStepsMarkup(status: AndroidTargetStatus): string {
  const current = ANDROID_ORDER[status.phase];
  const rows = ANDROID_STEPS.map((step) => {
    const order = ANDROID_ORDER[step.phase];
    let mark: string;
    let cls: string;
    if (status.phase === "error" && order >= current) { mark = icon("alert", { size: 14 }); cls = "is-error"; }
    else if (status.phase === "ready" || order < current) { mark = icon("check", { size: 14 }); cls = "is-done"; }
    else if (order === current) { mark = icon("refresh", { size: 14, className: "spinner" }); cls = "is-active"; }
    else { mark = icon("clock", { size: 14 }); cls = ""; }
    return `<li class="steps__item ${cls}">${mark}<span>${escapeHtml(step.label)}</span></li>`;
  }).join("");
  return `<ol class="steps">${rows}</ol>`;
}

/** Renders the actionable non-info diagnostics inline in the panel (right message,
 * right place) rather than only in the global drawer. */
function androidDiagnosticNotices(status: AndroidTargetStatus): string {
  const notable = status.diagnostics.filter((d) => /unavailable|failed|missing|not-active|not-running|degraded|software-mode/.test(d.id));
  return notable
    .map((d) => `<div class="notice notice--caution"><span class="notice__icon">${icon("alert", { size: 18 })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(d.what)}</p><p>${escapeHtml(d.why)}</p><p class="t-small t-subtle">${escapeHtml(d.fix)}</p></div></div>`)
    .join("");
}

function androidStatusBody(status: AndroidTargetStatus): string {
  if (!status.addonPresent) {
    return stateBlock({ icon: "apk", title: "Android target add-on not installed", body: "The GUI Android target is a separate, optional download. Install it with install-android-target.ps1 (Windows) or .sh (Linux), then launch it here." });
  }
  if (status.phase === "idle") {
    return stateBlock({ icon: "play", title: "No Android target running", body: "Launch to boot the AVD, provision it (client app, session CA, instrumentation), and start the screen stream — one click." });
  }
  if (status.phase === "error") {
    const first = status.diagnostics[0];
    const detail = first === undefined ? "" : `<div class="notice notice--danger"><span class="notice__icon">${icon("alert", { size: 18 })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(first.what)}</p><p>${escapeHtml(first.why)}</p><p class="t-small t-subtle">${escapeHtml(first.fix)}</p></div></div>`;
    return `${androidStepsMarkup(status)}${detail}`;
  }
  if (status.phase === "ready") {
    const facts = [
      status.serial === null ? null : `serial ${escapeHtml(status.serial)}`,
      status.androidSdk === null ? null : `Android API ${status.androidSdk}`,
      status.clientApkInstalled ? "client installed" : "client not installed",
      status.fridaServerStarted ? "instrumentation on" : "instrumentation off",
      status.streaming ? "streaming" : "no stream",
    ].filter((fact): fact is string => fact !== null).join(" · ");
    const banner = `<div class="notice notice--success"><span class="notice__icon">${icon("check", { size: 18 })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(status.message)}</p><p class="t-small t-subtle">${facts}</p></div></div>`;
    return `${banner}${androidDiagnosticNotices(status)}`;
  }
  const progress = `<div class="notice"><span class="notice__icon">${icon("refresh", { size: 18, className: "spinner" })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(status.message)}</p><p class="t-small t-subtle">This can take a few minutes, especially in software mode.</p></div></div>`;
  return `${progress}${androidStepsMarkup(status)}${androidDiagnosticNotices(status)}`;
}

/**
 * Mounts or unmounts the embedded ws-scrcpy screen. It is mounted exactly once
 * per live stream: re-rendering the iframe on a status poll would reload and reset
 * the stream, so a mounted screen is left untouched until the stream ends.
 */
function updateAndroidScreen(status: AndroidTargetStatus): void {
  if (androidScreen === null) return;
  const canStream = status.phase === "ready" && status.streaming;
  if (canStream) {
    if (androidScreenMounted) return;
    const src = `/android-stream/?token=${encodeURIComponent(operatorToken)}`;
    androidScreen.innerHTML = `<iframe class="android-screen__frame" title="Android target screen" src="${escapeHtml(src)}" allow="clipboard-read; clipboard-write"></iframe>`;
    androidScreenMounted = true;
    return;
  }
  androidScreenMounted = false;
  let body: string;
  if (!status.addonPresent) body = "Install the Android target add-on to stream a device screen.";
  else if (status.phase === "ready") body = "The target is running, but its streaming components are not installed. Reinstall the add-on to enable the screen.";
  else if (status.phase === "idle" || status.phase === "error") body = "Launch the Android target to see and drive its screen here.";
  else body = "The screen appears here once the target finishes provisioning and the stream starts.";
  androidScreen.innerHTML = stateBlock({ icon: "traffic", title: "Screen", body });
}

function renderAndroidStatus(status: AndroidTargetStatus): void {
  if (androidPhaseBadge !== null) androidPhaseBadge.textContent = status.phase;
  const inFlight = status.phase === "booting" || status.phase === "provisioning" || status.phase === "streaming";
  if (androidLaunch !== null) {
    androidLaunch.disabled = inFlight || !status.addonPresent;
    androidLaunch.hidden = status.phase === "ready";
  }
  if (androidStop !== null) androidStop.hidden = !(inFlight || status.phase === "ready");
  if (androidInstallPanel !== null) androidInstallPanel.hidden = status.phase !== "ready";
  if (androidStatus !== null) { androidStatus.innerHTML = androidStatusBody(status); hydrateIcons(androidStatus); }
  updateAndroidScreen(status);
}

function renderAndroidUnavailable(): void {
  if (androidStatus !== null) {
    androidStatus.innerHTML = stateBlock({ icon: "lock", title: "Workbench session not ready", body: "The operator token is not available yet. Reload once the local engine is up." });
    hydrateIcons(androidStatus);
  }
  if (androidLaunch !== null) androidLaunch.disabled = true;
}

async function refreshAndroidStatus(): Promise<void> {
  if (operatorToken === "") { renderAndroidUnavailable(); return; }
  try {
    const response = await fetch("/api/v1/android-target/status", { headers: pairingHeaders() });
    if (!response.ok) return;
    renderAndroidStatus((await response.json()) as AndroidTargetStatus);
  } catch { /* transient; the next poll retries */ }
}

async function launchAndroidTarget(): Promise<void> {
  if (operatorToken === "") return;
  await withBusy(androidLaunch, "Launching…", async () => {
    const response = await fetch("/api/v1/android-target/launch", { method: "POST", headers: pairingHeaders() });
    if (response.ok) renderAndroidStatus((await response.json()) as AndroidTargetStatus);
    else showDiagnostic((await response.json()) as Diagnostic);
  });
}

async function stopAndroidTarget(): Promise<void> {
  if (operatorToken === "") return;
  await withBusy(androidStop, "Stopping…", async () => {
    androidScreenMounted = false;
    const response = await fetch("/api/v1/android-target/stop", { method: "POST", headers: pairingHeaders() });
    if (response.ok) renderAndroidStatus((await response.json()) as AndroidTargetStatus);
  });
}

async function installTargetApk(): Promise<void> {
  const path = androidApkPath?.value.trim() ?? "";
  if (path === "") { toast("Enter the full path to the APK you want to install."); androidApkPath?.focus(); return; }
  await withBusy(androidApkInstall, "Installing…", async () => {
    const response = await fetch("/api/v1/android-target/install-apk", { method: "POST", headers: pairingHeaders(true), body: JSON.stringify({ path }) });
    if (response.status === 204) toast("Installed. Open the app on the screen and drive it — its traffic flows to the workbench.");
    else showDiagnostic((await response.json()) as Diagnostic);
  });
}

/** Native file picker for the target APK (same pattern as the APK analysis view). */
async function browseForAndroidApk(): Promise<void> {
  try {
    const response = await fetch("/api/v1/pick-file", { method: "POST" });
    if (response.ok) {
      const result = (await response.json()) as { available: boolean; path: string | null };
      if (result.available) {
        if (result.path !== null && result.path !== "" && androidApkPath !== null) { androidApkPath.value = result.path; androidApkPath.focus(); }
        return;
      }
    }
  } catch { /* fall through to the browser file input */ }
  androidApkFile?.click();
}

function enterAndroidView(): void {
  void refreshAndroidStatus();
  if (androidPoll === undefined) androidPoll = window.setInterval(() => void refreshAndroidStatus(), 1000);
}

/** Stops the status poll when the Android target view is left. */
function leaveAndroidView(): void {
  if (androidPoll !== undefined) { window.clearInterval(androidPoll); androidPoll = undefined; }
}

/* ==================================================================== *
 * Encoding helpers
 * ==================================================================== */

function parseHeaders(value: string): [string, string][] {
  return value.split("\n").filter((line) => line.includes(":")).map((line) => {
    const separator = line.indexOf(":");
    return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
  });
}

function formatHeaders(headers: readonly [string, string][]): string {
  return headers.map(([name, value]) => `${name}: ${value}`).join("\n") || "(none)";
}

function bytesToText(body: number[] | null | undefined): string {
  return body === null || body === undefined
    ? ""
    : new TextDecoder().decode(new Uint8Array(body));
}

void boot();
