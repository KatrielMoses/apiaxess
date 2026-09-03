import "./styles/index.css";

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
interface RepeaterRequest { method: string; url: string; headers: [string, string][]; body?: number[] | null; }
interface RepeaterResponse { status: number; headers: readonly [string, string][]; body?: number[]; durationMs: number; }
interface RepeaterRevision { revision: number; sentAt: string; request: RepeaterRequest; response?: RepeaterResponse | null; diagnostic?: Diagnostic | null; scope: string; }
interface RepeaterContext { id: string; sourceFlowId?: number; createdAt: string; current: RepeaterRequest; history: RepeaterRevision[]; }
interface RepeaterSendResult { context: RepeaterContext; revision: RepeaterRevision; diagnostics: (Diagnostic | null)[]; }
interface IntruderResult { ordinal: number; payloads: string[]; response?: { status: number; body?: number[] | null; durationMs: number } | null; matched: boolean; filtered: boolean; diff: { statusChanged: boolean; sizeChanged: boolean; sizeDelta: number; contentChanged: boolean }; diagnostic?: Diagnostic | null; }
type IntruderLocation = "url" | "header" | "body";
interface IntruderPosition { location: IntruderLocation; headerName?: string | null; start: number; end: number; setIndex: number; }
interface IntruderPayloadSet { name: string; values: string[]; }
interface IntruderMatchFilter { statuses: number[]; minSize?: number | null; maxSize?: number | null; contains?: string | null; regex?: string | null; }
interface IntruderConfig { baseRequest: RepeaterRequest; positions: IntruderPosition[]; payloadSets: IntruderPayloadSet[]; attackType: string; matchFilter: IntruderMatchFilter; concurrency: number; ratePerSecond: number; maxResults: number; authPreflight?: RepeaterRequest | null; sequence?: unknown[]; }
interface IntruderJob { id: string; tier: "ffuf" | "native"; state: string; config: IntruderConfig; results: IntruderResult[]; diagnostics: (Diagnostic | null)[]; }
interface CredentialPromptMsg { readonly id: number; readonly package: string; readonly screenSummary: string; readonly reason: string; readonly fields: readonly CredentialDialogField[]; }
interface LiveUpdate { readonly flows: readonly FlowSummary[]; readonly diagnostics: readonly Diagnostic[]; readonly prompts?: readonly CredentialPromptMsg[]; }
interface PipelineRun { readonly runId: string; readonly artifactPath: string; readonly stage: string; readonly status: "running" | "completed" | "failed"; readonly progressBasisPoints: number; readonly message: string; readonly diagnostics: (Diagnostic | null)[]; readonly dynamicRan: boolean; readonly updatedAt: string; readonly surfaceAvailable: boolean; }
interface SurfaceSummary { readonly schemaVersion: number; readonly assemblyRunId: string; readonly endpoints: readonly { readonly method: string; readonly pathTemplate: string; readonly minimumFactConfidence?: number | null; readonly signerCount: number }[]; readonly coverage: { readonly endpointCount: number; readonly confirmedEndpointCount: number; readonly inferredEndpointCount: number; readonly staticOnlyEndpointCount: number; readonly openHandoffCount: number; readonly resolvedHandoffCount: number }; readonly signerCount: number; readonly diagnostics: (Diagnostic | null)[]; }
interface DiscoveryEstimate { target: string; requestCount: number; ratePerSecond: number; estimatedLabel: string; }
interface BrowserLaunchStatus { running: boolean; browser?: string | null; target?: string | null; pid?: number | null; cdpConnected?: boolean; debugPort?: number | null; }
interface TargetIdentifier { readonly kind: string; readonly value: string; }
interface SessionStatus { readonly sessionId: string; readonly lifecycle: string; readonly artifactPath: string; readonly storePath: string; readonly flowCount: number; readonly repeaterCount: number; readonly intruderCount: number; readonly scopeConfigured: boolean; readonly recoveredFromCheckpoint: boolean; readonly lastCheckpointAt?: string | null; readonly scope?: { readonly declared_at?: string; readonly target?: { readonly target_type?: string; readonly primary?: TargetIdentifier } }; readonly analysisPipeline?: { readonly run_id?: string; readonly artifact_path?: string } | null; }
interface AuditActionDescriptor { readonly kind: string; readonly summary: string; }
interface AuditRecord { readonly id: string; readonly occurred_at: string; readonly action: AuditActionDescriptor; readonly outcome: string; readonly diagnostics: (Diagnostic | null)[]; }

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
const repeaterPanel = document.querySelector<HTMLElement>("#repeater-panel");
const intruderPanel = document.querySelector<HTMLElement>("#intruder-panel");
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

/* ==================================================================== *
 * State
 * ==================================================================== */

const flows = new Map<number, FlowSummary>();
const pending = new Set<number>();
const diagnostics = new DiagnosticsLog();
let selectedFlow: FlowDetail | null = null;
let control: WebSocket | null = null;
let selectedRepeater: RepeaterContext | null = null;
let selectedIntruder: IntruderJob | null = null;
let discoveryJob: IntruderJob | null = null;
let lastDiscoveryEstimate: DiscoveryEstimate | null = null;
let intruderPoll: number | undefined;
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

/** The send-to-repeater / send-to-intruder affordances for the selected flow. */
function renderDetailActions(flowId: number): void {
  if (detailActions === null) return;
  detailActions.replaceChildren();

  const repeater = document.createElement("button");
  repeater.type = "button";
  repeater.className = "btn btn--sm";
  repeater.innerHTML = `${icon("send", { size: 14 })}<span>Repeater</span>`;
  repeater.addEventListener("click", () => void createRepeater(flowId));

  const intruder = document.createElement("button");
  intruder.type = "button";
  intruder.className = "btn btn--sm";
  intruder.innerHTML = `${icon("discovery", { size: 14 })}<span>Intruder</span>`;
  intruder.addEventListener("click", () => void openIntruder(flowId));

  detailActions.append(repeater, intruder);
}

function renderDetailEmpty(): void {
  if (detail === null) return;
  detail.innerHTML = stateBlock({
    icon: "chevronRight",
    title: "No flow selected",
    body: "Choose a row from live traffic to load its request and response metadata, then send it to the repeater or the intruder.",
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
<section class="stack stack--tight">
  <p class="section-label">Request headers</p>
  <pre class="code">${escapeHtml(formatHeaders(flow.requestHeaders))}</pre>
  <p class="t-small t-subtle">${escapeHtml(body(flow.requestBody))}</p>
</section>
<section class="stack stack--tight">
  <p class="section-label">Response headers</p>
  <pre class="code">${escapeHtml(formatHeaders(flow.responseHeaders))}</pre>
  <p class="t-small t-subtle">${escapeHtml(body(flow.responseBody))}</p>
</section>
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
 * 7. Workbench — intruder
 * ==================================================================== */

async function openIntruder(flowId: number): Promise<void> {
  if (selectedFlow === null || selectedFlow.summary.id !== flowId) return;
  selectedIntruder = {
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
  renderIntruder();
  revealDrawer(intruderPanel);
}

/** Config is only editable before the job is created; the backend snapshots it. */
function intruderConfigLocked(): boolean {
  return selectedIntruder !== null && selectedIntruder.id !== "";
}

/** Text of the field a payload position substitutes into, for live preview. */
function positionFieldText(config: IntruderConfig, position: IntruderPosition): string {
  if (position.location === "url") return config.baseRequest.url;
  if (position.location === "body") return bytesToText(config.baseRequest.body);
  const name = (position.headerName ?? "").toLowerCase();
  return config.baseRequest.headers.find(([header]) => header.toLowerCase() === name)?.[1] ?? "";
}

/** Snapshots the current form inputs back into the draft config. */
function readIntruderForm(): void {
  if (selectedIntruder === null || intruderConfigLocked() || intruderPanel === null) return;
  const config = selectedIntruder.config;

  const sets: IntruderPayloadSet[] = [];
  intruderPanel.querySelectorAll<HTMLElement>("[data-set-row]").forEach((row) => {
    const j = row.dataset.setRow ?? "0";
    const name = valueOfIntruder(`#set-name-${j}`).trim() || `set ${Number(j) + 1}`;
    const values = valueOfIntruder(`#set-values-${j}`).split("\n").map((value) => value.trim()).filter(Boolean);
    sets.push({ name, values });
  });
  if (sets.length > 0) config.payloadSets = sets;

  const positions: IntruderPosition[] = [];
  intruderPanel.querySelectorAll<HTMLElement>("[data-position-row]").forEach((row) => {
    const i = row.dataset.positionRow ?? "0";
    const location = (valueOfIntruder(`#pos-location-${i}`) || "url") as IntruderLocation;
    const headerName = location === "header" ? (valueOfIntruder(`#pos-header-${i}`).trim() || null) : null;
    const start = Math.max(0, Math.floor(Number(valueOfIntruder(`#pos-start-${i}`)) || 0));
    const end = Math.max(start, Math.floor(Number(valueOfIntruder(`#pos-end-${i}`)) || 0));
    let setIndex = Math.floor(Number(valueOfIntruder(`#pos-set-${i}`)) || 0);
    if (setIndex >= config.payloadSets.length) setIndex = Math.max(0, config.payloadSets.length - 1);
    positions.push({ location, headerName, start, end, setIndex });
  });
  if (positions.length > 0) config.positions = positions;

  config.attackType = valueOfIntruder("#intruder-type") || "sniper";
  config.maxResults = Math.max(1, Math.floor(Number(valueOfIntruder("#intruder-max")) || 100));
  config.concurrency = Math.max(1, Math.floor(Number(valueOfIntruder("#intruder-concurrency")) || 1));
  config.ratePerSecond = Math.max(0, Math.floor(Number(valueOfIntruder("#intruder-rate")) || 0));

  const statuses = valueOfIntruder("#match-statuses").split(",").map((value) => Number(value.trim())).filter((value) => Number.isFinite(value) && value > 0);
  const parseSize = (raw: string): number | null => { const trimmed = raw.trim(); if (trimmed === "") return null; const n = Number(trimmed); return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : null; };
  const contains = valueOfIntruder("#match-contains");
  const regex = valueOfIntruder("#match-regex").trim();
  config.matchFilter = { statuses, minSize: parseSize(valueOfIntruder("#match-min")), maxSize: parseSize(valueOfIntruder("#match-max")), contains: contains === "" ? null : contains, regex: regex === "" ? null : regex };

  const seqRaw = valueOfIntruder("#intruder-sequence").trim();
  if (seqRaw === "") { config.sequence = []; }
  else { try { const parsed: unknown = JSON.parse(seqRaw); if (Array.isArray(parsed)) config.sequence = parsed; } catch { /* validated on launch */ } }
}

function addIntruderPosition(): void { if (selectedIntruder === null) return; readIntruderForm(); selectedIntruder.config.positions.push({ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }); renderIntruder(); }
function removeIntruderPosition(index: number): void { if (selectedIntruder === null) return; readIntruderForm(); selectedIntruder.config.positions.splice(index, 1); if (selectedIntruder.config.positions.length === 0) selectedIntruder.config.positions.push({ location: "url", headerName: null, start: 0, end: 0, setIndex: 0 }); renderIntruder(); }
function addIntruderSet(): void { if (selectedIntruder === null) return; readIntruderForm(); selectedIntruder.config.payloadSets.push({ name: `set ${selectedIntruder.config.payloadSets.length + 1}`, values: [] }); renderIntruder(); }
function removeIntruderSet(index: number): void { if (selectedIntruder === null) return; readIntruderForm(); const config = selectedIntruder.config; config.payloadSets.splice(index, 1); if (config.payloadSets.length === 0) config.payloadSets.push({ name: "set 1", values: [] }); config.positions.forEach((position) => { if (position.setIndex >= config.payloadSets.length) position.setIndex = config.payloadSets.length - 1; }); renderIntruder(); }

function renderIntruderPositionRow(config: IntruderConfig, position: IntruderPosition, index: number, locked: boolean): string {
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

function renderIntruderSetRow(set: IntruderPayloadSet, index: number, locked: boolean): string {
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

function renderIntruder(): void {
  if (intruderPanel === null || selectedIntruder === null) return;
  intruderPanel.hidden = false;
  const config = selectedIntruder.config;
  const locked = intruderConfigLocked();
  const disabled = locked ? "disabled" : "";
  const filter = config.matchFilter;
  const sequence = Array.isArray(config.sequence) ? config.sequence : [];
  const launchLabel = locked && selectedIntruder.state === "paused" ? "Resume" : locked ? "Start" : "Create attack";
  const sequencePlaceholder = escapeHtml('[{"name":"login","request":{"method":"POST","url":"https://target/login","headers":[]},"extractors":[]}]');
  const opt = (value: string, label: string, selected: boolean): string => `<option value="${value}"${selected ? " selected" : ""}>${label}</option>`;
  const attackHint = config.positions.length <= 1 || config.payloadSets.length <= 1
    ? "With a single position and set, all attack types are equivalent. Add positions/sets for Clusterbomb (every combination) or Pitchfork (paired by row)."
    : config.attackType === "clusterbomb" ? "Clusterbomb: every combination across sets."
    : config.attackType === "pitchfork" ? "Pitchfork: values paired by row across sets (shortest set wins)."
    : "Sniper: one position at a time using its set.";

  intruderPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("discovery", { size: 16 })}<h2>Intruder · ${escapeHtml(selectedIntruder.id === "" ? "new attack" : selectedIntruder.id.slice(-8))}</h2></div>
  <div class="row">
    <span class="badge">${escapeHtml(selectedIntruder.tier)}</span>
    <span class="badge ${selectedIntruder.state === "running" ? "badge--accent" : selectedIntruder.state === "failed" ? "badge--danger" : ""}">${escapeHtml(selectedIntruder.state)}</span>
    <button class="btn btn--quiet btn--icon" type="button" data-close-intruder><span class="visually-hidden">Close intruder</span>${icon("close", { size: 16 })}</button>
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
      <label class="field__label" for="intruder-type">Attack type</label>
      <select class="select" id="intruder-type" ${disabled}>${opt("sniper", "Sniper", config.attackType === "sniper")}${opt("clusterbomb", "Clusterbomb", config.attackType === "clusterbomb")}${opt("pitchfork", "Pitchfork", config.attackType === "pitchfork")}</select>
      <p class="field__hint">${escapeHtml(attackHint)}</p>
    </div>
    <div class="split-3">
      <div class="field"><label class="field__label" for="intruder-concurrency">Concurrency</label><input class="input input--mono" id="intruder-concurrency" type="number" min="1" value="${config.concurrency}" ${disabled} /></div>
      <div class="field"><label class="field__label" for="intruder-rate">Rate/s</label><input class="input input--mono" id="intruder-rate" type="number" min="0" value="${config.ratePerSecond}" ${disabled} /><p class="field__hint">0 = unlimited</p></div>
      <div class="field"><label class="field__label" for="intruder-max">Max results</label><input class="input input--mono" id="intruder-max" type="number" min="1" value="${config.maxResults}" ${disabled} /></div>
    </div>
  </div>

  <div class="stack stack--tight">
    <div class="row"><p class="section-label">Payload positions</p><span class="spacer"></span>${locked ? "" : `<button class="btn btn--sm" type="button" data-add-pos>${icon("plus", { size: 12 })}<span>Add position</span></button>`}</div>
    ${config.positions.map((position, index) => renderIntruderPositionRow(config, position, index, locked)).join("")}
  </div>

  <div class="stack stack--tight">
    <div class="row"><p class="section-label">Payload sets</p><span class="spacer"></span>${locked ? "" : `<button class="btn btn--sm" type="button" data-add-set>${icon("plus", { size: 12 })}<span>Add set</span></button>`}</div>
    ${config.payloadSets.map((set, index) => renderIntruderSetRow(set, index, locked)).join("")}
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
    <label class="field__label" for="intruder-sequence">Native token-chain sequence (JSON, optional)</label>
    <textarea class="textarea" id="intruder-sequence" spellcheck="false" placeholder="${sequencePlaceholder}" ${disabled}>${escapeHtml(sequence.length === 0 ? "" : JSON.stringify(sequence, null, 2))}</textarea>
    <p class="field__hint">Stateful native attacks: each step may extract <code class="t-mono">{{variable}}</code> values for later requests.</p>
  </div>

  <div class="row">
    ${selectedIntruder.state === "running" ? "" : `<button class="btn btn--primary" id="intruder-launch" type="button">${icon("play", { size: 14 })}<span>${escapeHtml(launchLabel)}</span></button>`}
    <button class="btn" id="intruder-pause" type="button">${icon("pause", { size: 14 })}<span>Pause</span></button>
    <button class="btn btn--danger" id="intruder-stop" type="button">${icon("stop", { size: 14 })}<span>Stop</span></button>
  </div>

  <div id="intruder-results">${renderIntruderResults(selectedIntruder.results)}</div>
</div>`;

  intruderPanel.querySelector("#intruder-launch")?.addEventListener("click", () => void launchIntruder());
  intruderPanel.querySelector("#intruder-pause")?.addEventListener("click", () => void pauseIntruder());
  intruderPanel.querySelector("#intruder-stop")?.addEventListener("click", () => void stopIntruder());
  intruderPanel.querySelector("[data-add-pos]")?.addEventListener("click", () => addIntruderPosition());
  intruderPanel.querySelector("[data-add-set]")?.addEventListener("click", () => addIntruderSet());
  intruderPanel.querySelectorAll<HTMLButtonElement>("[data-remove-pos]").forEach((button) => button.addEventListener("click", () => removeIntruderPosition(Number(button.dataset.removePos))));
  intruderPanel.querySelectorAll<HTMLButtonElement>("[data-remove-set]").forEach((button) => button.addEventListener("click", () => removeIntruderSet(Number(button.dataset.removeSet))));
  // A location change toggles the header-name field and refreshes the preview.
  intruderPanel.querySelectorAll<HTMLSelectElement>('[id^="pos-location-"]').forEach((select) => select.addEventListener("change", () => { readIntruderForm(); renderIntruder(); }));
  // Offset edits refresh their row's live preview without a full rebuild.
  intruderPanel.querySelectorAll<HTMLInputElement>('[id^="pos-start-"], [id^="pos-end-"]').forEach((input) => input.addEventListener("change", () => { readIntruderForm(); renderIntruder(); }));
  intruderPanel.querySelector("[data-close-intruder]")?.addEventListener("click", () => {
    intruderPanel.hidden = true;
    if (intruderPoll !== undefined) { window.clearInterval(intruderPoll); intruderPoll = undefined; }
  });
}

function renderIntruderResults(results: readonly IntruderResult[]): string {
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

async function launchIntruder(): Promise<void> {
  if (selectedIntruder === null) return;
  try {
    if (selectedIntruder.id === "") {
      readIntruderForm();
      const config = selectedIntruder.config;
      // Validate the token-chain sequence JSON before committing the job.
      const seqRaw = valueOfIntruder("#intruder-sequence").trim();
      if (seqRaw !== "") { try { const parsed: unknown = JSON.parse(seqRaw); if (!Array.isArray(parsed)) throw new Error("sequence must be a JSON array"); config.sequence = parsed; } catch (error) { showDiagnostic({ id: "proxy.intruder-config-invalid", what: "The token-chain sequence is invalid JSON.", why: String(error), fix: "Enter a JSON array of named request steps and retry." }); return; } }
      if (config.positions.length === 0) { showDiagnostic({ id: "proxy.intruder-config-invalid", what: "The attack has no payload positions.", why: "At least one marked position is required to substitute payloads.", fix: "Add a position and mark the bytes to replace, then start the attack." }); return; }
      if (config.payloadSets.every((set) => set.values.length === 0) && config.sequence?.length === 0) { showDiagnostic({ id: "proxy.intruder-config-invalid", what: "No payloads were supplied.", why: "Every payload set is empty, so there is nothing to send.", fix: "Enter at least one payload value, one per line." }); return; }
      const created = await fetch("/api/v1/workbench/intruder", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(config) });
      await requireOk(created, "intruder configuration failed");
      selectedIntruder = (await created.json()) as IntruderJob;
    }
    const action = selectedIntruder.state === "paused" ? "resume" : "start";
    const started = await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(selectedIntruder.id) + "/" + action, { method: "POST" });
    await requireOk(started, "intruder " + action + " failed");
    selectedIntruder = (await started.json()) as IntruderJob;
    renderIntruder();
    if (intruderPoll !== undefined) window.clearInterval(intruderPoll);
    intruderPoll = window.setInterval(() => void refreshIntruder(), 500);
  } catch (error) {
    reportUnexpected(error, { id: "proxy.intruder-config-invalid", what: "The intruder job could not start.", why: "", fix: "Check payload positions, payloads, and the session proxy/tool configuration." });
  }
}

async function refreshIntruder(): Promise<void> {
  if (selectedIntruder === null || selectedIntruder.id === "") return;
  try {
    const response = await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(selectedIntruder.id));
    await requireOk(response, "intruder status unavailable");
    selectedIntruder = (await response.json()) as IntruderJob;
    selectedIntruder.diagnostics.forEach(showDiagnostic);
    renderIntruder();
    if (["completed", "failed", "stopped"].includes(selectedIntruder.state) && intruderPoll !== undefined) { window.clearInterval(intruderPoll); intruderPoll = undefined; }
  } catch (error) {
    if (intruderPoll !== undefined) { window.clearInterval(intruderPoll); intruderPoll = undefined; }
    reportUnexpected(error, { id: "proxy.intruder-config-invalid", what: "The intruder status could not be loaded.", why: "", fix: "Check the active session and retry." });
  }
}

async function stopIntruder(): Promise<void> {
  if (selectedIntruder === null || selectedIntruder.id === "") return;
  try {
    await requireOk(await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(selectedIntruder.id) + "/stop", { method: "POST" }), "intruder stop failed");
    await refreshIntruder();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.intruder-config-invalid", what: "The intruder job could not stop.", why: "", fix: "Check the active session and retry." });
  }
}

async function pauseIntruder(): Promise<void> {
  if (selectedIntruder === null || selectedIntruder.id === "") return;
  try {
    const response = await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(selectedIntruder.id) + "/pause", { method: "POST" });
    await requireOk(response, "intruder pause failed");
    selectedIntruder = (await response.json()) as IntruderJob;
    renderIntruder();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.intruder-config-invalid", what: "The intruder job could not pause.", why: "", fix: "Pause only at a request boundary while the job is running." });
  }
}

function valueOfIntruder(selector: string): string { return intruderPanel?.querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(selector)?.value ?? ""; }

/* ==================================================================== *
 * 7. Workbench — repeater
 * ==================================================================== */

async function createRepeater(flowId: number): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/repeater", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ flowId }) });
    await requireOk(response, "repeater context unavailable");
    selectedRepeater = (await response.json()) as RepeaterContext;
    renderRepeater();
    revealDrawer(repeaterPanel);
  } catch (error) {
    reportUnexpected(error, { id: "proxy.repeater-history-failed", what: "The repeater context could not be created.", why: "", fix: "Check the selected flow and session store, then retry." });
  }
}

function renderRepeater(): void {
  if (repeaterPanel === null || selectedRepeater === null) return;
  repeaterPanel.hidden = false;
  repeaterPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("send", { size: 16 })}<h2>Repeater · ${escapeHtml(selectedRepeater.id.slice(-8))}</h2></div>
  <div class="row">
    <span class="panel__hint">append-only history</span>
    <button class="btn btn--quiet btn--icon" type="button" data-close-repeater><span class="visually-hidden">Close repeater</span>${icon("close", { size: 16 })}</button>
  </div>
</div>
<div class="panel__body stack">
  <div class="split-2">
    <div class="field">
      <label class="field__label" for="repeater-method">Method</label>
      <input class="input input--mono" id="repeater-method" value="${escapeHtml(selectedRepeater.current.method)}" />
    </div>
    <div class="field">
      <label class="field__label" for="repeater-url">URL</label>
      <input class="input input--mono" id="repeater-url" value="${escapeHtml(selectedRepeater.current.url)}" />
    </div>
  </div>
  <div class="split-2">
    <div class="field">
      <label class="field__label" for="repeater-headers">Headers</label>
      <textarea class="textarea" id="repeater-headers" spellcheck="false">${escapeHtml(formatHeaders(selectedRepeater.current.headers))}</textarea>
    </div>
    <div class="field">
      <label class="field__label" for="repeater-body">Body</label>
      <textarea class="textarea textarea--wrap" id="repeater-body" spellcheck="false">${escapeHtml(bytesToText(selectedRepeater.current.body))}</textarea>
    </div>
  </div>
  <div class="row">
    <button class="btn btn--primary" id="repeater-send" type="button">${icon("send", { size: 14 })}<span>Send request</span></button>
  </div>
  <div id="repeater-response">${renderRepeaterHistory(selectedRepeater.history)}</div>
</div>`;
  repeaterPanel.querySelector("#repeater-send")?.addEventListener("click", () => void sendRepeater());
  repeaterPanel.querySelectorAll<HTMLButtonElement>("[data-derive]").forEach((button) => button.addEventListener("click", () => void deriveRepeater(Number(button.dataset.derive))));
  repeaterPanel.querySelector("[data-close-repeater]")?.addEventListener("click", () => { repeaterPanel.hidden = true; });
}

function renderRepeaterHistory(history: readonly RepeaterRevision[]): string {
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

async function sendRepeater(): Promise<void> {
  const repeater = selectedRepeater;
  if (repeater === null) return;
  const repeaterId = repeater.id;
  const request: RepeaterRequest = { method: valueOf("#repeater-method"), url: valueOf("#repeater-url"), headers: parseHeaders(valueOf("#repeater-headers")), body: [...new TextEncoder().encode(valueOf("#repeater-body"))] };
  try {
    const update = await fetch("/api/v1/workbench/repeater/" + encodeURIComponent(repeaterId), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(request) });
    await requireOk(update, "repeater edit failed");
    const sent = await fetch("/api/v1/workbench/repeater/" + encodeURIComponent(repeaterId) + "/send", { method: "POST" });
    await requireOk(sent, "repeater send failed");
    const result = (await sent.json()) as Partial<RepeaterSendResult>;
    let context = result.context;
    if (context === null || context === undefined || typeof context.id !== "string") {
      const refreshed = await fetch("/api/v1/workbench/repeater/" + encodeURIComponent(repeaterId));
      await requireOk(refreshed, "repeater history refresh failed");
      context = (await refreshed.json()) as RepeaterContext;
    }
    if (context === null || typeof context.id !== "string") throw new Error("repeater response did not include a valid context");
    selectedRepeater = context;
    (result.diagnostics ?? []).forEach(showDiagnostic);
    showDiagnostic(result.revision?.diagnostic);
    renderRepeater();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.repeater-request-failed", what: "The repeater send failed.", why: "", fix: "Review the request and confirm the session proxy is running." });
  }
}

async function deriveRepeater(revision: number): Promise<void> {
  if (selectedRepeater === null) return;
  try {
    const response = await fetch("/api/v1/workbench/repeater/" + encodeURIComponent(selectedRepeater.id) + "/derive/" + revision, { method: "POST" });
    await requireOk(response, "repeater derivation failed");
    selectedRepeater = (await response.json()) as RepeaterContext;
    renderRepeater();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.repeater-request-failed", what: "The repeater request could not be derived.", why: "", fix: "Check the selected revision and session store, then retry." });
  }
}

function valueOf(selector: string): string { return repeaterPanel?.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)?.value ?? ""; }

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
  const stages = pipelineStages.slice(0, -1).map((stage, index) => {
    const done = index < stageIndex || run.status === "completed";
    const active = stage === run.stage && run.status === "running";
    return `<span class="stage ${done ? "is-done" : ""} ${active ? "is-active" : ""}"><span class="stage__marker"></span>${escapeHtml(STAGE_LABELS[stage] ?? stage)}</span>`;
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

function renderSurface(surface: SurfaceSummary): void {
  if (surfaceView === null) return;
  const coverage = surface.coverage;
  const endpointRows = surface.endpoints.map((entry) => {
    const confidence = entry.minimumFactConfidence;
    const percent = confidence === null || confidence === undefined ? null : Math.round(confidence * 100);
    const band = percent === null ? "" : percent >= 80 ? " confidence--high" : percent < 50 ? " confidence--low" : "";
    const confidenceHtml = percent === null
      ? '<span class="t-subtle">unscored</span>'
      : `<span class="confidence${band}" title="Minimum supporting fact confidence"><span class="confidence__track"><span class="confidence__fill" style="width:${percent}%"></span></span>${percent}%</span>`;
    const method = entry.method.toUpperCase();
    return `<div class="endpoint-row">
<span class="list-row__method" data-method="${escapeHtml(method)}">${escapeHtml(method)}</span>
<span class="endpoint-row__path" title="${escapeHtml(entry.pathTemplate)}">${escapeHtml(entry.pathTemplate)}</span>
<span class="endpoint-row__meta">${confidenceHtml}<span class="badge">${entry.signerCount} signer${entry.signerCount === 1 ? "" : "s"}</span></span>
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
  surface.diagnostics.forEach(showDiagnostic);
}

function renderSurfaceEmpty(): void {
  if (surfaceView === null) return;
  surfaceView.innerHTML = stateBlock({
    icon: "surface",
    title: "No surface assembled yet",
    body: "Run the APK pipeline to completion, or capture web traffic and fuse it. The assembled surface, its coverage, and its provenance appear here.",
  });
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
    return {
      method: String(identity.method ?? ""),
      pathTemplate: String(identity.path_template ?? identity.pathTemplate ?? ""),
      minimumFactConfidence: scores.length === 0 ? undefined : Math.min(...scores),
      signerCount: Array.isArray(entry.signers) ? entry.signers.length : 0,
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

function connect(session: WorkbenchSession): void {
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  control = new WebSocket(`${scheme}://${location.host}/api/v1/workbench/ws/control?token=${encodeURIComponent(session.authToken)}`);
  const telemetry = new WebSocket(`${scheme}://${location.host}/api/v1/workbench/ws/telemetry?token=${encodeURIComponent(session.authToken)}`);
  control.onopen = () => setStatus("Live control connected", "ready");
  control.onclose = () => setStatus("Control channel closed", "unavailable");
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
  telemetry.onclose = () => setStatus("Telemetry channel closed", "unavailable");
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
  const hasWork = current !== null && (current.flowCount > 0 || current.repeaterCount > 0 || current.intruderCount > 0 || current.scopeConfigured);
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

function discoveryRequestBody(): string {
  return JSON.stringify({ kind: discoveryKind?.value ?? "directory", wordlist: discoveryWordlist?.value ?? "small" });
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
    const response = await fetch("/api/v1/discovery/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind: discoveryKind?.value ?? "directory", wordlist: discoveryWordlist?.value ?? "small", confirmed: true }) });
    await requireOk(response, "discovery could not start");
    discoveryJob = await response.json() as IntruderJob;
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
  const response = await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(discoveryJob.id));
  if (!response.ok) return;
  discoveryJob = await response.json() as IntruderJob;
  renderDiscovery();
  if (["completed", "failed", "stopped"].includes(discoveryJob.state) && discoveryPoll !== undefined) {
    window.clearInterval(discoveryPoll);
    discoveryPoll = undefined;
  }
}

async function stopDiscovery(): Promise<void> {
  if (discoveryJob === null) return;
  await fetch("/api/v1/workbench/intruder/" + encodeURIComponent(discoveryJob.id) + "/stop", { method: "POST" });
  await refreshDiscovery();
  toast("Discovery cancelled");
}

/* ==================================================================== *
 * Fusion
 * ==================================================================== */

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
  if (sessionDetail === null) return;
  sessionDetail.innerHTML = `<div class="stack">
<div class="metric-grid">
  <div class="metric"><span class="metric__value">${status.flowCount}</span><span class="metric__label">flows</span></div>
  <div class="metric"><span class="metric__value">${status.repeaterCount}</span><span class="metric__label">repeaters</span></div>
  <div class="metric"><span class="metric__value">${status.intruderCount}</span><span class="metric__label">intruder jobs</span></div>
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
    message: "Enter the path to a session artifact on this machine. Captured traffic, repeater history, intruder jobs, and the audit trail are restored with it.",
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
document.querySelector("#web-fuse")?.addEventListener("click", () => void fuseWebTraffic());
document.querySelector("#web-export")?.addEventListener("click", () => showView("export"));
document.querySelector("#apk-run")?.addEventListener("click", () => void startPipeline());
document.querySelector("#apk-refresh")?.addEventListener("click", () => void refreshPipeline());
document.querySelector("#apk-browse")?.addEventListener("click", () => apkFile?.click());
apkFile?.addEventListener("change", () => {
  const file = apkFile.files?.[0];
  if (file === undefined || apkPath === null) return;
  // Browsers expose only the file name, never the full path. Fill what is
  // available and say so, rather than silently producing an unreadable path.
  apkPath.value = file.name;
  apkPath.focus();
  toast("Prefix the file name with its full directory path so the engine can read it.");
});
document.querySelector("#export-run")?.addEventListener("click", () => void runExport());
document.querySelector("#session-new")?.addEventListener("click", () => void newSession());
document.querySelector("#session-open")?.addEventListener("click", () => void openSession());
document.querySelector("#session-save")?.addEventListener("click", () => void saveSession());
document.querySelector("#surface-refresh")?.addEventListener("click", () => void refreshStoredSurface());

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
  if (lockup !== null) lockup.innerHTML = lockupHtml(22);
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
    if (view === "settings") void refreshSettings();
  });
  document
    .querySelector<HTMLButtonElement>("#settings-save")
    ?.addEventListener("click", () => void saveSettings());

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
 * Reopens durable repeater and intruder state after a reload. These jobs are
 * persisted with the session, so a resumed session should surface them rather
 * than leaving reachable state stranded. The most recent of each is restored
 * into its drawer; a live intruder job resumes polling.
 */
async function restoreWorkbench(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/repeater");
    if (response.ok) {
      const contexts = (await response.json()) as RepeaterContext[];
      const latest = contexts.at(-1);
      if (latest !== undefined) { selectedRepeater = latest; renderRepeater(); }
    }
  } catch { /* durable state; a transient read failure is not fatal */ }
  try {
    const response = await fetch("/api/v1/workbench/intruder");
    if (response.ok) {
      const jobs = (await response.json()) as IntruderJob[];
      const latest = jobs.at(-1);
      if (latest !== undefined) {
        selectedIntruder = latest;
        renderIntruder();
        if (latest.state === "running") {
          if (intruderPoll !== undefined) window.clearInterval(intruderPoll);
          intruderPoll = window.setInterval(() => void refreshIntruder(), 500);
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
