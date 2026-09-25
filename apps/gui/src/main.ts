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
import { initShell, refreshLayoutForSession } from "./ui/shell";
import { initTheme } from "./ui/theme";
import { type CredentialDialogField, choiceDialog, confirmDialog, credentialDialog, promptDialog } from "./ui/overlay";
import { toast } from "./ui/toast";
import {
  FUZZ_MARK,
  type ParsedTemplate,
  countTemplatePositions,
  markJsonBodyValues,
  parseFuzzTemplate,
  stripFuzzMarks,
} from "./fuzz/template";
import { parseRawRequest, rawRequestText, splitRawRequest as splitRawRequestParts, splitUrl, syncContentLength, urlOrigin } from "./http/request-editor";
import { prettyBody } from "./http/body-view";
import { isConfirmed, tallySurface } from "./surface/tally";
import { graphqlOperationsOn, readProtocolOperations, type SurfaceOperation } from "./surface/operations";
import { appendLiveEvents, grpcMethodOf, isEventTruncated, renderEventData, type SseEvent, type SseState, sseLabel } from "./http/flow-kind";
import { ingestWsEvents, initWsTab, type LiveWsEvent, loadWsConnections } from "./ws/ws-tab";
import { curlCommand, findAll, hexDump, inspectRequest, type InspectorItem, isBinaryBody, requestMethod, setRequestMethod, showNonPrintables, urlEncode } from "./http/message-tools";

/* ==================================================================== *
 * Engine contracts. These mirror the local API's response shapes and are
 * unchanged by the identity work.
 * ==================================================================== */

interface SystemStatus { readonly apiVersion: string; readonly service: string; readonly state: "ready"; }
interface WorkbenchSession { readonly authToken: string; readonly interceptEnabled: boolean; }
interface WorkbenchHealth { readonly proxyRunning: boolean; readonly backend?: { readonly hudsuckerAvailable: boolean }; }
interface FlowSummary { readonly id: number; readonly method?: string | null; readonly host?: string | null; readonly url?: string | null; readonly path?: string | null; readonly status?: number | null; readonly durationMs?: number | null; readonly contentType?: string | null; readonly size?: number | null; readonly origin?: string | null; readonly sse?: SseState | null; }
interface FlowDetail { readonly summary: FlowSummary; readonly requestHeaders: readonly [string, string][]; readonly responseHeaders: readonly [string, string][]; readonly requestBody?: number[] | null; readonly responseBody?: number[] | null; }
export interface ResendRequest { method: string; url: string; headers: [string, string][]; body?: number[] | null; }
interface ResendResponse { status: number; headers: readonly [string, string][]; body?: number[]; durationMs: number; httpVersion?: string | null; reason?: string | null; }
/** A diagnostic with the engine's typed context (`{ type, value }` per key). */
interface ContextDiagnostic extends Diagnostic { readonly context?: Record<string, { readonly type: string; readonly value: unknown }>; }
interface ResendRevision { revision: number; sentAt: string; request: ResendRequest; response?: ResendResponse | null; diagnostic?: ContextDiagnostic | null; scope: string; redirectChain?: RedirectHop[]; followedFrom?: number | null; }
interface ResendContext { id: string; sourceFlowId?: number; createdAt: string; current: ResendRequest; history: ResendRevision[]; name?: string | null; }
interface ResendSendResult { context: ResendContext; revision: ResendRevision; diagnostics: (Diagnostic | null)[]; }
interface FuzzerResult { ordinal: number; payloads: string[]; request: ResendRequest; response?: { status: number; headers: readonly [string, string][]; body?: number[] | null; durationMs: number } | null; matched: boolean; filtered: boolean; diff: { statusChanged: boolean; sizeChanged: boolean; sizeDelta: number; contentChanged: boolean }; diagnostic?: ContextDiagnostic | null; timeout?: boolean; comment?: string | null; grepMatchCounts?: number[]; grepExtracts?: (string | null)[]; reflectedCount?: number | null; redirectChain?: RedirectHop[]; retryCount?: number; }
export type FuzzerLocation = "url" | "header" | "body";
interface FuzzerPosition { location: FuzzerLocation; headerName?: string | null; start: number; end: number; setIndex: number; }
type CaseMode = "lower" | "upper" | "propercase" | "toggle";
interface CharacterRule { from: string; to: string; }
interface IteratorSlot { items: string[]; separator: string; }
type NullCount = "continuous" | { fixed: number };
type PayloadSource =
  | { type: "simpleList"; values: string[] }
  | { type: "runtimeFile"; path: string }
  | { type: "customIterator"; slots: IteratorSlot[] }
  | { type: "characterSubstitution"; base: string[]; rules: CharacterRule[] }
  | { type: "caseModification"; base: string[]; modes: CaseMode[] }
  | { type: "recursiveGrep"; seed: string[] }
  | { type: "illegalUnicode"; base: string[]; target: string }
  | { type: "characterBlocks"; item: string; min: number; max: number; step: number }
  | { type: "numbers"; from: number; to: number; step: number; order: "sequential" | "random"; radix: "dec" | "hex"; minIntegerDigits: number; maxFractionDigits: number }
  | { type: "dates"; from: string; to: string; stepDays: number; format: string }
  | { type: "bruteForcer"; charset: string; minLen: number; maxLen: number }
  | { type: "nullPayloads"; count: NullCount }
  | { type: "characterFrobber"; base: string[] }
  | { type: "bitFlipper"; base: string[]; format: "literal" | "asciiHex" }
  | { type: "usernameGenerator"; names: string[] }
  | { type: "ecbBlockShuffler"; base: string[]; blockSize: number }
  | { type: "copyOtherPayload"; sourcePosition: number };
type PayloadProcessor =
  | { type: "addPrefix"; text: string }
  | { type: "addSuffix"; text: string }
  | { type: "matchReplace"; pattern: string; replacement: string }
  | { type: "substring"; from: number; length?: number | null }
  | { type: "reverseSubstring"; from: number; length?: number | null }
  | { type: "modifyCase"; mode: CaseMode }
  | { type: "encode"; scheme: "url" | "urlAll" | "html" | "base64" | "asciiHex" }
  | { type: "decode"; scheme: "url" | "html" | "base64" | "asciiHex" }
  | { type: "hash"; algorithm: "md5" | "sha1" | "sha256" | "sha512"; output: "hex" | "base64" }
  | { type: "addRawPayload" }
  | { type: "skipIfMatchesRegex"; pattern: string };
interface FuzzerPayloadSet { name: string; source: PayloadSource; processors: PayloadProcessor[]; urlEncodeChars?: string | null; }
interface PayloadListInfo { id: string; label: string; category: string; count: number; }
interface FuzzerMatchFilter { statuses: number[]; minSize?: number | null; maxSize?: number | null; contains?: string | null; regex?: string | null; }
interface GrepMatchRule { name: string; pattern: string; isRegex: boolean; caseSensitive: boolean; excludeHeaders: boolean; }
type ExtractLocator = { type: "betweenDelimiters"; start: string; end: string } | { type: "regex"; pattern: string; group: number } | { type: "offset"; start: number; length: number };
interface GrepExtractRule { name: string; locator: ExtractLocator; maxLength: number; firstOnly: boolean; }
interface GrepReflectedConfig { enabled: boolean; caseSensitive: boolean; excludeHeaders: boolean; matchPreUrlEncoded: boolean; }
interface GrepConfig { matchRules: GrepMatchRule[]; extractRules: GrepExtractRule[]; reflected: GrepReflectedConfig; }
type RedirectMode = "never" | "onSite" | "inScope" | "always";
interface RedirectPolicy { mode: RedirectMode; processCookies: boolean; maxHops: number; }
interface RetryPolicy { maxRetries: number; pauseMs: number; }
type DelayPolicy = { type: "fixed"; ratePerSecond: number } | { type: "interval"; ms: number } | { type: "random"; minMs: number; maxMs: number };
interface RedirectHop { status: number; location: string; }
interface FuzzerConfig { baseRequest: ResendRequest; positions: FuzzerPosition[]; payloadSets: FuzzerPayloadSet[]; attackType: string; matchFilter: FuzzerMatchFilter; grep: GrepConfig; concurrency: number; delay: DelayPolicy; retry: RetryPolicy; redirect: RedirectPolicy; connectionClose: boolean; updateContentLength: boolean; maxResults: number; authPreflight?: ResendRequest | null; sequence?: unknown[]; }
interface FuzzerJob { id: string; tier: "ffuf" | "native"; state: string; config: FuzzerConfig; results: FuzzerResult[]; diagnostics: (Diagnostic | null)[]; progress?: { sent: number; total: number } | null; }
interface CredentialPromptMsg { readonly id: number; readonly package: string; readonly screenSummary: string; readonly reason: string; readonly fields: readonly CredentialDialogField[]; }
interface LiveUpdate { readonly flows: readonly FlowSummary[]; readonly diagnostics: readonly Diagnostic[]; readonly prompts?: readonly CredentialPromptMsg[]; readonly websocket?: readonly LiveWsEvent[]; readonly sse?: readonly SseEvent[]; }
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
type HostParty = "first_party" | "third_party";
interface SurfaceEndpoint { readonly method: string; readonly pathTemplate: string; readonly baseUrl?: string | null; readonly host?: string | null; readonly party?: HostParty | null; readonly evidenceSource?: string | null; readonly staticEvidence?: boolean | null; readonly minimumFactConfidence?: number | null; readonly signerCount: number; readonly detail?: EndpointDetail }
interface SurfaceSummary { readonly schemaVersion: number; readonly assemblyRunId: string; readonly endpoints: readonly SurfaceEndpoint[]; readonly coverage: { readonly endpointCount: number; readonly confirmedEndpointCount: number; readonly inferredEndpointCount: number; readonly staticOnlyEndpointCount: number; readonly openHandoffCount: number; readonly resolvedHandoffCount: number }; readonly signerCount: number; readonly diagnostics: (Diagnostic | null)[]; readonly protocolOperations?: readonly SurfaceOperation[]; }
interface DiscoveryEstimate { target: string; requestCount: number; ratePerSecond: number; estimatedLabel: string; }
interface BrowserLaunchStatus { running: boolean; browser?: string | null; target?: string | null; pid?: number | null; cdpConnected?: boolean; debugPort?: number | null; }
interface TargetIdentifier { readonly kind: string; readonly value: string; }
interface SessionStatus { readonly sessionId: string; readonly lifecycle: string; readonly artifactPath: string; readonly storePath: string; readonly flowCount: number; readonly resendCount: number; readonly fuzzerCount: number; readonly scopeConfigured: boolean; readonly recoveredFromCheckpoint: boolean; readonly lastCheckpointAt?: string | null; readonly scope?: { readonly declared_at?: string; readonly target?: { readonly target_type?: string; readonly primary?: TargetIdentifier }; readonly allowed_targets?: readonly ScopeRule[] }; readonly analysisPipeline?: { readonly run_id?: string; readonly artifact_path?: string } | null; }
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
  /** Device-wide proxy the target's traffic is captured through, when active. */
  readonly captureProxy?: string | null;
  /** Why capture routing failed, when it was attempted. */
  readonly captureIssue?: string | null;
  /** Static analysis of the installed APK, fused with the live drive on Fuse. */
  readonly staticAnalysis?: { readonly state: "running" | "ready" | "failed"; readonly endpointCount?: number | null; readonly message?: string | null } | null;
  /** Package of the APK installed from the panel, which "Open app" launches. */
  readonly installedPackage?: string | null;
  /** File name of that APK. */
  readonly installedApk?: string | null;
  /** Why the installed APK's package could not be read (install succeeded). */
  readonly installNote?: string | null;
  readonly diagnostics: readonly Diagnostic[];
}

/** A request the engine answered with a diagnostic (already recorded). */
class ApiRequestError extends Error {
  constructor(message: string, readonly diagnostic?: ContextDiagnostic) { super(message); }
}

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
const urlInput = document.querySelector<HTMLInputElement>("#edit-url");
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
const androidScopeHost = document.querySelector<HTMLInputElement>("#android-scope-host");
const androidScopeAdd = document.querySelector<HTMLButtonElement>("#android-scope-add");
const androidScopeList = document.querySelector<HTMLUListElement>("#android-scope-list");
const androidScopeHint = document.querySelector<HTMLElement>("#android-scope-hint");
const androidApkPath = document.querySelector<HTMLInputElement>("#android-apk-path");
const androidApkBrowse = document.querySelector<HTMLButtonElement>("#android-apk-browse");
const androidApkFile = document.querySelector<HTMLInputElement>("#android-apk-file");
const androidApkInstall = document.querySelector<HTMLButtonElement>("#android-apk-install");
const androidInstalled = document.querySelector<HTMLElement>("#android-installed");
const androidInstalledTitle = document.querySelector<HTMLElement>("#android-installed-title");
const androidInstalledDetail = document.querySelector<HTMLElement>("#android-installed-detail");
const androidOpenApp = document.querySelector<HTMLButtonElement>("#android-open-app");
const androidScreen = document.querySelector<HTMLElement>("#android-screen");

/* ==================================================================== *
 * State
 * ==================================================================== */

const flows = new Map<number, FlowSummary>();
const pending = new Set<number>();

/**
 * The Live traffic list shows observed capture traffic only. Resend/Fuzz tools
 * send through the same session proxy and are recorded as flows (tagged at the
 * write choke-point), but folding them into the Live list clutters it and their
 * synthesized requests must never read as observed traffic. Legacy flows with no
 * origin tag load as capture. `ingestFlow` is the single gate every flow source
 * passes through, so both the list and the flow-count badge stay capture-only.
 */
function isCaptureFlow(flow: FlowSummary): boolean {
  return flow.origin == null || flow.origin === "capture";
}

function ingestFlow(flow: FlowSummary): void {
  if (isCaptureFlow(flow)) flows.set(flow.id, flow);
}
const diagnostics = new DiagnosticsLog();
let selectedFlow: FlowDetail | null = null;
let control: WebSocket | null = null;
let telemetry: WebSocket | null = null;
let reconnectTimer: number | undefined;
let reconnectDelay = 1000;
let selectedResend: ResendContext | null = null;
/** Which sent revision the Response pane is showing; null = the latest. */
let selectedResendRevision: number | null = null;
let selectedFuzzer: FuzzerJob | null = null;
/** The raw request with `§` payload markers, edited while a Fuzz draft is being
 *  configured. Compiled into base request + positions when the attack starts. */
let fuzzTemplate = "";
/** Result-table sort + the ordinal of the row opened in the detail pane. */
let fuzzResultSort: { key: string; dir: 1 | -1 } = { key: "ordinal", dir: 1 };
let selectedFuzzResult: number | null = null;
/** When the current attack started, for the live sent-per-second readout. */
let fuzzStartedAt = 0;
/** Post-run display filter over the loaded results (client-side, no re-run). */
let fuzzDisplayFilter: { search: string; status: string; onlyMatched: boolean } = { search: "", status: "", onlyMatched: false };
/** Bundled "Add from list" payload lists, fetched once from the engine. */
let bundledPayloadLists: PayloadListInfo[] = [];
let bundledListsRequested = false;
let discoveryJob: FuzzerJob | null = null;
/** Resend queue (Repeater): every request sent here, newest first. */
const resendContexts = new Map<string, ResendContext>();
/** Resend contexts with a send in flight. Each send is bound to its own id for
 *  its whole lifecycle; a completion only touches the visible editor when that
 *  id is still the selected item. */
const resendInFlight = new Set<string>();
/** When each in-flight send started (ms), for the elapsed timer. */
const resendStartedAt = new Map<string, number>();
/** Aborts each in-flight send's HTTP request — the fallback when the engine
 *  cannot cancel it (or does not answer). */
const resendAborts = new Map<string, AbortController>();
/** Unsent editor contents per item, so switching items never drops typing. */
const resendDrafts = new Map<string, { raw: string; target: string }>();
/** Why the item's last send attempt never produced a revision (rejected
 *  request, engine error). Shown inline instead of a stale response. */
const resendFailures = new Map<string, ContextDiagnostic>();
/** Fuzz queue (Intruder): manually-created attacks only (discovery excluded). */
const fuzzerJobsList = new Map<string, FuzzerJob>();
let activeWorkbenchTab: "live" | "resend" | "fuzz" | "ws" = "live";
/** Endpoints of the currently rendered surface, so row expand and the
 * send-to-resend/fuzzer actions can resolve a clicked row by index. */
let lastSurfaceEndpoints: readonly SurfaceEndpoint[] = [];
let lastDiscoveryEstimate: DiscoveryEstimate | null = null;
/** The request body the cached estimate was computed for. When it matches the
 *  current selection we can open the run confirmation instantly instead of
 *  waiting on a fresh estimate round-trip. */
let lastDiscoveryEstimateKey: string | null = null;
let discoveryEstimateDebounce: number | undefined;
let fuzzerPoll: number | undefined;
let pipelinePoll: number | undefined;
/** When the GUI first observed the current pipeline run, for a live elapsed
 *  readout during long, quiet stages (intake) where the backend timestamp is
 *  frozen (#17). */
let pipelineStartedAt = 0;
let pipelineStartedRunId = "";
let discoveryPoll: number | undefined;
/** Wall-clock ms when the current discovery run started, for live elapsed
 *  progress on the ffuf tier (which reports hits, not a sent count). */
let discoveryStartedAt: number | null = null;
let browserPoll: number | undefined;
let flowsLoaded = false;
let latestHealth: WorkbenchHealth | null = null;
let latestBrowser: BrowserLaunchStatus | null = null;
let lastSessionStatus: SessionStatus | null = null;
/** The latest Android target status, so Live traffic can explain an empty list. */
let lastAndroidStatus: AndroidTargetStatus | null = null;
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
    throw new ApiRequestError(diagnostic.id + ": " + diagnostic.what, diagnostic);
  }
  throw new Error(fallback + " (" + response.status + ")");
}

/** Reports an unexpected failure once, in the diagnostic register. */
function reportUnexpected(error: unknown, diagnostic: Diagnostic): void {
  if (error instanceof ApiRequestError) return;
  showDiagnostic({ ...diagnostic, why: String(error) });
  toast(diagnostic.what, "danger");
}

/** The structured diagnostic a failed request carried, or the fallback filled
 *  in with the raw error text when the server gave no diagnostic. */
function errorDiagnostic(error: unknown, fallback: Diagnostic): Diagnostic {
  if (error instanceof ApiRequestError && error.diagnostic !== undefined) return error.diagnostic;
  return { ...fallback, why: fallback.why === "" ? String(error) : fallback.why };
}

/** Renders (or clears) a diagnostic inline on the panel that triggered it, so a
 *  form error is visible where the operator is looking — not only in the dock. */
function showInlineError(el: HTMLElement | null, diagnostic: Diagnostic | null): void {
  if (el === null) return;
  if (diagnostic === null) { el.hidden = true; el.innerHTML = ""; return; }
  el.hidden = false;
  el.innerHTML = diagnosticListHtml([diagnostic], "");
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

/** Percent-decodes a URL or path for readable display in list rows ONLY. The
 *  stored request/response and every resend/fuzz payload keep their original
 *  encoding — this is presentation, never data. Malformed encodings fall back
 *  to the raw string. */
function decodeForDisplay(value: string): string {
  if (!value.includes("%")) return value;
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Why Live traffic is empty, in terms of what is running. */
function emptyTrafficBody(): string {
  const android = lastAndroidStatus;
  if (android !== null && android.phase === "ready") {
    if ((android.captureProxy ?? null) !== null) {
      return "The Android target is capturing. Open and drive the app on its screen; its requests appear here as they are observed.";
    }
    return `The Android target is running, but its traffic is not routed through the capture proxy${android.captureIssue ? ` (${android.captureIssue})` : ""}, so nothing is captured. Stop and relaunch the target.`;
  }
  return "Launch the capture browser or point a client at the session proxy. Requests appear here as they are observed.";
}

function renderFlows(): void {
  if (flowList === null) return;
  if (flows.size === 0) {
    flowList.innerHTML = flowsLoaded
      ? stateBlock({
          icon: "traffic",
          title: "No traffic yet",
          body: emptyTrafficBody(),
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
    item.dataset.method = method;
    item.dataset.statusClass = statusClass(flow.status);
    item.innerHTML = `<span class="list-row__method" data-method="${escapeHtml(method)}">${escapeHtml(method === "" ? "—" : method)}</span><span class="list-row__target"><b>${escapeHtml(flow.host ?? "unknown")}</b>${escapeHtml(decodeForDisplay(flow.path ?? ""))}${flowKindChipHtml(flow)}</span><span class="list-row__status" data-class="${statusClass(flow.status)}">${flow.status ?? "…"}</span>`;
    item.addEventListener("click", () => void selectFlow(flow.id));
    item.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      showFlowMenu(event.clientX, event.clientY, flow.id);
    });
    flowList.append(item);
  });
  applyFlowSearch();
  updateWorkbenchCounts();
}

/** A chip naming what a flow is beyond request/response: an event stream
 *  (with its live event count, so it never reads as hung) or a gRPC call. */
function flowKindChipHtml(flow: FlowSummary): string {
  if (flow.sse !== null && flow.sse !== undefined) {
    return ` <span class="flow-kind${flow.sse.closed ? "" : " flow-kind--live"}" title="Server-Sent Events: a long-lived response, captured as a list of events">${escapeHtml(sseLabel(flow.sse))}</span>`;
  }
  const grpc = grpcMethodOf([flow.contentType], flow.path);
  if (grpc !== null) return ` <span class="flow-kind" title="gRPC call: ${escapeHtml(`${grpc.service} / ${grpc.method}`)}">gRPC</span>`;
  return "";
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
    item.innerHTML = `<span class="list-row__target"><b>${escapeHtml(method === "" ? "REQUEST" : method)}</b> ${escapeHtml(flow?.host ?? "")}${escapeHtml(decodeForDisplay(flow?.path ?? ""))}</span><span class="badge ${tone}">held #${flowId}${countdown}</span>`;
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
    if (urlInput !== null) urlInput.value = selectedFlow.summary.url ?? "";
    // Proxy-only headers are for this proxy, not the target, so they are not
    // offered for editing (and so never go upstream on a modified forward).
    if (headersInput !== null) headersInput.value = stripProxyArtifactHeaders(selectedFlow.requestHeaders).map(([name, value]) => `${name}: ${value}`).join("\n");
    if (bodyInput !== null) bodyInput.value = bytesToText(selectedFlow.requestBody);
    if (selectedLabel !== null) selectedLabel.textContent = `Flow #${flowId} · ${selectedFlow.summary.host ?? "unknown"}${selectedFlow.summary.path ?? ""}`;
    if (editor !== null) editor.hidden = false;
    if (detail !== null) detail.innerHTML = renderDetail(selectedFlow);
    sseView = null;
    if (selectedFlow.summary.sse !== null && selectedFlow.summary.sse !== undefined) void loadSseEvents(flowId);
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

/** Renders a captured flow body: the retained bytes are shown, Pretty-printed
 *  for JSON and hex-dumped for binary, with a size note — not just "N B
 *  retained in memory" (#21). */
function renderFlowBody(headers: readonly [string, string][], bytes: number[] | null | undefined): string {
  if (bytes === null || bytes === undefined) return `<p class="t-small t-subtle">Body not retained by this backend.</p>`;
  if (bytes.length === 0) return `<p class="t-small t-subtle">Empty body (0 B).</p>`;
  const note = (label: string): string => `<p class="t-small t-subtle">${escapeHtml(`${formatBytes(bytes.length)}${label}`)}</p>`;
  if (isBinaryBody(headers, bytes)) {
    return `${note(" · binary, shown as hex")}<pre class="code">${escapeHtml(hexDump(bytes))}</pre>`;
  }
  const { text, formatted } = prettyBody(headers, bytesToText(bytes));
  return `${note(formatted ? " · JSON" : "")}<pre class="code">${escapeHtml(text)}</pre>`;
}

function renderDetail(flow: FlowDetail): string {
  const summary = flow.summary;
  const header = (headers: readonly [string, string][], name: string): string | null => headers.find(([key]) => key.toLowerCase() === name)?.[1] ?? null;
  const grpc = grpcMethodOf([header(flow.requestHeaders, "content-type"), header(flow.responseHeaders, "content-type")], summary.path);
  const sse = summary.sse ?? null;
  const grpcNote = grpc === null ? "" : `<p class="t-small t-subtle">Protobuf body not decoded: without the service's .proto schema, a length-prefixed protobuf message yields only field numbers and wire types, so it is shown as bytes rather than with guessed field names.</p>`;
  const responseBody = sse === null
    ? renderFlowBody(flow.responseHeaders, flow.responseBody)
    : `<div class="sse-events" id="flow-sse-events" aria-live="polite"><p class="t-small t-subtle">Loading events…</p></div>`;
  return `<div class="stack">
<dl class="kv">
  <dt>Method</dt><dd class="t-mono">${escapeHtml(summary.method ?? "—")}</dd>
  <dt>URL</dt><dd class="t-mono">${escapeHtml(summary.url ?? `${summary.host ?? ""}${summary.path ?? ""}`)}</dd>
  <dt>Status</dt><dd class="t-mono">${summary.status ?? "pending"}</dd>
  <dt>Duration</dt><dd class="t-mono">${summary.durationMs === null || summary.durationMs === undefined ? "—" : `${summary.durationMs} ms`}${sse === null ? "" : " to headers"}</dd>
  <dt>Type</dt><dd class="t-mono">${escapeHtml(summary.contentType ?? "—")}</dd>${sse === null ? "" : `
  <dt>Stream</dt><dd class="t-mono" id="flow-sse-state">${escapeHtml(sseLabel(sse))}</dd>`}${grpc === null ? "" : `
  <dt>Protocol</dt><dd class="t-mono">gRPC · ${escapeHtml(`${grpc.service} / ${grpc.method}`)}</dd>`}
</dl>
<hr class="rule" />
<div class="reqres">
  <section class="reqres__col stack stack--tight">
    <p class="section-label">Request</p>
    <pre class="code">${escapeHtml(formatHeaders(flow.requestHeaders))}</pre>
    ${renderFlowBody(flow.requestHeaders, flow.requestBody)}${grpcNote}
  </section>
  <section class="reqres__col stack stack--tight">
    <p class="section-label">${sse === null ? "Response" : "Response · events"}</p>
    <pre class="code">${escapeHtml(formatHeaders(flow.responseHeaders))}</pre>
    ${responseBody}${sse === null ? grpcNote : ""}
  </section>
</div>
</div>`;
}

/* ---- Server-Sent Events on the selected flow ---- */

/** Events per page read from the engine. */
const SSE_PAGE_SIZE = 500;

/** The selected flow's loaded events; `complete` when every event up to the
 *  stream's count is loaded, so live events append without a gap. */
let sseView: { flowId: number; items: SseEvent[]; complete: boolean } | null = null;

function sseEventHtml(event: SseEvent): string {
  const meta = [`#${event.sequence}`, event.event ?? "message", event.id === null || event.id === undefined ? "" : `id ${event.id}`, event.retryMs === null || event.retryMs === undefined ? "" : `retry ${event.retryMs} ms`, formatTime(event.observedAt)].filter((part) => part !== "").join(" · ");
  const truncated = isEventTruncated(event) ? `<p class="t-small t-subtle">Truncated: ${formatBytes(event.dataBytes)} on the wire.</p>` : "";
  return `<div class="sse-event"><p class="t-small t-subtle t-mono sse-event__meta">${escapeHtml(meta)}</p><pre class="code sse-event__data">${escapeHtml(renderEventData(event.data))}</pre>${truncated}</div>`;
}

function renderSseEvents(): void {
  const region = document.querySelector<HTMLElement>("#flow-sse-events");
  if (region === null || sseView === null) return;
  if (sseView.items.length === 0) {
    region.innerHTML = `<p class="t-small t-subtle">${sseView.complete ? "No events yet: they appear here as the server sends them." : "Loading events…"}</p>`;
    return;
  }
  const more = sseView.complete ? "" : `<button class="btn btn--sm btn--quiet" type="button" data-sse-more>Load more events</button>`;
  region.innerHTML = `<div class="sse-events__list">${sseView.items.map(sseEventHtml).join("")}</div>${more}`;
  region.querySelector<HTMLButtonElement>("[data-sse-more]")?.addEventListener("click", () => void loadSseEvents(sseView?.flowId ?? -1, true));
}

/** Reads the selected flow's events, first page or the next one. */
async function loadSseEvents(flowId: number, more = false): Promise<void> {
  const loaded = more && sseView?.flowId === flowId ? sseView.items : [];
  const after = loaded.at(-1)?.sequence ?? 0;
  try {
    const response = await fetch(`/api/v1/workbench/flows/${flowId}/sse-events?after=${after}&limit=${SSE_PAGE_SIZE}`);
    await requireOk(response, "event stream unavailable");
    const page = (await response.json()) as SseEvent[];
    if (selectedFlow?.summary.id !== flowId) return;
    sseView = { flowId, items: [...loaded, ...page], complete: page.length < SSE_PAGE_SIZE };
    renderSseEvents();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.sse-events-unavailable", what: "The captured events could not be loaded.", why: "", fix: "Reconnect the active session, then select the flow again." });
  }
}

/** Routes live events to the selected flow's event list, appending in place. */
function ingestSseEvents(events: readonly SseEvent[]): void {
  // No early return on an empty batch: the stream's close arrives as a
  // summary update carrying no events, and the label must still follow it.
  if (sseView === null) return;
  const mine = events.filter((event) => event.flowId === sseView?.flowId);
  if (mine.length > 0 && sseView.complete) {
    const before = sseView.items.length;
    if (!appendLiveEvents(sseView.items, mine)) sseView.complete = false;
    const list = document.querySelector<HTMLElement>("#flow-sse-events .sse-events__list");
    if (list !== null && before > 0 && sseView.complete) list.insertAdjacentHTML("beforeend", sseView.items.slice(before).map(sseEventHtml).join(""));
    else renderSseEvents();
  }
  const state = flows.get(sseView.flowId)?.sse;
  const label = document.querySelector<HTMLElement>("#flow-sse-state");
  if (label !== null && state !== null && state !== undefined) label.textContent = sseLabel(state);
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
  const request: ResendRequest = { method: selectedFlow.summary.method ?? "GET", url: selectedFlow.summary.url ?? "", headers: [...selectedFlow.requestHeaders], body: selectedFlow.requestBody ?? null };
  seedFuzzDraft(request);
  renderFuzzList();
  showWorkbenchTab("fuzz");
}

/** Seeds a fresh Fuzz draft from a request: an unmarked template plus sane
 *  defaults. The operator marks positions in the template before starting. */
function seedFuzzDraft(request: ResendRequest): void {
  // Each Send-to-Fuzz keeps its own draft (like Resend's per-item drafts), so
  // sending a second request before starting the first never discards it.
  saveActiveDraftTemplate();
  // Drop proxy-injected artifacts so the operator fuzzes the real request.
  const seeded: ResendRequest = { ...request, headers: stripProxyArtifactHeaders(request.headers) };
  const draft: FuzzerJob = {
    id: "", tier: "native", state: "draft",
    config: {
      baseRequest: seeded,
      positions: [],
      payloadSets: [newPayloadSet(0)],
      attackType: "sniper",
      // A bounded status/size/content filter, so a "matched" row means the
      // response actually matched — not merely that a response arrived.
      matchFilter: { statuses: [], minSize: null, maxSize: null, contains: null, regex: null },
      grep: newGrepConfig(),
      // Sane throughput against a real target: modest parallelism, throttled.
      concurrency: 5, delay: newDelayPolicy(), retry: newRetryPolicy(), redirect: newRedirectPolicy(),
      connectionClose: false, updateContentLength: true, maxResults: 500, authPreflight: null, sequence: [],
    },
    results: [], diagnostics: [],
  };
  const key = `draft-${(nextDraftSeq += 1)}`;
  fuzzDrafts.set(key, draft);
  fuzzDraftTemplates.set(key, rawRequestText(seeded));
  selectedFuzzer = draft;
  selectedDraftKey = key;
  fuzzTemplate = rawRequestText(seeded);
  selectedFuzzResult = null;
  fuzzResultSort = { key: "ordinal", dir: 1 };
  renderFuzzer();
}

/** Persists the current draft's edited template so switching to another draft
 *  (or job) and back preserves each one's marks and edits. */
function saveActiveDraftTemplate(): void {
  if (selectedDraftKey === null || !fuzzDrafts.has(selectedDraftKey)) return;
  readFuzzerForm();
  fuzzDraftTemplates.set(selectedDraftKey, fuzzTemplate);
}

/** Selects a Fuzz queue row — a local draft or a started job — restoring that
 *  draft's own template. */
function selectFuzzerRow(key: string): void {
  saveActiveDraftTemplate();
  const draft = fuzzDrafts.get(key);
  if (draft !== undefined) {
    selectedFuzzer = draft;
    selectedDraftKey = key;
    fuzzTemplate = fuzzDraftTemplates.get(key) ?? rawRequestText(draft.config.baseRequest);
  } else {
    const job = fuzzerJobsList.get(key);
    if (job === undefined) return;
    selectedFuzzer = job;
    selectedDraftKey = null;
  }
  selectedFuzzResult = null;
  renderFuzzer();
  renderFuzzList();
}

/** Config is only editable before the job is created; the backend snapshots it. */
function fuzzerConfigLocked(): boolean {
  return selectedFuzzer !== null && selectedFuzzer.id !== "";
}

/** Proxy-injected hop-by-hop headers that should never appear in the request the
 *  operator fuzzes; stripped when seeding a draft from a captured flow. */
function stripProxyArtifactHeaders(headers: readonly [string, string][]): [string, string][] {
  const drop = new Set(["proxy-connection", "proxy-authorization", "proxy-authenticate"]);
  return headers.filter(([name]) => !drop.has(name.toLowerCase())).map(([name, value]) => [name, value]);
}

/** The absolute base URL's scheme, for reconstructing the URL from the raw
 *  template's request-line path + `Host` header at launch time. */
function fuzzTemplateScheme(): string {
  const url = selectedFuzzer?.config.baseRequest.url ?? "";
  const sep = url.indexOf("://");
  return sep === -1 ? "http" : url.slice(0, sep);
}

/** Inserts a `§…§` pair at the caret (Burp "Add §"), or wraps the selection when
 *  text is selected — so a position can be created where there's no literal text. */
function markFuzzSelection(): void {
  const area = fuzzerPanel?.querySelector<HTMLTextAreaElement>("#fuzz-template");
  if (area === null || area === undefined) return;
  const start = area.selectionStart;
  const end = area.selectionEnd;
  readFuzzerForm();
  fuzzTemplate = `${fuzzTemplate.slice(0, start)}${FUZZ_MARK}${fuzzTemplate.slice(start, end)}${FUZZ_MARK}${fuzzTemplate.slice(end)}`;
  renderFuzzer();
  // Restore the caret between the inserted pair (or after the wrapped value).
  window.requestAnimationFrame(() => {
    const next = fuzzerPanel?.querySelector<HTMLTextAreaElement>("#fuzz-template");
    if (next !== null && next !== undefined) {
      const caret = start === end ? start + FUZZ_MARK.length : end + FUZZ_MARK.length * 2;
      next.focus();
      next.setSelectionRange(caret, caret);
    }
  });
}

/** Auto-marks the obvious injection points: query-string and urlencoded-body
 *  parameter values. Replaces any existing markers. */
function autoMarkFuzz(): void {
  readFuzzerForm();
  const base = stripFuzzMarks(fuzzTemplate).replace(/\r\n/g, "\n");
  const markParams = (segment: string): string =>
    segment.replace(/([?&][^=&\s]+=)([^&#\s]*)/g, (_match, key: string, value: string) => (value === "" ? `${key}` : `${key}${FUZZ_MARK}${value}${FUZZ_MARK}`));
  const sep = base.indexOf("\n\n");
  const head = sep === -1 ? base : base.slice(0, sep);
  const bodyRaw = sep === -1 ? "" : base.slice(sep + 2);
  const lines = head.split("\n");
  lines[0] = markParams(lines[0]);
  const headMarked = lines.join("\n");
  // JSON first: a JSON body has no `=`, so the form branch never matches it.
  // markJsonBodyValues returns the body unchanged when it isn't valid JSON.
  const jsonMarked = markJsonBodyValues(bodyRaw);
  const bodyMarked = jsonMarked !== bodyRaw
    ? jsonMarked
    : /^[^=\s&]+=/.test(bodyRaw.trim())
      ? bodyRaw.replace(/([^=&\n]+=)([^&\n]*)/g, (_match, key: string, value: string) => (value === "" ? `${key}` : `${key}${FUZZ_MARK}${value}${FUZZ_MARK}`))
      : bodyRaw;
  fuzzTemplate = sep === -1 ? headMarked : `${headMarked}\n\n${bodyMarked}`;
  if (countTemplatePositions(fuzzTemplate) === 0) toast("No obvious parameters found — select a value and click Add §.", "info");
  renderFuzzer();
}

/** Removes payload markers: only those inside the selection when text is
 *  selected, otherwise all of them (Burp's clear-within-selection). */
function clearFuzzMarks(): void {
  const area = fuzzerPanel?.querySelector<HTMLTextAreaElement>("#fuzz-template");
  const start = area?.selectionStart ?? 0;
  const end = area?.selectionEnd ?? 0;
  readFuzzerForm();
  if (start !== end) {
    fuzzTemplate = `${fuzzTemplate.slice(0, start)}${stripFuzzMarks(fuzzTemplate.slice(start, end))}${fuzzTemplate.slice(end)}`;
  } else {
    fuzzTemplate = stripFuzzMarks(fuzzTemplate);
  }
  renderFuzzer();
}

/** The 17 payload source types, in menu order, with their labels. */
const PAYLOAD_SOURCE_TYPES: readonly (readonly [string, string])[] = [
  ["simpleList", "Simple list"],
  ["runtimeFile", "Runtime file"],
  ["customIterator", "Custom iterator"],
  ["characterSubstitution", "Character substitution"],
  ["caseModification", "Case modification"],
  ["recursiveGrep", "Recursive grep"],
  ["illegalUnicode", "Illegal Unicode"],
  ["characterBlocks", "Character blocks"],
  ["numbers", "Numbers"],
  ["dates", "Dates"],
  ["bruteForcer", "Brute forcer"],
  ["nullPayloads", "Null payloads"],
  ["characterFrobber", "Character frobber"],
  ["bitFlipper", "Bit flipper"],
  ["usernameGenerator", "Username generator"],
  ["ecbBlockShuffler", "ECB block shuffler"],
  ["copyOtherPayload", "Copy other payload"],
];
/** The 11 processing steps, in menu order, with their labels. */
const PAYLOAD_PROCESSOR_TYPES: readonly (readonly [string, string])[] = [
  ["addPrefix", "Add prefix"],
  ["addSuffix", "Add suffix"],
  ["matchReplace", "Match / replace"],
  ["substring", "Substring"],
  ["reverseSubstring", "Reverse substring"],
  ["modifyCase", "Modify case"],
  ["encode", "Encode"],
  ["decode", "Decode"],
  ["hash", "Hash"],
  ["addRawPayload", "Add raw payload"],
  ["skipIfMatchesRegex", "Skip if matches regex"],
];
const CASE_MODES: readonly (readonly [CaseMode, string])[] = [
  ["lower", "lower"],
  ["upper", "UPPER"],
  ["propercase", "Propercase"],
  ["toggle", "tOGGLE"],
];

/** A fresh, empty simple-list payload set. */
function newPayloadSet(index: number): FuzzerPayloadSet {
  return { name: `Payload set ${index + 1}`, source: { type: "simpleList", values: [] }, processors: [], urlEncodeChars: null };
}

/** An empty grep config (no match/extract rules, reflected off). */
function newGrepConfig(): GrepConfig {
  return { matchRules: [], extractRules: [], reflected: { enabled: false, caseSensitive: false, excludeHeaders: false, matchPreUrlEncoded: false } };
}
function newGrepMatchRule(index: number): GrepMatchRule {
  return { name: `Match ${index + 1}`, pattern: "", isRegex: false, caseSensitive: false, excludeHeaders: false };
}
function newGrepExtractRule(index: number): GrepExtractRule {
  return { name: `Extract ${index + 1}`, locator: { type: "betweenDelimiters", start: "", end: "" }, maxLength: 100, firstOnly: true };
}
function defaultExtractLocator(type: string): ExtractLocator {
  if (type === "regex") return { type, pattern: "", group: 1 };
  if (type === "offset") return { type, start: 0, length: 16 };
  return { type: "betweenDelimiters", start: "", end: "" };
}
/** Ensures a job loaded from an older backend has a grep block to edit. */
function ensureGrep(config: FuzzerConfig): GrepConfig {
  if (config.grep === undefined || config.grep === null) config.grep = newGrepConfig();
  return config.grep;
}

function newRedirectPolicy(): RedirectPolicy { return { mode: "never", processCookies: false, maxHops: 10 }; }
function newRetryPolicy(): RetryPolicy { return { maxRetries: 0, pauseMs: 0 }; }
function newDelayPolicy(): DelayPolicy { return { type: "fixed", ratePerSecond: 10 }; }
/** Ensures a job loaded from an older backend has WS4 attack settings to edit. */
function ensureAttackSettings(config: FuzzerConfig): void {
  if (config.delay === undefined || config.delay === null) config.delay = newDelayPolicy();
  if (config.retry === undefined || config.retry === null) config.retry = newRetryPolicy();
  if (config.redirect === undefined || config.redirect === null) config.redirect = newRedirectPolicy();
  if (config.connectionClose === undefined || config.connectionClose === null) config.connectionClose = false;
  if (config.updateContentLength === undefined || config.updateContentLength === null) config.updateContentLength = true;
}

/** How many payload sets an attack type needs: one for Sniper/Battering ram,
 *  one per position for Pitchfork/Cluster bomb. */
function requiredSetCount(attackType: string, positionCount: number): number {
  return attackType === "pitchfork" || attackType === "clusterbomb" ? Math.max(1, positionCount) : 1;
}

/** Grows/shrinks the draft's payload sets to match what the attack type needs. */
function reconcilePayloadSets(config: FuzzerConfig, attackType: string, positionCount: number): void {
  const need = requiredSetCount(attackType, positionCount);
  while (config.payloadSets.length < need) config.payloadSets.push(newPayloadSet(config.payloadSets.length));
  if (config.payloadSets.length > need) config.payloadSets.length = need;
}

const COUNT_HUGE = Number.MAX_SAFE_INTEGER;
function charLen(text: string): number { return [...text].length; }
function overlongCount(target: string): number {
  const code = target.codePointAt(0) ?? 0;
  return (code <= 0x7ff ? 1 : 0) + (code <= 0xffff ? 1 : 0) + 1;
}
function numbersCount(from: number, to: number, step: number): number {
  if (step === 0) return 1;
  const steps = (to - from) / step;
  return steps < 0 ? 0 : Math.floor(steps) + 1;
}
function datesCount(from: string, to: string, stepDays: number): number {
  const start = Date.parse(`${from}T00:00:00Z`); const end = Date.parse(`${to}T00:00:00Z`);
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  const step = stepDays === 0 ? 1 : stepDays;
  const span = Math.round((end - start) / 86_400_000);
  if (Math.sign(span) !== Math.sign(step) && span !== 0) return 0;
  return Math.floor(span / step) + 1;
}
function bruteCount(alphabet: number, minLen: number, maxLen: number): number {
  let total = 0;
  for (let n = minLen; n <= maxLen; n += 1) {
    total += n === 0 ? 1 : alphabet ** n;
    if (!Number.isFinite(total) || total > COUNT_HUGE) return COUNT_HUGE;
  }
  return total;
}
function factorialCount(n: number): number { let acc = 1; for (let k = 2; k <= n; k += 1) { acc *= k; if (acc > COUNT_HUGE) return COUNT_HUGE; } return acc; }
/** Client mirror of the Rust `set_cardinality` — the pre-skip value count. */
function payloadSetCount(set: FuzzerPayloadSet): number {
  const s = set.source;
  switch (s.type) {
    case "simpleList": return s.values.length;
    case "runtimeFile": return 0; // counted server-side at run (streamed)
    case "customIterator": return s.slots.reduce((product, slot) => product * slot.items.length, 1);
    case "characterSubstitution": return s.base.length;
    case "recursiveGrep": return s.seed.length;
    case "caseModification": return s.base.length * s.modes.length;
    case "illegalUnicode": return s.base.length * overlongCount(s.target);
    case "characterBlocks": { const step = Math.max(1, s.step); return s.min > s.max ? 0 : Math.floor((s.max - s.min) / step) + 1; }
    case "numbers": return numbersCount(s.from, s.to, s.step);
    case "dates": return datesCount(s.from, s.to, s.stepDays);
    case "bruteForcer": return bruteCount(charLen(s.charset), s.minLen, s.maxLen);
    case "nullPayloads": return s.count === "continuous" ? COUNT_HUGE : s.count.fixed;
    case "characterFrobber": return s.base.reduce((sum, value) => sum + charLen(value), 0);
    case "bitFlipper": return s.base.reduce((sum, value) => sum + bitFlipByteLen(value, s.format) * 8, 0);
    case "usernameGenerator": return s.names.reduce((sum, name) => sum + usernameSchemes(name).length, 0);
    case "ecbBlockShuffler": { const size = Math.max(1, s.blockSize); return s.base.reduce((sum, value) => sum + factorialCount(Math.ceil(utf8Len(value) / size)), 0); }
    case "copyOtherPayload": return 0;
  }
}
function utf8Len(text: string): number { return new TextEncoder().encode(text).length; }
function bitFlipByteLen(value: string, format: "literal" | "asciiHex"): number {
  if (format === "literal") return utf8Len(value);
  const hex = value.replace(/\s+/gu, "");
  return hex.length % 2 === 0 ? hex.length / 2 : 0;
}
/** Client mirror of the Rust username scheme generator, for the count preview. */
function usernameSchemes(name: string): string[] {
  const local = (name.split("@")[0] ?? name).trim();
  const parts = local.split(/[\s._]+/u).filter((part) => part !== "").map((part) => part.toLowerCase());
  const schemes: string[] = [];
  const push = (candidate: string): void => { if (candidate !== "" && !schemes.includes(candidate)) schemes.push(candidate); };
  if (parts.length === 1) { push(parts[0]); return schemes; }
  if (parts.length >= 2) {
    const first = parts[0]; const last = parts[parts.length - 1];
    const fi = first.slice(0, 1); const li = last.slice(0, 1);
    push(first); push(last); push(`${first}${last}`); push(`${first}.${last}`); push(`${first}_${last}`);
    push(`${fi}${last}`); push(`${fi}.${last}`); push(`${first}${li}`); push(`${last}${first}`); push(`${last}.${first}`);
  }
  return schemes;
}
/** Whether a set will generate no values (used to guard an empty launch). */
function payloadSetIsEmpty(set: FuzzerPayloadSet): boolean {
  const s = set.source;
  if (s.type === "simpleList") return s.values.length === 0;
  if (s.type === "customIterator") return s.slots.length === 0 || s.slots.some((slot) => slot.items.length === 0);
  if (s.type === "characterSubstitution" || s.type === "caseModification" || s.type === "illegalUnicode" || s.type === "characterFrobber" || s.type === "bitFlipper" || s.type === "ecbBlockShuffler") return s.base.length === 0;
  if (s.type === "recursiveGrep") return s.seed.length === 0;
  if (s.type === "usernameGenerator") return s.names.length === 0;
  if (s.type === "characterBlocks") return s.item === "" && false;
  return false; // generated sources (numbers, dates, brute, null, file, copy) are not "empty"
}
/** The pre-run request estimate mirroring the Rust `expected_request_count`. */
function estimateRequestCount(attackType: string, positionCount: number, sets: readonly FuzzerPayloadSet[]): number {
  if (positionCount === 0) return 0;
  const counts = sets.map(payloadSetCount);
  if (attackType === "battering_ram") return counts[0] ?? 0;
  if (attackType === "pitchfork") { const active = counts.slice(0, positionCount); return active.length === 0 ? 0 : Math.min(...active); }
  if (attackType === "clusterbomb") { return counts.slice(0, positionCount).reduce((product, size) => Math.min(COUNT_HUGE, product * size), 1); }
  return positionCount * (counts[0] ?? 0); // sniper: one set, per position
}

/** Human-readable request-count preview text, capping enormous estimates. */
function fuzzPreviewText(positionCount: number, expected: number): string {
  const count = expected >= COUNT_HUGE ? "a very large number of" : expected.toLocaleString();
  const suffix = expected >= COUNT_HUGE ? " (capped at max results)" : "";
  return `${positionCount} position${positionCount === 1 ? "" : "s"} · will send ${count} request${expected === 1 ? "" : "s"}${suffix}`;
}

/** Splits a textarea's lines into trimmed, non-empty values (drops '#' comments). */
function readLines(text: string): string[] {
  return text.split("\n").map((value) => value.trim()).filter((value) => value !== "" && !value.startsWith("#"));
}
/** Reads a numeric input value with a fallback. */
function readNum(selector: string, fallback: number): number {
  const raw = Number(fuzzerPanel?.querySelector<HTMLInputElement>(selector)?.value);
  return Number.isFinite(raw) ? raw : fallback;
}
function readStr(selector: string): string {
  return fuzzerPanel?.querySelector<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>(selector)?.value ?? "";
}

/** Reconstructs one payload set's source from its rendered inputs. */
function readPayloadSource(index: number): PayloadSource {
  const type = readStr(`[data-source-type="${index}"]`) || "simpleList";
  const list = (field: string): string[] => readLines(readStr(`[data-src-list="${index}:${field}"]`));
  switch (type) {
    case "runtimeFile": return { type, path: readStr(`[data-src="${index}:path"]`).trim() };
    case "customIterator": {
      const slots: IteratorSlot[] = [];
      fuzzerPanel?.querySelectorAll<HTMLTextAreaElement>(`[data-slot-items^="${index}:"]`).forEach((area) => {
        const slot = Number(area.dataset.slotItems?.split(":")[1]);
        slots[slot] = { items: readLines(area.value), separator: readStr(`[data-slot-sep="${index}:${slot}"]`) };
      });
      return { type, slots: slots.filter((slot) => slot !== undefined) };
    }
    case "characterSubstitution": {
      const rules: CharacterRule[] = readStr(`[data-src="${index}:rules"]`).split("\n")
        .map((line) => line.trim()).filter((line) => line.includes(">"))
        .map((line) => { const [from, to] = line.split(">"); return { from: [...(from ?? "")][0] ?? "", to: [...(to ?? "")][0] ?? "" }; })
        .filter((rule) => rule.from !== "");
      return { type, base: list("base"), rules };
    }
    case "caseModification": {
      const modes = CASE_MODES.map(([mode]) => mode).filter((mode) => (fuzzerPanel?.querySelector<HTMLInputElement>(`[data-mode="${index}:${mode}"]`)?.checked ?? false));
      return { type, base: list("base"), modes: modes.length === 0 ? ["lower"] : modes };
    }
    case "recursiveGrep": return { type, seed: list("seed") };
    case "illegalUnicode": return { type, base: list("base"), target: [...readStr(`[data-src="${index}:target"]`)][0] ?? "." };
    case "characterBlocks": return { type, item: readStr(`[data-src="${index}:item"]`), min: Math.max(0, Math.floor(readNum(`[data-src="${index}:min"]`, 1))), max: Math.max(0, Math.floor(readNum(`[data-src="${index}:max"]`, 8))), step: Math.max(1, Math.floor(readNum(`[data-src="${index}:step"]`, 1))) };
    case "numbers": return { type, from: readNum(`[data-src="${index}:from"]`, 0), to: readNum(`[data-src="${index}:to"]`, 100), step: readNum(`[data-src="${index}:step"]`, 1) || 1, order: (readStr(`[data-src="${index}:order"]`) as "sequential" | "random") || "sequential", radix: (readStr(`[data-src="${index}:radix"]`) as "dec" | "hex") || "dec", minIntegerDigits: Math.max(1, Math.floor(readNum(`[data-src="${index}:minIntegerDigits"]`, 1))), maxFractionDigits: Math.max(0, Math.floor(readNum(`[data-src="${index}:maxFractionDigits"]`, 0))) };
    case "dates": return { type, from: readStr(`[data-src="${index}:from"]`) || "2020-01-01", to: readStr(`[data-src="${index}:to"]`) || "2020-12-31", stepDays: Math.floor(readNum(`[data-src="${index}:stepDays"]`, 1)) || 1, format: readStr(`[data-src="${index}:format"]`) || "%Y-%m-%d" };
    case "bruteForcer": return { type, charset: readStr(`[data-src="${index}:charset"]`) || "abc", minLen: Math.max(0, Math.floor(readNum(`[data-src="${index}:minLen"]`, 1))), maxLen: Math.max(0, Math.floor(readNum(`[data-src="${index}:maxLen"]`, 3))) };
    case "nullPayloads": { const mode = readStr(`[data-src="${index}:mode"]`); return { type, count: mode === "continuous" ? "continuous" : { fixed: Math.max(1, Math.floor(readNum(`[data-src="${index}:fixed"]`, 10))) } }; }
    case "characterFrobber": return { type, base: list("base") };
    case "bitFlipper": return { type, base: list("base"), format: (readStr(`[data-src="${index}:format"]`) as "literal" | "asciiHex") || "literal" };
    case "usernameGenerator": return { type, names: list("names") };
    case "ecbBlockShuffler": return { type, base: list("base"), blockSize: Math.max(1, Math.floor(readNum(`[data-src="${index}:blockSize"]`, 16))) };
    case "copyOtherPayload": return { type, sourcePosition: Math.max(0, Math.floor(readNum(`[data-src="${index}:sourcePosition"]`, 0))) };
    default: return { type: "simpleList", values: list("values") };
  }
}

/** Reconstructs one payload set's ordered processing pipeline from its inputs. */
function readProcessors(index: number): PayloadProcessor[] {
  const found = fuzzerPanel?.querySelectorAll<HTMLElement>(`[data-proc-row="${index}"]`);
  const rows = found === undefined ? [] : Array.from(found);
  return rows.map((row) => {
    const type = row.querySelector<HTMLSelectElement>("[data-proc-type]")?.value ?? "addPrefix";
    const field = (name: string): string => row.querySelector<HTMLInputElement | HTMLSelectElement>(`[data-proc-field="${name}"]`)?.value ?? "";
    switch (type) {
      case "addSuffix": return { type, text: field("text") };
      case "matchReplace": return { type, pattern: field("pattern"), replacement: field("replacement") };
      case "substring": { const length = field("length").trim(); return { type, from: Math.max(0, Math.floor(Number(field("from")) || 0)), length: length === "" ? null : Math.max(0, Math.floor(Number(length))) }; }
      case "reverseSubstring": { const length = field("length").trim(); return { type, from: Math.max(0, Math.floor(Number(field("from")) || 0)), length: length === "" ? null : Math.max(0, Math.floor(Number(length))) }; }
      case "modifyCase": return { type, mode: (field("mode") as CaseMode) || "lower" };
      case "encode": return { type, scheme: (field("scheme") as "url" | "urlAll" | "html" | "base64" | "asciiHex") || "url" };
      case "decode": return { type, scheme: (field("scheme") as "url" | "html" | "base64" | "asciiHex") || "url" };
      case "hash": return { type, algorithm: (field("algorithm") as "md5" | "sha1" | "sha256" | "sha512") || "sha256", output: (field("output") as "hex" | "base64") || "hex" };
      case "addRawPayload": return { type };
      case "skipIfMatchesRegex": return { type, pattern: field("pattern") };
      default: return { type: "addPrefix", text: field("text") };
    }
  });
}

/** Snapshots the current draft form (template, attack type, payload sources +
 *  pipelines, filter, throughput) back into the config. Positions are compiled
 *  from the template only when the attack starts. */
function readFuzzerForm(): void {
  if (selectedFuzzer === null || fuzzerConfigLocked() || fuzzerPanel === null) return;
  const config = selectedFuzzer.config;
  const templateArea = fuzzerPanel.querySelector<HTMLTextAreaElement>("#fuzz-template");
  if (templateArea !== null) fuzzTemplate = templateArea.value;
  config.attackType = valueOfFuzzer("#fuzzer-type") || "sniper";
  reconcilePayloadSets(config, config.attackType, countTemplatePositions(fuzzTemplate));
  config.payloadSets.forEach((set, index) => {
    set.source = readPayloadSource(index);
    set.processors = readProcessors(index);
    const urlEncode = readStr(`[data-url-encode="${index}"]`);
    set.urlEncodeChars = urlEncode === "" ? null : urlEncode;
  });
  config.maxResults = Math.max(1, Math.floor(Number(valueOfFuzzer("#fuzzer-max")) || 100));
  config.concurrency = Math.max(1, Math.floor(Number(valueOfFuzzer("#fuzzer-concurrency")) || 1));
  config.delay = readDelayPolicy();
  config.retry = {
    maxRetries: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-retries")) || 0)),
    pauseMs: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-retry-pause")) || 0)),
  };
  config.redirect = {
    mode: (valueOfFuzzer("#fuzzer-redirect-mode") as RedirectMode) || "never",
    processCookies: (fuzzerPanel?.querySelector<HTMLInputElement>("#fuzzer-redirect-cookies")?.checked ?? false),
    maxHops: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-redirect-hops")) || 10)),
  };
  config.connectionClose = fuzzerPanel?.querySelector<HTMLInputElement>("#fuzzer-connection-close")?.checked ?? false;
  config.updateContentLength = fuzzerPanel?.querySelector<HTMLInputElement>("#fuzzer-update-cl")?.checked ?? true;
  const statuses = valueOfFuzzer("#match-statuses").split(",").map((value) => Number(value.trim())).filter((value) => Number.isFinite(value) && value > 0);
  const parseSize = (raw: string): number | null => { const trimmed = raw.trim(); if (trimmed === "") return null; const n = Number(trimmed); return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : null; };
  const contains = valueOfFuzzer("#match-contains");
  const regex = valueOfFuzzer("#match-regex").trim();
  config.matchFilter = { statuses, minSize: parseSize(valueOfFuzzer("#match-min")), maxSize: parseSize(valueOfFuzzer("#match-max")), contains: contains === "" ? null : contains, regex: regex === "" ? null : regex };
  config.grep = readGrepConfig();
  config.sequence = [];
}

/** Reconstructs the delay policy from the attack-settings inputs. */
function readDelayPolicy(): DelayPolicy {
  const mode = valueOfFuzzer("#fuzzer-delay-mode") || "fixed";
  if (mode === "interval") return { type: "interval", ms: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-delay-ms")) || 0)) };
  if (mode === "random") return { type: "random", minMs: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-delay-min")) || 0)), maxMs: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-delay-max")) || 0)) };
  return { type: "fixed", ratePerSecond: Math.max(0, Math.floor(Number(valueOfFuzzer("#fuzzer-rate")) || 0)) };
}

/** Reconstructs the grep block from its rendered inputs. */
function readGrepConfig(): GrepConfig {
  const bool = (selector: string): boolean => fuzzerPanel?.querySelector<HTMLInputElement>(selector)?.checked ?? false;
  const matchRows = fuzzerPanel === null ? [] : Array.from(fuzzerPanel.querySelectorAll<HTMLElement>("[data-grep-match-row]"));
  const matchRules: GrepMatchRule[] = matchRows.map((row) => ({
    name: row.querySelector<HTMLInputElement>("[data-gm-name]")?.value.trim() || "Match",
    pattern: row.querySelector<HTMLInputElement>("[data-gm-pattern]")?.value ?? "",
    isRegex: row.querySelector<HTMLInputElement>("[data-gm-regex]")?.checked ?? false,
    caseSensitive: row.querySelector<HTMLInputElement>("[data-gm-case]")?.checked ?? false,
    excludeHeaders: row.querySelector<HTMLInputElement>("[data-gm-nohdr]")?.checked ?? false,
  }));
  const extractRows = fuzzerPanel === null ? [] : Array.from(fuzzerPanel.querySelectorAll<HTMLElement>("[data-grep-extract-row]"));
  const extractRules: GrepExtractRule[] = extractRows.map((row) => {
    const type = row.querySelector<HTMLSelectElement>("[data-ge-type]")?.value ?? "betweenDelimiters";
    const field = (name: string): string => row.querySelector<HTMLInputElement>(`[data-ge-field="${name}"]`)?.value ?? "";
    let locator: ExtractLocator;
    if (type === "regex") locator = { type, pattern: field("pattern"), group: Math.max(0, Math.floor(Number(field("group")) || 0)) };
    else if (type === "offset") locator = { type, start: Math.max(0, Math.floor(Number(field("start")) || 0)), length: Math.max(0, Math.floor(Number(field("length")) || 0)) };
    else locator = { type: "betweenDelimiters", start: field("start"), end: field("end") };
    return {
      name: row.querySelector<HTMLInputElement>("[data-ge-name]")?.value.trim() || "Extract",
      locator,
      maxLength: Math.max(0, Math.floor(Number(row.querySelector<HTMLInputElement>("[data-ge-maxlen]")?.value) || 0)),
      firstOnly: row.querySelector<HTMLInputElement>("[data-ge-first]")?.checked ?? true,
    };
  });
  return {
    matchRules,
    extractRules,
    reflected: {
      enabled: bool("#grep-reflected"),
      caseSensitive: bool("#grep-reflected-case"),
      excludeHeaders: bool("#grep-reflected-nohdr"),
      matchPreUrlEncoded: bool("#grep-reflected-preenc"),
    },
  };
}

/** Appends an uploaded wordlist file into a simple-list payload set. */
function loadPayloadFile(index: number, file: File): void {
  const reader = new FileReader();
  reader.onload = (): void => {
    if (selectedFuzzer === null) return;
    readFuzzerForm();
    const text = typeof reader.result === "string" ? reader.result : "";
    const values = text.split(/\r?\n/u).map((value) => value.trim()).filter((value) => value !== "" && !value.startsWith("#"));
    const set = selectedFuzzer.config.payloadSets[index];
    if (set !== undefined && set.source.type === "simpleList") {
      set.source.values = [...set.source.values, ...values];
    }
    renderFuzzer();
    toast(`Loaded ${values.length.toLocaleString()} payloads from ${file.name}`, "success");
  };
  reader.readAsText(file);
}

/** A sensible default for a newly-added processing rule. */
function defaultProcessor(type: string): PayloadProcessor {
  switch (type) {
    case "addSuffix": return { type, text: "" };
    case "matchReplace": return { type, pattern: "", replacement: "" };
    case "substring": return { type, from: 0, length: null };
    case "reverseSubstring": return { type, from: 0, length: null };
    case "modifyCase": return { type, mode: "lower" };
    case "encode": return { type, scheme: "url" };
    case "decode": return { type, scheme: "url" };
    case "hash": return { type, algorithm: "sha256", output: "hex" };
    case "addRawPayload": return { type };
    case "skipIfMatchesRegex": return { type, pattern: "" };
    default: return { type: "addPrefix", text: "" };
  }
}

/** Snapshots the form, mutates one payload set, and re-renders the editor. */
function mutateSet(index: number, mutate: (set: FuzzerPayloadSet) => void): void {
  if (selectedFuzzer === null) return;
  readFuzzerForm();
  const set = selectedFuzzer.config.payloadSets[index];
  if (set !== undefined) mutate(set);
  renderFuzzer();
}

/** Applies an action to the payload set + processor row that raised the event. */
function procAction(event: Event, mutate: (set: FuzzerPayloadSet, position: number) => void): void {
  const row = (event.currentTarget as HTMLElement).closest<HTMLElement>("[data-proc-row]");
  if (row === null) return;
  mutateSet(Number(row.dataset.procRow), (set) => mutate(set, Number(row.dataset.procIndex)));
}

/** Appends clipboard lines into a simple-list payload set. */
async function pasteIntoList(index: number): Promise<void> {
  try {
    const text = await navigator.clipboard.readText();
    const values = text.split(/\r?\n/u).map((value) => value.trim()).filter((value) => value !== "" && !value.startsWith("#"));
    mutateSet(index, (set) => { if (set.source.type === "simpleList") set.source.values = [...set.source.values, ...values]; });
    toast(`Pasted ${values.length.toLocaleString()} payloads`, "success");
  } catch { toast("Clipboard paste is unavailable here", "danger"); }
}

/** Appends a bundled payload list's values into a simple-list payload set. */
async function addFromList(index: number): Promise<void> {
  const pick = fuzzerPanel?.querySelector<HTMLSelectElement>(`[data-list-pick="${index}"]`)?.value ?? "";
  if (pick === "") return;
  try {
    const response = await fetch(`/api/v1/workbench/fuzzer/payload-lists/${encodeURIComponent(pick)}`);
    await requireOk(response, "payload list load failed");
    const values = (await response.json()) as string[];
    mutateSet(index, (set) => { if (set.source.type === "simpleList") set.source.values = [...set.source.values, ...values]; });
    toast(`Added ${values.length.toLocaleString()} payloads from ${pick}`, "success");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The payload list could not be loaded.", why: "", fix: "Try again, or load a file instead." });
  }
}

/** Fetches the bundled "Add from list" payload lists once, then re-renders. */
function ensureBundledLists(): void {
  if (bundledListsRequested) return;
  bundledListsRequested = true;
  void (async () => {
    try {
      const response = await fetch("/api/v1/workbench/fuzzer/payload-lists");
      if (response.ok) {
        bundledPayloadLists = (await response.json()) as PayloadListInfo[];
        if (selectedFuzzer !== null && !fuzzerConfigLocked()) renderFuzzer();
      }
    } catch { /* the picker keeps its loading state; Load file still works */ }
  })();
}

/** Attaches all payload-editor handlers after the draft editor is (re)rendered. */
function wireFuzzPayloadEditor(panel: HTMLElement): void {
  ensureBundledLists();
  const structural = (): void => { readFuzzerForm(); renderFuzzer(); };
  panel.querySelectorAll<HTMLSelectElement>("[data-source-type], [data-proc-type]").forEach((el) => el.addEventListener("change", structural));
  panel.querySelectorAll<HTMLButtonElement>("[data-add-proc-btn]").forEach((btn) => btn.addEventListener("click", () => {
    const index = Number(btn.dataset.addProcBtn);
    const type = panel.querySelector<HTMLSelectElement>(`[data-add-proc="${index}"]`)?.value ?? "addPrefix";
    mutateSet(index, (set) => set.processors.push(defaultProcessor(type)));
  }));
  panel.querySelectorAll<HTMLButtonElement>("[data-proc-remove]").forEach((btn) => btn.addEventListener("click", (event) => procAction(event, (set, position) => { set.processors.splice(position, 1); })));
  panel.querySelectorAll<HTMLButtonElement>("[data-proc-up]").forEach((btn) => btn.addEventListener("click", (event) => procAction(event, (set, position) => { if (position > 0) { [set.processors[position - 1], set.processors[position]] = [set.processors[position], set.processors[position - 1]]; } })));
  panel.querySelectorAll<HTMLButtonElement>("[data-proc-down]").forEach((btn) => btn.addEventListener("click", (event) => procAction(event, (set, position) => { if (position < set.processors.length - 1) { [set.processors[position + 1], set.processors[position]] = [set.processors[position], set.processors[position + 1]]; } })));
  panel.querySelectorAll<HTMLButtonElement>("[data-slot-add]").forEach((btn) => btn.addEventListener("click", () => mutateSet(Number(btn.dataset.slotAdd), (set) => { if (set.source.type === "customIterator") set.source.slots.push({ items: [], separator: "" }); })));
  panel.querySelectorAll<HTMLButtonElement>("[data-slot-remove]").forEach((btn) => btn.addEventListener("click", () => {
    const [index, slot] = (btn.dataset.slotRemove ?? "").split(":").map(Number);
    mutateSet(index, (set) => { if (set.source.type === "customIterator") set.source.slots.splice(slot, 1); });
  }));
  panel.querySelectorAll<HTMLButtonElement>("[data-load-set]").forEach((btn) => btn.addEventListener("click", () => panel.querySelector<HTMLInputElement>(`[data-load-file="${btn.dataset.loadSet}"]`)?.click()));
  panel.querySelectorAll<HTMLInputElement>("[data-load-file]").forEach((input) => input.addEventListener("change", (event) => {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (file !== undefined) loadPayloadFile(Number(input.dataset.loadFile), file);
    (event.target as HTMLInputElement).value = "";
  }));
  panel.querySelectorAll<HTMLButtonElement>("[data-list-clear]").forEach((btn) => btn.addEventListener("click", () => mutateSet(Number(btn.dataset.listClear), (set) => { if (set.source.type === "simpleList") set.source.values = []; })));
  panel.querySelectorAll<HTMLButtonElement>("[data-list-dedupe]").forEach((btn) => btn.addEventListener("click", () => mutateSet(Number(btn.dataset.listDedupe), (set) => { if (set.source.type === "simpleList") set.source.values = [...new Set(set.source.values)]; })));
  panel.querySelectorAll<HTMLButtonElement>("[data-list-paste]").forEach((btn) => btn.addEventListener("click", () => void pasteIntoList(Number(btn.dataset.listPaste))));
  panel.querySelectorAll<HTMLButtonElement>("[data-list-add]").forEach((btn) => btn.addEventListener("click", () => void addFromList(Number(btn.dataset.listAdd))));
  panel.querySelectorAll<HTMLElement>("[data-src], [data-src-list], [data-slot-items], [data-slot-sep], [data-url-encode], [data-mode], [data-proc-field]").forEach((el) => {
    el.addEventListener("input", () => updateFuzzPreview());
    el.addEventListener("change", () => updateFuzzPreview());
  });
}

/** Resting state for the Resend editor when no item is open. With items in
 *  the queue it points there (and can reopen a collapsed queue) rather than
 *  implying the queue is empty. */
function seedResendEmpty(): void {
  if (resendPanel === null) return;
  resendPanel.hidden = false;
  renderedResendId = null;
  const newButton = `<div class="row resend-empty__actions"><button class="btn btn--sm" type="button" data-resend-new-inline>${icon("plus", { size: 14 })}<span>New request</span></button></div>`;
  if (resendContexts.size === 0) {
    resendPanel.innerHTML = `${stateBlock({
      icon: "refresh",
      title: "No request loaded",
      body: "Send a flow here from the traffic table or the API surface, or write one from scratch.",
      compact: true,
    })}${newButton}`;
    resendPanel.querySelector("[data-resend-new-inline]")?.addEventListener("click", () => void newResendRequest());
    return;
  }
  const count = resendContexts.size;
  const collapsed = queueCollapsed("resend");
  resendPanel.innerHTML = `${stateBlock({
    icon: "send",
    title: "Pick a request from the queue",
    body: `${count} ${count === 1 ? "item is" : "items are"} in the Resend queue${collapsed ? " (collapsed)" : ""}. Select one to edit and send it.`,
    compact: true,
  })}${collapsed ? `<div class="row resend-empty__actions"><button class="btn btn--sm" type="button" data-resend-show-queue>Show queue</button></div>` : ""}`;
  resendPanel.querySelector("[data-resend-show-queue]")?.addEventListener("click", () => {
    toggleQueueCollapse("resend");
    seedResendEmpty();
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

const FUZZ_ATTACK_HINTS: Record<string, string> = {
  sniper: "Sniper — one payload set, injected into each position in turn. Requests = positions × payloads.",
  battering_ram: "Battering ram — one payload set, the same value placed into every position at once. Requests = payloads.",
  pitchfork: "Pitchfork — one payload set per position, stepped together in parallel. Requests = the shortest set.",
  clusterbomb: "Cluster bomb — one payload set per position, every combination. Requests = the product of set sizes.",
};

function renderFuzzer(): void {
  if (fuzzerPanel === null || selectedFuzzer === null) return;
  fuzzerPanel.hidden = false;
  const config = selectedFuzzer.config;
  const locked = fuzzerConfigLocked();
  const state = selectedFuzzer.state;
  const disabled = locked ? "disabled" : "";
  const opt = (value: string, label: string, selected: boolean): string => `<option value="${value}"${selected ? " selected" : ""}>${label}</option>`;

  const editor = locked ? renderFuzzerLockedSummary(selectedFuzzer) : renderFuzzerDraftEditor(config, opt);
  const controls = renderFuzzerControls(selectedFuzzer, locked);
  const stateBadge = `<span class="badge ${state === "running" ? "badge--accent" : state === "failed" ? "badge--danger" : state === "completed" ? "badge--success" : ""}">${escapeHtml(state)}</span>`;

  fuzzerPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("discovery", { size: 16 })}<h2 title="${escapeHtml(`${config.baseRequest.url}${selectedFuzzer.id === "" ? "" : ` · ${selectedFuzzer.id}`}`)}">${escapeHtml(fuzzTitle(selectedFuzzer))}</h2></div>
  <div class="row">${stateBadge}<button class="btn btn--quiet btn--icon" type="button" data-close-fuzzer><span class="visually-hidden">Close Fuzz</span>${icon("close", { size: 16 })}</button></div>
</div>
<div class="panel__body stack">
  ${editor}
  ${controls}
  <div id="fuzzer-results">${renderFuzzerResults(selectedFuzzer)}</div>
</div>`;

  // Draft-editor wiring.
  fuzzerPanel.querySelector("[data-fuzz-mark]")?.addEventListener("click", () => markFuzzSelection());
  fuzzerPanel.querySelector("[data-fuzz-auto]")?.addEventListener("click", () => autoMarkFuzz());
  fuzzerPanel.querySelector("[data-fuzz-clear]")?.addEventListener("click", () => clearFuzzMarks());
  fuzzerPanel.querySelector<HTMLSelectElement>("#fuzzer-type")?.addEventListener("change", () => { readFuzzerForm(); renderFuzzer(); });
  // Delay-mode swaps the relevant fields, so re-render on change.
  fuzzerPanel.querySelector<HTMLSelectElement>("#fuzzer-delay-mode")?.addEventListener("change", () => { readFuzzerForm(); renderFuzzer(); });
  fuzzerPanel.querySelector<HTMLTextAreaElement>("#fuzz-template")?.addEventListener("input", () => updateFuzzPreview());
  wireFuzzPayloadEditor(fuzzerPanel);
  wireGrepSettings(fuzzerPanel);

  // Run controls.
  fuzzerPanel.querySelector("#fuzzer-launch")?.addEventListener("click", () => void launchFuzzer());
  fuzzerPanel.querySelector("#fuzzer-pause")?.addEventListener("click", () => void pauseFuzzer());
  fuzzerPanel.querySelector("#fuzzer-stop")?.addEventListener("click", () => void stopFuzzer());
  fuzzerPanel.querySelector("#fuzzer-rerun")?.addEventListener("click", () => { if (selectedFuzzer !== null) editAndRerunFuzz(selectedFuzzer); });
  fuzzerPanel.querySelector("[data-close-fuzzer]")?.addEventListener("click", () => {
    if (fuzzerPoll !== undefined) { window.clearInterval(fuzzerPoll); fuzzerPoll = undefined; }
    selectedFuzzer = null;
    seedFuzzerEmpty();
  });

  // Results table wiring (sort headers, row-select, display filter, comments).
  wireFuzzResults(fuzzerPanel);
}

/** Wires the results grid: sortable headers, row selection, the display-filter
 *  bar, and inline comment editing. Used for both the initial render and the
 *  incremental results re-render. */
function wireFuzzResults(container: HTMLElement): void {
  container.querySelectorAll<HTMLElement>("[data-sort]").forEach((header) => header.addEventListener("click", () => {
    const key = header.dataset.sort ?? "ordinal";
    fuzzResultSort = fuzzResultSort.key === key ? { key, dir: fuzzResultSort.dir === 1 ? -1 : 1 } : { key, dir: 1 };
    renderFuzzerResultsInto();
  }));
  container.querySelectorAll<HTMLElement>("[data-result-row]").forEach((row) => row.addEventListener("click", (event) => {
    // A click inside the inline comment field must not toggle the row detail.
    if ((event.target as HTMLElement).closest(".fuzz-comment") !== null) return;
    const ordinal = Number(row.dataset.resultRow);
    selectedFuzzResult = selectedFuzzResult === ordinal ? null : ordinal;
    renderFuzzerResultsInto();
  }));
  const search = container.querySelector<HTMLInputElement>("#fuzz-filter-search");
  search?.addEventListener("input", () => { fuzzDisplayFilter.search = search.value; renderFuzzerResultsInto(); refocusFuzzFilter("#fuzz-filter-search"); });
  const statusFilter = container.querySelector<HTMLInputElement>("#fuzz-filter-status");
  statusFilter?.addEventListener("input", () => { fuzzDisplayFilter.status = statusFilter.value; renderFuzzerResultsInto(); refocusFuzzFilter("#fuzz-filter-status"); });
  const onlyMatched = container.querySelector<HTMLInputElement>("#fuzz-filter-matched");
  onlyMatched?.addEventListener("change", () => { fuzzDisplayFilter.onlyMatched = onlyMatched.checked; renderFuzzerResultsInto(); });
  container.querySelectorAll<HTMLInputElement>(".fuzz-comment").forEach((input) => {
    input.addEventListener("click", (event) => event.stopPropagation());
    input.addEventListener("change", () => void setFuzzComment(Number(input.dataset.commentOrdinal), input.value));
  });
}

/** A `<select>` of options, marking the current value selected. */
function selectOptions(options: readonly (readonly [string, string])[], current: string): string {
  return options.map(([value, label]) => `<option value="${escapeHtml(value)}"${value === current ? " selected" : ""}>${escapeHtml(label)}</option>`).join("");
}

/** A plain list textarea for a source's `base`/`seed`/`names` field. */
function listField(index: number, field: string, label: string, values: readonly string[], placeholder: string): string {
  return `<div class="field"><label class="field__label">${escapeHtml(label)}</label><textarea class="textarea" data-src-list="${index}:${field}" spellcheck="false" placeholder="${escapeHtml(placeholder)}">${escapeHtml(values.join("\n"))}</textarea></div>`;
}
function numField(index: number, field: string, label: string, value: number, min?: number): string {
  return `<div class="field"><label class="field__label">${escapeHtml(label)}</label><input class="input input--mono" type="number"${min === undefined ? "" : ` min="${min}"`} data-src="${index}:${field}" value="${value}" /></div>`;
}
function strField(index: number, field: string, label: string, value: string, placeholder = ""): string {
  return `<div class="field"><label class="field__label">${escapeHtml(label)}</label><input class="input input--mono" type="text" data-src="${index}:${field}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" /></div>`;
}

/** The management buttons for a simple-list source. */
function listButtons(index: number): string {
  const listOptions = bundledPayloadLists.length === 0
    ? '<option value="">(loading lists…)</option>'
    : bundledPayloadLists.map((info) => `<option value="${escapeHtml(info.id)}">${escapeHtml(info.label)} (${info.count})</option>`).join("");
  return `<div class="row fuzz-list-actions">
    <button class="btn btn--sm btn--quiet" type="button" data-load-set="${index}">${icon("upload", { size: 12 })}<span>Load file</span></button>
    <input type="file" accept=".txt,.md,text/plain" data-load-file="${index}" hidden />
    <button class="btn btn--sm btn--quiet" type="button" data-list-paste="${index}">Paste</button>
    <button class="btn btn--sm btn--quiet" type="button" data-list-dedupe="${index}">Deduplicate</button>
    <button class="btn btn--sm btn--quiet" type="button" data-list-clear="${index}">Clear</button>
    <span class="spacer"></span>
    <select class="select select--sm" data-list-pick="${index}">${listOptions}</select>
    <button class="btn btn--sm" type="button" data-list-add="${index}">Add from list</button>
  </div>`;
}

/** The type-specific settings form for one payload set's source. */
function renderSourceSettings(set: FuzzerPayloadSet, index: number): string {
  const s = set.source;
  switch (s.type) {
    case "simpleList":
      return `${listButtons(index)}<textarea class="textarea" data-src-list="${index}:values" spellcheck="false" placeholder="one payload per line">${escapeHtml(s.values.join("\n"))}</textarea>`;
    case "runtimeFile":
      return `${strField(index, "path", "File path", s.path, "/absolute/path/to/wordlist.txt")}<p class="field__hint t-subtle">Streamed line-by-line at run time on the engine host.</p>`;
    case "customIterator": {
      const slots = s.slots.length === 0 ? [{ items: [], separator: "" }] : s.slots;
      const rows = slots.map((slot, si) => `<div class="split-2 fuzz-slot">
        <div class="field"><label class="field__label">Slot ${si + 1} items</label><textarea class="textarea" data-slot-items="${index}:${si}" spellcheck="false" placeholder="one item per line">${escapeHtml(slot.items.join("\n"))}</textarea></div>
        <div class="field"><label class="field__label">Separator before slot ${si + 1}</label><input class="input input--mono" type="text" data-slot-sep="${index}:${si}" value="${escapeHtml(slot.separator)}" />${si === slots.length - 1 && slots.length > 1 ? `<button class="btn btn--sm btn--quiet" type="button" data-slot-remove="${index}:${si}">Remove slot</button>` : ""}</div>
      </div>`).join("");
      return `${rows}${slots.length < 8 ? `<div class="row"><button class="btn btn--sm btn--quiet" type="button" data-slot-add="${index}">${icon("plus", { size: 12 })}<span>Add slot</span></button></div>` : ""}`;
    }
    case "characterSubstitution":
      return `${listField(index, "base", "Base values", s.base, "one value per line")}<div class="field"><label class="field__label">Substitution rules (one <code class="t-mono">from&gt;to</code> per line)</label><textarea class="textarea input--mono" data-src="${index}:rules" spellcheck="false" placeholder="e&gt;3&#10;a&gt;4">${escapeHtml(s.rules.map((rule) => `${rule.from}>${rule.to}`).join("\n"))}</textarea></div>`;
    case "caseModification":
      return `${listField(index, "base", "Base values", s.base, "one value per line")}<div class="field"><label class="field__label">Case modes</label><div class="row fuzz-modes">${CASE_MODES.map(([mode, label]) => `<label class="check"><input type="checkbox" data-mode="${index}:${mode}"${s.modes.includes(mode) ? " checked" : ""} /> ${escapeHtml(label)}</label>`).join("")}</div></div>`;
    case "recursiveGrep":
      return `${listField(index, "seed", "Seed values", s.seed, "initial values")}<p class="field__hint t-danger">Recursive grep requires a configured extract item (Grep-Extract) — the attack is rejected until one is set.</p>`;
    case "illegalUnicode":
      return `${listField(index, "base", "Base values", s.base, "one value per line")}${strField(index, "target", "Target character", s.target, ".")}`;
    case "characterBlocks":
      return `${strField(index, "item", "Item", s.item, "A")}<div class="split-3">${numField(index, "min", "Min blocks", s.min, 0)}${numField(index, "max", "Max blocks", s.max, 0)}${numField(index, "step", "Step", s.step, 1)}</div>`;
    case "numbers":
      return `<div class="split-3">${numField(index, "from", "From", s.from)}${numField(index, "to", "To", s.to)}${numField(index, "step", "Step", s.step)}</div>
        <div class="split-2"><div class="field"><label class="field__label">Order</label><select class="select" data-src="${index}:order">${selectOptions([["sequential", "Sequential"], ["random", "Random"]], s.order)}</select></div><div class="field"><label class="field__label">Radix</label><select class="select" data-src="${index}:radix">${selectOptions([["dec", "Decimal"], ["hex", "Hex"]], s.radix)}</select></div></div>
        <div class="split-2">${numField(index, "minIntegerDigits", "Min integer digits", s.minIntegerDigits, 1)}${numField(index, "maxFractionDigits", "Max fraction digits", s.maxFractionDigits, 0)}</div>`;
    case "dates":
      return `<div class="split-2"><div class="field"><label class="field__label">From</label><input class="input input--mono" type="date" data-src="${index}:from" value="${escapeHtml(s.from)}" /></div><div class="field"><label class="field__label">To</label><input class="input input--mono" type="date" data-src="${index}:to" value="${escapeHtml(s.to)}" /></div></div><div class="split-2">${numField(index, "stepDays", "Step (days)", s.stepDays)}${strField(index, "format", "Format", s.format, "%Y-%m-%d")}</div>`;
    case "bruteForcer":
      return `${strField(index, "charset", "Character set", s.charset, "abcdef0123456789")}<div class="split-2">${numField(index, "minLen", "Min length", s.minLen, 0)}${numField(index, "maxLen", "Max length", s.maxLen, 0)}</div>`;
    case "nullPayloads": {
      const mode = s.count === "continuous" ? "continuous" : "fixed";
      const fixed = s.count === "continuous" ? 10 : s.count.fixed;
      return `<div class="split-2"><div class="field"><label class="field__label">Count</label><select class="select" data-src="${index}:mode">${selectOptions([["fixed", "Fixed"], ["continuous", "Continuous (capped at max results)"]], mode)}</select></div>${numField(index, "fixed", "How many", fixed, 1)}</div>`;
    }
    case "characterFrobber":
      return listField(index, "base", "Base values", s.base, "one value per line");
    case "bitFlipper":
      return `${listField(index, "base", "Base values", s.base, "one value per line")}<div class="field"><label class="field__label">Format</label><select class="select" data-src="${index}:format">${selectOptions([["literal", "Literal text"], ["asciiHex", "ASCII-hex bytes"]], s.format)}</select></div>`;
    case "usernameGenerator":
      return listField(index, "names", "Names or emails", s.names, "John Smith&#10;jane.doe@example.test");
    case "ecbBlockShuffler":
      return `${listField(index, "base", "Base values", s.base, "one value per line")}${numField(index, "blockSize", "Block size (bytes)", s.blockSize, 1)}`;
    case "copyOtherPayload":
      return `${numField(index, "sourcePosition", "Mirror position #", s.sourcePosition, 0)}<p class="field__hint t-subtle">Pitchfork / Cluster bomb only — mirrors the payload of the position with this index.</p>`;
  }
}

/** One processing-pipeline rule row. */
function renderProcessorRow(processor: PayloadProcessor, index: number, position: number): string {
  const p = processor;
  const scalar = (field: string, value: string, placeholder = ""): string => `<input class="input input--mono input--sm" type="text" data-proc-field="${field}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" />`;
  const num = (field: string, value: number | null | undefined, placeholder = ""): string => `<input class="input input--mono input--sm" type="number" min="0" data-proc-field="${field}" value="${value ?? ""}" placeholder="${escapeHtml(placeholder)}" />`;
  const sel = (field: string, options: readonly (readonly [string, string])[], value: string): string => `<select class="select select--sm" data-proc-field="${field}">${selectOptions(options, value)}</select>`;
  let fields = "";
  switch (p.type) {
    case "addPrefix": case "addSuffix": fields = scalar("text", p.text, "text"); break;
    case "matchReplace": fields = `${scalar("pattern", p.pattern, "regex")}${scalar("replacement", p.replacement, "replacement")}`; break;
    case "substring": case "reverseSubstring": fields = `${num("from", p.from, "from")}${num("length", p.length, "length (optional)")}`; break;
    case "modifyCase": fields = sel("mode", CASE_MODES, p.mode); break;
    case "encode": fields = sel("scheme", [["url", "URL"], ["urlAll", "URL (all)"], ["html", "HTML"], ["base64", "Base64"], ["asciiHex", "ASCII-hex"]], p.scheme); break;
    case "decode": fields = sel("scheme", [["url", "URL"], ["html", "HTML"], ["base64", "Base64"], ["asciiHex", "ASCII-hex"]], p.scheme); break;
    case "hash": fields = `${sel("algorithm", [["md5", "MD5"], ["sha1", "SHA-1"], ["sha256", "SHA-256"], ["sha512", "SHA-512"]], p.algorithm)}${sel("output", [["hex", "Hex"], ["base64", "Base64"]], p.output)}`; break;
    case "addRawPayload": fields = '<span class="t-subtle t-small">appends the original payload</span>'; break;
    case "skipIfMatchesRegex": fields = scalar("pattern", p.pattern, "regex"); break;
  }
  return `<div class="row proc-row" data-proc-row="${index}" data-proc-index="${position}">
    <select class="select select--sm" data-proc-type>${selectOptions(PAYLOAD_PROCESSOR_TYPES, p.type)}</select>
    ${fields}
    <span class="spacer"></span>
    <button class="btn btn--sm btn--quiet" type="button" data-proc-up title="Move up">↑</button>
    <button class="btn btn--sm btn--quiet" type="button" data-proc-down title="Move down">↓</button>
    <button class="btn btn--sm btn--quiet" type="button" data-proc-remove title="Remove">✕</button>
  </div>`;
}

/** The full per-set editor: type, settings, processing pipeline, URL-encode. */
function renderPayloadSetBlock(set: FuzzerPayloadSet, index: number, perPosition: boolean): string {
  const count = payloadSetCount(set);
  const countText = set.source.type === "runtimeFile" ? "streamed at run" : `${count >= COUNT_HUGE ? "≈ huge" : count.toLocaleString()} value${count === 1 ? "" : "s"}`;
  const rows = set.processors.map((processor, position) => renderProcessorRow(processor, index, position)).join("");
  return `<div class="stack stack--tight fuzz-set" data-set-block="${index}">
    <div class="row"><label class="field__label">${perPosition ? `Position ${index + 1}` : "Payload set"}</label><span class="spacer"></span><span class="t-subtle t-small" data-set-count="${index}">${countText}</span></div>
    <div class="field"><label class="field__label">Payload type</label><select class="select" data-source-type="${index}">${selectOptions(PAYLOAD_SOURCE_TYPES, set.source.type)}</select></div>
    ${renderSourceSettings(set, index)}
    <div class="stack stack--tight fuzz-processing">
      <div class="row"><p class="section-label">Payload processing</p><span class="spacer"></span><select class="select select--sm" data-add-proc="${index}">${selectOptions(PAYLOAD_PROCESSOR_TYPES, "addPrefix")}</select><button class="btn btn--sm" type="button" data-add-proc-btn="${index}">${icon("plus", { size: 12 })}<span>Add rule</span></button></div>
      ${rows === "" ? '<p class="field__hint t-subtle">No processing rules — payloads are sent as generated.</p>' : rows}
      <div class="field"><label class="field__label">URL-encode these characters</label><input class="input input--mono" type="text" data-url-encode="${index}" value="${escapeHtml(set.urlEncodeChars ?? "")}" placeholder="e.g. &amp;=+/ (blank to skip)" /></div>
    </div>
  </div>`;
}

/** The grep settings: match rules (count columns), extract rules (value
 *  columns), and reflected-payload detection. Additive — never filters. */
function renderGrepSettings(config: FuzzerConfig): string {
  const grep = ensureGrep(config);
  const matchRows = grep.matchRules.map((rule, index) => `<div class="row grep-row" data-grep-match-row="${index}">
    <input class="input input--sm" data-gm-name value="${escapeHtml(rule.name)}" placeholder="name" />
    <input class="input input--mono input--sm" data-gm-pattern value="${escapeHtml(rule.pattern)}" placeholder="expression" />
    <label class="check check--sm"><input type="checkbox" data-gm-regex ${rule.isRegex ? "checked" : ""} /> regex</label>
    <label class="check check--sm"><input type="checkbox" data-gm-case ${rule.caseSensitive ? "checked" : ""} /> case</label>
    <label class="check check--sm"><input type="checkbox" data-gm-nohdr ${rule.excludeHeaders ? "checked" : ""} /> body only</label>
    <span class="spacer"></span>
    <button class="btn btn--sm btn--quiet" type="button" data-grep-match-remove="${index}" title="Remove">✕</button>
  </div>`).join("");
  const extractRows = grep.extractRules.map((rule, index) => {
    const loc = rule.locator;
    let fields: string;
    if (loc.type === "regex") fields = `<input class="input input--mono input--sm" data-ge-field="pattern" value="${escapeHtml(loc.pattern)}" placeholder="regex" /><input class="input input--mono input--sm grep-num" type="number" min="0" data-ge-field="group" value="${loc.group}" title="capture group" />`;
    else if (loc.type === "offset") fields = `<input class="input input--mono input--sm grep-num" type="number" min="0" data-ge-field="start" value="${loc.start}" title="start" /><input class="input input--mono input--sm grep-num" type="number" min="0" data-ge-field="length" value="${loc.length}" title="length" />`;
    else fields = `<input class="input input--mono input--sm" data-ge-field="start" value="${escapeHtml(loc.start)}" placeholder="start delim" /><input class="input input--mono input--sm" data-ge-field="end" value="${escapeHtml(loc.end)}" placeholder="end delim" />`;
    return `<div class="row grep-row" data-grep-extract-row="${index}">
      <input class="input input--sm" data-ge-name value="${escapeHtml(rule.name)}" placeholder="name" />
      <select class="select select--sm" data-ge-type>${selectOptions([["betweenDelimiters", "Between"], ["regex", "Regex"], ["offset", "Offset"]], loc.type)}</select>
      ${fields}
      <input class="input input--mono input--sm grep-num" type="number" min="0" data-ge-maxlen value="${rule.maxLength}" title="max length (0 = unlimited)" />
      <label class="check check--sm"><input type="checkbox" data-ge-first ${rule.firstOnly ? "checked" : ""} /> first only</label>
      <span class="spacer"></span>
      <button class="btn btn--sm btn--quiet" type="button" data-grep-extract-remove="${index}" title="Remove">✕</button>
    </div>`;
  }).join("");
  const r = grep.reflected;
  return `<div class="stack stack--tight">
    <div class="row"><p class="section-label">Grep · match</p><span class="spacer"></span><button class="btn btn--sm btn--quiet" type="button" data-grep-match-add>${icon("plus", { size: 12 })}<span>Add match</span></button></div>
    <p class="field__hint">Each rule adds an occurrence-count column to the results. Flagging only — it never filters.</p>
    ${matchRows}
    <div class="row"><p class="section-label">Grep · extract</p><span class="spacer"></span><button class="btn btn--sm btn--quiet" type="button" data-grep-extract-add>${icon("plus", { size: 12 })}<span>Add extract</span></button></div>
    <p class="field__hint">Each rule adds a value column, extracted from the response body.</p>
    ${extractRows}
    <div class="row"><p class="section-label">Grep · payloads (reflected)</p></div>
    <div class="row grep-row">
      <label class="check check--sm"><input type="checkbox" id="grep-reflected" ${r.enabled ? "checked" : ""} /> flag reflected payloads</label>
      <label class="check check--sm"><input type="checkbox" id="grep-reflected-case" ${r.caseSensitive ? "checked" : ""} /> case</label>
      <label class="check check--sm"><input type="checkbox" id="grep-reflected-nohdr" ${r.excludeHeaders ? "checked" : ""} /> body only</label>
      <label class="check check--sm"><input type="checkbox" id="grep-reflected-preenc" ${r.matchPreUrlEncoded ? "checked" : ""} /> also pre-URL-encoded</label>
    </div>
  </div>`;
}

/** Snapshots the form, mutates the grep block, and re-renders the editor. */
function mutateGrep(mutate: (grep: GrepConfig) => void): void {
  if (selectedFuzzer === null) return;
  readFuzzerForm();
  mutate(ensureGrep(selectedFuzzer.config));
  renderFuzzer();
}

/** Wires the grep settings controls (structural add/remove/type changes). */
function wireGrepSettings(panel: HTMLElement): void {
  panel.querySelector<HTMLButtonElement>("[data-grep-match-add]")?.addEventListener("click", () => mutateGrep((grep) => grep.matchRules.push(newGrepMatchRule(grep.matchRules.length))));
  panel.querySelector<HTMLButtonElement>("[data-grep-extract-add]")?.addEventListener("click", () => mutateGrep((grep) => grep.extractRules.push(newGrepExtractRule(grep.extractRules.length))));
  panel.querySelectorAll<HTMLButtonElement>("[data-grep-match-remove]").forEach((btn) => btn.addEventListener("click", () => mutateGrep((grep) => { grep.matchRules.splice(Number(btn.dataset.grepMatchRemove), 1); })));
  panel.querySelectorAll<HTMLButtonElement>("[data-grep-extract-remove]").forEach((btn) => btn.addEventListener("click", () => mutateGrep((grep) => { grep.extractRules.splice(Number(btn.dataset.grepExtractRemove), 1); })));
  panel.querySelectorAll<HTMLElement>("[data-grep-extract-row]").forEach((row) => {
    const index = Number(row.dataset.grepExtractRow);
    row.querySelector<HTMLSelectElement>("[data-ge-type]")?.addEventListener("change", (event) => {
      const type = (event.target as HTMLSelectElement).value;
      mutateGrep((grep) => { if (grep.extractRules[index] !== undefined) grep.extractRules[index].locator = defaultExtractLocator(type); });
    });
  });
}

/** The draft configuration editor: template + markers, attack type, payloads,
 *  match filter, throughput. */
function renderFuzzerDraftEditor(config: FuzzerConfig, opt: (value: string, label: string, selected: boolean) => string): string {
  const filter = config.matchFilter;
  const positionCount = countTemplatePositions(fuzzTemplate);
  const expected = estimateRequestCount(config.attackType, positionCount, config.payloadSets);
  const perPosition = config.attackType === "pitchfork" || config.attackType === "clusterbomb";
  const setBlocks = config.payloadSets.map((set, index) => renderPayloadSetBlock(set, index, perPosition)).join("");

  return `<div class="stack stack--tight fuzzer-base-block">
    <div class="row"><p class="section-label">Request template</p><span class="spacer"></span>
      <button class="btn btn--sm" type="button" data-fuzz-mark>${icon("plus", { size: 12 })}<span>Add §</span></button>
      <button class="btn btn--sm btn--quiet" type="button" data-fuzz-auto>Auto §</button>
      <button class="btn btn--sm btn--quiet" type="button" data-fuzz-clear>Clear §</button>
    </div>
    <textarea class="textarea fuzzer-base" id="fuzz-template" spellcheck="false">${escapeHtml(fuzzTemplate)}</textarea>
    <p class="field__hint">Wrap each value to fuzz in <code class="t-mono">§…§</code> markers — select text and click <b>Add §</b> (or place the caret to add an empty pair), or <b>Auto §</b> to mark query/body parameters. <span id="fuzz-preview" class="${expected > 10000 ? "t-danger" : "t-subtle"}">${escapeHtml(fuzzPreviewText(positionCount, expected))}</span></p>
  </div>

  <div class="field">
    <label class="field__label" for="fuzzer-type">Attack type</label>
    <select class="select" id="fuzzer-type">${opt("sniper", "Sniper", config.attackType === "sniper")}${opt("battering_ram", "Battering ram", config.attackType === "battering_ram")}${opt("pitchfork", "Pitchfork", config.attackType === "pitchfork")}${opt("clusterbomb", "Cluster bomb", config.attackType === "clusterbomb")}</select>
    <p class="field__hint">${escapeHtml(FUZZ_ATTACK_HINTS[config.attackType] ?? FUZZ_ATTACK_HINTS.sniper)}</p>
  </div>

  <div class="stack stack--tight">
    <p class="section-label">Payloads</p>
    ${perPosition && positionCount === 0 ? '<p class="field__hint t-subtle">Mark at least one position above to supply payloads.</p>' : setBlocks}
  </div>

  <div class="stack stack--tight">
    <p class="section-label">Match filter</p>
    <p class="field__hint">A response is flagged as a match only when it satisfies these rules. Leave all blank to keep every response.</p>
    <div class="split-2">
      <div class="field"><label class="field__label" for="match-statuses">Status codes (comma-separated)</label><input class="input input--mono" id="match-statuses" type="text" value="${escapeHtml(filter.statuses.join(", "))}" placeholder="200, 301, 401" /></div>
      <div class="split-2">
        <div class="field"><label class="field__label" for="match-min">Min length</label><input class="input input--mono" id="match-min" type="number" min="0" value="${filter.minSize ?? ""}" /></div>
        <div class="field"><label class="field__label" for="match-max">Max length</label><input class="input input--mono" id="match-max" type="number" min="0" value="${filter.maxSize ?? ""}" /></div>
      </div>
    </div>
    <div class="split-2">
      <div class="field"><label class="field__label" for="match-contains">Body contains</label><input class="input input--mono" id="match-contains" type="text" value="${escapeHtml(filter.contains ?? "")}" /></div>
      <div class="field"><label class="field__label" for="match-regex">Body regex</label><input class="input input--mono" id="match-regex" type="text" value="${escapeHtml(filter.regex ?? "")}" /></div>
    </div>
  </div>

  ${renderGrepSettings(config)}

  ${renderAttackSettings(config)}`;
}

/** The Resource pool / Attack settings panel: concurrency, delay variant,
 *  retries, redirect policy, connection handling, and Content-Length toggle. */
function renderAttackSettings(config: FuzzerConfig): string {
  ensureAttackSettings(config);
  const delay = config.delay;
  const delayFields = delay.type === "interval"
    ? `<div class="field"><label class="field__label" for="fuzzer-delay-ms">Gap (ms)</label><input class="input input--mono" id="fuzzer-delay-ms" type="number" min="0" value="${delay.ms}" /></div>`
    : delay.type === "random"
      ? `<div class="split-2"><div class="field"><label class="field__label" for="fuzzer-delay-min">Min (ms)</label><input class="input input--mono" id="fuzzer-delay-min" type="number" min="0" value="${delay.minMs}" /></div><div class="field"><label class="field__label" for="fuzzer-delay-max">Max (ms)</label><input class="input input--mono" id="fuzzer-delay-max" type="number" min="0" value="${delay.maxMs}" /></div></div>`
      : `<div class="field"><label class="field__label" for="fuzzer-rate">Rate/s</label><input class="input input--mono" id="fuzzer-rate" type="number" min="0" value="${delay.ratePerSecond}" /><p class="field__hint">0 = unlimited</p></div>`;
  const redirect = config.redirect;
  return `<div class="stack stack--tight">
    <p class="section-label">Resource pool &amp; attack settings</p>
    <div class="split-3">
      <div class="field"><label class="field__label" for="fuzzer-concurrency">Concurrency</label><input class="input input--mono" id="fuzzer-concurrency" type="number" min="1" value="${config.concurrency}" /></div>
      <div class="field"><label class="field__label" for="fuzzer-max">Max results</label><input class="input input--mono" id="fuzzer-max" type="number" min="1" value="${config.maxResults}" /></div>
      <div class="field"><label class="field__label" for="fuzzer-delay-mode">Delay</label><select class="select" id="fuzzer-delay-mode">${selectOptions([["fixed", "Fixed rate"], ["interval", "Interval"], ["random", "Random"]], delay.type)}</select></div>
    </div>
    <div class="split-2">${delayFields}
      <div class="split-2">
        <div class="field"><label class="field__label" for="fuzzer-retries">Retries</label><input class="input input--mono" id="fuzzer-retries" type="number" min="0" value="${config.retry.maxRetries}" /></div>
        <div class="field"><label class="field__label" for="fuzzer-retry-pause">Retry pause (ms)</label><input class="input input--mono" id="fuzzer-retry-pause" type="number" min="0" value="${config.retry.pauseMs}" /></div>
      </div>
    </div>
    <div class="split-3">
      <div class="field"><label class="field__label" for="fuzzer-redirect-mode">Redirects</label><select class="select" id="fuzzer-redirect-mode">${selectOptions([["never", "Never"], ["onSite", "On-site"], ["inScope", "In-scope"], ["always", "Always"]], redirect.mode)}</select></div>
      <div class="field"><label class="field__label" for="fuzzer-redirect-hops">Max hops</label><input class="input input--mono" id="fuzzer-redirect-hops" type="number" min="0" value="${redirect.maxHops}" /></div>
      <div class="field"><label class="field__label">&nbsp;</label><label class="check check--sm"><input type="checkbox" id="fuzzer-redirect-cookies" ${redirect.processCookies ? "checked" : ""} /> process cookies</label></div>
    </div>
    <div class="row fuzz-list-actions">
      <label class="check check--sm"><input type="checkbox" id="fuzzer-connection-close" ${config.connectionClose ? "checked" : ""} /> Connection: close</label>
      <label class="check check--sm"><input type="checkbox" id="fuzzer-update-cl" ${config.updateContentLength ? "checked" : ""} /> update Content-Length</label>
    </div>
  </div>`;
}

/** Read-only summary + progress for a created (running/finished) attack. */
function renderFuzzerLockedSummary(job: FuzzerJob): string {
  const config = job.config;
  const expected = estimateRequestCount(config.attackType, config.positions.length, config.payloadSets);
  const matched = job.results.filter((result) => result.matched).length;
  // The ffuf tier reports only matched hits, so its result count is not the
  // attempt count; prefer its live progress (sent/total) when present (#16b).
  const progress = job.progress ?? null;
  const sent = progress !== null ? progress.sent : job.results.length;
  const total = progress !== null && progress.total > 0 ? progress.total : expected;
  const percent = total > 0 ? Math.min(100, Math.round((sent / total) * 100)) : 0;
  const elapsed = fuzzStartedAt > 0 ? (Date.now() - fuzzStartedAt) / 1000 : 0;
  // The first `concurrency` requests fire immediately as the initial in-flight
  // batch before pacing throttles the rest, so an average taken during that
  // burst overstates the rate (e.g. 5 sent at 0.5s reads ~10/s under a 2/s
  // limit). Only show a rate once we're past that batch, when sent/elapsed
  // reflects the real steady pacing (#19d).
  const rate = job.state === "running" && elapsed > 1 && sent > config.concurrency ? `${(sent / elapsed).toFixed(1)}/s` : "";
  const tone = job.state === "completed" ? " progress--success" : job.state === "failed" ? " progress--failed" : job.state === "running" ? " progress--running" : "";
  const totalText = expected >= COUNT_HUGE ? "≈ huge" : expected.toLocaleString();
  const label = `${config.attackType.replace("_", " ")} · ${config.positions.length} position${config.positions.length === 1 ? "" : "s"} · ~${totalText} requests`;
  return `<div class="stack stack--tight">
    <p class="section-label">Attack</p>
    <p class="t-small t-subtle">${escapeHtml(label)}</p>
    <pre class="code fuzzer-base--compact">${escapeHtml(rawRequestText(config.baseRequest))}</pre>
    <div class="progress${tone}" role="progressbar" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100">
      <div class="progress__meta"><span>Sent ${sent.toLocaleString()}${total > 0 ? ` of ~${total.toLocaleString()}` : ""} · ${matched} matched${rate === "" ? "" : ` · ${rate}`}</span><span class="progress__value">${percent}%</span></div>
      <div class="progress__track"><div class="progress__fill" style="width:${percent}%"></div></div>
    </div>
  </div>`;
}

/** Start / pause / resume / stop, appropriate to the current state. */
function renderFuzzerControls(job: FuzzerJob, locked: boolean): string {
  const state = job.state;
  if (!locked) {
    return `<div class="row"><button class="btn btn--primary" id="fuzzer-launch" type="button">${icon("play", { size: 14 })}<span>Start attack</span></button></div>`;
  }
  if (state === "running") {
    return `<div class="row"><button class="btn" id="fuzzer-pause" type="button">${icon("pause", { size: 14 })}<span>Pause</span></button><button class="btn btn--danger" id="fuzzer-stop" type="button">${icon("stop", { size: 14 })}<span>Stop</span></button></div>`;
  }
  if (state === "paused") {
    return `<div class="row"><button class="btn btn--primary" id="fuzzer-launch" type="button">${icon("play", { size: 14 })}<span>Resume</span></button><button class="btn btn--danger" id="fuzzer-stop" type="button">${icon("stop", { size: 14 })}<span>Stop</span></button></div>`;
  }
  // completed / stopped / failed — offer edit & re-run into a fresh draft (#20).
  return `<div class="row"><button class="btn" id="fuzzer-rerun" type="button">${icon("discovery", { size: 14 })}<span>Edit &amp; re-run</span></button></div>`;
}

/** Clones a finished job into a new editable draft — its config and, when known,
 *  the exact §-marked template it ran — so the operator can tweak and run again. */
function editAndRerunFuzz(job: FuzzerJob): void {
  saveActiveDraftTemplate();
  const key = `draft-${(nextDraftSeq += 1)}`;
  const draft: FuzzerJob = {
    id: "",
    tier: "native",
    state: "draft",
    config: structuredClone(job.config),
    results: [],
    diagnostics: [],
  };
  fuzzDrafts.set(key, draft);
  // Prefer the verbatim template it ran; else fall back to the unmarked base
  // request (a job restored from disk), which the operator re-marks.
  fuzzDraftTemplates.set(key, fuzzJobTemplates.get(job.id) ?? rawRequestText(draft.config.baseRequest));
  selectedFuzzer = draft;
  selectedDraftKey = key;
  fuzzTemplate = fuzzDraftTemplates.get(key) ?? "";
  selectedFuzzResult = null;
  fuzzResultSort = { key: "ordinal", dir: 1 };
  renderFuzzer();
  renderFuzzList();
}

/** Re-renders only the results region (sort/row-select) without disturbing the
 *  draft editor above it. */
function renderFuzzerResultsInto(): void {
  const region = fuzzerPanel?.querySelector<HTMLElement>("#fuzzer-results");
  if (region === null || region === undefined || selectedFuzzer === null) return;
  region.innerHTML = renderFuzzerResults(selectedFuzzer);
  wireFuzzResults(region);
}

/** Restores focus (cursor at end) to a filter input after a results re-render. */
function refocusFuzzFilter(selector: string): void {
  const input = fuzzerPanel?.querySelector<HTMLInputElement>(selector);
  if (input !== null && input !== undefined) {
    input.focus();
    const end = input.value.length;
    input.setSelectionRange(end, end);
  }
}

/** Persists a result comment via the engine, updating the local model in place. */
async function setFuzzComment(ordinal: number, comment: string): Promise<void> {
  if (selectedFuzzer === null || selectedFuzzer.id === "") return;
  const result = selectedFuzzer.results.find((candidate) => candidate.ordinal === ordinal);
  if (result !== undefined) result.comment = comment === "" ? null : comment;
  try {
    const response = await fetch(`/api/v1/workbench/fuzzer/${encodeURIComponent(selectedFuzzer.id)}/results/${ordinal}/comment`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ comment: comment === "" ? null : comment }),
    });
    await requireOk(response, "comment save failed");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-config-invalid", what: "The comment could not be saved.", why: "", fix: "Try again." });
  }
}

/** Live-updates the request-count preview as the template or payloads change. */
function updateFuzzPreview(): void {
  if (selectedFuzzer === null || fuzzerPanel === null || fuzzerConfigLocked()) return;
  readFuzzerForm();
  const positionCount = countTemplatePositions(fuzzTemplate);
  const expected = estimateRequestCount(selectedFuzzer.config.attackType, positionCount, selectedFuzzer.config.payloadSets);
  const preview = fuzzerPanel.querySelector<HTMLElement>("#fuzz-preview");
  if (preview !== null) {
    preview.textContent = fuzzPreviewText(positionCount, expected);
    preview.className = expected > 10000 ? "t-danger" : "t-subtle";
  }
  // Keep each payload set's "N values" header live as values are typed, rather
  // than only on a structural re-render (#19c).
  selectedFuzzer.config.payloadSets.forEach((set, index) => {
    const cell = fuzzerPanel?.querySelector<HTMLElement>(`[data-set-count="${index}"]`);
    if (cell === null || cell === undefined) return;
    const count = payloadSetCount(set);
    cell.textContent = set.source.type === "runtimeFile" ? "streamed at run" : `${count >= COUNT_HUGE ? "≈ huge" : count.toLocaleString()} value${count === 1 ? "" : "s"}`;
  });
}

function renderFuzzerResults(job: FuzzerJob): string {
  const results = job.results;
  if (results.length === 0) {
    return stateBlock({
      icon: "discovery",
      title: job.state === "running" ? "Waiting for the first response…" : "No results yet",
      body: fuzzerConfigLocked() ? "Requests will stream in as they complete." : "Mark positions, supply payloads, then start the attack.",
      compact: true,
    });
  }
  const matchedCount = results.filter((result) => result.matched).length;
  const grep = job.config.grep ?? newGrepConfig();
  const payloadCols = fuzzPayloadColumnCount(job);
  const anyError = results.some((result) => result.diagnostic !== null && result.diagnostic !== undefined);
  const arrow = (key: string): string => (fuzzResultSort.key === key ? (fuzzResultSort.dir === 1 ? " ▲" : " ▼") : "");
  const visible = results.filter(fuzzResultMatchesFilter).sort((a, b) => {
    const av = fuzzSortComparable(a, fuzzResultSort.key);
    const bv = fuzzSortComparable(b, fuzzResultSort.key);
    const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
    return cmp * fuzzResultSort.dir || a.ordinal - b.ordinal;
  });
  // Dynamic header set: base + per-set payloads + status/length/time (+error) +
  // timeout + one column per grep match/extract rule (+reflected) + match + comment.
  const headers = [`<th data-sort="ordinal">#${arrow("ordinal")}</th>`];
  for (let i = 0; i < payloadCols; i += 1) headers.push(`<th data-sort="payload:${i}">${payloadCols === 1 ? "Payload" : `Payload ${i + 1}`}${arrow(`payload:${i}`)}</th>`);
  headers.push(`<th data-sort="status">Status${arrow("status")}</th>`, `<th data-sort="length">Length${arrow("length")}</th>`, `<th data-sort="time">Time${arrow("time")}</th>`);
  if (anyError) headers.push(`<th data-sort="error">Error${arrow("error")}</th>`);
  headers.push(`<th data-sort="timeout">Timeout${arrow("timeout")}</th>`);
  grep.matchRules.forEach((rule, i) => headers.push(`<th data-sort="match:${i}" title="grep match count">${escapeHtml(rule.name)}${arrow(`match:${i}`)}</th>`));
  grep.extractRules.forEach((rule, i) => headers.push(`<th data-sort="extract:${i}" title="grep extract">${escapeHtml(rule.name)}${arrow(`extract:${i}`)}</th>`));
  if (grep.reflected.enabled) headers.push(`<th data-sort="reflected">Reflected${arrow("reflected")}</th>`);
  const anyRedirects = results.some((result) => (result.redirectChain?.length ?? 0) > 0);
  if (anyRedirects) headers.push(`<th data-sort="redirects">Redirects${arrow("redirects")}</th>`);
  headers.push(`<th>Match</th>`, `<th>Comment</th>`);
  const rows = visible.map((result) => {
    const status = result.response?.status;
    const selected = selectedFuzzResult === result.ordinal ? " is-selected" : "";
    const cells = [`<td>${result.ordinal}</td>`];
    for (let i = 0; i < payloadCols; i += 1) cells.push(`<td class="t-mono">${escapeHtml(result.payloads[i] ?? "")}</td>`);
    const failure = status === undefined ? fuzzFailure(result) : null;
    cells.push(`<td><span class="list-row__status" data-class="${statusClass(status)}"${failure === null ? "" : ` title="${escapeHtml(failure.detail)}"`}>${status ?? escapeHtml(failure?.label ?? "failed")}</span></td>`);
    cells.push(`<td class="t-numeric">${fuzzResponseLength(result) ?? "—"}</td>`);
    cells.push(`<td class="t-numeric">${result.response?.durationMs ?? "—"}</td>`);
    if (anyError) {
      const error = fuzzFailure(result);
      cells.push(`<td class="t-small t-subtle"${error === null ? "" : ` title="${escapeHtml(error.detail)}"`}>${error === null ? "" : escapeHtml(error.label)}</td>`);
    }
    cells.push(`<td>${result.timeout === true ? '<span class="badge badge--caution">timeout</span>' : ""}</td>`);
    grep.matchRules.forEach((_, i) => { const count = result.grepMatchCounts?.[i] ?? 0; cells.push(`<td class="t-numeric${count > 0 ? " t-strong" : " t-subtle"}">${count}</td>`); });
    grep.extractRules.forEach((_, i) => cells.push(`<td class="t-mono t-small">${escapeHtml(result.grepExtracts?.[i] ?? "")}</td>`));
    if (grep.reflected.enabled) { const count = result.reflectedCount ?? 0; cells.push(`<td class="t-numeric${count > 0 ? " t-strong" : " t-subtle"}">${count}</td>`); }
    if (anyRedirects) { const hops = result.redirectChain?.length ?? 0; cells.push(`<td class="t-numeric${hops > 0 ? " t-strong" : " t-subtle"}">${hops}</td>`); }
    cells.push(`<td>${result.matched ? '<span class="badge badge--success">match</span>' : result.filtered ? '<span class="t-subtle">filtered</span>' : ""}</td>`);
    cells.push(`<td><input class="input input--sm fuzz-comment" data-comment-ordinal="${result.ordinal}" value="${escapeHtml(result.comment ?? "")}" placeholder="…" /></td>`);
    return `<tr class="fuzz-row${result.matched ? " is-match" : ""}${selected}" data-result-row="${result.ordinal}">${cells.join("")}</tr>`;
  }).join("");
  const filterBar = `<div class="row fuzz-filter">
    <input class="input input--sm" id="fuzz-filter-search" value="${escapeHtml(fuzzDisplayFilter.search)}" placeholder="Filter results…" />
    <input class="input input--sm grep-num" id="fuzz-filter-status" value="${escapeHtml(fuzzDisplayFilter.status)}" placeholder="status" />
    <label class="check check--sm"><input type="checkbox" id="fuzz-filter-matched" ${fuzzDisplayFilter.onlyMatched ? "checked" : ""} /> only matched</label>
    <span class="spacer"></span><span class="t-subtle t-small">${visible.length.toLocaleString()} of ${results.length.toLocaleString()}</span>
  </div>`;
  const detail = renderFuzzResultDetail(results);
  return `<div class="stack stack--tight"><p class="section-label">Results · ${results.length} · ${matchedCount} matched</p>
${filterBar}
<div class="discovery-results"><table class="data-table data-table--clickable"><thead><tr>${headers.join("")}</tr></thead><tbody>${rows}</tbody></table></div>
${detail}</div>`;
}

/** The number of per-set payload columns to render. */
function fuzzPayloadColumnCount(job: FuzzerJob): number {
  const perPosition = job.config.attackType === "pitchfork" || job.config.attackType === "clusterbomb";
  const widest = job.results.reduce((max, result) => Math.max(max, result.payloads.length), 1);
  return Math.max(widest, perPosition ? job.config.positions.length : 1);
}

/** The comparable value for a result under a (possibly dynamic) sort key. */
/** The response length for a result: the body length when present, else the
 *  reported Content-Length (ffuf-tier rows carry length here, not a body). */
function fuzzResponseLength(result: FuzzerResult): number | null {
  const response = result.response;
  if (response === null || response === undefined) return null;
  if (response.body !== null && response.body !== undefined) return response.body.length;
  const header = response.headers.find(([name]) => name.toLowerCase() === "content-length")?.[1];
  const value = header === undefined ? Number.NaN : Number(header);
  return Number.isFinite(value) ? value : null;
}

function fuzzSortComparable(result: FuzzerResult, key: string): number | string {
  if (key === "status") return result.response?.status ?? -1;
  if (key === "length") return fuzzResponseLength(result) ?? -1;
  if (key === "time") return result.response?.durationMs ?? -1;
  if (key === "error") return fuzzFailure(result)?.label ?? "";
  if (key === "timeout") return result.timeout === true ? 1 : 0;
  if (key === "reflected") return result.reflectedCount ?? -1;
  if (key === "redirects") return result.redirectChain?.length ?? -1;
  if (key === "retries") return result.retryCount ?? 0;
  if (key.startsWith("payload:")) return result.payloads[Number(key.slice("payload:".length))] ?? "";
  if (key.startsWith("match:")) return result.grepMatchCounts?.[Number(key.slice("match:".length))] ?? -1;
  if (key.startsWith("extract:")) return result.grepExtracts?.[Number(key.slice("extract:".length))] ?? "";
  return result.ordinal;
}

/** Whether a result passes the current client-side display filter. */
function fuzzResultMatchesFilter(result: FuzzerResult): boolean {
  const filter = fuzzDisplayFilter;
  if (filter.onlyMatched && !result.matched) return false;
  if (filter.status.trim() !== "" && String(result.response?.status ?? "") !== filter.status.trim()) return false;
  if (filter.search.trim() !== "") {
    const haystack = [result.payloads.join(" "), result.comment ?? "", String(result.response?.status ?? ""), ...(result.grepExtracts ?? []).map((value) => value ?? "")].join(" ").toLowerCase();
    if (!haystack.includes(filter.search.trim().toLowerCase())) return false;
  }
  return true;
}

/** The request/response inspector for the selected result row. */
function renderFuzzResultDetail(results: readonly FuzzerResult[]): string {
  if (selectedFuzzResult === null) return "";
  const result = results.find((candidate) => candidate.ordinal === selectedFuzzResult);
  if (result === undefined) return "";
  const responseText = result.response
    ? `${result.response.status}\n${formatHeaders(result.response.headers)}${bytesToText(result.response.body) === "" ? "" : `\n\n${bytesToText(result.response.body)}`}`
    : "";
  // The ffuf fast-path does not capture the full response — it reports only status
  // and size, which we surface as a synthesized Content-Length. Label it honestly
  // as reconstructed rather than presenting it as a full captured response. The
  // native tier captures the real response, so its label stays plain.
  const ffufTier = selectedFuzzer?.tier === "ffuf";
  const responseLabel = ffufTier
    ? `Response <span class="t-subtle t-small">(reconstructed from ffuf · status + size; body not captured)</span>`
    : "Response";
  const chain = result.redirectChain ?? [];
  const chainBlock = chain.length === 0
    ? ""
    : `<div class="stack stack--tight fuzz-redirect-chain"><p class="section-label">Redirect chain · ${chain.length} hop${chain.length === 1 ? "" : "s"}${(result.retryCount ?? 0) > 0 ? ` · ${result.retryCount} retr${result.retryCount === 1 ? "y" : "ies"}` : ""}</p>${chain.map((hop) => `<p class="t-small t-mono">${hop.status} → ${escapeHtml(hop.location)}</p>`).join("")}</div>`;
  return `<div class="stack stack--tight">${chainBlock}<div class="reqres fuzz-detail">
  <div class="reqres__col"><p class="section-label">Request · #${result.ordinal} <span class="t-subtle t-small">(as sent)</span></p><pre class="code">${escapeHtml(rawRequestText(result.request, { recomputeContentLength: selectedFuzzer?.config.updateContentLength ?? true }))}</pre></div>
  <div class="reqres__col"><p class="section-label">${responseLabel}</p>${result.response
    ? `<pre class="code">${escapeHtml(responseText)}</pre>`
    : resendFailureHtml(result.diagnostic ?? { id: "proxy.resend-request-failed", what: "No response was received.", why: "The attempt failed without a recorded reason.", fix: "Retry the attack; if it persists, check the session proxy." }, `#${result.ordinal} — no HTTP response.`)}</div>
</div></div>`;
}

/** Short plain-language label for a Fuzz result with no response, plus the
 *  full what/why for its hover title (the row inspector shows everything). */
function fuzzFailure(result: FuzzerResult): { label: string; detail: string } | null {
  const diagnostic = result.diagnostic;
  if (diagnostic === null || diagnostic === undefined) return null;
  const text = resendFailureText(diagnostic);
  return { label: failureLabel(diagnostic), detail: `${text.title} — ${text.why} (${diagnostic.id})` };
}

/** One or two words for a failed exchange: "refused", "timed out", … */
function failureLabel(diagnostic: ContextDiagnostic): string {
  const error = (diagnosticText(diagnostic, "error") ?? "").toLowerCase();
  if (diagnostic.id === "proxy.resend-timed-out" || diagnosticText(diagnostic, "timeout") === "true" || /timed out|10060/.test(error)) return "timed out";
  if (diagnostic.id === "proxy.resend-cancelled" || diagnostic.id === "proxy.fuzzer-cancelled") return "cancelled";
  if (diagnostic.id === "proxy.upstream-unreachable" || diagnostic.id === "proxy.resend-request-failed") {
    if (/refused|10061|econnrefused/.test(error)) return "refused";
    if (/dns|no such host|11001|name or service not known|failed to lookup|nodename/.test(error)) return "DNS failed";
    if (/tls|certificate|handshake/.test(error)) return "TLS failed";
    if (/reset|10054|forcibly closed|broken pipe|closed before/.test(error)) return "reset";
    if (/unreachable|10051|10065/.test(error)) return "unreachable";
    return diagnostic.id === "proxy.upstream-unreachable" ? "no connection" : "send failed";
  }
  if (diagnostic.id === "proxy.resend-outside-scope" || diagnostic.id === "proxy.fuzzer-outside-scope") return "out of scope";
  return "failed";
}

async function launchFuzzer(): Promise<void> {
  if (selectedFuzzer === null) return;
  try {
    const startedDraftKey = selectedDraftKey;
    if (selectedFuzzer.id === "") {
      readFuzzerForm();
      const config = selectedFuzzer.config;
      // Compile the §-marked raw request into a base request + payload positions;
      // the scheme comes from the captured flow's origin so the URL round-trips.
      const parsed = parseFuzzTemplate(fuzzTemplate, fuzzTemplateScheme());
      if (parsed.error !== undefined) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "The request template markers are invalid.", why: parsed.error, fix: "Fix the § markers so each position is a matched pair, then start." }); return; }
      if (parsed.positions.length === 0) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "The attack has no payload positions.", why: "No § markers are set, so there is nothing to fuzz.", fix: "Select a value in the request and click Add § (or Auto), then start." }); return; }
      config.baseRequest = { method: parsed.method, url: parsed.url, headers: parsed.headers, body: parsed.body };
      // Map positions to payload sets: Sniper/Battering ram share one set;
      // Pitchfork/Cluster bomb take one set per position, in order.
      const perPosition = config.attackType === "pitchfork" || config.attackType === "clusterbomb";
      config.positions = parsed.positions.map((position, index) => ({ ...position, setIndex: perPosition ? index : 0 }));
      reconcilePayloadSets(config, config.attackType, config.positions.length);
      const usedSets = perPosition ? config.payloadSets.slice(0, config.positions.length) : config.payloadSets.slice(0, 1);
      if (usedSets.every(payloadSetIsEmpty)) { showDiagnostic({ id: "proxy.fuzzer-config-invalid", what: "No payloads were supplied.", why: "Every payload set is empty, so there is nothing to send.", fix: "Enter payload values (or configure a generated source), then start." }); return; }
      config.sequence = [];
      const created = await fetch("/api/v1/workbench/fuzzer", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(config) });
      await requireOk(created, "fuzzer configuration failed");
      selectedFuzzer = (await created.json()) as FuzzerJob;
      // Remember the exact template this job ran, so it can be edited & re-run.
      fuzzJobTemplates.set(selectedFuzzer.id, fuzzTemplate);
      // The draft became a real job; drop its local draft entry so it does not
      // linger as a duplicate row.
      if (startedDraftKey !== null) {
        fuzzDrafts.delete(startedDraftKey);
        fuzzDraftTemplates.delete(startedDraftKey);
        selectedDraftKey = null;
      }
    }
    const action = selectedFuzzer.state === "paused" ? "resume" : "start";
    fuzzStartedAt = Date.now();
    selectedFuzzResult = null;
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
    // Stop marks the job Stopped immediately, but the in-flight batch keeps
    // completing and recording for a moment; refresh once more so the "Sent"
    // count reconciles to what actually reached the target.
    window.setTimeout(() => void refreshFuzzer(), 900);
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

/** The item whose editor is currently mounted (null when none). */
let renderedResendId: string | null = null;

function renderResend(): void {
  if (resendPanel === null || selectedResend === null) return;
  const ctx = selectedResend;
  resendPanel.hidden = false;
  selectedResendRevision = null;
  renderedResendId = ctx.id;
  const draft = resendDrafts.get(ctx.id);
  const target = draft?.target ?? urlOrigin(ctx.current.url);
  const rawText = draft?.raw ?? rawRequestText(ctx.current, { recomputeContentLength: true });
  resendPanel.innerHTML = `<div class="panel__header">
  <div class="panel__heading">${icon("send", { size: 16 })}<h2 title="${escapeHtml(ctx.current.url)}">${escapeHtml(resendTitle(ctx))}</h2></div>
  <div class="row">
    <button class="btn btn--sm btn--quiet" type="button" data-resend-copy-curl title="Copy the editor's request as a curl command (bash/zsh)">${icon("copy", { size: 14 })}<span>Copy curl</span></button>
    <button class="btn btn--sm btn--quiet" type="button" data-resend-copy-url title="Copy the editor's request URL">${icon("copy", { size: 14 })}<span>Copy URL</span></button>
    <button class="btn btn--quiet btn--icon" type="button" data-close-resend><span class="visually-hidden">Close Resend</span>${icon("close", { size: 16 })}</button>
  </div>
</div>
<div class="resend-split" data-resend-split>
  <div class="resend-split__pane resend-req">
    <div class="reqline">
      <input class="input input--mono reqline__url" id="resend-target" aria-label="Target — scheme://host:port the connection goes to" title="Target — where the connection goes. The Host header below is sent exactly as written." placeholder="https://api.example.com" spellcheck="false" value="${escapeHtml(target)}" />
    </div>
    <div class="resend-req__head"><p class="section-label">Request</p>${methodChipHtml(requestMethod(rawText))}${viewToggleHtml("req", resendRequestView)}${messageToolsHtml("req")}</div>
    ${findBarHtml("req")}
    <textarea class="textarea resend-raw${resendWrap("req") ? "" : " is-nowrap"}" id="resend-raw" aria-label="Raw HTTP request" spellcheck="false" wrap="${resendWrap("req") ? "soft" : "off"}" hidden>${escapeHtml(rawText)}</textarea>
    <pre class="code resend-pretty${resendWrap("req") ? "" : " is-nowrap"}" id="resend-req-pretty" aria-label="Request (read-only view)" hidden></pre>
    <p class="t-small resend-parse-error" id="resend-parse-error" role="alert" hidden></p>
    <div class="row resend-actions">
      <button class="btn btn--primary" id="resend-send" type="button" title="Send request (Ctrl+Enter)" aria-keyshortcuts="Control+Enter">${icon("send", { size: 14 })}<span>Send request</span></button>
      <button class="btn btn--sm" id="resend-cancel" type="button" title="Stop waiting for this send; it is kept in History as cancelled" hidden>Cancel</button>
      <label class="check check--sm" title="Off: a 3xx is shown as-is and you follow it with Follow redirection. On: each redirect is followed one hop at a time (up to ${RESEND_MAX_AUTO_HOPS}), every hop kept in History."><input type="checkbox" id="resend-autofollow"${resendAutoFollow() ? " checked" : ""} /> Follow redirects automatically</label>
      <label class="resend-timeout t-small" title="How long a send waits for a response before it is recorded as timed out">Timeout <select class="input input--sm" id="resend-timeout" aria-label="Send timeout">${RESEND_TIMEOUT_CHOICES.map((secs) => `<option value="${secs}"${secs === resendTimeoutSecs() ? " selected" : ""}>${secs} s</option>`).join("")}</select></label>
      <button class="btn btn--sm btn--quiet" type="button" id="resend-urlencode" title="URL-encode the text selected in the Raw request (Ctrl+U)" aria-keyshortcuts="Control+U">URL-encode selection</button>
    </div>
    <details class="resend-inspector" id="resend-inspector"${resendInspectorOpen() ? " open" : ""}><summary class="t-small" id="resend-inspector-summary">Inspector</summary><div class="resend-inspector__body" id="resend-inspector-body"></div></details>
  </div>
  <div class="resend-split__gutter" data-resend-gutter role="separator" aria-orientation="vertical" tabindex="0" aria-label="Resize request and response"></div>
  <div class="resend-split__pane resend-res" id="resend-res-pane"></div>
</div>`;
  const raw = resendPanel.querySelector<HTMLTextAreaElement>("#resend-raw");
  raw?.addEventListener("input", () => {
    // Keep Content-Length showing what will be sent while the body is edited.
    const synced = syncContentLength(raw.value);
    if (synced !== null) {
      const caret = raw.selectionStart;
      raw.value = synced.text;
      const next = caret > synced.at ? caret + synced.delta : caret;
      raw.setSelectionRange(next, next);
    }
    rememberResendDraft(ctx.id);
    scheduleResendInspector();
    syncMethodChip();
  });
  raw?.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "u") { event.preventDefault(); urlEncodeResendSelection(); }
  });
  resendPanel.querySelector("#resend-target")?.addEventListener("input", () => rememberResendDraft(ctx.id));
  resendPanel.querySelector<HTMLSelectElement>("#resend-method")?.addEventListener("change", (event) => {
    const method = (event.target as HTMLSelectElement).value;
    if (raw === null || method === "") return;
    const swapped = setRequestMethod(raw.value, method);
    raw.value = swapped.text;
    raw.dispatchEvent(new Event("input"));
    applyResendRequestView();
  });
  resendPanel.querySelector("#resend-urlencode")?.addEventListener("click", () => urlEncodeResendSelection());
  resendPanel.querySelector("[data-resend-copy-curl]")?.addEventListener("click", () => void copyResendRequest("curl"));
  resendPanel.querySelector("[data-resend-copy-url]")?.addEventListener("click", () => void copyResendRequest("url"));
  resendPanel.querySelector<HTMLDetailsElement>("#resend-inspector")?.addEventListener("toggle", (event) => {
    setResendInspectorOpen((event.target as HTMLDetailsElement).open);
  });
  const reqPane = resendPanel.querySelector<HTMLElement>(".resend-req");
  if (reqPane !== null) wireMessageTools(reqPane, "req", () => applyResendRequestView());
  // Ctrl+Enter (⌘+Enter) sends from anywhere in the request editor.
  resendPanel.querySelector(".resend-req")?.addEventListener("keydown", (event) => {
    const key = event as KeyboardEvent;
    if (key.key === "Enter" && (key.ctrlKey || key.metaKey)) {
      key.preventDefault();
      void sendResend();
    }
  });
  resendPanel.querySelector("#resend-cancel")?.addEventListener("click", () => void cancelResend(ctx.id));
  resendPanel.querySelector<HTMLSelectElement>("#resend-timeout")?.addEventListener("change", (event) => {
    setResendTimeoutSecs(Number((event.target as HTMLSelectElement).value));
  });
  resendPanel.querySelectorAll<HTMLButtonElement>('[data-view-toggle="req"] [data-view-mode]').forEach((button) => {
    button.addEventListener("click", () => {
      resendRequestView = button.dataset.viewMode === "pretty" ? "pretty" : "raw";
      applyResendRequestView();
    });
  });
  resendPanel.querySelector("#resend-send")?.addEventListener("click", () => void sendResend());
  resendPanel.querySelector<HTMLInputElement>("#resend-autofollow")?.addEventListener("change", (event) => {
    setResendAutoFollow((event.target as HTMLInputElement).checked);
  });
  resendPanel.querySelector("[data-close-resend]")?.addEventListener("click", () => { selectedResend = null; seedResendEmpty(); renderResendList(); });
  applyResendRequestView();
  renderResendInspector();
  if (resendInFlight.has(ctx.id)) {
    setResendSendBusy(true);
    showResendResponseLoading();
  } else {
    mountResendResponse();
  }
  initResendSplitter();
}

/* ---- RS5: message tools (find / wrap / non-printables), Inspector, copy,
 * method switch, URL-encode. The raw request text is the only source of truth;
 * every helper reads it or edits it. */

const STANDARD_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/** Method chip: switching it rewrites the request line's method token. */
function methodChipHtml(current: string): string {
  const upper = current.toUpperCase();
  const options = STANDARD_METHODS.includes(upper) || upper === "" ? STANDARD_METHODS : [upper, ...STANDARD_METHODS];
  return `<select class="input input--sm input--mono resend-method" id="resend-method" aria-label="Method — rewrites the request line" title="Method — rewrites the request line's method">${options.map((m) => `<option value="${m}"${m === upper ? " selected" : ""}>${m}</option>`).join("")}</select>`;
}

/** Keeps the method chip showing the request line's method as it is edited. */
function syncMethodChip(): void {
  const chip = resendPanel?.querySelector<HTMLSelectElement>("#resend-method");
  if (chip === null || chip === undefined) return;
  const method = requestMethod(valueOf("#resend-raw")).toUpperCase();
  if (chip.value === method) return;
  if (!Array.from(chip.options).some((option) => option.value === method) && method !== "") chip.insertAdjacentHTML("afterbegin", `<option value="${escapeHtml(method)}">${escapeHtml(method)}</option>`);
  chip.value = method;
}

type MessageSide = "req" | "res";
const RESEND_MSG_PREFS_KEY = "apiaxess.resend.messagePrefs";
function messagePrefs(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(RESEND_MSG_PREFS_KEY) ?? "{}") as Record<string, boolean>; } catch { return {}; }
}
function setMessagePref(key: string, on: boolean): void {
  const all = messagePrefs();
  all[key] = on;
  try { localStorage.setItem(RESEND_MSG_PREFS_KEY, JSON.stringify(all)); } catch { /* a preference; ignore storage failures */ }
}
/** Word wrap (on by default, so one-line JSON never scrolls sideways). */
function resendWrap(side: MessageSide): boolean { return messagePrefs()[`wrap.${side}`] !== false; }
/** Visible non-printables (off by default). */
function resendNonPrintables(side: MessageSide): boolean { return messagePrefs()[`np.${side}`] === true; }
function resendInspectorOpen(): boolean { return messagePrefs().inspector === true; }
function setResendInspectorOpen(open: boolean): void { setMessagePref("inspector", open); }

function messageToolsHtml(side: MessageSide): string {
  const np = side === "req"
    ? "Show non-printable characters (tab, control bytes). Display only — turn off to edit."
    : "Show non-printable characters (CR, tab, control bytes)";
  return `<div class="msgtools" role="group" aria-label="${side === "req" ? "Request" : "Response"} message tools">
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-msg-find title="Find in message (Ctrl+F)" aria-label="Find in message">${icon("search", { size: 14 })}</button>
  <button class="btn btn--sm btn--quiet" type="button" data-msg-wrap aria-pressed="${resendWrap(side)}" title="Wrap long lines">Wrap</button>
  <button class="btn btn--sm btn--quiet" type="button" data-msg-np aria-pressed="${resendNonPrintables(side)}" title="${np}" aria-label="Show non-printable characters">¶</button>
</div>`;
}

/** Find state per message, kept across re-renders of the History pane. */
const findState: Record<MessageSide, { open: boolean; query: string; index: number }> = {
  req: { open: false, query: "", index: 0 },
  res: { open: false, query: "", index: 0 },
};

function findBarHtml(side: MessageSide): string {
  const state = findState[side];
  return `<div class="findbar" data-findbar="${side}"${state.open ? "" : " hidden"}>
  <input class="input input--sm input--mono findbar__input" type="search" data-find-input placeholder="Find in message" aria-label="Find in message" value="${escapeHtml(state.query)}" />
  <span class="t-small t-subtle findbar__count" data-find-count aria-live="polite"></span>
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-find-step="-1" title="Previous match (Shift+Enter)" aria-label="Previous match">‹</button>
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-find-step="1" title="Next match (Enter)" aria-label="Next match">›</button>
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-find-close title="Close (Esc)" aria-label="Close find">${icon("close", { size: 12 })}</button>
</div>`;
}

/** The element a message's find runs over: the raw request textarea when it
 *  is the visible editor, else the read-only view / response body. */
function findTarget(side: MessageSide): HTMLTextAreaElement | HTMLElement | null {
  if (side === "res") return resendPanel?.querySelector<HTMLElement>("#resend-response-body") ?? null;
  const raw = resendPanel?.querySelector<HTMLTextAreaElement>("#resend-raw");
  if (raw !== null && raw !== undefined && !raw.hidden) return raw;
  return resendPanel?.querySelector<HTMLElement>("#resend-req-pretty") ?? null;
}

/** Wires a message's tool buttons and find bar inside `root`. `rerender`
 *  redraws the message after a wrap / non-printables toggle. */
function wireMessageTools(root: HTMLElement, side: MessageSide, rerender: () => void): void {
  const bar = root.querySelector<HTMLElement>(`[data-findbar="${side}"]`);
  const input = bar?.querySelector<HTMLInputElement>("[data-find-input]");
  const open = (): void => {
    if (bar === null || bar === undefined || input === null || input === undefined) return;
    findState[side].open = true;
    bar.hidden = false;
    const selected = window.getSelection()?.toString() ?? "";
    if (selected !== "" && !selected.includes("\n") && selected.length < 200) { input.value = selected; findState[side].query = selected; findState[side].index = 0; }
    input.focus();
    input.select();
    runFind(side, 0);
  };
  root.querySelector("[data-msg-find]")?.addEventListener("click", open);
  root.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") { event.preventDefault(); open(); }
  });
  input?.addEventListener("input", () => { findState[side].query = input.value; findState[side].index = 0; runFind(side, 0); });
  input?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); runFind(side, event.shiftKey ? -1 : 1); }
    else if (event.key === "Escape") { event.preventDefault(); closeFind(side); }
  });
  bar?.querySelectorAll<HTMLButtonElement>("[data-find-step]").forEach((button) => {
    button.addEventListener("click", () => runFind(side, Number(button.dataset.findStep) as 1 | -1));
  });
  bar?.querySelector("[data-find-close]")?.addEventListener("click", () => closeFind(side));
  root.querySelector("[data-msg-wrap]")?.addEventListener("click", () => { setMessagePref(`wrap.${side}`, !resendWrap(side)); rerender(); });
  root.querySelector("[data-msg-np]")?.addEventListener("click", () => { setMessagePref(`np.${side}`, !resendNonPrintables(side)); rerender(); });
  if (findState[side].open && findState[side].query !== "") runFind(side, 0, false);
}

function closeFind(side: MessageSide): void {
  findState[side].open = false;
  const bar = resendPanel?.querySelector<HTMLElement>(`[data-findbar="${side}"]`);
  if (bar !== null && bar !== undefined) bar.hidden = true;
  const target = findTarget(side);
  if (target !== null && !(target instanceof HTMLTextAreaElement)) target.querySelectorAll("mark.findhit").forEach((mark) => mark.replaceWith(mark.textContent ?? ""));
  target?.normalize();
  if (target instanceof HTMLTextAreaElement) target.focus();
}

/** Finds `query` over the whole message (scrolled-off text included), moves
 *  to the next/previous match, highlights it, and scrolls it into view. */
function runFind(side: MessageSide, step: 0 | 1 | -1, focusMatch = true): void {
  const state = findState[side];
  const target = findTarget(side);
  const count = resendPanel?.querySelector<HTMLElement>(`[data-findbar="${side}"] [data-find-count]`);
  if (target === null) return;
  const isTextarea = target instanceof HTMLTextAreaElement;
  const text = isTextarea ? target.value : target.textContent ?? "";
  const hits = findAll(text, state.query);
  if (hits.length === 0) {
    if (count !== null && count !== undefined) count.textContent = state.query === "" ? "" : "No matches";
    if (!isTextarea) paintFindHits(target, text, [], -1, 0);
    return;
  }
  state.index = ((step === 0 ? Math.min(state.index, hits.length - 1) : state.index + step) + hits.length) % hits.length;
  const start = hits[state.index];
  // The line number anchors the match even where an unfocused selection is faint.
  const line = isTextarea ? ` · line ${text.slice(0, start).split("\n").length}` : "";
  if (count !== null && count !== undefined) count.textContent = `${state.index + 1} of ${hits.length}${line}`;
  const end = start + state.query.length;
  if (isTextarea) {
    target.setSelectionRange(start, end, "forward");
    scrollTextareaTo(target, start);
    if (focusMatch && step !== 0) {
      // Show the selection, then hand focus back so Enter keeps stepping.
      const input = resendPanel?.querySelector<HTMLInputElement>(`[data-findbar="${side}"] [data-find-input]`);
      target.focus({ preventScroll: true });
      input?.focus({ preventScroll: true });
    }
  } else {
    paintFindHits(target, text, hits, state.index, state.query.length);
  }
}

/** Redraws a read-only message with every match marked and the current one
 *  scrolled into view. */
function paintFindHits(target: HTMLElement, text: string, hits: number[], current: number, length: number): void {
  let html = "";
  let cursor = 0;
  hits.forEach((hit, i) => {
    html += escapeHtml(text.slice(cursor, hit));
    html += `<mark class="findhit${i === current ? " is-current" : ""}">${escapeHtml(text.slice(hit, hit + length))}</mark>`;
    cursor = hit + length;
  });
  html += escapeHtml(text.slice(cursor));
  target.innerHTML = html;
  const mark = target.querySelector<HTMLElement>("mark.is-current");
  if (mark !== null) {
    const top = mark.offsetTop - target.offsetTop;
    target.scrollTop = Math.max(0, top - target.clientHeight / 2);
    target.scrollLeft = Math.max(0, mark.offsetLeft - target.offsetLeft - target.clientWidth / 2);
  }
}

/** Scrolls a textarea so character `offset` is in view, measuring with an
 *  off-screen mirror that has the same box, font, and wrapping. */
function scrollTextareaTo(textarea: HTMLTextAreaElement, offset: number): void {
  const style = getComputedStyle(textarea);
  const mirror = document.createElement("div");
  const copy = ["fontFamily", "fontSize", "fontWeight", "lineHeight", "letterSpacing", "tabSize", "paddingTop", "paddingRight", "paddingBottom", "paddingLeft", "overflowWrap", "wordBreak"] as const;
  copy.forEach((prop) => { mirror.style[prop] = style[prop]; });
  mirror.style.position = "absolute";
  mirror.style.visibility = "hidden";
  mirror.style.left = "-99999px";
  mirror.style.top = "0";
  mirror.style.boxSizing = "border-box";
  mirror.style.width = `${textarea.clientWidth}px`;
  mirror.style.whiteSpace = textarea.wrap === "off" ? "pre" : "pre-wrap";
  mirror.textContent = textarea.value.slice(0, offset);
  const marker = document.createElement("span");
  marker.textContent = "\u200b";
  mirror.append(marker);
  document.body.append(mirror);
  const top = marker.offsetTop;
  const left = marker.offsetLeft;
  mirror.remove();
  textarea.scrollTop = Math.max(0, top - textarea.clientHeight / 2);
  textarea.scrollLeft = textarea.wrap === "off" ? Math.max(0, left - textarea.clientWidth / 2) : 0;
}

/** URL-encodes the Raw request's selected text in place (undoable). */
function urlEncodeResendSelection(): void {
  const raw = resendPanel?.querySelector<HTMLTextAreaElement>("#resend-raw");
  if (raw === null || raw === undefined || raw.hidden) { toast("Switch the request to Raw to URL-encode a selection.", "info"); return; }
  const { selectionStart: start, selectionEnd: end } = raw;
  if (start === end) { toast("Select text in the Raw request to URL-encode it.", "info"); return; }
  const encoded = urlEncode(raw.value.slice(start, end));
  raw.focus();
  // insertText keeps the edit on the textarea's undo stack.
  if (!document.execCommand("insertText", false, encoded)) {
    raw.setRangeText(encoded, start, end, "select");
    raw.dispatchEvent(new Event("input"));
  }
  raw.setSelectionRange(start, start + encoded.length);
}

/** Copies the editor's request (what Send would send) as curl, or its URL. */
async function copyResendRequest(what: "curl" | "url"): Promise<void> {
  const parsed = parseRawRequest(valueOf("#resend-raw"), valueOf("#resend-target").trim());
  if (parsed.error !== undefined) { toast(`Cannot copy: ${parsed.error}`, "danger"); return; }
  const text = what === "url" ? parsed.url : curlCommand({ method: parsed.method, url: parsed.url, headers: parsed.headers, body: parsed.body });
  if (await copyText(text)) toast(what === "url" ? "URL copied." : "curl command copied (bash/zsh quoting).", "success");
  else toast("The clipboard is not available here.", "danger");
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.append(scratch);
    scratch.select();
    const ok = document.execCommand("copy");
    scratch.remove();
    return ok;
  }
}

/* Inspector: a read-mostly structured view of the raw request. Rows point at
 * their text; clicking one selects that value in the Raw editor to edit. */
let resendInspectorFrame: number | undefined;
function scheduleResendInspector(): void {
  if (resendInspectorFrame !== undefined) return;
  resendInspectorFrame = window.requestAnimationFrame(() => { resendInspectorFrame = undefined; renderResendInspector(); });
}

function renderResendInspector(): void {
  const body = resendPanel?.querySelector<HTMLElement>("#resend-inspector-body");
  const summary = resendPanel?.querySelector<HTMLElement>("#resend-inspector-summary");
  if (body === null || body === undefined || summary === null || summary === undefined) return;
  const inspected = inspectRequest(valueOf("#resend-raw").replace(/\r\n/g, "\n"));
  const plural = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
  const bodyLabel = inspected.bodyKind === "form" ? "form" : "JSON";
  summary.textContent = `Inspector · ${plural(inspected.query.length, "query param", "query params")} · ${plural(inspected.cookies.length, "cookie", "cookies")} · ${plural(inspected.headers.length, "header", "headers")}${inspected.bodyKind === null ? "" : ` · ${plural(inspected.body.length, `${bodyLabel} field`, `${bodyLabel} fields`)}`}`;
  const section = (title: string, items: InspectorItem[]): string => {
    if (items.length === 0) return "";
    const rows = items.map((item) => {
      const name = item.decodedName ?? item.name;
      const value = item.decodedValue ?? item.value;
      const rawNote = item.decodedName !== undefined || item.decodedValue !== undefined ? ` title="As written: ${escapeHtml(`${item.name}=${item.value}`)}"` : "";
      return `<tr data-insp-start="${item.start}" data-insp-end="${item.end}" tabindex="0"${rawNote}><td>${escapeHtml(name)}</td><td>${escapeHtml(value)}${item.decodedValue !== undefined ? ` <span class="t-subtle">(decoded)</span>` : ""}</td></tr>`;
    }).join("");
    return `<table class="insp-table"><caption>${escapeHtml(title)} <span class="t-subtle">${items.length}</span></caption><tbody>${rows}</tbody></table>`;
  };
  const html = section("Query parameters", inspected.query)
    + section("Cookies", inspected.cookies)
    + section("Request headers", inspected.headers)
    + (inspected.bodyKind === null ? "" : section(inspected.bodyKind === "form" ? "Body parameters (form)" : "Body fields (JSON, top level)", inspected.body));
  body.innerHTML = html === "" ? `<p class="t-small t-subtle">Nothing to inspect yet — the request has no query, cookies, or headers.</p>` : `${html}<p class="t-small t-subtle insp-hint">Read-only view of the Raw request. Click a row to select its value in the editor.</p>`;
  body.querySelectorAll<HTMLElement>("[data-insp-start]").forEach((row) => {
    const select = (): void => selectInResendRaw(Number(row.dataset.inspStart), Number(row.dataset.inspEnd));
    row.addEventListener("click", select);
    row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); } });
  });
}

/** Selects a range of the Raw request for editing, switching out of the
 *  read-only views first. */
function selectInResendRaw(start: number, end: number): void {
  if (resendRequestView !== "raw" || resendNonPrintables("req")) {
    resendRequestView = "raw";
    setMessagePref("np.req", false);
    resendPanel?.querySelector('.resend-req [data-msg-np]')?.setAttribute("aria-pressed", "false");
    applyResendRequestView();
  }
  const raw = resendPanel?.querySelector<HTMLTextAreaElement>("#resend-raw");
  if (raw === null || raw === undefined) return;
  raw.focus({ preventScroll: true });
  raw.setSelectionRange(start, end);
  scrollTextareaTo(raw, start);
}

/** Pretty | Raw view for the Resend request/response bodies. Pretty is a view
 *  only; the raw buffer is always what is sent. */
type BodyView = "pretty" | "raw";
/** The response also has a Hex view (lossless for binary bodies). */
type ResponseView = BodyView | "hex";
let resendRequestView: BodyView = "raw";
let resendResponseView: ResponseView = "pretty";
/** Binary revisions (`ctxId:revision`) the operator switched to a text view;
 *  every other binary response opens in Hex. */
const resendBinaryAsText = new Set<string>();

function viewToggleHtml(which: "req" | "res", mode: ResponseView): string {
  const button = (value: ResponseView, label: string, title: string): string =>
    `<button class="btn btn--sm btn--quiet" type="button" data-view-mode="${value}" aria-pressed="${mode === value}" title="${title}">${label}</button>`;
  const hex = which === "res" ? button("hex", "Hex", "Byte-exact hex dump of the body") : "";
  return `<div class="viewtoggle" role="group" aria-label="${which === "req" ? "Request" : "Response"} view" data-view-toggle="${which}">${button("pretty", "Pretty", "JSON bodies formatted (display only)")}${button("raw", "Raw", "The message as text")}${hex}</div>`;
}

/** A readable label for a Resend item: its name, else METHOD + path. */
function resendTitle(ctx: ResendContext): string {
  const named = ctx.name?.trim();
  if (named !== undefined && named !== "") return named;
  if (ctx.current.url === NEW_REQUEST_PLACEHOLDER_URL) return "New request";
  return requestTitle(ctx.current.method, ctx.current.url);
}

/** `METHOD /path · host` for a Resend or Fuzz title (long paths shortened). */
function requestTitle(method: string, url: string): string {
  const { authority, pathAndQuery } = splitUrl(url);
  const path = pathAndQuery.length > 60 ? `${pathAndQuery.slice(0, 57)}…` : pathAndQuery;
  return `${(method || "GET").toUpperCase()} ${path}${authority === "" ? "" : ` · ${authority}`}`;
}

/** A readable label for a Fuzz attack, mirroring Resend: its queue name, else
 *  the base request's `METHOD /path · host`. */
function fuzzTitle(job: FuzzerJob): string {
  const named = job.id === "" ? undefined : queueName(job.id);
  if (named !== undefined) return named;
  const base = job.config.baseRequest;
  return base.url.trim() === "" ? "New attack" : requestTitle(base.method, base.url);
}

/** Shows the request as Raw (the editable buffer) or Pretty (a read-only view
 *  of that same buffer with a JSON body formatted). */
function applyResendRequestView(): void {
  const raw = resendPanel?.querySelector<HTMLTextAreaElement>("#resend-raw");
  const pretty = resendPanel?.querySelector<HTMLElement>("#resend-req-pretty");
  if (raw === null || raw === undefined || pretty === null || pretty === undefined) return;
  resendPanel?.querySelectorAll<HTMLButtonElement>('[data-view-toggle="req"] [data-view-mode]').forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.viewMode === resendRequestView));
  });
  const wrap = resendWrap("req");
  raw.wrap = wrap ? "soft" : "off";
  raw.classList.toggle("is-nowrap", !wrap);
  pretty.classList.toggle("is-nowrap", !wrap);
  resendPanel?.querySelector('.resend-req [data-msg-wrap]')?.setAttribute("aria-pressed", String(wrap));
  const nonPrintables = resendNonPrintables("req");
  resendPanel?.querySelector('.resend-req [data-msg-np]')?.setAttribute("aria-pressed", String(nonPrintables));
  const readOnly = resendRequestView === "pretty" || nonPrintables;
  if (readOnly) {
    let text = raw.value;
    if (resendRequestView === "pretty") {
      const parts = splitRawRequestParts(raw.value);
      const head = raw.value.replace(/\r\n/g, "\n").split("\n\n")[0];
      const body = prettyBody(parts.headers, parts.body);
      text = parts.body === "" ? head : `${head}\n\n${body.text}`;
    }
    pretty.textContent = nonPrintables ? showNonPrintables(text) : text;
    pretty.title = nonPrintables
      ? "Display only, with non-printable characters shown — turn off ¶ to edit. What is sent is always the Raw request."
      : "Display only — switch to Raw to edit. What is sent is always the Raw request.";
  }
  raw.hidden = readOnly;
  pretty.hidden = !readOnly;
  if (findState.req.open && findState.req.query !== "") runFind("req", 0, false);
}

/** Reflects whether the visible item has a send in flight on its Send button;
 *  one send per item at a time. */
function setResendSendBusy(busy: boolean): void {
  const button = resendPanel?.querySelector<HTMLButtonElement>("#resend-send");
  if (button === null || button === undefined) return;
  button.disabled = busy;
  if (busy) button.setAttribute("aria-busy", "true");
  else button.removeAttribute("aria-busy");
  button.innerHTML = busy
    ? `${icon("refresh", { size: 16, className: "spinner" })}<span>Sending… <span data-resend-elapsed></span></span>`
    : `${icon("send", { size: 14 })}<span>Send request</span>`;
  const cancel = resendPanel?.querySelector<HTMLButtonElement>("#resend-cancel");
  if (cancel !== null && cancel !== undefined) {
    cancel.hidden = !busy;
    cancel.disabled = false;
    cancel.textContent = "Cancel";
  }
  tickResendElapsed();
}

/** Seconds since the visible item's send started, in every elapsed slot. */
function tickResendElapsed(): void {
  const started = selectedResend === null ? undefined : resendStartedAt.get(selectedResend.id);
  const text = started === undefined ? "" : `${Math.floor((Date.now() - started) / 1000)}s`;
  resendPanel?.querySelectorAll<HTMLElement>("[data-resend-elapsed]").forEach((slot) => { slot.textContent = text; });
}

let resendElapsedTimer: number | undefined;
function syncResendElapsedTimer(): void {
  if (resendInFlight.size > 0 && resendElapsedTimer === undefined) resendElapsedTimer = window.setInterval(tickResendElapsed, 500);
  else if (resendInFlight.size === 0 && resendElapsedTimer !== undefined) { window.clearInterval(resendElapsedTimer); resendElapsedTimer = undefined; }
}

/** Keeps (or, when it matches the item again, forgets) the editor's unsent
 *  contents for `id`. */
function rememberResendDraft(id: string): void {
  const ctx = resendContexts.get(id) ?? (selectedResend?.id === id ? selectedResend : null);
  if (ctx === null || renderedResendId !== id) return;
  const raw = valueOf("#resend-raw").replace(/\r\n/g, "\n");
  const target = valueOf("#resend-target").trim();
  const pristine = raw === rawRequestText(ctx.current, { recomputeContentLength: true }) && target === urlOrigin(ctx.current.url);
  const had = resendDrafts.has(id);
  if (pristine) resendDrafts.delete(id);
  else resendDrafts.set(id, { raw, target });
  if (had !== !pristine) renderResendList();
}

/** Asks the engine to cancel the item's in-flight send (recorded as a
 *  cancelled revision). If the engine has nothing to cancel or does not
 *  answer promptly, the HTTP request is aborted so the item is freed anyway. */
async function cancelResend(id: string): Promise<void> {
  if (!resendInFlight.has(id)) return;
  const button = resendPanel?.querySelector<HTMLButtonElement>("#resend-cancel");
  if (button !== null && button !== undefined && selectedResend?.id === id) { button.disabled = true; button.textContent = "Cancelling…"; }
  let cancelled = false;
  try {
    const response = await fetch(`/api/v1/workbench/resend/${encodeURIComponent(id)}/cancel`, { method: "POST" });
    if (response.ok) cancelled = ((await response.json()) as { cancelled?: boolean }).cancelled === true;
  } catch { /* fall through to the local abort */ }
  if (!cancelled) { resendAborts.get(id)?.abort(); return; }
  window.setTimeout(() => { if (resendInFlight.has(id)) resendAborts.get(id)?.abort(); }, 3000);
}

/** Send-timeout choices (seconds) and the remembered pick. */
const RESEND_TIMEOUT_CHOICES = [10, 30, 60, 120, 300];
const RESEND_TIMEOUT_KEY = "apiaxess.resend.timeoutSecs";
function resendTimeoutSecs(): number {
  try {
    const stored = Number(localStorage.getItem(RESEND_TIMEOUT_KEY));
    return RESEND_TIMEOUT_CHOICES.includes(stored) ? stored : 30;
  } catch { return 30; }
}
function setResendTimeoutSecs(secs: number): void {
  try { localStorage.setItem(RESEND_TIMEOUT_KEY, String(secs)); } catch { /* a preference; ignore storage failures */ }
}

const SCOPE_LABELS: Record<string, string> = {
  in_scope: "In scope",
  outside_declared_scope: "Out of scope",
  undetermined: "Scope undetermined",
  not_applicable: "No scope declared",
};
/** Human label for a scope disposition. */
function humanScope(scope: string): string {
  return SCOPE_LABELS[scope] ?? scope.replace(/_/g, " ");
}

/** One string value from a diagnostic's typed context. */
function diagnosticText(diagnostic: ContextDiagnostic, key: string): string | undefined {
  const entry = diagnostic.context?.[key];
  if (entry === undefined || entry.value === null || entry.value === undefined) return undefined;
  return String(entry.value);
}

/** Plain-language reading of a low-level connect/TLS error chain. */
function transportCause(error: string): string {
  const lower = error.toLowerCase();
  if (/refused|10061|econnrefused/.test(lower)) return "The connection was refused — nothing is listening at that address and port.";
  if (/timed out|10060/.test(lower)) return "The target did not answer in time.";
  if (/dns|no such host|11001|name or service not known|failed to lookup|nodename/.test(lower)) return "The host name could not be resolved (DNS).";
  if (/tls|certificate|handshake|alert/.test(lower)) return "The TLS handshake with the target failed.";
  if (/reset|10054|forcibly closed|broken pipe/.test(lower)) return "The target closed the connection before answering.";
  if (/unreachable|10051|10065/.test(lower)) return "The network or host is unreachable from this machine.";
  return "The exchange with the target failed before any HTTP response arrived.";
}

/** What/why/fix for a failed send, specific to the failure where known. */
function resendFailureText(diagnostic: ContextDiagnostic): { title: string; why: string; detail?: string; fix: string; tone: "danger" | "caution" } {
  const target = diagnosticText(diagnostic, "target");
  const error = diagnosticText(diagnostic, "error");
  switch (diagnostic.id) {
    case "proxy.upstream-unreachable": {
      const timedOut = /timed out/i.test(error ?? "");
      return {
        title: timedOut ? `No response from ${target ?? "the target"}` : `Could not connect to ${target ?? "the target"}`,
        why: transportCause(error ?? ""),
        detail: error,
        fix: "Verify the target is running and reachable from this machine — address, port, DNS, and routing — then resend.",
        tone: "danger",
      };
    }
    case "proxy.resend-timed-out":
      return {
        title: `No response from ${target ?? "the target"} within ${diagnosticText(diagnostic, "timeout_secs") ?? "the timeout"} s`,
        why: "The send was abandoned when its timeout ran out. The request may still have reached the target.",
        fix: "Check that the target is responsive, or raise the Timeout next to Send, then resend.",
        tone: "danger",
      };
    case "proxy.resend-cancelled":
      return {
        title: "Send cancelled",
        why: `You stopped waiting for ${target ?? "the target"}. The request may already have reached it.`,
        fix: "Resend when ready.",
        tone: "caution",
      };
    case "proxy.resend-request-failed": {
      const operation = diagnosticText(diagnostic, "operation");
      const field: Record<string, string> = { method: "The HTTP method", url: "The URL", "header-name": "A header name", "header-value": "A header value", send: "The send", edit: "The edit", "response-body": "The response body" };
      const subject = operation === undefined ? undefined : field[operation];
      return {
        title: subject !== undefined && operation !== "send" && operation !== "response-body" ? `${subject} is not valid` : "The request could not be sent",
        why: error ?? diagnostic.why,
        fix: operation === "send" || operation === "response-body" ? "Confirm the session proxy is running and the target is reachable, then resend." : "Correct it in the request editor and send again.",
        tone: "danger",
      };
    }
    default:
      return { title: diagnostic.what, why: error ?? diagnostic.why, fix: diagnostic.fix, tone: "danger" };
  }
}

/** Inline failure state: clearly "no HTTP response", never a fake status. */
function resendFailureHtml(diagnostic: ContextDiagnostic, lead: string): string {
  const text = resendFailureText(diagnostic);
  const detail = text.detail !== undefined && text.detail !== text.why ? `<p class="t-small t-subtle resend-error__detail"><code>${escapeHtml(text.detail)}</code></p>` : "";
  return `<div class="notice notice--${text.tone} resend-error" role="alert" data-diagnostic-id="${escapeHtml(diagnostic.id)}">
  <span class="notice__icon">${icon(text.tone === "caution" ? "info" : "alert", { size: 18 })}</span>
  <div class="notice__body">
    <p class="t-small t-subtle">${escapeHtml(lead)}</p>
    <p><strong>${escapeHtml(text.title)}</strong></p>
    <p>${escapeHtml(text.why)}</p>
    ${detail}
    <p class="t-small"><strong>Fix:</strong> ${escapeHtml(text.fix)}</p>
  </div>
</div>`;
}

/** Drag-resize the Request | Response split inside the Resend panel (30–70%),
 *  double-click to reset. Mirrors the Live-traffic list|detail behaviour. */
function initResendSplitter(): void {
  const split = resendPanel?.querySelector<HTMLElement>("[data-resend-split]");
  const gutter = resendPanel?.querySelector<HTMLElement>("[data-resend-gutter]");
  if (split === null || split === undefined || gutter === null || gutter === undefined) return;
  const setRatio = (ratio: number): void => {
    const clamped = Math.max(0.3, Math.min(0.7, ratio));
    split.style.setProperty("--resend-req", `${(clamped * 100).toFixed(1)}%`);
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
  gutter.addEventListener("dblclick", () => split.style.setProperty("--resend-req", "50%"));
}

/** The response status line as received (`HTTP/1.1 302 Found`). Responses
 *  recorded before the line was kept show just the code. */
function responseStatusLine(response: ResendResponse): string {
  const version = response.httpVersion ?? "";
  const reason = response.reason ?? "";
  return [version, String(response.status), reason].filter((part) => part !== "").join(" ");
}

/** A response as one read-only view: status line, headers, blank line, body —
 *  the body pretty-printed when `view` is Pretty and it is JSON. */
function composeRawResponse(response: ResendResponse, view: ResponseView, nonPrintables = false): string {
  const headerText = response.headers.map(([name, value]) => `${name}: ${value}`).join("\n");
  const head = headerText === "" ? responseStatusLine(response) : `${responseStatusLine(response)}\n${headerText}`;
  if (view === "hex") {
    const bytes = response.body ?? [];
    return bytes.length === 0 ? head : `${head}\n\n${hexDump(bytes)}`;
  }
  const rawBody = bytesToText(response.body);
  const formatted = view === "pretty" ? prettyBody(response.headers, rawBody).text : rawBody;
  const bodyText = nonPrintables ? showNonPrintables(formatted) : formatted;
  return bodyText === "" ? head : `${head}\n\n${bodyText}`;
}

/** The view a revision's response opens in: Hex for binary bodies unless the
 *  operator picked a text view for that revision. */
function effectiveResponseView(ctx: ResendContext, entry: ResendRevision): ResponseView {
  const response = entry.response;
  if (response === null || response === undefined) return resendResponseView;
  const binary = isBinaryBody(response.headers, response.body);
  if (binary && resendResponseView !== "hex" && !resendBinaryAsText.has(`${ctx.id}:${entry.revision}`)) return "hex";
  return resendResponseView;
}

/** The History pane: the selected revision as a pair — the exact request that
 *  was sent and the response it got — read-only, beside the editable draft.
 *  `‹`/`›` step through revisions; the dropdown jumps. A past request can be
 *  restored into the draft; a 3xx can be followed one hop at a time. */
function resendResponsePaneHtml(ctx: ResendContext): string {
  const history = ctx.history;
  const failure = resendFailures.get(ctx.id);
  if (failure !== undefined) {
    const back = history.length === 0 ? "" : `<div class="row"><button class="btn btn--sm btn--quiet" type="button" data-resend-dismiss-failure>Show History (${history.length})</button></div>`;
    return `<div class="resend-res__head"><p class="section-label">Response</p></div>${resendFailureHtml(failure, "Not sent — nothing was added to History.")}${back}`;
  }
  if (history.length === 0) {
    return `<div class="resend-res__head"><p class="section-label">History</p></div><div class="resend-res__empty">${stateBlock({ icon: "clock", title: "No sends yet", body: "Send the request; each send is kept here as a request/response pair.", compact: true })}</div>`;
  }
  const latest = history[history.length - 1].revision;
  const shown = selectedResendRevision ?? latest;
  const index = Math.max(0, history.findIndex((candidate) => candidate.revision === shown));
  const entry = history[index] ?? history[history.length - 1];
  const options = [...history].reverse().map((candidate) => {
    const st = candidate.response?.status ?? revisionFailureLabel(candidate);
    const hop = candidate.followedFrom !== null && candidate.followedFrom !== undefined ? ` · ↪ from #${candidate.followedFrom}` : "";
    return `<option value="${candidate.revision}"${candidate.revision === entry.revision ? " selected" : ""}>#${candidate.revision} · ${escapeHtml(String(st))}${hop} · ${escapeHtml(formatTime(candidate.sentAt))}</option>`;
  }).join("");
  const nav = `<div class="resend-hist-nav">
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-hist-step="-1" aria-label="Previous revision" title="Previous revision"${index <= 0 ? " disabled" : ""}>‹</button>
  <select class="input input--sm" id="resend-response-pick" aria-label="Revision">${options}</select>
  <button class="btn btn--sm btn--quiet btn--icon" type="button" data-hist-step="1" aria-label="Next revision" title="Next revision"${index >= history.length - 1 ? " disabled" : ""}>›</button>
</div>`;
  const view = effectiveResponseView(ctx, entry);
  const binary = entry.response ? isBinaryBody(entry.response.headers, entry.response.body) : false;
  const head = `<div class="resend-res__head"><p class="section-label">History</p>${nav}${entry.response ? `${viewToggleHtml("res", view)}${messageToolsHtml("res")}` : ""}</div>${entry.response ? findBarHtml("res") : ""}`;
  const status = entry.response?.status;
  const statusLabel = entry.response ? escapeHtml(responseStatusLine(entry.response)) : escapeHtml(revisionFailureLabel(entry));
  const endpoint = `${entry.request.method.toUpperCase()} ${entry.request.url}`;
  const meta = entry.response
    ? `${entry.response.durationMs} ms · ${formatBytes(entry.response.body?.length ?? 0)}${binary ? " · binary" : ""} · ${humanScope(entry.scope)}`
    : humanScope(entry.scope);
  const bodyText = entry.response ? composeRawResponse(entry.response, view, resendNonPrintables("res")) : "";
  const location = redirectLocation(entry);
  const follow = location === null
    ? ""
    : `<div class="row resend-follow"><button class="btn btn--sm" type="button" id="resend-follow" title="Send one request to ${escapeHtml(location)}">Follow redirection → ${escapeHtml(shortUrl(location, entry.request.url))}</button><label class="check check--sm" title="On: cookies this response sets (Set-Cookie) are merged into the next hop's Cookie header. Off: the request's Cookie header is sent as-is."><input type="checkbox" id="resend-follow-cookies"${resendFollowCookies() ? " checked" : ""} /> Apply Set-Cookie</label></div>`;
  return `${head}
<div class="reqline">
  <span class="resend-res__status list-row__status" data-class="${statusClass(status)}">${statusLabel}</span>
  <input class="input input--mono reqline__url" id="resend-response-endpoint" readonly value="${escapeHtml(endpoint)}" aria-label="Revision endpoint" />
  <button class="btn btn--sm btn--quiet" type="button" id="resend-restore" title="Load revision #${entry.revision}'s request into the editor to edit and resend">Restore to editor</button>
</div>
${redirectChainHtml(ctx, entry)}
<details class="resend-sent"><summary class="t-small">Request sent · #${entry.revision}</summary><pre class="code resend-sent__raw" id="resend-sent-request">${escapeHtml(rawRequestText(entry.request, { recomputeContentLength: true }))}</pre></details>
${entry.response
    ? `<p class="field__label" id="resend-response-label">Response · ${escapeHtml(meta)}</p>
<pre class="code resend-body${view === "hex" ? " is-hex is-nowrap" : resendWrap("res") ? "" : " is-nowrap"}" id="resend-response-body" tabindex="0" role="textbox" aria-readonly="true" aria-multiline="true" aria-labelledby="resend-response-label">${escapeHtml(bodyText)}</pre>`
    : `<p class="field__label">No HTTP response · ${escapeHtml(meta)}</p>${resendFailureHtml(entry.diagnostic ?? { id: "proxy.resend-request-failed", what: "No response was received.", why: "The send failed without a recorded reason.", fix: "Resend; if it persists, check the session proxy." }, `Revision #${entry.revision} — the request was attempted; no response was received.`)}`}
${follow}`;
}

/** Short label for a revision with no response (picker + status chip). */
function revisionFailureLabel(entry: ResendRevision): string {
  switch (entry.diagnostic?.id) {
    case "proxy.resend-cancelled": return "cancelled";
    case "proxy.resend-timed-out": return "timed out";
    case "proxy.upstream-unreachable": return "no connection";
    default: return "no response";
  }
}

/** Most redirect hops auto-follow takes before stopping (like the old default). */
const RESEND_MAX_AUTO_HOPS = 10;
const RESEND_AUTOFOLLOW_KEY = "apiaxess.resend.autoFollow";

const RESEND_FOLLOW_COOKIES_KEY = "apiaxess.resend.followCookies";
function resendFollowCookies(): boolean {
  try { return localStorage.getItem(RESEND_FOLLOW_COOKIES_KEY) !== "0"; } catch { return true; }
}
function setResendFollowCookies(on: boolean): void {
  try { localStorage.setItem(RESEND_FOLLOW_COOKIES_KEY, on ? "1" : "0"); } catch { /* a preference; ignore storage failures */ }
}
/** Follow endpoint for one hop, with the cookie and timeout preferences. */
function resendFollowUrl(id: string, revision: number): string {
  return `/api/v1/workbench/resend/${encodeURIComponent(id)}/follow/${revision}?cookies=${resendFollowCookies()}&timeoutSecs=${resendTimeoutSecs()}`;
}

function resendAutoFollow(): boolean {
  try { return localStorage.getItem(RESEND_AUTOFOLLOW_KEY) === "1"; } catch { return false; }
}
function setResendAutoFollow(on: boolean): void {
  try { localStorage.setItem(RESEND_AUTOFOLLOW_KEY, on ? "1" : "0"); } catch { /* a preference; ignore storage failures */ }
}

/** The absolute `Location` a revision's 3xx points to, or null. */
function redirectLocation(entry: ResendRevision): string | null {
  const response = entry.response;
  if (response === null || response === undefined || response.status < 300 || response.status > 399 || response.status === 304) return null;
  const location = response.headers.find(([name]) => name.toLowerCase() === "location")?.[1];
  if (location === undefined || location.trim() === "") return null;
  try { return new URL(location.trim(), entry.request.url).toString(); } catch { return null; }
}

/** A URL relative to `base` when it stays on the same origin (path only). */
function shortUrl(url: string, base: string): string {
  return urlOrigin(url) === urlOrigin(base) ? splitUrl(url).pathAndQuery : url;
}

/** `302 /redirect → 302 /a → 200 /final` for a revision reached by following. */
function redirectChainHtml(ctx: ResendContext, entry: ResendRevision): string {
  const chain = entry.redirectChain ?? [];
  if (chain.length === 0) return "";
  let root = entry;
  for (let guard = 0; guard < ctx.history.length && root.followedFrom !== null && root.followedFrom !== undefined; guard += 1) {
    const parent = ctx.history.find((candidate) => candidate.revision === root.followedFrom);
    if (parent === undefined) break;
    root = parent;
  }
  const steps = chain.map((hop, i) => ({ status: String(hop.status), url: i === 0 ? root.request.url : chain[i - 1].location }));
  steps.push({ status: entry.response ? String(entry.response.status) : "failed", url: entry.request.url });
  const origin = root.request.url;
  const items = steps.map((step) => `<span class="resend-chain__step"><span class="list-row__status" data-class="${statusClass(Number(step.status) || null)}">${escapeHtml(step.status)}</span> ${escapeHtml(shortUrl(step.url, origin))}</span>`);
  return `<p class="resend-chain t-small" aria-label="Redirect chain">${items.join('<span class="resend-chain__arrow" aria-hidden="true">→</span>')}</p>`;
}

/** Renders (or re-renders) just the History pane, preserving the request editor
 *  and split ratio, and wires its controls. */
function mountResendResponse(): void {
  const pane = resendPanel?.querySelector<HTMLElement>("#resend-res-pane");
  if (pane === null || pane === undefined || selectedResend === null) return;
  const ctx = selectedResend;
  pane.innerHTML = resendResponsePaneHtml(ctx);
  const shownEntry = ctx.history.find((candidate) => candidate.revision === (selectedResendRevision ?? ctx.history.at(-1)?.revision));
  pane.querySelectorAll<HTMLButtonElement>('[data-view-toggle="res"] [data-view-mode]').forEach((button) => {
    button.addEventListener("click", () => {
      const mode = button.dataset.viewMode;
      resendResponseView = mode === "raw" ? "raw" : mode === "hex" ? "hex" : "pretty";
      if (shownEntry !== undefined) {
        const key = `${ctx.id}:${shownEntry.revision}`;
        if (resendResponseView === "hex") resendBinaryAsText.delete(key);
        else resendBinaryAsText.add(key);
      }
      mountResendResponse();
    });
  });
  wireMessageTools(pane, "res", () => mountResendResponse());
  pane.querySelector<HTMLSelectElement>("#resend-response-pick")?.addEventListener("change", (event) => {
    resendFailures.delete(ctx.id);
    selectedResendRevision = Number((event.target as HTMLSelectElement).value);
    mountResendResponse();
  });
  pane.querySelectorAll<HTMLButtonElement>("[data-hist-step]").forEach((button) => {
    button.addEventListener("click", () => stepResendRevision(Number(button.dataset.histStep)));
  });
  const shown = selectedResendRevision ?? ctx.history.at(-1)?.revision;
  pane.querySelector("#resend-restore")?.addEventListener("click", () => { if (shown !== undefined) void restoreResendRevision(shown); });
  pane.querySelector("#resend-follow")?.addEventListener("click", () => { if (shown !== undefined) void followResendRedirect(shown); });
  pane.querySelector<HTMLInputElement>("#resend-follow-cookies")?.addEventListener("change", (event) => setResendFollowCookies((event.target as HTMLInputElement).checked));
  pane.querySelector("[data-resend-dismiss-failure]")?.addEventListener("click", () => { resendFailures.delete(ctx.id); mountResendResponse(); });
}

/** Steps the History view one revision back (-1) or forward (+1). */
function stepResendRevision(delta: number): void {
  const history = selectedResend?.history ?? [];
  if (history.length === 0) return;
  const shown = selectedResendRevision ?? history[history.length - 1].revision;
  const index = history.findIndex((candidate) => candidate.revision === shown);
  const next = history[Math.max(0, Math.min(history.length - 1, index + delta))];
  selectedResendRevision = next.revision;
  mountResendResponse();
}

/** Loads a past revision's request into the editable draft via the engine's
 *  derive endpoint. Unsent edits in the editor are only replaced on confirm. */
async function restoreResendRevision(revision: number): Promise<void> {
  const ctx = selectedResend;
  if (ctx === null || resendInFlight.has(ctx.id)) return;
  const pristine = rawRequestText(ctx.current, { recomputeContentLength: true });
  const edited = valueOf("#resend-raw").replace(/\r\n/g, "\n") !== pristine || valueOf("#resend-target").trim() !== urlOrigin(ctx.current.url);
  if (edited && !(await confirmDialog({ eyebrow: "Resend", title: `Restore revision #${revision}?`, message: "The editor has unsent edits. Restoring replaces them with the request from that revision.", confirmLabel: "Restore" }))) return;
  try {
    const response = await fetch(`/api/v1/workbench/resend/${encodeURIComponent(ctx.id)}/derive/${revision}`, { method: "POST" });
    await requireOk(response, "resend restore failed");
    const restored = (await response.json()) as ResendContext;
    if (restored.id !== ctx.id) throw new Error("restore returned a different item");
    resendContexts.set(restored.id, restored);
    resendDrafts.delete(restored.id);
    if (selectedResend?.id !== restored.id) { renderResendList(); return; }
    selectedResend = restored;
    renderResend();
    selectedResendRevision = revision;
    mountResendResponse();
    renderResendList();
    toast(`Revision #${revision} restored to the editor.`, "info");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "The revision could not be restored.", why: "", fix: "Retry; if it persists, reload the session." });
  }
}

/** Shows a processing state in the Response pane while a send is in flight. */
function showResendResponseLoading(): void {
  const pane = resendPanel?.querySelector<HTMLElement>("#resend-res-pane");
  if (pane === null || pane === undefined) return;
  pane.innerHTML = `<div class="resend-res__head"><p class="section-label">Response</p></div>
<div class="state state--compact"><span class="state__icon">${icon("refresh", { size: 26, className: "spinner" })}</span><p class="state__body">Sending request… <span data-resend-elapsed></span></p><p class="state__body t-small t-subtle">Times out after ${resendTimeoutSecs()} s. Cancel stops waiting; the attempt stays in History.</p></div>`;
  tickResendElapsed();
}

async function sendResend(): Promise<void> {
  // The editor always shows the selected item, so the request read here and
  // the id it is PUT/sent to belong to the same item.
  const resend = selectedResend;
  if (resend === null) return;
  const resendId = resend.id;
  if (resendInFlight.has(resendId)) return;
  const parsed = parseRawRequest(valueOf("#resend-raw"), valueOf("#resend-target").trim());
  const parseError = resendPanel?.querySelector<HTMLElement>("#resend-parse-error");
  if (parseError !== null && parseError !== undefined) {
    parseError.hidden = parsed.error === undefined;
    parseError.textContent = parsed.error ?? "";
  }
  if (parsed.error !== undefined) return;
  const request: ResendRequest = { method: parsed.method, url: parsed.url, headers: parsed.headers, body: parsed.body };
  // Show exactly what goes on the wire (e.g. a Content-Length the send adds).
  const raw = resendPanel?.querySelector<HTMLTextAreaElement>("#resend-raw");
  const asSent = rawRequestText(request, { recomputeContentLength: true });
  if (raw !== null && raw !== undefined && raw.value.replace(/\r\n/g, "\n") !== asSent) {
    raw.value = asSent;
    applyResendRequestView();
  }
  // Keep the sent edit on this item locally, so switching away and back shows
  // what was sent rather than the pre-edit request.
  const edited: ResendContext = { ...resend, current: request };
  resendContexts.set(resendId, edited);
  selectedResend = edited;
  resendDrafts.delete(resendId);
  await runResendExchange(resendId, "The resend send failed.", async (signal) => {
    const update = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId), { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(request), signal });
    await requireOk(update, "resend edit failed");
    const sent = await fetch(`/api/v1/workbench/resend/${encodeURIComponent(resendId)}/send?timeoutSecs=${resendTimeoutSecs()}`, { method: "POST", signal });
    await requireOk(sent, "resend send failed");
    return sent;
  });
}

/** Follows the 3xx on `revision` exactly one hop; the hop becomes a new
 *  revision (the draft is untouched). */
async function followResendRedirect(revision: number): Promise<void> {
  const resendId = selectedResend?.id;
  if (resendId === undefined || resendInFlight.has(resendId)) return;
  await runResendExchange(resendId, "The redirect could not be followed.", async (signal) => {
    const followed = await fetch(resendFollowUrl(resendId, revision), { method: "POST", signal });
    await requireOk(followed, "resend follow failed");
    return followed;
  });
}

/** One send-or-follow exchange bound to its own item for its whole lifecycle:
 *  the result always updates that item, but only touches the visible editor
 *  and History when it is still the selected one. With auto-follow on, a 3xx
 *  result is followed one hop at a time through this same path. */
async function runResendExchange(resendId: string, failure: string, issue: (signal: AbortSignal) => Promise<Response>): Promise<void> {
  const isVisible = (): boolean => selectedResend?.id === resendId;
  const abort = new AbortController();
  // Backstop: the engine enforces the send timeout; if it never answers at
  // all, stop waiting shortly after so the item is freed.
  const backstop = window.setTimeout(() => abort.abort(), (resendTimeoutSecs() + 15) * 1000);
  resendInFlight.add(resendId);
  resendStartedAt.set(resendId, Date.now());
  resendAborts.set(resendId, abort);
  resendFailures.delete(resendId);
  syncResendElapsedTimer();
  const settle = (): void => {
    window.clearTimeout(backstop);
    resendInFlight.delete(resendId);
    resendStartedAt.delete(resendId);
    resendAborts.delete(resendId);
    syncResendElapsedTimer();
  };
  if (isVisible()) {
    setResendSendBusy(true);
    showResendResponseLoading();
  }
  renderResendList();
  let followNext: number | null = null;
  try {
    const answered = await issue(abort.signal);
    const result = (await answered.json()) as Partial<ResendSendResult>;
    let context = result.context;
    if (context === null || context === undefined || typeof context.id !== "string") {
      const refreshed = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId));
      await requireOk(refreshed, "resend history refresh failed");
      context = (await refreshed.json()) as ResendContext;
    }
    if (context === null || typeof context.id !== "string" || context.id !== resendId) throw new Error("resend response did not include this item's context");
    settle();
    // A context removed while its send was in flight stays removed.
    if (resendContexts.has(resendId)) resendContexts.set(resendId, context);
    (result.diagnostics ?? []).forEach(showDiagnostic);
    showDiagnostic(result.revision?.diagnostic);
    if (isVisible()) {
      // Keep the operator's draft: take the history, not the stored current,
      // when this exchange did not come from the editor.
      const draft = selectedResend?.current;
      selectedResend = draft === undefined ? context : { ...context, current: draft };
      selectedResendRevision = null;
      setResendSendBusy(false);
      mountResendResponse();
    }
    renderResendList();
    const revision = result.revision;
    if (revision !== undefined && resendAutoFollow() && resendContexts.has(resendId) && redirectLocation(revision) !== null) {
      if ((revision.redirectChain?.length ?? 0) < RESEND_MAX_AUTO_HOPS) followNext = revision.revision;
      else toast(`Stopped after ${RESEND_MAX_AUTO_HOPS} redirects; use Follow redirection to continue.`, "info");
    }
  } catch (error) {
    settle();
    if (abort.signal.aborted) {
      // Stopped locally: pick up whatever the engine recorded, if anything.
      try {
        const refreshed = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(resendId));
        if (refreshed.ok && resendContexts.has(resendId)) {
          const context = (await refreshed.json()) as ResendContext;
          const draft = isVisible() ? selectedResend?.current : undefined;
          resendContexts.set(resendId, context);
          if (isVisible()) selectedResend = draft === undefined ? context : { ...context, current: draft };
        }
      } catch { /* the item is freed either way */ }
      if (isVisible()) {
        selectedResendRevision = null;
        setResendSendBusy(false);
        mountResendResponse();
      }
      renderResendList();
      toast("Stopped waiting for the send.", "info");
      return;
    }
    const diagnostic: ContextDiagnostic = error instanceof ApiRequestError && error.diagnostic !== undefined
      ? error.diagnostic
      : { id: "proxy.resend-request-failed", what: failure, why: String(error), fix: "Review the request and confirm the session proxy is running." };
    if (resendContexts.has(resendId)) resendFailures.set(resendId, diagnostic);
    if (isVisible()) {
      setResendSendBusy(false);
      mountResendResponse();
    }
    renderResendList();
    reportUnexpected(error, { id: "proxy.resend-request-failed", what: failure, why: "", fix: "Review the request and confirm the session proxy is running." });
  }
  if (followNext !== null) {
    const from = followNext;
    await runResendExchange(resendId, "The redirect could not be followed.", async (signal) => {
      const followed = await fetch(resendFollowUrl(resendId, from), { method: "POST", signal });
      await requireOk(followed, "resend follow failed");
      return followed;
    });
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
  // Anchor an elapsed clock to when this run was first seen, so a long quiet
  // stage still visibly ticks even while the backend's fields are unchanged.
  if (run.runId !== pipelineStartedRunId) {
    pipelineStartedRunId = run.runId;
    pipelineStartedAt = Date.now();
  }
  pipelineStatus.textContent = run.status + " · " + run.stage;
  const percent = Math.min(100, Math.max(0, run.progressBasisPoints / 100));
  const stageIndex = pipelineStages.indexOf(run.stage);
  // While running with no measurable progress yet (a long intake stage), show an
  // indeterminate bar so it reads as alive rather than hung at 0% (#17).
  const indeterminate = run.status === "running" && run.progressBasisPoints < 100 ? " progress--indeterminate" : "";
  const tone = run.status === "completed" ? " progress--success" : run.status === "failed" ? " progress--failed" : ` progress--running${indeterminate}`;
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
  ${run.status === "running" ? `<dt>Elapsed</dt><dd class="t-mono">${escapeHtml(formatDuration(Date.now() - pipelineStartedAt))} <span class="t-subtle">· working…</span></dd>` : ""}
</dl>
<div class="progress${tone}" role="progressbar" aria-valuenow="${percent}" aria-valuemin="0" aria-valuemax="100">
  <div class="progress__meta"><span>${escapeHtml(run.message)}${run.status === "running" && percent < 1 ? " — this can take several minutes on large artifacts" : ""}</span><span class="progress__value">${percent.toFixed(1)}%</span></div>
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
    const diag = { id: "pipeline.artifact-path-required", what: "An APK path is required.", why: "The analysis pipeline reads the artifact directly from this machine's filesystem.", fix: "Enter the full path to the APK and start the run again." };
    showDiagnostic(diag);
    // The pipeline diagnostics area is the panel's own error surface (#15).
    if (pipelineDiagnostics !== null) pipelineDiagnostics.innerHTML = diagnosticListHtml([diag], "");
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
    const diag = errorDiagnostic(error, { id: "pipeline.start-failed", what: "The analysis pipeline could not start.", why: "", fix: "Check that the artifact path exists and is readable by the engine, then retry." });
    if (pipelineDiagnostics !== null) pipelineDiagnostics.innerHTML = diagnosticListHtml([diag], "");
    reportUnexpected(error, diag);
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
  surfaceShown = true;
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
<span class="endpoint-row__meta">${graphqlChipHtml(entry, surface.protocolOperations ?? [])}${evidenceChipHtml(entry)}${partyChipHtml(entry)}${confidenceHtml}<span class="badge">${entry.signerCount} signer${entry.signerCount === 1 ? "" : "s"}</span></span>
</button>
<div class="endpoint-detail" data-ep-detail="${index}" hidden></div>
</div>`;
  }).join("");

  // Header counts use the same per-endpoint rule as the row badges.
  const tally = tallySurface(surface.endpoints);
  const unconfirmed = tally.inferred;
  surfaceView.innerHTML = `<div class="stack stack--loose">
<div class="metric-grid">
  <div class="metric"><span class="metric__value">${tally.endpoints}</span><span class="metric__label">endpoints</span></div>
  <div class="metric metric--success" title="Observed in live traffic (dynamic capture)"><span class="metric__value">${tally.confirmed}</span><span class="metric__label">confirmed</span></div>
  <div class="metric" title="Recovered from code only — not observed being hit"><span class="metric__value">${tally.inferred}</span><span class="metric__label">inferred</span></div>
  <div class="metric" title="Confirmed endpoints that were also found in the app's code"><span class="metric__value">${tally.alsoInCode}</span><span class="metric__label">also in code</span></div>
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

${protocolOperationsPanelHtml(surface.protocolOperations ?? [])}
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
  menu.setAttribute("role", "menu");
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.innerHTML = `<button class="context-menu__item" type="button" role="menuitem" data-ep-resend>${icon("send", { size: 14 })}<span>Resend</span></button><button class="context-menu__item" type="button" role="menuitem" data-ep-fuzzer>${icon("discovery", { size: 14 })}<span>Fuzz</span></button>`;
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
    // Stay on the surface; pre-render the (hidden) Resend panel so it is ready,
    // and flag the addition on the Workbench so the operator sees where it went
    // without a jarring, slow view switch.
    renderResend();
    notifyWorkbenchAddition("resend", `${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}`);
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "The endpoint could not be sent to Resend.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

/** Toasts and pulses the Workbench rail + the tool's tab badge so a send-to-tool
 *  from another view is visibly acknowledged where it landed. */
function notifyWorkbenchAddition(tool: "resend" | "fuzz", label: string): void {
  const toolName = tool === "resend" ? "Resend" : "Fuzz";
  toast(`Added ${label} to Workbench › ${toolName}`, "success");
  pulseElement(document.querySelector('.rail__cell[data-nav="workbench"]'));
  pulseElement(document.getElementById(tool === "resend" ? "resend-tab-count" : "fuzz-tab-count"));
}

/** Restarts a brief attention pulse on an element. */
function pulseElement(element: Element | null): void {
  if (element === null) return;
  element.classList.remove("is-pulsing");
  void (element as HTMLElement).offsetWidth;
  element.classList.add("is-pulsing");
  window.setTimeout(() => element.classList.remove("is-pulsing"), 1200);
}

/** Opens the Fuzzer in the workbench seeded from a surface endpoint. */
function sendEndpointToFuzzer(index: number): void {
  const endpoint = lastSurfaceEndpoints[index];
  if (endpoint === undefined) return;
  seedFuzzDraft(endpointRequest(endpoint));
  renderFuzzList();
  notifyWorkbenchAddition("fuzz", `${endpoint.method.toUpperCase()} ${endpoint.pathTemplate}`);
}

/* ==================================================================== *
 * 7c. Workbench tools — Live traffic / Resend (Repeater) / Fuzz (Intruder)
 * ==================================================================== */

/** Not-yet-run Fuzz drafts, each its own queue row with its own edited template,
 *  until it starts. Multiple coexist so no unstarted draft is silently lost. */
const fuzzDrafts = new Map<string, FuzzerJob>();
const fuzzDraftTemplates = new Map<string, string>();
let selectedDraftKey: string | null = null;
let nextDraftSeq = 0;
/** The §-marked template each started job was launched from, so a finished job
 *  can be edited and re-run verbatim (#20). Populated for jobs started in this
 *  session; a job restored from disk falls back to its unmarked base request. */
const fuzzJobTemplates = new Map<string, string>();

/** Switches the Workbench between its tools; nothing remounts. */
function showWorkbenchTab(name: "live" | "resend" | "fuzz" | "ws"): void {
  activeWorkbenchTab = name;
  if (name === "ws") void loadWsConnections();
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
  return `<span class="qrow__method" data-method="${escapeHtml(m)}">${escapeHtml(m)}</span><span class="qrow__target"><b>${escapeHtml(host)}</b>${escapeHtml(decodeForDisplay(path))}</span>`;
}

/** The endpoint of a request — path (+query), decoded, without the origin. Used
 *  for the compact queue rows and their hover title. */
function endpointOf(url: string): string {
  try {
    const parsed = new URL(url);
    return decodeForDisplay(parsed.pathname + parsed.search) || "/";
  } catch {
    return decodeForDisplay(url);
  }
}

/* Client-side, human-friendly names for queued Resend/Fuzz items, so the
 * operator can label rows they want to remember. Persisted locally — the
 * backend request/response are never touched. */
const QUEUE_NAMES_KEY = "apiaxess.queue-names";
function loadQueueNames(): Record<string, string> {
  try {
    const raw = localStorage.getItem(QUEUE_NAMES_KEY);
    return raw === null ? {} : (JSON.parse(raw) as Record<string, string>);
  } catch {
    return {};
  }
}
function queueName(id: string): string | undefined {
  const name = loadQueueNames()[id];
  return name !== undefined && name.trim() !== "" ? name : undefined;
}
function setQueueName(id: string, name: string): void {
  const all = loadQueueNames();
  if (name.trim() === "") delete all[id];
  else all[id] = name.trim();
  try {
    localStorage.setItem(QUEUE_NAMES_KEY, JSON.stringify(all));
  } catch {
    /* naming is a convenience; ignore quota/availability failures */
  }
}

/* Per-tool collapse state for the queue rail, persisted locally. */
const QUEUE_COLLAPSE_KEY = "apiaxess.queue-collapsed";
function collapsedTools(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(QUEUE_COLLAPSE_KEY);
    return raw === null ? {} : (JSON.parse(raw) as Record<string, boolean>);
  } catch {
    return {};
  }
}
/** Laptop widths, where an expanded Resend queue squeezes the editor. */
const NARROW_WORKBENCH = window.matchMedia("(max-width: 1119px)");
/** Whether a tool's queue is collapsed: the operator's explicit choice, else
 *  collapsed by default for Resend at laptop widths. */
function queueCollapsed(tool: string): boolean {
  const chosen = collapsedTools()[tool];
  return chosen ?? (tool === "resend" && NARROW_WORKBENCH.matches);
}
function applyQueueCollapse(tool: string): void {
  const collapsed = queueCollapsed(tool);
  document.querySelector<HTMLElement>(`.wb-split[data-wbsplit="${tool}"]`)?.classList.toggle("is-list-collapsed", collapsed);
  const button = document.querySelector<HTMLElement>(`[data-wb-collapse="${tool}"]`);
  if (button !== null) {
    button.title = collapsed ? "Expand queue" : "Collapse queue";
    button.setAttribute("aria-label", collapsed ? "Expand queue" : "Collapse queue");
  }
}
function toggleQueueCollapse(tool: string): void {
  const all = collapsedTools();
  all[tool] = !queueCollapsed(tool);
  try {
    localStorage.setItem(QUEUE_COLLAPSE_KEY, JSON.stringify(all));
  } catch {
    /* convenience only */
  }
  applyQueueCollapse(tool);
}

/** A compact queue row: method chip + the endpoint (or the custom name), a
 *  status cell, and a hover-revealed rename control. The full endpoint is the
 *  hover title so a renamed row still shows what it points at. */
function queueRowHtml(opts: { id: string; attr: string; method: string; url: string; status: string; active: boolean; name?: string | null; draft?: boolean }): string {
  const endpoint = endpointOf(opts.url);
  // `name` present = the item carries its own (durable) name; else local label.
  const custom = opts.name === undefined ? queueName(opts.id) : (opts.name?.trim() || undefined);
  const shown = custom ?? endpoint;
  const m = opts.method.toUpperCase() || "GET";
  const title = `${custom === undefined ? `${m} ${endpoint}` : `${custom} — ${m} ${endpoint}`}${opts.draft === true ? " · unsent edits" : ""}`;
  return `<div class="qrow${opts.active ? " is-active" : ""}${opts.draft === true ? " has-draft" : ""}" data-${opts.attr}-row="${escapeHtml(opts.id)}" title="${escapeHtml(title)}">
<button class="qrow__open" type="button" data-${opts.attr}="${escapeHtml(opts.id)}">
<span class="qrow__method" data-method="${escapeHtml(m)}">${escapeHtml(m)}</span>
<span class="qrow__name">${escapeHtml(shown)}</span>
<span class="qrow__status">${escapeHtml(opts.status)}</span>
</button>
<button class="qrow__rename" type="button" data-${opts.attr}-rename="${escapeHtml(opts.id)}" title="Rename this item" aria-label="Rename this item">${icon("edit", { size: 14 })}</button>
<button class="qrow__delete" type="button" data-${opts.attr}-delete="${escapeHtml(opts.id)}" title="Remove from queue" aria-label="Remove from queue">${icon("close", { size: 14 })}</button>
</div>`;
}

/** Turns a queue row's name into an inline text field, committing on Enter/blur
 *  and cancelling on Escape. */
function beginQueueRename(rowId: string, attr: string, onDone: () => void, durable?: { current: string | undefined; save: (name: string) => void }): void {
  const row = document.querySelector<HTMLElement>(`[data-${attr}-row="${CSS.escape(rowId)}"]`);
  const nameEl = row?.querySelector<HTMLElement>(".qrow__name");
  if (row === null || nameEl === null || nameEl === undefined) return;
  const input = document.createElement("input");
  input.className = "qrow__rename-input";
  input.value = (durable === undefined ? queueName(rowId) : durable.current) ?? nameEl.textContent ?? "";
  input.setAttribute("aria-label", "Item name");
  let committed = false;
  const commit = (save: boolean): void => {
    if (committed) return;
    committed = true;
    if (save && durable !== undefined) durable.save(input.value);
    else if (save) setQueueName(rowId, input.value);
    onDone();
  };
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); commit(true); }
    else if (event.key === "Escape") { event.preventDefault(); commit(false); }
  });
  input.addEventListener("blur", () => commit(true));
  nameEl.replaceWith(input);
  input.focus();
  input.select();
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
  if (selectedResend === null && renderedResendId === null) seedResendEmpty();
  if (items.length === 0) {
    list.innerHTML = stateBlock({ icon: "send", title: "Resend queue is empty", body: "Right-click a request in Live traffic or the API surface and choose Resend, or use New.", compact: true });
    return;
  }
  list.innerHTML = items
    .map((ctx) => {
      const last = ctx.history[ctx.history.length - 1]?.response?.status;
      const failed = ctx.history.length > 0 && last === undefined ? "✕" : "—";
      const status = resendInFlight.has(ctx.id) ? "…" : last === undefined ? failed : String(last);
      return queueRowHtml({ id: ctx.id, attr: "resend-id", method: ctx.current.method, url: ctx.current.url, status, active: selectedResend?.id === ctx.id, name: ctx.name ?? null, draft: resendDrafts.has(ctx.id) });
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
  list.querySelectorAll<HTMLElement>("[data-resend-id-rename]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const id = button.dataset.resendIdRename ?? "";
      beginQueueRename(id, "resend-id", () => renderResendList(), { current: resendContexts.get(id)?.name ?? undefined, save: (name) => void renameResend(id, name) });
    });
  });
  list.querySelectorAll<HTMLElement>("[data-resend-id-delete]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      void deleteResendContext(button.dataset.resendIdDelete ?? "");
    });
  });
  list.querySelectorAll<HTMLElement>("[data-resend-id-row]").forEach((row) => {
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      const ctx = resendContexts.get(row.dataset.resendIdRow ?? "");
      if (ctx !== undefined) showHostScopeMenu(event.clientX, event.clientY, ctx.current.url);
    });
  });
}

/** Removes a resend context from the queue (and the durable store). If it was
 *  the open one, the editor resets to the empty state. */
async function deleteResendContext(id: string): Promise<void> {
  const ctx = resendContexts.get(id);
  if (id === "" || ctx === undefined) return;
  const revisions = ctx.history.length;
  const history = revisions === 0 ? "It has no sends yet." : `Its ${revisions} ${revisions === 1 ? "revision" : "revisions"} of request/response history will be deleted too.`;
  const drafted = resendDrafts.has(id) ? " Unsent edits in its editor are discarded." : "";
  const inFlight = resendInFlight.has(id) ? " Its send in flight is cancelled first." : "";
  if (!(await confirmDialog({ eyebrow: "Resend", title: `Delete “${resendTitle(ctx)}”?`, message: `${history}${drafted}${inFlight} This cannot be undone.`, confirmLabel: "Delete", tone: "danger" }))) return;
  try {
    if (resendInFlight.has(id)) await cancelResend(id);
    const response = await fetch("/api/v1/workbench/resend/" + encodeURIComponent(id), { method: "DELETE" });
    if (!response.ok && response.status !== 404) { await requireOk(response, "could not remove the resend item"); return; }
    resendContexts.delete(id);
    resendDrafts.delete(id);
    resendFailures.delete(id);
    setQueueName(id, "");
    if (selectedResend?.id === id) { selectedResend = null; seedResendEmpty(); }
    renderResendList();
    toast(revisions === 0 ? "Resend item deleted." : `Resend item and ${revisions} ${revisions === 1 ? "revision" : "revisions"} deleted.`, "success");
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "Could not remove the resend item.", why: "", fix: "Retry; if it persists, reload the session." });
  }
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
    void migrateLocalResendNames(contexts);
  } catch {
    /* the list is a convenience; the detail pane still holds the selection */
  }
}

/** Placeholder target for a hand-crafted request until the operator sets one:
 *  `.invalid` never resolves, so an accidental send fails honestly (DNS). */
const NEW_REQUEST_PLACEHOLDER_URL = "http://new-request.invalid/";

/** Creates a blank, editable Resend item (not tied to a captured flow) and
 *  opens it with the Target empty and focused. */
async function newResendRequest(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/resend", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: { method: "GET", url: NEW_REQUEST_PLACEHOLDER_URL, headers: [] } }) });
    await requireOk(response, "resend context unavailable");
    const ctx = (await response.json()) as ResendContext;
    resendDrafts.set(ctx.id, { raw: "GET / HTTP/1.1\nHost: ", target: "" });
    registerResend(ctx);
    showView("workbench");
    showWorkbenchTab("resend");
    renderResend();
    resendPanel?.querySelector<HTMLInputElement>("#resend-target")?.focus();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "A new request could not be created.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

/** Saves an item's name in the session (durable, exported). Blank clears it. */
async function renameResend(id: string, name: string): Promise<void> {
  try {
    const response = await fetch(`/api/v1/workbench/resend/${encodeURIComponent(id)}/name`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: name.trim() === "" ? null : name.trim() }) });
    await requireOk(response, "resend rename failed");
    const renamed = (await response.json()) as ResendContext;
    const known = resendContexts.get(id);
    if (known !== undefined) resendContexts.set(id, { ...known, name: renamed.name ?? null });
    if (selectedResend?.id === id) {
      selectedResend = { ...selectedResend, name: renamed.name ?? null };
      const heading = resendPanel?.querySelector<HTMLElement>(".panel__heading h2");
      if (heading !== null && heading !== undefined) heading.textContent = resendTitle(selectedResend);
    }
    setQueueName(id, "");
    renderResendList();
  } catch (error) {
    renderResendList();
    reportUnexpected(error, { id: "proxy.resend-history-failed", what: "The name could not be saved.", why: "", fix: "Retry; names are limited to 120 characters." });
  }
}

/** Earlier builds kept Resend names in this browser only; move any that the
 *  session does not have yet into the session store. */
async function migrateLocalResendNames(contexts: ResendContext[]): Promise<void> {
  for (const ctx of contexts) {
    const local = queueName(ctx.id);
    if (local === undefined) continue;
    if (ctx.name !== undefined && ctx.name !== null && ctx.name !== "") { setQueueName(ctx.id, ""); continue; }
    await renameResend(ctx.id, local);
  }
}

/** Keeps the Fuzz queue in sync with the selected job's persisted state. */
function syncFuzzToList(): void {
  if (selectedFuzzer !== null && selectedFuzzer.id !== "") {
    fuzzerJobsList.set(selectedFuzzer.id, selectedFuzzer);
  }
  renderFuzzList();
}

function renderFuzzList(): void {
  const list = document.getElementById("fuzz-list");
  const count = document.getElementById("fuzz-tab-count");
  if (list === null) return;
  const rows: { key: string; job: FuzzerJob }[] = [];
  fuzzDrafts.forEach((job, key) => rows.push({ key, job }));
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
      const isDraft = fuzzDrafts.has(key);
      const active = isDraft ? selectedDraftKey === key : selectedFuzzer?.id === job.id;
      const req = job.config.baseRequest;
      const state = isDraft ? "draft" : job.state;
      return queueRowHtml({ id: key, attr: "fuzz-key", method: req.method, url: req.url, status: state, active });
    })
    .join("");
  list.querySelectorAll<HTMLElement>("[data-fuzz-key]").forEach((row) => {
    row.addEventListener("click", () => {
      selectFuzzerRow(row.dataset.fuzzKey ?? "");
    });
  });
  list.querySelectorAll<HTMLElement>("[data-fuzz-key-rename]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const key = button.dataset.fuzzKeyRename ?? "";
      beginQueueRename(key, "fuzz-key", () => renderFuzzList());
    });
  });
  list.querySelectorAll<HTMLElement>("[data-fuzz-key-delete]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      void deleteFuzzJob(button.dataset.fuzzKeyDelete ?? "");
    });
  });
  list.querySelectorAll<HTMLElement>("[data-fuzz-key-row]").forEach((row) => {
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      const key = row.dataset.fuzzKeyRow ?? "";
      const job = fuzzDrafts.get(key) ?? fuzzerJobsList.get(key);
      if (job !== undefined) showHostScopeMenu(event.clientX, event.clientY, job.config.baseRequest.url);
    });
  });
}

/** Removes a fuzz attack from the queue. A not-yet-created draft is dropped
 *  locally; a persisted job is deleted on the backend too. */
async function deleteFuzzJob(key: string): Promise<void> {
  if (key === "") return;
  if (fuzzDrafts.has(key)) {
    fuzzDrafts.delete(key);
    fuzzDraftTemplates.delete(key);
    if (selectedDraftKey === key) {
      selectedDraftKey = null;
      selectedFuzzer = null;
      // Fall back to another draft, then a started job, then the empty state.
      const nextDraft = [...fuzzDrafts.keys()][0];
      const nextJob = [...fuzzerJobsList.keys()][0];
      if (nextDraft !== undefined) { selectFuzzerRow(nextDraft); return; }
      if (nextJob !== undefined) { selectFuzzerRow(nextJob); return; }
      seedFuzzerEmpty();
    }
    renderFuzzList();
    return;
  }
  try {
    const response = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(key), { method: "DELETE" });
    if (!response.ok && response.status !== 404) { await requireOk(response, "could not remove the fuzz attack"); return; }
    fuzzerJobsList.delete(key);
    setQueueName(key, "");
    if (selectedFuzzer?.id === key) {
      if (fuzzerPoll !== undefined) { window.clearInterval(fuzzerPoll); fuzzerPoll = undefined; }
      selectedFuzzer = null;
      seedFuzzerEmpty();
    }
    renderFuzzList();
  } catch (error) {
    reportUnexpected(error, { id: "proxy.fuzzer-persistence-failed", what: "Could not remove the fuzz attack.", why: "", fix: "Retry; if it persists, reload the session." });
  }
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

/** Filters the Live-traffic list by the search box, the method dropdown, and the
 *  response-status dropdown. All three combine (AND). */
function applyFlowSearch(): void {
  const query = (document.querySelector<HTMLInputElement>("#flow-search")?.value ?? "").trim().toLowerCase();
  const method = (document.querySelector<HTMLSelectElement>("#flow-filter-method")?.value ?? "").toUpperCase();
  const statusClassFilter = document.querySelector<HTMLSelectElement>("#flow-filter-status")?.value ?? "";
  document.querySelectorAll<HTMLElement>("#flow-list .list-row").forEach((row) => {
    const matchesText = query === "" || (row.textContent?.toLowerCase().includes(query) ?? false);
    const matchesMethod = method === "" || row.dataset.method === method;
    const matchesStatus = statusClassFilter === "" || row.dataset.statusClass === statusClassFilter;
    row.hidden = !(matchesText && matchesMethod && matchesStatus);
  });
}

function initWorkbenchTools(): void {
  document.querySelectorAll<HTMLElement>(".wb-tab").forEach((tab) => {
    tab.addEventListener("click", () => showWorkbenchTab((tab.dataset.wbtab as "live" | "resend" | "fuzz" | "ws") ?? "live"));
  });
  document.querySelector<HTMLInputElement>("#flow-search")?.addEventListener("input", applyFlowSearch);
  document.querySelector<HTMLSelectElement>("#flow-filter-method")?.addEventListener("change", applyFlowSearch);
  document.querySelector<HTMLSelectElement>("#flow-filter-status")?.addEventListener("change", applyFlowSearch);
  document.querySelectorAll<HTMLElement>("[data-wb-collapse]").forEach((button) => {
    button.addEventListener("click", () => toggleQueueCollapse(button.dataset.wbCollapse ?? ""));
  });
  document.querySelector("[data-resend-new]")?.addEventListener("click", () => void newResendRequest());
  applyQueueCollapse("resend");
  applyQueueCollapse("fuzz");
  NARROW_WORKBENCH.addEventListener("change", () => {
    applyQueueCollapse("resend");
    if (selectedResend === null) seedResendEmpty();
  });
  initWorkbenchSplitters();
  initWsTab();
  renderResendList();
  renderFuzzList();
}

/** Right-click menu on a Live-traffic row: Resend or Fuzz that request. */
/** The registrable domain to add to scope: `a.b.example.com` → `example.com`.
 *  A small compound-suffix table keeps common two-part TLDs (co.uk, com.au…)
 *  from collapsing to the public suffix. Presentation-grade, not a full PSL. */
function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter((label) => label !== "");
  if (labels.length <= 2) return labels.join(".");
  const twoPartTlds = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "co.jp", "com.au", "com.br", "co.nz", "co.za", "com.cn", "com.mx", "com.sg", "com.hk"]);
  const lastTwo = labels.slice(-2).join(".");
  return twoPartTlds.has(lastTwo) ? labels.slice(-3).join(".") : lastTwo;
}

/** True for IP literals (IPv4/IPv6) and `localhost`. These must be scoped as an
 *  exact host — applying registrable-domain truncation to an address mangles it
 *  (e.g. `127.0.0.1` → `0.1`), producing a wrong, useless scope rule. */
function isIpOrLocalhost(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (h === "localhost") return true;
  if (h.includes(":")) return true; // IPv6 literal
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h); // IPv4 dotted quad
}

interface ScopeTarget { readonly label: string; readonly kind: "exact" | "domain_suffix"; readonly value: string }

/** The scope target for a captured host: an exact rule (verbatim, normalized
 *  host) for IPs/localhost, otherwise a DomainSuffix rule for the registrable
 *  domain. Returns `null` when there is no usable host. The `label` is the exact
 *  value being added, so the menu reads truthfully ("Add 127.0.0.1 to scope"). */
function scopeTargetForHost(host: string): ScopeTarget | null {
  const trimmed = host.trim();
  if (trimmed === "") return null;
  if (isIpOrLocalhost(trimmed)) {
    const value = trimmed.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
    return { label: value, kind: "exact", value };
  }
  const domain = registrableDomain(trimmed);
  if (domain === "") return null;
  return { label: domain, kind: "domain_suffix", value: domain };
}

/** Host component of a URL (or the string itself when it isn't a full URL). */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

interface ScopeRule { id: string; host: { kind: string; domain?: string; host?: string }; ports: number[] }

/** The label a scope rule is shown with: its exact host or its domain. */
function scopeRuleLabel(rule: ScopeRule): string {
  return rule.host.kind === "exact" ? (rule.host.host ?? "") : (rule.host.domain ?? "");
}

/** Renders the declared scope on the Android target's Capture scope panel. */
function renderAndroidScope(status: SessionStatus): void {
  if (androidScopeList === null) return;
  const rules = status.scope?.allowed_targets ?? [];
  androidScopeList.replaceChildren(...rules.map((rule) => {
    const item = document.createElement("li");
    item.className = "scope-list__item";
    const label = scopeRuleLabel(rule);
    item.append(document.createTextNode(rule.host.kind === "exact" ? label : `*.${label}`));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "scope-list__remove";
    remove.textContent = "×";
    remove.setAttribute("aria-label", `Remove ${label} from scope`);
    remove.addEventListener("click", () => void removeScopeRule(rule.id, label));
    item.append(remove);
    return item;
  }));
  if (androidScopeHint !== null) androidScopeHint.textContent = rules.length === 0 ? "none declared" : `${rules.length} in scope`;
}

/** Removes one allow rule from the active session scope. */
async function removeScopeRule(ruleId: string, label: string): Promise<void> {
  try {
    const current = await fetch("/api/v1/session/scope");
    await requireOk(current, "scope read failed");
    const scope = await current.json() as { allowed_targets?: ScopeRule[] };
    scope.allowed_targets = (scope.allowed_targets ?? []).filter((rule) => rule.id !== ruleId);
    const put = await fetch("/api/v1/session/scope", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(scope) });
    await requireOk(put, "scope update failed");
    toast(`Removed ${label} from scope`, "success");
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "web.scope-remove-failed", what: "Could not remove the host from scope.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

/** Adds the host typed on the Android target's Capture scope panel. */
async function addAndroidScopeHost(): Promise<void> {
  if (androidScopeHost === null) return;
  const typed = androidScopeHost.value.trim();
  if (typed === "") {
    showDiagnostic({ id: "android.scope-host-empty", what: "No host to add.", why: "The Host in scope field is empty.", fix: "Type the host the app talks to (for example api.example.com), then add it." });
    return;
  }
  const host = hostOf(typed.includes("://") ? typed : `https://${typed}`);
  if (scopeTargetForHost(host) === null) {
    showDiagnostic({ id: "android.scope-host-invalid", what: `"${typed}" is not a host.`, why: "Scope rules name a host or domain.", fix: "Type a host such as api.example.com or an IP address." });
    return;
  }
  await addHostToScope(host);
  androidScopeHost.value = "";
}

/** Adds a domain (and its subdomains) to the active session scope as a
 *  DomainSuffix allow rule, so its traffic is treated as in-scope. Adds the
 *  registrable domain, never the specific endpoint. */
async function addHostToScope(host: string, exact = false): Promise<void> {
  const normalized = host.trim().toLowerCase().replace(/\.$/, "");
  const target: ScopeTarget | null = exact ? (normalized === "" ? null : { label: normalized, kind: "exact", value: normalized }) : scopeTargetForHost(host);
  if (target === null) return;
  try {
    const current = await fetch("/api/v1/session/scope");
    if (!current.ok) {
      showDiagnostic({ id: "web.scope-unavailable", what: "There is no active scope to add to.", why: "A session scope is declared when you start a web session or run an APK analysis.", fix: "Start a web session first, then add hosts to its scope." });
      return;
    }
    const scope = await current.json() as { allowed_targets?: ScopeRule[] };
    const rules = scope.allowed_targets ?? [];
    const already = rules.some((rule) => (rule.host.kind === "domain_suffix" && rule.host.domain === target.value) || (rule.host.kind === "exact" && rule.host.host === target.value));
    if (already) { toast(`${target.label} is already in scope`, "info"); return; }
    const hostMatch = target.kind === "exact" ? { kind: "exact", host: target.value } : { kind: "domain_suffix", domain: target.value };
    rules.push({ id: `manual:${target.value}`, host: hostMatch, ports: [] });
    scope.allowed_targets = rules;
    const put = await fetch("/api/v1/session/scope", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(scope) });
    await requireOk(put, "scope update failed");
    toast(`Added ${target.label} to scope`, "success");
    await refreshSession();
  } catch (error) {
    reportUnexpected(error, { id: "web.scope-add-failed", what: "Could not add the host to scope.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

function showFlowMenu(x: number, y: number, flowId: number): void {
  document.querySelector(".context-menu")?.remove();
  const menu = document.createElement("div");
  menu.className = "context-menu";
  menu.setAttribute("role", "menu");
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  const host = flows.get(flowId)?.host ?? "";
  const scopeLabel = host === "" ? "" : (scopeTargetForHost(host)?.label ?? "");
  const scopeItem = scopeLabel === "" ? "" : `<button class="context-menu__item" type="button" role="menuitem" data-flow-scope>${icon("shield", { size: 14 })}<span>Add ${escapeHtml(scopeLabel)} to scope</span></button>`;
  menu.innerHTML = `<button class="context-menu__item" type="button" role="menuitem" data-flow-resend>${icon("send", { size: 14 })}<span>Resend</span></button><button class="context-menu__item" type="button" role="menuitem" data-flow-fuzz>${icon("discovery", { size: 14 })}<span>Fuzz</span></button>${scopeItem}`;
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
  menu.querySelector("[data-flow-scope]")?.addEventListener("click", () => {
    close();
    void addHostToScope(host);
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

/** A one-item context menu offering to add a URL's registrable domain to scope.
 *  Used on Resend/Fuzz queue rows, where scope violations surface. */
function showHostScopeMenu(x: number, y: number, url: string): void {
  const host = hostOf(url);
  const scopeLabel = host === "" ? "" : (scopeTargetForHost(host)?.label ?? "");
  if (scopeLabel === "") return;
  document.querySelector(".context-menu")?.remove();
  const menu = document.createElement("div");
  menu.className = "context-menu";
  menu.setAttribute("role", "menu");
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  menu.innerHTML = `<button class="context-menu__item" type="button" role="menuitem" data-scope-add>${icon("shield", { size: 14 })}<span>Add ${escapeHtml(scopeLabel)} to scope</span></button>`;
  const close = (): void => {
    menu.remove();
    document.removeEventListener("click", close);
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key === "Escape") close();
  };
  menu.querySelector("[data-scope-add]")?.addEventListener("click", () => {
    close();
    void addHostToScope(host);
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
    // The Resend queue is compact rows, so it may go narrower than the others.
    const min = split.dataset.wbsplit === "resend" ? 0.15 : 0.3;
    const setRatio = (ratio: number): void => {
      const clamped = Math.max(min, Math.min(0.7, ratio));
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
    gutter.addEventListener("dblclick", () => split.style.removeProperty("--wb-list"));
    gutter.addEventListener("keydown", (event) => {
      const current = parseFloat(getComputedStyle(split).getPropertyValue("--wb-list")) || 50;
      if (event.key === "ArrowLeft") { setRatio((current - 4) / 100); event.preventDefault(); }
      else if (event.key === "ArrowRight") { setRatio((current + 4) / 100); event.preventDefault(); }
    });
  });
}

function renderSurfaceEmpty(): void {
  if (surfaceView === null) return;
  surfaceShown = false;
  const fuse = `<div class="row surface-empty__actions"><button class="btn btn--primary" type="button" data-surface-fuse>${icon("surface", { size: 14 })}<span>${lastFuseFailure === null ? "Fuse captured traffic" : "Retry fuse"}</span></button></div>`;
  if (lastFuseFailure !== null) {
    const failure = lastFuseFailure;
    const detail = diagnosticText(failure, "detail") ?? diagnosticText(failure, "error");
    surfaceView.innerHTML = `<div class="notice notice--danger surface-fuse-error" role="alert" data-diagnostic-id="${escapeHtml(failure.id)}">
  <span class="notice__icon">${icon("alert", { size: 18 })}</span>
  <div class="notice__body">
    <p class="notice__title">Couldn't assemble the API surface</p>
    <p>${escapeHtml(failure.what)}</p>
    <p class="t-small">${escapeHtml(failure.why)}</p>
    ${detail === undefined ? "" : `<p class="t-small t-subtle"><code>${escapeHtml(detail)}</code></p>`}
    <p class="t-small"><strong>Fix:</strong> ${escapeHtml(failure.fix)}</p>
  </div>
</div>${fuse}`;
  } else {
    surfaceView.innerHTML = `${stateBlock({
      icon: "surface",
      title: "No surface assembled yet",
      body: "Run the APK pipeline to completion, or capture web traffic and fuse it. The assembled surface, its coverage, and its provenance appear here.",
    })}${fuse}`;
  }
  surfaceView.querySelector<HTMLButtonElement>("[data-surface-fuse]")?.addEventListener("click", (event) => void fuseWebTraffic(event.currentTarget as HTMLButtonElement));
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

/** The endpoint's host: the engine's bound host, else its base URL's host. */
function endpointHost(endpoint: SurfaceEndpoint): string {
  if (endpoint.host !== undefined && endpoint.host !== null && endpoint.host !== "") return endpoint.host.replace(/:\d+$/, "");
  const base = (endpoint.detail?.baseUrl ?? endpoint.baseUrl ?? "").trim();
  if (base === "") return "";
  const afterScheme = base.includes("://") ? base.slice(base.indexOf("://") + 3) : base;
  const authority = afterScheme.split(/[/?#]/)[0] ?? "";
  const hostPort = authority.includes("@") ? authority.slice(authority.indexOf("@") + 1) : authority;
  return hostPort.replace(/:\d+$/, "").replace(/\.$/, "").toLowerCase();
}

/** First- vs third-party label for an endpoint's host, as classified by the
 * engine: first-party is the app's own backend domain, any other host is
 * third-party. Null when the engine could not tell (no chip is shown). */
function endpointParty(endpoint: SurfaceEndpoint): "first" | "third" | null {
  if (endpoint.party === "first_party") return "first";
  if (endpoint.party === "third_party") return "third";
  return null;
}

/** Renders the confirmed/inferred evidence chip: "confirmed" when the app was
 * observed hitting the endpoint dynamically, "inferred" when it is a static-only
 * candidate (e.g. a bundled SDK base not observed being hit) — so an unconfirmed
 * candidate is never presented as confirmed surface. */
function evidenceChipHtml(endpoint: SurfaceEndpoint): string {
  // Same rule as the header tally (tallySurface): confirmed or inferred, never blank.
  if (isConfirmed(endpoint)) {
    return `<span class="party-chip party-chip--confirmed" title="${endpoint.staticEvidence === true ? "Observed being hit in dynamic capture, and also found in the app's code" : "Observed being hit in dynamic capture"}">confirmed</span>`;
  }
  return `<span class="party-chip party-chip--inferred" title="Static-inferred candidate — recovered from the app's code but not observed being hit. Treat as a lead, not a confirmed endpoint.">inferred</span>`;
}

/** Names the GraphQL operations an endpoint carries, so a POST /graphql row
 *  reads as the operations it runs rather than an opaque POST. */
function graphqlChipHtml(endpoint: SurfaceEndpoint, operations: readonly SurfaceOperation[]): string {
  const carried = graphqlOperationsOn(operations, endpoint.host, endpoint.pathTemplate);
  if (carried.length === 0) return "";
  return `<span class="party-chip party-chip--confirmed" title="${escapeHtml(carried.map((operation) => operation.label).join(", "))}">GraphQL · ${carried.length} operation${carried.length === 1 ? "" : "s"}</span>`;
}

/** Lists GraphQL operations and gRPC methods: operations in their native
 *  protocol shape, not flattened into REST endpoints. */
function protocolOperationsPanelHtml(operations: readonly SurfaceOperation[]): string {
  if (operations.length === 0) return "";
  const rows = operations.map((operation) => {
    const tag = operation.kind === "grpc" ? "gRPC" : "GQL";
    const source = operation.observed
      ? `<span class="party-chip party-chip--confirmed" title="${operation.inCode ? "Observed in captured traffic, and also found in the app's code" : "Observed in captured traffic"}">confirmed</span>`
      : `<span class="party-chip party-chip--inferred" title="Found in the app's code, not observed being called">inferred</span>`;
    const where = operation.kind === "graphql" && operation.endpointUrl !== null ? `<span class="t-small t-subtle t-mono">${escapeHtml(operation.endpointUrl)}</span>` : "";
    const note = operation.kind === "grpc" ? `<span class="t-small t-subtle" title="Without the service's .proto schema a protobuf body yields only field numbers and wire types">protobuf body not decoded without schema</span>` : "";
    return `<div class="list-row protocol-op"><span class="list-row__method" data-method="${tag}">${tag}</span><span class="list-row__target t-mono">${escapeHtml(operation.label)} ${where}</span><span class="endpoint-row__meta">${note}${source}</span></div>`;
  }).join("");
  return `<article class="panel">
  <div class="panel__header">
    <div class="panel__heading">${icon("surface", { size: 16 })}<h2>Protocol operations</h2></div>
    <span class="panel__hint">${operations.length} GraphQL / gRPC</span>
  </div>
  <div class="panel__body panel__body--flush">${rows}</div>
</article>
`;
}

/** Renders the first/third-party chip for an endpoint row, or "" when unknown. */
function partyChipHtml(endpoint: SurfaceEndpoint): string {
  const party = endpointParty(endpoint);
  if (party === null) return "";
  const host = escapeHtml(endpointHost(endpoint));
  return party === "third"
    ? `<span class="party-chip party-chip--third" title="Third-party host the app calls (${host}) — real surface, but not the app's own backend">3rd party</span>`
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
    const hasSource = (source: string): boolean => facts.some((fact) => {
      const sources = (fact as Record<string, unknown>).sources;
      return Array.isArray(sources) && sources.includes(source);
    });
    const observed = hasSource("dynamic_capture");
    const detail = extractEndpointDetail(endpoint);
    const party: HostParty | null = entry.party === "first_party" || entry.party === "third_party" ? entry.party : null;
    return {
      method: String(identity.method ?? ""),
      pathTemplate: String(identity.path_template ?? identity.pathTemplate ?? ""),
      baseUrl: detail.baseUrl,
      host: typeof identity.host === "string" ? identity.host : null,
      party,
      evidenceSource: observed ? "confirmed" : "static_inferred",
      staticEvidence: hasSource("static_analysis"),
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
    protocolOperations: readProtocolOperations(value),
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
    update.flows.forEach((flow) => ingestFlow(flow));
    // WebSocket events route to the WebSocket tab only, never the HTTP grid.
    ingestWsEvents(update.websocket ?? []);
    // Event-stream events belong to their HTTP flow's detail.
    ingestSseEvents(update.sse ?? []);
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
    message.url = urlInput?.value ?? "";
    message.headers = parseHeaders(headersInput?.value ?? "");
    // An untouched body goes back as the held bytes, so a binary body is not
    // mangled by the text round-trip through the editor.
    const held = selectedFlow.requestBody ?? [];
    const text = bodyInput?.value ?? "";
    message.body = text === bytesToText(held) ? [...held] : [...new TextEncoder().encode(text)];
  }
  sendControl(message);
}

/* ==================================================================== *
 * 5. Web session and capture browser
 * ==================================================================== */

async function startWebSession(): Promise<void> {
  const webError = document.querySelector<HTMLElement>("#web-error");
  showInlineError(webError, null);
  const target = webTarget?.value.trim() ?? "";
  if (!target || !webAuthorize?.checked) {
    const diag = { id: "web.authorization-required", what: "Web authorization is required.", why: target === "" ? "No target URL was entered; a web session actively establishes a target scope." : "You must affirm that you are authorized to test this target.", fix: "Enter the target and affirm that you are authorized to test it." };
    showDiagnostic(diag);
    showInlineError(webError, diag);
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
    const diag = errorDiagnostic(error, { id: "web.session-start-failed", what: "Web session could not start.", why: "", fix: "Check the target URL and local API." });
    showInlineError(webError, diag);
    reportUnexpected(error, diag);
  }
}

function renderBrowserState(status: BrowserLaunchStatus | null, stopped = false): void {
  latestBrowser = status;
  // The capture browser is driven from the two top-of-page actions now: show
  // Launch when nothing is running, Stop while it is.
  const running = status !== null && status.running;
  const launchBtn = document.querySelector<HTMLButtonElement>("#capture-launch");
  const stopBtn = document.querySelector<HTMLButtonElement>("#capture-stop");
  if (launchBtn !== null) launchBtn.hidden = running;
  if (stopBtn !== null) stopBtn.hidden = !running;
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
    const report = (await response.json()) as HarImportReport;
    const imported = report.imported;
    toast(`Imported ${imported} flow${imported === 1 ? "" : "s"} from ${file.name}`, "success");
    harScope = report.derivedScope ?? null;
    renderHarScopeNotice();
    if (harScope !== null) await refreshSession();
    // Fold the imported flows into the live list immediately.
    try {
      const flowsResponse = await fetch("/api/v1/workbench/flows");
      if (flowsResponse.ok) { ((await flowsResponse.json()) as FlowSummary[]).forEach((flow) => ingestFlow(flow)); renderFlows(); }
    } catch { /* the telemetry stream also carries new flows */ }
  } catch (error) {
    reportUnexpected(error, { id: "proxy.har-import-failed", what: "The HAR file could not be imported.", why: "", fix: "Confirm the file is a valid HAR export and that a session is active, then retry." });
  }
}

interface HarDerivedScope { hosts: string[]; excludedHosts: string[]; }
interface HarImportReport { readonly imported: number; readonly derivedScope?: HarDerivedScope | null; }

/** The scope the last HAR import derived, shown until dismissed. */
let harScope: HarDerivedScope | null = null;

/** Tells the operator the scope a HAR import set, and lets them narrow it
 *  (remove a host) or widen it to a host the HAR left out. */
function renderHarScopeNotice(): void {
  const notice = document.querySelector<HTMLElement>("#har-scope-notice");
  if (notice === null) return;
  if (harScope === null) { notice.hidden = true; notice.replaceChildren(); return; }
  const scope = harScope;
  const chip = (host: string, action: "remove" | "add"): string => action === "remove"
    ? `<span class="scope-list__item">${escapeHtml(host)}<button class="scope-list__remove" type="button" data-har-remove="${escapeHtml(host)}" aria-label="Remove ${escapeHtml(host)} from scope">×</button></span>`
    : `<button class="btn btn--sm btn--quiet" type="button" data-har-add="${escapeHtml(host)}">Add ${escapeHtml(host)}</button>`;
  notice.hidden = false;
  notice.innerHTML = `<div class="notice notice--caution">
  <span class="notice__icon">${icon("alert", { size: 18 })}</span>
  <div class="notice__body">
    <p class="notice__title">No scope was set — scoped to ${scope.hosts.length} host${scope.hosts.length === 1 ? "" : "s"} from the HAR</p>
    <div class="har-scope__hosts">${scope.hosts.map((host) => chip(host, "remove")).join("")}</div>
    ${scope.excludedHosts.length === 0 ? "" : `<p class="t-small">Also in the HAR, not in scope: ${scope.excludedHosts.map((host) => chip(host, "add")).join(" ")}</p>`}
    <p class="t-small t-subtle">Only in-scope traffic fuses into the surface. Remove a host to narrow the scope, or add one the HAR also used.</p>
  </div>
  <button class="btn btn--sm btn--quiet" type="button" data-har-dismiss aria-label="Dismiss">Dismiss</button>
</div>`;
  notice.querySelectorAll<HTMLButtonElement>("[data-har-remove]").forEach((button) => button.addEventListener("click", () => void removeHarScopeHost(button.dataset.harRemove ?? "")));
  notice.querySelectorAll<HTMLButtonElement>("[data-har-add]").forEach((button) => button.addEventListener("click", () => void addHarScopeHost(button.dataset.harAdd ?? "")));
  notice.querySelector<HTMLButtonElement>("[data-har-dismiss]")?.addEventListener("click", () => { harScope = null; renderHarScopeNotice(); });
}

async function removeHarScopeHost(host: string): Promise<void> {
  try {
    const current = await fetch("/api/v1/session/scope");
    await requireOk(current, "scope read failed");
    const scope = await current.json() as { allowed_targets?: ScopeRule[] };
    const rule = (scope.allowed_targets ?? []).find((candidate) => candidate.host.kind === "exact" && candidate.host.host === host);
    if (rule !== undefined) await removeScopeRule(rule.id, host);
    if (harScope !== null) harScope = { hosts: harScope.hosts.filter((value) => value !== host), excludedHosts: [...harScope.excludedHosts, host] };
    renderHarScopeNotice();
  } catch (error) {
    reportUnexpected(error, { id: "web.scope-remove-failed", what: "Could not remove the host from scope.", why: "", fix: "Confirm a session is active, then retry." });
  }
}

async function addHarScopeHost(host: string): Promise<void> {
  await addHostToScope(host, true);
  if (harScope !== null) harScope = { hosts: [...harScope.hosts, host], excludedHosts: harScope.excludedHosts.filter((value) => value !== host) };
  renderHarScopeNotice();
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
  prefetchDiscoveryEstimate();
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

function renderDiscoveryEstimate(estimate: DiscoveryEstimate, key: string): void {
  lastDiscoveryEstimate = estimate;
  lastDiscoveryEstimateKey = key;
  if (discoveryEstimateView === null) return;
  discoveryEstimateView.innerHTML = `<div class="discovery-estimate">
<div class="discovery-estimate__item"><span class="metric__label">Target</span><span class="t-mono t-small">${escapeHtml(estimate.target)}</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Requests</span><span class="discovery-estimate__value">${estimate.requestCount.toLocaleString()}</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Rate</span><span class="discovery-estimate__value">${estimate.ratePerSecond}/s</span></div>
<div class="discovery-estimate__item"><span class="metric__label">Duration</span><span class="discovery-estimate__value">${escapeHtml(estimate.estimatedLabel)}</span></div>
</div>`;
  if (discoveryStatus !== null) discoveryStatus.textContent = `${estimate.requestCount.toLocaleString()} requests · ${estimate.estimatedLabel} at ${estimate.ratePerSecond}/s`;
}

async function estimateDiscovery(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#discovery-estimate");
  const key = discoveryRequestBody();
  const response = await withBusy(button, "Estimating…", () =>
    fetch("/api/v1/discovery/estimate", { method: "POST", headers: { "content-type": "application/json" }, body: key }),
  );
  try {
    await requireOk(response, "discovery estimate unavailable");
    const estimate = await response.json() as DiscoveryEstimate;
    renderDiscoveryEstimate(estimate, key);
  } catch (error) {
    reportUnexpected(error, { id: "web.discovery-estimate-failed", what: "Discovery estimate unavailable.", why: "", fix: "Check the active web session and selected wordlist." });
  }
}

/** Silently refreshes the estimate cache in the background so the run
 *  confirmation opens instantly. Failures are swallowed — the explicit Estimate
 *  button and runDiscovery's own fallback surface any real error. */
function prefetchDiscoveryEstimate(): void {
  if (discoveryEstimateDebounce !== undefined) window.clearTimeout(discoveryEstimateDebounce);
  discoveryEstimateDebounce = window.setTimeout(() => {
    const key = discoveryRequestBody();
    if (key === lastDiscoveryEstimateKey) return;
    void fetch("/api/v1/discovery/estimate", { method: "POST", headers: { "content-type": "application/json" }, body: key })
      .then(async (response) => {
        if (!response.ok) return;
        const estimate = await response.json() as DiscoveryEstimate;
        renderDiscoveryEstimate(estimate, key);
      })
      .catch(() => { /* best-effort warm cache */ });
  }, 150);
}

/** Whether a discovery run is currently active (running/paused). */
function discoveryRunning(): boolean {
  return discoveryJob !== null && (discoveryJob.state === "running" || discoveryJob.state === "paused");
}

/** Reflects single-flight in the controls: while a run is active, Run is
 *  disabled (never start a second concurrent ffuf) and Cancel is enabled; when
 *  idle, Run is enabled and Cancel is disabled with a reason. */
function setDiscoveryControls(): void {
  const run = document.querySelector<HTMLButtonElement>("#discovery-run");
  const cancel = document.querySelector<HTMLButtonElement>("#discovery-stop");
  const running = discoveryRunning();
  if (run !== null) {
    run.disabled = running;
    run.title = running ? "A discovery run is already active — cancel it first." : "";
  }
  if (cancel !== null) {
    cancel.disabled = !running;
    cancel.title = running ? "Stop the active discovery run." : "No discovery run is active.";
  }
}

async function runDiscovery(): Promise<void> {
  if (discoveryRunning()) { toast("A discovery run is already active — cancel it first.", "info"); return; }
  const key = discoveryRequestBody();
  // Snappy confirm: use the warm cache when it matches the current selection so
  // the dialog opens immediately. Only fetch (with the run button busy) when we
  // have nothing valid cached.
  let estimate = key === lastDiscoveryEstimateKey ? lastDiscoveryEstimate : null;
  if (estimate === null) {
    const runButton = document.querySelector<HTMLButtonElement>("#discovery-run");
    const estimateResponse = await withBusy(runButton, "Preparing…", () =>
      fetch("/api/v1/discovery/estimate", { method: "POST", headers: { "content-type": "application/json" }, body: key }),
    );
    if (!estimateResponse.ok) { await requireOk(estimateResponse, "discovery estimate unavailable"); return; }
    estimate = await estimateResponse.json() as DiscoveryEstimate;
    renderDiscoveryEstimate(estimate, key);
  }

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
    discoveryStartedAt = Date.now();
    renderDiscovery();
    setDiscoveryControls();
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
      // The ffuf tier reports only hits, not a per-probe count. Drive a live
      // bar from real elapsed time against the estimated duration, and show an
      // honest projected sent-count (≈ elapsed × rate) so the panel is never
      // frozen while the wire streams — without claiming an exact count.
      const elapsedSec = running && discoveryStartedAt !== null ? Math.max(0, (Date.now() - discoveryStartedAt) / 1000) : 0;
      const totalSec = rate > 0 && candidates > 0 ? candidates / rate : 0;
      if (running) {
        const projected = rate > 0 ? Math.min(candidates || Infinity, Math.floor(elapsedSec * rate)) : 0;
        percent = totalSec > 0 ? Math.min(99, (elapsedSec / totalSec) * 100) : 0;
        tone = totalSec > 0 ? " progress--running" : " progress--indeterminate progress--running";
        const sent = rate > 0 && candidates > 0 ? `≈${projected.toLocaleString()} / ${candidates.toLocaleString()} sent` : `${Math.round(elapsedSec)}s elapsed`;
        label = `${sent} · ${hits} hit${hits === 1 ? "" : "s"}`;
        value = totalSec > 0 ? `${rate}/s · ~${Math.max(0, Math.ceil(totalSec - elapsedSec))}s left` : `${rate}/s`;
      } else {
        percent = 100;
        tone = outcome;
        label = `${hits} hit${hits === 1 ? "" : "s"}${candidates > 0 ? ` · ${candidates.toLocaleString()} candidates` : ""}`;
        value = job.state;
      }
    }
    // Announce a value whenever the bar is determinate (any tier with a known
    // total, or a finished run) — only a totalless running ffuf bar is not.
    const determinate = !tone.includes("progress--indeterminate");
    const progressAttributes = determinate
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
  setDiscoveryControls();
}

async function refreshDiscovery(): Promise<void> {
  if (discoveryJob === null) return;
  const response = await fetch("/api/v1/workbench/fuzzer/" + encodeURIComponent(discoveryJob.id));
  if (!response.ok) return;
  discoveryJob = await response.json() as FuzzerJob;
  renderDiscovery();
  setDiscoveryControls();
  if (["completed", "failed", "stopped"].includes(discoveryJob.state) && discoveryPoll !== undefined) {
    window.clearInterval(discoveryPoll);
    discoveryPoll = undefined;
    discoveryStartedAt = null;
  }
}

async function stopDiscovery(): Promise<void> {
  if (!discoveryRunning()) return;
  const cancel = document.querySelector<HTMLButtonElement>("#discovery-stop");
  try {
    await withBusy(cancel, "Cancelling…", async () => {
      // The engine kills the underlying ffuf/native process for the active run;
      // the UI only flips to STOPPED once that has actually happened.
      const response = await fetch("/api/v1/discovery/cancel", { method: "POST" });
      await requireOk(response, "discovery could not be cancelled");
      discoveryJob = await response.json() as FuzzerJob;
    });
    renderDiscovery();
    setDiscoveryControls();
    if (discoveryPoll !== undefined) { window.clearInterval(discoveryPoll); discoveryPoll = undefined; }
    discoveryStartedAt = null;
    toast("Discovery cancelled — probing stopped.", "success");
  } catch (error) {
    reportUnexpected(error, { id: "web.discovery-cancel-failed", what: "Discovery could not be cancelled.", why: "", fix: "Retry Cancel; the run may have already finished." });
    await refreshDiscovery();
  }
}

/* ==================================================================== *
 * Fusion
 * ==================================================================== */

/** Why the last fusion failed (null after a success). Shown inline on the API
 *  surface panel instead of a permanent "No surface assembled yet". */
let lastFuseFailure: ContextDiagnostic | null = null;
/** Whether the surface panel currently shows an assembled surface. */
let surfaceShown = false;
/** The failure already announced by toast, so a repeating auto-fuse does not
 *  toast the same failure every tick. */
let announcedFuseFailure = "";

/** Records a fusion failure: inline on the surface panel when no surface is
 *  shown (a surface already on screen stays), a toast once per distinct
 *  failure, and the diagnostics register. */
function reportFuseFailure(diagnostic: ContextDiagnostic): void {
  lastFuseFailure = diagnostic;
  showDiagnostic(diagnostic);
  if (!surfaceShown) renderSurfaceEmpty();
  const key = `${diagnostic.id}:${diagnosticText(diagnostic, "detail") ?? ""}`;
  if (key !== announcedFuseFailure) {
    announcedFuseFailure = key;
    toast(`Couldn't assemble the API surface — ${diagnostic.what}`, "danger");
  }
}

function fuseSucceeded(surface: unknown): number {
  lastFuseFailure = null;
  announcedFuseFailure = "";
  const normalized = normalizeFusedSurface(surface);
  renderSurface(normalized);
  return Array.isArray(normalized?.endpoints) ? normalized.endpoints.length : 0;
}

/** The engine's diagnostic from a failed fuse response, or a stand-in naming
 *  the HTTP status when the body was not a diagnostic. */
async function fuseDiagnostic(response: Response): Promise<ContextDiagnostic> {
  try {
    const candidate = (await response.json()) as Partial<ContextDiagnostic>;
    if (typeof candidate.id === "string" && typeof candidate.what === "string") return candidate as ContextDiagnostic;
  } catch { /* fall through */ }
  return { id: "web.fusion-failed", what: "The engine rejected the fuse request.", why: `HTTP ${response.status} without a diagnostic.`, fix: "Retry; if it persists, check the engine log." };
}

/** Live fusion while capturing: keeps the API surface current with no
 *  navigation, so it is ready the instant the operator opens it. A failure is
 *  never swallowed — it is reported inline on the surface panel. */
let autoFuseTick = 0;
async function autoFuseWebTraffic(): Promise<void> {
  let response: Response;
  try {
    response = await fetch("/api/v1/web/fuse", { method: "POST" });
  } catch {
    return; // the engine is unreachable; the connection status already says so
  }
  if (response.ok) fuseSucceeded(await response.json());
  else reportFuseFailure(await fuseDiagnostic(response));
}

/** The Fuse control: assembles the surface from everything captured so far,
 *  with progress on the button and the result as a toast + the surface view. */
async function fuseWebTraffic(trigger?: HTMLButtonElement | null): Promise<void> {
  const button = trigger ?? document.querySelector<HTMLButtonElement>("#web-fuse");
  await withBusy(button, "Fusing…", async () => {
    let response: Response;
    try {
      response = await fetch("/api/v1/web/fuse", { method: "POST" });
    } catch (error) {
      reportFuseFailure({ id: "web.fusion-failed", what: "The engine could not be reached.", why: String(error), fix: "Confirm the engine is running, then retry." });
      return;
    }
    if (!response.ok) {
      reportFuseFailure(await fuseDiagnostic(response));
      showView("surface");
      return;
    }
    const endpoints = fuseSucceeded(await response.json());
    setStatus("Web traffic fused · observation-based coverage", "ready");
    toast(endpoints === 0
      ? "Fused — no in-scope API endpoints captured yet. Browse the target, then fuse again."
      : `API surface assembled · ${endpoints} endpoint${endpoints === 1 ? "" : "s"}`, endpoints === 0 ? "info" : "success");
    showView("surface");
  });
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
  const sessionChanged = lastSessionStatus?.sessionId !== status.sessionId;
  lastSessionStatus = status;
  if (headerSession !== null) {
    headerSession.textContent = status.sessionId;
    headerSession.title = status.artifactPath;
  }
  // The status bar's session cell was static "no session"; keep it live so it
  // never contradicts the header/sidebar (#18).
  const statusbarSession = document.querySelector<HTMLElement>("#statusbar-session");
  if (statusbarSession !== null) {
    statusbarSession.textContent = status.sessionId;
    statusbarSession.title = `${status.lifecycle} · ${status.artifactPath}`;
  }
  // Layout is keyed per session; now that the id is known, restore this
  // session's persisted pane widths (#9).
  if (sessionChanged) refreshLayoutForSession();
  if (sessionBadge !== null) sessionBadge.textContent = status.lifecycle;
  updateScopePill(status);
  renderAndroidScope(status);
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
${status.scopeConfigured ? "" : `<div class="notice notice--caution"><span class="notice__icon">${icon("shield", { size: 18 })}</span><div class="notice__body"><p class="notice__title">No network allow rules declared</p><p>Active work is gated on a declared scope. Start a web session, run an APK analysis, or add hosts on the Android target's Capture scope panel to establish one.</p></div></div>`}
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
    const rules = status.scope?.allowed_targets ?? [];
    let shown = "";
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(primary)) {
      try {
        shown = new URL(primary).host;
      } catch {
        shown = primary;
      }
    } else if (rules.length > 0) {
      // A session without a URL target (Android target, workbench) is scoped by
      // its host rules alone; name them rather than an internal session id.
      const first = scopeRuleLabel(rules[0]!);
      shown = rules.length > 1 ? `${first} +${rules.length - 1}` : first;
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
  const sessionError = document.querySelector<HTMLElement>("#session-error");
  showInlineError(sessionError, null);
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
    const diag = errorDiagnostic(error, { id: "session.open-failed", what: "The session could not be opened.", why: "", fix: "Check that the artifact path exists and was written by this version, then retry." });
    showInlineError(sessionError, diag);
    reportUnexpected(error, diag);
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
discoveryWordlist?.addEventListener("change", () => { updateWordlistHint(); prefetchDiscoveryEstimate(); });
discoveryKind?.addEventListener("change", () => prefetchDiscoveryEstimate());
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
  return `<div class="field" data-field="${escapeHtml(entry.key)}">
    <div class="row row--between">
      <label class="field__label">${escapeHtml(entry.label)}</label>
      ${settingSourceBadge(entry.source)}
    </div>
    ${settingControl(entry)}
    <p class="field__hint">${escapeHtml(entry.description)}<span class="t-subtle">${escapeHtml(restart)}${escapeHtml(envNote)}</span></p>
    <p class="field__error" data-error-for="${escapeHtml(entry.key)}" role="alert" hidden></p>
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

/** Client-side validation for numeric knobs, mirroring the engine's own rule so
 *  an invalid value is caught inline before it is rejected server-side. Returns
 *  an error message, or null when the value is acceptable (empty clears it). */
function validateSettingValue(key: string, value: string): string | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (key === "APIAXESS_DISCOVERY_RATE") {
    return /^\d+$/.test(trimmed) && Number(trimmed) > 0 ? null : "Must be a positive number (requests per second).";
  }
  return null;
}

/** Shows or clears the inline error under a settings field. */
function setSettingError(key: string, message: string | null): void {
  const slot = document.querySelector<HTMLElement>(`#settings-body [data-error-for="${CSS.escape(key)}"]`);
  const field = document.querySelector<HTMLElement>(`#settings-body [data-field="${CSS.escape(key)}"]`);
  if (slot !== null) {
    slot.textContent = message ?? "";
    slot.hidden = message === null;
  }
  field?.classList.toggle("is-invalid", message !== null);
}

async function saveSettings(): Promise<void> {
  const button = document.querySelector<HTMLButtonElement>("#settings-save");
  const controls = document.querySelectorAll<HTMLInputElement | HTMLSelectElement>(
    "#settings-body [data-setting]",
  );
  const values: Record<string, string> = {};
  let firstInvalid: HTMLElement | null = null;
  controls.forEach((control) => {
    const key = control.dataset.setting ?? "";
    if (key === "") return;
    const error = validateSettingValue(key, control.value);
    setSettingError(key, error);
    if (error !== null && firstInvalid === null) firstInvalid = control;
    if (control.value !== (control.dataset.original ?? "")) {
      values[key] = control.value;
    }
  });
  if (firstInvalid !== null) {
    (firstInvalid as HTMLElement).focus();
    toast("Fix the highlighted setting before saving", "danger");
    return;
  }
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
  androidScopeAdd?.addEventListener("click", () => void addAndroidScopeHost());
  androidScopeHost?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      void addAndroidScopeHost();
    }
  });
  androidStop?.addEventListener("click", () => void stopAndroidTarget());
  androidApkInstall?.addEventListener("click", () => void installTargetApk());
  androidOpenApp?.addEventListener("click", () => void openTargetApp());
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
    initial.forEach((flow) => ingestFlow(flow));
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
    // Pairing establishes a reverse tunnel to the device, which only succeeds on
    // an authorized, online device. Arming an OFFLINE/UNAUTHORIZED device (e.g.
    // the app's own managed emulator while it boots) just fails the tunnel, so
    // the control is disabled with a reason rather than offered and failing (#10).
    const ready = device.state.toLowerCase() === "ready";
    const reason = ready
      ? ""
      : device.state.toLowerCase() === "offline"
        ? "Device is offline (booting, asleep, or a managed target) — it can't be paired yet."
        : device.state.toLowerCase() === "unauthorized"
          ? "Authorize this host's adb key on the device, then refresh."
          : `Device is not ready (${device.state}).`;
    row.innerHTML = `<span class="list-row__target"><b>${escapeHtml(device.serial)}</b> <span class="badge${ready ? "" : " badge--caution"}">${escapeHtml(device.state)}</span><br><span class="t-small t-subtle">${escapeHtml(device.description)}</span></span>`;
    const arm = document.createElement("button");
    arm.type = "button";
    arm.className = "btn btn--sm btn--primary";
    arm.disabled = !ready;
    if (!ready) arm.title = reason;
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
    return `${banner}${androidCaptureNotice(status)}${androidStaticNotice(status)}${androidDiagnosticNotices(status)}`;
  }
  const progress = `<div class="notice"><span class="notice__icon">${icon("refresh", { size: 18, className: "spinner" })}</span><div class="notice__body"><p class="notice__title">${escapeHtml(status.message)}</p><p class="t-small t-subtle">This can take a few minutes, especially in software mode.</p></div></div>`;
  return `${progress}${androidStepsMarkup(status)}${androidDiagnosticNotices(status)}`;
}

/** ws-scrcpy's scrcpy-server port on the device, which its "proxy over adb"
 *  interface reaches (`remote=tcp:8886`). */
const SCRCPY_SERVER_REMOTE = "tcp:8886";

/**
 * The embedded screen's URL: ws-scrcpy's stream view for one device, opened
 * directly rather than its Device Tracker. Mirrors the deep-link ws-scrcpy
 * itself builds: the page is served under `/android-stream/` (the engine's
 * authenticated proxy, `?token=` sets the stream cookie), and the stream
 * WebSocket is same-origin under the same prefix so the cookie authenticates it.
 */
function androidStreamSrc(serial: string, token: string, player: string, location: Location): string {
  const wsScheme = location.protocol === "https:" ? "wss" : "ws";
  const stream = `${wsScheme}://${location.host}/android-stream/?action=proxy-adb&remote=${encodeURIComponent(SCRCPY_SERVER_REMOTE)}&udid=${encodeURIComponent(serial)}`;
  const view = `action=stream&udid=${encodeURIComponent(serial)}&player=${encodeURIComponent(player)}&ws=${encodeURIComponent(stream)}&fitToScreen=true`;
  return `/android-stream/?token=${encodeURIComponent(token)}#!${view}`;
}

/** ws-scrcpy player to decode the H.264 stream with: the browser's WebCodecs
 *  decoder when it can decode H.264, else the pure-JavaScript Broadway decoder
 *  (slower, but works in any browser). */
async function preferredStreamPlayer(): Promise<"webcodecs" | "broadway"> {
  try {
    if (typeof VideoDecoder !== "undefined") {
      const support = await VideoDecoder.isConfigSupported({ codec: "avc1.42E01E" });
      if (support.supported === true) return "webcodecs";
    }
  } catch {
    // Fall through to the software decoder.
  }
  return "broadway";
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
    androidScreenMounted = true;
    const screen = androidScreen;
    const serial = status.serial;
    void preferredStreamPlayer().then((player) => {
      if (!androidScreenMounted) return;
      // Without a serial there is no device to open; the tracker lists what is attached.
      const src = serial === null
        ? `/android-stream/?token=${encodeURIComponent(operatorToken)}`
        : androidStreamSrc(serial, operatorToken, player, window.location);
      screen.innerHTML = `<iframe class="android-screen__frame" title="Android target screen" src="${escapeHtml(src)}" allow="clipboard-read; clipboard-write"></iframe>`;
    });
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

/** Static analysis of the installed app, which Fuse combines with the drive. */
function androidStaticNotice(status: AndroidTargetStatus): string {
  const analysis = status.staticAnalysis ?? null;
  if (analysis === null) return "";
  if (analysis.state === "running") {
    return `<div class="notice"><span class="notice__icon">${icon("refresh", { size: 18, className: "spinner" })}</span><div class="notice__body"><p class="notice__title">Analyzing the installed app</p><p class="t-small t-subtle">Static analysis of the APK runs alongside the drive; Fuse then combines its endpoint templates with the observed traffic.</p></div></div>`;
  }
  if (analysis.state === "ready") {
    const count = analysis.endpointCount ?? 0;
    return `<div class="notice"><span class="notice__icon">${icon("check", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Static analysis ready · ${count} ${count === 1 ? "endpoint" : "endpoints"}</p><p class="t-small t-subtle">Fuse combines them with the live drive, so observed paths take the app's own templates.</p></div></div>`;
  }
  return `<div class="notice notice--caution"><span class="notice__icon">${icon("alert", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Static analysis of the installed app failed</p><p>${escapeHtml(analysis.message ?? "The APK could not be analyzed.")} Fuse still builds the surface from the live drive alone.</p></div></div>`;
}

/** Whether the target's app traffic is being captured, and if not, why. */
function androidCaptureNotice(status: AndroidTargetStatus): string {
  const proxy = status.captureProxy ?? null;
  if (proxy !== null) {
    const captured = flows.size === 1 ? "1 flow captured" : `${flows.size} flows captured`;
    return `<div class="notice"><span class="notice__icon">${icon("traffic", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Capture active</p><p class="t-small t-subtle">App traffic on the target routes through the workbench proxy (device proxy ${escapeHtml(proxy)}) and is decrypted with the session CA · ${captured}. Only in-scope hosts reach the fused surface.</p></div></div>`;
  }
  const why = status.captureIssue ?? "the device proxy was not set up for this launch";
  return `<div class="notice notice--caution"><span class="notice__icon">${icon("alert", { size: 18 })}</span><div class="notice__body"><p class="notice__title">Capture not active</p><p>The target's traffic is not routed through the capture proxy (${escapeHtml(why)}), so apps on it reach the network directly and nothing is captured.</p><p class="t-small t-subtle">Stop and relaunch the target to set up capture again.</p></div></div>`;
}

function renderAndroidStatus(status: AndroidTargetStatus): void {
  lastAndroidStatus = status;
  if (flows.size === 0) renderFlows();
  if (androidPhaseBadge !== null) androidPhaseBadge.textContent = status.phase;
  const inFlight = status.phase === "booting" || status.phase === "provisioning" || status.phase === "streaming";
  if (androidLaunch !== null) {
    androidLaunch.disabled = inFlight || !status.addonPresent;
    androidLaunch.hidden = status.phase === "ready";
  }
  if (androidStop !== null) androidStop.hidden = !(inFlight || status.phase === "ready");
  if (androidInstallPanel !== null) androidInstallPanel.hidden = status.phase !== "ready";
  updateAndroidInstalled(status);
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

/**
 * The installed app's lasting state and its "Open app" action. Updated in place
 * (text + visibility only) so the 1 s status poll never recreates the button
 * under the user's click.
 */
function updateAndroidInstalled(status: AndroidTargetStatus): void {
  if (androidInstalled === null) return;
  const apk = status.installedApk ?? null;
  const pkg = status.installedPackage ?? null;
  androidInstalled.hidden = status.phase !== "ready" || apk === null;
  if (androidInstalled.hidden) return;
  if (androidInstalledTitle !== null) androidInstalledTitle.textContent = pkg === null ? `Installed ${apk}` : `Installed ${pkg}`;
  if (androidInstalledDetail !== null) {
    androidInstalledDetail.textContent = pkg === null
      ? (status.installNote ?? "Open it from the device's app drawer on the screen.")
      : `${apk} is on the target. Open it, then drive it on the screen; its traffic flows to the workbench.`;
  }
  if (androidOpenApp !== null) androidOpenApp.hidden = pkg === null;
}

async function installTargetApk(): Promise<void> {
  const path = androidApkPath?.value.trim() ?? "";
  if (path === "") { toast("Enter the full path to the APK you want to install."); androidApkPath?.focus(); return; }
  await withBusy(androidApkInstall, "Installing…", async () => {
    const response = await fetch("/api/v1/android-target/install-apk", { method: "POST", headers: pairingHeaders(true), body: JSON.stringify({ path }) });
    if (response.status === 204) {
      toast("Installed. Open the app, then drive it on the screen.");
      await refreshAndroidStatus();
    } else showDiagnostic((await response.json()) as Diagnostic);
  });
}

async function openTargetApp(): Promise<void> {
  await withBusy(androidOpenApp, "Opening…", async () => {
    const response = await fetch("/api/v1/android-target/open-app", { method: "POST", headers: pairingHeaders() });
    if (response.ok) toast("Opened on the target. Drive it on the screen.");
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

/** A compact elapsed readout: `Ss`, `Mm Ss`, or `Hh Mm`. */
function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

void boot();
