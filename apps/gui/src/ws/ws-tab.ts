/* WebSocket tab: the live-capture workbench's view of WebSocket traffic.
 *
 * Separate from the HTTP flow list by design: WebSocket connections and their
 * messages arrive on their own telemetry field, are listed here only, and never
 * enter the Live grid or the fused REST surface. */

import { findAll } from "../http/message-tools.ts";
import { escapeHtml, formatBytes, formatTime, hydrateIcons, stateBlock } from "../ui/dom";
import {
  decodePayload,
  defaultView,
  filterConnections,
  isTruncated,
  previewPayload,
  renderPayload,
  upsertConnection,
  type WsConnection,
  type WsMessage,
  type WsView,
} from "./ws-model.ts";

/** One WebSocket event on the telemetry stream. */
export interface LiveWsEvent {
  readonly connection: WsConnection;
  readonly message?: WsMessage;
}

/** Messages fetched per page; a chatty stream loads page by page. */
const PAGE_SIZE = 500;

interface LoadedMessages {
  items: WsMessage[];
  /** Whether every message up to the connection's count is loaded, so live
   *  messages can be appended without a gap. */
  complete: boolean;
}

let connections: WsConnection[] = [];
let selectedConnection: number | null = null;
let selectedMessage: number | null = null;
let view: WsView = "pretty";
let viewChosen = false;
let wrap = true;
let findQuery = "";
const loaded = new Map<number, LoadedMessages>();
let renderQueued = false;

const $ = <T extends HTMLElement>(selector: string): T | null => document.querySelector<T>(selector);

/** Wires the tab's controls. Call once at startup. */
export function initWsTab(): void {
  $("#ws-host-filter")?.addEventListener("input", () => renderList());
  $("#ws-open-only")?.addEventListener("change", () => renderList());
  $("#ws-list")?.addEventListener("click", (event) => {
    const row = (event.target as HTMLElement).closest<HTMLElement>("[data-ws-connection]");
    if (row !== null) void selectConnection(Number(row.dataset.wsConnection));
  });
  $("#ws-detail")?.addEventListener("click", (event) => {
    const target = event.target as HTMLElement;
    const message = target.closest<HTMLElement>("[data-ws-message]");
    if (message !== null) {
      selectedMessage = Number(message.dataset.wsMessage);
      viewChosen = false;
      renderDetail();
      return;
    }
    const viewButton = target.closest<HTMLElement>("[data-ws-view]");
    if (viewButton !== null) {
      view = viewButton.dataset.wsView as WsView;
      viewChosen = true;
      renderPayloadPane();
      return;
    }
    if (target.closest("[data-ws-wrap]") !== null) {
      wrap = !wrap;
      renderPayloadPane();
      return;
    }
    if (target.closest("[data-ws-more]") !== null) void loadMore();
  });
  $("#ws-detail")?.addEventListener("input", (event) => {
    const target = event.target as HTMLInputElement;
    if (target.id === "ws-find") {
      findQuery = target.value;
      renderFindCount();
    }
  });
  renderList();
  renderDetail();
}

/** Loads the session's WebSocket connections (on opening the tab). */
export async function loadWsConnections(): Promise<void> {
  try {
    const response = await fetch("/api/v1/workbench/ws-connections");
    if (!response.ok) return;
    connections = (await response.json()) as WsConnection[];
    renderList();
    if (selectedConnection !== null) renderDetail();
  } catch {
    /* transient; live events and the next open refresh it */
  }
}

/** Routes live WebSocket events into the tab (never into the HTTP grid). */
export function ingestWsEvents(events: readonly LiveWsEvent[]): void {
  if (events.length === 0) return;
  for (const event of events) {
    // A connection first seen live has no party yet: re-read the list once.
    if (!connections.some((known) => known.id === event.connection.id)) scheduleListRefresh();
    connections = upsertConnection(connections, event.connection);
    const message = event.message;
    if (message === undefined) continue;
    const store = loaded.get(event.connection.id);
    if (store !== undefined && store.complete) {
      const last = store.items.at(-1)?.sequence ?? 0;
      if (message.sequence === last + 1) store.items.push(message);
      else if (message.sequence > last + 1) store.complete = false;
    }
  }
  scheduleRender();
}

let listRefreshQueued = false;

function scheduleListRefresh(): void {
  if (listRefreshQueued) return;
  listRefreshQueued = true;
  window.setTimeout(() => {
    listRefreshQueued = false;
    void loadWsConnections();
  }, 250);
}

function scheduleRender(): void {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    renderList();
    renderDetail();
  });
}

function partyChip(connection: WsConnection): string {
  if (connection.party === "first_party") return `<span class="party-chip party-chip--first" title="The app's own backend host">1st party</span>`;
  if (connection.party === "third_party") return `<span class="party-chip party-chip--third" title="Third-party host">3rd party</span>`;
  return "";
}

function scopeLabel(scope: string): string {
  if (scope === "in_scope") return "in scope";
  if (scope === "outside_declared_scope") return "out of scope";
  return "scope undetermined";
}

function renderList(): void {
  const list = $("#ws-list");
  if (list === null) return;
  const hostFilter = $<HTMLInputElement>("#ws-host-filter")?.value ?? "";
  const openOnly = $<HTMLInputElement>("#ws-open-only")?.checked ?? false;
  const shown = filterConnections(connections, hostFilter, openOnly);
  const count = $("#ws-tab-count");
  if (count !== null) {
    count.textContent = String(connections.length);
    count.hidden = connections.length === 0;
  }
  const counts = $("#ws-counts");
  if (counts !== null) counts.textContent = shown.length === connections.length ? `${connections.length} ${connections.length === 1 ? "connection" : "connections"}` : `${shown.length} of ${connections.length} connections`;
  if (connections.length === 0) {
    list.innerHTML = stateBlock({
      icon: "traffic",
      title: "No WebSocket traffic yet",
      body: "WebSocket connections the captured app or browser opens through the session proxy appear here with every message they exchange. HTTP requests stay in Live traffic.",
    });
    return;
  }
  if (shown.length === 0) {
    const filters = [hostFilter.trim() !== "" ? "the host filter" : "", openOnly ? "Open only" : ""].filter((part) => part !== "").join(" and ");
    list.innerHTML = stateBlock({ icon: "traffic", title: "No matching connections", body: `No WebSocket connection matches ${filters}.` });
    return;
  }
  list.innerHTML = [...shown].reverse().map((connection) => {
    const open = (connection.closedAt ?? null) === null;
    const status = open ? `<span class="ws-status ws-status--open" title="Open">open</span>` : `<span class="ws-status" title="Closed${connection.closeCode ? ` (code ${connection.closeCode})` : ""}">closed</span>`;
    const selected = connection.id === selectedConnection ? " is-selected" : "";
    return `<button class="list-row ws-row${selected}" type="button" data-ws-connection="${connection.id}">
  <span class="ws-row__main"><span class="t-mono ws-row__host">${escapeHtml(connection.host ?? connection.url)}</span><span class="t-mono t-small t-subtle ws-row__path">${escapeHtml(connection.path ?? "")}</span></span>
  <span class="ws-row__meta">${status}<span class="t-small t-numeric" title="Messages">${connection.messageCount}</span>${partyChip(connection)}<span class="t-small t-subtle">${scopeLabel(connection.scope)}</span></span>
</button>`;
  }).join("");
}

async function selectConnection(id: number): Promise<void> {
  selectedConnection = id;
  selectedMessage = null;
  renderList();
  if (!loaded.has(id)) {
    loaded.set(id, { items: [], complete: false });
    renderDetail();
    await fetchPage(id);
  }
  renderDetail();
}

async function fetchPage(id: number): Promise<void> {
  const store = loaded.get(id);
  if (store === undefined) return;
  const after = store.items.at(-1)?.sequence ?? 0;
  try {
    const response = await fetch(`/api/v1/workbench/ws-connections/${id}/messages?after=${after}&limit=${PAGE_SIZE}`);
    if (!response.ok) return;
    const page = (await response.json()) as WsMessage[];
    store.items.push(...page);
    const connection = connections.find((candidate) => candidate.id === id);
    store.complete = page.length < PAGE_SIZE && (connection === undefined || store.items.length >= connection.messageCount);
  } catch {
    /* leave the page for "Load more" to retry */
  }
}

async function loadMore(): Promise<void> {
  if (selectedConnection === null) return;
  await fetchPage(selectedConnection);
  renderDetail();
}

function renderDetail(): void {
  const detail = $("#ws-detail");
  if (detail === null) return;
  const connection = connections.find((candidate) => candidate.id === selectedConnection);
  if (connection === undefined) {
    detail.innerHTML = stateBlock({ icon: "traffic", title: "Select a connection", body: "Its messages appear here, sent ↑ and received ↓, with a payload viewer." });
    return;
  }
  const store = loaded.get(connection.id);
  const items = store?.items ?? [];
  const open = (connection.closedAt ?? null) === null;
  const rows = items.map((message) => {
    const bytes = decodePayload(message.payloadBase64);
    const sent = message.direction === "client_to_server";
    const selected = message.sequence === selectedMessage ? " is-selected" : "";
    return `<button class="list-row ws-message${selected}" type="button" data-ws-message="${message.sequence}">
  <span class="ws-message__dir ${sent ? "ws-message__dir--sent" : "ws-message__dir--received"}" title="${sent ? "Sent by the client" : "Received from the server"}">${sent ? "↑" : "↓"}</span>
  <span class="t-small ws-message__kind">${escapeHtml(message.kind)}</span>
  <span class="t-mono t-small ws-message__preview">${escapeHtml(previewPayload(message, bytes))}</span>
  <span class="t-small t-subtle t-numeric">${escapeHtml(formatBytes(message.payloadBytes))} · ${escapeHtml(formatTime(message.observedAt))}</span>
</button>`;
  }).join("");
  const more = store !== undefined && !store.complete && items.length < connection.messageCount
    ? `<button class="btn btn--sm btn--quiet" type="button" data-ws-more>Load more (${items.length} of ${connection.messageCount})</button>`
    : "";
  const loading = store !== undefined && items.length === 0 && connection.messageCount > 0 && !store.complete
    ? `<p class="t-small t-subtle">Loading messages…</p>` : "";
  detail.innerHTML = `<div class="ws-detail">
  <div class="ws-detail__head">
    <p class="t-mono ws-detail__url">${escapeHtml(connection.url)}</p>
    <p class="t-small t-subtle">${open ? "Open" : `Closed${connection.closeCode ? ` · code ${connection.closeCode}` : ""}`} · ${connection.messageCount} ${connection.messageCount === 1 ? "message" : "messages"} · opened ${escapeHtml(formatTime(connection.openedAt))}</p>
  </div>
  <div class="ws-messages" role="list" aria-label="WebSocket messages">${rows || (loading === "" ? `<p class="t-small t-subtle">No messages on this connection.</p>` : "")}${loading}${more}</div>
  <div class="ws-payload" id="ws-payload"></div>
</div>`;
  hydrateIcons(detail);
  renderPayloadPane();
}

function renderPayloadPane(): void {
  const pane = $("#ws-payload");
  if (pane === null) return;
  const store = selectedConnection === null ? undefined : loaded.get(selectedConnection);
  const message = store?.items.find((candidate) => candidate.sequence === selectedMessage);
  if (message === undefined) {
    pane.innerHTML = `<p class="t-small t-subtle">Select a message to view its payload.</p>`;
    return;
  }
  const bytes = decodePayload(message.payloadBase64);
  if (!viewChosen) view = defaultView(message, bytes);
  const truncated = isTruncated(message)
    ? `<p class="t-small t-subtle">Showing ${escapeHtml(formatBytes(message.retainedBytes))} of ${escapeHtml(formatBytes(message.payloadBytes))} (payload capped when captured).</p>` : "";
  const button = (name: WsView, label: string): string => `<button class="btn btn--sm btn--quiet" type="button" data-ws-view="${name}" aria-pressed="${view === name}">${label}</button>`;
  // A hex dump is columnar: it never wraps.
  const wrapped = wrap && view !== "hex";
  pane.innerHTML = `<div class="ws-payload__bar">
  ${button("pretty", "Pretty")}${button("raw", "Raw")}${button("hex", "Hex")}
  <button class="btn btn--sm btn--quiet" type="button" data-ws-wrap aria-pressed="${wrap}" title="Wrap long lines"${view === "hex" ? " disabled" : ""}>Wrap</button>
  <input class="input input--sm input--mono" id="ws-find" type="search" placeholder="Find" value="${escapeHtml(findQuery)}" aria-label="Find in payload" />
  <span class="t-small t-subtle" id="ws-find-count"></span>
</div>
${truncated}
<pre class="ws-payload__body${wrapped ? " is-wrapped" : ""}" id="ws-payload-body">${escapeHtml(renderPayload(bytes, view))}</pre>`;
  renderFindCount();
}

function renderFindCount(): void {
  const body = $("#ws-payload-body");
  const count = $("#ws-find-count");
  if (body === null || count === null) return;
  if (findQuery === "") {
    count.textContent = "";
    return;
  }
  const matches = findAll(body.textContent ?? "", findQuery).length;
  count.textContent = matches === 1 ? "1 match" : `${matches} matches`;
}
