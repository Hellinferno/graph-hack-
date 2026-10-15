/**
 * Typed client for the AegisGraph REST + SSE API (docs/DESIGN.md §6).
 * The Vite dev server proxies `/api` to http://localhost:8000 (see vite.config.ts).
 */
import type { AgentEvent, GraphSnapshot, JsonObject, JsonValue, RunMode } from './events';
import { AGENT_EVENT_TYPES, parseAgentEvent } from './events';
import type { EpisodeRecord, GetDecisionProofResult, PlaybookRecord, RollbackRemediationResult, SimulationRecord } from './tools';
import {
  asArray,
  asBoolean,
  asNullableNumber,
  asNullableString,
  asNumber,
  asNumberRecord,
  asObject,
  asObjectArray,
  asString,
  asStringArray,
} from './lib/json';

export const API_BASE = '/api';
export const FALKORDB_BROWSER_URL = 'http://localhost:3000';

/* ------------------------------------------------------------------ */
/* Response types                                                      */
/* ------------------------------------------------------------------ */

export interface HealthResponse {
  status: 'ok' | 'degraded';
  falkordb: boolean;
  /** Where the FalkorDB Browser is published (FALKORDB_BROWSER_PORT on the backend). */
  falkordb_browser_url: string;
  prod_graph: string;
  graphs: string[];
  label_counts: Record<string, number>;
  llm_configured: boolean;
  model: string | null;
  /** 'anthropic' | 'openrouter' when LLM mode is configured. */
  llm_provider: string | null;
  mcp_servers: string[];
}

export interface IncidentSummary {
  id: string;
  title: string;
  status: string;
  raw_alert: string;
  timestamp: number | null;
  cve_id: string | null;
  audit_count: number;
}

export interface GraphOverviewEntry {
  name: string;
  nodes: number;
  edges: number;
  kind: 'prod' | 'memory' | 'sandbox' | string;
}

export interface GraphOverview {
  graphs: GraphOverviewEntry[];
  label_counts: Record<string, number>;
}

export interface ToolInfo {
  name: string;
  description: string;
  input_schema: JsonObject;
  server: string;
}

export interface StartRunRequest {
  incident_id: string;
  alert_text?: string;
  mode?: RunMode;
}

export interface StartRunResponse {
  run_id: string;
}

export type RunStatus = 'running' | 'completed' | 'error';

export interface RunRecord {
  run_id: string;
  status: RunStatus;
  events: AgentEvent[];
}

export interface SeedRequest {
  reset_memory?: boolean;
}

export interface MemoryOverview {
  graph: string | null;
  counts: Record<string, number>;
  episodes: EpisodeRecord[];
  playbooks: PlaybookRecord[];
  simulations: SimulationRecord[];
}

export interface RunStreamHandlers {
  onEvent(event: AgentEvent): void;
  /** The server replays its buffer after an EventSource reconnect; callers should reset their state. */
  onReplay?(): void;
  onDone(): void;
  onError(error: Error): void;
}

export type Unsubscribe = () => void;

/** Everything the console needs from the backend. The mock client implements the same interface. */
export interface AegisClient {
  health(): Promise<HealthResponse>;
  seed(body?: SeedRequest): Promise<Record<string, number>>;
  incidents(): Promise<IncidentSummary[]>;
  incident(id: string): Promise<GetDecisionProofResult>;
  graph(): Promise<GraphSnapshot>;
  graphs(): Promise<GraphOverview>;
  graphByName(name: string): Promise<GraphSnapshot>;
  tools(): Promise<ToolInfo[]>;
  callTool(name: string, args: JsonObject): Promise<JsonObject>;
  startRun(body: StartRunRequest): Promise<StartRunResponse>;
  run(runId: string): Promise<RunRecord>;
  subscribeRunEvents(runId: string, handlers: RunStreamHandlers): Unsubscribe;
  memory(): Promise<MemoryOverview>;
  rollback(auditId: string): Promise<RollbackRemediationResult>;
}

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

export class ApiError extends Error {
  readonly status: number;
  readonly detail: JsonValue;

  constructor(status: number, message: string, detail: JsonValue = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }

  /** True when the backend answered 503 (FalkorDB unreachable, DESIGN.md §6) or the API itself is down. */
  get isUnavailable(): boolean {
    return this.status === 0 || this.status === 503;
  }
}

export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}

function messageFromBody(status: number, body: JsonValue): string {
  const detail = asObject(body).detail;
  if (typeof detail === 'string' && detail) return detail;
  if (typeof body === 'string' && body) return body.slice(0, 300);
  if (status === 503) return 'FalkorDB is unreachable (HTTP 503)';
  if (status === 404) return 'Not found (HTTP 404)';
  return `Request failed (HTTP ${status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(init?.headers ?? {}),
      },
    });
  } catch (cause) {
    throw new ApiError(0, `Backend API unreachable at ${API_BASE}${path} (is the FastAPI server on :8000 running?)`, String(cause));
  }
  const text = await response.text();
  let body: JsonValue = null;
  if (text) {
    try {
      body = JSON.parse(text) as JsonValue;
    } catch {
      body = text;
    }
  }
  if (!response.ok) throw new ApiError(response.status, messageFromBody(response.status, body), body);
  return body as T;
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) });
}

/* ------------------------------------------------------------------ */
/* Normalisers (tolerant of small shape differences in list payloads)  */
/* ------------------------------------------------------------------ */

function nameOf(entry: JsonValue): string {
  return typeof entry === 'string' ? entry : asString(asObject(entry).name);
}

function normalizeHealth(raw: JsonValue): HealthResponse {
  const o = asObject(raw);
  return {
    status: asString(o.status) === 'ok' ? 'ok' : 'degraded',
    falkordb: asBoolean(o.falkordb),
    falkordb_browser_url: asString(o.falkordb_browser_url, FALKORDB_BROWSER_URL),
    prod_graph: asString(o.prod_graph, 'aegis_prod_graph'),
    graphs: asArray(o.graphs).map(nameOf).filter(Boolean),
    label_counts: asNumberRecord(o.label_counts),
    llm_configured: asBoolean(o.llm_configured),
    model: asNullableString(o.model),
    llm_provider: asNullableString(o.llm_provider),
    mcp_servers: asArray(o.mcp_servers).map(nameOf).filter(Boolean),
  };
}

export function normalizeIncident(o: JsonObject): IncidentSummary {
  const audits = o.audits;
  return {
    id: asString(o.id ?? o.incident_id),
    title: asString(o.title),
    status: asString(o.status, 'OPEN'),
    raw_alert: asString(o.raw_alert),
    timestamp: asNullableNumber(o.timestamp),
    cve_id: asNullableString(o.cve_id ?? o.cve),
    audit_count:
      typeof o.audit_count === 'number' ? o.audit_count : Array.isArray(audits) ? audits.length : asNumber(audits, 0),
  };
}

function normalizeIncidents(raw: JsonValue): IncidentSummary[] {
  const list = Array.isArray(raw) ? raw : asArray(asObject(raw).incidents);
  return asObjectArray(list).map(normalizeIncident);
}

function normalizeGraphOverview(raw: JsonValue): GraphOverview {
  const o = asObject(raw);
  return {
    graphs: asObjectArray(o.graphs).map((g) => ({
      name: asString(g.name),
      nodes: asNumber(g.nodes),
      edges: asNumber(g.edges),
      kind: asString(g.kind, 'prod'),
    })),
    label_counts: asNumberRecord(o.label_counts),
  };
}

function normalizeTools(raw: JsonValue): ToolInfo[] {
  const list = Array.isArray(raw) ? raw : asArray(asObject(raw).tools);
  return asObjectArray(list).map((t) => ({
    name: asString(t.name),
    description: asString(t.description),
    input_schema: asObject(t.input_schema ?? t.inputSchema),
    server: asString(t.server, 'aegisgraph'),
  }));
}

export function normalizeEpisode(o: JsonObject): EpisodeRecord {
  return {
    id: asString(o.id),
    incident_id: asString(o.incident_id),
    cve_id: asNullableString(o.cve_id),
    started_at: asNullableNumber(o.started_at),
    finished_at: asNullableNumber(o.finished_at),
    mode: asString(o.mode),
    outcome: asString(o.outcome),
    summary: asString(o.summary),
    tool_call_count: asNumber(o.tool_call_count),
  };
}

export function normalizePlaybook(o: JsonObject): PlaybookRecord {
  return {
    signature: asString(o.signature),
    action_type: asString(o.action_type),
    bridge_service: asString(o.bridge_service),
    iam_role: asString(o.iam_role),
    success_count: asNumber(o.success_count),
    last_used: asNullableNumber(o.last_used),
    last_incident_id: asNullableString(o.last_incident_id),
  };
}

export function normalizeSimulation(o: JsonObject): SimulationRecord {
  return {
    id: asString(o.id),
    incident_id: asString(o.incident_id),
    cve_id: asNullableString(o.cve_id),
    timestamp: asNullableNumber(o.timestamp),
    bridge_service: asString(o.bridge_service),
    iam_role: asString(o.iam_role),
    safe: asBoolean(o.safe),
    exposure_closed: asBoolean(o.exposure_closed),
    critical_flows_intact: asBoolean(o.critical_flows_intact),
    critical_services_connected: asBoolean(o.critical_services_connected),
    sandbox_graph: asString(o.sandbox_graph),
    exposure_before: asNumber(o.exposure_before),
    exposure_after: asNumber(o.exposure_after),
  };
}

function normalizeMemory(raw: JsonValue): MemoryOverview {
  const o = asObject(raw);
  const counts: Record<string, number> = { ...asNumberRecord(o.label_counts), ...asNumberRecord(o.counts) };
  for (const [key, value] of Object.entries(o)) {
    if (typeof value === 'number') counts[key] = value;
  }
  return {
    graph: asNullableString(o.graph),
    counts,
    episodes: asObjectArray(o.episodes).map(normalizeEpisode),
    playbooks: asObjectArray(o.playbooks).map(normalizePlaybook),
    simulations: asObjectArray(o.simulations).map(normalizeSimulation),
  };
}

function normalizeSnapshot(raw: JsonValue, fallbackName: string): GraphSnapshot {
  const o = asObject(raw);
  const snapshot = o as unknown as GraphSnapshot;
  return {
    graph: asString(o.graph, fallbackName),
    nodes: Array.isArray(snapshot.nodes) ? snapshot.nodes : [],
    edges: Array.isArray(snapshot.edges) ? snapshot.edges : [],
  };
}

/** `POST /api/seed` answers `{prod: {label: count}, memory: {...}}`; the console reports the production counts. */
function normalizeSeed(raw: JsonValue): Record<string, number> {
  const o = asObject(raw);
  return asNumberRecord(o.prod ?? o.label_counts ?? raw);
}

function normalizeRun(raw: JsonValue, runId: string): RunRecord {
  const o = asObject(raw);
  const status = asString(o.status, 'running');
  return {
    run_id: asString(o.run_id, runId),
    status: status === 'completed' || status === 'error' ? status : 'running',
    events: asObjectArray(o.events)
      .map((e) => parseAgentEvent('', JSON.stringify(e)))
      .filter((e): e is AgentEvent => e !== null),
  };
}

/** Shared by the HTTP client and the mock client, so both turn the same payloads into the same UI data. */
export const normalizers = {
  health: normalizeHealth,
  incidents: normalizeIncidents,
  graphOverview: normalizeGraphOverview,
  tools: normalizeTools,
  memory: normalizeMemory,
  snapshot: normalizeSnapshot,
  seed: normalizeSeed,
  run: normalizeRun,
};

/* ------------------------------------------------------------------ */
/* SSE subscriber: GET /api/runs/{id}/events                           */
/* ------------------------------------------------------------------ */

/**
 * Subscribe to a run's event stream. Each SSE message is `event: <type>` + `data: <json>`;
 * the stream ends with `event: done`. Returns a function that closes the stream.
 */
export function subscribeRunEvents(runId: string, handlers: RunStreamHandlers): Unsubscribe {
  const source = new EventSource(`${API_BASE}/runs/${encodeURIComponent(runId)}/events`);
  let opened = false;
  let finished = false;

  const deliver = (eventName: string, data: string) => {
    const event = parseAgentEvent(eventName, data);
    if (event) handlers.onEvent(event);
  };

  for (const type of AGENT_EVENT_TYPES) {
    source.addEventListener(type, (raw) => deliver(type, (raw as MessageEvent<string>).data));
  }
  // Unnamed messages (no `event:` line) carry the type inside the payload.
  source.onmessage = (raw: MessageEvent<string>) => deliver('', raw.data);
  source.addEventListener('done', () => {
    finished = true;
    source.close();
    handlers.onDone();
  });
  source.onopen = () => {
    if (opened) handlers.onReplay?.();
    opened = true;
  };
  source.onerror = () => {
    if (finished) return;
    if (source.readyState === EventSource.CLOSED) {
      finished = true;
      handlers.onError(new Error(`Event stream for run ${runId} closed before it finished`));
    }
  };

  return () => {
    finished = true;
    source.close();
  };
}

/* ------------------------------------------------------------------ */
/* HTTP client                                                         */
/* ------------------------------------------------------------------ */

export function createHttpClient(): AegisClient {
  return {
    health: () => request<JsonValue>('/health').then(normalizeHealth),
    seed: (body = {}) => post<JsonValue>('/seed', body).then(normalizeSeed),
    incidents: () => request<JsonValue>('/incidents').then(normalizeIncidents),
    incident: (id) => request<GetDecisionProofResult>(`/incidents/${encodeURIComponent(id)}`),
    graph: () => request<JsonValue>('/graph').then((raw) => normalizeSnapshot(raw, 'aegis_prod_graph')),
    graphs: () => request<JsonValue>('/graphs').then(normalizeGraphOverview),
    graphByName: (name) =>
      request<JsonValue>(`/graph/${encodeURIComponent(name)}`).then((raw) => normalizeSnapshot(raw, name)),
    tools: () => request<JsonValue>('/tools').then(normalizeTools),
    callTool: (name, args) => post<JsonObject>(`/tools/${encodeURIComponent(name)}`, args),
    startRun: (body) =>
      post<JsonValue>('/runs', body).then((raw) => ({ run_id: asString(asObject(raw).run_id ?? asObject(raw).id) })),
    run: (runId) => request<JsonValue>(`/runs/${encodeURIComponent(runId)}`).then((raw) => normalizeRun(raw, runId)),
    subscribeRunEvents,
    memory: () => request<JsonValue>('/memory').then(normalizeMemory),
    rollback: (auditId) => post<RollbackRemediationResult>(`/rollback/${encodeURIComponent(auditId)}`),
  };
}

export const modeHint = (mode: RunMode, llmConfigured: boolean): string => {
  if (mode === 'llm' && !llmConfigured) return 'LLM mode needs OPENROUTER_API_KEY (free models) or ANTHROPIC_API_KEY in the project .env; restart the API.';
  if (mode === 'auto') return llmConfigured ? 'Auto resolves to the LLM agent.' : 'Auto resolves to the deterministic agent.';
  return '';
};

export const toolNames = (tools: ToolInfo[]): string[] => asStringArray(tools.map((t) => t.name));
