/**
 * Agent event and graph snapshot types.
 * Mirrors docs/DESIGN.md §5 (agent events), §4 (path objects) and §6 (/api/graph snapshots).
 */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export interface JsonObject {
  [key: string]: JsonValue;
}

/* ------------------------------------------------------------------ */
/* Graph shapes (§3.1 labels/edges, §4 path objects, §6 snapshots)     */
/* ------------------------------------------------------------------ */

export const NODE_LABELS = [
  'Vulnerability',
  'Package',
  'Function',
  'Service',
  'IAMRole',
  'Database',
  'Developer',
  'Incident',
  'ActionAudit',
] as const;
export type NodeLabel = (typeof NODE_LABELS)[number];

export const EDGE_TYPES = [
  'AFFECTS',
  'IMPORTS',
  'CALLS',
  'MAINTAINED',
  'DEPLOYS_CODE',
  'ROUTES_TO',
  'ASSUMES_ROLE',
  'CAN_ACCESS',
  'TRIGGERED_ON',
  'RESOLVED_BY',
  'MODIFIED_ENTITY',
] as const;
export type EdgeType = (typeof EDGE_TYPES)[number];

/** Edge `status` property on ROUTES_TO / CAN_ACCESS. A missing status means ACTIVE. */
export type EdgeStatus = 'ACTIVE' | 'ISOLATED_BY_AEGIS' | 'QUARANTINED_BY_AEGIS';
export type ServiceTier = 'critical' | 'standard';
export type ServiceStatus = 'HEALTHY' | 'DEGRADED' | 'ISOLATED';
export type RoleStatus = 'ACTIVE' | 'QUARANTINED';
export type IncidentStatus = 'OPEN' | 'MITIGATED';

/** FalkorDB internal ids are integers; string ids are tolerated for mocks. */
export type GraphId = number | string;

export interface GraphNode {
  id: GraphId;
  labels: string[];
  /** `name`, else `id`, else `arn`, else the internal id (see graph.node_name in the backend). */
  name: string;
  properties: JsonObject;
}

export interface GraphEdge {
  id: GraphId;
  type: string;
  src_id: GraphId;
  dst_id: GraphId;
  properties: JsonObject;
}

/** `path` objects embedded in tool results (§4). */
export interface GraphPath {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** `GET /api/graph` and `GET /api/graph/{name}` (graph.graph_snapshot). */
export interface GraphSnapshot {
  graph: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* ------------------------------------------------------------------ */
/* Agent events (§5)                                                   */
/* ------------------------------------------------------------------ */

export type RunMode = 'auto' | 'deterministic' | 'llm';
export type ResolvedRunMode = Exclude<RunMode, 'auto'>;

export const STAGE_NAMES = ['anchor', 'blast_radius', 'chokepoint', 'simulate', 'act'] as const;
export type StageName = (typeof STAGE_NAMES)[number];
export type StageNumber = 1 | 2 | 3 | 4 | 5;
export type StageStatus = 'started' | 'completed' | 'skipped';

export const HIGHLIGHT_STYLES = ['attack', 'chokepoint', 'quarantined', 'safe', 'proof'] as const;
export type HighlightStyle = (typeof HIGHLIGHT_STYLES)[number];

export type RunOutcome = 'MITIGATED' | 'PARTIAL' | 'NO_ACTION' | 'ERROR';

/** Code owner as returned by find_code_owner / execute_remediation and carried on the decision event. */
export interface CodeOwner {
  name: string;
  handle: string;
  team: string;
  on_call: boolean;
  target_file?: string;
  repo_name?: string;
  function?: string;
  package?: string;
  current_version?: string;
  fixed_version?: string;
  expertise_score?: number;
}

export interface DecisionScores {
  betweenness: number | null;
  pagerank: number | null;
}

interface EventBase {
  ts: number;
  run_id: string;
}

export interface RunStartedEvent extends EventBase {
  type: 'run_started';
  incident_id: string;
  /** The orchestrator resolves `auto`, but the wider type is tolerated here. */
  mode: RunMode;
  model: string | null;
  /** Tool names available via MCP. */
  tools: string[];
}

export interface StageEvent extends EventBase {
  type: 'stage';
  stage: StageNumber;
  name: StageName;
  status: StageStatus;
  detail: string;
}

export interface ThinkingEvent extends EventBase {
  type: 'thinking';
  text: string;
}

export interface AssistantTextEvent extends EventBase {
  type: 'assistant_text';
  text: string;
}

export interface ToolCallEvent extends EventBase {
  type: 'tool_call';
  call_id: string;
  name: string;
  args: JsonObject;
  seq: number;
}

/** `result` is the tool's dict, or `{ error: string }` when `is_error` is true. */
export interface ToolResultEvent extends EventBase {
  type: 'tool_result';
  call_id: string;
  name: string;
  result: JsonObject;
  duration_ms: number;
  is_error: boolean;
}

export interface HighlightEdgeRef {
  src: string;
  dst: string;
  type?: string;
}

export interface GraphHighlightEvent extends EventBase {
  type: 'graph_highlight';
  style: HighlightStyle;
  /** Node names (service / role / database names, CVE ids, ...). */
  nodes: string[];
  edges: HighlightEdgeRef[];
  label: string;
}

/** One pivot service considered as the remediation target (agent.rank_candidates). */
export interface DecisionCandidate {
  service: string;
  tier: ServiceTier | string;
  rps: number | null;
  iam_roles: string[];
  /** Number of exposure paths that pass through this service. */
  coverage: number;
  total_paths: number;
  betweenness: number;
  pagerank: number;
  eligible: boolean;
  reason: string;
}

export interface DecisionEvent extends EventBase {
  type: 'decision';
  action: string;
  bridge_service: string | null;
  iam_role: string | null;
  justification: string;
  scores: DecisionScores | Record<string, never>;
  sim_passed: boolean | null;
  code_owner: CodeOwner | string | null;
  candidates?: DecisionCandidate[];
  simulation?: string | null;
  sandbox_graph?: string | null;
}

export interface RunCompletedEvent extends EventBase {
  type: 'run_completed';
  outcome: RunOutcome;
  summary: string;
  audit_id: string | null;
  duration_ms: number;
  tool_call_count: number;
  episode_id: string | null;
}

export interface RunErrorEvent extends EventBase {
  type: 'error';
  message: string;
  recoverable: boolean;
}

export type AgentEvent =
  | RunStartedEvent
  | StageEvent
  | ThinkingEvent
  | AssistantTextEvent
  | ToolCallEvent
  | ToolResultEvent
  | GraphHighlightEvent
  | DecisionEvent
  | RunCompletedEvent
  | RunErrorEvent;

export type AgentEventType = AgentEvent['type'];

export const AGENT_EVENT_TYPES = [
  'run_started',
  'stage',
  'thinking',
  'assistant_text',
  'tool_call',
  'tool_result',
  'graph_highlight',
  'decision',
  'run_completed',
  'error',
] as const satisfies readonly AgentEventType[];

export function isAgentEventType(value: string): value is AgentEventType {
  return (AGENT_EVENT_TYPES as readonly string[]).includes(value);
}

/**
 * Parse one SSE message (`event: <type>` + `data: <json>`) into a typed event.
 * The payload's own `type` field wins over the SSE event name when both are present.
 */
export function parseAgentEvent(eventName: string, data: string): AgentEvent | null {
  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    return null;
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return null;
  const record = payload as Record<string, unknown>;
  const type = typeof record.type === 'string' ? record.type : eventName;
  if (!isAgentEventType(type)) return null;
  return { ...record, type } as unknown as AgentEvent;
}
