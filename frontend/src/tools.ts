/**
 * Typed shapes of the 13 MCP tool results (docs/DESIGN.md §4).
 * Tool results arrive as plain `JsonObject` on `tool_result` events; use `readResult` to narrow them.
 */
import type { CodeOwner, GraphPath, JsonObject, JsonValue, ServiceStatus, ServiceTier } from './events';

export const TOOL_NAMES = [
  'find_entry_points',
  'trace_blast_radius',
  'rank_service_criticality',
  'shortest_attack_path',
  'expand_neighborhood',
  'detect_service_communities',
  'find_code_owner',
  'recall_similar_incidents',
  'simulate_remediation',
  'execute_remediation',
  'rollback_remediation',
  'get_decision_proof',
  'read_graph',
] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

/** One executed query, as recorded by graph.CypherTrace.as_dict(). */
export interface CypherTrace {
  graph: string;
  cypher: string;
  params: JsonObject;
  run_time_ms: number;
  rows: number;
}

export interface ToolResultBase {
  cypher: CypherTrace[];
  duration_ms: number;
}

export interface AffectedPackage {
  name: string;
  version: string;
  fixed_version: string;
}

export interface EntryPointMatch {
  cve_id: string;
  severity: string;
  cvss: number;
  summary: string;
  vector_distance: number | null;
  fulltext_score: number | null;
  combined_score: number;
  affected_packages: AffectedPackage[];
  entry_services: string[];
  entry_functions: string[];
}

export interface FindEntryPointsResult extends ToolResultBase {
  matches: EntryPointMatch[];
  best_cve_id: string | null;
}

export interface ExposedPath {
  origin_service: string;
  pivot_service: string;
  pivot_tier: ServiceTier | string;
  iam_role: string;
  database: string;
  classification: string;
  access_mode: string;
  route_hops: number;
  total_hops: number;
  path_nodes: string[];
  path: GraphPath;
}

export interface PivotService {
  name: string;
  tier: ServiceTier | string;
  rps: number;
  path_count: number;
}

export interface TraceBlastRadiusResult extends ToolResultBase {
  cve_id: string;
  origin_services: string[];
  exposed_paths: ExposedPath[];
  total_paths: number;
  exposed_databases: string[];
  pivot_services: PivotService[];
}

export interface CentralityRow {
  service: string;
  tier: ServiceTier | string;
  rps: number;
  score: number;
}

export interface RankServiceCriticalityResult extends ToolResultBase {
  pagerank: CentralityRow[];
  betweenness: CentralityRow[];
  harmonic_centrality?: CentralityRow[];
  /** Highest PageRank (most depended-upon service). */
  most_critical: string | null;
  /** Highest betweenness (where shortest paths funnel). */
  top_chokepoint?: string | null;
}

export interface ShortestAttackPathResult extends ToolResultBase {
  found: boolean;
  path_nodes: string[];
  hop_count: number;
  path: GraphPath | null;
}

export interface ReachableService {
  name: string;
  tier: ServiceTier | string;
  status: ServiceStatus | string;
}

export interface ExpandNeighborhoodResult extends ToolResultBase {
  source: string;
  depth: number;
  reachable_services: ReachableService[];
  blast_radius_size: number;
  edges: { src: string; dst: string; type: string }[];
}

export interface ServiceCommunity {
  community_id: number | string;
  services: string[];
}

export interface WccComponent {
  component_id: number | string;
  services: string[];
}

export interface DetectServiceCommunitiesResult extends ToolResultBase {
  communities: ServiceCommunity[];
  components: WccComponent[];
}

export interface FindCodeOwnerResult extends ToolResultBase {
  owners: CodeOwner[];
  recommended: CodeOwner | null;
}

export interface PastIncident {
  incident_id: string;
  title: string;
  cve_id: string | null;
  action_type: string;
  bridge_service: string | null;
  iam_role: string | null;
  assigned_developer: string | null;
  sim_passed: boolean;
  timestamp: number | null;
  rolled_back: boolean;
}

/** Memory-graph `Playbook` node (§3.3). */
export interface PlaybookRecord {
  signature: string;
  action_type: string;
  bridge_service: string;
  iam_role: string;
  success_count: number;
  last_used: number | null;
  last_incident_id: string | null;
}

/** Memory-graph `Episode` node (§3.3). */
export interface EpisodeRecord {
  id: string;
  incident_id: string;
  cve_id: string | null;
  started_at: number | null;
  finished_at: number | null;
  mode: string;
  outcome: string;
  summary: string;
  tool_call_count: number;
}

/** Memory-graph `Simulation` node (§3.3). */
export interface SimulationRecord {
  id: string;
  incident_id: string;
  cve_id: string | null;
  timestamp: number | null;
  bridge_service: string;
  iam_role: string;
  safe: boolean;
  exposure_closed: boolean;
  critical_flows_intact: boolean;
  critical_services_connected: boolean;
  sandbox_graph: string;
  exposure_before: number;
  exposure_after: number;
}

export interface RecallSimilarIncidentsResult extends ToolResultBase {
  past_incidents: PastIncident[];
  playbooks: PlaybookRecord[];
  episodes: EpisodeRecord[];
}

export interface CriticalFlow {
  source: string;
  target: string;
  intact: boolean;
}

export interface SimulateRemediationResult extends ToolResultBase {
  simulation_id: string;
  sandbox_graph: string;
  safe_to_execute: boolean;
  exposure_before: number;
  exposure_after: number;
  exposure_closed: boolean;
  critical_flows: CriticalFlow[];
  critical_flows_intact: boolean;
  wcc_components: WccComponent[];
  critical_services_connected: boolean;
  severed_routes: { src: string; dst: string }[];
  quarantined_access: { role: string; database: string }[];
  sandbox_kept: boolean;
}

/** Edge mutations carry `type` (relationship type); node mutations carry `label`. */
export interface Mutation {
  kind: 'edge' | 'node';
  type?: string;
  label?: string;
  src?: string | null;
  dst?: string | null;
  name?: string | null;
  property: string;
  previous: JsonValue;
  new: JsonValue;
}

export interface PrDraft {
  title: string;
  branch: string;
  assignee: string;
  file: string;
  body: string;
}

export interface ExecuteRemediationResult extends ToolResultBase {
  status: 'ACTION_EXECUTED' | 'PARTIAL' | 'REFUSED' | 'NO_ACTION_NEEDED';
  reason?: string;
  audit_id?: string;
  incident_status?: string;
  isolated_bridge?: string;
  quarantined_role?: string;
  mutations?: Mutation[];
  assigned_code_owner?: CodeOwner | null;
  pr_draft?: PrDraft;
  pr_url?: string;
  verification?: { exposed_paths_before: number; exposed_paths_after: number };
  scores?: { betweenness: number | null; pagerank: number | null };
}

export interface RollbackRemediationResult extends ToolResultBase {
  status: 'ROLLED_BACK' | 'ALREADY_ROLLED_BACK';
  restored: JsonValue[];
  /** Mutations not restored because the entity changed since or another active action owns it. */
  skipped?: JsonValue[];
  incident_status: string | null;
}

export interface GetDecisionProofResult extends ToolResultBase {
  incident: JsonObject;
  audits: JsonObject[];
  proof_subgraph: GraphPath;
}

export interface ReadGraphResult extends ToolResultBase {
  columns: string[];
  rows: JsonValue[][];
  row_count: number;
}

/** Narrow a raw tool result. Returns null for missing results and for `{ error }` payloads. */
export function readResult<T extends ToolResultBase>(result: JsonObject | null | undefined): T | null {
  if (!result || typeof result.error === 'string') return null;
  return result as unknown as T;
}

export function toolErrorMessage(result: JsonObject | null | undefined): string | null {
  if (!result) return null;
  return typeof result.error === 'string' ? result.error : null;
}
