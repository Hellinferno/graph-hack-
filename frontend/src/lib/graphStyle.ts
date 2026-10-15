import type { EdgeStatus, GraphHighlightEvent, HighlightStyle, JsonObject, NodeLabel } from '../events';
import { NODE_LABELS } from '../events';

export const LABEL_COLORS: Record<NodeLabel, string> = {
  Vulnerability: '#ff5c6c',
  Package: '#ff9f43',
  Function: '#9fb3c8',
  Service: '#3fa7f5',
  IAMRole: '#f5c542',
  Database: '#c77dff',
  Developer: '#2ed3a3',
  Incident: '#ff7ab6',
  ActionAudit: '#7ee7fc',
};

export const UNKNOWN_NODE_COLOR = '#6b7f94';

export const HIGHLIGHT_COLORS: Record<HighlightStyle, string> = {
  attack: '#ff4d5e',
  chokepoint: '#ffb020',
  quarantined: '#38d996',
  safe: '#4da3ff',
  proof: '#b48cff',
};

export const HIGHLIGHT_LABELS: Record<HighlightStyle, string> = {
  attack: 'Attack path',
  chokepoint: 'Chokepoint',
  quarantined: 'Quarantined',
  safe: 'Critical flow intact',
  proof: 'Decision proof',
};

export const EDGE_ACTIVE_COLOR = 'rgba(134, 160, 184, 0.35)';
export const EDGE_SEVERED_COLOR = '#38d996';

export function primaryLabel(labels: string[]): NodeLabel | null {
  for (const label of NODE_LABELS) {
    if (labels.includes(label)) return label;
  }
  return null;
}

export function nodeColor(labels: string[]): string {
  const label = primaryLabel(labels);
  return label ? LABEL_COLORS[label] : UNKNOWN_NODE_COLOR;
}

/** Service radius scales with the square root of rps (180 rps ≈ 4.3, 14 200 rps ≈ 15). */
export function serviceRadius(rps: number): number {
  const radius = 3 + Math.sqrt(Math.max(rps, 0)) / 10;
  return Math.min(Math.max(radius, 4), 16);
}

export function edgeStatus(properties: JsonObject): EdgeStatus {
  const status = properties.status;
  return status === 'ISOLATED_BY_AEGIS' || status === 'QUARANTINED_BY_AEGIS' ? status : 'ACTIVE';
}

export function isSevered(status: EdgeStatus): boolean {
  return status !== 'ACTIVE';
}

export interface HighlightIndex {
  nodes: Map<string, HighlightStyle>;
  edges: Map<string, HighlightStyle>;
}

export function edgeKey(src: string, dst: string, type?: string): string {
  return type ? `${src}→${dst}:${type}` : `${src}→${dst}`;
}

/** Fold highlight events into lookup maps. Later events win for the same node or edge. */
export function buildHighlightIndex(highlights: GraphHighlightEvent[]): HighlightIndex {
  const nodes = new Map<string, HighlightStyle>();
  const edges = new Map<string, HighlightStyle>();
  for (const highlight of highlights) {
    for (const name of highlight.nodes ?? []) nodes.set(name, highlight.style);
    for (const edge of highlight.edges ?? []) {
      edges.set(edgeKey(edge.src, edge.dst), highlight.style);
      if (edge.type) edges.set(edgeKey(edge.src, edge.dst, edge.type), highlight.style);
    }
  }
  return { nodes, edges };
}

export function lookupEdgeStyle(index: HighlightIndex, src: string, dst: string, type: string): HighlightStyle | undefined {
  return index.edges.get(edgeKey(src, dst, type)) ?? index.edges.get(edgeKey(src, dst));
}
